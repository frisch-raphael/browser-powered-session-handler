import javax.swing.*;
import java.awt.*;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Edits stable-ID native steps on the EDT; password buffers travel separately from saved definitions. */
public final class StepsPanel extends JPanel {
    private final JPanel rowsPanel = new JPanel();
    private final List<Row> rows = new ArrayList<>();
    private final JComboBox<AuthStep.Type> typePicker = new JComboBox<>(AuthStep.Type.values());
    private final JButton addStep;
    private final JButton undoStep = UiIcons.button(UiIcons.Action.UNDO, "Undo", this::undo);
    private final JTextArea emptyHint = new JTextArea("Add the actions needed to sign in, such as filling fields and clicking Sign in.\nLeave this empty only when opening the Login URL returns credentials without further interaction.", 4, 0);
    private final java.util.ArrayDeque<UndoEntry> history = new java.util.ArrayDeque<>();
    private boolean restoringUndo;
    private Runnable changed = () -> {};
    private boolean loading;
    private static final java.util.regex.Pattern STEP_PATH = java.util.regex.Pattern.compile("^steps\\[(\\d+)]");

    /** Captures raw editor text without performing validation or JSON/storage work on the EDT. */
    record Input(UUID id, AuthStep.Type type, String selector, String value, String state, DurationUnit durationUnit) {
        Input { if (durationUnit == null) durationUnit = DurationUnit.MILLISECONDS; }
        Input(UUID id, AuthStep.Type type, String selector, String value, String state) { this(id, type, selector, value, state, DurationUnit.MILLISECONDS); }
    }
    /** Old unfinished drafts retain milliseconds; newly captured UI text explicitly records seconds. */
    enum DurationUnit { MILLISECONDS, SECONDS }
    /** Bounded session-only recovery; owned secret arrays are wiped when discarded. */
    private record UndoEntry(Snapshot snapshot, UUID focus) implements AutoCloseable { @Override public void close() { snapshot.close(); } }

    /** Owns captured secure-step arrays until the background save consumes or discards this snapshot. */
    static final class Snapshot implements AutoCloseable {
        final List<Input> inputs;
        final Map<UUID, char[]> secrets;
        /**
         * Adopts raw row metadata and independent password arrays for one background draft operation.
         *
         * @param inputs Stable row identities and raw nonsecret text.
         * @param secrets Captured caller-owned arrays.
         */
        Snapshot(List<Input> inputs, Map<UUID, char[]> secrets) { this.inputs = List.copyOf(inputs); this.secrets = secrets; }
        /**
         * Builds immutable steps off the EDT, preserving ordinary input whitespace and stable secret owners.
         * @return Ordered definitions, validated fully later by the native codec.
         */
        List<AuthStep.Definition> definitions() {
            var definitions = new ArrayList<AuthStep.Definition>();
            for (int index = 0; index < inputs.size(); index++) {
                var i = inputs.get(index); Integer duration = null;
                if (i.type() == AuthStep.Type.WAIT_TIME) try { duration = duration(i.value(), i.durationUnit()); }
                catch (IllegalArgumentException error) { throw new ConfigManager.NativeFormatException("steps[" + index + "].durationMs: enter a duration from 0 to 300 seconds, with at most three decimal places."); }
                definitions.add(new AuthStep.Definition(i.id(), i.type(), i.type().requiresSelector() ? i.selector() : null,
                        i.type() == AuthStep.Type.INPUT ? i.value() : null, i.state() != null && (i.type() == AuthStep.Type.WAIT_LOAD_STATE || i.type() == AuthStep.Type.WAIT_SELECTOR && AuthStep.ELEMENT_STATES.contains(i.state()) || i.type() == AuthStep.Type.WAIT_URL && AuthStep.URL_MATCHES.contains(i.state())) ? i.state() : null,
                        i.type() == AuthStep.Type.WAIT_URL ? i.value() : null, duration));
            }
            return List.copyOf(definitions);
        }
        /** Wipes every captured secure-step buffer after save, rejection or shutdown. */
        @Override public void close() { secrets.values().forEach(v -> Arrays.fill(v, '\0')); }
        /**
         * Converts integer milliseconds or explicit exact seconds without truncating fractional milliseconds.
         * @param value Raw wait editor text, optionally suffixed with ms or s.
         * @return Canonical integer milliseconds; the codec enforces the 0-300000 range.
         */
        private static int duration(String value, DurationUnit unit) {
            try {
                String text = value.trim().toLowerCase(java.util.Locale.ROOT);
                if (text.endsWith("ms")) return new BigDecimal(text.substring(0, text.length() - 2).trim()).intValueExact();
                if (text.endsWith("s")) { text = text.substring(0, text.length() - 1).trim(); unit = DurationUnit.SECONDS; }
                return new BigDecimal(text).multiply(BigDecimal.valueOf(unit == DurationUnit.SECONDS ? 1000 : 1)).intValueExact();
            } catch (RuntimeException ex) { throw new IllegalArgumentException("Wait time requires integer milliseconds or exact seconds such as 1.5s."); }
        }
    }

    /** Creates a scrollable step editor without loading files, modules or browser state. */
    public StepsPanel() {
        super(new BorderLayout(6, 6)); rowsPanel.setLayout(new BoxLayout(rowsPanel, BoxLayout.Y_AXIS));
        var controls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        var types = typePicker; typeLabels(types);
        addStep = UiIcons.button(UiIcons.Action.ADD, "Add step", () -> { remember(null, null); add(new AuthStep.Definition(UUID.randomUUID(), (AuthStep.Type) types.getSelectedItem(), "", "", "load", "", 1000), null); notifyChanged(); });
        undoStep.setEnabled(false); undoStep.setToolTipText("Undo the last step removal, type change or move (Alt+Backspace).");
        controls.add(types); controls.add(addStep); controls.add(undoStep);
        emptyHint.setEditable(false); emptyHint.setOpaque(false); emptyHint.setLineWrap(true); emptyHint.setWrapStyleWord(true); emptyHint.setFont(UIManager.getFont("Label.font"));
        emptyHint.setBorder(BorderFactory.createEmptyBorder(12, 8, 8, 8)); emptyHint.setMaximumSize(new Dimension(Integer.MAX_VALUE, 110));
        emptyHint.getAccessibleContext().setAccessibleName("Configure login actions"); rowsPanel.add(emptyHint);
        getInputMap(WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(KeyStroke.getKeyStroke("alt BACK_SPACE"), "undoStep");
        getActionMap().put("undoStep", new AbstractAction() { @Override public void actionPerformed(java.awt.event.ActionEvent event) { undo(); } });
        add(controls, BorderLayout.NORTH); add(new JScrollPane(rowsPanel), BorderLayout.CENTER);
    }

    /**
     * Registers a lightweight EDT edit notification, leaving validation and saves to its owner.
     *
     * @param changed Lightweight EDT callback; callers debounce background local saves separately.
     */
    public void setChangeListener(Runnable changed) { this.changed = changed; }

    /**
     * Populates one saved journey's rows and independent session values without changing their UUIDs.
     * @param definitions Ordered native steps.
     * @param values Borrowed secret snapshot; accessor copies are wiped after populating Swing fields.
     */
    public void setSteps(List<AuthStep.Definition> definitions, SecretStore.Values values) {
        loading = true;
        try {
            clear(); for (var step : definitions) { char[] secret = values.stepValue(step.id()); try { add(step, secret); } finally { if (secret != null) Arrays.fill(secret, '\0'); } }
        } finally { loading = false; }
        rowsPanel.revalidate(); rowsPanel.repaint(); activate(rows.isEmpty() ? null : rows.getFirst(), false);
    }

    /** Restores unfinished step text while keeping secure values in their separate buffers. */
    void setDraft(List<Input> inputs, SecretStore.Values values) {
        loading = true;
        try {
            clear();
            for (var input : inputs) {
                var definition = new AuthStep.Definition(input.id(), input.type(), input.selector(), input.type() == AuthStep.Type.INPUT ? input.value() : null,
                        input.state(), input.type() == AuthStep.Type.WAIT_URL ? input.value() : "", 0);
                char[] secret = values.stepValue(input.id());
                try { add(definition, secret); rows.get(rows.size() - 1).value.setText(input.type() == AuthStep.Type.WAIT_TIME ? durationText(input.value(), input.durationUnit()) : input.value()); }
                finally { if (secret != null) Arrays.fill(secret, '\0'); }
            }
        } finally { loading = false; }
        rowsPanel.revalidate(); rowsPanel.repaint(); activate(rows.isEmpty() ? null : rows.getFirst(), false);
    }

    /**
     * Returns eDT-captured raw steps and owned secret buffers for one background operation.
     *
     * @return EDT-captured raw steps and owned secret buffers for one background operation.
     */
    Snapshot snapshot() {
        return snapshot(null, null);
    }
    /** Captures the previous type before a destructive combo change has cleared its inputs. */
    private Snapshot snapshot(Row changing, AuthStep.Type previous) {
        var inputs = new ArrayList<Input>(); Map<UUID, char[]> secrets = new HashMap<>();
        for (Row row : rows) {
            var type = row == changing && previous != null ? previous : (AuthStep.Type) row.type.getSelectedItem();
            inputs.add(new Input(row.id, type, row.selector.getText(), row.value.getText(), (String) row.state.getSelectedItem(), DurationUnit.SECONDS));
            if (type == AuthStep.Type.SECURE_INPUT && row.secretProvided) secrets.put(row.id, row.secret.getPassword());
        }
        return new Snapshot(inputs, secrets);
    }

    /** Clears visible secret documents and removes only this editor's rows. */
    public void clear() { rows.forEach(r -> r.secret.setText("")); rows.clear(); rowsPanel.removeAll(); if (!restoringUndo) { history.forEach(UndoEntry::close); history.clear(); } renumber(); }
    /** Keeps structural Undo local to this journey and wipes evicted secret snapshots. */
    private void remember(Row changing, AuthStep.Type previous) {
        if (loading || restoringUndo) return;
        var captured = snapshot(changing, previous);
        for (var id : new ArrayList<>(captured.secrets.keySet())) if (changing == null || !id.equals(changing.id)) Arrays.fill(captured.secrets.remove(id), '\0');
        history.addLast(new UndoEntry(captured, changing == null ? null : changing.id));
        while (history.size() > 20) history.removeFirst().close(); undoStep.setEnabled(true);
    }
    /** Restores one explicit structural edit while retaining stable IDs and session-only secret ownership. */
    private void undo() {
        if (history.isEmpty()) return;
        var entry = history.removeLast(); restoringUndo = true;
        try (entry; var current = snapshot()) {
            var restored = new ArrayList<>(current.inputs); var before = entry.snapshot();
            if (entry.focus() == null) {
                var ids = before.inputs.stream().map(Input::id).collect(java.util.stream.Collectors.toSet());
                restored.removeIf(input -> !ids.contains(input.id()));
            } else {
                int original = -1; Input saved = null;
                for (int i = 0; i < before.inputs.size(); i++) if (before.inputs.get(i).id().equals(entry.focus())) { original = i; saved = before.inputs.get(i); break; }
                Input present = restored.stream().filter(i -> i.id().equals(entry.focus())).findFirst().orElse(null);
                if (saved != null) {
                    restored.removeIf(i -> i.id().equals(entry.focus()));
                    boolean replace = present == null || present.type() != saved.type();
                    restored.add(Math.min(original, restored.size()), replace ? saved : present);
                    if (replace) {
                        char[] previous = current.secrets.remove(entry.focus()); if (previous != null) Arrays.fill(previous, '\0');
                        char[] secret = before.secrets.get(entry.focus()); if (secret != null) current.secrets.put(entry.focus(), secret.clone());
                    }
                }
            }
            var ids = restored.stream().map(Input::id).collect(java.util.stream.Collectors.toSet());
            for (var id : new ArrayList<>(current.secrets.keySet())) if (!ids.contains(id)) Arrays.fill(current.secrets.remove(id), '\0');
            try (var values = new SecretStore.Values(null, current.secrets)) { setDraft(restored, values); }
        }
        finally { restoringUndo = false; undoStep.setEnabled(!history.isEmpty()); }
        if (!rows.isEmpty()) revealStep(entry.focus() == null ? rows.getLast().id : entry.focus(), null);
        else addStep.requestFocusInWindow();
        notifyChanged();
    }
    /** Converts legacy saved milliseconds to seconds; invalid unfinished text remains literal. */
    private static String durationText(String value, DurationUnit unit) {
        try { return BigDecimal.valueOf(Snapshot.duration(value, unit), 3).stripTrailingZeros().toPlainString(); }
        catch (IllegalArgumentException error) { return value; }
    }
    /**
     * Adds one stable-ID row and its optional secure value without changing another step's identity.
     *
     * @param definition New or saved stable step.
     * @param secret Optional supplied secure value.
     */
    private void add(AuthStep.Definition definition, char[] secret) { Row row = new Row(definition, secret); rows.add(row); rowsPanel.add(row); renumber(); rowsPanel.revalidate(); rowsPanel.repaint(); if (!loading) activate(row, true); }
    /** Expands the selected row, keeping the rest scannable and never exposing values in summaries. */
    private void activate(Row active, boolean focus) {
        for (var row : rows) { row.expanded.setSelected(row == active); row.inputs.setVisible(row == active); row.updateFields(); }
        if (focus && active != null) SwingUtilities.invokeLater(() -> { if (rows.contains(active)) { active.scrollRectToVisible(new Rectangle(0, 0, active.getWidth(), active.getHeight())); active.firstInput().requestFocusInWindow(); } });
    }
    /** Updates visible sequence numbers without changing the stable step identities or their secret associations. */
    private void renumber() {
        if (rows.isEmpty()) { if (emptyHint.getParent() != rowsPanel) rowsPanel.add(emptyHint); } else rowsPanel.remove(emptyHint);
        undoStep.setEnabled(!history.isEmpty());
        for (int i = 0; i < rows.size(); i++) { var row = rows.get(i); row.number.setText("Step " + (i + 1)); row.summary(); row.up.setEnabled(i > 0); row.down.setEnabled(i < rows.size() - 1); row.up.getAccessibleContext().setAccessibleName("Move step " + (i + 1) + " up"); row.down.getAccessibleContext().setAccessibleName("Move step " + (i + 1) + " down"); row.remove.getAccessibleContext().setAccessibleName("Remove step " + (i + 1)); }
        addStep.setEnabled(rows.size() < 256);
        addStep.setToolTipText(rows.size() < 256 ? "Add step" : "Maximum 256 steps per journey. Remove a step to add another.");
    }
    /** Restores human-readable step choices after the host's native theme pass replaces renderers. */
    void refreshPresentation() { typeLabels(typePicker); rows.forEach(row -> { typeLabels(row.type); stateLabels(row.state); }); }
    /** @param id Stable action identity. @return Whether the currently displayed sequence contains it. */
    boolean containsStep(UUID id) { return rows.stream().anyMatch(row -> row.id.equals(id)); }
    /** @param id Exact action to reveal. @param message Optional safe guidance; null only navigates. */
    void revealStep(UUID id, String message) {
        revealStep(id, message, true);
    }
    /** @param id Exact action. @param message Safe guidance. @param missingSecret Focus a secure value only when that value is the missing input. */
    void revealStep(UUID id, String message, boolean missingSecret) {
        for (var row : rows) if (row.id.equals(id)) {
            activate(row, false);
            var kind = (AuthStep.Type) row.type.getSelectedItem();
            JComponent field = kind == AuthStep.Type.SECURE_INPUT && missingSecret ? row.secret : kind.requiresSelector() ? row.selector : kind == AuthStep.Type.WAIT_LOAD_STATE ? row.state : row.value;
            if (message != null) InlineValidation.show(field, message);
            row.updateFields();
            InlineValidation.focus(field); return;
        }
    }
    /** @param path Indexed validation path. @param guidance Safe correction. @param focus Whether an explicit action may focus the input. */
    void showInvalid(String path, String guidance, boolean focus) {
        var match = STEP_PATH.matcher(path); if (!match.find()) return;
        int index = Integer.parseInt(match.group(1)); if (index >= rows.size()) return;
        var row = rows.get(index); JComponent target = path.contains("selector") ? row.selector : path.contains("state") || path.contains("match") ? row.state : row.value;
        if (focus) activate(row, false);
        InlineValidation.show(target, guidance);
        row.updateFields();
        if (focus) InlineValidation.focus(target);
    }
    /**
     * Labels actions in task language while leaving the enum/wire discriminator unchanged.
     * @param combo Step-kind selector owned by this editor.
     */
    private static void typeLabels(JComboBox<AuthStep.Type> combo) {
        combo.setRenderer(new DefaultListCellRenderer() {
            /** Renders one supported action with native selection and focus colors. */
            @Override public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean selected, boolean focus) {
                String label = value instanceof AuthStep.Type kind ? kind.label() : "";
                var option = super.getListCellRendererComponent(list, label, index, selected, focus);
                if (index != 0 && index != 3) return option;
                var group = new JPanel(new BorderLayout()); var caption = new JLabel(index == 0 ? "Interactions" : "Waits"); caption.setBorder(BorderFactory.createEmptyBorder(5, 5, 3, 5)); caption.setFont(caption.getFont().deriveFont(Font.BOLD));
                group.setBackground(list.getBackground()); group.add(caption, BorderLayout.NORTH); group.add(option); return group;
            }
        });
    }
    /** Runs only the lightweight EDT edit callback outside population. */
    private void notifyChanged() { if (!loading) changed.run(); }
    /** Gives browser lifecycle states readable captions without changing their saved wire values. */
    private static void stateLabels(JComboBox<String> combo) {
        combo.setRenderer(new DefaultListCellRenderer() { @Override public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean selected, boolean focus) {
            String label = switch (String.valueOf(value)) { case "load" -> "Page load event"; case "domcontentloaded" -> "DOM ready"; case "networkidle" -> "Network idle"; case "visible" -> "Visible"; case "hidden" -> "Hidden"; case "attached" -> "Present in page"; case "detached" -> "Removed from page"; case "exact" -> "Exact URL"; case "glob" -> "URL pattern"; default -> String.valueOf(value); };
            var component = super.getListCellRendererComponent(list, label, index, selected, focus);
            setToolTipText(switch (String.valueOf(value)) { case "load" -> "Wait for the browser's page load event. An already reached state returns immediately."; case "domcontentloaded" -> "Wait for the page's initial HTML to be parsed. This does not wait for all application data."; case "networkidle" -> "Wait for at least 500 ms without network connections. Background traffic can prevent this condition."; default -> ""; }); return component;
        } });
    }

    /** Owns one step's Swing fields; reordering never reallocates its stable UUID. */
    private final class Row extends JPanel {
        final UUID id;
        final JComboBox<AuthStep.Type> type = new JComboBox<>(AuthStep.Type.values());
        final JTextField selector = new PlaceholderTextField("CSS selector", 18), value = new PlaceholderTextField("Value / URL pattern / wait", 20);
        final PlaceholderPasswordField secret = new PlaceholderPasswordField("Secret value", 18);
        boolean secretProvided;
        final JComboBox<String> state = new JComboBox<>(AuthStep.LOAD_STATES.toArray(String[]::new));
        final JLabel number = new JLabel(), valueCaption = new JLabel("Value"), stateCaption = new JLabel("Load state");
        final JToggleButton expanded = new JToggleButton();
        final JPanel inputs = new JPanel();
        final JPanel selectorLine, valueLine, stateLine, secretLine;
        final JButton up, down, remove;
        AuthStep.Type previous;
        /**
         * Constructs a native step row while preserving its saved UUID and missing-versus-supplied secure value.
         *
         * @param definition Immutable configuration to populate.
         * @param password Optional supplied secure value.
         */
        Row(AuthStep.Definition definition, char[] password) {
            super(new BorderLayout(6, 6)); setBorder(BorderFactory.createEmptyBorder(8, 8, 12, 8));
            id = definition.id(); previous = definition.type(); type.setSelectedItem(previous); typeLabels(type);
            selector.setText(definition.selector() == null ? "" : definition.selector());
            value.setText(switch (previous) { case WAIT_URL -> definition.urlPattern(); case WAIT_TIME -> definition.durationMs() == null ? "" : BigDecimal.valueOf(definition.durationMs(), 3).stripTrailingZeros().toPlainString(); default -> definition.value() == null ? "" : definition.value(); });
            stateLabels(state);
            configureState(previous, definition.state()); secretProvided = password != null; if (password != null) secret.setText(new String(password));
            state.setToolTipText("Wait for the load event, DOM readiness, or network idle before continuing.");
            secret.setToolTipText("Value entered into the selected element. Stored for this session unless Remember secrets is enabled.");
            var header = new JPanel(new BorderLayout(6, 0)); expanded.putClientProperty("html.disable", true); expanded.setHorizontalAlignment(SwingConstants.LEFT); expanded.addActionListener(e -> activate(expanded.isSelected() ? this : null, false)); header.add(expanded);
            var actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
            up = UiIcons.button(UiIcons.Action.UP, "Move step up", () -> move("Up")); down = UiIcons.button(UiIcons.Action.DOWN, "Move step down", () -> move("Down"));
            remove = UiIcons.button(UiIcons.Action.REMOVE, "Remove step", () -> move("Remove")); actions.add(up); actions.add(down); actions.add(remove); header.add(actions, BorderLayout.EAST);
            inputs.setLayout(new BoxLayout(inputs, BoxLayout.Y_AXIS)); inputs.add(line(new JLabel("Action"), type));
            selectorLine = line(new JLabel("CSS selector"), selector); valueLine = line(valueCaption, value);
            stateLine = line(stateCaption, state); secretLine = line(new JLabel("Secure value"), secret);
            inputs.add(selectorLine); inputs.add(valueLine); inputs.add(stateLine); inputs.add(secretLine);
            add(header, BorderLayout.NORTH); add(inputs, BorderLayout.CENTER); inputs.setVisible(false); updateFields();
            type.addActionListener(e -> {
                var next = (AuthStep.Type) type.getSelectedItem();
                if (next == previous) return;
                remember(this, previous);
                if (previous == AuthStep.Type.SECURE_INPUT && next != previous) { secret.setText(""); secretProvided = false; }
                if (next != previous) { if (!next.requiresSelector()) selector.setText(""); value.setText(""); configureState(next, null); }
                previous = next; updateFields(); notifyChanged(); activate(this, true);
            });
            state.addActionListener(e -> { summary(); notifyChanged(); });
            for (JTextField field : List.of(selector, value, secret)) field.getDocument().addDocumentListener(new DocumentChangeListener(() -> { if (field == secret) secretProvided = true; summary(); notifyChanged(); }));
            for (var shortcut : new String[][]{{"alt UP", "Up"}, {"alt DOWN", "Down"}, {"alt DELETE", "Remove"}}) {
                getInputMap(WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(KeyStroke.getKeyStroke(shortcut[0]), shortcut[1]);
                getActionMap().put(shortcut[1], new AbstractAction() { @Override public void actionPerformed(java.awt.event.ActionEvent event) { move(shortcut[1]); } });
            }
        }
        /** Shows only fields owned by the current type and keeps missing values distinct from supplied empty input. */
        private void updateFields() {
            var kind = (AuthStep.Type) type.getSelectedItem(); selectorLine.setVisible(kind.requiresSelector());
            valueLine.setVisible(kind == AuthStep.Type.INPUT || kind == AuthStep.Type.WAIT_URL || kind == AuthStep.Type.WAIT_TIME);
            valueCaption.setText(kind == AuthStep.Type.WAIT_TIME ? "Duration (seconds)" : kind == AuthStep.Type.WAIT_URL ? "URL or URL pattern" : "Text value");
            value.setToolTipText(kind == AuthStep.Type.WAIT_TIME ? "Pause for 0 to 300 seconds. Fractional seconds are supported, for example 1.5. This delay always runs in full." : kind == AuthStep.Type.WAIT_URL ? "An exact URL, such as https://app.example/dashboard, or a Playwright glob such as **/dashboard. Plain URLs match exactly, including query string and trailing slash; regular expressions are not supported." : "Replace the field's existing contents with this saved text. Leave empty to clear the field. Use Enter secret for sensitive values.");
            selector.setToolTipText("CSS selector of the element this step uses, for example #username.");
            stateCaption.setText(kind == AuthStep.Type.WAIT_SELECTOR ? "Condition" : kind == AuthStep.Type.WAIT_URL ? "Match" : "Load state");
            stateLine.setVisible(kind == AuthStep.Type.WAIT_LOAD_STATE || kind == AuthStep.Type.WAIT_SELECTOR || kind == AuthStep.Type.WAIT_URL); secretLine.setVisible(kind == AuthStep.Type.SECURE_INPUT); secret.setEnabled(kind == AuthStep.Type.SECURE_INPUT);
            if (kind == AuthStep.Type.WAIT_SELECTOR) state.setToolTipText("Wait for the element to be visible, hidden, present in the page, or removed from the page.");
            else if (kind == AuthStep.Type.WAIT_URL) state.setToolTipText("Exact URL compares the whole URL. URL pattern uses Playwright glob wildcards, such as **/dashboard.");
            summary(); setMaximumSize(new Dimension(Integer.MAX_VALUE, getPreferredSize().height)); revalidate(); repaint();
        }
        /** @return First input belonging to this action. */
        JComponent firstInput() { var kind = (AuthStep.Type) type.getSelectedItem(); return kind.requiresSelector() ? selector : kind == AuthStep.Type.WAIT_LOAD_STATE ? state : value; }
        /** Summaries contain action/selector metadata, never entered text or secure values. */
        void summary() { var kind = (AuthStep.Type) type.getSelectedItem(); String detail = kind.requiresSelector() ? selector.getText() : kind == AuthStep.Type.WAIT_TIME ? value.getText() + " seconds" : ""; if (detail.length() > 70) detail = detail.substring(0, 67) + "..."; String condition = kind == AuthStep.Type.WAIT_SELECTOR ? " (" + state.getSelectedItem() + ")" : ""; expanded.setText(number.getText() + " — " + kind.label() + condition + (detail.isBlank() ? "" : " · " + detail)); expanded.setToolTipText("Expand or collapse this step. Alt+Up/Down moves it; Alt+Delete removes it."); }
        /** Uses native saved values while making match/condition semantics explicit in the editor. */
        private void configureState(AuthStep.Type kind, String desired) {
            var options = kind == AuthStep.Type.WAIT_SELECTOR ? AuthStep.ELEMENT_STATES : kind == AuthStep.Type.WAIT_URL ? AuthStep.URL_MATCHES : AuthStep.LOAD_STATES;
            String fallback = kind == AuthStep.Type.WAIT_URL && (value.getText().contains("*") || value.getText().contains("{")) ? "glob" : options.getFirst();
            state.setModel(new DefaultComboBoxModel<>(options.toArray(String[]::new))); state.setSelectedItem(desired != null && options.contains(desired) ? desired : fallback); stateLabels(state);
        }
        /**
         * Pairs one persistent accessible caption with a field that expands within the step width.
         * @param label Meaningful visible caption.
         * @param field Native input owned by this stable step.
         * @return A compact labeled row.
         */
        private JPanel line(JLabel label, JComponent field) { var panel = new JPanel(new BorderLayout(8, 3)); panel.setAlignmentX(Component.LEFT_ALIGNMENT); label.setLabelFor(field); panel.add(label, BorderLayout.WEST); panel.add(InlineValidation.wrap(field), BorderLayout.CENTER); panel.setBorder(BorderFactory.createEmptyBorder(3, 0, 3, 0)); return panel; }
        /**
         * Reorders the existing row identity or removes it while clearing its visible secure document.
         *
         * @param action Reorders this stable row or explicitly removes its visible secret.
         */
        private void move(String action) {
            int index = rows.indexOf(this);
            if (index < 0) return;
            if (!action.equals("Remove") && (action.equals("Up") ? index == 0 : index == rows.size() - 1)) return;
            remember(this, null);
            if (action.equals("Remove")) { secret.setText(""); rows.remove(this); }
            else { int to = index + (action.equals("Up") ? -1 : 1); if (to < 0 || to >= rows.size()) return; rows.remove(index); rows.add(to, this); }
            rowsPanel.removeAll(); rows.forEach(rowsPanel::add); renumber(); rowsPanel.revalidate(); rowsPanel.repaint(); notifyChanged();
            if (!rows.isEmpty()) activate(action.equals("Remove") ? rows.get(Math.min(index, rows.size() - 1)) : this, true); else addStep.requestFocusInWindow();
        }
    }
}
