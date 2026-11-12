package bpsh.burp.ui;

import bpsh.journey.editing.JourneyDraftCompiler;
import bpsh.journey.AuthStep;
import bpsh.journey.JourneyDraft;
import bpsh.journey.SecretStore;
import java.awt.*;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.Set;
import java.util.HashSet;
import javax.swing.*;

/** Edits stable-ID native steps on the EDT; password buffers travel separately from saved definitions. */
public final class StepsPanel extends JPanel {
    private final JPanel rowsPanel = new JPanel();
    private final List<Row> rows = new ArrayList<>();
    private final JComboBox<AuthStep.Type> typePicker = UiTooltips.comboBox(AuthStep.Type.values());
    private final JButton addStep;
    private final JButton recordSteps = UiIcons.button(UiIcons.Action.RECORD, "Record in browser", () -> {});
    private final JButton undoStep = UiIcons.button(UiIcons.Action.UNDO, "Undo", this::undo);
    private final JTextArea emptyHint = new JTextArea("Add the actions needed to sign in, such as filling fields and clicking Sign in.\nLeave this empty only when opening the Login URL returns credentials without further interaction.", 4, 0);
    private final java.util.ArrayDeque<UndoEntry> history = new java.util.ArrayDeque<>();
    private boolean restoringUndo;
    private Runnable changed = () -> {};
    private boolean loading;
    private boolean recordingReview, changingType;
    private Set<UUID> reviewedPopups = Set.of();
    private final Set<UUID> missingReviewValues = new HashSet<>();
    private java.util.function.BiConsumer<UUID, AuthStep.Type> corrected = (id, type) -> {};
    private static final java.util.regex.Pattern STEP_PATH = java.util.regex.Pattern.compile("^steps\\[(\\d+)]");
    private record Reference(String id, String label) { @Override public String toString() { return label; } }



    /** Bounded session-only recovery; owned secret arrays are wiped when discarded. */
    private record UndoEntry(Snapshot snapshot, UUID focus, boolean replacement) implements AutoCloseable {
        UndoEntry(Snapshot snapshot, UUID focus) { this(snapshot, focus, false); }
        @Override public void close() { snapshot.close(); }
    }

    /** Owns captured secure-step arrays until the background save consumes or discards this snapshot. */
    static final class Snapshot implements AutoCloseable {
        final List<JourneyDraft.StepInput> inputs;
        final Map<UUID, char[]> secrets;
        final Set<UUID> missingValues;
        /**
         * Adopts raw row metadata and independent password arrays for one background draft operation.
         *
         * @param inputs Stable row identities and raw nonsecret text.
         * @param secrets Captured caller-owned arrays.
         */
        Snapshot(List<JourneyDraft.StepInput> inputs, Map<UUID, char[]> secrets) { this(inputs, secrets, Set.of()); }
        Snapshot(List<JourneyDraft.StepInput> inputs, Map<UUID, char[]> secrets, Set<UUID> missing) { this.inputs = List.copyOf(inputs); this.secrets = secrets; this.missingValues = Set.copyOf(missing); }

            List<AuthStep.Definition> definitions() { return JourneyDraftCompiler.steps(inputs); }
        /** Wipes every captured secure-step buffer after save, rejection or shutdown. */
        @Override public void close() { secrets.values().forEach(v -> Arrays.fill(v, '\0')); }

    }

    /** Creates a scrollable step editor without loading files, modules or browser state. */
    public StepsPanel() {
        super(new BorderLayout(6, 6)); rowsPanel.setLayout(new BoxLayout(rowsPanel, BoxLayout.Y_AXIS));
        var controls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        var types = typePicker; typeLabels(types);
        addStep = UiIcons.button(UiIcons.Action.ADD, "Add step", () -> { remember(null, null); var kind = (AuthStep.Type) types.getSelectedItem(); add(new AuthStep.Definition(UUID.randomUUID(), kind, "", "", "load", "", 1000), null); rows.getLast().setOperation(JourneyDraft.defaultOperation(kind)); notifyChanged(); });
        undoStep.setEnabled(false); undoStep.setToolTipText("Undo the last step change or recording replacement (Alt+Backspace).");
        controls.add(types); controls.add(addStep); controls.add(undoStep);
        recordSteps.setVisible(false); recordSteps.setToolTipText("Record in browser: perform the login, then review the recorded steps before replacing these steps."); controls.add(recordSteps);
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
    /** Installs the complete recording action at composition time, without a second add-action picker. */
    void recordingAction(Runnable action) { recordSteps.setVisible(true); recordSteps.addActionListener(event -> action.run()); }
    void recordingEnabled(boolean enabled) { recordSteps.setEnabled(enabled); }
    /** Review-only conversions preserve captured values; ordinary editor conversions retain their clearing rules. */
    void recordingReview(Set<UUID> popups, java.util.function.BiConsumer<UUID, AuthStep.Type> correction) {
        recordingReview = true; reviewedPopups = Set.copyOf(popups); corrected = correction;
    }
    void restoreMissingValues(Set<UUID> missing) { missingReviewValues.clear(); missingReviewValues.addAll(missing); }

    /** Replaces only the sequence as one undoable edit, with caller-owned values copied into native fields. */
    void replaceRecording(List<JourneyDraft.StepInput> inputs, SecretStore.Values values) {
        var previous = snapshot(); boolean oldRestoring = restoringUndo; restoringUndo = true; boolean replaced = false;
        try {
            setDraft(inputs, values); replaced = true;
            history.addLast(new UndoEntry(previous, null, true));
            while (history.size() > 20) history.removeFirst().close();
        } catch (RuntimeException error) {
            try (var old = new SecretStore.Values(null, previous.secrets)) { setDraft(previous.inputs, old); }
            throw error;
        } finally {
            restoringUndo = oldRestoring; if (!replaced) previous.close(); undoStep.setEnabled(!history.isEmpty());
        }
        notifyChanged();
    }

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
    void setDraft(List<JourneyDraft.StepInput> inputs, SecretStore.Values values) {
        loading = true;
        try {
            clear();
            for (var input : inputs) {
                var definition = input.structuralStep();
                char[] secret = values.stepValue(input.id());
                try { add(definition, secret); var row = rows.getLast(); row.value.setText(input.type() == AuthStep.Type.WAIT_TIME ? durationText(input.value(), input.durationUnit()) : input.value()); row.setOperation(input.operation()); }
                finally { if (secret != null) Arrays.fill(secret, '\0'); }
            }
        } finally { loading = false; }
        renumber(); rowsPanel.revalidate(); rowsPanel.repaint(); activate(rows.isEmpty() ? null : rows.getFirst(), false);
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
        var inputs = new ArrayList<JourneyDraft.StepInput>(); Map<UUID, char[]> secrets = new HashMap<>();
        var missing = new HashSet<>(missingReviewValues);
        for (Row row : rows) {
            var type = row == changing && previous != null ? previous : (AuthStep.Type) row.type.getSelectedItem();
            inputs.add(new JourneyDraft.StepInput(row.id, type, row.selector.getText(), row.value.getText(), (String) row.state.getSelectedItem(), JourneyDraft.DurationUnit.SECONDS, row.operation(type)));
            if (type == AuthStep.Type.SECURE_INPUT && row.secretProvided) secrets.put(row.id, row.secret.getPassword());
            if (recordingReview && type == AuthStep.Type.SECURE_INPUT && !row.secretProvided) missing.add(row.id);
        }
        return new Snapshot(inputs, secrets, missing);
    }

    /** Clears visible secret documents and removes only this editor's rows. */
    public void clear() { rows.forEach(r -> r.secret.setText("")); rows.clear(); missingReviewValues.clear(); rowsPanel.removeAll(); if (!restoringUndo) { history.forEach(UndoEntry::close); history.clear(); } renumber(); }
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
            var missing = new HashSet<>(current.missingValues);
            if (entry.replacement()) {
                restored = new ArrayList<>(before.inputs); current.secrets.values().forEach(value -> Arrays.fill(value, '\0')); current.secrets.clear();
                before.secrets.forEach((id, value) -> current.secrets.put(id, value.clone())); missing = new HashSet<>(before.missingValues);
            } else if (entry.focus() == null) {
                var ids = before.inputs.stream().map(JourneyDraft.StepInput::id).collect(java.util.stream.Collectors.toSet());
                restored.removeIf(input -> !ids.contains(input.id()));
            } else {
                int original = -1; JourneyDraft.StepInput saved = null;
                for (int i = 0; i < before.inputs.size(); i++) if (before.inputs.get(i).id().equals(entry.focus())) { original = i; saved = before.inputs.get(i); break; }
                JourneyDraft.StepInput present = restored.stream().filter(i -> i.id().equals(entry.focus())).findFirst().orElse(null);
                if (saved != null) {
                    restored.removeIf(i -> i.id().equals(entry.focus()));
                    boolean replace = present == null || present.type() != saved.type();
                    restored.add(Math.min(original, restored.size()), replace ? saved : present);
                    if (replace) {
                        char[] previous = current.secrets.remove(entry.focus()); if (previous != null) Arrays.fill(previous, '\0');
                        char[] secret = before.secrets.get(entry.focus()); if (secret != null) current.secrets.put(entry.focus(), secret.clone());
                        missing.remove(entry.focus()); if (before.missingValues.contains(entry.focus())) missing.add(entry.focus());
                    }
                }
            }
            var ids = restored.stream().map(JourneyDraft.StepInput::id).collect(java.util.stream.Collectors.toSet());
            for (var id : new ArrayList<>(current.secrets.keySet())) if (!ids.contains(id)) Arrays.fill(current.secrets.remove(id), '\0');
            try (var values = new SecretStore.Values(null, current.secrets)) { setDraft(restored, values); }
            restoreMissingValues(missing);
        }
        finally { restoringUndo = false; undoStep.setEnabled(!history.isEmpty()); }
        if (!rows.isEmpty()) revealStep(entry.focus() == null ? rows.getLast().id : entry.focus(), null);
        else addStep.requestFocusInWindow();
        notifyChanged();
    }
    /** Converts legacy saved milliseconds to seconds; invalid unfinished text remains literal. */
    private static String durationText(String value, JourneyDraft.DurationUnit unit) {
        try { return BigDecimal.valueOf(JourneyDraftCompiler.duration(value, unit), 3).stripTrailingZeros().toPlainString(); }
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
        for (int i = 0; i < rows.size(); i++) { var row = rows.get(i); row.number.setText("Step " + (i + 1)); row.refreshReferences(i); row.summary(); row.up.setEnabled(i > 0); row.down.setEnabled(i < rows.size() - 1); row.up.getAccessibleContext().setAccessibleName("Move step " + (i + 1) + " up"); row.down.getAccessibleContext().setAccessibleName("Move step " + (i + 1) + " down"); row.remove.getAccessibleContext().setAccessibleName("Remove step " + (i + 1)); }
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
            JComponent field = kind == AuthStep.Type.SECURE_INPUT && missingSecret ? row.secret : row.firstInput();
            if (message != null) InlineValidation.show(field, message);
            row.updateFields();
            InlineValidation.focus(field); return;
        }
    }
    /** @param path Indexed validation path. @param guidance Safe correction. @param focus Whether an explicit action may focus the input. */
    void showInvalid(String path, String guidance, boolean focus) {
        var match = STEP_PATH.matcher(path); if (!match.find()) return;
        int index = Integer.parseInt(match.group(1)); if (index >= rows.size()) return;
        var row = rows.get(index); JComponent target = path.contains("selector") ? row.selector : path.contains("triggerStepId") ? row.trigger : path.contains("pageRef") ? (row.type.getSelectedItem() == AuthStep.Type.EXPECT_POPUP ? row.popupName : row.pageChoice) : path.contains("checked") ? row.checked : path.contains("values") ? row.options : path.contains("key") ? row.key : path.contains("state") || path.contains("match") ? row.state : row.value;
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
        StepActionHelp.install(combo);
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
        final JComboBox<AuthStep.Type> type = UiTooltips.comboBox(AuthStep.Type.values());
        final JTextField selector = new PlaceholderTextField("CSS selector", 18), value = new PlaceholderTextField("Value / URL pattern / wait", 20);
        final PlaceholderPasswordField secret = new PlaceholderPasswordField("Secret value", 18);
        boolean secretProvided;
        final JComboBox<String> state = UiTooltips.comboBox(AuthStep.LOAD_STATES.toArray(String[]::new));
        final JLabel number = new JLabel(), valueCaption = new JLabel("Value"), stateCaption = new JLabel("Load state"), selectorCaption = new JLabel("Selector");
        final JToggleButton expanded = new JToggleButton();
        final JPanel inputs = new JPanel();
        final JPanel selectorLine, valueLine, stateLine, secretLine;
        final JComboBox<String> checked = UiTooltips.comboBox(new String[]{"", "true", "false"});
        final JComboBox<String> key = UiTooltips.comboBox(AuthStep.KEYS.toArray(String[]::new));
        final javax.swing.table.DefaultTableModel optionValues = new javax.swing.table.DefaultTableModel(new Object[]{"Option value"}, 0);
        final JTable options = UiTooltips.table(optionValues);
        final JTextField popupName = UiTooltips.textField(18);
        final JComboBox<Reference> trigger = UiTooltips.comboBox(), pageChoice = UiTooltips.comboBox();
        final JPanel checkedLine, optionsLine, keyLine, popupLine, triggerLine, pageLine;
        boolean updatingReferences;
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
            selectorLine = line(selectorCaption, selector); valueLine = line(valueCaption, value);
            stateLine = line(stateCaption, state); secretLine = line(new JLabel("Secure value"), secret);
            inputs.add(selectorLine); inputs.add(valueLine); inputs.add(stateLine); inputs.add(secretLine);
            checked.setRenderer(new DefaultListCellRenderer() { @Override public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean selected, boolean focus) {
                return super.getListCellRendererComponent(list, "true".equals(value) ? "Checked" : "false".equals(value) ? "Unchecked" : "Choose a state", index, selected, focus);
            } });
            key.setRenderer(new DefaultListCellRenderer() { @Override public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean selected, boolean focus) {
                putClientProperty("html.disable", true); return super.getListCellRendererComponent(list, "Control+Enter".equals(value) ? "Ctrl+Enter" : value, index, selected, focus);
            } });
            checkedLine = line(new JLabel("State"), checked); keyLine = line(new JLabel("Key"), key);
            var optionPanel = new JPanel(new BorderLayout(4, 4)); options.putClientProperty("terminateEditOnFocusLost", true);
            options.setPreferredScrollableViewportSize(new Dimension(240, 70)); options.getTableHeader().setReorderingAllowed(false);
            options.setDefaultRenderer(Object.class, new javax.swing.table.DefaultTableCellRenderer() { @Override public Component getTableCellRendererComponent(JTable table, Object value, boolean selected, boolean focus, int row, int column) {
                putClientProperty("html.disable", true); return super.getTableCellRendererComponent(table, value, selected, focus, row, column);
            } });
            optionPanel.add(new JScrollPane(options)); var optionButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
            var addOption = new JButton("Add value"); var removeOption = new JButton("Remove value");
            addOption.addActionListener(e -> optionValues.addRow(new Object[]{""}));
            removeOption.addActionListener(e -> { int selected = options.getSelectedRow(); if (selected >= 0) optionValues.removeRow(selected); });
            optionButtons.add(addOption); optionButtons.add(removeOption); optionPanel.add(optionButtons, BorderLayout.SOUTH);
            optionsLine = line(new JLabel("Dropdown options"), optionPanel);
            options.putClientProperty("validationMessage", optionPanel.getClientProperty("validationMessage"));
            options.putClientProperty("validationContainer", optionPanel.getClientProperty("validationContainer"));
            popupLine = line(new JLabel("Popup name"), popupName); triggerLine = line(new JLabel("Opening step"), trigger); pageLine = line(new JLabel("Page"), pageChoice);
            for (var combo : List.of(trigger, pageChoice)) combo.setRenderer(new DefaultListCellRenderer() {
                @Override public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean selected, boolean focus) {
                    putClientProperty("html.disable", true); return super.getListCellRendererComponent(list, value, index, selected, focus);
                }
            });
            for (var component : List.of(checkedLine, optionsLine, keyLine, popupLine, triggerLine, pageLine)) inputs.add(component);
            setOperation(JourneyDraft.StepInput.fromDefinition(definition).operation());
            add(header, BorderLayout.NORTH); add(inputs, BorderLayout.CENTER); inputs.setVisible(false); updateFields();
            type.addActionListener(e -> {
                var next = (AuthStep.Type) type.getSelectedItem();
                if (next == previous) return;
                remember(this, previous);
                boolean toText = recordingReview && previous == AuthStep.Type.SECURE_INPUT && next == AuthStep.Type.INPUT;
                boolean toSecret = recordingReview && previous == AuthStep.Type.INPUT && next == AuthStep.Type.SECURE_INPUT;
                boolean missing = toText && !secretProvided || toSecret && missingReviewValues.contains(id);
                char[] retained = toText && secretProvided ? secret.getPassword() : toSecret && !missing ? value.getText().toCharArray() : null;
                changingType = true;
                try {
                    if (previous == AuthStep.Type.SECURE_INPUT) { secret.setText(""); secretProvided = false; }
                    if (!next.requiresSelector() || !previous.requiresSelector()) selector.setText("");
                    value.setText(""); configureState(next, null); setOperation(JourneyDraft.defaultOperation(next)); missingReviewValues.remove(id);
                    if (toText && retained != null) value.setText(new String(retained));
                    if (toSecret && retained != null) { secret.setText(new String(retained)); secretProvided = true; }
                    if (missing) missingReviewValues.add(id);
                } finally { changingType = false; if (retained != null) Arrays.fill(retained, '\0'); }
                previous = next; renumber(); updateFields(); if (recordingReview) corrected.accept(id, next); notifyChanged(); activate(this, true);
            });
            state.addActionListener(e -> { updateFields(); notifyChanged(); });
            for (JTextField field : List.of(selector, value, secret)) field.getDocument().addDocumentListener(new DocumentChangeListener(() -> {
                if (field == secret) secretProvided = true;
                if (recordingReview && !changingType && (field == value || field == secret)) missingReviewValues.remove(id);
                summary(); notifyChanged();
            }));
            checked.addActionListener(e -> operationChanged()); key.addActionListener(e -> operationChanged());
            trigger.addActionListener(e -> operationChanged()); pageChoice.addActionListener(e -> operationChanged());
            optionValues.addTableModelListener(e -> operationChanged());
            options.addPropertyChangeListener("tableCellEditor", e -> {
                if (options.getEditorComponent() instanceof javax.swing.text.JTextComponent editor && !Boolean.TRUE.equals(editor.getClientProperty("optionEditObserved"))) {
                    editor.putClientProperty("optionEditObserved", true);
                    editor.getDocument().addDocumentListener(new DocumentChangeListener(() -> { if (!updatingReferences) { InlineValidation.clear(options); notifyChanged(); } }));
                }
            });
            popupName.getDocument().addDocumentListener(new DocumentChangeListener(() -> { if (!updatingReferences) { renumber(); notifyChanged(); } }));
            for (var shortcut : new String[][]{{"alt UP", "Up"}, {"alt DOWN", "Down"}, {"alt DELETE", "Remove"}}) {
                getInputMap(WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(KeyStroke.getKeyStroke(shortcut[0]), shortcut[1]);
                getActionMap().put(shortcut[1], new AbstractAction() { @Override public void actionPerformed(java.awt.event.ActionEvent event) { move(shortcut[1]); } });
            }
        }
        /** Shows only fields owned by the current type and keeps missing values distinct from supplied empty input. */
        private void updateFields() {
            var kind = (AuthStep.Type) type.getSelectedItem(); selectorLine.setVisible(kind.requiresSelector());
            selectorCaption.setText(kind == AuthStep.Type.ENTER_FRAME ? "Frame selector" : "Selector");
            valueLine.setVisible(kind == AuthStep.Type.INPUT || kind == AuthStep.Type.WAIT_URL || kind == AuthStep.Type.WAIT_TIME);
            boolean glob = "glob".equals(state.getSelectedItem());
            valueCaption.setText(kind == AuthStep.Type.WAIT_TIME ? "Duration (seconds)" : kind == AuthStep.Type.WAIT_URL ? glob ? "URL pattern" : "Exact URL" : "Text");
            help(value, kind == AuthStep.Type.WAIT_TIME ? "Enter seconds, for example 2 or 0.5. Use a dot for decimals." : kind == AuthStep.Type.WAIT_URL ? glob ? "Use * within one URL segment, or ** across slashes. Example: **/dashboard. Regular expressions are not supported." : "Full URL, for example https://example.com/dashboard. The query string and trailing slash must also match." : "Enter the text to fill in. Leave empty to clear the field. Use Enter secret for sensitive values.");
            help(selector, kind == AuthStep.Type.ENTER_FRAME ? "Selector for an embedded frame, for example iframe[name=login]. Recorded selectors may use Playwright formats. Do not enter the frame URL or browser ID." : "Selector, for example #username or button[type=submit]. CSS and recorded Playwright selectors identify an element in the current page or frame. Do not enter JavaScript code.");
            stateCaption.setText(kind == AuthStep.Type.WAIT_SELECTOR ? "Condition" : kind == AuthStep.Type.WAIT_URL ? "Match" : "Load state");
            stateLine.setVisible(kind == AuthStep.Type.WAIT_LOAD_STATE || kind == AuthStep.Type.WAIT_SELECTOR || kind == AuthStep.Type.WAIT_URL); secretLine.setVisible(kind == AuthStep.Type.SECURE_INPUT); secret.setEnabled(kind == AuthStep.Type.SECURE_INPUT);
            if (kind == AuthStep.Type.WAIT_SELECTOR) help(state, "Present means the element exists, even if hidden. Removed means it no longer exists.");
            else if (kind == AuthStep.Type.WAIT_URL) help(state, "Exact URL compares the whole URL. URL pattern uses Playwright glob wildcards, such as **/dashboard.");
            checkedLine.setVisible(kind == AuthStep.Type.SET_CHECKED); optionsLine.setVisible(kind == AuthStep.Type.SELECT_OPTIONS);
            keyLine.setVisible(kind == AuthStep.Type.PRESS_KEY); popupLine.setVisible(kind == AuthStep.Type.EXPECT_POPUP);
            triggerLine.setVisible(kind == AuthStep.Type.EXPECT_POPUP && !reviewedPopups.contains(id)); pageLine.setVisible(kind == AuthStep.Type.SWITCH_PAGE);
            help(secret, "Enter the secret to fill in. Saved between sessions only if Remember secrets is on.");
            help(checked, "Choose the state after this step. Radio buttons can only be selected.");
            help(options, "Enter option values, not the visible labels. For <option value=admin>Administrator</option>, enter admin. Remove all rows to clear a multi-select. An empty row selects an empty option value.");
            help(key, "Choose Enter, Ctrl+Enter, Tab or Shift+Tab. Tab moves focus forward; Shift+Tab moves it backward.");
            help(popupName, "Name used by later Switch page steps. Use 1–32 lowercase letters, digits, hyphens or underscores; start with a letter. Example: popup-1. Reserve main for the initial tab.");
            help(trigger, rows.indexOf(this) + 1 < rows.size() && java.util.Set.of(AuthStep.Type.CLICK, AuthStep.Type.PRESS_KEY).contains(rows.get(rows.indexOf(this) + 1).type.getSelectedItem()) ? "Choose the next step that opens this popup." : "Add a Click element or Press key step immediately after this one.");
            help(pageChoice, "Choose where the next steps will run.");
            summary(); setMaximumSize(new Dimension(Integer.MAX_VALUE, getPreferredSize().height)); revalidate(); repaint();
        }
        /** @return First input belonging to this action. */
        JComponent firstInput() {
            var kind = (AuthStep.Type) type.getSelectedItem();
            if (kind.requiresSelector()) return selector;
            return switch (kind) {
                case WAIT_LOAD_STATE -> state; case EXPECT_POPUP -> popupName; case SWITCH_PAGE -> pageChoice;
                case PARENT_FRAME, MAIN_FRAME, CLOSE_PAGE -> type; default -> value;
            };
        }

        private void help(JComponent field, String text) { UiTooltips.set(field, text, 320); }

        private void operationChanged() { if (!updatingReferences) { InlineValidation.clear(options); InlineValidation.clear(key); summary(); notifyChanged(); } }

        JourneyDraft.Operation operation(AuthStep.Type kind) {
            return switch (kind) {
                case SET_CHECKED -> new JourneyDraft.Checked(String.valueOf(checked.getSelectedItem()));
                case SELECT_OPTIONS -> {
                    var values = new ArrayList<String>();
                    for (int i = 0; i < optionValues.getRowCount(); i++) values.add(options.isEditing() && options.getEditingRow() == i
                            && options.getEditorComponent() instanceof javax.swing.text.JTextComponent editor ? editor.getText() : String.valueOf(optionValues.getValueAt(i, 0)));
                    yield new JourneyDraft.Options(values);
                }
                case PRESS_KEY -> new JourneyDraft.Key(String.valueOf(key.getSelectedItem()));
                case EXPECT_POPUP -> new JourneyDraft.Popup(popupName.getText(), reference(trigger));
                case SWITCH_PAGE -> new JourneyDraft.PageTarget(reference(pageChoice));
                default -> null;
            };
        }

        void setOperation(JourneyDraft.Operation operation) {
            updatingReferences = true;
            try {
                checked.setModel(new DefaultComboBoxModel<>(new String[]{"", "true", "false"}));
                optionValues.setRowCount(0); key.setModel(new DefaultComboBoxModel<>(AuthStep.KEYS.toArray(String[]::new))); popupName.setText("");
                trigger.setModel(new DefaultComboBoxModel<>()); pageChoice.setModel(new DefaultComboBoxModel<>());
                if (operation != null) switch (operation) {
                    case JourneyDraft.Checked c -> { if (!java.util.Set.of("", "true", "false").contains(c.checked())) checked.addItem(c.checked()); checked.setSelectedItem(c.checked()); }
                    case JourneyDraft.Options o -> o.values().forEach(value -> optionValues.addRow(new Object[]{value}));
                    case JourneyDraft.Key k -> { if (!AuthStep.KEYS.contains(k.key())) key.addItem(k.key()); key.setSelectedItem(k.key()); }
                    case JourneyDraft.Popup p -> { popupName.setText(p.pageRef()); trigger.addItem(new Reference(p.triggerStepId(), p.triggerStepId().isEmpty() ? "Choose opening step" : "Unavailable opening step")); }
                    case JourneyDraft.PageTarget p -> pageChoice.addItem(new Reference(p.pageRef(), p.pageRef().isEmpty() ? "Choose a page" : "Unavailable page"));
                }
            } finally { updatingReferences = false; }
        }

        private String reference(JComboBox<Reference> combo) { return combo.getSelectedItem() instanceof Reference ref ? ref.id() : ""; }

        void refreshReferences(int index) {
            updatingReferences = true;
            try {
                String previousTrigger = reference(trigger), previousPage = reference(pageChoice);
                var triggers = new ArrayList<Reference>(); triggers.add(new Reference("", "Choose opening step"));
                if (index + 1 < rows.size()) {
                    var next = rows.get(index + 1); var kind = (AuthStep.Type) next.type.getSelectedItem();
                    if (kind == AuthStep.Type.CLICK || kind == AuthStep.Type.PRESS_KEY) triggers.add(new Reference(next.id.toString(), "Step " + (index + 2) + " — " + kind.label()));
                }
                var pages = new ArrayList<Reference>(); pages.add(new Reference("", "Choose a page")); pages.add(new Reference("main", "Initial tab"));
                for (int i = 0; i < index; i++) { var row = rows.get(i); if (row.type.getSelectedItem() == AuthStep.Type.EXPECT_POPUP && !row.popupName.getText().isBlank()) pages.add(new Reference(row.popupName.getText(), row.popupName.getText())); }
                references(trigger, triggers, previousTrigger, "Unavailable opening step"); references(pageChoice, pages, previousPage, "Unavailable page");
            } finally { updatingReferences = false; }
        }

        private void references(JComboBox<Reference> combo, List<Reference> choices, String selected, String invalid) {
            if (choices.stream().noneMatch(choice -> choice.id().equals(selected))) choices.add(new Reference(selected, invalid));
            combo.setModel(new DefaultComboBoxModel<>(choices.toArray(Reference[]::new)));
            choices.stream().filter(choice -> choice.id().equals(selected)).findFirst().ifPresent(combo::setSelectedItem);
        }
        /** Summaries contain action/selector metadata, never entered text or secure values. */
        void summary() {
            var kind = (AuthStep.Type) type.getSelectedItem();
            String detail = kind.requiresSelector() ? selector.getText() : kind == AuthStep.Type.WAIT_TIME ? value.getText() + " seconds" : "";
            if (detail.length() > 70) detail = detail.substring(0, 67) + "...";
            String condition = kind == AuthStep.Type.WAIT_SELECTOR ? " (" + state.getSelectedItem() + ")"
                    : kind == AuthStep.Type.PRESS_KEY ? " (" + ("Control+Enter".equals(key.getSelectedItem()) ? "Ctrl+Enter" : key.getSelectedItem()) + ")" : "";
            expanded.setText(number.getText() + " — " + kind.label() + condition + (detail.isBlank() ? "" : " · " + detail));
            expanded.setToolTipText("Expand or collapse this step. Alt+Up/Down moves it; Alt+Delete removes it.");
        }
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
