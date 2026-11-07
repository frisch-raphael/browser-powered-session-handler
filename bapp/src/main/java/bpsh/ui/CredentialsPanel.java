package bpsh.ui;

import bpsh.model.CredentialNames;
import bpsh.model.JourneyDefinition;
import bpsh.model.JourneyDraft;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import javax.swing.*;

/** Edits response tokens, captured cookies and their request destinations without runtime values. */
final class CredentialsPanel extends JPanel {
    private final JPanel content = new JPanel();
    private final List<Row> rows = new ArrayList<>();
    private final JButton add;
    private Runnable changed = () -> {};
    private boolean loading;
    private boolean nameLayoutPending;
    private final JLabel namingHelp = new JLabel("Name each credential to choose it individually in requests.");



    CredentialsPanel() {
        super(new BorderLayout(6, 6)); content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        var toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        add = UiIcons.button(UiIcons.Action.ADD, "Add token or cookie", () -> {
            addRow(new JourneyDraft.CredentialInput("", "json_path", "", "", "", "", "", "", "", "disabled", ""));
            var target = rows.stream().filter(r -> rows.size() > 1 && r.name.getText().isBlank()).findFirst().orElse(rows.getLast());
            activate(target); SwingUtilities.invokeLater(() -> { target.scrollRectToVisible(new Rectangle(0, 0, target.getWidth(), target.getHeight())); (rows.size() > 1 && target.name.getText().isBlank() ? target.name : target.origin).requestFocusInWindow(); });
            notifyChanged();
        });
        namingHelp.setVisible(false); toolbar.add(add); toolbar.add(namingHelp); add(toolbar, BorderLayout.NORTH); add(content, BorderLayout.CENTER);
    }
    void setChangeListener(Runnable listener) { changed = listener; }
    List<JourneyDraft.CredentialInput> snapshot() { return rows.stream().map(Row::snapshot).toList(); }

    /** Focuses only after explicit Save validation. */
    void focusInvalid(String message) {
        showInvalid(message, "Check this token setting.", true);
    }
    /** @param message Validated field path. @param guidance Sanitized correction. @param focus Whether an explicit action may scroll/focus the field. */
    void showInvalid(String message, String guidance, boolean focus) {
        if (rows.isEmpty()) return;
        int index = 0;
        var match = java.util.regex.Pattern.compile("tokens\\[(\\d+)\\]").matcher(message);
        if (match.find()) index = Math.min(rows.size() - 1, Integer.parseInt(match.group(1)));
        if (message.startsWith("injection.tokens[") && index < injectionInputs().size()) index = injectionInputs().get(index);
        var row = rows.get(index); Component target;
        if (message.startsWith("injection")) target = message.contains(".name:") ? row.destination : row.injection;
        else if (message.matches("extraction\\.tokens\\[\\d+]\\.name:.*")) { target = row.name; row.nameValidationActive = true; }
        else if (message.endsWith(".type:")) target = row.type;
        else if (message.contains("Origin") || message.contains("origin")) target = row.origin;
        else if (message.contains("domain")) target = row.domain;
        else if (message.contains("pathSubstring")) target = row.path;
        else if (message.contains("startRegex")) target = row.startRegex;
        else if (message.contains("endRegex")) target = row.endRegex;
        else if (message.contains(".path:")) target = row.cookiePath;
        else target = row.selector;
        InlineValidation.show((JComponent) target, guidance);
        if (focus) { activate(row); if (target == row.domain || target == row.cookiePath) { row.filtersToggle.setSelected(true); row.filters.setVisible(true); } InlineValidation.focus((JComponent) target); }
    }
    /** Checks all required names before Test or Copy. @return First invalid field path and safe guidance, or null. */
    String validateNames() {
        rows.forEach(row -> row.nameValidationActive = true);
        refresh();
        for (int index = 0; index < rows.size(); index++) {
            String problem = nameProblem(rows.get(index));
            if (problem != null) return "extraction.tokens[" + index + "].name: " + problem;
        }
        return null;
    }
    /** @param row Credential being edited. @return Its naming problem, including case-insensitive duplicates, or null. */
    private String nameProblem(Row row) {
        if (rows.size() < 2) return null;
        String name = row.name.getText().trim(), problem = CredentialNames.problem(name);
        if (problem != null) return problem;
        return rows.stream().filter(other -> other != row).map(other -> other.name.getText().trim())
                .anyMatch(other -> CredentialNames.problem(other) == null && name.equalsIgnoreCase(other)) ? CredentialNames.DUPLICATE : null;
    }
    /** Refreshes checked names without asking Swing to lay out a document while it is being edited. */
    private void namesEdited() {
        if (loading) return;
        refreshNameErrors();
        if (!nameLayoutPending) {
            nameLayoutPending = true;
            SwingUtilities.invokeLater(() -> { nameLayoutPending = false; refresh(); });
        }
    }
    /** Updates errors affected by a name edit, including duplicates in other checked rows. */
    private void refreshNameErrors() {
        for (var row : rows) {
            if (rows.size() < 2) { row.nameValidationActive = false; InlineValidation.clear(row.name); }
            else if (row.nameValidationActive) {
                String problem = nameProblem(row);
                if (problem == null) InlineValidation.clear(row.name); else InlineValidation.show(row.name, problem);
            }
        }
    }
    private List<Integer> injectionInputs() {
        var indices = new ArrayList<Integer>();
        for (int i = 0; i < rows.size(); i++) if (rows.get(i).type.getSelectedIndex() != 1) indices.add(i);
        return indices;
    }


    /** Restores raw selector text without validating incomplete extraction or destinations. */
    void setInputs(List<JourneyDraft.CredentialInput> inputs) {
        loading = true;
        try { rows.clear(); content.removeAll(); inputs.forEach(this::addRow); }
        finally { loading = false; }
        refresh();
    }
    void setDefinition(JourneyDefinition.Extraction definition) {
        var mappings = new ArrayList<JourneyDefinition.TokenInjection>();
        if (definition instanceof JourneyDefinition.CombinedExtraction combined) {
            for (var token : combined.tokens()) if (!(token.selector() instanceof JourneyDefinition.CookieExtraction)) mappings.add(new JourneyDefinition.TokenInjection(token.name(), mappings.isEmpty() ? JourneyDefinition.InjectionType.BEARER : JourneyDefinition.InjectionType.DISABLED, null));
        } else if (!(definition instanceof JourneyDefinition.CookieExtraction)) mappings.add(new JourneyDefinition.TokenInjection(null, JourneyDefinition.InjectionType.BEARER, null));
        setDefinition(definition, JourneyDefinition.Injection.perToken(mappings));
    }
    /** Populates each response token with its saved destination. */
    void setDefinition(JourneyDefinition.Extraction definition, JourneyDefinition.Injection injection) {
        loading = true;
        try {
            rows.clear(); content.removeAll();
            if (definition instanceof JourneyDefinition.CombinedExtraction combined) {
                for (var token : combined.tokens()) addSelector(token.name(), token.selector(), injection, false);
            } else addSelector("", definition, injection, true);
        } finally { loading = false; }
        refresh();
    }
    private void addSelector(String name, JourneyDefinition.Extraction selector, JourneyDefinition.Injection injection, boolean single) {
        String kind = "json_path", origin = "", path = "", value = "", domain = "", cookiePath = "", start = "", end = "";
        if (selector instanceof JourneyDefinition.JsonExtraction json) { origin = json.responseOrigin().toString(); path = json.pathSubstring(); value = json.jsonPath(); }
        else if (selector instanceof JourneyDefinition.RegexExtraction regex) { kind = "regex"; origin = regex.responseOrigin().toString(); path = regex.pathSubstring(); start = regex.startRegex(); end = regex.endRegex(); }
        else if (selector instanceof JourneyDefinition.CookieExtraction cookie) { kind = "cookie"; origin = cookie.originUrl().toString(); value = cookie.name(); domain = empty(cookie.domain()); cookiePath = empty(cookie.path()); }
        String mode = "disabled", destination = "";
        for (var mapping : injection.tokens()) if (java.util.Objects.equals(mapping.tokenName(), single ? null : name)) { mode = mapping.type().wire(); destination = empty(mapping.name()); }
        addRow(new JourneyDraft.CredentialInput(name, kind, origin, path, value, domain, cookiePath, start, end, mode, destination));
    }
    private static String empty(String value) { return value == null ? "" : value; }
    private void addRow(JourneyDraft.CredentialInput input) { if (rows.size() >= 16) return; var row = new Row(input); rows.add(row); content.add(row); refresh(); }
    private void refresh() {
        namingHelp.setVisible(rows.size() > 1);
        refreshNameErrors();
        for (var row : rows) {
            row.nameLine.setVisible(rows.size() > 1); row.remove.setEnabled(rows.size() > 1);
            row.summary();
            row.body.invalidate();
            row.setMaximumSize(new Dimension(Integer.MAX_VALUE, row.getPreferredSize().height));
        }
        add.setEnabled(rows.size() < 16); content.revalidate(); content.repaint();
    }
    private void notifyChanged() { if (!loading) changed.run(); }
    /** Keeps long credential sets readable while preserving every hidden input's identity. */
    private void activate(Row selected) { for (var row : rows) { row.expanded.setSelected(row == selected); row.body.setVisible(row == selected); } refresh(); }

    private final class Row extends JPanel {
        final JComboBox<String> type = new JComboBox<>(new String[]{"JSON response", "Cookie", "Text between patterns"});
        final JComboBox<String> injection = new JComboBox<>(new String[]{"Disabled", "Bearer", "Header", "Cookie"});
        final JTextField name = new JTextField(), origin = new JTextField(), path = new JTextField(), selector = new JTextField(), domain = new JTextField(), cookiePath = new JTextField(), startRegex = new JTextField(), endRegex = new JTextField(), destination = new JTextField();
        final JLabel originLabel = new JLabel(), selectorLabel = new JLabel(), destinationLabel = new JLabel();
        final JPanel nameLine, pathLine, selectorLine, domainLine, cookiePathLine, startLine, endLine, injectionLine, destinationLine;
        final JButton remove;
        final JToggleButton expanded = new JToggleButton(), filtersToggle = new JToggleButton("Cookie filters (optional)");
        final JPanel body = new JPanel(), filters = new JPanel(), usePanel = new JPanel();
        int previousType;
        String previousInjection;
        boolean nameValidationActive;

        Row(JourneyDraft.CredentialInput input) {
            setLayout(new GridBagLayout());
            type.setSelectedIndex(input.cookie() ? 1 : input.type().equals("regex") ? 2 : 0);
            previousType = type.getSelectedIndex();
            injection.setSelectedItem(capitalize(input.injection()));
            previousInjection = injection.getSelectedItem().toString();
            name.setText(input.name()); origin.setText(input.origin()); path.setText(input.path()); selector.setText(input.selector()); domain.setText(input.domain()); cookiePath.setText(input.cookiePath()); startRegex.setText(input.startRegex()); endRegex.setText(input.endRegex()); destination.setText(input.destination());
            var header = new JPanel(new BorderLayout(6, 0)); expanded.putClientProperty("html.disable", true); expanded.setHorizontalAlignment(SwingConstants.LEFT); expanded.setSelected(rows.isEmpty());
            expanded.addActionListener(e -> activate(expanded.isSelected() ? this : null)); header.add(expanded);
            remove = UiIcons.button(UiIcons.Action.REMOVE, "Remove token", () -> { rows.remove(this); content.remove(this); refresh(); notifyChanged(); }); header.add(remove, BorderLayout.EAST);
            var placement = new GridBagConstraints(); placement.gridx = 0; placement.gridy = 0; placement.weightx = 1; placement.fill = GridBagConstraints.HORIZONTAL; placement.insets = new Insets(8, 8, 0, 8); add(header, placement);
            body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS)); body.setVisible(expanded.isSelected()); placement.gridy = 1; placement.insets = new Insets(12, 8, 20, 8); add(body, placement);
            nameLine = line(new JLabel("Credential name"), name, "1-64 characters: A-Z, a-z, 0-9, _ or -. Start with a letter or digit. Names must be unique, ignoring case.", CredentialsPanel.this::namesEdited); body.add(nameLine);
            name.addFocusListener(new java.awt.event.FocusAdapter() {
                @Override public void focusLost(java.awt.event.FocusEvent event) {
                    if (!loading && rows.contains(Row.this)) { nameValidationActive |= nameProblem(Row.this) != null; refresh(); }
                }
            });
            var capture = new JPanel(); capture.setLayout(new BoxLayout(capture, BoxLayout.Y_AXIS)); body.add(paddedGroup(capture, "Capture from browser", 0));
            capture.add(line(new JLabel("Source"), type, "")); capture.add(line(originLabel, origin, ""));
            pathLine = line(new JLabel("Path contains"), path, "Match part of the response URL path, excluding its query string."); capture.add(pathLine);
            selectorLine = line(selectorLabel, selector, ""); capture.add(selectorLine);
            startLine = line(new JLabel("Start regex"), startRegex, "RE2 expression before the token. For <token>example</token>, start <token> and end </token> capture example. Boundaries are excluded."); capture.add(startLine);
            endLine = line(new JLabel("End regex"), endRegex, "RE2 expression after the token. Capture ends before the next match; the first complete pair wins. Boundaries are excluded."); capture.add(endLine);
            filters.setLayout(new BoxLayout(filters, BoxLayout.Y_AXIS)); filters.setVisible(!input.domain().isBlank() || !input.cookiePath().isBlank()); filtersToggle.setSelected(filters.isVisible());
            filtersToggle.addActionListener(e -> { filters.setVisible(filtersToggle.isSelected()); refresh(); }); capture.add(filtersToggle); capture.add(filters);
            domainLine = line(new JLabel("Exact domain (optional)"), domain, "Distinguish same-name cookies by their exact stored domain."); filters.add(domainLine);
            cookiePathLine = line(new JLabel("Exact path (optional)"), cookiePath, "Distinguish same-name cookies by their exact stored path."); filters.add(cookiePathLine);
            var useFields = new JPanel(); useFields.setLayout(new BoxLayout(useFields, BoxLayout.Y_AXIS));
            usePanel.setLayout(new BorderLayout()); usePanel.add(paddedGroup(useFields, "Use on matching requests", 16)); body.add(usePanel);
            injectionLine = line(new JLabel("Inject into"), injection, "Destination on requests matching Session handling. Disabled keeps this token available through BPSH tags."); useFields.add(injectionLine);
            destinationLine = line(destinationLabel, destination, ""); useFields.add(destinationLine);
            mode();
            type.addActionListener(e -> {
                if (type.getSelectedIndex() == previousType) return;
                boolean cookie = type.getSelectedIndex() == 1;
                loading = true;
                try {
                    if (cookie != (previousType == 1)) { origin.setText(""); path.setText(""); }
                    selector.setText(""); domain.setText(""); cookiePath.setText(""); startRegex.setText(""); endRegex.setText("");
                    if (cookie) { injection.setSelectedItem("Disabled"); destination.setText(""); }
                    previousType = type.getSelectedIndex();
                }
                finally { loading = false; }
                mode(); refresh(); notifyChanged();
            });
            injection.addActionListener(e -> {
                String selected = injection.getSelectedItem().toString();
                if (selected.equals(previousInjection)) return;
                previousInjection = selected;
                destination.setText("");
                mode(); refresh(); notifyChanged();
            });
            for (var field : List.of(name, origin, path, selector, domain, cookiePath, startRegex, endRegex, destination)) field.getDocument().addDocumentListener(new DocumentChangeListener(() -> {
                summary(); notifyChanged();
            }));
        }
        private void mode() {
            boolean cookie = type.getSelectedIndex() == 1, regex = type.getSelectedIndex() == 2;
            originLabel.setText(cookie ? "Capture URL" : "Response origin"); selectorLabel.setText(cookie ? "Cookie name" : "JSON path");
            String originHelp = cookie ? "A page where this cookie is available after you sign in." : "Exact origin of the token response, for example https://login.example.";
            String selectorHelp = cookie ? "Capture the cookie with this name. Its value replaces the cookie with the same name in matching requests." : "Path to the token string using dotted keys and array indexes, for example data.tokens[0].value.";
            origin.setToolTipText(originHelp); originLabel.setToolTipText(originHelp); selector.setToolTipText(selectorHelp); selectorLabel.setToolTipText(selectorHelp);
            type.setToolTipText(cookie ? null : regex ? "Capture text between start and end regex matches in a UTF-8 response body, up to 1 MiB. Matching spans line breaks." : "Read a token string from a matching JSON response.");
            pathLine.setVisible(!cookie); selectorLine.setVisible(!regex); domainLine.setVisible(cookie); cookiePathLine.setVisible(cookie); startLine.setVisible(regex); endLine.setVisible(regex);
            filtersToggle.setVisible(cookie); filters.setVisible(cookie && filtersToggle.isSelected());
            injectionLine.setVisible(!cookie); destinationLine.setVisible(!cookie && injection.getSelectedIndex() >= 2);
            usePanel.setVisible(!cookie);
            destinationLabel.setText(injection.getSelectedIndex() == 2 ? "Header name" : "Cookie name");
            destination.setToolTipText(injection.getSelectedIndex() == 2 ? "Header to replace with the raw token, for example X-CSRF-Token. Bearer adds its own prefix to Authorization." : "Cookie to replace with the raw token, for example csrf.");
            destinationLabel.setToolTipText(destination.getToolTipText());
        }
        /** Uses configured names and source type, never captured credential values. */
        private void summary() { String title = name.getText().isBlank() ? "Credential " + (rows.indexOf(this) + 1) : name.getText(); expanded.setText(title + " — " + type.getSelectedItem()); expanded.setToolTipText("Expand or collapse this credential."); }
        private JourneyDraft.CredentialInput snapshot() { return new JourneyDraft.CredentialInput(name.getText(), type.getSelectedIndex() == 1 ? "cookie" : type.getSelectedIndex() == 2 ? "regex" : "json_path", origin.getText(), path.getText(), selector.getText(), domain.getText(), cookiePath.getText(), startRegex.getText(), endRegex.getText(), injection.getSelectedItem().toString().toLowerCase(java.util.Locale.ROOT), destination.getText()); }
    }
    private static String capitalize(String value) { return Character.toUpperCase(value.charAt(0)) + value.substring(1); }
    /** Keeps spacing in layout constraints so host border theming cannot remove it. */
    private static JPanel paddedGroup(JPanel fields, String title, int separation) {
        var frame = new JPanel(new GridBagLayout()); frame.setBorder(BorderFactory.createTitledBorder(title));
        var placement = new GridBagConstraints(); placement.weightx = 1; placement.fill = GridBagConstraints.HORIZONTAL;
        placement.insets = new Insets(8, 12, 12, 12); frame.add(fields, placement);
        var group = new JPanel(new GridBagLayout()); placement.insets = new Insets(separation, 0, 0, 0); group.add(frame, placement); return group;
    }
    private static JPanel line(JLabel label, JComponent input, String help) {
        return line(label, input, help, () -> InlineValidation.clear(input));
    }
    /** @param label Field caption. @param input Existing editor. @param help Plain tooltip. @param onEdit Updates validation after an edit. @return Aligned field and guidance. */
    private static JPanel line(JLabel label, JComponent input, String help, Runnable onEdit) {
        var row = new JPanel(new GridBagLayout()); var placement = new GridBagConstraints();
        placement.gridx = 0; placement.gridy = 0; placement.anchor = GridBagConstraints.WEST; placement.insets = new Insets(6, 0, 6, 12);
        label.setLabelFor(input); label.setToolTipText(help); input.setToolTipText(help); row.add(label, placement);
        placement.gridx = 1; placement.weightx = 1; placement.fill = GridBagConstraints.HORIZONTAL; placement.insets = new Insets(6, 0, 6, 0);
        row.add(InlineValidation.wrap(input, onEdit), placement); return row;
    }
}
