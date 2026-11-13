package bpsh.burp.ui;

import bpsh.request.RequestSettings;
import bpsh.burp.http.ProxyListeners;
import bpsh.journey.JourneyDefinition;
import java.awt.*;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DocumentFilter;

/** Ordered session-handling rules with inline scope and expiration settings. */
final class AutomaticRulesPanel extends JPanel {
    /** Editor-only URL choices; persisted state derives from the typed condition. */
    enum Mode { BURP_SCOPE, ALL_REQUESTS, SINGLE_URL }
    /** Stable scoped identity and literal display label from the saved registry. */
    record Option(RequestSettings.JourneySelection key, String label) {
        @Override public String toString() { return label; }
    }
    /** Keeps incomplete edits local until the full rules snapshot validates. */
    private record Draft(boolean enabled, RequestSettings.JourneySelection journey, Mode mode, String prefix,
                         boolean detect, JourneyDefinition.RecoveryMode recovery, String status, String pattern, boolean regex, Integer port) {}
    private final List<Draft> rows = new ArrayList<>();
    private final Map<RequestSettings.JourneySelection, Option> options = new LinkedHashMap<>();
    private final JComboBox<Option> available = new JComboBox<>();
    private final Model model = new Model();
    final JTable table = new JTable(model);
    private final JScrollPane tableScroll = new JScrollPane(table);
    final JComboBox<Mode> urlMode = new JComboBox<>(Mode.values());
    final JTextField prefix = new JTextField(32), failureStatus = new JTextField("401", 8), pattern = new JTextField(32);
    final JCheckBox useRegex = new JCheckBox("Use regex");
    final JComboBox<Port> proxyPort = new JComboBox<>();
    private List<ProxyListeners.Choice> listeners = List.of();
    private final JLabel listenerStatus = new JLabel();
    private Runnable refreshListeners = () -> {};
    /** Literal port label retaining saved missing and stopped choices. */
    record Port(Integer value, boolean configured, boolean running) {
        @Override public String toString() { return value == null ? "Any listener" : value + (!configured ? " (not configured)" : !running ? " (stopped)" : ""); }
    }
    final JCheckBox detect = new JCheckBox("Detect expired sessions");
    final JComboBox<JourneyDefinition.RecoveryMode> recoveryMode = new JComboBox<>(JourneyDefinition.RecoveryMode.values());
    private final JPanel detail = new JPanel(new GridBagLayout());
    private final JLabel selected = new JLabel("Select a rule to configure its URL scope and session expiration.");
    private final JButton add, up, down, remove;
    private Runnable changed = () -> {};
    private boolean loading;
    private long revision;
    private enum Input { URL, STATUS, RESPONSE, GROUP }
    private record Problem(int row, Input input, String guidance) {}
    private Problem problem;

    /** Builds a theme-native list whose order is never changed by sorting. */
    AutomaticRulesPanel() {
        setLayout(new BorderLayout(0, 10));
        ((AbstractDocument) failureStatus.getDocument()).setDocumentFilter(new StatusDigits());
        var top = new JPanel(new BorderLayout(8, 6));
        top.add(text("Matching journeys run from top to bottom. Cached sessions are reused."), BorderLayout.NORTH);
        var actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        available.setPrototypeDisplayValue(new Option(null, "Customer portal authentication"));
        actions.add(available); add = UiIcons.button(UiIcons.Action.ADD, "Add automatic journey", this::addSelected); actions.add(add);
        up = UiIcons.button(UiIcons.Action.UP, "Move rule up", () -> move(-1)); down = UiIcons.button(UiIcons.Action.DOWN, "Move rule down", () -> move(1));
        remove = UiIcons.button(UiIcons.Action.REMOVE, "Remove automatic rule", this::removeSelected);
        actions.add(up); actions.add(down); actions.add(remove); top.add(actions, BorderLayout.CENTER); add(top, BorderLayout.NORTH);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION); table.setRowHeight(table.getFontMetrics(table.getFont()).getHeight() + 10);
        table.getColumnModel().getColumn(0).setMaxWidth(55); table.setAutoCreateRowSorter(false);
        var literal = new DefaultTableCellRenderer(); literal.putClientProperty("html.disable", true); table.setDefaultRenderer(Object.class, literal);
        table.getSelectionModel().addListSelectionListener(e -> { if (!e.getValueIsAdjusting() && !loading) populate(); });
        table.addMouseListener(new java.awt.event.MouseAdapter() { @Override public void mousePressed(java.awt.event.MouseEvent e) { table.setFocusable(true); table.requestFocusInWindow(); } });
        var center = new JPanel(new BorderLayout(0, 12)); center.add(InlineValidation.wrap(tableScroll), BorderLayout.NORTH);
        var details = new JPanel(new BorderLayout(0, 8)); selected.putClientProperty("html.disable", true); details.add(selected, BorderLayout.NORTH);
        row("URL handling", urlMode, 0); row("URL", prefix, 1); row("", useRegex, 2); row("Proxy port", proxyPort, 3); row("", listenerStatus, 4); row("", detect, 5); row("Detect by", recoveryMode, 6); row("Failure status", failureStatus, 7); row("RE2 expression", pattern, 8);
        var stretch = new GridBagConstraints(); stretch.gridy = 9; stretch.weighty = 1; detail.add(Box.createVerticalGlue(), stretch);
        details.add(detail, BorderLayout.CENTER); center.add(details, BorderLayout.CENTER); add(center, BorderLayout.CENTER);
        refreshPresentation();
        useRegex.setToolTipText("Regex matched anywhere in the URL.");
        useRegex.addActionListener(e -> edited()); proxyPort.addActionListener(e -> edited());
        proxyPort.addPopupMenuListener(new javax.swing.event.PopupMenuListener() {
            @Override public void popupMenuWillBecomeVisible(javax.swing.event.PopupMenuEvent e) { refreshListeners.run(); }
            @Override public void popupMenuWillBecomeInvisible(javax.swing.event.PopupMenuEvent e) {}
            @Override public void popupMenuCanceled(javax.swing.event.PopupMenuEvent e) {}
        });
        addHierarchyListener(e -> { if ((e.getChangeFlags() & java.awt.event.HierarchyEvent.SHOWING_CHANGED) != 0 && isShowing()) refreshListeners.run(); });
        urlMode.addActionListener(e -> edited()); recoveryMode.addActionListener(e -> edited()); detect.addActionListener(e -> edited());
        for (var field : List.of(prefix, failureStatus, pattern)) field.getDocument().addDocumentListener(new DocumentChangeListener(this::edited));
        prefix.setToolTipText("Match the beginning of the request URL, for example https://app.example/api/.");
        detect.setToolTipText("A matching response starts shared reauthentication and one replay per request. Failed recovery pauses this journey until Test login succeeds. Configured cache expiry still applies.");
        pattern.setToolTipText("RE2 expression searched in the response body. A match authorizes shared reauthentication and at most one replay of the affected request.");
        refresh(); populate();
    }

    /** Restores task labels and compact list geometry after Burp applies its component theme. */
    void refreshPresentation() {
        var optionRenderer = new DefaultListCellRenderer() {
            @Override public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean selected, boolean focus) {
                return super.getListCellRendererComponent(list, value == null ? options.isEmpty() ? "No saved journeys" : "All saved journeys added" : value, index, selected, focus);
            }
        }; optionRenderer.putClientProperty("html.disable", true); available.setRenderer(optionRenderer);
        friendly(urlMode); friendly(recoveryMode);
        var literal = new DefaultTableCellRenderer(); literal.putClientProperty("html.disable", true); table.setDefaultRenderer(Object.class, literal);
        table.getColumnModel().getColumn(0).setMaxWidth(55);
        table.setRowHeight(table.getFontMetrics(table.getFont()).getHeight() + 10);
        tableScroll.setColumnHeaderView(table.getTableHeader()); tableScroll.setPreferredSize(new Dimension(680, 175)); tableScroll.setMinimumSize(new Dimension(0, 110));
        revalidate(); repaint();
    }

    /** @param condition Persisted typed restriction. @return Editor URL choice. */
    private static Mode mode(RequestSettings.UrlCondition condition) {
        return condition instanceof RequestSettings.AllRequests ? Mode.ALL_REQUESTS : condition instanceof RequestSettings.BurpScope ? Mode.BURP_SCOPE : Mode.SINGLE_URL;
    }
    /** @param action Coalesced asynchronous host refresh request. */
    void onListenerRefresh(Runnable action) { refreshListeners = action; }
    /** @param choices Latest successfully read configured ports. @param failure Safe refresh error or null. */
    void setListeners(List<ProxyListeners.Choice> choices, String failure) {
        if (failure == null) listeners = List.copyOf(choices);
        listenerStatus.setText(failure == null ? "" : failure);
        boolean before = loading; loading = true;
        try { int selected = table.getSelectedRow(); populatePorts(selected < 0 ? null : rows.get(selected).port()); }
        finally { loading = before; }
    }
    /** @param saved Explicit saved restriction, retained even when no longer configured. */
    private void populatePorts(Integer saved) {
        proxyPort.removeAllItems(); proxyPort.addItem(new Port(null,true,true));
        for (var choice : listeners) proxyPort.addItem(new Port(choice.port(),true,choice.running()));
        if (saved != null && listeners.stream().noneMatch(c -> c.port() == saved)) proxyPort.addItem(new Port(saved,false,false));
        for (int i=0;i<proxyPort.getItemCount();i++) if (java.util.Objects.equals(proxyPort.getItemAt(i).value(),saved)) proxyPort.setSelectedIndex(i);
    }
    /** Installs the controller's debounced autosave notification. */
    void onChange(Runnable action) { changed = action; }
    /** Publishes saved labels without replacing incomplete rule edits or missing identities. */
    void setJourneys(List<Option> journeys) {
        int selectedRow = table.getSelectedRow(); loading = true;
        var previous = (Option) available.getSelectedItem(); options.clear(); journeys.forEach(o -> options.put(o.key(), o));
        try { refreshAvailable(previous == null ? null : previous.key()); model.fireTableDataChanged(); if (selectedRow >= 0 && selectedRow < rows.size()) table.setRowSelectionInterval(selectedRow, selectedRow); }
        finally { loading = false; }
        populate();
    }
    /** Populates persisted rules without saving or starting authentication. */
    void setRules(List<RequestSettings.AutomaticRule> rules) {
        invalidateValidation();
        loading = true;
        try { rows.clear(); for (var r : rules) rows.add(new Draft(r.enabled(), r.journey(), mode(r.url()), r.url() instanceof RequestSettings.Prefix p ? p.value().toString() : r.url() instanceof RequestSettings.Regex regex ? regex.value() : "", r.recovery().enabled(), r.recovery().mode(), r.recovery().statusCode() == null ? "401" : r.recovery().statusCode().toString(), r.recovery().pattern() == null ? "" : r.recovery().pattern(), r.url() instanceof RequestSettings.Regex, r.proxyPort())); model.fireTableDataChanged(); if (!rows.isEmpty()) table.setRowSelectionInterval(0, 0); }
        finally { loading = false; }
        refresh(); populate();
    }
    /** Captures the exact local draft generation without exposing field values. Selection does not change it. */
    long revision() { return revision; }
    /** Attributes safe compiler guidance without selecting another row during background validation. */
    boolean showInvalid(String message, String guidance, boolean focus) {
        if (message == null) return false;
        int row = -1; Input input = Input.GROUP;
        var path = java.util.regex.Pattern.compile("^controls\\.rules\\[([0-9]{1,2})]\\.([^:]+)(?=:|$)").matcher(message);
        var local = java.util.regex.Pattern.compile("^Rule ([1-9][0-9]?): ").matcher(message);
        if (path.find()) {
            row = Integer.parseInt(path.group(1)); String field = path.group(2);
            input = field.equals("url") || field.startsWith("url.") ? Input.URL
                    : field.equals("recovery.statusCode") ? Input.STATUS : field.equals("recovery.pattern") ? Input.RESPONSE : Input.GROUP;
        } else if (local.find()) {
            row = Integer.parseInt(local.group(1)) - 1;
            input = message.contains("failure status") ? Input.STATUS : Input.URL;
        } else if (!message.startsWith("controls.rules")) return false;
        problem = new Problem(row, input, guidance);
        if (focus && row >= 0 && row < rows.size()) table.setRowSelectionInterval(row, row);
        refreshValidation();
        if (focus) { var target = problemInput(); if (target != null) InlineValidation.focus(target); }
        return true;
    }
    private JComponent problemInput() {
        if (problem == null || problem.row() != table.getSelectedRow()) return null;
        JComponent input = switch (problem.input()) { case URL -> prefix; case STATUS -> failureStatus; case RESPONSE -> pattern; case GROUP -> null; };
        return input != null && input.isVisible() ? input : null;
    }
    private void refreshValidation() {
        InlineValidation.clear(prefix); InlineValidation.clear(pattern); InlineValidation.clear(tableScroll); validateFailureStatus();
        if (problem != null) InlineValidation.show(problemInput() == null ? tableScroll : problemInput(), problem.guidance());
    }
    private void invalidateValidation() {
        revision++; problem = null;
        for (var input : List.of(prefix, failureStatus, pattern, tableScroll)) InlineValidation.clear(input);
    }
    /** Captures every row in visible order; incomplete active fields reject the whole autosave. */
    List<RequestSettings.AutomaticRule> snapshot() {
        var result = new ArrayList<RequestSettings.AutomaticRule>();
        for (int i = 0; i < rows.size(); i++) {
            var d = rows.get(i); RequestSettings.UrlCondition url; Integer status = null;
            try { url = switch(d.mode()) {
                case ALL_REQUESTS -> new RequestSettings.AllRequests();
                case BURP_SCOPE -> new RequestSettings.BurpScope();
                case SINGLE_URL -> d.regex() ? new RequestSettings.Regex(d.prefix()) : new RequestSettings.Prefix(URI.create(d.prefix().trim()));
            }; }
            catch (RuntimeException ex) { throw new IllegalArgumentException("Rule " + (i + 1) + ": enter an absolute HTTP(S) URL prefix."); }
            if (d.recovery() != JourneyDefinition.RecoveryMode.REGEX) {
                status = d.detect() ? statusCode(d.status()) : Integer.valueOf(401);
                if (status == null) throw new IllegalArgumentException("Rule " + (i + 1) + ": failure status must be between 100 and 599.");
            }
            var recovery = new JourneyDefinition.Recovery(d.detect(), d.recovery(), status, d.recovery() == JourneyDefinition.RecoveryMode.STATUS_CODE ? null : d.detect() ? d.pattern() : "session expired");
            result.add(new RequestSettings.AutomaticRule(d.enabled(), d.journey(), url, d.port(), recovery));
        }
        return List.copyOf(result);
    }
    /** Adds a saved identity once, initially enabled with status-401 expiration detection. */
    private void addSelected() {
        var o = (Option) available.getSelectedItem(); if (o == null || rows.size() >= 64) return;
        rows.add(new Draft(true, o.key(), Mode.BURP_SCOPE, "", true, JourneyDefinition.RecoveryMode.STATUS_CODE, "401", "", false, null));
        invalidateValidation();
        model.fireTableDataChanged(); table.setRowSelectionInterval(rows.size() - 1, rows.size() - 1); refresh(); changed.run();
    }
    /** Removes the selected rule, retaining the saved journey itself. */
    private void removeSelected() { int i = table.getSelectedRow(); if (i < 0) return; rows.remove(i); invalidateValidation(); model.fireTableDataChanged(); if (!rows.isEmpty()) table.setRowSelectionInterval(Math.min(i, rows.size() - 1), Math.min(i, rows.size() - 1)); refresh(); populate(); changed.run(); }
    /** Moves the selected rule one position without sorting or changing its identity. */
    private void move(int delta) { int i = table.getSelectedRow(), target = i + delta; if (i < 0 || target < 0 || target >= rows.size()) return; java.util.Collections.swap(rows, i, target); invalidateValidation(); model.fireTableDataChanged(); table.setRowSelectionInterval(target, target); refresh(); changed.run(); }
    /** Captures edits without allowing a partial rule to mutate applied controls. */
    private void edited() {
        if (loading) return; int i = table.getSelectedRow(); if (i < 0) return; var d = rows.get(i);
        loading = true;
        try {
            if (urlMode.getSelectedItem() != d.mode() && urlMode.getSelectedItem() != Mode.SINGLE_URL) prefix.setText("");
            if (!detect.isSelected() || recoveryMode.getSelectedItem() != d.recovery()) {
                if (!detect.isSelected() || recoveryMode.getSelectedItem() == JourneyDefinition.RecoveryMode.REGEX) failureStatus.setText("");
                if (!detect.isSelected() || recoveryMode.getSelectedItem() == JourneyDefinition.RecoveryMode.STATUS_CODE) pattern.setText("");
            }
            if (detect.isSelected() && recoveryMode.getSelectedItem() != JourneyDefinition.RecoveryMode.REGEX
                    && (!d.detect() || d.recovery() == JourneyDefinition.RecoveryMode.REGEX) && failureStatus.getText().isEmpty())
                failureStatus.setText("401");
        } finally { loading = false; }
        rows.set(i, new Draft(d.enabled(), d.journey(), (Mode) urlMode.getSelectedItem(), prefix.getText(), detect.isSelected(), (JourneyDefinition.RecoveryMode) recoveryMode.getSelectedItem(), failureStatus.getText(), pattern.getText(), useRegex.isSelected(), proxyPort.getSelectedItem() instanceof Port port ? port.value() : null));
        invalidateValidation();
        model.fireTableRowsUpdated(i, i); conditional(); changed.run();
    }
    /** Displays the selected rule without invoking autosave. */
    private void populate() {
        int i = table.getSelectedRow(); loading = true;
        try { detail.setVisible(i >= 0); if (i >= 0) { var d = rows.get(i); selected.setText(label(d.journey())); urlMode.setSelectedItem(d.mode()); prefix.setText(d.prefix()); useRegex.setSelected(d.regex()); populatePorts(d.port()); detect.setSelected(d.detect()); recoveryMode.setSelectedItem(d.recovery()); failureStatus.setText(d.status()); pattern.setText(d.pattern()); } else selected.setText(rows.isEmpty() ? "Add a saved journey to configure automatic authentication." : "Select a rule to configure it."); }
        finally { loading = false; }
        conditional(); refreshButtons();
    }
    /** Shows only fields used by the selected matching and expiration modes. */
    private void conditional() { visible(prefix, urlMode.getSelectedItem() == Mode.SINGLE_URL); visible(useRegex, urlMode.getSelectedItem() == Mode.SINGLE_URL); prefix.setToolTipText(useRegex.isSelected() ? "Regex matched anywhere in the URL." : "Match the beginning of the request URL, for example https://app.example/api/."); visible(recoveryMode, detect.isSelected()); visible(failureStatus, detect.isSelected() && recoveryMode.getSelectedItem() != JourneyDefinition.RecoveryMode.REGEX); visible(pattern, detect.isSelected() && recoveryMode.getSelectedItem() != JourneyDefinition.RecoveryMode.STATUS_CODE); refreshValidation(); revalidate(); }
    /** Shows required/range guidance without moving focus or replacing unfinished input. */
    private void validateFailureStatus() {
        if (loading) return;
        if (table.getSelectedRow() >= 0 && failureStatus.isVisible() && statusCode(failureStatus.getText()) == null)
            InlineValidation.show(failureStatus, "Enter an HTTP status from 100 to 599.");
        else InlineValidation.clear(failureStatus);
    }
    /** @param text Status input. @return Valid HTTP status, or null while incomplete or outside the range. */
    private static Integer statusCode(String text) { return text.matches("[1-5][0-9]{2}") ? Integer.valueOf(text) : null; }
    /** Accepts up to three ASCII digits while allowing deletion during editing. */
    private static final class StatusDigits extends DocumentFilter {
        @Override public void insertString(FilterBypass fb, int offset, String text, AttributeSet attributes) throws BadLocationException { replace(fb, offset, 0, text, attributes); }
        @Override public void replace(FilterBypass fb, int offset, int length, String text, AttributeSet attributes) throws BadLocationException {
            var document = fb.getDocument();
            var current = document.getText(0, document.getLength());
            var next = current.substring(0, offset) + (text == null ? "" : text) + current.substring(offset + length);
            if (next.matches("[0-9]{0,3}")) fb.replace(offset, length, text, attributes);
        }
    }
    /** Updates options and action availability. */
    private void refresh() { refreshAvailable(null); refreshButtons(); }
    /** Rebuilds the add picker with identities not already present. */
    private void refreshAvailable(RequestSettings.JourneySelection previous) { available.removeAllItems(); options.values().stream().filter(o -> rows.stream().noneMatch(r -> r.journey().equals(o.key()))).forEach(available::addItem); if (previous != null) for (int i = 0; i < available.getItemCount(); i++) if (available.getItemAt(i).key().equals(previous)) available.setSelectedIndex(i); add.setEnabled(available.getItemCount() > 0 && rows.size() < 64); }
    /** Keeps movement and removal actions valid at both list boundaries. */
    private void refreshButtons() { int i = table.getSelectedRow(); up.setEnabled(i > 0); down.setEnabled(i >= 0 && i < rows.size() - 1); remove.setEnabled(i >= 0); }
    /** Returns a literal label while retaining unavailable saved references. */
    private String label(RequestSettings.JourneySelection key) { var o = options.get(key); return o == null ? "Unavailable journey" : o.label(); }
    /** Adds a native labeled field in the detail grid. */
    private void row(String name, JComponent input, int y) { var label = new JLabel(name); label.setLabelFor(input); input.putClientProperty("ruleLabel", label); var c = new GridBagConstraints(); c.gridy = y; c.insets = new Insets(4, 0, 4, 8); c.anchor = GridBagConstraints.WEST; detail.add(label, c); c.gridx = 1; c.weightx = 1; c.fill = GridBagConstraints.HORIZONTAL; detail.add(input == failureStatus ? InlineValidation.wrap(input, this::validateFailureStatus) : input == prefix || input == pattern ? InlineValidation.wrap(input) : input, c); }
    /** Updates both a field and its caption. */
    private static void visible(JComponent field, boolean show) { InlineValidation.visible(field, show); ((JLabel) field.getClientProperty("ruleLabel")).setVisible(show); }
    /** Builds wrapping, literal non-editable guidance. */
    private static JTextArea text(String value) { var text = new JTextArea(value); text.setEditable(false); text.setLineWrap(true); text.setWrapStyleWord(true); text.setOpaque(false); text.setFont(UIManager.getFont("Label.font")); text.setColumns(55); text.setSize(600, text.getFontMetrics(text.getFont()).getHeight() * 2); return text; }
    /** Uses task language for persisted enum values. */
    private static void friendly(JComboBox<?> combo) { combo.setRenderer(new DefaultListCellRenderer() { @Override public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean selected, boolean focus) { return super.getListCellRendererComponent(list, switch (String.valueOf(value)) { case "BURP_SCOPE" -> "Burp target scope"; case "ALL_REQUESTS" -> "All requests"; case "SINGLE_URL" -> "Custom URL"; case "STATUS_CODE" -> "HTTP status"; case "REGEX" -> "Response text pattern"; case "BOTH" -> "HTTP status or response text"; default -> ""; }, index, selected, focus); } }); }
    /** Stable unsorted rows; only the activation checkbox is edited directly in the table. */
    private final class Model extends AbstractTableModel {
        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return 5; }
        @Override public String getColumnName(int c) { return new String[]{"On", "Journey", "URL scope", "Proxy port", "Expired session"}[c]; }
        @Override public Class<?> getColumnClass(int c) { return c == 0 ? Boolean.class : String.class; }
        @Override public boolean isCellEditable(int r, int c) { return c == 0; }
        @Override public Object getValueAt(int r, int c) { var d = rows.get(r); return switch (c) { case 0 -> d.enabled(); case 1 -> label(d.journey()); case 2 -> d.mode() == Mode.SINGLE_URL ? (d.regex() ? "Regex: " : "Prefix: ") + d.prefix() : d.mode() == Mode.ALL_REQUESTS ? "All requests" : "Burp target scope"; case 3 -> d.port() == null ? "Any listener" : d.port().toString(); default -> !d.detect() ? "Detection off" : d.recovery() == JourneyDefinition.RecoveryMode.STATUS_CODE ? "HTTP " + d.status() : d.recovery() == JourneyDefinition.RecoveryMode.REGEX ? "Response text" : "HTTP " + d.status() + " or response text"; }; }
        @Override public void setValueAt(Object value, int r, int c) { if (c != 0) return; var d = rows.get(r); rows.set(r, new Draft(Boolean.TRUE.equals(value), d.journey(), d.mode(), d.prefix(), d.detect(), d.recovery(), d.status(), d.pattern(), d.regex(), d.port())); invalidateValidation(); fireTableRowsUpdated(r, r); changed.run(); }
    }
}
