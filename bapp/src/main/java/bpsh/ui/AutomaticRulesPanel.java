package bpsh.ui;

import bpsh.config.Config;
import bpsh.model.JourneyDefinition;
import java.awt.*;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;

/** Ordered session-handling rules with inline scope and expiration settings. */
final class AutomaticRulesPanel extends JPanel {
    /** Stable scoped identity and literal display label from the saved registry. */
    record Option(Config.JourneySelection key, String label) {
        @Override public String toString() { return label; }
    }
    /** Keeps incomplete edits local until the full rules snapshot validates. */
    private record Draft(boolean enabled, Config.JourneySelection journey, Config.UrlMode mode, String prefix,
                         boolean detect, JourneyDefinition.RecoveryMode recovery, String status, String pattern) {}
    private final List<Draft> rows = new ArrayList<>();
    private final Map<Config.JourneySelection, Option> options = new LinkedHashMap<>();
    private final JComboBox<Option> available = new JComboBox<>();
    private final Model model = new Model();
    final JTable table = new JTable(model);
    private final JScrollPane tableScroll = new JScrollPane(table);
    final JComboBox<Config.UrlMode> urlMode = new JComboBox<>(Config.UrlMode.values());
    final JTextField prefix = new JTextField(32), failureStatus = new JTextField("401", 8), pattern = new JTextField(32);
    final JCheckBox detect = new JCheckBox("Detect expired sessions");
    final JComboBox<JourneyDefinition.RecoveryMode> recoveryMode = new JComboBox<>(JourneyDefinition.RecoveryMode.values());
    private final JPanel detail = new JPanel(new GridBagLayout());
    private final JLabel selected = new JLabel("Select a rule to configure its URL scope and session expiration.");
    private final JButton add, up, down, remove;
    private Runnable changed = () -> {};
    private boolean loading;

    /** Builds a theme-native list whose order is never changed by sorting. */
    AutomaticRulesPanel() {
        setLayout(new BorderLayout(0, 10));
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
        var center = new JPanel(new BorderLayout(0, 12)); center.add(tableScroll, BorderLayout.NORTH);
        var details = new JPanel(new BorderLayout(0, 8)); selected.putClientProperty("html.disable", true); details.add(selected, BorderLayout.NORTH);
        row("URL handling", urlMode, 0); row("URL prefix", prefix, 1); row("", detect, 2); row("Detect by", recoveryMode, 3); row("Failure status", failureStatus, 4); row("RE2 expression", pattern, 5);
        var stretch = new GridBagConstraints(); stretch.gridy = 6; stretch.weighty = 1; detail.add(Box.createVerticalGlue(), stretch);
        details.add(detail, BorderLayout.CENTER); center.add(details, BorderLayout.CENTER); add(center, BorderLayout.CENTER);
        refreshPresentation();
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
    void setRules(List<Config.AutomaticRule> rules) {
        loading = true;
        try { rows.clear(); for (var r : rules) rows.add(new Draft(r.enabled(), r.journey(), r.urlMode(), r.urlPrefix() == null ? "" : r.urlPrefix().toString(), r.recovery().enabled(), r.recovery().mode(), r.recovery().statusCode() == null ? "401" : r.recovery().statusCode().toString(), r.recovery().pattern() == null ? "" : r.recovery().pattern())); model.fireTableDataChanged(); if (!rows.isEmpty()) table.setRowSelectionInterval(0, 0); }
        finally { loading = false; }
        refresh(); populate();
    }
    /** Captures every row in visible order; incomplete active fields reject the whole autosave. */
    List<Config.AutomaticRule> snapshot() {
        var result = new ArrayList<Config.AutomaticRule>();
        for (int i = 0; i < rows.size(); i++) {
            var d = rows.get(i); URI uri = null; Integer status = null;
            try { if (d.mode() == Config.UrlMode.SINGLE_URL) uri = URI.create(d.prefix().trim()); }
            catch (RuntimeException ex) { throw new IllegalArgumentException("Rule " + (i + 1) + ": enter an absolute HTTP(S) URL prefix."); }
            if (d.recovery() != JourneyDefinition.RecoveryMode.REGEX) try { status = d.detect() ? Integer.valueOf(d.status().trim()) : 401; }
            catch (RuntimeException ex) { throw new IllegalArgumentException("Rule " + (i + 1) + ": failure status must be between 100 and 599."); }
            var recovery = new JourneyDefinition.Recovery(d.detect(), d.recovery(), status, d.recovery() == JourneyDefinition.RecoveryMode.STATUS_CODE ? null : d.detect() ? d.pattern() : "session expired");
            result.add(new Config.AutomaticRule(d.enabled(), d.journey(), d.mode(), uri, recovery));
        }
        return List.copyOf(result);
    }
    /** Adds a saved identity once, initially enabled with status-401 expiration detection. */
    private void addSelected() {
        var o = (Option) available.getSelectedItem(); if (o == null || rows.size() >= 64) return;
        rows.add(new Draft(true, o.key(), Config.UrlMode.BURP_SCOPE, "", true, JourneyDefinition.RecoveryMode.STATUS_CODE, "401", ""));
        model.fireTableDataChanged(); table.setRowSelectionInterval(rows.size() - 1, rows.size() - 1); refresh(); changed.run();
    }
    /** Removes the selected rule, retaining the saved journey itself. */
    private void removeSelected() { int i = table.getSelectedRow(); if (i < 0) return; rows.remove(i); model.fireTableDataChanged(); if (!rows.isEmpty()) table.setRowSelectionInterval(Math.min(i, rows.size() - 1), Math.min(i, rows.size() - 1)); refresh(); populate(); changed.run(); }
    /** Moves the selected rule one position without sorting or changing its identity. */
    private void move(int delta) { int i = table.getSelectedRow(), target = i + delta; if (i < 0 || target < 0 || target >= rows.size()) return; java.util.Collections.swap(rows, i, target); model.fireTableDataChanged(); table.setRowSelectionInterval(target, target); refresh(); changed.run(); }
    /** Captures edits without allowing a partial rule to mutate applied controls. */
    private void edited() {
        if (loading) return; int i = table.getSelectedRow(); if (i < 0) return; var d = rows.get(i);
        loading = true;
        try {
            if (urlMode.getSelectedItem() != d.mode() && urlMode.getSelectedItem() != Config.UrlMode.SINGLE_URL) prefix.setText("");
            if (!detect.isSelected() || recoveryMode.getSelectedItem() != d.recovery()) {
                if (!detect.isSelected() || recoveryMode.getSelectedItem() == JourneyDefinition.RecoveryMode.REGEX) failureStatus.setText("");
                if (!detect.isSelected() || recoveryMode.getSelectedItem() == JourneyDefinition.RecoveryMode.STATUS_CODE) pattern.setText("");
            }
        } finally { loading = false; }
        rows.set(i, new Draft(d.enabled(), d.journey(), (Config.UrlMode) urlMode.getSelectedItem(), prefix.getText(), detect.isSelected(), (JourneyDefinition.RecoveryMode) recoveryMode.getSelectedItem(), failureStatus.getText(), pattern.getText()));
        model.fireTableRowsUpdated(i, i); conditional(); changed.run();
    }
    /** Displays the selected rule without invoking autosave. */
    private void populate() {
        int i = table.getSelectedRow(); loading = true;
        try { detail.setVisible(i >= 0); if (i >= 0) { var d = rows.get(i); selected.setText(label(d.journey())); urlMode.setSelectedItem(d.mode()); prefix.setText(d.prefix()); detect.setSelected(d.detect()); recoveryMode.setSelectedItem(d.recovery()); failureStatus.setText(d.status()); pattern.setText(d.pattern()); } else selected.setText(rows.isEmpty() ? "Add a saved journey to configure automatic authentication." : "Select a rule to configure it."); }
        finally { loading = false; }
        conditional(); refreshButtons();
    }
    /** Shows only fields used by the selected matching and expiration modes. */
    private void conditional() { visible(prefix, urlMode.getSelectedItem() == Config.UrlMode.SINGLE_URL); visible(recoveryMode, detect.isSelected()); visible(failureStatus, detect.isSelected() && recoveryMode.getSelectedItem() != JourneyDefinition.RecoveryMode.REGEX); visible(pattern, detect.isSelected() && recoveryMode.getSelectedItem() != JourneyDefinition.RecoveryMode.STATUS_CODE); revalidate(); }
    /** Updates options and action availability. */
    private void refresh() { refreshAvailable(null); refreshButtons(); }
    /** Rebuilds the add picker with identities not already present. */
    private void refreshAvailable(Config.JourneySelection previous) { available.removeAllItems(); options.values().stream().filter(o -> rows.stream().noneMatch(r -> r.journey().equals(o.key()))).forEach(available::addItem); if (previous != null) for (int i = 0; i < available.getItemCount(); i++) if (available.getItemAt(i).key().equals(previous)) available.setSelectedIndex(i); add.setEnabled(available.getItemCount() > 0 && rows.size() < 64); }
    /** Keeps movement and removal actions valid at both list boundaries. */
    private void refreshButtons() { int i = table.getSelectedRow(); up.setEnabled(i > 0); down.setEnabled(i >= 0 && i < rows.size() - 1); remove.setEnabled(i >= 0); }
    /** Returns a literal label while retaining unavailable saved references. */
    private String label(Config.JourneySelection key) { var o = options.get(key); return o == null ? "Unavailable journey" : o.label(); }
    /** Adds a native labeled field in the detail grid. */
    private void row(String name, JComponent input, int y) { var label = new JLabel(name); label.setLabelFor(input); input.putClientProperty("ruleLabel", label); var c = new GridBagConstraints(); c.gridy = y; c.insets = new Insets(4, 0, 4, 8); c.anchor = GridBagConstraints.WEST; detail.add(label, c); c.gridx = 1; c.weightx = 1; c.fill = GridBagConstraints.HORIZONTAL; detail.add(input, c); }
    /** Updates both a field and its caption. */
    private static void visible(JComponent field, boolean show) { field.setVisible(show); ((JLabel) field.getClientProperty("ruleLabel")).setVisible(show); }
    /** Builds wrapping, literal non-editable guidance. */
    private static JTextArea text(String value) { var text = new JTextArea(value); text.setEditable(false); text.setLineWrap(true); text.setWrapStyleWord(true); text.setOpaque(false); text.setFont(UIManager.getFont("Label.font")); text.setColumns(55); text.setSize(600, text.getFontMetrics(text.getFont()).getHeight() * 2); return text; }
    /** Uses task language for persisted enum values. */
    private static void friendly(JComboBox<?> combo) { combo.setRenderer(new DefaultListCellRenderer() { @Override public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean selected, boolean focus) { return super.getListCellRendererComponent(list, switch (String.valueOf(value)) { case "BURP_SCOPE" -> "Burp target scope"; case "ALL_REQUESTS" -> "All requests"; case "SINGLE_URL" -> "URL prefix"; case "STATUS_CODE" -> "HTTP status"; case "REGEX" -> "Response text pattern"; case "BOTH" -> "HTTP status or response text"; default -> ""; }, index, selected, focus); } }); }
    /** Stable unsorted rows; only the activation checkbox is edited directly in the table. */
    private final class Model extends AbstractTableModel {
        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return 4; }
        @Override public String getColumnName(int c) { return new String[]{"On", "Journey", "URL scope", "Expired session"}[c]; }
        @Override public Class<?> getColumnClass(int c) { return c == 0 ? Boolean.class : String.class; }
        @Override public boolean isCellEditable(int r, int c) { return c == 0; }
        @Override public Object getValueAt(int r, int c) { var d = rows.get(r); return switch (c) { case 0 -> d.enabled(); case 1 -> label(d.journey()); case 2 -> d.mode() == Config.UrlMode.SINGLE_URL ? d.prefix() : d.mode() == Config.UrlMode.ALL_REQUESTS ? "All requests" : "Burp target scope"; default -> !d.detect() ? "Detection off" : d.recovery() == JourneyDefinition.RecoveryMode.STATUS_CODE ? "HTTP " + d.status() : d.recovery() == JourneyDefinition.RecoveryMode.REGEX ? "Response text" : "HTTP " + d.status() + " or response text"; }; }
        @Override public void setValueAt(Object value, int r, int c) { if (c != 0) return; var d = rows.get(r); rows.set(r, new Draft(Boolean.TRUE.equals(value), d.journey(), d.mode(), d.prefix(), d.detect(), d.recovery(), d.status(), d.pattern())); fireTableRowsUpdated(r, r); changed.run(); }
    }
}
