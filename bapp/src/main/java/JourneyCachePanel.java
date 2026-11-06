import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.time.ZoneId;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/** Explicit read-only inspection of one journey's usable cache; values never enter logs, persistence or diagnostics. */
final class JourneyCachePanel extends JPanel {
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("dd MMM uuuu HH:mm:ss z").withZone(ZoneId.systemDefault());
    private static final DateTimeFormatter COMPACT_TIME = DateTimeFormatter.ofPattern("dd MMM, HH:mm:ss").withZone(ZoneId.systemDefault());
    private final JLabel empty = new JLabel("No usable cached credentials.");
    private final JPanel metadata = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
    private final JLabel expires = new JLabel(), refresh = new JLabel(), cached = new JLabel();
    private final Model model = new Model();
    private final JTable table = new JTable(model);
    private final PlainRenderer renderer = new PlainRenderer();
    private final JPopupMenu menu = new JPopupMenu();
    private final JMenuItem copyName = new JMenuItem("Copy name"), copyValue = new JMenuItem("Copy value");
    private final Consumer<String> feedback, clipboard;
    private JourneyDefinition.Identity shown;
    private long version = -1;

    /** @param close Hides the dock and releases its displayed credential references. */
    JourneyCachePanel(Runnable close) { this(close, message -> {}); }
    /** @param close Hides the dock. @param feedback Reports only safe clipboard failures, never the copied text. */
    JourneyCachePanel(Runnable close, Consumer<String> feedback) {
        this(close, feedback, text -> Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null));
    }
    /** @param close Hides the dock. @param feedback Safe clipboard-failure reporting. @param clipboard Explicit copy destination; tests use an owned clipboard. */
    JourneyCachePanel(Runnable close, Consumer<String> feedback, Consumer<String> clipboard) {
        super(new BorderLayout(8, 6)); setBorder(BorderFactory.createEmptyBorder(8, 0, 0, 0));
        this.feedback = feedback; this.clipboard = clipboard;
        metadata.add(timing("Expires", expires)); metadata.add(Box.createHorizontalStrut(24));
        metadata.add(timing("Refresh due", refresh)); metadata.add(Box.createHorizontalStrut(24));
        metadata.add(timing("Cached", cached));
        metadata.setVisible(false);
        var actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0)); actions.add(UiIcons.button(UiIcons.Action.REMOVE, "Close journey cache", close));
        var summary = new JPanel(new BorderLayout(0, 5)); summary.add(metadata); summary.add(empty, BorderLayout.SOUTH);
        var top = new JPanel(new BorderLayout(8, 0)); top.add(summary); top.add(actions, BorderLayout.EAST); add(top, BorderLayout.NORTH);
        getAccessibleContext().setAccessibleName("Journey cache"); metadata.getAccessibleContext().setAccessibleName("Cache lifetime");
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION); table.setDefaultRenderer(Object.class, renderer); table.getAccessibleContext().setAccessibleName("Cached credentials");
        table.getColumnModel().getColumn(0).setPreferredWidth(80); table.getColumnModel().getColumn(0).setMaxWidth(110);
        table.getColumnModel().getColumn(1).setPreferredWidth(220); table.getColumnModel().getColumn(2).setPreferredWidth(700);
        copyName.addActionListener(e -> copy(true)); copyValue.addActionListener(e -> copy(false)); menu.add(copyName); menu.add(copyValue);
        table.getSelectionModel().addListSelectionListener(e -> updateCopyActions()); updateCopyActions();
        table.addMouseListener(new MouseAdapter() {
            /** Selects the clicked credential before opening its actions on platforms that trigger on press. */
            @Override public void mousePressed(MouseEvent event) { popup(event); }
            /** Supports platforms whose native popup trigger occurs on release. */
            @Override public void mouseReleased(MouseEvent event) { popup(event); }
        });
        table.getInputMap().put(KeyStroke.getKeyStroke("shift F10"), "cacheMenu");
        table.getInputMap().put(KeyStroke.getKeyStroke("CONTEXT_MENU"), "cacheMenu");
        table.getActionMap().put("cacheMenu", new AbstractAction() {
            /** Opens the same actions for the keyboard-selected credential. */
            @Override public void actionPerformed(java.awt.event.ActionEvent event) {
                int row = table.getSelectedRow(); if (row < 0) return;
                var cell = table.getCellRect(row, 1, true); menu.show(table, cell.x, cell.y + cell.height);
            }
        });
        add(new JScrollPane(table)); setPreferredSize(new Dimension(0, 310)); setMinimumSize(new Dimension(0, 180));
    }
    /** @param event Native popup gesture; blank rows clear selection and never expose another row's actions. */
    private void popup(MouseEvent event) {
        if (!event.isPopupTrigger()) return;
        int row = table.rowAtPoint(event.getPoint());
        if (row < 0) { table.clearSelection(); return; }
        table.setRowSelectionInterval(row, row); table.requestFocusInWindow(); menu.show(table, event.getX(), event.getY());
    }
    /** Enables copy only while a current displayed credential is selected. */
    private void updateCopyActions() { int row = table.getSelectedRow(); boolean enabled = row >= 0 && row < model.rows.size(); copyName.setEnabled(enabled); copyValue.setEnabled(enabled); }
    /** @param name Whether to copy the configured token name or actual cookie name, rather than its captured value. */
    private void copy(boolean name) {
        int row = table.getSelectedRow(); if (row < 0 || row >= model.rows.size()) return;
        var credential = model.rows.get(table.convertRowIndexToModel(row));
        try { clipboard.accept(name ? credential.copyName() : credential.value()); }
        catch (IllegalStateException | SecurityException | HeadlessException error) { feedback.accept("Could not access the clipboard. Try copying again."); }
    }
    /**
     * Displays only a matching, usable publication supplied by the coordinator; no acquisition or secret-store access occurs.
     * @param entry Reviewed saved journey, or null when selection is absent/stale.
     * @param snapshot Current usable atomic publication, or null when absent/expired/invalidated.
     */
    void refresh(JourneyRegistry.Entry entry, TokenSnapshot snapshot) {
        getAccessibleContext().setAccessibleDescription(entry == null ? null : "Cached credentials for " + entry.definition().alias());
        if (entry == null || snapshot == null || !entry.identity().equals(snapshot.identity())) { clear(); return; }
        if (entry.identity().equals(shown) && version == snapshot.version()) return;
        clear(); shown = entry.identity(); version = snapshot.version(); metadata.setVisible(true);
        updateTiming(snapshot.lifetime());
        var rows = new ArrayList<Credential>();
        if (entry.definition().extraction() instanceof JourneyDefinition.CombinedExtraction combined) {
            for (var token : combined.tokens()) add(rows, token.name(), token.selector(), snapshot.namedTokens().get(token.name()));
        } else add(rows, entry.definition().extraction() instanceof JourneyDefinition.CookieExtraction cookie ? cookie.name() : "Default", entry.definition().extraction(), snapshot.value());
        model.rows = List.copyOf(rows); model.fireTableDataChanged(); empty.setVisible(rows.isEmpty());
        if (!rows.isEmpty()) table.setRowSelectionInterval(0, 0);
    }
    /** Drops every displayed value on close, expiry, invalidation, selection change or unload. */
    void clear() { menu.setVisible(false); shown = null; version = -1; if (!model.rows.isEmpty()) { model.rows = List.of(); model.fireTableDataChanged(); } table.clearSelection(); updateCopyActions(); renderer.setText(""); for (var label : List.of(expires, refresh, cached)) timingValue(label, "", null); metadata.setVisible(false); empty.setVisible(true); }
    /** Displays fixed acquisition and deadline timestamps for this cache publication. */
    private void updateTiming(TokenLifetime.Window lifetime) {
        timestamp(expires, lifetime.acquiredAt().plusNanos(lifetime.usableNanos()), "Expires");
        timestamp(refresh, lifetime.acquiredAt().plusNanos(lifetime.refreshNanos()), "Refresh due");
        timestamp(cached, lifetime.acquiredAt(), "Cached at");
    }
    /** @param label Timing value. @param instant Fixed timestamp. @param caption Meaning of the timestamp. */
    private static void timestamp(JLabel label, Instant instant, String caption) { timingValue(label, COMPACT_TIME.format(instant), caption + ": " + TIME.format(instant)); }
    /** @param caption Timing meaning. @param value Fixed timestamp. @return Compact native label/value pair. */
    private static JPanel timing(String caption, JLabel value) {
        var group = new JPanel(new BorderLayout(0, 2)); group.add(new JLabel(caption), BorderLayout.NORTH); group.add(value);
        value.setFont(value.getFont().deriveFont(Font.BOLD)); value.getAccessibleContext().setAccessibleName(caption);
        return group;
    }
    /** @param label Timing value. @param value Compact timestamp. @param exact Plain-text full timestamp, also exposed to assistive technology. */
    private static void timingValue(JLabel label, String value, String exact) {
        label.setText(value); label.getAccessibleContext().setAccessibleDescription(exact);
        var group = (JPanel) label.getParent(); group.setToolTipText(exact);
        for (var child : group.getComponents()) if (child instanceof JLabel part) part.setToolTipText(exact);
    }
    /** @param rows Owned display list. @param name User-defined credential name. @param source Configured source. @param value Captured value; null is omitted. */
    private static void add(List<Credential> rows, String name, JourneyDefinition.Extraction source, String value) { if (value != null) rows.add(new Credential(source instanceof JourneyDefinition.CookieExtraction ? "Cookie" : "Token", source instanceof JourneyDefinition.CookieExtraction cookie && !cookie.name().equals(name) ? name + " (" + cookie.name() + ")" : name, source instanceof JourneyDefinition.CookieExtraction cookie ? cookie.name() : name, value)); }
    /** Owns an inspection-only value whose diagnostic representation is deliberately redacted. */
    private record Credential(String type, String name, String copyName, String value) { /** @return Metadata-free diagnostic label without any captured credential. */ @Override public String toString() { return "CachedCredential[redacted]"; } }
    /** Read-only rows for the explicitly opened cache viewer. */
    private static final class Model extends AbstractTableModel {
        List<Credential> rows = List.of();
        /** @return Captured configured credential count. */ @Override public int getRowCount() { return rows.size(); }
        /** @return Type, name and value columns. */ @Override public int getColumnCount() { return 3; }
        /** @param column Visible column. @return User-facing caption. */ @Override public String getColumnName(int column) { return switch (column) { case 0 -> "Type"; case 1 -> "Name"; default -> "Value"; }; }
        /** @param row Captured credential. @param column Visible column. @return Inspection-only value or label, never used as a log message. */ @Override public Object getValueAt(int row, int column) { var credential = rows.get(row); return switch (column) { case 0 -> credential.type(); case 1 -> credential.name(); default -> credential.value(); }; }
    }
    /** Treats token/cookie text as literal data, including HTML-looking values. */
    private static final class PlainRenderer extends DefaultTableCellRenderer {
        /** @return Native themed cell with HTML interpretation disabled. */ @Override public Component getTableCellRendererComponent(JTable table, Object value, boolean selected, boolean focus, int row, int column) { putClientProperty("html.disable", true); super.getTableCellRendererComponent(table, value, selected, focus, row, column); setText(String.valueOf(value)); return this; }
    }
}
