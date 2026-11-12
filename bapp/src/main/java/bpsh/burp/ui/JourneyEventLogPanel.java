package bpsh.burp.ui;

import bpsh.authentication.session.JourneyEventLog;
import bpsh.journey.JourneyKey;
import java.awt.*;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;

/** Burp-style event dock with per-journey time/type/message rows, filters and selectable safe details. */
final class JourneyEventLogPanel extends JPanel {
    private final JourneyEventLog log;
    private final Model model = new Model();
    private final JTable table = new JTable(model);
    private final TableRowSorter<Model> sorter = new TableRowSorter<>(model);
    private final JTextArea detail = new JTextArea(5, 0);
    private final JTextField search = new JTextField(18);
    private final EnumMap<JourneyEventLog.Level, JToggleButton> levels = new EnumMap<>(JourneyEventLog.Level.class);
    private final JButton clear;
    private final JSplitPane detailSplit;
    private boolean positioned;
    private JourneyKey key;
    private long revision = -1;
    private final JButton goToStep = new JButton("Go to step");
    private java.util.function.Predicate<JourneyEventLog.StepTarget> canReveal = step -> false;
    private java.util.function.Consumer<JourneyEventLog.StepTarget> reveal = step -> {};

    /** @param log Owned session history. @param close Collapses the dock without clearing its history. */
    JourneyEventLogPanel(JourneyEventLog log, Runnable close) {
        super(new BorderLayout(8, 6)); this.log = log;
        setBorder(BorderFactory.createEmptyBorder(8, 0, 0, 0));
        getAccessibleContext().setAccessibleName("Journey event log");
        var filters = new JPanel(new BorderLayout(8, 0)); var types = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0)); types.add(new JLabel("Filter"));
        for (var level : JourneyEventLog.Level.values()) { var toggle = new JToggleButton(caption(level), true); levels.put(level, toggle); toggle.addActionListener(e -> filter()); types.add(toggle); }
        filters.add(types); var right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0)); search.getAccessibleContext().setAccessibleName("Search event messages"); search.setToolTipText("Filter this journey's events by message text.");
        search.getDocument().addDocumentListener(new DocumentChangeListener(this::filter)); right.add(new JLabel("Search")); right.add(search);
        clear = UiIcons.button(UiIcons.Action.TRASH, "Clear this journey's event log", () -> { log.clear(key); revision = -1; refresh(key, null); }); right.add(clear);
        right.add(UiIcons.button(UiIcons.Action.REMOVE, "Close event log", close)); filters.add(right, BorderLayout.EAST);
        table.setRowSorter(sorter); table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION); table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        table.setDefaultRenderer(Object.class, new PlainRenderer()); table.getAccessibleContext().setAccessibleName("Journey events");
        table.getSelectionModel().addListSelectionListener(e -> selection());
        detail.setEditable(false); detail.setLineWrap(true); detail.setWrapStyleWord(true); detail.setOpaque(false); detail.getAccessibleContext().setAccessibleName("Event detail");
        var eventDetail = new JPanel(new BorderLayout(0, 6)); eventDetail.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 0)); eventDetail.add(new JLabel("Event detail"), BorderLayout.NORTH); eventDetail.add(new JScrollPane(detail));
        goToStep.setVisible(false); goToStep.addActionListener(e -> { var step = selectedStep(); if (step != null && canReveal.test(step)) reveal.accept(step); });
        var actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0)); actions.add(goToStep); eventDetail.add(actions, BorderLayout.SOUTH);
        eventDetail.setMinimumSize(new Dimension(260, 100));
        detailSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(table), eventDetail); detailSplit.setResizeWeight(0.65);
        var body = new JPanel(new BorderLayout(0, 6)); body.add(filters, BorderLayout.NORTH); body.add(detailSplit); add(body);
        setPreferredSize(new Dimension(0, 310)); setMinimumSize(new Dimension(0, 180));
        refreshPresentation();
    }
    /** @param key Selected stable journey owner. @param alias Optional current alias for assistive context, without a visible heading. @return Total unfiltered event count. */
    int refresh(JourneyKey key, String alias) {
        initializeDivider();
        boolean changed = !Objects.equals(this.key, key);
        if (changed) { this.key = key; revision = -1; table.clearSelection(); detail.setText(""); }
        if (alias != null || changed) getAccessibleContext().setAccessibleDescription(alias == null ? null : "Events for " + alias);
        long observed = log.revision();
        if (revision != observed) {
            long selected = selectedSequence(); boolean follow = table.getSelectedRow() < 0 || table.getSelectedRow() == table.getRowCount() - 1;
            model.rows = key == null ? List.of() : log.snapshot(key); revision = observed; model.fireTableDataChanged();
            int restore = -1; for (int row = 0; row < model.rows.size(); row++) if (model.rows.get(row).sequence() == selected) restore = table.convertRowIndexToView(row);
            if (follow && table.getRowCount() > 0) restore = table.getRowCount() - 1;
            if (restore >= 0) { table.setRowSelectionInterval(restore, restore); if (follow) table.scrollRectToVisible(table.getCellRect(restore, 0, true)); }
            else selection();
        }
        clear.setEnabled(key != null && !model.rows.isEmpty()); stepAction(); return model.rows.size();
    }
    /** @param available Checks the exact current saved generation. @param reveal Reveals its stable step in the editor. */
    void onStep(java.util.function.Predicate<JourneyEventLog.StepTarget> available, java.util.function.Consumer<JourneyEventLog.StepTarget> reveal) { this.canReveal = available; this.reveal = reveal; stepAction(); }
    /** @return Selected safe action target, or null for ordinary events and filtered-out selection. */
    private JourneyEventLog.StepTarget selectedStep() { int row = table.getSelectedRow(); if (row < 0) return null; int index = table.convertRowIndexToModel(row); return index >= model.rows.size() ? null : model.rows.get(index).step(); }
    /** Keeps navigation unavailable for changed, removed or unrelated journey generations. */
    private void stepAction() { var step = selectedStep(); goToStep.setVisible(step != null); goToStep.setEnabled(step != null && canReveal.test(step)); goToStep.setToolTipText(goToStep.isEnabled() ? "Show the failed action in Login steps." : "This action is unavailable in the current saved journey."); }
    /** Filters by enabled severities and literal text; regular expressions and message HTML are never evaluated. */
    private void filter() {
        String query = search.getText().toLowerCase(Locale.ROOT);
        sorter.setRowFilter(new RowFilter<>() { /** @return Whether the safe row matches both current filters. */ @Override public boolean include(Entry<? extends Model, ? extends Integer> entry) { var event = model.rows.get(entry.getIdentifier()); return levels.get(event.level()).isSelected() && event.message().toLowerCase(Locale.ROOT).contains(query); } }); selection();
    }
    /** Copies only the selected safe event into the plain-text detail pane. */
    private void selection() {
        stepAction();
        int selected = table.getSelectedRow();
        if (selected < 0) { detail.setText(model.rows.isEmpty() ? "No events for this journey yet." : table.getRowCount() == 0 ? "No events match your filters." : "Select an event to read its details."); return; }
        int index = table.convertRowIndexToModel(selected); if (index >= model.rows.size()) return;
        var event = model.rows.get(index); detail.setText("Time: " + Model.TIME.format(event.time()) + "\nType: " + caption(event.level()) + "\n\n" + event.message()); detail.setCaretPosition(0);
    }
    /** @return Stable selected sequence, or -1 when filters/selection leave no row. */
    private long selectedSequence() { int row = table.getSelectedRow(); return row < 0 || table.convertRowIndexToModel(row) >= model.rows.size() ? -1 : model.rows.get(table.convertRowIndexToModel(row)).sequence(); }
    /** Gives the detail pane a readable initial share after actual layout; subsequent operator resizing is retained. */
    void initializeDivider() { if (!positioned && isVisible() && detailSplit.getWidth() > 0) { detailSplit.setDividerLocation(0.65); positioned = true; } }
    /** Sizes metadata columns from the current host font so timestamps and severity captions stay readable. */
    void refreshPresentation() {
        var metrics = table.getFontMetrics(table.getFont());
        int time = metrics.stringWidth("23:59:59 31 Dec 2026") + 20, type = metrics.stringWidth("Warning") + 20;
        for (int index = 0; index < 2; index++) { var column = table.getColumnModel().getColumn(index); int width = index == 0 ? time : type; column.setMinWidth(width); column.setPreferredWidth(width); column.setMaxWidth(width + 30); }
    }
    /** @param level Safe enum. @return Familiar event severity caption. */
    private static String caption(JourneyEventLog.Level level) { return switch (level) { case INFO -> "Info"; case WARNING -> "Warning"; case ERROR -> "Error"; }; }
    /** Presents immutable events without making editable copies or retaining runtime credentials. */
    private static final class Model extends AbstractTableModel {
        static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss dd MMM uuuu").withZone(ZoneId.systemDefault());
        List<JourneyEventLog.Event> rows = List.of();
        /** @return Current selected journey's bounded event count. */ @Override public int getRowCount() { return rows.size(); }
        /** @return Time, type and message columns. */ @Override public int getColumnCount() { return 3; }
        /** @param column Visible column. @return Comparable timestamps for chronological sorting across dates. */ @Override public Class<?> getColumnClass(int column) { return column == 0 ? java.time.Instant.class : String.class; }
        /** @param column Visible column. @return Familiar Burp-style caption. */ @Override public String getColumnName(int column) { return switch (column) { case 0 -> "Time"; case 1 -> "Type"; default -> "Message"; }; }
        /** @param row Immutable event index. @param column Visible column. @return Safe literal display value. */ @Override public Object getValueAt(int row, int column) { var event = rows.get(row); return switch (column) { case 0 -> event.time(); case 1 -> caption(event.level()); default -> event.message(); }; }
    }
    /** Prevents Swing's HTML renderer from interpreting message text as markup. */
    private static final class PlainRenderer extends DefaultTableCellRenderer {
        /** @return Native themed cell containing literal text only. */
        @Override public Component getTableCellRendererComponent(JTable table, Object value, boolean selected, boolean focus, int row, int column) { putClientProperty("html.disable", true); super.getTableCellRendererComponent(table, value, selected, focus, row, column); setText(value instanceof java.time.Instant time ? Model.TIME.format(time) : String.valueOf(value)); return this; }
    }
}
