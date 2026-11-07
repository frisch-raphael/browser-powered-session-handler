package bpsh.ui;

import bpsh.config.JourneyTransfer;
import bpsh.model.JourneyDefinition;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;

/** Reviews a batch of files without exposing or retaining imported secret values in table cells. */
final class JourneyImportPanel extends JPanel {
    record Item(int source, UUID journeyId, String displayName, String alias, String fileName) {}
    private final List<Item> items;
    private final DefaultTableModel model;
    private final JTable table;
    private final JLabel count = new JLabel();

    JourneyImportPanel(List<Item> items, JourneyDefinition.Scope scope) {
        super(new BorderLayout(6, 8)); this.items = List.copyOf(items);
        var help = new JTextArea("Choose journeys to import into " + (scope == JourneyDefinition.Scope.PROJECT ? "Project" : "User")
                + ". Edit tag aliases to resolve conflicts. Existing journeys are kept. Imported secrets remain session-only.");
        help.setRows(2); help.setColumns(60); help.setEditable(false); help.setLineWrap(true); help.setWrapStyleWord(true); help.setOpaque(false); help.setFont(UIManager.getFont("Label.font")); add(help, BorderLayout.NORTH);
        // Establish a wrapping width before the first pack; an unsized text area can consume the entire preview.
        help.setSize(700, help.getFontMetrics(help.getFont()).getHeight() * 2);
        model = new DefaultTableModel(new String[]{"Import", "Journey", "Source file", "Tag alias"}, 0) {
            @Override public Class<?> getColumnClass(int column) { return column == 0 ? Boolean.class : String.class; }
            @Override public boolean isCellEditable(int row, int column) { return column == 0 || column == 3; }
        };
        for (var item : items) model.addRow(new Object[]{true, item.displayName(), item.fileName(), item.alias()});
        table = new JTable(model); table.setAutoCreateRowSorter(true); table.setFillsViewportHeight(true);
        table.getColumnModel().getColumn(0).setMaxWidth(65);
        var renderer = new DefaultTableCellRenderer(); renderer.putClientProperty("html.disable", Boolean.TRUE); table.setDefaultRenderer(String.class, renderer);
        var scroll = new JScrollPane(table); scroll.setColumnHeaderView(table.getTableHeader()); add(scroll, BorderLayout.CENTER);
        var actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        var all = new JButton("Select all"); all.addActionListener(e -> selectAll(true)); actions.add(all);
        var none = new JButton("Select none"); none.addActionListener(e -> selectAll(false)); actions.add(none); actions.add(count); add(actions, BorderLayout.SOUTH);
        model.addTableModelListener(e -> updateCount()); updateCount(); setPreferredSize(new Dimension(850, 330));
    }

    private void selectAll(boolean selected) { if (table.isEditing()) table.getCellEditor().stopCellEditing(); for (int i = 0; i < model.getRowCount(); i++) model.setValueAt(selected, i, 0); }
    private void updateCount() { int selected = 0; for (int i = 0; i < model.getRowCount(); i++) if (Boolean.TRUE.equals(model.getValueAt(i, 0))) selected++; count.setText(selected + " of " + items.size() + " selected"); }

    /** Uses model order so sorting the preview never changes which identity receives an alias edit. */
    List<JourneyTransfer.ImportSelection> selection() {
        if (table.isEditing() && !table.getCellEditor().stopCellEditing()) return List.of();
        var selected = new ArrayList<JourneyTransfer.ImportSelection>();
        for (int i = 0; i < model.getRowCount(); i++) if (Boolean.TRUE.equals(model.getValueAt(i, 0))) {
            var item = items.get(i); selected.add(new JourneyTransfer.ImportSelection(item.source(), item.journeyId(), String.valueOf(model.getValueAt(i, 3)).trim()));
        }
        return List.copyOf(selected);
    }
}
