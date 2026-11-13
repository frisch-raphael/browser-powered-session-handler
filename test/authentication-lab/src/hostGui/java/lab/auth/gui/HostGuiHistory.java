package lab.auth.gui;

import java.awt.Point;
import java.awt.Rectangle;
import java.util.Objects;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import javax.swing.JTable;
import static lab.auth.gui.HostGuiSelectors.*;

/** Reveals one nonce-bound history row with real wheel input before selecting its neutral Method cell. */
final class HostGuiHistory {
    private static final int MAX_SCROLLS = 128;
    private HostGuiHistory() {}
    private record Target(int row, int column, Rectangle cell, Point center, int scroll) {}

    /** Shares the driver's original deadline and restores its input guard on every outcome. */
    static int select(JTable table, String nonce, HostGuiDriver.Input input, Runnable guard, Consumer<BooleanSupplier> until) {
        if (nonce == null || !nonce.matches("h[0-9a-f]{16}")) throw new Failure("GUI_HISTORY_NONCE_INVALID");
        int[] pinned = {-1}, scrolls = {0};
        Runnable identity = () -> {
            guard.run();
            if (pinned[0] >= 0) edt(() -> { target(table, nonce, pinned[0]); return true; });
        };
        input.bindOperationGuard(identity);
        try {
            until.accept(() -> {
                identity.run();
                Target target = edt(() -> target(table, nonce, pinned[0]));
                if (target == null) return false;
                if (pinned[0] < 0) pinned[0] = target.row();
                if (target.scroll() == 0) return true;
                if (++scrolls[0] > MAX_SCROLLS) throw new Failure("GUI_HISTORY_SCROLL_LIMIT");
                identity.run(); input.scroll(table, target.scroll()); return false;
            });
            identity.run();
            Target chosen = edt(() -> target(table, nonce, pinned[0]));
            if (chosen == null || chosen.scroll() != 0) throw new Failure("GUI_HISTORY_CELL_CHANGED");
            input.bindOperationGuard(() -> {
                identity.run();
                edt(() -> {
                    Target current = target(table, nonce, pinned[0]);
                    if (current == null || current.scroll() != 0 || current.column() != chosen.column()
                            || !current.cell().equals(chosen.cell())) throw new Failure("GUI_HISTORY_CELL_CHANGED");
                    return true;
                });
            });
            input.click(table, chosen.center()); return pinned[0];
        } finally { input.bindOperationGuard(guard); }
    }

    /** Re-reads public metadata, view ordering, Method header and viewport on every guard/scroll step. */
    private static Target target(JTable table, String nonce, int pinned) {
        int found = -1;
        for (int row = 0; row < table.getRowCount(); row++) {
            boolean matches = false;
            for (int column = 0; column < table.getColumnCount(); column++)
                matches |= Objects.toString(table.getValueAt(row, column), "").contains(nonce);
            if (matches) {
                if (found >= 0) throw new Failure("GUI_HISTORY_NONCE_AMBIGUOUS");
                found = row;
            }
        }
        if (found < 0) {
            if (pinned >= 0) throw new Failure("GUI_HISTORY_ROW_CHANGED");
            return null;
        }
        if (pinned >= 0 && found != pinned) throw new Failure("GUI_HISTORY_ROW_CHANGED");
        int column = historySelectionColumn(table, found);
        Rectangle cell = table.getCellRect(found, column, true), visible = table.getVisibleRect();
        if (visible.isEmpty() || cell.isEmpty() || cell.height > visible.height) throw new Failure("GUI_CONTROL_CLIPPED");
        Point center = new Point(cell.x + cell.width / 2, cell.y + cell.height / 2);
        if (center.x < visible.x || center.x >= (long) visible.x + visible.width)
            throw new Failure("GUI_HISTORY_METHOD_CLIPPED");
        int scroll = cell.y < visible.y ? -3 : (long) cell.y + cell.height > (long) visible.y + visible.height ? 3 : 0;
        return new Target(found, column, cell, center, scroll);
    }
}
