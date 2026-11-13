package lab.auth.gui;

import java.awt.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class HostGuiHistoryTest {
    private static final String NONCE = "h0123456789abcdef";

    @Test void wheelsToOffscreenNonceAndClicksOnlyVisibleReadonlyMethodCell() {
        var table = new History(40, 35); var input = new Input(table);
        int row = select(table, input, () -> {});
        assertEquals(35, row); assertTrue(input.scrolls > 0); assertEquals(1, input.clicks);
        assertEquals("Method", table.getColumnName(input.clickedColumn)); assertEquals(35, input.clickedRow);
        assertTrue(table.getVisibleRect().contains(table.getCellRect(35, input.clickedColumn, true)));
    }

    @Test void scrollsUpAndResolvesMethodAfterColumnReorderingWithoutTouchingActionColumn() {
        var table = new History(40, 2); table.viewport.y = 600; table.moveColumn(1, 2);
        var input = new Input(table); select(table, input, () -> {});
        assertTrue(input.upward > 0); assertEquals(1, input.clicks); assertEquals(2, input.clickedColumn);
    }

    @Test void refusesMissingOrReorderedPinnedNonceAfterWheelBeforeAnyClick() {
        for (boolean remove : new boolean[]{false, true}) {
            var table = new History(40, 35); var input = new Input(table);
            input.afterScroll = () -> {
                var model = (DefaultTableModel) table.getModel();
                if (remove) model.setValueAt("/unrelated", 35, 2);
                else model.moveRow(35, 35, 34);
            };
            assertEquals("GUI_HISTORY_ROW_CHANGED", assertThrows(HostGuiSelectors.Failure.class,
                    () -> select(table, input, () -> {})).getMessage());
            assertEquals(0, input.clicks);
        }
    }

    @Test void refusesDuplicatedNonceOrUnsafeMethodIntroducedAfterWheel() {
        for (int kind = 0; kind < 3; kind++) {
            int variant = kind; var table = new History(40, 35); var input = new Input(table);
            input.afterScroll = () -> {
                if (variant == 0) table.getModel().setValueAt("/" + NONCE, 34, 2);
                else if (variant == 1) table.editable = true;
                else table.getColumnModel().getColumn(1).setHeaderValue("Action");
            };
            // JTable.getColumnName reads the model, not renderer-only header values.
            if (kind == 2) input.afterScroll = () -> ((DefaultTableModel)table.getModel()).setColumnIdentifiers(new String[]{"#", "Action", "URL"});
            String expected = kind == 0 ? "GUI_HISTORY_NONCE_AMBIGUOUS" : kind == 1 ? "GUI_HISTORY_METHOD_EDITABLE" : "GUI_HISTORY_METHOD_MISSING";
            assertEquals(expected, assertThrows(HostGuiSelectors.Failure.class, () -> select(table, input, () -> {})).getMessage());
            assertEquals(0, input.clicks);
        }
    }

    @Test void operationDeadlineAndScrollCapStopUnmovingViewportWithoutClicking() {
        var table = new History(40, 35); var input = new Input(table); input.moveViewport = false;
        var checks = new AtomicInteger();
        assertEquals("GUI_DEADLINE", assertThrows(HostGuiSelectors.Failure.class, () -> select(table, input, () -> {
            if (checks.incrementAndGet() > 8) throw new HostGuiSelectors.Failure("GUI_DEADLINE");
        })).getMessage()); assertEquals(0, input.clicks);
        var capped = new Input(table); capped.moveViewport = false;
        assertEquals("GUI_HISTORY_SCROLL_LIMIT", assertThrows(HostGuiSelectors.Failure.class,
                () -> select(table, capped, () -> {})).getMessage());
        assertEquals(128, capped.scrolls); assertEquals(0, capped.clicks);
    }

    @Test void refusesClippedMethodOrEmptyViewportAndRechecksIdentityBeforeActualInput() {
        var horizontal = new History(40, 2); horizontal.viewport = new Rectangle(0, 0, 100, 100);
        var input = new Input(horizontal);
        assertEquals("GUI_HISTORY_METHOD_CLIPPED", assertThrows(HostGuiSelectors.Failure.class,
                () -> select(horizontal, input, () -> {})).getMessage()); assertEquals(0, input.clicks);
        var empty = new History(40, 2); empty.viewport.height = 0;
        assertEquals("GUI_CONTROL_CLIPPED", assertThrows(HostGuiSelectors.Failure.class,
                () -> select(empty, new Input(empty), () -> {})).getMessage());
        var changed = new History(40, 2); var racing = new Input(changed);
        racing.beforeClickGuard = () -> changed.moveColumn(1, 0);
        assertEquals("GUI_HISTORY_CELL_CHANGED", assertThrows(HostGuiSelectors.Failure.class,
                () -> select(changed, racing, () -> {})).getMessage()); assertEquals(0, racing.clicks);
    }

    @Test void waitsForInitialNonceButNeverClicksMissingDataAndRestoresOriginalGuard() {
        var table = new History(40, -1); var input = new Input(table); var polls = new AtomicInteger();
        Runnable original = () -> {};
        assertEquals("GUI_DEADLINE", assertThrows(HostGuiSelectors.Failure.class, () -> HostGuiHistory.select(table, NONCE, input, original, ready -> {
            for (int i = 0; i < 3; i++) { polls.incrementAndGet(); assertFalse(ready.getAsBoolean()); }
            throw new HostGuiSelectors.Failure("GUI_DEADLINE");
        })).getMessage());
        assertEquals(3, polls.get()); assertEquals(0, input.scrolls); assertEquals(0, input.clicks); assertSame(original, input.guard);
    }

    private static int select(History table, Input input, Runnable guard) {
        return HostGuiHistory.select(table, NONCE, input, guard, ready -> {
            for (int i = 0; i < 200; i++) if (ready.getAsBoolean()) return;
            throw new AssertionError("Unbounded history operation");
        });
    }

    private static final class History extends JTable {
        Rectangle viewport = new Rectangle(0, 0, 600, 100); boolean editable;
        History(int count, int target) {
            super(new DefaultTableModel(new String[]{"#", "Method", "URL"}, 0));
            var model = (DefaultTableModel) getModel();
            for (int i = 0; i < count; i++) model.addRow(new Object[]{i, "GET", i == target ? "/" + NONCE : "/other"});
            setRowHeight(20); setSize(600, count * 20); doLayout();
        }
        @Override public Rectangle getVisibleRect() { return viewport == null ? new Rectangle() : new Rectangle(viewport); }
        @Override public boolean isCellEditable(int row, int column) { return editable; }
    }

    private static final class Input implements HostGuiDriver.Input {
        final History table; Runnable guard = () -> {}, afterScroll = () -> {}, beforeClickGuard = () -> {};
        int clicks, scrolls, upward, clickedRow, clickedColumn; boolean moveViewport = true;
        Input(History table) { this.table = table; }
        @Override public void bindOperationGuard(Runnable value) { guard = value; }
        @Override public void scroll(Component target, int units) {
            guard.run(); assertSame(table, target); assertEquals(3, Math.abs(units)); assertEquals(0, clicks);
            scrolls++; if (units < 0) upward++;
            if (moveViewport) table.viewport.y = Math.max(0, Math.min(table.getHeight() - table.viewport.height, table.viewport.y + units * table.getRowHeight()));
            afterScroll.run();
        }
        @Override public void click(Component target, Point relative) {
            beforeClickGuard.run(); guard.run(); assertSame(table, target); assertTrue(table.getVisibleRect().contains(relative));
            clickedRow = table.rowAtPoint(relative); clickedColumn = table.columnAtPoint(relative);
            assertEquals("Method", table.getColumnName(clickedColumn)); clicks++;
        }
        @Override public void keys(int... keys) { fail("Unexpected keys"); }
        @Override public void text(String text) { fail("Unexpected text"); }
    }
}
