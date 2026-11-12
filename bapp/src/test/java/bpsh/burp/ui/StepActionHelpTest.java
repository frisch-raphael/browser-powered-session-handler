package bpsh.burp.ui;

import bpsh.journey.AuthStep;
import java.awt.Point;
import javax.swing.JComboBox;
import javax.swing.JList;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Verifies help follows the hovered cell rather than the selected item without editing anything. */
class StepActionHelpTest {
    @Test void hoveringAnUnselectedCellAndEmptySpaceUpdatesAndClearsHelp() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var list = new JList<>(AuthStep.Type.values()); list.setFixedCellHeight(24); list.setFixedCellWidth(250);
            list.setSize(250, 500); list.setSelectedIndex(0);
            int index = AuthStep.Type.MAIN_FRAME.ordinal();
            StepActionHelp.hover(list, new Point(20, index * 24 + 8));
            assertEquals(UiTooltips.lines(StepActionHelp.text(AuthStep.Type.MAIN_FRAME), 80), list.getToolTipText());
            assertFalse(list.getToolTipText().startsWith("<html>"));
            assertEquals(0, list.getSelectedIndex());
            StepActionHelp.hover(list, new Point(20, 499)); assertNull(list.getToolTipText());
        });
    }

    @Test void actualNativePopupHelpClearsOnCloseAndKeyboardHelpDoesNotCommitAnAction() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var combo = new JComboBox<>(AuthStep.Type.values()); StepActionHelp.install(combo);
            var popup = (javax.swing.plaf.basic.BasicComboPopup) combo.getAccessibleContext().getAccessibleChild(0);
            var list = popup.getList(); list.setSize(350, 900); list.setFixedCellHeight(50);
            list.setSelectedIndex(AuthStep.Type.PRESS_KEY.ordinal());
            assertEquals(AuthStep.Type.CLICK, combo.getSelectedItem());
            assertEquals(StepActionHelp.text(AuthStep.Type.PRESS_KEY), combo.getAccessibleContext().getAccessibleDescription());
            StepActionHelp.hover(list, new Point(10, AuthStep.Type.CLICK.ordinal() * 50 + 2));
            assertNull(list.getToolTipText(), "The decorative group caption has no action help");
            StepActionHelp.hover(list, new Point(10, AuthStep.Type.MAIN_FRAME.ordinal() * 50 + 30));
            assertNotNull(list.getToolTipText());
            for (var listener : combo.getPopupMenuListeners()) listener.popupMenuWillBecomeInvisible(new javax.swing.event.PopupMenuEvent(combo));
            assertNull(list.getToolTipText());
            assertEquals(StepActionHelp.text(AuthStep.Type.CLICK), combo.getAccessibleContext().getAccessibleDescription());
            assertEquals(AuthStep.Type.CLICK, combo.getSelectedItem());
        });
    }

    @Test void everyActionHasHelpAndKeyboardSelectionExposesItWithoutDuplicatingListeners() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var combo = new JComboBox<>(AuthStep.Type.values()); StepActionHelp.install(combo);
            int listeners = combo.getActionListeners().length; StepActionHelp.install(combo);
            assertEquals(listeners, combo.getActionListeners().length);
            for (var type : AuthStep.Type.values()) {
                assertFalse(StepActionHelp.text(type).isBlank()); combo.setSelectedItem(type);
                assertEquals(StepActionHelp.text(type), combo.getAccessibleContext().getAccessibleDescription());
            }
            assertEquals("Press key", AuthStep.Type.PRESS_KEY.label());
            assertEquals("Run the next steps in the current tab or popup, outside all embedded frames.", StepActionHelp.text(AuthStep.Type.MAIN_FRAME));
        });
    }
}
