package bpsh.burp.ui;

import java.awt.*;
import java.util.concurrent.atomic.AtomicLong;
import javax.swing.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Checks feedback priority, expiry, ownership and disclosure through real Swing components. */
class SessionStatusBarTest {
    @Test void testActivityHighlightsLogWithoutOpeningItOrClosingTheCacheAndOpeningClearsIt() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var bar = new SessionStatusBar(); bar.context("journey"); bar.setCacheOpen(true);
            bar.highlightLog("journey"); bar.logCount(true, 3);
            assertFalse(bar.isLogOpen()); assertTrue(bar.isCacheOpen());
            assertEquals("New test events available", toggle(bar).getAccessibleContext().getAccessibleDescription());
            bar.state("Signing in...", "", true); assertFalse(bar.isLogOpen());
            toggle(bar).doClick();
            assertTrue(bar.isLogOpen()); assertFalse(bar.isCacheOpen());
            assertEquals("Show this journey's event history.", toggle(bar).getAccessibleContext().getAccessibleDescription());
            bar.highlightLog("journey"); assertEquals("Show this journey's event history.", toggle(bar).getAccessibleContext().getAccessibleDescription());
            bar.setLogOpen(false); bar.highlightLog("journey");
            assertEquals("New test events available", toggle(bar).getAccessibleContext().getAccessibleDescription());
            bar.setLogOpen(true); assertEquals("Show this journey's event history.", toggle(bar).getAccessibleContext().getAccessibleDescription());
        });
    }

    @Test void logHighlightBelongsToItsJourneyAcrossSelectionChangesAndBackgroundCompletion() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var bar = new SessionStatusBar(); bar.context("first"); bar.highlightLog("first");
            bar.context("second"); assertEquals("Show this journey's event history.", toggle(bar).getAccessibleContext().getAccessibleDescription());
            bar.highlightLog("first"); assertEquals("Show this journey's event history.", toggle(bar).getAccessibleContext().getAccessibleDescription());
            bar.context("first"); assertEquals("New test events available", toggle(bar).getAccessibleContext().getAccessibleDescription());
            toggle(bar).doClick(); assertEquals("Show this journey's event history.", toggle(bar).getAccessibleContext().getAccessibleDescription());
            bar.context("second"); bar.highlightLog("first");
            bar.context("first"); assertEquals("Show this journey's event history.", toggle(bar).getAccessibleContext().getAccessibleDescription(), "Selecting a journey with its log already open acknowledges its events.");
        });
    }
    @Test void savedNoticeExpiresBackToLiveStateWithoutASecondOutput() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var time = new AtomicLong(); var bar = new SessionStatusBar(time::get);
            bar.state("Authenticated", "", false); bar.setText("Settings saved.");
            assertEquals("Settings saved.", bar.getText()); time.set(4_000_000_001L);
            bar.state("Authenticated", "", false); assertEquals("Authenticated", bar.getText());
            assertTrue(toggle(bar).getText().startsWith("Event log")); assertFalse(bar.isLogOpen());
        });
    }
    @Test void actionableFailurePersistsAndLogDockStaysOpenAcrossPolling() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var time = new AtomicLong(); var bar = new SessionStatusBar(time::get);
            bar.error("Session cookie was not found. Check the cookie name and URL."); time.set(Long.MAX_VALUE / 2);
            bar.state("Not authenticated", "", false); assertTrue(bar.getText().contains("Check the cookie name"));
            assertTrue(toggle(bar).isVisible()); toggle(bar).doClick();
            assertTrue(bar.isLogOpen()); bar.state("Not authenticated", "", false);
            assertTrue(bar.isLogOpen());
        });
    }
    @Test void switchingIdentityOrStartingAnAttemptRemovesObsoleteGuidance() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var bar = new SessionStatusBar(); bar.context("one"); bar.error("Enter the old PIN. Open settings."); toggle(bar).doClick();
            bar.context("two"); bar.state("Not authenticated", "", false);
            assertEquals("Not authenticated", bar.getText()); assertTrue(bar.isLogOpen());
            bar.error("Previous attempt failed. Correct the settings.");
            bar.state("Signing in... · 3 requests waiting", "", true);
            assertEquals("Signing in... · 3 requests waiting", bar.getText()); assertTrue(bar.isLogOpen());
        });
    }
    @Test void compactActionBarHasNoStatusTextAtSupportedWidths() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var bar = new SessionStatusBar(); bar.addAction(new JButton("Retry"));
            bar.error("Session cookie was not found. " + "Check the configured cookie name and URL. ".repeat(12));
            toggle(bar).doClick(); bar.refreshPresentation();
            for (int width : new int[]{700, 960, 1500}) {
                bar.setSize(width, bar.getPreferredSize().height); layout(bar); layout(bar);
                assertTrue(bar.getHeight() < 80);
                assertTrue(toggle(bar).getX() >= 0); assertTrue(bar.getPreferredSize().height < 200);
                assertFalse(containsTextOutput(bar), "the toolbar must not display authentication or action messages");
            }
        });
    }
    @Test void fieldGuidanceClearsAfterEditingAndDoesNotOccupyHiddenRows() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var input = new JTextField(); var row = InlineValidation.wrap(input);
            InlineValidation.show(input, "Enter a valid URL.");
            var guidance = (JTextArea) input.getClientProperty("validationMessage"); assertTrue(guidance.isVisible());
            input.setText("https://example.test"); assertFalse(guidance.isVisible());
            InlineValidation.show(input, "Check this value."); InlineValidation.visible(input, false);
            assertFalse(row.isVisible()); assertFalse(guidance.isVisible());
            InlineValidation.visible(input, true); assertTrue(row.isVisible()); assertFalse(guidance.isVisible());
        });
    }
    /** @param bar Owned status bar. @return Single details disclosure. */
    private static JToggleButton toggle(Container bar) { for (var child : bar.getComponents()) { if (child instanceof JToggleButton button) return button; if (child instanceof Container container) { var found = findToggle(container); if (found != null) return found; } } throw new AssertionError("No disclosure"); }
    /** @param parent Owned subtree. @return Disclosure or null. */
    private static JToggleButton findToggle(Container parent) { for (var child : parent.getComponents()) { if (child instanceof JToggleButton button) return button; if (child instanceof Container container) { var found = findToggle(container); if (found != null) return found; } } return null; }
    /** @param component Owned component subtree. */
    private static void layout(Component component) { if (component instanceof Container container) { container.doLayout(); for (var child : container.getComponents()) layout(child); } }
    /** @param component Owned toolbar subtree. @return Whether a visible text-output control remains beside its actions. */
    private static boolean containsTextOutput(Component component) { if (component instanceof javax.swing.text.JTextComponent || component instanceof JLabel) return component.isVisible(); if (component instanceof Container parent) for (var child : parent.getComponents()) if (containsTextOutput(child)) return true; return false; }
}
