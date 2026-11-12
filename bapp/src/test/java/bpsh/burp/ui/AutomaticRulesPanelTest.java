package bpsh.burp.ui;

import bpsh.request.RequestSettings;
import bpsh.burp.http.OrderedSessionHandlingTest;
import bpsh.journey.JourneyDefinition;
import bpsh.authentication.session.CoordinatorFixtures;
import java.awt.*;
import java.net.URI;
import java.util.List;
import javax.swing.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises visible list actions and incomplete rule edits on the Swing event thread. */
class AutomaticRulesPanelTest {
    @Test void listenerRefreshPreservesMissingPortAndUnfinishedRegexWithoutSaving() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var panel=new AutomaticRulesPanel();var journey=CoordinatorFixtures.journey("first");
            var key=new RequestSettings.JourneySelection(JourneyDefinition.Scope.PROJECT,journey.id());
            panel.setRules(List.of(new RequestSettings.AutomaticRule(true,key,new RequestSettings.Regex("/login"),8081,OrderedSessionHandlingTest.RECOVERY)));
            assertTrue(panel.useRegex.isSelected());assertEquals("Regex matched anywhere in the URL.",panel.useRegex.getToolTipText());
            panel.prefix.setText("unfinished[");
            var changes=new java.util.concurrent.atomic.AtomicInteger();panel.onChange(changes::incrementAndGet);
            panel.setListeners(List.of(new bpsh.burp.http.ProxyListeners.Choice(8082,true,List.of())),null);
            assertEquals("unfinished[",panel.prefix.getText());
            assertEquals(8081,((AutomaticRulesPanel.Port)panel.proxyPort.getSelectedItem()).value());
            assertTrue(panel.proxyPort.getSelectedItem().toString().contains("not configured"));
            panel.setListeners(List.of(new bpsh.burp.http.ProxyListeners.Choice(8081,false,List.of())),null);
            assertTrue(panel.proxyPort.getSelectedItem().toString().contains("stopped"));
            panel.setListeners(List.of(),"Could not refresh proxy ports.");
            assertEquals(8081,panel.snapshot().getFirst().proxyPort());assertEquals(0,changes.get());
            panel.setListeners(List.of(new bpsh.burp.http.ProxyListeners.Choice(8081,true,List.of())),null);
            assertEquals("8081",panel.proxyPort.getSelectedItem().toString());assertEquals(0,changes.get());
        });
    }
    @Test void hostThemeRefreshRestoresTaskLabelsWithoutChangingSavedModes() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var panel = new AutomaticRulesPanel();
            panel.urlMode.setSelectedItem(AutomaticRulesPanel.Mode.SINGLE_URL); panel.recoveryMode.setSelectedItem(JourneyDefinition.RecoveryMode.BOTH);
            panel.urlMode.setRenderer(new DefaultListCellRenderer()); panel.recoveryMode.setRenderer(new DefaultListCellRenderer());
            panel.refreshPresentation();
            assertEquals("Custom URL", ((JLabel) panel.urlMode.getRenderer().getListCellRendererComponent(new JList<>(), AutomaticRulesPanel.Mode.SINGLE_URL, -1, false, false)).getText());
            assertEquals("HTTP status or response text", ((JLabel) panel.recoveryMode.getRenderer().getListCellRendererComponent(new JList<>(), JourneyDefinition.RecoveryMode.BOTH, -1, false, false)).getText());
            assertEquals(AutomaticRulesPanel.Mode.SINGLE_URL, panel.urlMode.getSelectedItem()); assertEquals(JourneyDefinition.RecoveryMode.BOTH, panel.recoveryMode.getSelectedItem());
        });
    }
    @Test void addReorderDisableRemoveAndRefreshKeepEachRulesIdentityAndDetails() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var panel = new AutomaticRulesPanel(); var first = CoordinatorFixtures.journey("first"); var second = CoordinatorFixtures.journey("second");
            var a = new RequestSettings.JourneySelection(JourneyDefinition.Scope.PROJECT, first.id()); var b = new RequestSettings.JourneySelection(JourneyDefinition.Scope.LIBRARY, second.id());
            panel.setJourneys(List.of(new AutomaticRulesPanel.Option(a, "<html>Literal first"), new AutomaticRulesPanel.Option(b, "Second")));
            find(panel, "Add automatic journey").doClick(); find(panel, "Add automatic journey").doClick();
            assertFalse(find(panel, "Add automatic journey").isEnabled()); assertEquals(List.of(a, b), panel.snapshot().stream().map(RequestSettings.AutomaticRule::journey).toList());
            panel.urlMode.setSelectedItem(AutomaticRulesPanel.Mode.SINGLE_URL); panel.prefix.setText("https://app.example/admin/");
            find(panel, "Move rule up").doClick(); assertEquals(List.of(b, a), panel.snapshot().stream().map(RequestSettings.AutomaticRule::journey).toList());
            assertEquals(URI.create("https://app.example/admin/"), ((RequestSettings.Prefix) panel.snapshot().getFirst().url()).value()); assertEquals(0, panel.table.getSelectedRow());
            panel.table.setValueAt(false, 1, 0); assertFalse(panel.snapshot().get(1).enabled());
            panel.setJourneys(List.of(new AutomaticRulesPanel.Option(a, "Renamed first"))); assertEquals(0, panel.table.getSelectedRow()); assertEquals("Unavailable journey", panel.table.getValueAt(0, 1)); assertEquals(b, panel.snapshot().getFirst().journey());
            find(panel, "Remove automatic rule").doClick(); assertEquals(List.of(a), panel.snapshot().stream().map(RequestSettings.AutomaticRule::journey).toList());
            assertFalse(find(panel, "Move rule up").isEnabled()); assertFalse(find(panel, "Move rule down").isEnabled());
        });
    }
    @Test void invalidDraftsNeverEraseRowsAndRe2StatusAndPrefixFieldsFollowTheirMode() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var panel = new AutomaticRulesPanel(); var j = CoordinatorFixtures.journey("first"); var key = new RequestSettings.JourneySelection(JourneyDefinition.Scope.PROJECT, j.id());
            panel.setRules(List.of(new RequestSettings.AutomaticRule(true, key, new RequestSettings.AllRequests(), null, OrderedSessionHandlingTest.RECOVERY)));
            panel.failureStatus.setText(""); assertThrows(IllegalArgumentException.class, panel::snapshot); assertEquals(1, panel.table.getRowCount());
            panel.recoveryMode.setSelectedItem(JourneyDefinition.RecoveryMode.REGEX); assertFalse(panel.failureStatus.isVisible()); assertTrue(panel.pattern.isVisible());
            panel.pattern.setText("session.*expired"); assertEquals("session.*expired", panel.snapshot().getFirst().recovery().pattern());
            panel.urlMode.setSelectedItem(AutomaticRulesPanel.Mode.SINGLE_URL); panel.prefix.setText("https://app.example/");
            panel.urlMode.setSelectedItem(AutomaticRulesPanel.Mode.ALL_REQUESTS); assertFalse(panel.prefix.isVisible()); assertEquals("", panel.prefix.getText()); assertInstanceOf(RequestSettings.AllRequests.class, panel.snapshot().getFirst().url());
            panel.detect.doClick(); assertFalse(panel.pattern.isVisible()); assertFalse(panel.snapshot().getFirst().recovery().enabled());
        });
    }
    @Test void failureStatusRequiresThreeDigitsInRangeOnlyWhenUsed() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var panel = new AutomaticRulesPanel(); var journey = CoordinatorFixtures.journey("first");
            var key = new RequestSettings.JourneySelection(JourneyDefinition.Scope.PROJECT, journey.id());
            panel.setRules(List.of(new RequestSettings.AutomaticRule(true, key, new RequestSettings.AllRequests(), null, OrderedSessionHandlingTest.RECOVERY)));
            var error = (JTextArea) panel.failureStatus.getClientProperty("validationMessage");
            for (var mode : List.of(JourneyDefinition.RecoveryMode.STATUS_CODE, JourneyDefinition.RecoveryMode.BOTH)) {
                panel.recoveryMode.setSelectedItem(mode); panel.pattern.setText("expired");
                for (var invalid : List.of("", "99", "099", "600", "999")) {
                    panel.failureStatus.setText(invalid);
                    assertEquals(invalid, panel.failureStatus.getText()); assertTrue(error.isVisible());
                    assertEquals("Enter an HTTP status from 100 to 599.", error.getText());
                    assertEquals(error.getText(), panel.failureStatus.getAccessibleContext().getAccessibleDescription());
                    assertThrows(IllegalArgumentException.class, panel::snapshot);
                }
                for (var valid : List.of("100", "401", "599")) {
                    panel.failureStatus.setText(valid); assertFalse(error.isVisible());
                    assertEquals(Integer.valueOf(valid), panel.snapshot().getFirst().recovery().statusCode());
                }
            }
            panel.failureStatus.setText(""); panel.detect.doClick();
            assertFalse(error.isVisible()); assertFalse(panel.snapshot().getFirst().recovery().enabled());
            panel.detect.doClick(); assertEquals("401", panel.failureStatus.getText()); assertFalse(error.isVisible());
            panel.recoveryMode.setSelectedItem(JourneyDefinition.RecoveryMode.REGEX); panel.pattern.setText("expired");
            assertFalse(error.isVisible()); assertFalse(panel.failureStatus.getParent().isVisible());
            assertNull(panel.snapshot().getFirst().recovery().statusCode());
            panel.recoveryMode.setSelectedItem(JourneyDefinition.RecoveryMode.STATUS_CODE);
            assertEquals("401", panel.failureStatus.getText()); assertFalse(error.isVisible());
            panel.failureStatus.setText("403"); assertFalse(error.isVisible());
        });
    }
    @Test void statusDetectionDefaultsTo401WithoutOverwritingAnExistingStatus() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var panel = new AutomaticRulesPanel(); var journey = CoordinatorFixtures.journey("first");
            var key = new RequestSettings.JourneySelection(JourneyDefinition.Scope.PROJECT, journey.id());
            panel.setJourneys(List.of(new AutomaticRulesPanel.Option(key, "Customer portal")));
            find(panel, "Add automatic journey").doClick(); assertEquals(401, panel.snapshot().getFirst().recovery().statusCode());
            panel.failureStatus.setText("403");
            panel.recoveryMode.setSelectedItem(JourneyDefinition.RecoveryMode.BOTH); panel.pattern.setText("expired");
            assertEquals(403, panel.snapshot().getFirst().recovery().statusCode());
            panel.recoveryMode.setSelectedItem(JourneyDefinition.RecoveryMode.REGEX);
            panel.recoveryMode.setSelectedItem(JourneyDefinition.RecoveryMode.BOTH);
            assertEquals(401, panel.snapshot().getFirst().recovery().statusCode());
            panel.detect.doClick(); panel.detect.doClick();
            assertEquals("401", panel.failureStatus.getText());
        });
    }
    @Test void failureStatusRejectsLettersSignsWhitespaceAndLongPastes() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var panel = new AutomaticRulesPanel(); var journey = CoordinatorFixtures.journey("first");
            var key = new RequestSettings.JourneySelection(JourneyDefinition.Scope.PROJECT, journey.id());
            panel.setRules(List.of(new RequestSettings.AutomaticRule(true, key, new RequestSettings.AllRequests(), null, OrderedSessionHandlingTest.RECOVERY)));
            for (var rejected : List.of("not-a-status", "40x", "-1", "+401", " 401 ", "4010", "４０１")) {
                panel.failureStatus.selectAll(); panel.failureStatus.replaceSelection(rejected);
                assertEquals("401", panel.failureStatus.getText());
            }
            panel.failureStatus.selectAll(); panel.failureStatus.replaceSelection("403");
            assertEquals(403, panel.snapshot().getFirst().recovery().statusCode());
            panel.failureStatus.setCaretPosition(3); panel.failureStatus.replaceSelection("0");
            assertEquals("403", panel.failureStatus.getText());
            panel.failureStatus.select(2, 3); panel.failureStatus.replaceSelection("");
            assertEquals("40", panel.failureStatus.getText()); assertThrows(IllegalArgumentException.class, panel::snapshot);
            panel.failureStatus.replaceSelection("1"); assertEquals(401, panel.snapshot().getFirst().recovery().statusCode());
        });
    }
    /** Captures native rendering for compact/wide visual review with the same real controller components. */
    @Test void rendersOrderedRulesAtCompactAndWideWidths() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var panel = new AutomaticRulesPanel(); var first = OrderedSessionHandlingTest.journey("first", true); var second = OrderedSessionHandlingTest.journey("second", true);
            var a = new RequestSettings.JourneySelection(JourneyDefinition.Scope.PROJECT, first.id()); var b = new RequestSettings.JourneySelection(JourneyDefinition.Scope.PROJECT, second.id());
            panel.setJourneys(List.of(new AutomaticRulesPanel.Option(a, "Customer portal"), new AutomaticRulesPanel.Option(b, "Administration")));
            panel.setRules(List.of(new RequestSettings.AutomaticRule(true, a, new RequestSettings.Prefix(URI.create("https://app.example/")), null, OrderedSessionHandlingTest.RECOVERY), new RequestSettings.AutomaticRule(true, b, new RequestSettings.Prefix(URI.create("https://app.example/admin/")), null, OrderedSessionHandlingTest.RECOVERY)));
            panel.failureStatus.setText("");
            for (int width : new int[]{740, 1100}) {
                panel.setSize(width, 640); layout(panel); assertTrue(panel.table.getWidth() > 500); assertTrue(panel.failureStatus.isVisible());
                var error = (JTextArea) panel.failureStatus.getClientProperty("validationMessage");
                assertTrue(error.isVisible()); assertTrue(error.getWidth() > 200); assertTrue(error.getHeight() >= error.getFontMetrics(error.getFont()).getHeight());
                var image = new java.awt.image.BufferedImage(width, 640, java.awt.image.BufferedImage.TYPE_INT_RGB); var g = image.createGraphics(); panel.printAll(g); g.dispose();
                try { var out = java.nio.file.Path.of("build/ui-previews"); java.nio.file.Files.createDirectories(out); javax.imageio.ImageIO.write(image, "png", out.resolve("ordered-session-handling-" + width + ".png").toFile()); } catch (java.io.IOException ex) { throw new AssertionError(ex); }
            }
        });
    }
    /** Returns a button by the same accessible action name used in the native UI. */
    private static JButton find(Component component, String action) { if (component instanceof JButton b && action.equals(b.getAccessibleContext().getAccessibleName())) return b; if (component instanceof Container c) for (var child : c.getComponents()) { var result = findOrNull(child, action); if (result != null) return result; } throw new AssertionError(action); }
    /** Finds an action in a child subtree, or returns null. */
    private static JButton findOrNull(Component component, String action) { if (component instanceof JButton b && action.equals(b.getAccessibleContext().getAccessibleName())) return b; if (component instanceof Container c) for (var child : c.getComponents()) { var result = findOrNull(child, action); if (result != null) return result; } return null; }
    /** Applies local layout managers recursively. */
    private static void layout(Component component) { if (component instanceof Container c) { c.doLayout(); for (var child : c.getComponents()) layout(child); } }
}
