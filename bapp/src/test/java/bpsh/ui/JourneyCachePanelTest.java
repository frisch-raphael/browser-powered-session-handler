package bpsh.ui;

import bpsh.config.Config;
import bpsh.config.ConfigManager;
import bpsh.config.JourneyRegistry;
import bpsh.credentials.TokenLifetime;
import bpsh.credentials.TokenSnapshot;
import bpsh.model.JourneyDefinition;
import bpsh.model.JourneyKey;
import bpsh.session.AuthenticationCoordinatorTest;
import bpsh.session.CoordinatorFixtures;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.swing.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Verifies explicit cache inspection without acquisition, cross-journey disclosure, logging or editable values. */
class JourneyCachePanelTest {
    @org.junit.jupiter.api.io.TempDir java.nio.file.Path root;
    /** @param extraction Configured sources. @return Owned immutable generation. */
    private static JourneyRegistry.Entry entry(JourneyDefinition.Extraction extraction) {
        var base = CoordinatorFixtures.journey("employee");
        var definition = new JourneyDefinition(base.id(), base.displayName(), base.alias(), base.authenticationUrl(), false, List.of(), base.browser(), extraction, base.injection(), base.cache(), null);
        return new JourneyRegistry.Entry(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, base.id(), 1), definition);
    }
    /** @param entry Exact publication owner. @param primary Primary captured value. @param cookies Captured cookies. @param names All named credentials. @return Synthetic, bounded cache publication. */
    private static TokenSnapshot token(JourneyRegistry.Entry entry, String primary, Map<String, String> cookies, Map<String, String> names) {
        var lifetime = new TokenLifetime.Window(Instant.parse("2026-11-05T12:00:00Z"), 0, 60_000_000_000L, 50_000_000_000L, java.util.OptionalLong.empty());
        return new TokenSnapshot(entry.identity(), 1, primary, lifetime, cookies, names);
    }
    @Test void combinedTokensAndCookiesAppearOnceWithNamesAndReadOnlyValues() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var base = CoordinatorFixtures.journey("employee");
            var entry = entry(new JourneyDefinition.CombinedExtraction(List.of(new JourneyDefinition.NamedExtraction("access", base.extraction()), new JourneyDefinition.NamedExtraction("session", new JourneyDefinition.CookieExtraction(java.net.URI.create("https://app.example/"), "sid", null, null)))));
            var panel = new JourneyCachePanel(() -> {}); panel.refresh(entry, token(entry, "qa-access", Map.of("sid", "qa-session"), Map.of("access", "qa-access", "session", "qa-session")));
            var table = member(panel, "table", JTable.class); assertEquals(2, table.getRowCount());
            assertEquals("access", table.getValueAt(0, 1)); assertEquals("qa-access", table.getValueAt(0, 2));
            assertEquals("Cookie", table.getValueAt(1, 0)); assertEquals("session (sid)", table.getValueAt(1, 1)); assertEquals("qa-session", table.getValueAt(1, 2));
            assertFalse(table.isCellEditable(0, 2)); assertEquals(0, descendants(panel, JSplitPane.class));
            assertNotNull(member(panel, "expires", JLabel.class).getToolTipText());
            assertFalse(member(member(panel, "model", Object.class), "rows", List.class).toString().contains("qa-access"));
        });
    }
    @Test void singleCookieIsNotDuplicatedAsAPrimaryTokenAndHtmlLookingValuesRemainLiteral() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var entry = entry(new JourneyDefinition.CookieExtraction(java.net.URI.create("https://app.example/"), "sid", null, null));
            var panel = new JourneyCachePanel(() -> {}); panel.refresh(entry, token(entry, "<html>qa-session", Map.of("sid", "<html>qa-session"), Map.of()));
            var table = member(panel, "table", JTable.class); assertEquals(1, table.getRowCount()); assertEquals("Cookie", table.getValueAt(0, 0));
            assertEquals("<html>qa-session", ((JLabel) table.prepareRenderer(table.getCellRenderer(0, 2), 0, 2)).getText());
        });
    }
    @Test void fixedTimingPreservesSelectionAndExposesFullTimesWithoutHtml() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            Instant acquired = Instant.parse("2026-11-05T12:00:00Z");
            var panel = new JourneyCachePanel(() -> {});
            var base = CoordinatorFixtures.journey("employee");
            var owner = entry(new JourneyDefinition.CombinedExtraction(List.of(new JourneyDefinition.NamedExtraction("access", base.extraction()), new JourneyDefinition.NamedExtraction("session", new JourneyDefinition.CookieExtraction(java.net.URI.create("https://app.example/"), "sid", null, null)))));
            var snapshot = token(owner, "qa-access", Map.of("sid", "qa-session"), Map.of("access", "qa-access", "session", "qa-session"));
            panel.refresh(owner, snapshot);
            var expiry = member(panel, "expires", JLabel.class); var refresh = member(panel, "refresh", JLabel.class); var cached = member(panel, "cached", JLabel.class);
            var compact = java.time.format.DateTimeFormatter.ofPattern("dd MMM, HH:mm:ss").withZone(java.time.ZoneId.systemDefault());
            assertEquals(compact.format(acquired.plusSeconds(60)), expiry.getText()); assertEquals(compact.format(acquired.plusSeconds(50)), refresh.getText()); assertEquals(compact.format(acquired), cached.getText());
            assertEquals("Expires: " + java.time.format.DateTimeFormatter.ofPattern("dd MMM uuuu HH:mm:ss z").withZone(java.time.ZoneId.systemDefault()).format(acquired.plusSeconds(60)), expiry.getToolTipText());
            assertFalse(expiry.getToolTipText().contains("<html>")); assertEquals(expiry.getToolTipText(), expiry.getAccessibleContext().getAccessibleDescription());
            var table = member(panel, "table", JTable.class); table.setRowSelectionInterval(1, 1);
            for (int i = 0; i < 5; i++) panel.refresh(owner, snapshot);
            assertEquals(compact.format(acquired.plusSeconds(60)), expiry.getText()); assertEquals(compact.format(acquired.plusSeconds(50)), refresh.getText()); assertEquals(compact.format(acquired), cached.getText()); assertEquals(1, table.getSelectedRow());
            panel.clear(); assertCleared(panel);
        });
    }
    @Test void cacheSummaryRendersAtCompactAndWideDockWidths() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var owner = entry(CoordinatorFixtures.journey("employee").extraction());
            var panel = new JourneyCachePanel(() -> {});
            var lifetime = new TokenLifetime.Window(Instant.parse("2026-11-05T12:00:00Z"), 0, 86_400_000_000_000L, 82_800_000_000_000L, java.util.OptionalLong.empty());
            panel.refresh(owner, new TokenSnapshot(owner.identity(), 1, "qa-access", lifetime, Map.of(), Map.of()));
            for (int width : new int[]{740, 1100}) {
                panel.setSize(width, 250); layout(panel);
                var summary = member(panel, "metadata", JPanel.class);
                for (var child : summary.getComponents()) assertTrue(child.getX() + child.getWidth() <= summary.getWidth());
                var image = new java.awt.image.BufferedImage(width, 250, java.awt.image.BufferedImage.TYPE_INT_RGB);
                var graphics = image.createGraphics(); panel.printAll(graphics); graphics.dispose();
                try { var out = java.nio.file.Path.of("build/ui-previews"); java.nio.file.Files.createDirectories(out); javax.imageio.ImageIO.write(image, "png", out.resolve("cache-timing-" + width + ".png").toFile()); }
                catch (java.io.IOException error) { throw new AssertionError(error); }
            }
        });
    }
    @Test void contextActionsCopyTokenNamesCookieNamesAndCompleteValuesOnlyWhenInvoked() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var copied = new java.util.ArrayList<String>(); var feedback = new java.util.ArrayList<String>();
            var base = CoordinatorFixtures.journey("employee");
            var owner = entry(new JourneyDefinition.CombinedExtraction(List.of(new JourneyDefinition.NamedExtraction("access", base.extraction()), new JourneyDefinition.NamedExtraction("session", new JourneyDefinition.CookieExtraction(java.net.URI.create("https://app.example/"), "sid", null, null)))));
            String longValue = "qa-" + "x".repeat(4096);
            var panel = new JourneyCachePanel(() -> {}, feedback::add, copied::add);
            panel.refresh(owner, token(owner, longValue, Map.of("sid", "qa-session"), Map.of("access", longValue, "session", "qa-session")));
            assertTrue(copied.isEmpty());
            var table = member(panel, "table", JTable.class); var name = member(panel, "copyName", JMenuItem.class); var value = member(panel, "copyValue", JMenuItem.class);
            assertEquals("Copy name", name.getText()); assertEquals("Copy value", value.getText());
            name.doClick(); value.doClick(); table.setRowSelectionInterval(1, 1); name.doClick(); value.doClick();
            assertEquals(List.of("access", longValue, "sid", "qa-session"), copied);
            assertTrue(feedback.isEmpty(), "successful copy needs no status message");
            assertNotNull(table.getInputMap().get(KeyStroke.getKeyStroke("shift F10")));
            assertNotNull(table.getInputMap().get(KeyStroke.getKeyStroke("CONTEXT_MENU")));
            assertFalse(feedback.toString().contains(longValue)); assertFalse(feedback.toString().contains("qa-session"));
        });
    }
    @Test void missingSelectionAndInvalidationDisableCopyWithoutRetainingOldMenuValues() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var copied = new java.util.ArrayList<String>(); var panel = new JourneyCachePanel(() -> {}, message -> {}, copied::add);
            var name = member(panel, "copyName", JMenuItem.class); var value = member(panel, "copyValue", JMenuItem.class);
            assertFalse(name.isEnabled()); assertFalse(value.isEnabled());
            var owner = entry(CoordinatorFixtures.journey("employee").extraction()); panel.refresh(owner, token(owner, "qa-access", Map.of(), Map.of()));
            member(panel, "table", JTable.class).clearSelection(); assertFalse(name.isEnabled()); assertFalse(value.isEnabled());
            member(panel, "table", JTable.class).setRowSelectionInterval(0, 0); assertTrue(value.isEnabled()); panel.clear();
            name.doClick(); value.doClick(); assertTrue(copied.isEmpty()); assertCleared(panel);
            panel.refresh(owner, token(owner, "qa-access", Map.of(), Map.of())); name.doClick(); assertEquals(List.of("Default"), copied);
        });
    }
    @Test void unavailableClipboardShowsActionableFeedbackWithoutValuesOrRawExceptions() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var feedback = new java.util.ArrayList<String>();
            var panel = new JourneyCachePanel(() -> {}, feedback::add, text -> { throw new IllegalStateException("sensitive clipboard failure"); });
            var owner = entry(CoordinatorFixtures.journey("employee").extraction()); panel.refresh(owner, token(owner, "qa-access", Map.of(), Map.of()));
            member(panel, "copyValue", JMenuItem.class).doClick();
            assertEquals(List.of("Could not access the clipboard. Try copying again."), feedback);
        });
    }
    @Test void wrongIdentityMissingPublicationAndClosingReleaseAllDisplayedValues() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var entry = entry(CoordinatorFixtures.journey("employee").extraction()); var panel = new JourneyCachePanel(() -> {});
            var token = token(entry, "qa-access", Map.of(), Map.of()); panel.refresh(entry, token);
            var other = new JourneyRegistry.Entry(new JourneyDefinition.Identity(entry.identity().scope(), UUID.randomUUID(), 1), entry.definition());
            panel.refresh(other, token); assertCleared(panel);
            panel.refresh(entry, token); panel.refresh(entry, null); assertCleared(panel);
            panel.refresh(entry, token); panel.clear(); assertCleared(panel);
        });
    }
    @Test void inspectionReadsTheExistingPublicationWithoutStartingOrJoiningAuthentication() throws Exception {
        try (var fixture = new AuthenticationCoordinatorTest.Fixture(Config.Controls.defaults())) {
            var ticket = fixture.acquire(0); fixture.clock.runWorker(); ticket.future().join();
            var owner = fixture.entry(0); var events = fixture.coordinator.events().snapshot(owner.identity().key());
            SwingUtilities.invokeAndWait(() -> { var panel = new JourneyCachePanel(() -> {}); for (int i = 0; i < 5; i++) panel.refresh(owner, fixture.coordinator.peek(owner.identity())); assertEquals(1, member(panel, "table", JTable.class).getRowCount()); fixture.coordinator.invalidate(owner.identity()); panel.refresh(owner, fixture.coordinator.peek(owner.identity())); assertCleared(panel); });
            assertEquals(1, fixture.attempts.get()); assertTrue(fixture.clock.workers.isEmpty());
            assertEquals(events.size() + 1, fixture.coordinator.events().snapshot(owner.identity().key()).size());
            assertFalse(fixture.coordinator.events().snapshot(owner.identity().key()).toString().contains("fixture-"));
        }
    }
    @Test void logAndCacheButtonsAreAdjacentMutuallyExclusiveAndIndependentlyClosable() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var status = new SessionStatusBar(); var log = member(status, "eventLog", JToggleButton.class); var cache = member(status, "cache", JToggleButton.class);
            assertSame(log.getParent(), cache.getParent()); assertEquals(0, ((java.awt.Container) log.getParent()).getComponentZOrder(log)); assertEquals(1, ((java.awt.Container) cache.getParent()).getComponentZOrder(cache));
            log.doClick(); assertTrue(status.isLogOpen()); cache.doClick(); assertFalse(status.isLogOpen()); assertTrue(status.isCacheOpen());
            cache.doClick(); assertFalse(status.isCacheOpen()); status.cacheAvailable(false); assertFalse(cache.isEnabled());
        });
    }
    @Test void controllerClearsInspectionOnLogSwitchStaleSelectionAndUnloadWithoutAcquiring() throws Exception {
        var harness = new JourneyRegistryTest().new NativeUi(); harness.root = root;
        try (var editor = harness.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
            var owner = editor.registry.snapshot().resolve("employee");
            harness.edt(() -> harness.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, owner.identity().key()));
            harness.await(() -> { try { return !(boolean) harness.member(editor.ui, "editorLoading"); } catch (Exception error) { return false; } });
            harness.edt(() -> {
                SessionStatusBar status = harness.member(editor.ui, "status"); JourneyCachePanel panel = harness.member(editor.ui, "cacheView");
                status.setCacheOpen(true); harness.call(editor.ui, "showEventDock", new Class<?>[]{}); assertTrue(editor.clock.workers.isEmpty());
                panel.refresh(owner, token(owner, "qa-access", Map.of(), Map.of()));
                status.setLogOpen(true); harness.call(editor.ui, "showEventDock", new Class<?>[]{}); assertCleared(panel);
                status.setCacheOpen(true); harness.call(editor.ui, "showEventDock", new Class<?>[]{}); panel.refresh(owner, token(owner, "qa-access", Map.of(), Map.of()));
                editor.registry.disableScope(JourneyDefinition.Scope.PROJECT); harness.call(editor.ui, "refreshJourneyUi", new Class<?>[]{}); assertCleared(panel);
                panel.refresh(owner, token(owner, "qa-access", Map.of(), Map.of())); editor.ui.shutdown(); assertCleared(panel);
            });
        }
    }
    /** @param panel Owned inspector. */
    private static void assertCleared(JourneyCachePanel panel) { assertEquals(0, member(panel, "table", JTable.class).getRowCount()); assertFalse(member(panel, "metadata", JPanel.class).isVisible()); for (String name : List.of("expires", "refresh", "cached")) { var label = member(panel, name, JLabel.class); assertEquals("", label.getText()); assertNull(label.getToolTipText()); assertNull(label.getAccessibleContext().getAccessibleDescription()); } assertEquals("", member(panel, "renderer", JLabel.class).getText()); assertFalse(member(panel, "copyName", JMenuItem.class).isEnabled()); assertFalse(member(panel, "copyValue", JMenuItem.class).isEnabled()); }
    /** @param component Offscreen native hierarchy to lay out before rendering. */
    private static void layout(java.awt.Component component) { if (component instanceof java.awt.Container container) { container.doLayout(); for (var child : container.getComponents()) layout(child); } }
    /** @param parent Owned component hierarchy. @param type Removed detail-container type. @return Matching descendants. */
    private static int descendants(java.awt.Container parent, Class<?> type) { int count = 0; for (var child : parent.getComponents()) { if (type.isInstance(child)) count++; if (child instanceof java.awt.Container container) count += descendants(container, type); } return count; }
    /** @param target Owned local component. @param name Test seam. @param type Expected member type. @return Local member only; never an installed application. */
    private static <T> T member(Object target, String name, Class<T> type) { try { var field = target.getClass().getDeclaredField(name); field.setAccessible(true); return type.cast(field.get(target)); } catch (ReflectiveOperationException error) { throw new AssertionError(error); } }
}
