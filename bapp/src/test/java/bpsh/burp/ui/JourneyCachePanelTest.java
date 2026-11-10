package bpsh.burp.ui;

import bpsh.journey.JourneyCatalog;
import bpsh.journey.persistence.JourneyDocument;

import bpsh.request.RequestSettings;
import bpsh.journey.persistence.ProjectStore;
import bpsh.journey.editing.JourneyWorkspace;
import bpsh.authentication.credentials.TokenLifetime;
import bpsh.authentication.credentials.TokenSnapshot;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.JourneyKey;
import bpsh.authentication.session.AuthenticationCoordinatorTest;
import bpsh.authentication.session.CoordinatorFixtures;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.swing.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Verifies explicit cache inspection without acquisition, cross-journey disclosure, logging or editable values. */
class JourneyCachePanelTest {
    @Test void unfinishedRecordingCanShowHttpAuthenticationBeforeCaptureRulesExist() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var base=CoordinatorFixtures.journey("http-user");var origin=java.net.URI.create("https://app.example");
            var draft=bpsh.journey.JourneyDraft.capture(Map.of("url",origin.toString()),Map.of("httpAuthentication",true),JourneyDefinition.SlotKind.INDEX,"",List.of(),List.of());
            var owner=new JourneyCatalog.Entry(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT,base.id(),1),draft.definition(base.id(),"HTTP user","http-user",false));
            var settings=new bpsh.journey.HttpAuthentication(bpsh.journey.HttpAuthentication.Protocol.NTLM_V2,"user-a","LAB","",java.util.Set.of(origin));
            var accepted=new bpsh.authentication.http.HttpAuthenticationProgress(bpsh.authentication.http.HttpAuthenticationProgress.Stage.ACCEPTED,
                    settings.protocol(),origin,Instant.now(),200);
            var panel=new JourneyCachePanel(()->{});panel.refresh(owner,null,List.of(accepted),settings);
            var table=member(panel,"table",JTable.class);assertEquals(1,table.getRowCount());
            assertEquals("HTTP auth",table.getValueAt(0,0));assertEquals(origin.toString(),table.getValueAt(0,2));assertTrue(httpDetails(table,0).contains("Accepted"));
            assertFalse(member(panel,"metadata",JPanel.class).isVisible());
            panel.refresh(owner,null,List.of(),null);assertEquals(0,table.getRowCount());
        });
    }
    @Test void httpOnlyIdentityAppearsBeforeAndAfterAuthenticationWithoutAFakeTokenOrCopyableSecret() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var base=CoordinatorFixtures.journey("http-user");var origin=java.net.URI.create("https://app.example");
            var definition=new JourneyDefinition(base.id(),base.displayName(),base.alias(),origin,false,List.of(),base.browser(),null,
                    JourneyDefinition.Injection.perToken(List.of()),base.cache(),null,
                    new bpsh.journey.HttpAuthentication(bpsh.journey.HttpAuthentication.Protocol.NTLM_V2,"user-a","LAB","",java.util.Set.of(origin)),null);
            var owner=new JourneyCatalog.Entry(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT,base.id(),1),definition);
            var copied=new java.util.ArrayList<String>();var panel=new JourneyCachePanel(()->{},message->{},copied::add);
            panel.refresh(owner,null);var table=member(panel,"table",JTable.class);
            assertEquals(1,table.getRowCount());assertEquals("HTTP auth",table.getValueAt(0,0));assertEquals("NTLMv2 · LAB\\user-a",table.getValueAt(0,1));
            assertEquals(origin.toString(),table.getValueAt(0,2));assertEquals("Not yet observed",httpDetails(table,0));
            assertFalse(member(panel,"metadata",JPanel.class).isVisible());assertFalse(member(panel,"copyValue",JMenuItem.class).isEnabled());
            var accepted=new bpsh.authentication.http.HttpAuthenticationProgress(bpsh.authentication.http.HttpAuthenticationProgress.Stage.ACCEPTED,
                    bpsh.journey.HttpAuthentication.Protocol.NTLM_V2,origin,Instant.parse("2026-11-09T12:00:00Z"),200);
            panel.refresh(owner,null,List.of(accepted));assertTrue(httpDetails(table,0).contains("Accepted"));
            assertEquals(origin.toString(),table.getValueAt(0,2));assertTrue(copied.isEmpty());
            panel.refresh(owner,null,List.of());assertEquals(origin.toString(),table.getValueAt(0,2));assertEquals("Not yet observed",httpDetails(table,0));
            panel.refresh(null,null,List.of(accepted));assertEquals(0,table.getRowCount());
        });
    }
    @Test void httpFailureUpdatesBesideCapturedCookiesWithoutChangingTheTokenLifetime() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var origin=java.net.URI.create("https://app.example");var original=entry(new JourneyDefinition.CookieExtraction(origin,"sid",null,"/"));
            var base=original.definition();var definition=new JourneyDefinition(base.id(),base.displayName(),base.alias(),origin,false,List.of(),base.browser(),
                    base.extraction(),base.injection(),base.cache(),null,
                    new bpsh.journey.HttpAuthentication(bpsh.journey.HttpAuthentication.Protocol.NTLM_V2,"user-a","LAB","",java.util.Set.of(origin)),null);
            var owner=new JourneyCatalog.Entry(original.identity(),definition);var captured=token(owner,"session-a",Map.of("sid","session-a"),Map.of());
            var panel=new JourneyCachePanel(()->{});panel.refresh(owner,captured);var table=member(panel,"table",JTable.class);
            assertEquals(2,table.getRowCount());assertEquals("session-a",table.getValueAt(0,2));
            String acquired=member(panel,"cached",JLabel.class).getText();
            var rejected=new bpsh.authentication.http.HttpAuthenticationProgress(bpsh.authentication.http.HttpAuthenticationProgress.Stage.REJECTED,
                    bpsh.journey.HttpAuthentication.Protocol.NTLM_V2,origin,Instant.now(),401);
            panel.refresh(owner,captured,List.of(rejected));assertEquals(origin.toString(),table.getValueAt(1,2));assertTrue(httpDetails(table,1).contains("Rejected"));
            assertNull(((JComponent)table.prepareRenderer(table.getCellRenderer(0,2),0,2)).getToolTipText(),"Cookie values must not inherit an HTTP tooltip");
            assertEquals(acquired,member(panel,"cached",JLabel.class).getText());assertEquals("session-a",table.getValueAt(0,2));
            table.setRowSelectionInterval(1,1);assertFalse(member(panel,"copyValue",JMenuItem.class).isEnabled());
            table.setRowSelectionInterval(0,0);assertTrue(member(panel,"copyValue",JMenuItem.class).isEnabled());
        });
    }
    @org.junit.jupiter.api.io.TempDir java.nio.file.Path root;
    /** @return Status information shown on hover, separate from the origin-only Value cell. */
    private static String httpDetails(JTable table,int row) { return ((JComponent)table.prepareRenderer(table.getCellRenderer(row,2),row,2)).getToolTipText(); }
    /** @param extraction Configured sources. @return Owned immutable generation. */
    private static JourneyCatalog.Entry entry(JourneyDefinition.Extraction extraction) {
        var base = CoordinatorFixtures.journey("employee");
        var definition = new JourneyDefinition(base.id(), base.displayName(), base.alias(), base.authenticationUrl(), false, List.of(), base.browser(), extraction, base.injection(), base.cache(), null);
        return new JourneyCatalog.Entry(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, base.id(), 1), definition);
    }
    /** @param entry Exact publication owner. @param primary Primary captured value. @param cookies Captured cookies. @param names All named credentials. @return Synthetic, bounded cache publication. */
    private static TokenSnapshot token(JourneyCatalog.Entry entry, String primary, Map<String, String> cookies, Map<String, String> names) {
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
    @Test void unfinishedConfigurationStillDisplaysThePreviouslyCapturedValuesAndTiming() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var base = CoordinatorFixtures.journey("employee"); var owner = entry(base.extraction());
            var original = token(owner, "qa-access", Map.of(), Map.of());
            var draft = bpsh.journey.JourneyDraft.capture(Map.of("url", "unfinished"), Map.of(), JourneyDefinition.SlotKind.INDEX, "", List.of(), List.of());
            var unfinished = new JourneyCatalog.Entry(new JourneyDefinition.Identity(owner.identity().scope(), owner.identity().journeyId(), 2),
                    draft.definition(owner.definition().id(), "employee", "employee", false));
            var retained = new TokenSnapshot(unfinished.identity(), original.version(), original.value(), original.lifetime(), original.cookies(), original.namedTokens(), owner.definition().extraction());
            var panel = new JourneyCachePanel(() -> {}); panel.refresh(unfinished, retained);
            var table = member(panel, "table", JTable.class); assertEquals(1, table.getRowCount());
            assertEquals("Default", table.getValueAt(0, 1)); assertEquals("qa-access", table.getValueAt(0, 2));
            assertTrue(member(panel, "metadata", JPanel.class).isVisible());
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
            var other = new JourneyCatalog.Entry(new JourneyDefinition.Identity(entry.identity().scope(), UUID.randomUUID(), 1), entry.definition());
            panel.refresh(other, token); assertCleared(panel);
            panel.refresh(entry, token); panel.refresh(entry, null); assertCleared(panel);
            panel.refresh(entry, token); panel.clear(); assertCleared(panel);
        });
    }
    @Test void inspectionReadsTheExistingPublicationWithoutStartingOrJoiningAuthentication() throws Exception {
        try (var fixture = new AuthenticationCoordinatorTest.Fixture(RequestSettings.Controls.defaults())) {
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
        try (var editor = harness.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
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
