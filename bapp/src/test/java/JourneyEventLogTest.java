import org.junit.jupiter.api.Test;
import javax.swing.*;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

/** Establishes bounded history, actual coordinator coverage and native event-dock behavior. */
class JourneyEventLogTest {
    private static final Instant NOW = Instant.parse("2026-11-05T12:00:00Z");
    /** @return Fresh stable owner independent of its readable alias. */
    private static SecretStore.Key key() { return new SecretStore.Key(JourneyDefinition.Scope.PROJECT, UUID.randomUUID()); }

    @Test void historyIsIsolatedByStableIdentityAndCoalescesRepeatedWarnings() {
        var log = new JourneyEventLog(); var first = key(); var second = key();
        log.append(first, NOW, JourneyEventLog.Level.ERROR, "Missing PIN. Enter it in certificate settings.");
        log.append(second, NOW, JourneyEventLog.Level.INFO, "Login succeeded.");
        log.append(first, NOW.plusSeconds(1), JourneyEventLog.Level.ERROR, "Missing PIN. Enter it in certificate settings.");
        assertEquals(1, log.snapshot(first).size()); assertEquals(1, log.snapshot(second).size());
        assertFalse(log.snapshot(first).getFirst().message().contains("succeeded"));
        log.clear(first); assertTrue(log.snapshot(first).isEmpty()); assertEquals(1, log.snapshot(second).size());
        log.close(); log.append(first, NOW, JourneyEventLog.Level.INFO, "Late completion."); assertTrue(log.snapshot(first).isEmpty());
    }
    @Test void bothPerJourneyAndTotalHistoryHaveFiniteBounds() {
        var log = new JourneyEventLog(); var first = key();
        for (int i = 0; i < 250; i++) log.append(first, NOW.plusSeconds(i), JourneyEventLog.Level.INFO, "Attempt " + i);
        assertEquals(200, log.snapshot(first).size()); assertEquals("Attempt 50", log.snapshot(first).getFirst().message());
        var owners = java.util.stream.IntStream.range(0, 24).mapToObj(i -> key()).toList();
        for (var owner : owners) for (int i = 0; i < 200; i++) log.append(owner, NOW.plusSeconds(i), JourneyEventLog.Level.INFO, "Event " + i);
        assertEquals(4000, owners.stream().mapToInt(owner -> log.snapshot(owner).size()).sum()); assertTrue(log.snapshot(first).isEmpty());
        log.append(first, NOW, JourneyEventLog.Level.ERROR, "x".repeat(10000)); assertTrue(log.snapshot(first).getFirst().message().length() <= JourneyEventLog.MESSAGE_LIMIT + 1);
    }
    @Test void automaticAcquisitionLogsLifecycleWithoutDependingOnUiPollingOrRetainingTokenValues() {
        try (var fixture = new AuthenticationCoordinatorTest.Fixture(Config.Controls.defaults())) {
            var owner = fixture.entry(0).identity().key(); var ticket = fixture.acquire(0); fixture.clock.runWorker(); ticket.future().join();
            var messages = fixture.coordinator.events().snapshot(owner).stream().map(JourneyEventLog.Event::message).toList();
            assertEquals(List.of("Authentication queued.", "Login attempt 1 started.", "Credentials captured."), messages);
            assertFalse(messages.toString().contains("fixture-")); assertTrue(fixture.coordinator.events().snapshot(fixture.entry(1).identity().key()).isEmpty());
            fixture.coordinator.invalidate(fixture.entry(0).identity()); assertTrue(fixture.coordinator.events().snapshot(owner).getLast().message().contains("cleared"));
        }
    }
    @Test void applicationResponseFeedbackReportsItsStatusWithoutClaimingAuthentication() {
        for (int status : List.of(200, 204)) try (var fixture = new AuthenticationCoordinatorTest.Fixture(Config.Controls.defaults());
                var recovery = new SessionRecovery(fixture.coordinator, fixture.clock::nanos)) {
            var ticket = fixture.acquire(0); fixture.clock.runWorker(); ticket.future().join();
            var entry = fixture.entry(0); var token = fixture.coordinator.peek(entry.identity());
            var rule = new JourneyDefinition.Recovery(false, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null);
            recovery.record(17, List.of(new SessionRecovery.Used(entry.identity(), token.version(), rule)), false);
            recovery.receivedPlan(17, status, () -> { throw new AssertionError("Status feedback must not inspect a login page's body."); }, false, true);
            var message = fixture.coordinator.events().snapshot(entry.identity().key()).getLast().message();
            assertEquals("Request using this journey's credentials returned HTTP " + status + ".", message);
            assertFalse(message.toLowerCase().contains("accepted"));
        }
    }
    @Test void terminalFailuresRecordSafeRecovery() {
        try (var fixture = new AuthenticationCoordinatorTest.Fixture(Config.Controls.defaults())) {
            var failure = new AuthenticationFailure(AuthenticationFailure.Phase.EXTRACTION, AuthenticationFailure.Cause.EXTRACTION, "Session cookie missing.", "Check the cookie name.");
            fixture.fail.set(failure); var ticket = fixture.acquire(0); fixture.clock.runWorker(); assertTrue(ticket.future().isCompletedExceptionally());
            var last = fixture.coordinator.events().snapshot(fixture.entry(0).identity().key()).getLast();
            assertEquals(JourneyEventLog.Level.ERROR, last.level()); assertEquals(failure.getMessage(), last.message());
        }
    }
    @Test void backgroundRetryAndCancellationAreRecordedWithoutUiCallers() {
        try (var fixture = new AuthenticationCoordinatorTest.Fixture(Config.Controls.defaults())) {
            fixture.fail.set(CoordinatorFixtures.failure(AuthenticationFailure.Cause.TRANSPORT));
            fixture.acquire(0); fixture.clock.runWorker();
            var owner = fixture.entry(0).identity().key();
            assertTrue(fixture.coordinator.events().snapshot(owner).getLast().message().contains("Retrying in 5 seconds"));
            fixture.clock.advance(5000); assertTrue(fixture.coordinator.events().snapshot(owner).getLast().message().contains("attempt 2"));
            assertTrue(fixture.coordinator.cancelAuthentication(fixture.entry(0).identity()));
            assertTrue(fixture.coordinator.events().snapshot(owner).getLast().message().contains("cancelled"));
            assertEquals(JourneyEventLog.Level.WARNING, fixture.coordinator.events().snapshot(owner).getLast().level());
        }
    }
    @Test void eventDockFiltersLiteralTextAndSeverityAndSwitchesJourneyWithoutLeakingDetails() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var log = new JourneyEventLog(); var first = key(); var second = key();
            log.append(first, NOW, JourneyEventLog.Level.INFO, "Login started."); log.append(first, NOW.plusSeconds(1), JourneyEventLog.Level.ERROR, "<html>Missing cookie.");
            log.append(second, NOW, JourneyEventLog.Level.WARNING, "Cancelled.");
            var panel = new JourneyEventLogPanel(log, () -> {}); panel.refresh(first, "employee");
            var table = member(panel, "table", JTable.class); assertEquals(2, table.getRowCount());
            var search = member(panel, "search", JTextField.class); search.setText("<html>"); assertEquals(1, table.getRowCount());
            table.setRowSelectionInterval(0, 0); assertTrue(member(panel, "detail", JTextArea.class).getText().contains("<html>Missing cookie."));
            assertEquals("<html>Missing cookie.", ((JLabel) table.prepareRenderer(table.getCellRenderer(0, 2), 0, 2)).getText());
            search.setText(""); panel.refresh(second, "admin"); assertEquals(1, table.getRowCount());
            assertFalse(member(panel, "detail", JTextArea.class).getText().contains("cookie"));
            @SuppressWarnings("unchecked") var levels = (java.util.Map<JourneyEventLog.Level, JToggleButton>) member(panel, "levels", java.util.Map.class);
            levels.get(JourneyEventLog.Level.WARNING).doClick(); assertEquals(0, table.getRowCount());
            levels.get(JourneyEventLog.Level.WARNING).doClick(); member(panel, "clear", JButton.class).doClick(); assertEquals(0, table.getRowCount()); assertEquals(2, log.snapshot(first).size());
        });
    }
    @Test void compactDockKeepsTimestampAndEventDetailReadable() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var panel = new JourneyEventLogPanel(new JourneyEventLog(), () -> {});
            panel.setSize(960, 310); layout(panel); layout(panel); panel.initializeDivider(); layout(panel);
            var split = member(panel, "detailSplit", JSplitPane.class);
            assertTrue(split.getRightComponent().getWidth() >= 280);
            var table = member(panel, "table", JTable.class);
            assertTrue(table.getColumnModel().getColumn(0).getMinWidth() > table.getFontMetrics(table.getFont()).stringWidth("23:59:59 31 Dec 2026"));
        });
    }
    /** @param component Owned local layout subtree. */
    private static void layout(java.awt.Component component) { if (component instanceof java.awt.Container container) { container.doLayout(); for (var child : container.getComponents()) layout(child); } }
    /** @param target Owned test component. @param name Stable private seam. @param type Expected member type. @return Local component, never an installed-app control. */
    private static <T> T member(Object target, String name, Class<T> type) { try { var field = target.getClass().getDeclaredField(name); field.setAccessible(true); return type.cast(field.get(target)); } catch (ReflectiveOperationException error) { throw new AssertionError(error); } }
}
