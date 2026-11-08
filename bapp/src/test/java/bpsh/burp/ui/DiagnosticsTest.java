package bpsh.burp.ui;

import bpsh.burp.http.Diagnostics;
import bpsh.authentication.AuthenticationFailure;
import bpsh.authentication.session.CoordinatorFixtures;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Verifies actionable outcomes and repeated-warning suppression independently of Burp's logger. */
public class DiagnosticsTest {
    public @Test void errorsWithoutConfirmedRecoveryDisplayOnlyTheProblem() {
        var logs = new ArrayList<String>();
        try (var diagnostics = new Diagnostics(() -> 0, logs::add)) {
            var failure = new AuthenticationFailure(AuthenticationFailure.Phase.NAVIGATION,
                    AuthenticationFailure.Cause.UNKNOWN, "The browser could not open the login page.");
            assertEquals("", failure.recovery());
            assertEquals(failure.problem(), failure.getMessage());
            diagnostics.state("employee", failure);
            assertEquals(List.of("Journey employee: " + failure.problem()), logs);
        }
        var withAction = new AuthenticationFailure(AuthenticationFailure.Phase.SETUP,
                AuthenticationFailure.Cause.MISSING_SECRET, "The PIN is missing.", "Enter the PIN.");
        assertEquals("The PIN is missing. Enter the PIN.", withAction.getMessage());
    }
    public @Test void everyTaggedRequestKeepsItsAnnotationWhileRepeatedLogsAreCountedAndSuppressed() {
        AtomicLong now = new AtomicLong(); var logs = new ArrayList<String>();
        try (var diagnostics = new Diagnostics(now::get, logs::add)) {
            var failure = new AuthenticationFailure(AuthenticationFailure.Phase.QUEUE, AuthenticationFailure.Cause.CAPACITY, "The global waiting-request limit was reached.", "Let authentication finish and resend, or adjust the enabled global limit.");
            for (int i = 0; i < 20; i++) {
                var notice = diagnostics.request(i, "Employee", failure, true); assertTrue(notice.requestStopped()); assertTrue(notice.text().contains("not sent")); assertTrue(notice.text().contains("employee"));
            }
            assertEquals(1, logs.size()); now.set(5_000_000_000L); diagnostics.request(21, "employee", failure, true);
            assertEquals(2, logs.size()); assertTrue(logs.getLast().contains("19 similar messages suppressed"));
            var ordinary = diagnostics.request(22, "employee", failure, false); assertFalse(ordinary.requestStopped()); assertTrue(ordinary.text().contains("unchanged request was sent"));
        }
    }
    public @Test void unsafeAliasIsNotLoggedAndUnknownCauseRemainsUnknown() {
        var logs = new ArrayList<String>();
        try (var diagnostics = new Diagnostics(() -> 0, logs::add)) {
            var failure = CoordinatorFixtures.failure(AuthenticationFailure.Cause.UNKNOWN);
            var notice = diagnostics.request(1, "secret\r\nInjected: value", failure, true);
            assertFalse(notice.text().contains("secret")); assertFalse(notice.text().contains("password"));
            assertTrue(notice.text().contains(failure.problem())); assertTrue(notice.text().contains(failure.recovery()));
            assertEquals(AuthenticationFailure.Cause.UNKNOWN, failure.reason());
            assertFalse(notice.text().contains("phase ")); assertFalse(notice.text().contains("cause "));
        }
    }
    public @Test void brokenLoggingSinkCannotPreventAnAnnotationAndCloseStopsEmissions() {
        AtomicLong calls = new AtomicLong();
        var diagnostics = new Diagnostics(() -> 0, value -> { calls.incrementAndGet(); throw new IllegalStateException("host logger unavailable"); });
        assertNotNull(diagnostics.request(1, "employee", CoordinatorFixtures.failure(AuthenticationFailure.Cause.UNKNOWN), true)); diagnostics.close();
        assertNotNull(diagnostics.request(2, "admin", CoordinatorFixtures.failure(AuthenticationFailure.Cause.UNKNOWN), true)); assertEquals(1, calls.get());
    }
    public @Test void backgroundGuidanceIsRateLimitedWithoutClaimingARequestWasNotSent() {
        var logs = new ArrayList<String>();
        try (var diagnostics = new Diagnostics(() -> 0, logs::add)) {
            var failure = CoordinatorFixtures.failure(AuthenticationFailure.Cause.CONFIGURATION);
            diagnostics.state("employee", failure); diagnostics.state("employee", failure);
            assertEquals(1, logs.size()); assertFalse(logs.getFirst().contains("not sent")); assertTrue(logs.getFirst().contains("employee"));
        }
    }
}
