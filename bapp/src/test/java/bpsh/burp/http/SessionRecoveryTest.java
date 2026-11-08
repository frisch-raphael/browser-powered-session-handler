package bpsh.burp.http;

import bpsh.request.RequestSettings;
import bpsh.authentication.credentials.CredentialUse;
import bpsh.authentication.credentials.TokenSnapshot;
import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.JourneyDefinition;
import bpsh.authentication.session.AuthenticationCoordinator;
import bpsh.authentication.session.AuthenticationCoordinatorTest;
import bpsh.authentication.session.CoordinatorFixtures;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Establishes response provenance and encoded/decoded ceilings using real bounded codecs and RE2. */
public class SessionRecoveryTest {
    /** @param value Fixture bytes. @param type Declared MIME. @param encoding Declared content coding. @return Lazy response. */
    public static SessionRecovery.Response response(byte[] value, String type, String encoding) {
        return new SessionRecovery.Response(200, type, encoding, value.length, () -> new ByteArrayInputStream(value));
    }
    /** @param text Fixture body. @return UTF-8 bytes. */
    public static byte[] bytes(String text) { return text.getBytes(StandardCharsets.UTF_8); }
    /** @param input Original bytes. @param gzip Whether gzip or zlib-deflate is used. @return Actual compressed bytes. */
    public static byte[] compressed(byte[] input, boolean gzip) throws Exception {
        var out = new ByteArrayOutputStream(); try (var encoded = gzip ? new GZIPOutputStream(out) : new DeflaterOutputStream(out)) { encoded.write(input); } return out.toByteArray();
    }
    /** @param token Current snapshot. @param rule Captured recovery rule. @return Token-free request provenance. */
    public static CredentialUse used(TokenSnapshot token, JourneyDefinition.Recovery rule) { return new CredentialUse(token.identity(), token.version(), rule); }

    public @Test void attributedStatusInvalidatesOnlyUsedVersionAndNeverReadsTheBody() {
        try (var f = new AuthenticationCoordinatorTest.Fixture(RequestSettings.Controls.defaults()); var recovery = new SessionRecovery(f.coordinator, f.clock::nanos)) {
            f.acquire(0); f.clock.runWorker(); var old = f.coordinator.peek(f.entry(0).identity());
            recovery.record(10, List.of(used(old, new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null))), false);
            var refresh = f.coordinator.test(f.entry(0), false); f.clock.runWorker(); assertTrue(refresh.future().isDone());
            var neverRead = new SessionRecovery.Response(401, "application/octet-stream", "br", Long.MAX_VALUE, () -> { fail("status rule must not open a body"); return null; });
            assertEquals(0, recovery.received(10, neverRead, false)); assertNotNull(f.coordinator.peek(old.identity()));
            var current = f.coordinator.peek(old.identity()); recovery.record(11, List.of(used(current, new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null))), false);
            assertEquals(1, recovery.received(11, neverRead, false)); assertNull(f.coordinator.peek(old.identity())); assertEquals(0, recovery.received(11, neverRead, false));
        }
    }
    public @Test void internalUnattributedAndExpiredIdsCannotInvalidateUiSelection() {
        try (var f = new AuthenticationCoordinatorTest.Fixture(RequestSettings.Controls.defaults()); var recovery = new SessionRecovery(f.coordinator, f.clock::nanos)) {
            f.acquire(0); f.clock.runWorker(); var token = f.coordinator.peek(f.entry(0).identity()); var provenance = List.of(used(token, new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null)));
            var status = new SessionRecovery.Response(401, null, null, 0, () -> { fail("no body"); return null; });
            recovery.record(1, provenance, true); assertEquals(0, recovery.received(1, status, false)); assertEquals(0, recovery.received(999, status, false));
            recovery.record(2, provenance, false); assertEquals(0, recovery.received(2, status, true));
            recovery.record(3, provenance, false); f.clock.advance(300_000); assertEquals(0, recovery.received(3, status, false)); assertNotNull(f.coordinator.peek(token.identity()));
        }
    }
    public @Test void multiJourneyResponseAppliesEachCapturedRuleRatherThanGuessingAResponsibleCredential() {
        try (var f = new AuthenticationCoordinatorTest.Fixture(RequestSettings.Controls.defaults()); var recovery = new SessionRecovery(f.coordinator, f.clock::nanos)) {
            f.acquire(0); f.acquire(1); f.clock.runWorker(); f.clock.runWorker();
            var first = f.coordinator.peek(f.entry(0).identity()); var second = f.coordinator.peek(f.entry(1).identity());
            recovery.record(1, List.of(used(first, new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null)),
                    used(second, new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.REGEX, null, "sign.*in"))), false);
            byte[] body = bytes("please sign\n in again");
            assertEquals(2, recovery.received(1, new SessionRecovery.Response(401, "text/html", null, body.length, () -> new ByteArrayInputStream(body)), false));
            assertNull(f.coordinator.peek(first.identity())); assertNull(f.coordinator.peek(second.identity()));
        }
    }
    public static String original(int id, boolean tagged) {
        return "POST /protected?case=" + id + " HTTP/1.1\r\nHost: app.example\r\nAuthorization: Bearer "
                + (tagged ? "<@employee/>" : "stale") + "\r\nCookie: unrelated=keep\r\nX-Trace: original-" + id + "\r\nContent-Length: 9\r\n\r\nbody=data";
    }
    public static JourneyDefinition.Recovery lossRule() { return new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null); }
    public static void captured(AuthenticationCoordinatorTest.Fixture f, SessionRecovery recovery, long id, boolean tagged) throws Exception {
        var resolver = new NativeTagResolver(f.registry, f.coordinator); byte[] raw = original((int) id, tagged).getBytes(StandardCharsets.ISO_8859_1);
        try (var operation = resolver.resolveAutomatic(raw, tagged ? List.of() : List.of(new NativeTagResolver.Automatic(f.entry(0), lossRule())))) {
            var resolved = operation.future().join(); resolved.commit();
            var uses = resolved.uses().stream().map(u -> new CredentialUse(u.identity(), u.version(), lossRule())).toList();
            recovery.record(id, uses, false, resolved.replayTemplate(raw));
        }
    }
    public static SessionRecovery.Decision lost(SessionRecovery recovery, long id) {
        return recovery.receivedPlan(id, 401, () -> { fail("status detection must not inspect body metadata"); return null; }, false, true);
    }

    public @org.junit.jupiter.params.ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(booleans = {false, true})
    void eightOriginalsShareRecoveryAndReceiveOneByteFaithfulReplayEach(boolean tagged) throws Exception {
        try (var f = new AuthenticationCoordinatorTest.Fixture(RequestSettings.Controls.defaults()); var recovery = new SessionRecovery(f.coordinator, f.clock::nanos)) {
            f.acquire(0); f.clock.runWorker(); var decisions = new java.util.ArrayList<SessionRecovery.Decision>();
            for (int i = 1; i <= 8; i++) captured(f, recovery, i, tagged);
            for (int i = 1; i <= 8; i++) { decisions.add(lost(recovery, i)); assertNull(lost(recovery, i).replay()); }
            assertEquals(1, f.clock.workers.size()); f.clock.runWorker(); assertEquals(2, f.attempts.get());
            for (int i = 0; i < 8; i++) try (var plan = decisions.get(i).replay().join()) {
                assertEquals(i + 1, plan.originalId()); byte[] replay = plan.claim();
                String actual = new String(replay, StandardCharsets.ISO_8859_1);
                assertEquals(original(i + 1, false).replace("Bearer stale", "Bearer fixture-2"), actual);
                assertThrows(AuthenticationFailure.class, plan::claim);
                recovery.record(1000 + i, plan.uses(), false);
                assertNull(recovery.receivedPlan(1000 + i, 200, () -> null, false, true).replay());
            }
            assertTrue(f.coordinator.status(f.entry(0).identity()).acceptedUse()); assertEquals(0, f.coordinator.capacity().waitingRequests());
            assertEquals(1, f.coordinator.events().snapshot(f.entry(0).identity().key()).stream()
                    .filter(e -> e.message().equals("Request using this journey's credentials returned HTTP 200.")).count(), "the observed HTTP status is visible once per publication, independently of credential capture");
        }
    }

    public @Test void replacementRejectionStopsTheEpisodeAndCannotProduceASecondReplay() throws Exception {
        try (var f = new AuthenticationCoordinatorTest.Fixture(RequestSettings.Controls.defaults()); var recovery = new SessionRecovery(f.coordinator, f.clock::nanos)) {
            f.acquire(0); f.clock.runWorker(); captured(f, recovery, 10, false); var decision = lost(recovery, 10); f.clock.runWorker();
            try (var plan = decision.replay().join()) {
                plan.claim(); recovery.record(11, plan.uses(), false); assertNull(lost(recovery, 11).replay());
                assertEquals(AuthenticationCoordinator.Phase.PAUSED, f.coordinator.status(f.entry(0).identity()).phase());
                assertNull(lost(recovery, 11).replay()); f.clock.advance(3_600_000); assertTrue(f.clock.workers.isEmpty());
                assertEquals(AuthenticationFailure.Cause.AUTH_REJECTED, CoordinatorFixtures.error(f.acquire(0)).reason());
            }
        }
    }

    public @org.junit.jupiter.params.ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(booleans = {false, true})
    void replayOfLateOriginalPausesRejectedReplacementButNeverRetiresNewerPublication(boolean refreshAgain) throws Exception {
        try (var f = new AuthenticationCoordinatorTest.Fixture(RequestSettings.Controls.defaults()); var recovery = new SessionRecovery(f.coordinator, f.clock::nanos)) {
            f.acquire(0); f.clock.runWorker(); captured(f, recovery, 1, false);
            var refreshed = f.coordinator.test(f.entry(0), false); f.clock.runWorker(); refreshed.future().join();
            var token = f.coordinator.peek(f.entry(0).identity()); var decision = lost(recovery, 1);
            try (var plan = decision.replay().join()) {
                assertTrue(new String(plan.claim(), StandardCharsets.ISO_8859_1).contains("Bearer " + token.value()));
                assertEquals(2, f.attempts.get(), "late rejection must not invalidate or reacquire the newer publication");
                recovery.record(2, plan.uses(), false);
                if (refreshAgain) {
                    var newer = f.coordinator.test(f.entry(0), false); f.clock.runWorker(); newer.future().join();
                    var current = f.coordinator.peek(token.identity()); assertNotEquals(token.version(), current.version());
                    assertNull(lost(recovery, 2).replay()); assertSame(current, f.coordinator.peek(token.identity()));
                    assertEquals(AuthenticationCoordinator.Phase.READY, f.coordinator.status(token.identity()).phase());
                } else {
                    assertNull(lost(recovery, 2).replay());
                    assertEquals(AuthenticationCoordinator.Phase.PAUSED, f.coordinator.status(token.identity()).phase());
                    assertEquals(AuthenticationFailure.Cause.AUTH_REJECTED, CoordinatorFixtures.error(f.acquire(0)).reason());
                    f.clock.advance(3_600_000); assertTrue(f.clock.workers.isEmpty());
                }
            }
        }
    }

    public @Test void exhaustedRecoveryRetainsTheUnderlyingCauseForEveryOriginalAndDoesNotReplay() throws Exception {
        try (var f = new AuthenticationCoordinatorTest.Fixture(RequestSettings.Controls.defaults()); var recovery = new SessionRecovery(f.coordinator, f.clock::nanos)) {
            f.acquire(0); f.clock.runWorker(); captured(f, recovery, 1, true); captured(f, recovery, 2, false);
            f.fail.set(new AuthenticationFailure(AuthenticationFailure.Phase.NAVIGATION, AuthenticationFailure.Cause.TRANSPORT, "The login connection was refused.").atInput(AuthenticationFailure.Input.LOGIN_URL));
            var a = lost(recovery, 1); var b = lost(recovery, 2);
            f.clock.runWorker(); f.clock.advance(5000); f.clock.runWorker(); f.clock.advance(15_000); f.clock.runWorker();
            for (var result : List.of(a, b)) {
                var failure = assertThrows(java.util.concurrent.CompletionException.class, () -> result.replay().join());
                var actual = (AuthenticationFailure) failure.getCause(); assertEquals(AuthenticationFailure.Cause.TRANSPORT, actual.reason());
                assertEquals(AuthenticationFailure.Phase.NAVIGATION, actual.phase()); assertTrue(actual.getMessage().contains("3 attempts"));
                assertTrue(actual.getMessage().contains("connection was refused"));
                assertEquals(AuthenticationFailure.Input.LOGIN_URL, actual.input().input(), "Persistent pause must retain the correct input");
            }
            assertEquals(4, f.attempts.get()); f.clock.advance(3_600_000); assertTrue(f.clock.workers.isEmpty());
            assertEquals(AuthenticationCoordinator.Phase.PAUSED, f.coordinator.status(f.entry(0).identity()).phase());
            f.fail.set(null); var explicit = f.coordinator.test(f.entry(0), false); f.clock.runWorker(); assertTrue(explicit.future().isDone());
            assertTrue(a.replay().isCompletedExceptionally()); assertTrue(b.replay().isCompletedExceptionally());
            assertEquals(5, f.attempts.get(), "explicit Test starts a new cycle but never replays the previous originals");
        }
    }

    public @Test void timeoutAloneDisabledMaintenanceAndUnattributedResponsesNeverAuthorizeReplay() throws Exception {
        try (var f = new AuthenticationCoordinatorTest.Fixture(RequestSettings.Controls.defaults()); var recovery = new SessionRecovery(f.coordinator, f.clock::nanos)) {
            f.acquire(0); f.clock.runWorker(); captured(f, recovery, 1, false);
            assertNull(recovery.receivedPlan(1, 504, () -> null, false, true).replay());
            captured(f, recovery, 2, true); assertNull(recovery.receivedPlan(2, 401, () -> null, false, false).replay());
            assertNull(lost(recovery, 999).replay()); assertEquals(1, f.attempts.get()); assertTrue(f.clock.workers.isEmpty());
        }
    }

    public @Test void configurationChangeBeforeReplayCommitNeverSwitchesTheCapturedJourneyIdentity() throws Exception {
        try (var f = new AuthenticationCoordinatorTest.Fixture(RequestSettings.Controls.defaults()); var recovery = new SessionRecovery(f.coordinator, f.clock::nanos)) {
            f.acquire(0); f.clock.runWorker(); captured(f, recovery, 1, true); var decision = lost(recovery, 1); f.clock.runWorker();
            try (var plan = decision.replay().join()) {
                var replacementOwner = CoordinatorFixtures.journey("employee"); CoordinatorFixtures.load(f.registry, List.of(replacementOwner, f.definitions.get(1))); f.coordinator.configurationChanged();
                var failure = assertThrows(AuthenticationFailure.class, plan::claim); assertEquals(AuthenticationFailure.Cause.STALE, failure.reason());
                assertTrue(f.clock.workers.isEmpty());
            }
        }
    }

    public @Test void cancelledOriginalDetachesItsWaitWhileOtherOriginalsStillReceiveTheSharedReplacement() throws Exception {
        try (var f = new AuthenticationCoordinatorTest.Fixture(RequestSettings.Controls.defaults()); var recovery = new SessionRecovery(f.coordinator, f.clock::nanos)) {
            f.acquire(0); f.clock.runWorker(); captured(f, recovery, 1, false); captured(f, recovery, 2, false);
            var first = lost(recovery, 1); var second = lost(recovery, 2); first.replay().cancel(false);
            assertEquals(1, f.coordinator.capacity().waitingRequests()); f.clock.runWorker();
            assertTrue(first.replay().isCancelled()); try (var plan = second.replay().join()) { assertNotNull(plan.claim()); }
            assertEquals(2, f.attempts.get()); assertEquals(0, f.coordinator.capacity().waitingRequests());
        }
    }

    public @Test void shutdownRevokesBothWaitingAndReadyReplaysWithoutCancellingAnotherOwner() throws Exception {
        try (var f = new AuthenticationCoordinatorTest.Fixture(RequestSettings.Controls.defaults()); var recovery = new SessionRecovery(f.coordinator, f.clock::nanos)) {
            f.acquire(0); f.clock.runWorker(); captured(f, recovery, 1, false); var ready = lost(recovery, 1); f.clock.runWorker();
            var plan = ready.replay().join(); recovery.close(); assertThrows(AuthenticationFailure.class, plan::claim);
        }
        try (var f = new AuthenticationCoordinatorTest.Fixture(RequestSettings.Controls.defaults()); var recovery = new SessionRecovery(f.coordinator, f.clock::nanos)) {
            f.acquire(0); f.clock.runWorker(); captured(f, recovery, 2, false); var waiting = lost(recovery, 2);
            var independent = f.coordinator.test(f.entry(1), false); recovery.close();
            assertTrue(waiting.replay().isCompletedExceptionally()); assertEquals(0, f.coordinator.capacity().waitingRequests());
            f.clock.runWorker(); f.clock.runWorker(); assertTrue(independent.future().isDone()); assertFalse(independent.future().isCompletedExceptionally());
        }
    }

    public @Test void missingReplayTemplateStillSharesRecoveryAndTerminalFailureRemainsPaused() throws Exception {
        try (var f = new AuthenticationCoordinatorTest.Fixture(RequestSettings.Controls.defaults()); var recovery = new SessionRecovery(f.coordinator, f.clock::nanos)) {
            f.acquire(0); f.clock.runWorker(); var token = f.coordinator.peek(f.entry(0).identity());
            recovery.record(1, List.of(new CredentialUse(token.identity(), token.version(), lossRule())), false);
            f.fail.set(new AuthenticationFailure(AuthenticationFailure.Phase.PIN, AuthenticationFailure.Cause.PIN_REJECTED, "The security device rejected the PIN."));
            assertNull(lost(recovery, 1).replay()); assertEquals(1, f.clock.workers.size()); f.clock.runWorker();
            assertEquals(2, f.attempts.get()); assertEquals(AuthenticationCoordinator.Phase.PAUSED, f.coordinator.status(token.identity()).phase());
            assertEquals(AuthenticationFailure.Cause.PIN_REJECTED, CoordinatorFixtures.error(f.acquire(0)).reason());
            f.clock.advance(3_600_000); assertTrue(f.clock.workers.isEmpty());
        }
    }

    public @Test void rawAndDecodedCeilingsAreInclusiveAndNonTextNeverOpensABody() throws Exception {
        byte[] exact = bytes("x".repeat(65_536)), above = bytes("x".repeat(65_537));
        assertNotNull(SessionRecovery.boundedText(response(exact, "text/plain", null)));
        assertNull(SessionRecovery.boundedText(response(above, "text/plain", null)));
        for (boolean gzip : List.of(true, false)) {
            assertNotNull(SessionRecovery.boundedText(response(compressed(exact, gzip), "application/json; charset=UTF-8", gzip ? "gzip" : "deflate")));
            assertNull(SessionRecovery.boundedText(response(compressed(above, gzip), "text/plain", gzip ? "gzip" : "deflate")));
        }
        for (String type : List.of("image/png", "application/octet-stream", "multipart/form-data", "text/plain; charset=UTF-16")) {
            var response = new SessionRecovery.Response(200, type, null, 0, () -> { fail("unsupported MIME/charset must not materialize a body"); return null; }); assertNull(SessionRecovery.boundedText(response));
        }
    }
    public @Test void unsupportedEncodingInvalidUtf8AndDishonestActualLengthAreSkipped() {
        AtomicInteger reads = new AtomicInteger();
        var unsupported = new SessionRecovery.Response(200, "text/plain", "br", 10, () -> { reads.incrementAndGet(); return new ByteArrayInputStream(new byte[10]); });
        assertNull(SessionRecovery.boundedText(unsupported)); assertEquals(0, reads.get());
        assertNull(SessionRecovery.boundedText(response(new byte[]{(byte) 0xc3, 0x28}, "text/plain", null)));
        assertNull(SessionRecovery.boundedText(new SessionRecovery.Response(200, "text/plain", null, 1, () -> new ByteArrayInputStream(new byte[65_537]))));
        assertNull(SessionRecovery.boundedText(response(bytes("not gzip"), "text/plain", "gzip")));
    }
    public @Test void regexUsesFindDotallAndRejectsUnsupportedOversizedOrExcessiveProgramsSafely() throws Exception {
        assertTrue(SessionRecovery.compile("sign.*in").matcher("prefix sign\n in suffix").find());
        for (String source : List.of("(?=secret).*", "(a)\\1", "x".repeat(4097), "(a{1000}){1000}")) {
            var ex = assertThrows(AuthenticationFailure.class, () -> SessionRecovery.compile(source)); assertFalse(ex.getMessage().contains("secret")); assertEquals(AuthenticationFailure.Cause.CONFIGURATION, ex.reason());
        }

    }
    public @Test void boundedLedgerEvictsOldestAndConsumesEveryResponseAtMostOnce() {
        try (var f = new AuthenticationCoordinatorTest.Fixture(RequestSettings.Controls.defaults()); var recovery = new SessionRecovery(f.coordinator, f.clock::nanos)) {
            f.acquire(0); f.clock.runWorker(); var token = f.coordinator.peek(f.entry(0).identity());
            for (int i = 0; i <= 10_000; i++) recovery.record(i, List.of(used(token, new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null))), false);
            var response = new SessionRecovery.Response(401, null, null, 0, null);
            assertEquals(0, recovery.received(0, response, false)); assertNotNull(f.coordinator.peek(token.identity()));
            assertEquals(1, recovery.received(10_000, response, false)); assertEquals(0, recovery.received(10_000, response, false));
        }
    }
    public @Test void unsupportedTextEncodingHasFixedActionableGuidanceWithoutReadingOrLoggingHeaders() {
        try (var f = new AuthenticationCoordinatorTest.Fixture(RequestSettings.Controls.defaults())) {
            var messages = new java.util.ArrayList<String>();
            try (var recovery = new SessionRecovery(f.coordinator, f.clock::nanos, (identity, message) -> messages.add(message))) {
                f.acquire(0); f.clock.runWorker(); var token = f.coordinator.peek(f.entry(0).identity());
                recovery.record(1, List.of(used(token, new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.REGEX, null, "sign in"))), false);
                var response = new SessionRecovery.Response(200, "text/plain", "unsupported-secret-value", 1, () -> { fail("unsupported encoding must not open a body"); return null; });
                assertEquals(0, recovery.received(1, response, false)); assertEquals(1, messages.size());
                assertEquals("Session detection could not read the response's text encoding or compression.", messages.getFirst()); assertFalse(messages.getFirst().contains("unsupported-secret-value")); assertNotNull(f.coordinator.peek(token.identity()));
            }
        }
    }
}
