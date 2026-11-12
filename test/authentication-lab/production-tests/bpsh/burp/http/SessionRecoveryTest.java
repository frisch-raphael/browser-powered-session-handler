package bpsh.burp.http;

import bpsh.request.RequestSettings;
import bpsh.authentication.credentials.CredentialUse;
import bpsh.authentication.credentials.TokenExtractor;
import bpsh.authentication.credentials.TokenLifetimeTest;
import bpsh.authentication.credentials.TokenSnapshot;
import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.JourneyDefinition;
import bpsh.authentication.session.AuthenticationCoordinator;
import bpsh.authentication.session.AuthenticationCoordinatorTest;
import bpsh.authentication.session.CoordinatorFixtures;
import bpsh.support.AuthLabSupport;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
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

    public @Test void attributedStatusInvalidatesOnlyUsedVersionAndNeverReadsTheBody() throws Exception {
        long began=System.nanoTime();Map<String,Object> observed;var bodyReads=new AtomicInteger();
        try (var f = new AuthenticationCoordinatorTest.Fixture(RequestSettings.Controls.defaults()); var recovery = new SessionRecovery(f.coordinator, f.clock::nanos)) {
            f.acquire(0); f.clock.runWorker(); var old = f.coordinator.peek(f.entry(0).identity());
            recovery.record(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 10), List.of(used(old, new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null))), false);
            var refresh = f.coordinator.test(f.entry(0), false); f.clock.runWorker(); assertTrue(refresh.future().isDone());
            var published=f.coordinator.peek(old.identity());assertNotNull(published);assertNotEquals(old.version(),published.version());
            var neverRead = new SessionRecovery.Response(401, "application/octet-stream", "br", Long.MAX_VALUE, () -> { bodyReads.incrementAndGet();fail("status rule must not open a body"); return null; });
            int late=recovery.received(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 10),neverRead,false);assertEquals(0,late);assertNotNull(f.coordinator.peek(old.identity()));
            boolean preserved=f.coordinator.peek(old.identity())==published;assertTrue(preserved);
            var current = f.coordinator.peek(old.identity()); recovery.record(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 11), List.of(used(current, new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null))), false);
            int currentInvalidated=recovery.received(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 11),neverRead,false);assertEquals(1,currentInvalidated);assertNull(f.coordinator.peek(old.identity()));int repeated=recovery.received(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 11),neverRead,false);assertEquals(0,repeated);
            observed=Map.of("oldVersion",old.version(),"newVersion",published.version(),"lateInvalidated",late,"latePreservedCurrent",preserved,"currentInvalidated",currentInvalidated,"repeatedInvalidated",repeated,"bodyReads",bodyReads.get());
        }
        TokenLifetimeTest.lifetime("late-old-401",observed,began);
    }
    public @Test void internalUnattributedAndExpiredIdsCannotInvalidateUiSelection() {
        try (var f = new AuthenticationCoordinatorTest.Fixture(RequestSettings.Controls.defaults()); var recovery = new SessionRecovery(f.coordinator, f.clock::nanos)) {
            f.acquire(0); f.clock.runWorker(); var token = f.coordinator.peek(f.entry(0).identity()); var provenance = List.of(used(token, new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null)));
            var status = new SessionRecovery.Response(401, null, null, 0, () -> { fail("no body"); return null; });
            recovery.record(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 1), provenance, true); assertEquals(0, recovery.received(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 1), status, false)); assertEquals(0, recovery.received(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 999), status, false));
            recovery.record(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 2), provenance, false); assertEquals(0, recovery.received(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 2), status, true));
            recovery.record(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 3), provenance, false); f.clock.advance(300_000); assertEquals(0, recovery.received(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 3), status, false)); assertNotNull(f.coordinator.peek(token.identity()));
        }
    }
    public @Test void multiJourneyResponseAppliesEachCapturedRuleRatherThanGuessingAResponsibleCredential() {
        try (var f = new AuthenticationCoordinatorTest.Fixture(RequestSettings.Controls.defaults()); var recovery = new SessionRecovery(f.coordinator, f.clock::nanos)) {
            f.acquire(0); f.acquire(1); f.clock.runWorker(); f.clock.runWorker();
            var first = f.coordinator.peek(f.entry(0).identity()); var second = f.coordinator.peek(f.entry(1).identity());
            recovery.record(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 1), List.of(used(first, new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null)),
                    used(second, new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.REGEX, null, "sign.*in"))), false);
            byte[] body = bytes("please sign\n in again");
            assertEquals(2, recovery.received(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 1), new SessionRecovery.Response(401, "text/html", null, body.length, () -> new ByteArrayInputStream(body)), false));
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
            recovery.record(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, id), uses, false, resolved.replayTemplate(raw));
        }
    }
    public static SessionRecovery.Decision lost(SessionRecovery recovery, long id) {
        return recovery.receivedPlan(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, id), 401, () -> { fail("status detection must not inspect body metadata"); return null; }, false, true);
    }

    public static AuthLabSupport matrixTargets;
    public static AuthLabSupport matrixTargets() throws Exception {
        if (matrixTargets == null) matrixTargets = new AuthLabSupport(List.of("recovery"));
        return matrixTargets;
    }
    public @org.junit.jupiter.api.AfterAll static void closeMatrixTargets() throws Exception { if (matrixTargets != null) matrixTargets.close(); }

    public @org.junit.jupiter.api.TestFactory
    java.util.stream.Stream<org.junit.jupiter.api.DynamicTest> eightOriginalsShareRecoveryAndReceiveOneByteFaithfulReplayEach() {
        var cases = new java.util.ArrayList<org.junit.jupiter.api.DynamicTest>();
        for (String trigger : List.of("status-match", "body-match", "no-match", "disabled", "success", "replacement-rejected", "acquisition-failed", "original-timeout", "post-action", "replay-once"))
            for (boolean tagged : List.of(false, true)) for (boolean combined : List.of(false, true)) for (int originals : List.of(1, 8)) {
                String id = "CORE.recovery.trigger=" + trigger + "~requestMode=" + (tagged ? "tagged" : "auto") + "~outputs=" + (combined ? "combined" : "single") + "~originals=" + originals;
                cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("[case=" + id + "]", () -> recoveryMatrix(id, trigger, tagged, combined, originals)));
            }
        return cases.stream();
    }
    /** One complete journey supplies all selected outputs; only the acquisition boundary is controlled HTTP. */
    public static JourneyDefinition matrixJourney(AuthLabSupport.Case target, boolean combined) {
        var base = CoordinatorFixtures.journey("employee");
        var json = new JourneyDefinition.JsonExtraction(TokenExtractor.origin(target.url("")), target.url("login/json").getRawPath(), "access_token");
        JourneyDefinition.Extraction extraction = combined ? new JourneyDefinition.CombinedExtraction(List.of(
                new JourneyDefinition.NamedExtraction("access", json), new JourneyDefinition.NamedExtraction("session",
                new JourneyDefinition.CookieExtraction(target.url("protected/"), "LAB_C1", target.url("").getHost(), target.cookiePath())))) : json;
        return new JourneyDefinition(base.id(), base.displayName(), base.alias(), target.url("start"), false, List.of(), base.browser(), extraction,
                JourneyDefinition.Injection.perToken(List.of(new JourneyDefinition.TokenInjection(combined ? "access" : null, JourneyDefinition.InjectionType.BEARER, null))), base.cache(), null);
    }
    /** Independently constructs the expected complete wire request, including body and unrelated bytes. */
    public static String matrixWire(AuthLabSupport.Case target, boolean combined, boolean tagged, boolean post, int original, TokenSnapshot token) {
        var endpoint = target.url("protected/" + (combined ? "b_c1" : "b"));
        String bearer = token != null ? token.value() : tagged ? combined ? "<@employee token=\"access\"/>" : "<@employee/>" : "stale";
        String cookie = !combined ? "" : ";LAB_C1=" + (token != null ? token.cookies().get("LAB_C1") : tagged ? "<@employee token=\"session\"/>" : "stale");
        return (post ? "POST " : "GET ") + endpoint.getRawPath() + "?" + endpoint.getRawQuery() + " HTTP/1.1\r\nHost: " + endpoint.getAuthority()
                + "\r\nAuthorization: Bearer " + bearer + "\r\nCookie: unrelated=keep" + cookie + "\r\nX-Trace:\t original-" + original
                + (post ? "\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 9\r\n\r\nbody=data" : "\r\n\r\n");
    }
    /** Exercises actual extraction, byte transformation, response matching and recovery; accepting-service assertions use the canonical app. */
    public static void recoveryMatrix(String id, String trigger, boolean tagged, boolean combined, int originals) throws Exception {
        long started = System.nanoTime(), ready, checked; var captured = new java.util.LinkedHashMap<String, Object>();
        Map<String,Object> lifetimeProof=null,injectionProof=null;
        var clock = new java.util.concurrent.atomic.AtomicReference<CoordinatorFixtures.ManualRuntime>();
        try (var target = matrixTargets().prepare(id)) {
            var definition = matrixJourney(target, combined);
            try (var f = new AuthenticationCoordinatorTest.Fixture(RequestSettings.Controls.defaults(), List.of(definition, CoordinatorFixtures.journey("admin")),
                    (entry, recover, deadline, cancelled) -> target.acquire(entry, clock.get()));
                 var recovery = new SessionRecovery(f.coordinator, f.clock::nanos)) {
                clock.set(f.clock); f.clock.wall = java.time.Instant.now(); f.acquire(0); f.clock.runWorker(); var entry = f.entry(0); var initial = f.coordinator.peek(entry.identity());
                assertNotNull(initial, () -> "Initial controlled acquisition failed: " + f.coordinator.status(entry.identity()).failure());
                var initialCredentials = new java.util.LinkedHashMap<String, String>(); initialCredentials.put("B", initial.value());
                if (combined) initialCredentials.put("C1", initial.cookies().get("LAB_C1"));
                var initialProof = target.prove(combined ? "b_c1" : "b", initialCredentials, "user2");
                boolean noRecovery = List.of("no-match", "disabled", "success", "original-timeout").contains(trigger);
                boolean rejected = List.of("replacement-rejected", "replay-once").contains(trigger);
                boolean post = trigger.equals("post-action");
                if (!trigger.equals("success")) target.revoke(initialProof.path("issuanceId").asText());
                var rule = new JourneyDefinition.Recovery(true, trigger.equals("body-match") ? JourneyDefinition.RecoveryMode.REGEX : JourneyDefinition.RecoveryMode.STATUS_CODE,
                        trigger.equals("body-match") ? null : 401, trigger.equals("body-match") ? "not_authenticated" : null);
                var resolver = new NativeTagResolver(f.registry, f.coordinator); var responses = new java.util.ArrayList<AuthLabSupport.Case.WireResponse>();
                ready = System.nanoTime();boolean initialBytesMatch=true;
                for (int original = 0; original < originals; original++) {
                    String raw = matrixWire(target, combined, tagged, post, original, null);
                    try (var operation = resolver.resolveAutomatic(bytes(raw), tagged ? List.of() : List.of(new NativeTagResolver.Automatic(entry, rule)))) {
                        var resolved = operation.future().join(); byte[] wire = resolved.commit();boolean matches=java.util.Arrays.equals(bytes(matrixWire(target, combined, false, post, original, initial)), wire);assertTrue(matches, "Initial request bytes must match the independent template.");initialBytesMatch&=matches;
                        recovery.record(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 100 + original), resolved.uses().stream().map(u -> new CredentialUse(u.identity(), u.version(), rule)).toList(), false, resolved.replayTemplate(bytes(raw)));
                        if (trigger.equals("no-match")) target.fault("PROTECTED", original + 2, "HTTP_ERROR", 403, null); // Initial proof consumed occurrence 1.
                        if (trigger.equals("original-timeout")) { target.originalTimesOut(wire, original + 2); continue; }
                        var response = target.exchange(wire); assertEquals(trigger.equals("success") ? 200 : trigger.equals("no-match") ? 403 : 401, response.status());
                        responses.add(response);
                    }
                }
                assertEquals(0, target.snapshot().path("counters").path("actions").asInt());
                if (trigger.equals("acquisition-failed")) f.fail.set(CoordinatorFixtures.failure(AuthenticationFailure.Cause.TRANSPORT));
                var decisions = new java.util.ArrayList<SessionRecovery.Decision>();
                for (int original = 0; original < responses.size(); original++) {
                    var response = responses.get(original);
                    java.util.function.Supplier<SessionRecovery.Response> details = () -> {
                        assertEquals("body-match", trigger, "Status-only detection must not materialize a body.");
                        return new SessionRecovery.Response(response.status(), "application/json", null, response.bodyBytes().length, () -> new ByteArrayInputStream(response.bodyBytes()));
                    };
                    var decision = recovery.receivedPlan(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 100 + original), response.status(), details, false, !trigger.equals("disabled"));
                    assertNull(recovery.receivedPlan(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 100 + original), response.status(), details, false, true).replay(), "The original response is consumed once."); decisions.add(decision);
                }
                int replayed = 0, proofs = 0; boolean bytesMatch = true;String replayAccount=null,replayIssuance=null;int replayStatus=0;
                if (noRecovery) {
                    decisions.forEach(decision -> assertNull(decision.replay())); assertTrue(f.clock.workers.isEmpty()); assertEquals(1, f.attempts.get());
                    assertEquals(initial.version(), f.coordinator.peek(entry.identity()).version());
                } else {
                    assertEquals(1, f.clock.workers.size(), "All originals share one recovery acquisition."); f.clock.runWorker();
                    if (trigger.equals("acquisition-failed")) {
                        f.clock.advance(5000); f.clock.runWorker(); f.clock.advance(15_000); f.clock.runWorker();
                        for (var decision : decisions) {
                            var error = assertThrows(java.util.concurrent.CompletionException.class, () -> decision.replay().join());
                            assertEquals(AuthenticationFailure.Cause.TRANSPORT, ((AuthenticationFailure) error.getCause()).reason());
                        }
                    } else {
                        var replacement = f.coordinator.peek(entry.identity()); assertNotNull(replacement); assertNotEquals(initial.version(), replacement.version());
                        String replacementIssuance = target.currentLoginIssuance(); assertNotEquals(initialProof.path("issuanceId").asText(), replacementIssuance);
                        if (trigger.equals("replacement-rejected")) {
                            var probe = target.exchange(bytes(matrixWire(target, combined, false, false, 999, replacement)));
                            assertEquals(200, probe.status()); assertEquals("user2", probe.body().path("accountId").asText()); assertEquals(replacementIssuance, probe.body().path("issuanceId").asText());
                            target.revoke(probe.body().path("issuanceId").asText());
                        }
                        for (int original = 0; original < originals; original++) try (var plan = decisions.get(original).replay().join()) {
                            assertEquals(new RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 100 + original), plan.originalId());
                            if (rejected && original > 0) { assertThrows(AuthenticationFailure.class, plan::claim); continue; }
                            byte[] actual = plan.claim(), expected = bytes(matrixWire(target, combined, false, post, original, replacement));
                            assertTrue(java.util.Arrays.equals(expected, actual), "Replay bytes must preserve the independent complete template."); bytesMatch &= java.util.Arrays.equals(expected, actual); assertThrows(AuthenticationFailure.class, plan::claim);
                            if (trigger.equals("replay-once")) {
                                // The first protected proof plus all originals precede this replay.
                                target.fault("PROTECTED", originals + 2, "HTTP_ERROR", 401, null);
                            }
                            var response = target.exchange(actual); replayed++;
                            assertEquals(rejected ? 401 : 200, response.status());
                            if (!rejected) {
                                assertEquals("user2", response.body().path("accountId").asText()); assertEquals(replacementIssuance, response.body().path("issuanceId").asText()); proofs++;
                                replayAccount=response.body().path("accountId").asText();replayIssuance=response.body().path("issuanceId").asText();replayStatus=response.status();
                                if (post) assertEquals(original + 1, response.body().path("actionId").asInt());
                            }
                            recovery.record(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 1000 + original), plan.uses(), false);
                            assertNull(recovery.receivedPlan(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 1000 + original), response.status(), () -> new SessionRecovery.Response(response.status(), "application/json", null,
                                    response.bodyBytes().length, () -> new ByteArrayInputStream(response.bodyBytes())), false, true).replay(), "A replay can never authorize another replay.");
                        }
                    }
                }
                int recoveryAttempts = f.attempts.get() - 1, actions = target.snapshot().path("counters").path("actions").asInt();
                assertEquals(noRecovery ? 0 : trigger.equals("acquisition-failed") ? 3 : 1, recoveryAttempts);
                assertEquals(post ? originals : 0, actions); assertEquals(noRecovery || trigger.equals("acquisition-failed") ? 0 : rejected ? 1 : originals, replayed);
                var status = f.coordinator.status(entry.identity());
                if (rejected || trigger.equals("acquisition-failed")) {
                    assertEquals(AuthenticationCoordinator.Phase.PAUSED, status.phase()); f.clock.advance(3_600_000); assertTrue(f.clock.workers.isEmpty());
                    CoordinatorFixtures.error(f.acquire(0)); assertTrue(f.clock.workers.isEmpty());
                } else if (!noRecovery) assertTrue(status.acceptedUse());
                assertEquals(0, f.coordinator.capacity().waitingRequests());
                if (trigger.equals("success") || !noRecovery && !rejected && !trigger.equals("acquisition-failed"))
                    assertEquals(1, f.coordinator.events().snapshot(entry.identity().key()).stream().filter(event -> event.message().equals("Request using this journey's credentials returned HTTP 200.")).count());
                captured.put("trigger", trigger); captured.put("tagged", tagged); captured.put("combined", combined); captured.put("originals", originals);
                captured.put("recoveryAttempts", recoveryAttempts); captured.put("replays", replayed); captured.put("protectedProofs", proofs); captured.put("actions", actions);
                captured.put("bytesMatch", bytesMatch); captured.put("waitingRequests", f.coordinator.capacity().waitingRequests()); captured.put("state", status.phase().name());
                if(id.equals("CORE.recovery.trigger=status-match~requestMode=auto~outputs=single~originals=1"))lifetimeProof=Map.of("initialAccount",initialProof.path("accountId").asText(),"initialIssuance",initialProof.path("issuanceId").asText(),"originalStatus",responses.getFirst().status(),"replacementAccount",replayAccount,"replacementIssuance",replayIssuance,"replacementStatus",replayStatus,"recoveryAttempts",recoveryAttempts,"replays",replayed,"waitingRequests",f.coordinator.capacity().waitingRequests());
                if(trigger.equals("success")&&!tagged&&originals==1) {
                    var response=responses.getFirst();assertEquals("user2",response.body().path("accountId").asText());assertEquals(initialProof.path("issuanceId").asText(),response.body().path("issuanceId").asText());
                    injectionProof=Map.of("mode","AUTOMATIC","combined",combined,"bytesMatch",initialBytesMatch,"status",response.status(),"account",response.body().path("accountId").asText(),"issuance",response.body().path("issuanceId").asText(),"expectedIssuance",initialProof.path("issuanceId").asText(),"roles",response.body().path("acceptedRoles"),"attempts",f.attempts.get(),"waitingRequests",f.coordinator.capacity().waitingRequests());
                }
                checked = System.nanoTime();
            }
        }
        AuthLabSupport.component(id, captured, Map.of("startupMs", TimeUnit.NANOSECONDS.toMillis(ready - started), "caseMs", TimeUnit.NANOSECONDS.toMillis(checked - ready), "cleanupMs", TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - checked)));
        if(lifetimeProof!=null)TokenLifetimeTest.lifetime("server-revoked",lifetimeProof,started);
        if(injectionProof!=null)AuthLabSupport.component("CORE.injection."+(combined?"combined":"bearer"),injectionProof,Map.of("startupMs",TimeUnit.NANOSECONDS.toMillis(ready-started),"caseMs",TimeUnit.NANOSECONDS.toMillis(checked-ready),"cleanupMs",TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-checked)));
    }

    public @Test void replacementRejectionStopsTheEpisodeAndCannotProduceASecondReplay() throws Exception {
        try (var f = new AuthenticationCoordinatorTest.Fixture(RequestSettings.Controls.defaults()); var recovery = new SessionRecovery(f.coordinator, f.clock::nanos)) {
            f.acquire(0); f.clock.runWorker(); captured(f, recovery, 10, false); var decision = lost(recovery, 10); f.clock.runWorker();
            try (var plan = decision.replay().join()) {
                plan.claim(); recovery.record(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 11), plan.uses(), false); assertNull(lost(recovery, 11).replay());
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
                recovery.record(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 2), plan.uses(), false);
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
            assertNull(recovery.receivedPlan(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 1), 504, () -> null, false, true).replay());
            captured(f, recovery, 2, true); assertNull(recovery.receivedPlan(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 2), 401, () -> null, false, false).replay());
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
            recovery.record(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 1), List.of(new CredentialUse(token.identity(), token.version(), lossRule())), false);
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
            for (int i = 0; i <= 10_000; i++) recovery.record(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, i), List.of(used(token, new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null))), false);
            var response = new SessionRecovery.Response(401, null, null, 0, null);
            assertEquals(0, recovery.received(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 0), response, false)); assertNotNull(f.coordinator.peek(token.identity()));
            assertEquals(1, recovery.received(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 10_000), response, false)); assertEquals(0, recovery.received(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 10_000), response, false));
        }
    }
    public @Test void unsupportedTextEncodingHasFixedActionableGuidanceWithoutReadingOrLoggingHeaders() {
        try (var f = new AuthenticationCoordinatorTest.Fixture(RequestSettings.Controls.defaults())) {
            var messages = new java.util.ArrayList<String>();
            try (var recovery = new SessionRecovery(f.coordinator, f.clock::nanos, (identity, message) -> messages.add(message))) {
                f.acquire(0); f.clock.runWorker(); var token = f.coordinator.peek(f.entry(0).identity());
                recovery.record(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 1), List.of(used(token, new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.REGEX, null, "sign in"))), false);
                var response = new SessionRecovery.Response(200, "text/plain", "unsupported-secret-value", 1, () -> { fail("unsupported encoding must not open a body"); return null; });
                assertEquals(0, recovery.received(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 1), response, false)); assertEquals(1, messages.size());
                assertEquals("Session detection could not read the response's text encoding or compression.", messages.getFirst()); assertFalse(messages.getFirst().contains("unsupported-secret-value")); assertNotNull(f.coordinator.peek(token.identity()));
            }
        }
    }
}
