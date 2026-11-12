package bpsh.burp.http;

import bpsh.journey.persistence.JourneyDocument;
import bpsh.journey.persistence.JourneyJson;

import bpsh.request.RequestSettings;
import bpsh.journey.persistence.ProjectStore;
import bpsh.journey.editing.JourneyWorkspace;
import bpsh.authentication.credentials.AuthenticationResult;
import bpsh.authentication.credentials.CredentialUse;
import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.ConfigurationException;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.SecretStore;
import bpsh.authentication.session.AuthenticationCoordinator;
import bpsh.authentication.session.CoordinatorFixtures;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.concurrent.CompletionException;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Covers ordered acquisition, atomic wire composition and persisted per-rule policy. */
public class OrderedSessionHandlingTest {
    @Test void nonWaitingResolutionWarmsCredentialsAndComposesCachedCredentials() throws Exception {
        try (var f = new Fixture(false)) {
            var error = assertThrows(AuthenticationFailure.class, () -> f.resolver.resolveAutomatic(RAW.getBytes(StandardCharsets.ISO_8859_1), f.rules("first", "second"), false));
            assertEquals(AuthenticationFailure.Cause.NOT_READY, error.reason());
            while (!f.clock.workers.isEmpty()) f.clock.runWorker();
            try (var operation = f.resolver.resolveAutomatic(RAW.getBytes(StandardCharsets.ISO_8859_1), f.rules("first", "second"), false)) {
                assertTrue(operation.future().isDone());
                assertTrue(new String(operation.future().join().commit(), StandardCharsets.ISO_8859_1).contains("second"));
            }
        }
    }

    @Test void requestPolicyDefaultsAndRoundTripsStrictly() throws Exception {
        String source = bpsh.burp.ui.JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false);
        try (var original = JourneyJson.read(source, JourneyDocument.DocumentKind.PROJECT)) {
            assertEquals(RequestSettings.RequestPolicy.WAIT_FOR_LOGIN, original.controls().requestPolicy());
            String json = JourneyJson.write(original).replace("wait_for_login", "do_not_wait");
            try (var loaded = JourneyJson.read(json, JourneyDocument.DocumentKind.PROJECT)) {
                assertEquals(RequestSettings.RequestPolicy.DO_NOT_WAIT, loaded.controls().requestPolicy());
                assertEquals(json, JourneyJson.write(loaded));
            }
            assertThrows(ConfigurationException.class, () -> JourneyJson.read(json.replace("do_not_wait", "unknown"), JourneyDocument.DocumentKind.PROJECT));
        }
    }

    public static final JourneyDefinition.Recovery RECOVERY = new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null);
    public static final String RAW = "GET /api HTTP/1.1\r\nHost: app.example\r\nAuthorization: stale\r\nCookie: sid=stale; csrf_cookie=stale; untouched=keep\r\n\r\n";
    /** Owns a deterministic coordinator and synthetic credentials only. */
    public static final class Fixture implements AutoCloseable {
        public final SecretStore secrets = new SecretStore(); public final JourneyWorkspace registry = new JourneyWorkspace(secrets);
        public final CoordinatorFixtures.ManualRuntime clock = new CoordinatorFixtures.ManualRuntime();
        public final List<String> calls = new ArrayList<>(); public final AuthenticationCoordinator coordinator; public final NativeTagResolver resolver;
        public String fail;
        public Fixture(boolean combined) {
            CoordinatorFixtures.load(registry, List.of(journey("first", combined), journey("second", combined)));
            coordinator = new AuthenticationCoordinator(registry, RequestSettings.Controls.defaults(), clock, (entry, recovery, deadline, cancelled) -> {
                String alias = entry.definition().alias(); calls.add(alias);
                if (alias.equals(fail)) throw CoordinatorFixtures.failure(AuthenticationFailure.Cause.AUTH_REJECTED);
                return new AuthenticationResult(entry.identity(), alias + "-access", clock.instant(), clock.nanos(),
                        Map.of("sid", alias + "-sid"), combined ? Map.of("access", alias + "-access", "extra", alias + "-extra", "cookievalue", alias + "-cookie", "session", alias + "-sid") : Map.of(), OptionalLong.empty());
            }, entry -> null); resolver = new NativeTagResolver(registry, coordinator);
        }
        public List<NativeTagResolver.Automatic> rules(String... aliases) { return java.util.Arrays.stream(aliases).map(alias -> new NativeTagResolver.Automatic(registry.snapshot().resolve(alias), RECOVERY)).toList(); }
        @Override public void close() { coordinator.close(); secrets.close(); }
    }
    /** Creates either a single bearer or mixed destinations with shared and distinct names. */
    public static JourneyDefinition journey(String alias, boolean combined) {
        var base = CoordinatorFixtures.journey(alias); if (!combined) return base;
        var json = new JourneyDefinition.JsonExtraction(URI.create("https://login.example"), "/token", "value");
        var sources = new JourneyDefinition.CombinedExtraction(List.of(new JourneyDefinition.NamedExtraction("access", json), new JourneyDefinition.NamedExtraction("extra", json), new JourneyDefinition.NamedExtraction("cookievalue", json),
                new JourneyDefinition.NamedExtraction("session", new JourneyDefinition.CookieExtraction(URI.create("https://app.example/"), "sid", null, null))));
        var injection = JourneyDefinition.Injection.perToken(List.of(new JourneyDefinition.TokenInjection("access", JourneyDefinition.InjectionType.BEARER, null),
                new JourneyDefinition.TokenInjection("extra", JourneyDefinition.InjectionType.HEADER, "X-" + alias), new JourneyDefinition.TokenInjection("cookievalue", JourneyDefinition.InjectionType.COOKIE, "csrf_cookie")));
        return new JourneyDefinition(base.id(), base.displayName(), base.alias(), base.authenticationUrl(), false, List.of(), base.browser(), sources, injection, base.cache(), null);
    }
    public @Test void sessionsStartSequentiallyAndAllCredentialsCommitTogetherWithLastRuleWinning() throws Exception {
        try (var f = new Fixture(true); var op = f.resolver.resolveAutomatic(RAW.getBytes(StandardCharsets.ISO_8859_1), f.rules("first", "second"))) {
            assertEquals(1, f.clock.workers.size()); assertEquals(1, f.coordinator.capacity().waitingRequests());
            f.clock.runWorker(); assertEquals(List.of("first"), f.calls); assertFalse(op.future().isDone()); assertEquals(1, f.clock.workers.size());
            f.clock.runWorker(); var resolved = op.future().join(); String wire = new String(resolved.commit(), StandardCharsets.ISO_8859_1);
            assertEquals(List.of("first", "second"), f.calls); assertTrue(wire.contains("Authorization: Bearer second-access\r\n"));
            assertTrue(wire.contains("X-first: first-extra\r\n")); assertTrue(wire.contains("X-second: second-extra\r\n"));
            assertTrue(wire.contains("sid=second-sid")); assertTrue(wire.contains("csrf_cookie=second-cookie")); assertTrue(wire.contains("untouched=keep"));
            assertFalse(wire.contains("stale")); assertEquals(2, resolved.uses().size()); assertEquals(0, f.coordinator.capacity().waitingRequests());
            try (var cached = f.resolver.resolveAutomatic(RAW.getBytes(StandardCharsets.ISO_8859_1), f.rules("second", "first"))) {
                assertTrue(cached.future().isDone()); assertTrue(f.clock.workers.isEmpty()); assertTrue(new String(cached.future().join().commit(), StandardCharsets.ISO_8859_1).contains("Bearer first-access")); assertEquals(2, f.calls.size());
            }
        }
    }
    public @Test void failureStopsRemainingLoginsAndNeverExposesPartialBytes() throws Exception {
        try (var f = new Fixture(true)) {
            f.fail = "first"; byte[] raw = RAW.getBytes(StandardCharsets.ISO_8859_1);
            try (var op = f.resolver.resolveAutomatic(raw, f.rules("first", "second"))) {
                f.clock.runWorker(); assertThrows(CompletionException.class, () -> op.future().join()); assertEquals(List.of("first"), f.calls); assertTrue(f.clock.workers.isEmpty()); assertArrayEquals(RAW.getBytes(StandardCharsets.ISO_8859_1), raw); assertEquals(0, f.coordinator.capacity().waitingRequests());
            }
        }
        try (var f = new Fixture(true)) {
            f.fail = "second";
            try (var op = f.resolver.resolveAutomatic(RAW.getBytes(StandardCharsets.ISO_8859_1), f.rules("first", "second"))) { f.clock.runWorker(); f.clock.runWorker(); assertThrows(CompletionException.class, () -> op.future().join()); assertEquals(List.of("first", "second"), f.calls); }
        }
    }
    public @Test void timeoutAndDetachRetainOneOriginalDeadlineAndDoNotStartPendingJourney() throws Exception {
        for (boolean cancel : List.of(false, true)) try (var f = new Fixture(false)) {
            f.coordinator.updateControls(CoordinatorFixtures.controls(1, 1, 1000, 1000, 3000));
            var op = f.resolver.resolveAutomatic(RAW.getBytes(StandardCharsets.ISO_8859_1), f.rules("first", "second"));
            if (cancel) op.close(); else f.clock.advance(1000);
            assertThrows(CompletionException.class, () -> op.future().join()); f.clock.runWorker(); assertEquals(List.of("first"), f.calls); assertTrue(f.clock.workers.isEmpty()); assertEquals(0, f.coordinator.capacity().waitingRequests());
        }
        try (var f = new Fixture(false)) {
            f.coordinator.updateControls(CoordinatorFixtures.controls(null, null, 1000, 1000, 3000));
            try (var op = f.resolver.resolveAutomatic(RAW.getBytes(StandardCharsets.ISO_8859_1), f.rules("first", "second"))) { f.clock.advance(900); f.clock.runWorker(); f.clock.advance(100); assertThrows(CompletionException.class, () -> op.future().join()); assertEquals(0, f.coordinator.capacity().waitingRequests()); }
        }
    }
    public @Test void explicitTagsSuppressAutomaticRulesAndStaleGenerationCannotCommit() throws Exception {
        try (var f = new Fixture(false); var op = f.resolver.resolveAutomatic("GET / HTTP/1.1\r\nHost: app.example\r\nX-Tag: <@first/>\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1), f.rules("second"))) {
            f.clock.runWorker(); assertEquals(List.of("first"), f.calls); assertFalse(new String(op.future().join().commit(), StandardCharsets.ISO_8859_1).contains("Authorization:"));
        }
        try (var f = new Fixture(false); var op = f.resolver.resolveAutomatic(RAW.getBytes(StandardCharsets.ISO_8859_1), f.rules("first", "second"))) {
            f.clock.runWorker(); f.clock.runWorker(); var resolved = op.future().join(); f.coordinator.invalidateVersion(f.registry.snapshot().resolve("first").identity(), f.coordinator.peek(f.registry.snapshot().resolve("first").identity()).version()); assertThrows(AuthenticationFailure.class, resolved::commit);
        }
    }
    public @Test void rulesRoundTripOrderActivationScopesAndExpirationWithoutJourneyRecovery() throws Exception {
        try (var f = new Fixture(false)) {
            var a = f.registry.snapshot().resolve("first"); var b = f.registry.snapshot().resolve("second");
            var rules = List.of(new RequestSettings.AutomaticRule(false, new RequestSettings.JourneySelection(a.identity().scope(), a.identity().journeyId()), new RequestSettings.Prefix(URI.create("https://app.example/api")), null, RECOVERY),
                    new RequestSettings.AutomaticRule(true, new RequestSettings.JourneySelection(b.identity().scope(), b.identity().journeyId()), new RequestSettings.AllRequests(), null, new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.BOTH, 403, "session.*expired")));
            var d = RequestSettings.Controls.defaults(); var controls = new RequestSettings.Controls(true, rules, d.tools(), d.requestWaitTimeoutMs(), d.attemptTimeoutMs(), d.cycleTimeoutMs(), null, null);
            try (var doc = new JourneyDocument(JourneyDocument.DocumentKind.PROJECT, java.util.UUID.randomUUID(), List.of(a.definition(), b.definition()), List.of(), controls, Map.of()); var round = JourneyJson.read(JourneyJson.write(doc), doc.kind())) { assertEquals(controls, round.controls()); }
            var duplicate = new RequestSettings.Controls(true, List.of(rules.getFirst(), rules.getFirst()), d.tools(), 60_000, 60_000, 300_000, null, null);
            try (var doc = new JourneyDocument(JourneyDocument.DocumentKind.PROJECT, java.util.UUID.randomUUID(), List.of(a.definition()), List.of(), duplicate, Map.of())) { assertTrue(assertThrows(ConfigurationException.class, () -> JourneyJson.write(doc)).getMessage().contains("only once")); }
        }
    }
    public @Test void expirationAttributionExcludesAnEntirelyOverwrittenJourney() throws Exception {
        try (var f = new Fixture(false); var recovery = new SessionRecovery(f.coordinator, f.clock::nanos);
             var op = f.resolver.resolveAutomatic(RAW.getBytes(StandardCharsets.ISO_8859_1), f.rules("first", "second"))) {
            f.clock.runWorker(); f.clock.runWorker(); var result = op.future().join(); result.commit();
            assertEquals(List.of(f.registry.snapshot().resolve("second").identity()), result.uses().stream().map(CredentialUse::identity).toList());
            recovery.record(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 1), result.uses(), false); assertEquals(1, recovery.received(new bpsh.burp.http.RequestExchange(bpsh.browser.AuthTrafficGuard.Family.GLOBAL, 1), new SessionRecovery.Response(401, null, null, 0, () -> { throw new AssertionError("Status-only detection must not read the body."); }), false));
            assertNotNull(f.coordinator.peek(f.registry.snapshot().resolve("first").identity())); assertNull(f.coordinator.peek(f.registry.snapshot().resolve("second").identity()));
        }
    }
    public @Test void deletingAPendingJourneyReleasesTheWholeRequestImmediately() throws Exception {
        try (var f = new Fixture(false); var op = f.resolver.resolveAutomatic(RAW.getBytes(StandardCharsets.ISO_8859_1), f.rules("first", "second"))) {
            var first = f.registry.snapshot().resolve("first").definition();
            CoordinatorFixtures.load(f.registry, List.of(first)); f.coordinator.configurationChanged();
            assertTrue(op.future().isCompletedExceptionally()); assertEquals(0, f.coordinator.capacity().waitingRequests());
            f.clock.runWorker(); assertEquals(List.of("first"), f.calls); assertTrue(f.clock.workers.isEmpty());
        }
    }
}
