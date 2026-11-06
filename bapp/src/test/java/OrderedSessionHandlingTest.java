import org.junit.jupiter.api.Test;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.concurrent.CompletionException;
import static org.junit.jupiter.api.Assertions.*;

/** Covers ordered acquisition, atomic wire composition and persisted per-rule policy. */
class OrderedSessionHandlingTest {
    static final JourneyDefinition.Recovery RECOVERY = new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null);
    static final String RAW = "GET /api HTTP/1.1\r\nHost: app.example\r\nAuthorization: stale\r\nCookie: sid=stale; csrf_cookie=stale; untouched=keep\r\n\r\n";
    /** Owns a deterministic coordinator and synthetic credentials only. */
    static final class Fixture implements AutoCloseable {
        final SecretStore secrets = new SecretStore(); final JourneyRegistry registry = new JourneyRegistry(secrets);
        final CoordinatorFixtures.ManualRuntime clock = new CoordinatorFixtures.ManualRuntime();
        final List<String> calls = new ArrayList<>(); final AuthenticationCoordinator coordinator; final NativeTagResolver resolver;
        String fail;
        Fixture(boolean combined) {
            CoordinatorFixtures.load(registry, List.of(journey("first", combined), journey("second", combined)));
            coordinator = new AuthenticationCoordinator(registry, Config.Controls.defaults(), clock, (entry, recovery, deadline, cancelled) -> {
                String alias = entry.definition().alias(); calls.add(alias);
                if (alias.equals(fail)) throw CoordinatorFixtures.failure(AuthenticationFailure.Cause.AUTH_REJECTED);
                return new BrowserFlowRunner.Outcome(entry.identity(), alias + "-access", clock.instant(), clock.nanos(),
                        Map.of("sid", alias + "-sid"), combined ? Map.of("access", alias + "-access", "extra", alias + "-extra", "cookievalue", alias + "-cookie", "session", alias + "-sid") : Map.of(), OptionalLong.empty());
            }, entry -> null); resolver = new NativeTagResolver(registry, coordinator);
        }
        List<NativeTagResolver.Automatic> rules(String... aliases) { return java.util.Arrays.stream(aliases).map(alias -> new NativeTagResolver.Automatic(registry.snapshot().resolve(alias), RECOVERY)).toList(); }
        @Override public void close() { coordinator.close(); secrets.close(); }
    }
    /** Creates either a single bearer or mixed destinations with shared and distinct names. */
    static JourneyDefinition journey(String alias, boolean combined) {
        var base = CoordinatorFixtures.journey(alias); if (!combined) return base;
        var json = new JourneyDefinition.JsonExtraction(URI.create("https://login.example"), "/token", "value");
        var sources = new JourneyDefinition.CombinedExtraction(List.of(new JourneyDefinition.NamedExtraction("access", json), new JourneyDefinition.NamedExtraction("extra", json), new JourneyDefinition.NamedExtraction("cookievalue", json),
                new JourneyDefinition.NamedExtraction("session", new JourneyDefinition.CookieExtraction(URI.create("https://app.example/"), "sid", null, null))));
        var injection = JourneyDefinition.Injection.perToken(List.of(new JourneyDefinition.TokenInjection("access", JourneyDefinition.InjectionType.BEARER, null),
                new JourneyDefinition.TokenInjection("extra", JourneyDefinition.InjectionType.HEADER, "X-" + alias), new JourneyDefinition.TokenInjection("cookievalue", JourneyDefinition.InjectionType.COOKIE, "csrf_cookie")));
        return new JourneyDefinition(base.id(), base.displayName(), base.alias(), base.authenticationUrl(), false, List.of(), base.browser(), sources, injection, base.cache(), null);
    }
    @Test void sessionsStartSequentiallyAndAllCredentialsCommitTogetherWithLastRuleWinning() throws Exception {
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
    @Test void failureStopsRemainingLoginsAndNeverExposesPartialBytes() throws Exception {
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
    @Test void timeoutAndDetachRetainOneOriginalDeadlineAndDoNotStartPendingJourney() throws Exception {
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
    @Test void explicitTagsSuppressAutomaticRulesAndStaleGenerationCannotCommit() throws Exception {
        try (var f = new Fixture(false); var op = f.resolver.resolveAutomatic("GET / HTTP/1.1\r\nHost: app.example\r\nX-Tag: <@first/>\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1), f.rules("second"))) {
            f.clock.runWorker(); assertEquals(List.of("first"), f.calls); assertFalse(new String(op.future().join().commit(), StandardCharsets.ISO_8859_1).contains("Authorization:"));
        }
        try (var f = new Fixture(false); var op = f.resolver.resolveAutomatic(RAW.getBytes(StandardCharsets.ISO_8859_1), f.rules("first", "second"))) {
            f.clock.runWorker(); f.clock.runWorker(); var resolved = op.future().join(); f.coordinator.invalidateVersion(f.registry.snapshot().resolve("first").identity(), f.coordinator.peek(f.registry.snapshot().resolve("first").identity()).version()); assertThrows(AuthenticationFailure.class, resolved::commit);
        }
    }
    @Test void rulesRoundTripOrderActivationScopesAndExpirationWithoutJourneyRecovery() throws Exception {
        try (var f = new Fixture(false)) {
            var a = f.registry.snapshot().resolve("first"); var b = f.registry.snapshot().resolve("second");
            var rules = List.of(new Config.AutomaticRule(false, new Config.JourneySelection(a.identity().scope(), a.identity().journeyId()), Config.UrlMode.SINGLE_URL, URI.create("https://app.example/api"), RECOVERY),
                    new Config.AutomaticRule(true, new Config.JourneySelection(b.identity().scope(), b.identity().journeyId()), Config.UrlMode.ALL_REQUESTS, null, new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.BOTH, 403, "session.*expired")));
            var d = Config.Controls.defaults(); var controls = new Config.Controls(true, rules, d.tools(), d.requestWaitTimeoutMs(), d.attemptTimeoutMs(), d.cycleTimeoutMs(), null, null);
            try (var doc = new ConfigManager.NativeDocument(ConfigManager.DocumentKind.PROJECT, java.util.UUID.randomUUID(), List.of(a.definition(), b.definition()), List.of(), controls, Map.of()); var round = ConfigManager.parseNative(ConfigManager.nativeToJson(doc), doc.kind())) { assertEquals(controls, round.controls()); }
            var duplicate = new Config.Controls(true, List.of(rules.getFirst(), rules.getFirst()), d.tools(), 60_000, 60_000, 300_000, null, null);
            try (var doc = new ConfigManager.NativeDocument(ConfigManager.DocumentKind.PROJECT, java.util.UUID.randomUUID(), List.of(a.definition()), List.of(), duplicate, Map.of())) { assertTrue(assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.nativeToJson(doc)).getMessage().contains("only once")); }
        }
    }
    @Test void expirationAttributionExcludesAnEntirelyOverwrittenJourney() throws Exception {
        try (var f = new Fixture(false); var recovery = new SessionRecovery(f.coordinator, f.clock::nanos);
             var op = f.resolver.resolveAutomatic(RAW.getBytes(StandardCharsets.ISO_8859_1), f.rules("first", "second"))) {
            f.clock.runWorker(); f.clock.runWorker(); var result = op.future().join(); result.commit();
            assertEquals(List.of(f.registry.snapshot().resolve("second").identity()), result.uses().stream().map(SessionRecovery.Used::identity).toList());
            recovery.record(1, result.uses(), false); assertEquals(1, recovery.received(1, new SessionRecovery.Response(401, null, null, 0, () -> { throw new AssertionError("Status-only detection must not read the body."); }), false));
            assertNotNull(f.coordinator.peek(f.registry.snapshot().resolve("first").identity())); assertNull(f.coordinator.peek(f.registry.snapshot().resolve("second").identity()));
        }
    }
    @Test void deletingAPendingJourneyReleasesTheWholeRequestImmediately() throws Exception {
        try (var f = new Fixture(false); var op = f.resolver.resolveAutomatic(RAW.getBytes(StandardCharsets.ISO_8859_1), f.rules("first", "second"))) {
            var first = f.registry.snapshot().resolve("first").definition();
            CoordinatorFixtures.load(f.registry, List.of(first)); f.coordinator.configurationChanged();
            assertTrue(op.future().isCompletedExceptionally()); assertEquals(0, f.coordinator.capacity().waitingRequests());
            f.clock.runWorker(); assertEquals(List.of("first"), f.calls); assertTrue(f.clock.workers.isEmpty());
        }
    }
}
