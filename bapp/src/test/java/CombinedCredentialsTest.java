import org.junit.jupiter.api.Test;
import com.microsoft.playwright.options.Cookie;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.concurrent.CompletionException;
import static org.junit.jupiter.api.Assertions.*;

/** Verifies complete named credential acquisition and atomic insertion without a native device. */
class CombinedCredentialsTest {
    static final JourneyDefinition.JsonExtraction JSON = new JourneyDefinition.JsonExtraction(URI.create("https://login.example"), "/token", "access_token");
    static final JourneyDefinition.CookieExtraction COOKIE = new JourneyDefinition.CookieExtraction(URI.create("https://app.example/"), "sid", null, null);
    static final JourneyDefinition.CombinedExtraction SOURCES = new JourneyDefinition.CombinedExtraction(List.of(new JourneyDefinition.NamedExtraction("access", JSON), new JourneyDefinition.NamedExtraction("session", COOKIE)));
    static final JourneyDefinition.Injection INJECTION = JourneyDefinition.Injection.perToken(List.of(new JourneyDefinition.TokenInjection("access", JourneyDefinition.InjectionType.BEARER, null)));

    @Test void namedSourcesAndBothRecoveryRoundTripAndRejectDuplicateNames() {
        String base = JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false);
        try {
            String value = JourneyRegistryTest.edit(base, "/journeys/0", "extraction", ConfigManager.extractionNode(SOURCES));
            value = JourneyRegistryTest.edit(value, "/journeys/0", "injection", ConfigManager.injectionNode(INJECTION));
            try (var parsed = ConfigManager.parseNative(value, ConfigManager.DocumentKind.PROJECT); var roundTrip = ConfigManager.parseNative(ConfigManager.nativeToJson(parsed), parsed.kind())) {
                assertEquals(SOURCES, roundTrip.journeys().getFirst().extraction());
            }
            String duplicate = value.replace("\"session\"", "\"access\"");
            assertTrue(assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.parseNative(duplicate, ConfigManager.DocumentKind.PROJECT)).getMessage().contains("unique"));
        } catch (Exception ex) { throw new AssertionError(ex); }
    }

    @Test void everySourceMustArriveAndJsonResponsesAreRoutedToTheirOwnSelectors() throws Exception {
        var second = new JourneyDefinition.JsonExtraction(URI.create("https://other.example"), "/other", "value");
        var definition = new JourneyDefinition.CombinedExtraction(List.of(new JourneyDefinition.NamedExtraction("access", JSON), new JourneyDefinition.NamedExtraction("other", second), new JourneyDefinition.NamedExtraction("session", COOKIE)));
        var clock = Clock.fixed(Instant.ofEpochSecond(2_000_000_000L), ZoneOffset.UTC); var extractor = new TokenExtractor(definition, clock);
        extractor.considerJson("https://login.example/token", "{\"access_token\":\"access-value\",\"value\":\"wrong-value\"}".getBytes(StandardCharsets.UTF_8), true);
        assertFalse(extractor.hasToken());
        extractor.considerJson("https://other.example/other", "{\"value\":\"other-value\"}".getBytes(StandardCharsets.UTF_8), true);
        assertFalse(extractor.hasToken());
        Cookie cookie = new Cookie("sid", "cookie-value").setDomain("app.example").setPath("/").setExpires(2_000_000_020d);
        extractor.collectCookies(url -> { assertEquals("https://app.example/", url); return List.of(cookie); });
        assertTrue(extractor.hasToken()); assertEquals("access-value", extractor.result());
        assertEquals(Map.of("access", "access-value", "other", "other-value", "session", "cookie-value"), extractor.namedValues());
        assertEquals(2_000_000_020L, extractor.expirySeconds().orElseThrow());
        var lifetime = TokenLifetime.acquire(extractor.result(), new JourneyDefinition.Cache(1800, 10), clock.instant(), 100, extractor.expirySeconds());
        assertFalse(lifetime.usable(100, clock.instant().plusSeconds(20)));
        extractor.collectCookies(url -> List.of(new Cookie("sid", "rotated").setDomain("app.example").setPath("/")));
        assertEquals("rotated", extractor.cookieValues().get("sid"));
        extractor.collectCookies(url -> List.of()); assertFalse(extractor.hasToken());
    }

    @Test void namedTagsShareOneLoginAndAutomaticInjectionAddsJsonAndAllCookies() throws Exception {
        try (var secrets = new SecretStore()) {
            var registry = new JourneyRegistry(secrets); var base = CoordinatorFixtures.journey("employee");
            var journey = new JourneyDefinition(base.id(), base.displayName(), base.alias(), base.authenticationUrl(), false, base.steps(), base.browser(), SOURCES, INJECTION, base.cache(), null);
            CoordinatorFixtures.load(registry, List.of(journey)); var clock = new CoordinatorFixtures.ManualRuntime(); var attempts = new java.util.concurrent.atomic.AtomicInteger();
            try (var coordinator = new AuthenticationCoordinator(registry, Config.Controls.defaults(), clock, (entry, recovery, deadline, cancelled) -> {
                attempts.incrementAndGet(); return new BrowserFlowRunner.Outcome(entry.identity(), "access-value", clock.instant(), clock.nanos(), Map.of("sid", "cookie-value", "tenant", "tenant-value"), Map.of("access", "access-value", "session", "cookie-value"), OptionalLong.empty());
            }, entry -> null)) {
                var resolver = new NativeTagResolver(registry, coordinator); var entry = registry.snapshot().resolve("employee");
                String raw = "GET / HTTP/1.1\r\nHost: app.example\r\nAuthorization: Bearer <@employee token=\"access\"/>\r\nCookie: sid=<@employee token=\"session\"/>\r\n\r\n";
                var tagged = resolver.resolve(raw.getBytes(StandardCharsets.US_ASCII), null, false); clock.runWorker();
                String expanded = new String(tagged.future().join().commit(), StandardCharsets.US_ASCII);
                assertTrue(expanded.contains("Bearer access-value")); assertTrue(expanded.contains("sid=cookie-value")); assertEquals(1, attempts.get()); assertEquals(1, tagged.future().join().uses().size());
                var missing = resolver.resolve(raw.replace(" token=\"access\"", "").getBytes(StandardCharsets.US_ASCII), null, false);
                assertTrue(assertThrows(CompletionException.class, () -> missing.future().join()).getCause().getMessage().contains("token="));
                var unknown = resolver.resolve(raw.replace("token=\"access\"", "token=\"unknown\"").getBytes(StandardCharsets.US_ASCII), null, false);
                assertThrows(CompletionException.class, () -> unknown.future().join());
                var ordinary = resolver.resolve("GET / HTTP/1.1\r\nHost: app.example\r\nCookie: sid=old; unrelated=keep\r\nCookie: sid=duplicate\r\n\r\n".getBytes(StandardCharsets.US_ASCII), entry, true);
                String injected = new String(ordinary.future().join().commit(), StandardCharsets.US_ASCII);
                assertTrue(injected.contains("Authorization: Bearer access-value\r\n")); assertTrue(injected.contains("sid=cookie-value")); assertFalse(injected.contains("tenant=tenant-value")); assertTrue(injected.contains("unrelated=keep")); assertFalse(injected.contains("sid=old")); assertFalse(injected.contains("sid=duplicate")); assertEquals(1, attempts.get());
            }
        }
    }

    @Test void eitherRecoveryConditionInvalidatesAndStatusMatchAvoidsReadingBody() {
        for (boolean status : List.of(true, false)) try (var f = new AuthenticationCoordinatorTest.Fixture(Config.Controls.defaults()); var recovery = new SessionRecovery(f.coordinator, f.clock::nanos)) {
            f.acquire(0); f.clock.runWorker(); var token = f.coordinator.peek(f.entry(0).identity());
            recovery.record(1, List.of(new SessionRecovery.Used(token.identity(), token.version(), new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.BOTH, 401, "session.*expired"))), false);
            byte[] body = "session expired".getBytes(StandardCharsets.UTF_8);
            assertEquals(1, recovery.received(1, status ? 401 : 200, () -> { assertFalse(status); return new SessionRecovery.Response(200, "text/plain", null, body.length, () -> new java.io.ByteArrayInputStream(body)); }, false));
        }
    }
    @Test void severalJsonValuesRequireExplicitDestinationsAndInjectTheChosenValue() throws Exception {
        var sources = new JourneyDefinition.CombinedExtraction(List.of(new JourneyDefinition.NamedExtraction("first", JSON), new JourneyDefinition.NamedExtraction("second", JSON)));
        String value = JourneyRegistryTest.edit(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false), "/journeys/0", "extraction", ConfigManager.extractionNode(sources));
        String missing = value;
        assertTrue(assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.parseNative(missing, ConfigManager.DocumentKind.PROJECT)).getMessage().contains("injection.tokens"));
        value = JourneyRegistryTest.edit(value, "/journeys/0", "injection", ConfigManager.injectionNode(JourneyDefinition.Injection.perToken(List.of(
                new JourneyDefinition.TokenInjection("first", JourneyDefinition.InjectionType.DISABLED, null),
                new JourneyDefinition.TokenInjection("second", JourneyDefinition.InjectionType.BEARER, null)))));
        try (var document = ConfigManager.parseNative(value, ConfigManager.DocumentKind.PROJECT); var secrets = new SecretStore()) {
            var registry = new JourneyRegistry(secrets); registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, document); var clock = new CoordinatorFixtures.ManualRuntime();
            try (var coordinator = new AuthenticationCoordinator(registry, Config.Controls.defaults(), clock, (entry, recovery, deadline, cancelled) -> new BrowserFlowRunner.Outcome(entry.identity(), "first-value", clock.instant(), clock.nanos(), Map.of(), Map.of("first", "first-value", "second", "second-value"), OptionalLong.empty()), entry -> null)) {
                var resolver = new NativeTagResolver(registry, coordinator);
                var operation = resolver.resolve("GET / HTTP/1.1\r\nHost: app.example\r\n\r\n".getBytes(StandardCharsets.US_ASCII), registry.snapshot().resolve("employee"), true); clock.runWorker();
                String request = new String(operation.future().join().commit(), StandardCharsets.US_ASCII);
                assertTrue(request.contains("Authorization: Bearer second-value\r\n")); assertFalse(request.contains("first-value"));
            }
        }
    }
}
