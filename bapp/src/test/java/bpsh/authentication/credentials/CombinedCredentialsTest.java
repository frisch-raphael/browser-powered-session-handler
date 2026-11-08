package bpsh.authentication.credentials;

import bpsh.journey.persistence.JourneyDocument;
import bpsh.journey.persistence.JourneyJson;

import bpsh.request.RequestSettings;
import bpsh.journey.persistence.ProjectStore;
import bpsh.journey.editing.JourneyWorkspace;
import bpsh.burp.http.NativeTagResolver;
import bpsh.burp.http.SessionRecovery;
import bpsh.journey.ConfigurationException;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.SecretStore;
import bpsh.authentication.session.AuthenticationCoordinator;
import bpsh.authentication.session.AuthenticationCoordinatorTest;
import bpsh.authentication.session.CoordinatorFixtures;
import bpsh.burp.ui.JourneyRegistryTest;
import bpsh.authentication.credentials.CapturedCookie;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.concurrent.CompletionException;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Verifies complete named credential acquisition and atomic insertion without a native device. */
public class CombinedCredentialsTest {
    public static final JourneyDefinition.JsonExtraction JSON = new JourneyDefinition.JsonExtraction(URI.create("https://login.example"), "/token", "access_token");
    public static final JourneyDefinition.CookieExtraction COOKIE = new JourneyDefinition.CookieExtraction(URI.create("https://app.example/"), "sid", null, null);
    public static final JourneyDefinition.CombinedExtraction SOURCES = new JourneyDefinition.CombinedExtraction(List.of(new JourneyDefinition.NamedExtraction("access", JSON), new JourneyDefinition.NamedExtraction("session", COOKIE)));
    public static final JourneyDefinition.Injection INJECTION = JourneyDefinition.Injection.perToken(List.of(new JourneyDefinition.TokenInjection("access", JourneyDefinition.InjectionType.BEARER, null)));

    public @Test void cachedValuesFollowRenamedReorderedAndRemovedSourcesWithoutResettingTheirLifetime() throws Exception {
        var owner = CoordinatorFixtures.journey("employee"); var identity = new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, owner.id(), 1);
        var lifetime = TokenLifetime.acquire("access-value", owner.cache(), Instant.ofEpochSecond(2_000_000_000L), 123, OptionalLong.empty());
        var original = new TokenSnapshot(identity, 7, "access-value", lifetime, Map.of("sid", "cookie-value"), Map.of("access", "access-value", "session", "cookie-value"));
        var current = new JourneyDefinition.Identity(identity.scope(), identity.journeyId(), 2);
        var renamed = new JourneyDefinition.CombinedExtraction(List.of(new JourneyDefinition.NamedExtraction("cookie", COOKIE), new JourneyDefinition.NamedExtraction("bearer", JSON)));
        var rebound = original.reconfigure(current, SOURCES, renamed); assertNotNull(rebound);
        assertEquals(Map.of("cookie", "cookie-value", "bearer", "access-value"), rebound.namedTokens()); assertEquals("access-value", rebound.value());
        assertEquals(Map.of("sid", "cookie-value"), rebound.cookies()); assertSame(lifetime, rebound.lifetime()); assertEquals(7, rebound.version());
        var single = original.reconfigure(current, SOURCES, JSON); assertNotNull(single); assertEquals("access-value", single.value());
        assertTrue(single.namedTokens().isEmpty()); assertTrue(single.cookies().isEmpty());
        assertNull(original.reconfigure(current, SOURCES, new JourneyDefinition.JsonExtraction(JSON.responseOrigin(), "/new", "new_token")));
        assertNull(original.reconfigure(current, SOURCES, new JourneyDefinition.CombinedExtraction(List.of())));
    }

    public @Test void namedSourcesAndBothRecoveryRoundTripAndRejectDuplicateNames() {
        String base = JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false);
        try {
            String value = JourneyRegistryTest.edit(base, "/journeys/0", "extraction", JourneyJson.extractionNode(SOURCES));
            value = JourneyRegistryTest.edit(value, "/journeys/0", "injection", JourneyJson.injectionNode(INJECTION));
            try (var parsed = JourneyJson.read(value, JourneyDocument.DocumentKind.PROJECT); var roundTrip = JourneyJson.read(JourneyJson.write(parsed), parsed.kind())) {
                assertEquals(SOURCES, roundTrip.journeys().getFirst().extraction());
            }
            String duplicate = value.replace("\"session\"", "\"access\"");
            assertTrue(assertThrows(ConfigurationException.class, () -> JourneyJson.read(duplicate, JourneyDocument.DocumentKind.PROJECT)).getMessage().contains("unique"));
        } catch (Exception ex) { throw new AssertionError(ex); }
    }

    public @Test void everySourceMustArriveAndJsonResponsesAreRoutedToTheirOwnSelectors() throws Exception {
        var second = new JourneyDefinition.JsonExtraction(URI.create("https://other.example"), "/other", "value");
        var definition = new JourneyDefinition.CombinedExtraction(List.of(new JourneyDefinition.NamedExtraction("access", JSON), new JourneyDefinition.NamedExtraction("other", second), new JourneyDefinition.NamedExtraction("session", COOKIE)));
        var clock = Clock.fixed(Instant.ofEpochSecond(2_000_000_000L), ZoneOffset.UTC); var extractor = new TokenExtractor(definition, clock);
        extractor.considerJson("https://login.example/token", "{\"access_token\":\"access-value\",\"value\":\"wrong-value\"}".getBytes(StandardCharsets.UTF_8), true);
        assertFalse(extractor.hasToken());
        extractor.considerJson("https://other.example/other", "{\"value\":\"other-value\"}".getBytes(StandardCharsets.UTF_8), true);
        assertFalse(extractor.hasToken());
        CapturedCookie cookie = new bpsh.authentication.credentials.CapturedCookie("sid", "cookie-value", "app.example", "/", 2_000_000_020d);
        extractor.collectCookies(url -> { assertEquals("https://app.example/", url); return List.of(cookie); });
        assertTrue(extractor.hasToken()); assertEquals("access-value", extractor.result());
        assertEquals(Map.of("access", "access-value", "other", "other-value", "session", "cookie-value"), extractor.namedValues());
        assertEquals(2_000_000_020L, extractor.expirySeconds().orElseThrow());
        var lifetime = TokenLifetime.acquire(extractor.result(), new JourneyDefinition.Cache(1800, 10), clock.instant(), 100, extractor.expirySeconds());
        assertFalse(lifetime.usable(100, clock.instant().plusSeconds(20)));
        extractor.collectCookies(url -> List.of(new bpsh.authentication.credentials.CapturedCookie("sid", "rotated", "app.example", "/", null)));
        assertEquals("rotated", extractor.cookieValues().get("sid"));
        extractor.collectCookies(url -> List.of()); assertFalse(extractor.hasToken());
    }

    public @Test void namedTagsShareOneLoginAndAutomaticInjectionAddsJsonAndAllCookies() throws Exception {
        try (var secrets = new SecretStore()) {
            var registry = new JourneyWorkspace(secrets); var base = CoordinatorFixtures.journey("employee");
            var journey = new JourneyDefinition(base.id(), base.displayName(), base.alias(), base.authenticationUrl(), false, base.steps(), base.browser(), SOURCES, INJECTION, base.cache(), null);
            CoordinatorFixtures.load(registry, List.of(journey)); var clock = new CoordinatorFixtures.ManualRuntime(); var attempts = new java.util.concurrent.atomic.AtomicInteger();
            try (var coordinator = new AuthenticationCoordinator(registry, RequestSettings.Controls.defaults(), clock, (entry, recovery, deadline, cancelled) -> {
                attempts.incrementAndGet(); return new AuthenticationResult(entry.identity(), "access-value", clock.instant(), clock.nanos(), Map.of("sid", "cookie-value", "tenant", "tenant-value"), Map.of("access", "access-value", "session", "cookie-value"), OptionalLong.empty());
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

    public @Test void eitherRecoveryConditionInvalidatesAndStatusMatchAvoidsReadingBody() {
        for (boolean status : List.of(true, false)) try (var f = new AuthenticationCoordinatorTest.Fixture(RequestSettings.Controls.defaults()); var recovery = new SessionRecovery(f.coordinator, f.clock::nanos)) {
            f.acquire(0); f.clock.runWorker(); var token = f.coordinator.peek(f.entry(0).identity());
            recovery.record(1, List.of(new CredentialUse(token.identity(), token.version(), new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.BOTH, 401, "session.*expired"))), false);
            byte[] body = "session expired".getBytes(StandardCharsets.UTF_8);
            assertEquals(1, recovery.received(1, status ? 401 : 200, () -> { assertFalse(status); return new SessionRecovery.Response(200, "text/plain", null, body.length, () -> new java.io.ByteArrayInputStream(body)); }, false));
        }
    }
    public @Test void severalJsonValuesRequireExplicitDestinationsAndInjectTheChosenValue() throws Exception {
        var sources = new JourneyDefinition.CombinedExtraction(List.of(new JourneyDefinition.NamedExtraction("first", JSON), new JourneyDefinition.NamedExtraction("second", JSON)));
        String value = JourneyRegistryTest.edit(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false), "/journeys/0", "extraction", JourneyJson.extractionNode(sources));
        String missing = value;
        assertTrue(assertThrows(ConfigurationException.class, () -> JourneyJson.read(missing, JourneyDocument.DocumentKind.PROJECT)).getMessage().contains("injection.tokens"));
        value = JourneyRegistryTest.edit(value, "/journeys/0", "injection", JourneyJson.injectionNode(JourneyDefinition.Injection.perToken(List.of(
                new JourneyDefinition.TokenInjection("first", JourneyDefinition.InjectionType.DISABLED, null),
                new JourneyDefinition.TokenInjection("second", JourneyDefinition.InjectionType.BEARER, null)))));
        try (var document = JourneyJson.read(value, JourneyDocument.DocumentKind.PROJECT); var secrets = new SecretStore()) {
            var registry = new JourneyWorkspace(secrets); registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, document); var clock = new CoordinatorFixtures.ManualRuntime();
            try (var coordinator = new AuthenticationCoordinator(registry, RequestSettings.Controls.defaults(), clock, (entry, recovery, deadline, cancelled) -> new AuthenticationResult(entry.identity(), "first-value", clock.instant(), clock.nanos(), Map.of(), Map.of("first", "first-value", "second", "second-value"), OptionalLong.empty()), entry -> null)) {
                var resolver = new NativeTagResolver(registry, coordinator);
                var operation = resolver.resolve("GET / HTTP/1.1\r\nHost: app.example\r\n\r\n".getBytes(StandardCharsets.US_ASCII), registry.snapshot().resolve("employee"), true); clock.runWorker();
                String request = new String(operation.future().join().commit(), StandardCharsets.US_ASCII);
                assertTrue(request.contains("Authorization: Bearer second-value\r\n")); assertFalse(request.contains("first-value"));
            }
        }
    }
}
