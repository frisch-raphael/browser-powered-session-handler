import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import com.microsoft.playwright.BrowserType;
import java.lang.reflect.Field;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises production browser ownership/extraction with actual bundled Chromium and local origins. */
class BrowserJourneyIntegrationTest {
    static BrowserRuntimeManager runtime;
    static Pkcs11IdentityManager identities;
    static AuthTrafficGuard guard;
    static BrowserFlowRunner runner;

    /** Fails if pinned assets are missing; this explicit suite never skips browser prerequisites. */
    @BeforeAll static void setup() throws Exception {
        runtime = new BrowserRuntimeManager(); runtime.acquire(System.nanoTime() + TimeUnit.MINUTES.toNanos(5), () -> false);
        identities = new Pkcs11IdentityManager(); guard = new AuthTrafficGuard(); runner = new BrowserFlowRunner(runtime, identities, guard, Clock.systemUTC());
    }
    /** Releases only suite-owned services; the verified immutable browser cache remains reusable. */
    @AfterAll static void shutdown() { if (runtime != null) runtime.close(); if (identities != null) identities.close(); if (guard != null) guard.close(); }
    /** @param j Current fixture definition. @param values Session snapshot. @return Production-runner outcome under a finite attempt deadline. */
    static BrowserFlowRunner.Outcome run(JourneyDefinition j, SecretStore.Values values) throws Exception {
        return runner.run(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, j.id(), 1), j, values, false,
                System.nanoTime() + TimeUnit.SECONDS.toNanos(25), () -> false);
    }
    /** @param type Retained step kind. @param selector Optional selector. @param value Optional ordinary input/state/pattern. @return Stable-ID immutable fixture step. */
    static AuthStep.Definition step(AuthStep.Type type, String selector, String value) {
        return new AuthStep.Definition(UUID.randomUUID(), type, selector, type == AuthStep.Type.INPUT ? value : null,
                type == AuthStep.Type.WAIT_LOAD_STATE ? value : null, type == AuthStep.Type.WAIT_URL ? value : null,
                type == AuthStep.Type.WAIT_TIME ? Integer.parseInt(value) : null);
    }

    @Test void sessionLossRecoveryUsesThreeSequentialFreshBrowsersAndReplaysEightActualRequestsOnce() throws Exception {
        var loginAttempts = new AtomicInteger(); var issuances = new AtomicInteger(); var protectedIngress = new AtomicInteger(); var acceptedActions = new AtomicInteger();
        var acceptedToken = new java.util.concurrent.atomic.AtomicReference<String>();
        var lifecycle = new java.util.concurrent.CopyOnWriteArrayList<BrowserFlowRunner.Lifecycle>();
        try (var origin = IntegrationFixtures.http(); var secrets = new SecretStore()) {
            origin.route("/login", e -> {
                int attempt = loginAttempts.incrementAndGet();
                IntegrationFixtures.respond(e, attempt == 2 || attempt == 3 ? 503 : 200, "text/html",
                        attempt == 2 || attempt == 3 ? "temporarily unavailable" : "<script>fetch('/token')</script>");
            });
            origin.route("/token", e -> { String token = "browser-recovery-" + issuances.incrementAndGet(); acceptedToken.set(token); IntegrationFixtures.respond(e, 200, "application/json", "{\"access_token\":\"" + token + "\"}"); });
            origin.route("/protected", e -> {
                protectedIngress.incrementAndGet(); boolean accepted = acceptedToken.get() != null && ("Bearer " + acceptedToken.get()).equals(e.getRequestHeaders().getFirst("Authorization"));
                if (accepted) acceptedActions.incrementAndGet(); IntegrationFixtures.respond(e, accepted ? 200 : 401, "text/plain", accepted ? "fixture-account" : "session lost");
            });
            origin.start(); var definition = IntegrationFixtures.journey(origin, List.of()); var registry = new JourneyRegistry(secrets); CoordinatorFixtures.load(registry, List.of(definition));
            var observedRunner = new BrowserFlowRunner(runtime, identities, guard, Clock.systemUTC(), lifecycle::add);
            try (var coordinator = new AuthenticationCoordinator(registry, secrets, observedRunner, identities, Config.Controls.defaults()); var recovery = new SessionRecovery(coordinator)) {
                var entry = registry.snapshot().resolve(definition.alias()); coordinator.acquire(List.of(entry)).future().get(25, TimeUnit.SECONDS);
                var initial = coordinator.peek(entry.identity()); var client = java.net.http.HttpClient.newHttpClient();
                var proof = client.send(java.net.http.HttpRequest.newBuilder(origin.url("/protected")).header("Authorization", "Bearer " + initial.value()).build(), java.net.http.HttpResponse.BodyHandlers.ofString());
                assertEquals(200, proof.statusCode()); assertEquals("fixture-account", proof.body()); acceptedToken.set(null);
                var resolver = new NativeTagResolver(registry, coordinator); var rule = new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null);
                var observations = new java.util.ArrayList<Integer>();
                for (int i = 0; i < 8; i++) {
                    String raw = "POST /protected HTTP/1.1\r\nHost: " + origin.url("/").getAuthority() + "\r\nAuthorization: Bearer stale\r\nX-Trace: original-" + i + "\r\nContent-Length: 9\r\n\r\nbody=data";
                    try (var operation = resolver.resolveAutomatic(raw.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1), List.of(new NativeTagResolver.Automatic(entry, rule)))) {
                        var resolved = operation.future().join(); String wire = new String(resolved.commit(), java.nio.charset.StandardCharsets.ISO_8859_1);
                        assertTrue(wire.contains("Bearer " + initial.value()));
                        recovery.record(100 + i, resolved.uses(), false, resolved.replayTemplate(raw.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1)));
                        var response = client.send(java.net.http.HttpRequest.newBuilder(origin.url("/protected")).header("Authorization", "Bearer " + initial.value()).POST(java.net.http.HttpRequest.BodyPublishers.ofString("body=data")).build(), java.net.http.HttpResponse.BodyHandlers.ofString());
                        observations.add(response.statusCode()); assertEquals(401, response.statusCode());
                    }
                }
                var decisions = new java.util.ArrayList<SessionRecovery.Decision>();
                for (int i = 0; i < 8; i++) decisions.add(recovery.receivedPlan(100 + i, observations.get(i), () -> null, false, true));
                for (int i = 0; i < 8; i++) try (var plan = decisions.get(i).replay().get(60, TimeUnit.SECONDS)) {
                    String wire = new String(plan.claim(), java.nio.charset.StandardCharsets.ISO_8859_1);
                    assertTrue(wire.contains("X-Trace: original-" + i)); assertTrue(wire.endsWith("body=data"));
                    String authorization = wire.lines().filter(line -> line.startsWith("Authorization:")).findFirst().orElseThrow().substring("Authorization:".length()).trim();
                    var response = client.send(java.net.http.HttpRequest.newBuilder(origin.url("/protected")).header("Authorization", authorization).header("X-Trace", "original-" + i)
                            .POST(java.net.http.HttpRequest.BodyPublishers.ofString("body=data")).build(), java.net.http.HttpResponse.BodyHandlers.ofString());
                    assertEquals(200, response.statusCode()); assertEquals("fixture-account", response.body());
                    recovery.record(200 + i, plan.uses(), false); assertNull(recovery.receivedPlan(200 + i, response.statusCode(), () -> null, false, true).replay());
                    assertThrows(AuthenticationFailure.class, plan::claim);
                }
                assertEquals(4, loginAttempts.get()); assertEquals(2, issuances.get()); assertEquals(17, protectedIngress.get()); assertEquals(9, acceptedActions.get());
                assertEquals(3, coordinator.status(entry.identity()).attempts()); assertTrue(coordinator.status(entry.identity()).acceptedUse());
                int browsers = 0, contexts = 0; var seen = new java.util.HashSet<Long>(); int opens = 0;
                for (var event : lifecycle) switch (event.event()) {
                    case BROWSER_OPEN -> { assertEquals(0, browsers); browsers++; opens++; assertTrue(seen.add(event.resourceId())); }
                    case CONTEXT_OPEN -> { assertEquals(0, contexts); contexts++; assertTrue(seen.add(event.resourceId())); }
                    case CONTEXT_CLOSED -> { assertEquals(1, contexts); contexts--; }
                    case BROWSER_CLOSED -> { assertEquals(0, contexts); assertEquals(1, browsers); browsers--; }
                }
                assertEquals(4, opens); assertEquals(0, browsers); assertEquals(0, contexts);
            }
        }
    }

    @Test void retainedStepsAndSecureInputProduceNormalizedToken() throws Exception {
        var secure = step(AuthStep.Type.SECURE_INPUT, "#password", null); AtomicInteger posted = new AtomicInteger();
        try (var origin = IntegrationFixtures.http()) {
            origin.route("/login", e -> IntegrationFixtures.respond(e, 200, "text/html", """
                <input id='name'><input id='password' type='password'><button id='submit'>Sign in</button>
                <script>submit.onclick=async()=>{await fetch('/credentials',{method:'POST',body:JSON.stringify({user:document.querySelector('#name').value,password:document.querySelector('#password').value})});location.href='/done'};</script>
                """));
            origin.route("/credentials", e -> { String body = new String(e.getRequestBody().readAllBytes()); if (body.contains("fixture-user") && body.contains("fixture-password")) posted.incrementAndGet(); IntegrationFixtures.respond(e, 200, "text/plain", "ok"); });
            origin.route("/done", e -> IntegrationFixtures.respond(e, 200, "text/html", "<div id='done'>Ready</div><script>setTimeout(()=>fetch('/token'),1200)</script>"));
            origin.route("/token", e -> IntegrationFixtures.respond(e, 200, "application/json", "{\"access_token\":\"  Bearer fixture-token  \"}")); origin.start();
            var steps = List.of(step(AuthStep.Type.WAIT_LOAD_STATE, null, "load"), step(AuthStep.Type.INPUT, "#name", "fixture-user"), secure,
                    step(AuthStep.Type.WAIT_SELECTOR, "#submit", null), step(AuthStep.Type.WAIT_TIME, null, "10"), step(AuthStep.Type.CLICK, "#submit", null),
                    step(AuthStep.Type.WAIT_URL, null, "**/done"), step(AuthStep.Type.WAIT_LOAD_STATE, null, "domcontentloaded"),
                    step(AuthStep.Type.WAIT_LOAD_STATE, null, "networkidle"), step(AuthStep.Type.WAIT_SELECTOR, "#done", null));
            JourneyDefinition j = IntegrationFixtures.journey(origin, steps);
            j = IntegrationFixtures.configured(j, j.authenticationUrl(), new JourneyDefinition.Browser(true, null, 5000, 3000), j.extraction(), null);
            try (var values = new SecretStore.Values(null, Map.of(secure.id(), "fixture-password".toCharArray()))) {
                var result = run(j, values); assertEquals("fixture-token", result.token()); assertEquals(1, posted.get()); assertFalse(result.toString().contains("fixture-token"));
            }
        }
    }
    @Test void namedJsonAndSeveralCookiesAreAcquiredTogether() throws Exception {
        try (var origin = IntegrationFixtures.http(); var values = SecretStore.Values.empty()) {
            origin.route("/login", e -> {
                e.getResponseHeaders().add("Set-Cookie", "sid=session-value; Path=/; HttpOnly");
                IntegrationFixtures.respond(e, 200, "text/html", "<script>fetch('/token')</script>");
            });
            origin.route("/token", e -> {
                e.getResponseHeaders().add("Set-Cookie", "tenant=tenant-value; Path=/; HttpOnly");
                IntegrationFixtures.respond(e, 200, "application/json", "{\"access_token\":\"access-value\"}");
            }); origin.start();
            var base = IntegrationFixtures.journey(origin, List.of());
            var selection = new JourneyDefinition.CombinedExtraction(List.of(
                    new JourneyDefinition.NamedExtraction("access", base.extraction()),
                    new JourneyDefinition.NamedExtraction("session", new JourneyDefinition.CookieExtraction(origin.url("/"), "sid", null, "/")),
                    new JourneyDefinition.NamedExtraction("tenant", new JourneyDefinition.CookieExtraction(origin.url("/"), "tenant", null, "/"))));
            var journey = IntegrationFixtures.configured(base, base.authenticationUrl(), base.browser(), selection, null);
            var result = run(journey, values);
            assertEquals(Map.of("access", "access-value", "session", "session-value", "tenant", "tenant-value"), result.namedTokens());
            assertEquals(Map.of("sid", "session-value", "tenant", "tenant-value"), result.cookies());
            assertEquals("access-value", result.token()); assertFalse(result.toString().contains("access-value"));
        }
    }
    @Test void earlyJsonAndCookieAttemptsStartWithFreshContextState() throws Exception {
        AtomicInteger oldCookies = new AtomicInteger(), visits = new AtomicInteger();
        try (var origin = IntegrationFixtures.http(); var empty = SecretStore.Values.empty()) {
            origin.route("/login", e -> {
                if (e.getRequestHeaders().getFirst("Cookie") != null) oldCookies.incrementAndGet();
                e.getResponseHeaders().add("Set-Cookie", "session=fresh-" + visits.incrementAndGet() + "; Path=/; HttpOnly");
                IntegrationFixtures.respond(e, 200, "text/html", "<script>fetch('/token')</script>");
            });
            origin.route("/token", e -> IntegrationFixtures.respond(e, 200, "application/json", "{\"access_token\":\"early-token\"}")); origin.start();
            JourneyDefinition j = IntegrationFixtures.journey(origin, List.of()); assertEquals("early-token", run(j, empty).token());
            JourneyDefinition cookie = IntegrationFixtures.configured(j, j.authenticationUrl(), j.browser(), new JourneyDefinition.CookieExtraction(origin.url("/"), "session", null, "/"), null);
            assertEquals("fresh-2", run(cookie, empty).token()); assertEquals("fresh-3", run(cookie, empty).token()); assertEquals(0, oldCookies.get());
        }
    }
    @Test void responseBodyRegexJsonAndCookiesCompleteOneBrowserLogin() throws Exception {
        try (var origin = IntegrationFixtures.http(); var values = SecretStore.Values.empty()) {
            origin.route("/login", e -> {
                e.getResponseHeaders().add("Set-Cookie", "sid=session-value; Path=/; HttpOnly");
                IntegrationFixtures.respond(e, 200, "text/html; charset=utf-8", "<meta name='csrf' content='csrf-value'><script>fetch('/token')</script>");
            });
            origin.route("/token", e -> IntegrationFixtures.respond(e, 200, "application/json", "{\"access_token\":\"access-value\"}")); origin.start();
            var base = IntegrationFixtures.journey(origin, List.of());
            var selection = new JourneyDefinition.CombinedExtraction(List.of(
                    new JourneyDefinition.NamedExtraction("access", base.extraction()),
                    new JourneyDefinition.NamedExtraction("csrf", new JourneyDefinition.RegexExtraction(origin.url(""), "/login", "name='csrf' content='", "'")),
                    new JourneyDefinition.NamedExtraction("session", new JourneyDefinition.CookieExtraction(origin.url("/"), "sid", null, "/"))));
            var journey = IntegrationFixtures.configured(base, base.authenticationUrl(), base.browser(), selection, null);
            var result = run(journey, values);
            assertEquals(Map.of("access", "access-value", "csrf", "csrf-value", "session", "session-value"), result.namedTokens());
            assertEquals(Map.of("sid", "session-value"), result.cookies());
            assertFalse(result.toString().contains("csrf-value"));
        }
    }
    @Test void productionCoordinatorPublishesOwnedBrowserResultWithOriginalAcquisitionClocks() throws Exception {
        var providers = java.util.Arrays.stream(java.security.Security.getProviders()).map(java.security.Provider::getName).toList();
        try (var origin = IntegrationFixtures.http(); var secrets = new SecretStore()) {
            origin.route("/login", e -> IntegrationFixtures.respond(e, 200, "text/html", "<script>fetch('/token')</script>"));
            origin.route("/token", e -> IntegrationFixtures.respond(e, 200, "application/json", "{\"access_token\":\"coordinator-token\"}")); origin.start();
            var registry = new JourneyRegistry(secrets); var journey = IntegrationFixtures.journey(origin, List.of()); CoordinatorFixtures.load(registry, List.of(journey));
            try (var coordinator = new AuthenticationCoordinator(registry, secrets, runner, identities, Config.Controls.defaults())) {
                var entry = registry.snapshot().resolve(journey.alias()); var ticket = coordinator.acquire(List.of(entry));
                var snapshot = ticket.future().get(25, TimeUnit.SECONDS).get(entry.identity());
                assertEquals("coordinator-token", snapshot.value()); assertSame(snapshot, coordinator.peek(entry.identity()));
                assertTrue(snapshot.lifetime().acquiredNanos() - System.nanoTime() <= 0); assertEquals(AuthenticationCoordinator.Phase.READY, coordinator.status(entry.identity()).phase());
                assertEquals(0, coordinator.capacity().waitingRequests());
            }
        }
        assertEquals(providers, java.util.Arrays.stream(java.security.Security.getProviders()).map(java.security.Provider::getName).toList(), "ordinary journeys must never initialize a native provider");
    }
    @Test void relevantStatusesAndMalformedResponsesHaveDistinctDispositions() throws Exception {
        for (int status : List.of(503, 401, 200)) try (var origin = IntegrationFixtures.http(); var empty = SecretStore.Values.empty()) {
            origin.route("/login", e -> IntegrationFixtures.respond(e, 200, "text/html", "<script>fetch('/token')</script>"));
            origin.route("/token", e -> { e.getResponseHeaders().set("Retry-After", "7"); IntegrationFixtures.respond(e, status, "application/json", "{}"); }); origin.start();
            var ex = assertThrows(AuthenticationFailure.class, () -> run(IntegrationFixtures.journey(origin, List.of()), empty));
            assertEquals(status == 503 ? AuthenticationFailure.Cause.TEMPORARY_SERVICE : status == 401 ? AuthenticationFailure.Cause.AUTH_REJECTED : AuthenticationFailure.Cause.EXTRACTION, ex.reason());
            assertEquals(status == 503, ex.retryable()); if (status == 503) assertNotNull(ex.retryAfter());
        }
    }
    @Test void unconfiguredSubresource503DoesNotBecomeAnAuthenticationRetry() throws Exception {
        try (var origin = IntegrationFixtures.http(); var empty = SecretStore.Values.empty()) {
            origin.route("/login", e -> IntegrationFixtures.respond(e, 200, "text/html", "<script>fetch('/unrelated')</script>"));
            origin.route("/unrelated", e -> IntegrationFixtures.respond(e, 503, "text/plain", "temporary third-party asset")); origin.start();
            var ex = assertThrows(AuthenticationFailure.class, () -> run(IntegrationFixtures.journey(origin, List.of()), empty));
            assertEquals(AuthenticationFailure.Cause.EXTRACTION, ex.reason()); assertFalse(ex.retryable());
        }
    }
    @Test void elapsedAttemptPreservesRelevantServiceAndAuthenticationErrors() throws Exception {
        for (int status : List.of(503, 401)) try (var origin = IntegrationFixtures.http(); var empty = SecretStore.Values.empty()) {
            origin.route("/login", e -> IntegrationFixtures.respond(e, 200, "text/html", "<script>fetch('/token')</script>"));
            origin.route("/token", e -> IntegrationFixtures.respond(e, status, "application/json", "{}")); origin.start();
            var j = IntegrationFixtures.journey(origin, List.of(step(AuthStep.Type.WAIT_SELECTOR, "#never-present", null)));
            j = IntegrationFixtures.configured(j, j.authenticationUrl(), new JourneyDefinition.Browser(true, null, 1000, 10_000), j.extraction(), null);
            JourneyDefinition journey = j;
            var ex = assertThrows(AuthenticationFailure.class, () -> runner.run(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, journey.id(), 1),
                    journey, empty, false, System.nanoTime() + TimeUnit.SECONDS.toNanos(4), () -> false));
            assertEquals(status == 503 ? AuthenticationFailure.Cause.TEMPORARY_SERVICE : AuthenticationFailure.Cause.AUTH_REJECTED, ex.reason());
        }
    }
    @Test void actualUserAgentMarkerCoversRedirectsPopupsFramesFetchWorkersAndWebsocketHandshake() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http(); var proxy = new IntegrationFixtures.ForwardProxy(guard, null, null); var empty = SecretStore.Values.empty()) {
            cross.route("/cross", e -> { e.getResponseHeaders().set("Access-Control-Allow-Origin", "*"); IntegrationFixtures.respond(e, 200, "text/plain", "cross"); }); cross.start();
            origin.route("/login", e -> IntegrationFixtures.respond(e, 200, "text/html", """
                <iframe src='/frame'></iframe><script>
                (async()=>{fetch('/redirect');window.open('/popup');fetch('%s');new Worker('/worker.js');
                let ws=new WebSocket('ws://'+location.host+'/ws');ws.onopen=()=>ws.close();
                try { await navigator.serviceWorker.register('/sw.js');let active=await navigator.serviceWorker.ready;active.active.postMessage('go'); }
                finally { setTimeout(()=>fetch('/token'),1800); }})();</script>
                """.formatted(cross.url("/cross"))));
            origin.route("/redirect", e -> { e.getResponseHeaders().set("Location", "/redirected"); e.sendResponseHeaders(302, -1); e.close(); });
            for (String path : List.of("/redirected", "/frame-fetch", "/popup-fetch", "/dedicated-fetch", "/sw-fetch")) origin.route(path, e -> IntegrationFixtures.respond(e, 200, "text/plain", "ok"));
            origin.route("/frame", e -> IntegrationFixtures.respond(e, 200, "text/html", "<script>fetch('/frame-fetch')</script>"));
            origin.route("/popup", e -> IntegrationFixtures.respond(e, 200, "text/html", "<script>fetch('/popup-fetch')</script>"));
            origin.route("/worker.js", e -> IntegrationFixtures.respond(e, 200, "application/javascript", "fetch('/dedicated-fetch')"));
            origin.route("/sw.js", e -> IntegrationFixtures.respond(e, 200, "application/javascript", "self.addEventListener('install',e=>self.skipWaiting());self.addEventListener('activate',e=>e.waitUntil(clients.claim()));self.addEventListener('message',e=>e.waitUntil(fetch('/sw-fetch')));"));
            origin.route("/ws", e -> {
                // LittleProxy's CONNECT tunnel is opaque to its HTTP filter. Inspect the actual
                // upgrade request at this owned fixture boundary; real-Burp stripping remains P5.
                var decision = guard.classify(e.getRequestHeaders().getFirst("User-Agent"), AuthTrafficGuard.Family.GLOBAL, 9_000_000);
                proxy.seen.add(new IntegrationFixtures.Seen("/ws", decision.userAgent(), decision.classification()));
                try { String accept = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest((e.getRequestHeaders().getFirst("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").getBytes()));
                    e.getResponseHeaders().set("Upgrade", "websocket"); e.getResponseHeaders().set("Connection", "Upgrade"); e.getResponseHeaders().set("Sec-WebSocket-Accept", accept); e.sendResponseHeaders(101, -1); e.close();
                } catch (Exception ex) { e.close(); }
            });
            origin.route("/token", e -> IntegrationFixtures.respond(e, 200, "application/json", "{\"access_token\":\"marked-token\"}")); origin.start();
            JourneyDefinition j = IntegrationFixtures.journey(origin, List.of());
            j = IntegrationFixtures.configured(j, j.authenticationUrl(), new JourneyDefinition.Browser(true, new JourneyDefinition.Proxy(proxy.url()), 10_000, 5000), j.extraction(), null);
            try { assertEquals("marked-token", run(j, empty).token()); }
            catch (AuthenticationFailure failure) { throw new AssertionError("Marker fixture did not capture its token; observed paths: "
                    + proxy.seen.stream().map(IntegrationFixtures.Seen::path).toList(), failure); }
            Set<String> paths = new HashSet<>(); proxy.seen.forEach(s -> paths.add(s.path()));
            assertTrue(paths.containsAll(List.of("/redirect", "/redirected", "/frame-fetch", "/popup-fetch", "/cross", "/dedicated-fetch", "/sw-fetch", "/ws")), "Required ownership paths: " + paths);
            assertTrue(proxy.seen.stream().allMatch(s -> s.classification() == AuthTrafficGuard.Classification.OWNED));
            String base = proxy.seen.getFirst().agent(); assertTrue(base.startsWith("Mozilla/"));
            for (var seen : proxy.seen) assertEquals(base, seen.agent(), "Clean User-Agent on " + seen.path());
            assertFalse(base.contains("BPSHAuth/"));
        }
    }
    @Test void cancellationKillsOnlyTheOwnedDriverAndReturnsTypedCancellation() throws Exception {
        AtomicInteger requests = new AtomicInteger(); java.util.concurrent.atomic.AtomicBoolean cancel = new java.util.concurrent.atomic.AtomicBoolean();
        try (var origin = IntegrationFixtures.http(); var empty = SecretStore.Values.empty(); var timer = java.util.concurrent.Executors.newSingleThreadScheduledExecutor()) {
            origin.route("/login", e -> { requests.incrementAndGet(); cancel.set(true); IntegrationFixtures.respond(e, 200, "text/html", "never emits token"); }); origin.start();
            JourneyDefinition j = IntegrationFixtures.journey(origin, List.of(step(AuthStep.Type.WAIT_SELECTOR, "#never", null)));
            var ex = assertThrows(AuthenticationFailure.class, () -> runner.run(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, j.id(), 1), j, empty, false,
                    System.nanoTime() + TimeUnit.SECONDS.toNanos(20), cancel::get));
            assertEquals(AuthenticationFailure.Cause.CANCELLED, ex.reason()); assertEquals(1, requests.get());
        }
    }


    @Test void coldAndUpgradeProbesUseNormalBudgets() throws Exception {
        IntegrationFixtures.verifyColdAndUpgrade();
    }

    @Test void packagedClassloaderUsesExactResourcesWithoutSharedDriverCacheOrJvmMutation() throws Exception {
        Path jar = IntegrationFixtures.packagedJar();
        try (var loader = new URLClassLoader(new java.net.URL[]{jar.toUri().toURL(), Path.of("build/classes/java/test").toUri().toURL()}, ClassLoader.getPlatformClassLoader())) {
            loader.loadClass("BrowserJourneyIntegrationTest$PackagedProbe").getMethod("exercise").invoke(null);
        }
    }

    /** Runs only against the candidate JAR, this test probe and JDK platform modules. */
    public static class PackagedProbe {
        /** Verifies actual scoped resources, pinned versions, form/JSON/cookies and fresh contexts. */
        public static void exercise() throws Exception {
            ClassLoader loader = PlaywrightDriverAdapter.class.getClassLoader();
            String scope = "META-INF/bpsh/" + BrowserRuntimeManager.hostPlatform() + "/";
            if (loader.getResource(scope + "browser-assets.json") == null || loader.getResource(scope + "browser-assets.zip") == null)
                throw new AssertionError("Host payload resources missing.");
            for (String name : List.of("driver/package/cli.js", "driver/win32_x64/node.exe", "driver/linux/node", "driver/mac/node"))
                if (loader.getResource(name) != null) throw new AssertionError("Duplicate driver execution resources remain.");
            var json = new com.fasterxml.jackson.databind.ObjectMapper();
            com.fasterxml.jackson.databind.JsonNode metadata;
            try (var in = loader.getResourceAsStream(scope + "browser-assets.json")) { metadata = json.readTree(in); }
            Class<?> driver = loader.loadClass("com.microsoft.playwright.impl.driver.Driver"); Field instance = driver.getDeclaredField("instance"); instance.setAccessible(true); Object before = instance.get(null);
            Map<Object, Object> properties = new java.util.HashMap<>(System.getProperties());
            var origin = com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1", 0), 0);
            origin.createContext("/login", exchange -> {
                byte[] bytes = "<form method='POST' action='/token'><input id='user' name='user'><button id='submit'>Sign in</button></form>".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "text/html"); exchange.sendResponseHeaders(200, bytes.length);
                try (var out = exchange.getResponseBody()) { out.write(bytes); } finally { exchange.close(); }
            });
            origin.createContext("/token", exchange -> {
                exchange.getRequestBody().readAllBytes();
                byte[] bytes = "{\"access_token\":\"packaged-owned-token\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json"); exchange.getResponseHeaders().add("Set-Cookie", "session=packaged-owned-cookie; Path=/; HttpOnly");
                exchange.sendResponseHeaders(200, bytes.length);
                try (var out = exchange.getResponseBody()) { out.write(bytes); } finally { exchange.close(); }
            });
            origin.start();
            try (var runtime = new BrowserRuntimeManager()) {
                var ready = runtime.acquire(System.nanoTime() + TimeUnit.MINUTES.toNanos(5), () -> false);
                if (!Files.isRegularFile(ready.nodeExecutable()) || !Files.isRegularFile(ready.driverEntryPoint()) || !Files.isRegularFile(ready.browserExecutable()))
                    throw new AssertionError("Verified host selectors are missing.");
                var versionBuilder = new ProcessBuilder(ready.nodeExecutable().toString(), "--version").redirectError(ProcessBuilder.Redirect.DISCARD);
                versionBuilder.environment().clear(); versionBuilder.environment().putAll(PlaywrightDriverAdapter.environment(ready));
                Process node = versionBuilder.start();
                try {
                    if (!node.waitFor(10, TimeUnit.SECONDS) || node.exitValue() != 0) throw new AssertionError("Pinned Node version check failed.");
                    byte[] output = node.getInputStream().readNBytes(129);
                    if (output.length > 128 || !new String(output, java.nio.charset.StandardCharsets.UTF_8).trim().equals("v" + metadata.path("nodeVersion").asText()))
                        throw new AssertionError("Pinned Node version differs.");
                } finally { if (node.isAlive()) node.destroyForcibly(); }
                try (var session = PlaywrightDriverAdapter.open(ready, System.nanoTime() + TimeUnit.SECONDS.toNanos(30), () -> false);
                     var browser = session.playwright().chromium().launch(new BrowserType.LaunchOptions().setHeadless(true).setTimeout(20000).setExecutablePath(ready.browserExecutable()).setArgs(List.of("--no-proxy-server")));
                     var context = browser.newContext()) {
                    if (!browser.version().equals(metadata.path("browserVersion").asText())) throw new AssertionError("Pinned Chromium version differs.");
                    var page = context.newPage(); page.navigate("http://127.0.0.1:" + origin.getAddress().getPort() + "/login");
                    page.fill("#user", "fixture"); page.click("#submit");
                    if (!page.textContent("body").contains("packaged-owned-token")) throw new AssertionError("Packaged form/JSON flow failed.");
                    if (context.cookies().stream().noneMatch(cookie -> cookie.name.equals("session") && cookie.value.equals("packaged-owned-cookie")))
                        throw new AssertionError("Packaged cookie capture failed.");
                    try (var fresh = browser.newContext()) { if (!fresh.cookies().isEmpty()) throw new AssertionError("Browser contexts shared cookies."); }
                }
            } finally { origin.stop(0); }
            if (instance.get(null) != before || !properties.equals(new java.util.HashMap<>(System.getProperties()))) throw new AssertionError("Driver singleton or JVM properties changed.");
        }
    }
}
