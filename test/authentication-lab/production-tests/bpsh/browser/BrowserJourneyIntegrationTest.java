package bpsh.browser;

import bpsh.config.Config;
import bpsh.config.JourneyRegistry;
import bpsh.credentials.AuthenticationResult;
import bpsh.http.NativeTagResolver;
import bpsh.http.SessionRecovery;
import bpsh.model.AuthStep;
import bpsh.model.AuthenticationFailure;
import bpsh.model.JourneyDefinition;
import bpsh.mtls.Pkcs11IdentityManager;
import bpsh.runtime.BrowserRuntimeManager;
import bpsh.runtime.PlaywrightDriverAdapter;
import bpsh.secrets.SecretStore;
import bpsh.session.AuthenticationCoordinator;
import bpsh.session.CoordinatorFixtures;
import bpsh.support.AuthLabSupport;
import bpsh.support.IntegrationFixtures;
import bpsh.support.ProductionLabAdapter;
import bpsh.ui.DiagnosticsTest;
import com.microsoft.playwright.BrowserType;
import java.lang.reflect.Field;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises production browser ownership/extraction with actual bundled Chromium and local origins. */
public class BrowserJourneyIntegrationTest {
    public static BrowserRuntimeManager runtime;
    public static Pkcs11IdentityManager identities;
    public static AuthTrafficGuard guard;
    public static BrowserFlowRunner runner;
    public static final java.util.concurrent.CopyOnWriteArrayList<BrowserFlowRunner.Lifecycle> resourceEvents = new java.util.concurrent.CopyOnWriteArrayList<>();
    public static AuthLabSupport controlledTargets;
    public static AuthLabSupport targets() throws Exception {
        if (controlledTargets == null) controlledTargets = new AuthLabSupport();
        return controlledTargets;
    }

    /** Fails if pinned assets are missing; this explicit suite never skips browser prerequisites. */
    public @BeforeAll static void setup() throws Exception {
        runtime = new BrowserRuntimeManager(); runtime.acquire(System.nanoTime() + TimeUnit.MINUTES.toNanos(5), () -> false);
        identities = new Pkcs11IdentityManager(); guard = new AuthTrafficGuard(); runner = new BrowserFlowRunner(runtime, identities, guard, Clock.systemUTC(), resourceEvents::add);
    }
    /** Releases only suite-owned services; the verified immutable browser cache remains reusable. */
    public @AfterAll static void shutdown() throws Exception {
        try { if (controlledTargets != null) controlledTargets.close(); }
        finally { if (runtime != null) runtime.close(); if (identities != null) identities.close(); if (guard != null) guard.close(); }
    }
    /** @param j Current fixture definition. @param values Session snapshot. @return Production-runner outcome under a finite attempt deadline. */
    public static AuthenticationResult run(JourneyDefinition j, SecretStore.Values values) throws Exception {
        return runner.run(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, j.id(), 1), j, values, false,
                System.nanoTime() + TimeUnit.SECONDS.toNanos(25), () -> false);
    }
    /** @param type Retained step kind. @param selector Optional selector. @param value Optional ordinary input/state/pattern. @return Stable-ID immutable fixture step. */
    public static AuthStep.Definition step(AuthStep.Type type, String selector, String value) {
        return new AuthStep.Definition(UUID.randomUUID(), type, selector, type == AuthStep.Type.INPUT ? value : null,
                type == AuthStep.Type.WAIT_LOAD_STATE ? value : null, type == AuthStep.Type.WAIT_URL ? value : null,
                type == AuthStep.Type.WAIT_TIME ? Integer.parseInt(value) : null);
    }

    public @Test void sessionLossRecoveryUsesThreeSequentialFreshBrowsersAndReplaysEightActualRequestsOnce() throws Exception {
        long caseBegan=System.nanoTime();var processes=new ProductionLabAdapter.BrowserProcesses();Map<String,Object> observed;
        try {
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
            var clock = new CoordinatorFixtures.ManualRuntime(); clock.now = System.nanoTime(); clock.wall = java.time.Instant.now();
            // Advance only coordinator scheduling. Actual Chromium keeps its real monotonic deadline and cleanup.
            try (var coordinator = new AuthenticationCoordinator(registry, Config.Controls.defaults(), clock, (entry, recover, deadline, cancelled) -> {
                long remaining = deadline - clock.nanos(); long began = System.nanoTime();
                try (var values = SecretStore.Values.empty()) {
                    return observedRunner.run(entry.identity(), entry.definition(), values, recover, began + remaining, cancelled);
                } finally { clock.advance(java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - began)); }
            }, entry -> null); var recovery = new SessionRecovery(coordinator, clock::nanos)) {
                var entry = registry.snapshot().resolve(definition.alias()); var initialTicket = coordinator.acquire(List.of(entry)); clock.runWorker(); initialTicket.future().join();
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
                assertEquals(1, clock.workers.size()); clock.runWorker(); clock.advance(5000); clock.runWorker(); clock.advance(15_000); clock.runWorker();
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
                observed=new java.util.LinkedHashMap<>();observed.put("loginRequests",loginAttempts.get());observed.put("issuedCredentials",issuances.get());observed.put("protectedIngress",protectedIngress.get());observed.put("acceptedRequests",acceptedActions.get());
                observed.put("recoveryAttempts",coordinator.status(entry.identity()).attempts());observed.put("originals",observations.size());observed.put("replays",decisions.size());observed.put("acceptedUse",coordinator.status(entry.identity()).acceptedUse());
                observed.put("browsersOpened",opens);observed.put("browsersClosed",lifecycle.stream().filter(event->event.event()==BrowserFlowRunner.ResourceEvent.BROWSER_CLOSED).count());
                observed.put("contextsOpened",lifecycle.stream().filter(event->event.event()==BrowserFlowRunner.ResourceEvent.CONTEXT_OPEN).count());observed.put("contextsClosed",lifecycle.stream().filter(event->event.event()==BrowserFlowRunner.ResourceEvent.CONTEXT_CLOSED).count());
                observed.put("distinctResources",seen.size());
                observed.put("events",lifecycle.stream().map(event->Map.of("event",event.event().name(),"resource",event.resourceId(),"parent",event.parentId())).toList());
            }
        }
        }finally{processes.close();}
        processes.requireObserved(4);observed.put("drivers",processes.drivers());observed.put("processes",processes.processes());observed.put("alive",processes.alive());
        AuthLabSupport.component("RUN.recovery.network-third-succeeds",observed,Map.of("startupMs",0L,"caseMs",TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-caseBegan),"cleanupMs",0L));
    }

    public @Test void retainedStepsAndSecureInputProduceNormalizedToken() throws Exception {
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
    public @Test void namedJsonAndSeveralCookiesAreAcquiredTogether() throws Exception {
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
        var roles = List.of("B", "C1", "C2");
        try (var target = targets().prepare("BROW.basic.json");
             var prepared = ProductionLabAdapter.login(targets(), target, roles, "admin", "adminpass")) {
            ProductionLabAdapter.automaticAndTaggedProofs(targets(), target, prepared, "admin");
        }
    }

    public @org.junit.jupiter.api.TestFactory
    java.util.stream.Stream<org.junit.jupiter.api.DynamicTest> controlledJavaLoginAuthenticatesExpectedAccount() {
        return List.of("cookie-one", "cookie-two", "two-page", "csrf-cookie", "javascript", "interstitial", "invalid-credentials").stream().map(variant ->
                org.junit.jupiter.api.DynamicTest.dynamicTest("[case=BROW.basic." + variant + "]", () -> {
                    var roles = variant.equals("cookie-one") ? List.of("C1") : variant.equals("cookie-two") ? List.of("C1","C2") : List.of("B");
                    try (var target = targets().prepare("BROW.basic." + variant);
                         var prepared = ProductionLabAdapter.login(targets(), target, roles, "user2", variant.equals("invalid-credentials") ? "incorrect" : "pass2")) {
                        if (variant.equals("invalid-credentials")) {
                            var failure = assertThrows(AuthenticationFailure.class, () -> ProductionLabAdapter.run(targets(), target, prepared));
                            target.failure(failure, "AUTH_REJECTED");
                            assertTrue(target.snapshot().path("events").toString().contains("login-rejected-http-401"));
                            assertEquals(AuthenticationFailure.Cause.AUTH_REJECTED, failure.reason());
                            assertFalse(target.snapshot().path("events").toString().contains("login-completed"));
                        } else {
                            var result = ProductionLabAdapter.run(targets(), target, prepared);
                            target.prove(roles.stream().map(String::toLowerCase).collect(java.util.stream.Collectors.joining("_")), ProductionLabAdapter.credentials(result, roles), "user2");
                        }
                    }
                }));
    }

    public @org.junit.jupiter.api.TestFactory
    java.util.stream.Stream<org.junit.jupiter.api.DynamicTest> controlledRedirectsAuthenticateWithoutChangingMethodsOrLosingCookies() {
        return List.of("zero", "one", "multi", "cross-origin", "cookie-each-hop", "deep-link", "post-303", "post-307").stream().map(variant ->
                org.junit.jupiter.api.DynamicTest.dynamicTest("[case=BROW.redirect." + variant + "]", () -> {
                    try (var target = targets().prepare("BROW.redirect." + variant);
                         var prepared = ProductionLabAdapter.login(targets(), target, List.of("B"), "user2", "pass2")) {
                        var result = ProductionLabAdapter.run(targets(), target, prepared);
                        target.prove("b", ProductionLabAdapter.credentials(result, List.of("B")), "user2");
                        var hops = new ArrayList<String>(); target.snapshot().path("events").forEach(e -> { if (e.path("name").asText().startsWith("hop-")) hops.add(e.path("name").asText()); });
                        assertEquals(variant.equals("zero") ? 0 : variant.equals("one") || variant.startsWith("post-") ? 1 : 3, hops.size());
                        for (int i = 0; i < hops.size(); i++) assertEquals("hop-" + i + (variant.equals("post-307") ? "-POST" : "-GET"), hops.get(i));
                    }
                }));
    }

    public @org.junit.jupiter.api.TestFactory
    java.util.stream.Stream<org.junit.jupiter.api.DynamicTest> controlledCookieSelectionUsesTheCurrentApplicableCredential() {
        return List.of("idp-client-decoy", "early-cookie-rotated", "same-name-paths", "deleted-mid-flow", "ambiguous").stream().map(variant ->
                org.junit.jupiter.api.DynamicTest.dynamicTest("[case=BROW.cookie-selection." + variant + "]", () -> {
                    try (var target = targets().prepare("BROW.cookie-selection." + variant);
                         var prepared = ProductionLabAdapter.login(targets(), target, List.of("C1"), "user2", "pass2")) {
                        if (variant.equals("deleted-mid-flow") || variant.equals("ambiguous")) {
                            var failure = assertThrows(AuthenticationFailure.class, () -> ProductionLabAdapter.run(targets(), target, prepared));
                            target.failure(failure, "EXTRACTION");
                            assertEquals(AuthenticationFailure.Cause.EXTRACTION, failure.reason());
                            assertFalse(failure.problem().toLowerCase().contains("connection"));
                            if (variant.equals("ambiguous")) assertTrue(failure.problem().toLowerCase().contains("more than one cookie"));
                        } else {
                            var result = ProductionLabAdapter.run(targets(), target, prepared);
                            target.prove("c1", ProductionLabAdapter.credentials(result, List.of("C1")), "user2");
                            String control=variant.equals("idp-client-decoy")?"decoy-cookie-set":variant.equals("early-cookie-rotated")?"selected-cookie-rotated":"competing-path-cookie-set";
                            assertTrue(java.util.stream.StreamSupport.stream(target.snapshot().path("events").spliterator(),false).anyMatch(event->event.path("name").asText().equals(control)),"The competing or rotated cookie must actually be emitted before selection can qualify.");
                        }
                    }
                }));
    }
    public @org.junit.jupiter.api.TestFactory
    java.util.stream.Stream<org.junit.jupiter.api.DynamicTest> controlledResponseSurfacesProduceUsableCredentials() {
        return List.of("early-response", "late-response", "nested-json", "popup", "frame", "cors-fetch", "service-worker").stream().map(variant ->
                org.junit.jupiter.api.DynamicTest.dynamicTest("[case=BROW.surfaces." + variant + "]", () -> {
                    try (var target = targets().prepare("BROW.surfaces." + variant);
                         var prepared = ProductionLabAdapter.login(targets(), target, List.of("B"), "user2", "pass2")) {
                        var result = variant.equals("late-response") ? ProductionLabAdapter.runAtCheckpoint(targets(), target, prepared, "late-token", false)
                                : ProductionLabAdapter.run(targets(), target, prepared);
                        target.prove("b", ProductionLabAdapter.credentials(result, List.of("B")), "user2");
                        String kind = switch (variant) { case "early-response" -> "early"; case "late-response" -> "late"; case "nested-json" -> "nested"; case "cors-fetch" -> "cors"; case "service-worker" -> "worker"; default -> variant; };
                        assertTrue(java.util.stream.StreamSupport.stream(target.snapshot().path("events").spliterator(), false).anyMatch(event ->
                                event.path("name").asText().equals("token-emitted") && event.path("safeIds").toString().contains("\"value\":\"" + kind + "\"")));
                        // Close acknowledged in-flight target work before inspecting the final retained page observations.
                        target.close();
                        var state = target.snapshot(); assertFalse(state.path("truncated").asBoolean(), "Missing page observations cannot establish a pass.");
                        var required = switch (variant) {
                            case "early-response" -> List.of("page-early-ready");
                            case "late-response" -> List.of("page-late-ready", "late-token-requested");
                            case "nested-json" -> List.of("page-nested-ready");
                            case "popup" -> List.of("page-popup-parent-ready", "page-popup-parent-done");
                            case "frame" -> List.of("page-frame-parent-ready", "page-frame-parent-done");
                            case "cors-fetch" -> List.of("page-cors-ready", "page-cors-done", "cors-probe-requested", "page-cors-denied");
                            case "service-worker" -> List.of("page-worker-controlled", "page-worker-ready");
                            default -> throw new IllegalArgumentException();
                        };
                        var names = new java.util.HashSet<String>(); state.path("events").forEach(event -> names.add(event.path("name").asText()));
                        var missing = required.stream().filter(name -> !names.contains(name)).toList(); target.surfaceObservation(state, required, missing);
                        assertTrue(missing.isEmpty(), "The production browser ended without required application page observations: " + missing);
                        assertFalse(names.contains("page-cors-unexpected"), "The browser must deny JavaScript access to the unpermitted CORS response.");
                        assertTrue(names.stream().noneMatch(name -> name.endsWith("fixture-stage-failed")), "The application reported a JavaScript stage failure.");
                        if (variant.equals("early-response")) {
                            long tokenSequence = Long.MAX_VALUE, readySequence = -1;
                            for (var event : state.path("events")) {
                                if (event.path("name").asText().equals("token-emitted")) tokenSequence = Math.min(tokenSequence, event.path("sequence").asLong());
                                if (event.path("name").asText().equals("page-early-ready")) readySequence = event.path("sequence").asLong();
                            }
                            assertTrue(tokenSequence < readySequence, "Early response must precede the actual page-ready marker.");
                        }
                    }
                }));
    }

    public @org.junit.jupiter.api.TestFactory
    java.util.stream.Stream<org.junit.jupiter.api.DynamicTest> controlledRepeatedAttemptsDoNotReuseBrowserCookiesOrStorage() {
        return List.of("cookies", "local-storage", "session-storage", "service-worker").stream().map(kind ->
                org.junit.jupiter.api.DynamicTest.dynamicTest("[case=BROW.fresh." + kind + "]", () -> {
                    long started = System.nanoTime(), ready, checked; Map<String, Object> facts;
                    try (var target = targets().prepare("BROW.fresh." + kind);
                         var prepared = ProductionLabAdapter.login(targets(), target, List.of("B"), "user2", "pass2")) {
                        ready = System.nanoTime();
                        String definitionHash = ProductionLabAdapter.savedDefinitionHash(prepared);
                        assertEquals(target.url("fresh/" + kind + "/start"), prepared.definition.authenticationUrl());
                        target.freshPhase("PRIME");
                        var first = ProductionLabAdapter.run(targets(), target, prepared);
                        var firstProof = target.prove("b", ProductionLabAdapter.credentials(first, List.of("B")), "user2");
                        long primeSequence = freshEvent(target.snapshot(), kind, "PRIME", "present");
                        assertEquals(definitionHash, ProductionLabAdapter.savedDefinitionHash(prepared));
                        target.freshPhase("PROBE");
                        var second = ProductionLabAdapter.run(targets(), target, prepared);
                        var secondProof = target.prove("b", ProductionLabAdapter.credentials(second, List.of("B")), "user2");
                        assertEquals(first.identity(), second.identity(), "Both attempts must use the same saved identity/generation.");
                        assertEquals(definitionHash, ProductionLabAdapter.savedDefinitionHash(prepared));
                        assertNotEquals(firstProof.path("issuanceId").asText(), secondProof.path("issuanceId").asText(), "Each actual attempt must complete a new login.");
                        assertFalse(first.token().equals(second.token()), "The second proof must not reuse the first attempt's credential.");
                        target.close(); var state = target.snapshot(); long probeSequence = freshEvent(state, kind, "PROBE", "absent");
                        var logins = new ArrayList<Long>(); state.path("events").forEach(event -> { if (event.path("name").asText().equals("login-completed")) logins.add(event.path("sequence").asLong()); });
                        assertEquals(2, logins.size()); assertTrue(primeSequence < logins.getFirst());
                        assertTrue(logins.getFirst() < probeSequence && probeSequence < logins.getLast(), "The second attempt observes state before any second login/output issuance.");
                        var contexts = resourceEvents.stream().filter(event -> event.identity().journeyId().equals(prepared.definition.id()) && !event.bootstrap()
                                && event.event() == BrowserFlowRunner.ResourceEvent.CONTEXT_OPEN).toList();
                        assertEquals(2, contexts.size()); assertNotEquals(contexts.getFirst().resourceId(), contexts.getLast().resourceId());
                        for (var context : contexts) assertEquals(1, resourceEvents.stream().filter(event -> event.resourceId() == context.resourceId()
                                && event.event() == BrowserFlowRunner.ResourceEvent.CONTEXT_CLOSED).count());
                        int firstClose = java.util.stream.IntStream.range(0, resourceEvents.size()).filter(i -> resourceEvents.get(i).resourceId() == contexts.getFirst().resourceId()
                                && resourceEvents.get(i).event() == BrowserFlowRunner.ResourceEvent.CONTEXT_CLOSED).findFirst().orElseThrow();
                        assertTrue(firstClose < resourceEvents.indexOf(contexts.getLast()), "The first actual context must close before the second opens.");
                        target.freshObservation(definitionHash, firstProof, secondProof, primeSequence, probeSequence, logins.getLast(), state,
                                contexts.getFirst().resourceId(), contexts.getLast().resourceId());
                        var owned = ProductionLabAdapter.resources(target.id); assertEquals(2, owned.size());
                        assertEquals(contexts.getFirst().resourceId(), owned.getFirst().contextId()); assertEquals(contexts.getLast().resourceId(), owned.getLast().contextId());
                        var captured = new java.util.LinkedHashMap<String, Object>();
                        captured.put("sameDefinition", definitionHash.equals(ProductionLabAdapter.savedDefinitionHash(prepared)));
                        captured.put("firstAccount", firstProof.path("accountId").asText()); captured.put("secondAccount", secondProof.path("accountId").asText());
                        captured.put("differentIssuance", !firstProof.path("issuanceId").asText().equals(secondProof.path("issuanceId").asText()));
                        captured.put("differentToken", !first.token().equals(second.token()));
                        captured.put("primeSequence", primeSequence); captured.put("firstLoginSequence", logins.getFirst()); captured.put("probeSequence", probeSequence); captured.put("secondLoginSequence", logins.getLast());
                        captured.put("firstContext", owned.getFirst().contextId()); captured.put("secondContext", owned.getLast().contextId()); captured.put("firstClosedBeforeSecond", firstClose < resourceEvents.indexOf(contexts.getLast()));
                        captured.put("closedContexts", owned.stream().mapToInt(ProductionLabAdapter.AttemptResources::contextsClosed).sum());
                        captured.put("openedBrowsers", owned.stream().mapToInt(ProductionLabAdapter.AttemptResources::browsersOpened).sum()); captured.put("closedBrowsers", owned.stream().mapToInt(ProductionLabAdapter.AttemptResources::browsersClosed).sum());
                        captured.put("drivers", owned.stream().mapToInt(ProductionLabAdapter.AttemptResources::drivers).sum()); captured.put("processes", owned.stream().mapToInt(ProductionLabAdapter.AttemptResources::observedProcesses).sum());
                        captured.put("alive", owned.stream().mapToLong(ProductionLabAdapter.AttemptResources::alive).sum()); facts = Map.copyOf(captured); checked = System.nanoTime();
                    }
                    AuthLabSupport.component("BROW.fresh." + kind, facts, Map.of("startupMs", TimeUnit.NANOSECONDS.toMillis(ready - started),
                            "caseMs", TimeUnit.NANOSECONDS.toMillis(checked - ready), "cleanupMs", TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - checked)));
                }));
    }
    /** Requires the actual browser observation, including the positive prime control; fixture defaults cannot pass. */
    public static long freshEvent(com.fasterxml.jackson.databind.JsonNode state, String kind, String phase, String presence) {
        assertFalse(state.path("truncated").asBoolean()); var sequences = new ArrayList<Long>();
        state.path("events").forEach(event -> {
            if (!event.path("name").asText().equals(phase.equals("PRIME") ? "fresh-prime-observed" : "fresh-probe-observed")) return;
            var labels = new java.util.HashMap<String, String>(); event.path("safeIds").forEach(label -> labels.put(label.path("kind").asText(), label.path("value").asText()));
            assertEquals(Map.of("variant", kind, "phase", phase, "presence", presence), labels, "Actual stored/probed state must match the selected variant and phase.");
            sequences.add(event.path("sequence").asLong());
        });
        assertEquals(1, sequences.size(), "Require exactly one current browser state observation per attempt."); return sequences.getFirst();
    }
    public @org.junit.jupiter.api.TestFactory
    java.util.stream.Stream<org.junit.jupiter.api.DynamicTest> controlledRedirectFailuresPublishNoCredentialAndCloseTheirProcesses() {
        return List.of("missing-callback", "wrong-return", "missing-state", "loop", "unreachable-hop", "cancel-before-callback").stream().map(variant ->
                org.junit.jupiter.api.DynamicTest.dynamicTest("[case=BROW.redirect-failure." + variant + "]", () -> {
                    try (var target = targets().prepare("BROW.redirect-failure." + variant);
                         var prepared = ProductionLabAdapter.login(targets(), target, List.of("B"), "user2", "pass2")) {
                        var failure = assertThrows(AuthenticationFailure.class, () -> {
                            if (variant.equals("cancel-before-callback")) ProductionLabAdapter.runAtCheckpoint(targets(), target, prepared, "cancel-before-callback", true);
                            else ProductionLabAdapter.run(targets(), target, prepared);
                        });
                        String expected = variant.equals("unreachable-hop") ? "TRANSPORT" : variant.equals("cancel-before-callback") ? "CANCELLED" : "FINITE_NO_OUTPUT";
                        target.failure(failure, expected);
                        if (!expected.equals("FINITE_NO_OUTPUT")) assertEquals(expected, failure.reason().name());
                        var snapshot = target.snapshot(); assertFalse(snapshot.path("truncated").asBoolean());
                        assertTrue(java.util.stream.StreamSupport.stream(snapshot.path("events").spliterator(), false).anyMatch(event -> event.path("phase").asText().equals("HOP")));
                        assertFalse(snapshot.path("events").toString().contains("login-completed")); assertEquals(0, snapshot.path("counters").path("actions").asInt());
                    }
                }));
    }
    public @Test void earlyJsonAndCookieAttemptsStartWithFreshContextState() throws Exception {
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
            cookie = new JourneyDefinition(cookie.id(), cookie.displayName(), cookie.alias(), cookie.authenticationUrl(), false,
                    List.of(step(AuthStep.Type.CLICK, "#CANARY_SELECTOR", null), step(AuthStep.Type.WAIT_SELECTOR, "#CANARY_SELECTOR", null)), cookie.browser(), cookie.extraction(), cookie.injection(), cookie.cache(), null);
            var first = run(cookie, empty); var second = run(cookie, empty);
            assertEquals("fresh-2", first.token()); assertEquals("fresh-3", second.token()); assertEquals(0, oldCookies.get());
            assertEquals(2, first.skippedSteps()); assertEquals(2, second.skippedSteps());
        }
    }
    public @Test void responseBodyRegexJsonAndCookiesCompleteOneBrowserLogin() throws Exception {
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
    public @Test void productionCoordinatorPublishesOwnedBrowserResultWithOriginalAcquisitionClocks() throws Exception {
        var providers = java.util.Arrays.stream(java.security.Security.getProviders()).map(java.security.Provider::getName).toList();
        try (var origin = IntegrationFixtures.http(); var secrets = new SecretStore()) {
            origin.route("/login", e -> IntegrationFixtures.respond(e, 200, "text/html", "<script>fetch('/token')</script>"));
            origin.route("/token", e -> IntegrationFixtures.respond(e, 200, "application/json", "{\"access_token\":\"coordinator-token\"}")); origin.start();
            var registry = new JourneyRegistry(secrets); var journey = IntegrationFixtures.journey(origin, List.of()); CoordinatorFixtures.load(registry, List.of(journey));
            try (var coordinator = BrowserAuthentication.coordinator(registry, secrets, runner, identities, Config.Controls.defaults())) {
                var entry = registry.snapshot().resolve(journey.alias()); var ticket = coordinator.acquire(List.of(entry));
                var snapshot = ticket.future().get(25, TimeUnit.SECONDS).get(entry.identity());
                assertEquals("coordinator-token", snapshot.value()); assertSame(snapshot, coordinator.peek(entry.identity()));
                assertTrue(snapshot.lifetime().acquiredNanos() - System.nanoTime() <= 0); assertEquals(AuthenticationCoordinator.Phase.READY, coordinator.status(entry.identity()).phase());
                assertEquals(0, coordinator.capacity().waitingRequests());
            }
        }
        assertEquals(providers, java.util.Arrays.stream(java.security.Security.getProviders()).map(java.security.Provider::getName).toList(), "ordinary journeys must never initialize a native provider");
    }
    public @Test void relevantStatusesAndMalformedResponsesHaveDistinctDispositions() throws Exception {
        for (int status : List.of(503, 401, 200)) try (var origin = IntegrationFixtures.http(); var empty = SecretStore.Values.empty()) {
            origin.route("/login", e -> IntegrationFixtures.respond(e, 200, "text/html", "<script>fetch('/token')</script>"));
            origin.route("/token", e -> { e.getResponseHeaders().set("Retry-After", "7"); IntegrationFixtures.respond(e, status, "application/json", "{}"); }); origin.start();
            var ex = assertThrows(AuthenticationFailure.class, () -> run(IntegrationFixtures.journey(origin, List.of()), empty));
            assertEquals(status == 503 ? AuthenticationFailure.Cause.TEMPORARY_SERVICE : status == 401 ? AuthenticationFailure.Cause.AUTH_REJECTED : AuthenticationFailure.Cause.EXTRACTION, ex.reason());
            assertEquals(status == 503, ex.retryable()); if (status == 503) assertNotNull(ex.retryAfter());
        }
        actualStepFailuresKeepTheirOwnIdentityAndSafeMessage();
    }
    /** Actual Chromium failures complement the fast mapper/presentation cases without repeating the complete UI matrix. */
    private static void actualStepFailuresKeepTheirOwnIdentityAndSafeMessage() throws Exception {
        var variants = new ArrayList<String>();
        for (var type : AuthStep.Type.values()) if (type != AuthStep.Type.WAIT_TIME) variants.add("step-timeout-" + type.name());
        variants.addAll(List.of("step-timeout-hidden-WAIT_SELECTOR", "step-timeout-attached-WAIT_SELECTOR",
                "step-timeout-detached-WAIT_SELECTOR", "step-timeout-exact-WAIT_URL"));
        variants.addAll(List.of("step-ambiguous-CLICK", "step-missing-secret-SECURE_INPUT"));
        for (String variant : variants) {
            var release = new java.util.concurrent.CountDownLatch(1);
            try (var origin = IntegrationFixtures.http()) {
                origin.route("/login", e -> IntegrationFixtures.respond(e, 200, "text/html", "<input><input>"
                        + (variant.contains("-hidden-") || variant.contains("-detached-") ? "<input id=CANARY_SELECTOR>" : "")
                        + "<button id=begin-busy onclick=\"fetch('/busy')\">Begin</button>"));
                origin.route("/busy", e -> { try { release.await(5, TimeUnit.SECONDS); IntegrationFixtures.respond(e, 200, "text/plain", "ready"); }
                    catch (InterruptedException error) { Thread.currentThread().interrupt(); e.close(); } });
                origin.start(); var actions = new ArrayList<>(DiagnosticsTest.presentationSteps(variant));
                String waitMode = variant.contains("-hidden-") ? "hidden" : variant.contains("-attached-") ? "attached"
                        : variant.contains("-detached-") ? "detached" : variant.contains("-exact-") ? "exact" : null;
                if (waitMode != null) {
                    var action = actions.get(1);
                    actions.set(1, new AuthStep.Definition(action.id(), action.type(), action.selector(), action.value(), waitMode, action.urlPattern(), action.durationMs()));
                }
                if (actions.get(1).type() == AuthStep.Type.WAIT_LOAD_STATE) actions.set(0, step(AuthStep.Type.CLICK, "#begin-busy", null));
                if (variant.startsWith("step-ambiguous")) {
                    var original = actions.get(1); actions.set(1, new AuthStep.Definition(original.id(), original.type(), "input[data-private='CANARY_SELECTOR'], input", null, null, null, null));
                }
                var base = IntegrationFixtures.journey(origin, actions);
                var journey = IntegrationFixtures.configured(base, base.authenticationUrl(), new JourneyDefinition.Browser(true, null, 2000, 50), base.extraction(), null);
                try (var values = new SecretStore.Values(null, variant.startsWith("step-missing-secret") || actions.get(1).type() != AuthStep.Type.SECURE_INPUT ? Map.of() : Map.of(actions.get(1).id(), "CANARY_SECURE_SECRET".toCharArray()))) {
                    var failure = assertThrows(AuthenticationFailure.class, () -> run(journey, values));
                    assertEquals(variant.startsWith("step-missing-secret") ? AuthenticationFailure.Phase.SETUP : AuthenticationFailure.Phase.STEP, failure.phase(), () -> variant + ": " + failure.problem());
                    assertEquals(variant.startsWith("step-missing-secret") ? AuthenticationFailure.Cause.MISSING_SECRET : variant.startsWith("step-ambiguous") ? AuthenticationFailure.Cause.UNKNOWN : AuthenticationFailure.Cause.STEP_TIMEOUT, failure.reason());
                    assertNotNull(failure.step()); assertEquals(actions.get(1).id(), failure.step().id()); assertEquals(2, failure.step().number()); assertEquals(actions.get(1).type(), failure.step().type());
                    assertTrue(failure.problem().contains("Step 2")); assertTrue(failure.problem().contains(DiagnosticsTest.stepLabel(actions.get(1).type())));
                    for (String secret : List.of("CANARY_SELECTOR", "CANARY_PLAIN_SECRET", "CANARY_SECURE_SECRET", "CANARY_URL_SECRET", origin.url("/").toString())) assertFalse(failure.getMessage().contains(secret));
                    assertNull(failure.getCause(), "The safe failure must not retain the SDK's raw exception text.");
                    if (variant.equals("step-timeout-CLICK")) {
                        var presentation = new DiagnosticsTest(); presentation.temporary = Files.createTempDirectory(Path.of(System.getProperty("java.io.tmpdir")), "step-presentation-");
                        presentation.checkPresentation(variant, failure, journey);
                    }
                    var plan = AuthLabSupport.JSON.readTree(Files.readAllBytes(Path.of(System.getProperty("authlab.plan"))));
                    Files.writeString(Path.of(plan.path("reportDirectory").asText()).resolve("step-error-observations.jsonl"), AuthLabSupport.JSON.writeValueAsString(Map.of(
                            "variant", variant, "stepNumber", failure.step().number(), "stepType", failure.step().type().name(), "stepIdentityMatched", true,
                            "phase", failure.phase().name(), "cause", failure.reason().name(), "redacted", true, "presentationChecked", variant.equals("step-timeout-CLICK"))) + "\n",
                            java.nio.charset.StandardCharsets.UTF_8, java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
                } finally { release.countDown(); }
            }
        }
    }
    public @Test void unconfiguredSubresource503DoesNotBecomeAnAuthenticationRetry() throws Exception {
        long began=System.nanoTime();var processes=new ProductionLabAdapter.BrowserProcesses();int first=resourceEvents.size();var logins=new AtomicInteger();var assets=new AtomicInteger();AuthenticationFailure failure;
        try(var origin=IntegrationFixtures.http();var empty=SecretStore.Values.empty()) {
            origin.route("/login",e->{logins.incrementAndGet();IntegrationFixtures.respond(e,200,"text/html","<body><script>fetch('/unrelated').then(()=>{let done=document.createElement('div');done.id='asset-observed';done.textContent='Asset observed';document.body.append(done)})</script>");});
            origin.route("/unrelated",e->{assets.incrementAndGet();IntegrationFixtures.respond(e,503,"text/plain","temporary third-party asset");});origin.start();
            var initial=IntegrationFixtures.journey(origin,List.of(step(AuthStep.Type.WAIT_SELECTOR,"#asset-observed",null)));
            var journey=IntegrationFixtures.configured(initial,initial.authenticationUrl(),new JourneyDefinition.Browser(true,null,10_000,100),initial.extraction(),null);
            failure=assertThrows(AuthenticationFailure.class,()->run(journey,empty));assertEquals(AuthenticationFailure.Cause.EXTRACTION,failure.reason());assertFalse(failure.retryable());assertEquals(1,assets.get());assertEquals(1,logins.get());
        } finally {processes.close();}
        processes.requireObserved(1);var events=List.copyOf(resourceEvents.subList(first,resourceEvents.size()));
        boolean ordered=events.size()==4&&events.stream().map(BrowserFlowRunner.Lifecycle::event).toList().equals(List.of(BrowserFlowRunner.ResourceEvent.BROWSER_OPEN,BrowserFlowRunner.ResourceEvent.CONTEXT_OPEN,BrowserFlowRunner.ResourceEvent.CONTEXT_CLOSED,BrowserFlowRunner.ResourceEvent.BROWSER_CLOSED))
            &&events.get(0).resourceId()==events.get(3).resourceId()&&events.get(1).resourceId()==events.get(2).resourceId()&&events.get(0).resourceId()!=events.get(1).resourceId()&&events.get(1).parentId()==events.get(0).resourceId();assertTrue(ordered);
        var observed=new java.util.LinkedHashMap<String,Object>();observed.put("attempts",logins.get());observed.put("assetRequests",assets.get());observed.put("cause",failure.reason().name());observed.put("retryable",failure.retryable());observed.put("orderedCleanup",ordered);
        observed.put("resources",events.stream().map(BrowserFlowRunner.Lifecycle::resourceId).distinct().count());observed.put("drivers",processes.drivers());observed.put("processes",processes.processes());observed.put("alive",processes.alive());
        AuthLabSupport.component("CORE.retry.subresource-error",observed,Map.of("startupMs",0L,"caseMs",TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-began),"cleanupMs",0L));
    }
    public @Test void elapsedAttemptPreservesRelevantServiceAndAuthenticationErrors() throws Exception {
        for (int status : List.of(503, 401)) try (var origin = IntegrationFixtures.http(); var empty = SecretStore.Values.empty()) {
            origin.route("/login", e -> IntegrationFixtures.respond(e, 200, "text/html", "<script>fetch('/token')</script>"));
            origin.route("/token", e -> IntegrationFixtures.respond(e, status, "application/json", "{}")); origin.start();
            var j = IntegrationFixtures.journey(origin, List.of(step(AuthStep.Type.WAIT_SELECTOR, "#never-present", null)));
            j = IntegrationFixtures.configured(j, j.authenticationUrl(), new JourneyDefinition.Browser(true, null, 1000, 10_000), j.extraction(), null);
            JourneyDefinition journey = j;
            var ex = assertThrows(AuthenticationFailure.class, () -> runner.run(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, journey.id(), 1),
                    journey, empty, false, System.nanoTime() + TimeUnit.SECONDS.toNanos(4), () -> false));
            assertEquals(status == 503 ? AuthenticationFailure.Cause.TEMPORARY_SERVICE : AuthenticationFailure.Cause.AUTH_REJECTED, ex.reason());
            assertNull(ex.step(), "An observed server failure must not be relabelled as the later selector timeout.");
        }
    }
    public @org.junit.jupiter.api.TestFactory
    java.util.stream.Stream<org.junit.jupiter.api.DynamicTest> actualUserAgentMarkerCoversRedirectsPopupsFramesFetchWorkersAndWebsocketHandshake() {
        return java.util.stream.Stream.of(
                ProductionLabAdapter.processCase("TLS.proxy.http-proxy",1,BrowserJourneyIntegrationTest::ordinaryProxyCoversOwnedBrowserSurfaces),
                ProductionLabAdapter.processCase("TLS.proxy.direct",2,BrowserJourneyIntegrationTest::ordinaryDirectJourneyDoesNotReuseThePreviousProxy),
                ProductionLabAdapter.processCase("TLS.proxy.no-direct-fallback",1,BrowserJourneyIntegrationTest::unavailableOrdinaryProxyDoesNotFallBackToTheOrigin));
    }
    private static void ordinaryProxyCoversOwnedBrowserSurfaces() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http(); var proxy = new IntegrationFixtures.ForwardProxy(guard); var empty = SecretStore.Values.empty()) {
            var requiredPaths=Set.of("/redirect","/redirected","/frame-fetch","/popup-fetch","/cross","/dedicated-fetch","/sw-fetch","/ws");
            Set<String> reachedPaths=java.util.concurrent.ConcurrentHashMap.newKeySet();
            java.util.function.Consumer<String> reached=path->{if(requiredPaths.contains(path))reachedPaths.add(path);};
            cross.route("/cross", e -> { reached.accept("/cross");e.getResponseHeaders().set("Access-Control-Allow-Origin", "*"); IntegrationFixtures.respond(e, 200, "text/plain", "cross"); }); cross.start();
            origin.route("/login", e -> IntegrationFixtures.respond(e, 200, "text/html", """
                <body><script>
                (async()=>{
                const signal=name=>new Promise(resolve=>{const listener=e=>{if(e.data===name){window.removeEventListener('message',listener);resolve();}};window.addEventListener('message',listener);});
                await fetch('/redirect');await fetch('%s');
                const frameReady=signal('frame-ready'),frame=document.createElement('iframe');frame.src='/frame';document.body.append(frame);await frameReady;
                const popupReady=signal('popup-ready');window.open('/popup');await popupReady;
                const worker=new Worker('/worker.js');await new Promise(resolve=>worker.onmessage=()=>resolve());
                const swReady=new Promise(resolve=>navigator.serviceWorker.addEventListener('message',e=>{if(e.data==='sw-ready')resolve();}));
                const registration=await navigator.serviceWorker.register('/sw.js');await navigator.serviceWorker.ready;registration.active.postMessage('go');
                await swReady;await new Promise(resolve=>{const ws=new WebSocket('ws://'+location.host+'/ws');ws.onopen=()=>{ws.close();resolve();};});
                await fetch('/token');
                })().catch(()=>fetch('/fixture-error'));</script>
                """.formatted(cross.url("/cross"))));
            origin.route("/redirect", e -> { reached.accept("/redirect");e.getResponseHeaders().set("Location", "/redirected"); e.sendResponseHeaders(302, -1); e.close(); });
            for (String path : List.of("/redirected", "/frame-fetch", "/popup-fetch", "/dedicated-fetch", "/sw-fetch")) origin.route(path, e -> {reached.accept(path);IntegrationFixtures.respond(e, 200, "text/plain", "ok");});
            origin.route("/frame", e -> IntegrationFixtures.respond(e, 200, "text/html", "<script>fetch('/frame-fetch').then(()=>parent.postMessage('frame-ready','*'))</script>"));
            origin.route("/popup", e -> IntegrationFixtures.respond(e, 200, "text/html", "<script>fetch('/popup-fetch').then(()=>opener.postMessage('popup-ready','*'))</script>"));
            origin.route("/worker.js", e -> IntegrationFixtures.respond(e, 200, "application/javascript", "fetch('/dedicated-fetch').then(()=>postMessage('worker-ready'))"));
            origin.route("/sw.js", e -> IntegrationFixtures.respond(e, 200, "application/javascript", "self.addEventListener('install',e=>self.skipWaiting());self.addEventListener('activate',e=>e.waitUntil(clients.claim()));self.addEventListener('message',e=>e.waitUntil(fetch('/sw-fetch').then(()=>e.source.postMessage('sw-ready'))));"));
            origin.route("/ws", e -> {
                reached.accept("/ws");
                // LittleProxy's CONNECT tunnel is opaque to its HTTP filter. Inspect the actual
                // upgrade request at this owned fixture boundary; real-Burp stripping remains P5.
                var decision = guard.classify(e.getRequestHeaders().getFirst("User-Agent"), AuthTrafficGuard.Family.GLOBAL, 9_000_000);
                proxy.seen.add(new IntegrationFixtures.Seen("/ws", decision.userAgent(), decision.classification()));
                try { String accept = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest((e.getRequestHeaders().getFirst("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").getBytes()));
                    e.getResponseHeaders().set("Upgrade", "websocket"); e.getResponseHeaders().set("Connection", "Upgrade"); e.getResponseHeaders().set("Sec-WebSocket-Accept", accept); e.sendResponseHeaders(101, -1); e.close();
                } catch (Exception ex) { e.close(); }
            });
            origin.route("/token", e -> {
                if(reachedPaths.containsAll(requiredPaths))IntegrationFixtures.respond(e,200,"application/json","{\"access_token\":\"marked-token\"}");
                else IntegrationFixtures.respond(e,500,"text/plain","owned browser surfaces incomplete");
            }); origin.start();
            JourneyDefinition j = IntegrationFixtures.journey(origin, List.of());
            j = IntegrationFixtures.configured(j, j.authenticationUrl(), new JourneyDefinition.Browser(true, new JourneyDefinition.Proxy(proxy.url()), 10_000, 5000), j.extraction(), null);
            try{assertTrue("marked-token".equals(run(j,empty).token()),"The configured proxy must return the expected output.");}
            catch(AuthenticationFailure failure){retainOrdinaryProxyFacts(proxy,false);var missing=new HashSet<>(requiredPaths);missing.removeAll(reachedPaths);if(!missing.isEmpty())throw new AssertionError("Owned browser fixture did not observe required paths: "+missing+"; observed proxy paths: "+proxy.seen.stream().map(IntegrationFixtures.Seen::path).distinct().toList(),failure);throw failure;}
            Set<String> paths = new HashSet<>(); proxy.seen.forEach(s -> paths.add(s.path()));
            assertTrue(paths.containsAll(requiredPaths), "Required ownership paths: " + paths);
            assertTrue(proxy.seen.stream().allMatch(s -> s.classification() == AuthTrafficGuard.Classification.OWNED));
            String base = proxy.seen.getFirst().agent(); assertTrue(base.startsWith("Mozilla/"));
            for (var seen : proxy.seen) assertEquals(base, seen.agent(), "Clean User-Agent on " + seen.path());
            assertFalse(base.contains("BPSHAuth/"));
            retainOrdinaryProxyFacts(proxy,true);
        }
    }
    private static void retainOrdinaryProxyFacts(IntegrationFixtures.ForwardProxy proxy,boolean outputReturned) throws Exception {
        var observed=List.copyOf(proxy.seen);String agent=observed.isEmpty()?"":observed.getFirst().agent();
        ProductionLabAdapter.retainProcessFacts("http-proxy",Map.of("proxyRequests",proxy.accepted.get(),"ownershipPathsObserved",observed.stream().map(IntegrationFixtures.Seen::path).distinct().count(),
                "allRequestsOwned",!observed.isEmpty()&&observed.stream().allMatch(seen->seen.classification()==AuthTrafficGuard.Classification.OWNED),
                "cleanAgentPreserved",agent!=null&&agent.startsWith("Mozilla/")&&!agent.contains("BPSHAuth/")&&observed.stream().allMatch(seen->java.util.Objects.equals(agent,seen.agent())),"expectedOutputReturned",outputReturned));
    }
    private static void ordinaryDirectJourneyDoesNotReuseThePreviousProxy() throws Exception {
        var requests=new AtomicInteger();var directHadMarker=new java.util.concurrent.atomic.AtomicBoolean();
        try(var origin=IntegrationFixtures.http();var proxy=new IntegrationFixtures.ForwardProxy(guard);var values=SecretStore.Values.empty()) {
            origin.route("/login",exchange->IntegrationFixtures.respond(exchange,200,"text/html","<script>fetch('/token')</script>"));
            origin.route("/token",exchange->{requests.incrementAndGet();if(requests.get()>1&&java.util.Objects.toString(exchange.getRequestHeaders().getFirst("User-Agent"),"").contains("BPSHAuth/"))directHadMarker.set(true);
                IntegrationFixtures.respond(exchange,200,"application/json","{\"access_token\":\"direct-route-proof\"}");});origin.start();
            var first=IntegrationFixtures.journey(origin,List.of());first=IntegrationFixtures.configured(first,first.authenticationUrl(),new JourneyDefinition.Browser(true,new JourneyDefinition.Proxy(proxy.url()),10000,3000),first.extraction(),null);
            assertTrue("direct-route-proof".equals(run(first,values).token()),"The proxy comparison must return the expected output.");long before=proxy.accepted.get();assertTrue(before>0);
            var direct=IntegrationFixtures.journey(origin,List.of());direct=IntegrationFixtures.configured(direct,direct.authenticationUrl(),new JourneyDefinition.Browser(true,null,10000,3000),direct.extraction(),null);
            assertTrue("direct-route-proof".equals(run(direct,values).token()),"The direct request must return the expected output.");assertEquals(2,requests.get());assertEquals(before,proxy.accepted.get());assertFalse(directHadMarker.get());
            ProductionLabAdapter.retainProcessFacts("direct-route",Map.of("primeProxyRequests",before,"directProxyRequests",proxy.accepted.get()-before,
                    "tokenRequests",requests.get(),"expectedOutputsReturned",2,"directHadMarker",directHadMarker.get()));
        }
    }
    private static void unavailableOrdinaryProxyDoesNotFallBackToTheOrigin() throws Exception {
        var reached=new AtomicInteger();
        try(var origin=IntegrationFixtures.http();var proxy=new IntegrationFixtures.ForwardProxy(null);var values=SecretStore.Values.empty()) {
            origin.route("/login",exchange->{reached.incrementAndGet();IntegrationFixtures.respond(exchange,200,"application/json","{\"access_token\":\"must-not-arrive\"}");});origin.start();
            var unavailable=proxy.url();proxy.close();var initial=IntegrationFixtures.journey(origin,List.of());
            var journey=IntegrationFixtures.configured(initial,initial.authenticationUrl(),new JourneyDefinition.Browser(true,new JourneyDefinition.Proxy(unavailable),5000,500),initial.extraction(),null);
            var failure=assertThrows(AuthenticationFailure.class,()->run(journey,values));assertEquals(0,reached.get());
            // The lower mapper owner already establishes generic browser-proxy error disposition.
            ProductionLabAdapter.retainProcessFacts("ordinary-no-direct-fallback",Map.of("phase",failure.phase().name(),"cause",failure.reason().name(),
                    "retryable",failure.retryable(),"originRequests",reached.get(),"credentialReturned",false,"configuredProxyHadCredentials",false));
        }
    }
    public @Test void cancellationKillsOnlyTheOwnedDriverAndReturnsTypedCancellation() throws Exception {
        AtomicInteger requests = new AtomicInteger(); java.util.concurrent.atomic.AtomicBoolean cancel = new java.util.concurrent.atomic.AtomicBoolean();
        try (var origin = IntegrationFixtures.http(); var empty = SecretStore.Values.empty(); var timer = java.util.concurrent.Executors.newSingleThreadScheduledExecutor()) {
            origin.route("/login", e -> { requests.incrementAndGet(); cancel.set(true); IntegrationFixtures.respond(e, 200, "text/html", "never emits token"); }); origin.start();
            JourneyDefinition j = IntegrationFixtures.journey(origin, List.of(step(AuthStep.Type.WAIT_SELECTOR, "#never", null)));
            var ex = assertThrows(AuthenticationFailure.class, () -> runner.run(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, j.id(), 1), j, empty, false,
                    System.nanoTime() + TimeUnit.SECONDS.toNanos(20), cancel::get));
            assertEquals(AuthenticationFailure.Cause.CANCELLED, ex.reason()); assertEquals(1, requests.get());
        }
    }


    public @Test void coldAndUpgradeProbesUseNormalBudgets() throws Exception {
        IntegrationFixtures.verifyColdAndUpgrade();
    }

    public @Test void packagedClassloaderUsesExactResourcesWithoutSharedDriverCacheOrJvmMutation() throws Exception {
        Path jar = IntegrationFixtures.packagedJar();
        try (var loader = new URLClassLoader(new java.net.URL[]{jar.toUri().toURL(), Path.of("build/classes/java/test").toUri().toURL()}, ClassLoader.getPlatformClassLoader())) {
            loader.loadClass("bpsh.browser.BrowserJourneyIntegrationTest$PackagedProbe").getMethod("exercise").invoke(null);
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
