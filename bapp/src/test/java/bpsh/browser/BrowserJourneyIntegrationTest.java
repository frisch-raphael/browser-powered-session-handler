package bpsh.browser;

import lab.auth.LoginFlows;

import bpsh.request.RequestSettings;
import bpsh.journey.editing.JourneyWorkspace;
import bpsh.authentication.credentials.AuthenticationResult;
import bpsh.burp.http.NativeTagResolver;
import bpsh.burp.http.SessionRecovery;
import bpsh.journey.AuthStep;
import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.JourneyDefinition;
import bpsh.transport.tls.Pkcs11IdentityManager;
import bpsh.browser.runtime.BrowserRuntimeManager;
import bpsh.browser.runtime.PlaywrightDriverAdapter;
import bpsh.journey.SecretStore;
import bpsh.authentication.session.AuthenticationCoordinator;
import bpsh.authentication.session.CoordinatorFixtures;
import bpsh.support.IntegrationFixtures;
import com.microsoft.playwright.BrowserType;
import java.lang.reflect.Field;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
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
    static bpsh.transport.httpauth.HttpTransportRuntime httpTransport;

    /** Fails if pinned assets are missing; this explicit suite never skips browser prerequisites. */
    public @BeforeAll static void setup() throws Exception {
        runtime = new BrowserRuntimeManager(); runtime.acquire(System.nanoTime() + TimeUnit.MINUTES.toNanos(5), () -> false);
        identities = new Pkcs11IdentityManager(); httpTransport = new bpsh.transport.httpauth.HttpTransportRuntime(identities); guard = new AuthTrafficGuard(); runner = new BrowserFlowRunner(runtime, httpTransport, guard, Clock.systemUTC());
    }
    /** Releases only suite-owned services; the verified immutable browser cache remains reusable. */
    public @AfterAll static void shutdown() { if (runtime != null) runtime.close(); if (httpTransport != null) httpTransport.close(); if (identities != null) identities.close(); if (guard != null) guard.close(); }
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

    @org.junit.jupiter.api.io.TempDir Path httpPolicyTemporary;
    @org.junit.jupiter.params.ParameterizedTest(name="application-authorization-fresh-{0}")
    @org.junit.jupiter.params.provider.EnumSource(bpsh.journey.HttpAuthentication.Protocol.class)
    public void httpApplicationAuthorizationOnFreshConnection(bpsh.journey.HttpAuthentication.Protocol protocol) throws Exception {
        bpsh.support.HttpAuthenticationBrowserPolicies.authorization(new BrowserSessionLauncher(runtime,httpTransport,guard,Clock.systemUTC()),protocol,false);
    }
    @org.junit.jupiter.params.ParameterizedTest(name="application-authorization-reused-{0}")
    @org.junit.jupiter.params.provider.EnumSource(bpsh.journey.HttpAuthentication.Protocol.class)
    public void httpApplicationAuthorizationOnEstablishedConnection(bpsh.journey.HttpAuthentication.Protocol protocol) throws Exception {
        bpsh.support.HttpAuthenticationBrowserPolicies.authorization(new BrowserSessionLauncher(runtime,httpTransport,guard,Clock.systemUTC()),protocol,true);
    }
    @Test public void httpBrowserTrustConsentIsScoped() throws Exception {
        bpsh.support.HttpAuthenticationBrowserPolicies.trust(new BrowserSessionLauncher(runtime,httpTransport,guard,Clock.systemUTC()),httpTransport,httpPolicyTemporary);
    }

    private static AuthStep.Definition operation(AuthStep.Type type, String selector, AuthStep.Operation payload) {
        return new AuthStep.Definition(UUID.randomUUID(), type, selector, null, null, null, null, payload);
    }

    @org.junit.jupiter.params.ParameterizedTest(name="recording-{0}")
    @org.junit.jupiter.params.provider.EnumSource(bpsh.journey.HttpAuthentication.Protocol.class)
    public void httpAuthenticatedFormCanBeRecordedAndReplayed(bpsh.journey.HttpAuthentication.Protocol protocol) throws Exception {
        long began=System.nanoTime();
        var lab=IntegrationFixtures.httpAuthentication(protocol.name(),null);
        java.util.Map<String,Object> observed;
        try(lab;
            var values=new SecretStore.Values(null,Map.of(),"alpha-password".toCharArray())) {
            var base=new JourneyDefinition(UUID.randomUUID(),"Record HTTP form","record-http",lab.url("/login"),false,List.of(),
                    new JourneyDefinition.Browser(true,null,10000,5000),new JourneyDefinition.CookieExtraction(lab.url("/"),"app-session",null,"/"),
                    JourneyDefinition.Injection.perToken(List.of()),new JourneyDefinition.Cache(1800,10),null,
                    new bpsh.journey.HttpAuthentication(protocol,"user-a","LAB","",Set.of(lab.url("/"))),null);
            try(var recorder=new BrowserJourneyRecorder(new BrowserSessionLauncher(runtime,httpTransport,guard,Clock.systemUTC()),
                    BrowserSessionLauncher.Visibility.HEADLESS,(context,control)->{
                        var page=context.pages().getFirst();page.locator("#user").fill("user-a");page.locator("#submit").click();control.stop();
                    })) {
                var frozen=new java.util.concurrent.CompletableFuture<bpsh.journey.JourneyRecording.Result>();
                recorder.start(recordingRequest(base),values.copy(),recordingResult(frozen));
                try(var result=frozen.get(45,TimeUnit.SECONDS)) {
                    assertTrue(result.complete(),()->result.problems().toString());
                    var replay=new JourneyDefinition(base.id(),base.displayName(),base.alias(),base.authenticationUrl(),false,
                            result.candidates().stream().map(bpsh.journey.JourneyRecording.Candidate::step).toList(),base.browser(),base.extraction(),
                            base.injection(),base.cache(),null,base.httpAuthentication(),null);
                    var replayed=run(replay,values);
                    assertEquals("session-user-a",replayed.token());
                    observed=bpsh.support.HttpAuthenticationCapture.observed(lab);
                    observed.put("capturedExpectedAccount", "session-user-a".equals(replayed.token()));
                    observed.put("reportedProtocol",replayed.httpProtocol().name());
                    observed.put("candidateCount",result.candidates().size());
                    assertEquals(2,lab.applicationPosts.get());
                    assertEquals(0,lab.leakedDirectives.get());
                }
            }
        }
        bpsh.support.HttpAuthenticationCapture.record(protocol.name(),"recording",lab,observed,began);
    }

    @org.junit.jupiter.params.ParameterizedTest(name="protected-form-{0}")
    @org.junit.jupiter.params.provider.EnumSource(bpsh.journey.HttpAuthentication.Protocol.class)
    public void httpAuthenticationOpensProtectedFormAndCapturesApplicationCookie(bpsh.journey.HttpAuthentication.Protocol protocol) throws Exception {
        long began=System.nanoTime();
        var lab=IntegrationFixtures.httpAuthentication(protocol.name(),null);
        java.util.Map<String,Object> observed;
        try(lab;
            var values=new SecretStore.Values(null,Map.of(),"alpha-password".toCharArray())) {
            var id=UUID.randomUUID();
            var journey=new JourneyDefinition(id,"HTTP form","http-form",lab.url("/login"),false,
                    List.of(step(AuthStep.Type.INPUT,"#user","user-a"),step(AuthStep.Type.CLICK,"#submit",null)),
                    new JourneyDefinition.Browser(true,null,10000,5000),
                    new JourneyDefinition.CookieExtraction(lab.url("/"),"app-session",null,"/"),
                    JourneyDefinition.Injection.perToken(List.of()),new JourneyDefinition.Cache(1800,10),null,
                    new bpsh.journey.HttpAuthentication(protocol,"user-a","LAB","",Set.of(lab.url("/"))),null);
            var result=run(journey,values);
            assertEquals("session-user-a",result.token());
            assertEquals(protocol,result.httpProtocol());
            assertTrue(lab.observations.stream().anyMatch(o->o.path().equals("/login") && o.method().equals("POST") && o.user().equals("user-a")));
            assertEquals(0,lab.leakedDirectives.get());
            observed=bpsh.support.HttpAuthenticationCapture.observed(lab);
            observed.put("capturedExpectedAccount", "session-user-a".equals(result.token()));
            observed.put("reportedProtocol",result.httpProtocol().name());
            observed.put("httpObservationCount",result.httpObservations().size());
        }
        bpsh.support.HttpAuthenticationCapture.record(protocol.name(),"browser",lab,observed,began);
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(booleans = {false, true})
    public void tokenResponseLimitAlsoCoversServiceWorkerResponses(boolean large) throws Exception {
        try (var origin = IntegrationFixtures.http(); var values = SecretStore.Values.empty()) {
            origin.route("/login", e -> IntegrationFixtures.respond(e, 200, "text/html", "<script>navigator.serviceWorker.addEventListener('controllerchange',()=>fetch('/token'));navigator.serviceWorker.register('/sw.js')</script>"));
            String script = "self.addEventListener('install',()=>self.skipWaiting());self.addEventListener('activate',e=>e.waitUntil(clients.claim()));self.addEventListener('fetch',e=>{if(new URL(e.request.url).pathname==='/token')e.respondWith(new Response(JSON.stringify({access_token:'worker-token',padding:'x'.repeat(" + (large ? 1048576 : 10) + ")}),{headers:{'Content-Type':'application/json'}}))})";
            origin.route("/sw.js", e -> IntegrationFixtures.respond(e, 200, "application/javascript", script)); origin.start();
            var journey = IntegrationFixtures.journey(origin, List.of());
            if (large) {
                var error = assertThrows(AuthenticationFailure.class, () -> run(journey, values));
                assertTrue(error.getMessage().contains("extraction limit"), error.getMessage());
            } else assertEquals("worker-token", run(journey, values).token());
        }
    }

    public @Test void tokenCaptureStreamsOutOfProcessFrameResponses() throws Exception {
        try (var origin = IntegrationFixtures.http(); var values = SecretStore.Values.empty()) {
            origin.route("/login", e -> IntegrationFixtures.respond(e, 200, "text/html", "<iframe src='http://localhost:" + origin.url("/").getPort() + "/token'></iframe>"));
            origin.route("/token", e -> IntegrationFixtures.respond(e, 200, "application/json", "{\"access_token\":\"frame-token\"}")); origin.start();
            var base = IntegrationFixtures.journey(origin, List.of());
            var journey = IntegrationFixtures.configured(base, base.authenticationUrl(), base.browser(),
                    new JourneyDefinition.JsonExtraction(java.net.URI.create("http://localhost:" + origin.url("/").getPort()), "/token", "access_token"), null);
            assertEquals("frame-token", run(journey, values).token());
        }
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"small", "exact", "chunked-large", "gzip-small", "gzip-large"})
    public void tokenResponseStreamingEnforcesDecodedLimit(String kind) throws Exception {
        try (var origin = IntegrationFixtures.http(); var values = SecretStore.Values.empty()) {
            origin.route("/token", exchange -> {
                String json = "{\"access_token\":\"bounded-token\",\"padding\":\"";
                int size = kind.equals("exact") ? (1 << 20) : kind.endsWith("large") ? (1 << 20) + 1 : 200;
                byte[] body = (json + "x".repeat(size - json.length() - 2) + "\"}").getBytes(java.nio.charset.StandardCharsets.UTF_8);
                if (kind.startsWith("gzip")) {
                    var buffer = new java.io.ByteArrayOutputStream();
                    try (var gzip = new java.util.zip.GZIPOutputStream(buffer)) { gzip.write(body); }
                    body = buffer.toByteArray(); exchange.getResponseHeaders().set("Content-Encoding", "gzip");
                }
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, kind.equals("chunked-large") ? 0 : body.length);
                try (var output = exchange.getResponseBody()) { output.write(body); } catch (java.io.IOException ignored) { /* oversized responses are aborted */ }
            }).start();
            var journey = IntegrationFixtures.journey(origin.url("/token"), List.of());
            if (kind.endsWith("large")) {
                var error = assertThrows(AuthenticationFailure.class, () -> run(journey, values));
                assertTrue(error.getMessage().contains("extraction limit"), error.getMessage());
            } else assertEquals("bounded-token", run(journey, values).token());
        }
    }

    public @Test void explicitControlsNestedCrossOriginFramesAndPopupReplayProduceVerifiedOutput() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http(); var values = SecretStore.Values.empty()) {
            var observed = LoginFlows.journeyControls(origin.owner, cross.owner); cross.start(); origin.start();
            var open = step(AuthStep.Type.CLICK, "#open", null);
            var steps = List.of(
                    operation(AuthStep.Type.SET_CHECKED, "#check", new AuthStep.Checked(true)),
                    operation(AuthStep.Type.SET_CHECKED, "#check", new AuthStep.Checked(false)),
                    operation(AuthStep.Type.SET_CHECKED, "#radio", new AuthStep.Checked(true)),
                    operation(AuthStep.Type.SELECT_OPTIONS, "#single", new AuthStep.Options(List.of("admin"))),
                    operation(AuthStep.Type.SELECT_OPTIONS, "#multi", new AuthStep.Options(List.of())),
                    operation(AuthStep.Type.SELECT_OPTIONS, "#multi", new AuthStep.Options(List.of("", "blue,green"))),
                    operation(AuthStep.Type.PRESS_KEY, "#enter", new AuthStep.Key("Control+Enter")),
                    operation(AuthStep.Type.ENTER_FRAME, "#outer", new AuthStep.Context()),
                    operation(AuthStep.Type.ENTER_FRAME, "#inner", new AuthStep.Context()),
                    step(AuthStep.Type.INPUT, "#nested", "nested value"), step(AuthStep.Type.CLICK, "#framebutton", null),
                    new AuthStep.Definition(UUID.randomUUID(), AuthStep.Type.WAIT_URL, null, null, "exact", origin.url("/controls/inner?done").toString(), null),
                    step(AuthStep.Type.WAIT_SELECTOR, "#frame-done", null),
                    operation(AuthStep.Type.PARENT_FRAME, null, new AuthStep.Context()), step(AuthStep.Type.WAIT_SELECTOR, "#outer-marker", null),
                    operation(AuthStep.Type.MAIN_FRAME, null, new AuthStep.Context()),
                    operation(AuthStep.Type.EXPECT_POPUP, null, new AuthStep.Popup("popup-1", open.id())), open,
                    operation(AuthStep.Type.SWITCH_PAGE, null, new AuthStep.PageTarget("popup-1")),
                    step(AuthStep.Type.INPUT, "#popup-text", "popup value"), operation(AuthStep.Type.PRESS_KEY, "#popup-text", new AuthStep.Key("Enter")),
                    step(AuthStep.Type.WAIT_SELECTOR, "#submitted", null), operation(AuthStep.Type.CLOSE_PAGE, null, new AuthStep.Context()),
                    operation(AuthStep.Type.SWITCH_PAGE, null, new AuthStep.PageTarget("main")), step(AuthStep.Type.CLICK, "#finish", null));
            var result = run(IntegrationFixtures.journey(origin, steps), values);
            assertEquals("controls-token", result.token()); assertEquals("nested value", observed.nested.get());
            assertEquals("popup value", observed.popup.get()); assertEquals(1, observed.completed.get());
        }
    }

    public @Test void competingClosedAndMissingPopupsFailWithoutChoosingAnotherPage() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http(); var values = SecretStore.Values.empty()) {
            LoginFlows.journeyControls(origin.owner, cross.owner); cross.start(); origin.start();
            for (String scenario : List.of("double", "closed", "missing")) {
                var trigger = step(AuthStep.Type.CLICK, scenario.equals("missing") ? "#enter" : "#" + scenario, null);
                var steps = List.of(operation(AuthStep.Type.EXPECT_POPUP, null, new AuthStep.Popup("popup-1", trigger.id())), trigger,
                        step(AuthStep.Type.WAIT_TIME, null, scenario.equals("missing") ? "0" : "400"),
                        operation(AuthStep.Type.SWITCH_PAGE, null, new AuthStep.PageTarget("popup-1")));
                var base = IntegrationFixtures.journey(origin, steps);
                var journey = new JourneyDefinition(base.id(), base.displayName(), base.alias(), base.authenticationUrl(), false, steps,
                        new JourneyDefinition.Browser(true, null, 1000, 100), base.extraction(), base.injection(), base.cache(), null);
                var failure = assertThrows(AuthenticationFailure.class, () -> run(journey, values), scenario);
                assertEquals(scenario.equals("double") ? AuthenticationFailure.Cause.POPUP_AMBIGUOUS
                        : scenario.equals("closed") ? AuthenticationFailure.Cause.PAGE_CLOSED : AuthenticationFailure.Cause.POPUP_TIMEOUT, failure.reason(), scenario);
                assertFalse(failure.getMessage().contains(origin.url("/login").toString()));
            }
        }
    }

    public @Test void radioClearingAndMultipleValuesOnSingleSelectGiveActionableErrors() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http(); var values = SecretStore.Values.empty()) {
            LoginFlows.journeyControls(origin.owner, cross.owner); cross.start(); origin.start();
            for (var action : List.of(operation(AuthStep.Type.SET_CHECKED, "#radio", new AuthStep.Checked(false)),
                    operation(AuthStep.Type.SELECT_OPTIONS, "#single", new AuthStep.Options(List.of("guest", "admin"))))) {
                var failure = assertThrows(AuthenticationFailure.class, () -> run(IntegrationFixtures.journey(origin, List.of(action)), values));
                assertEquals(AuthenticationFailure.Cause.CONFIGURATION, failure.reason()); assertEquals(action.id(), failure.step().id());
                assertTrue(failure.getMessage().contains(action.type() == AuthStep.Type.SET_CHECKED ? "Radio buttons can only be selected" : "requires one option value"));
                assertFalse(failure.getMessage().contains(action.selector()));
            }
        }
    }

    public @Test void detachedFrameRequiresExplicitRecoveryAndWrongOpenerCannotSatisfyPopup() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http(); var values = SecretStore.Values.empty()) {
            LoginFlows.journeyControls(origin.owner, cross.owner); cross.start(); origin.start();
            var base = IntegrationFixtures.journey(origin, List.of());
            var identity = new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, base.id(), 1);
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(25);
            var launcher = new BrowserSessionLauncher(runtime, httpTransport, guard, Clock.systemUTC());
            try (var session = launcher.open(identity, bpsh.journey.BrowserSetup.from(base), values, BrowserSessionLauncher.Visibility.HEADLESS,
                    false, deadline, () -> false, ignored -> {})) {
                var context = session.context(); var main = context.newPage();
                try (var executor = new BrowserStepExecutor(context, main, List.of())) {
                    main.navigate(origin.url("/login").toString());
                    executor.execute(operation(AuthStep.Type.ENTER_FRAME, "#outer", new AuthStep.Context()), values, 2000, deadline, () -> false);
                    executor.execute(operation(AuthStep.Type.ENTER_FRAME, "#inner", new AuthStep.Context()), values, 2000, deadline, () -> false);
                    main.evaluate("document.querySelector('#outer').remove()");
                    var detached = assertThrows(AuthenticationFailure.class, () -> executor.execute(step(AuthStep.Type.INPUT, "#nested", "must not reach main"), values, 1000, deadline, () -> false));
                    assertEquals(AuthenticationFailure.Cause.FRAME_DETACHED, detached.reason());
                    executor.execute(operation(AuthStep.Type.MAIN_FRAME, null, new AuthStep.Context()), values, 1000, deadline, () -> false);
                    var trigger = step(AuthStep.Type.CLICK, "#enter", null);
                    executor.execute(operation(AuthStep.Type.EXPECT_POPUP, null, new AuthStep.Popup("popup-1", trigger.id())), values, 2000, deadline, () -> false);
                    executor.execute(trigger, values, 2000, deadline, () -> false);
                    var other = context.newPage(); other.navigate(origin.url("/login").toString()); other.locator("#open").click();
                    var wrong = assertThrows(AuthenticationFailure.class, () -> executor.execute(operation(AuthStep.Type.SWITCH_PAGE, null,
                            new AuthStep.PageTarget("popup-1")), values, 2000, deadline, () -> false));
                    assertEquals(AuthenticationFailure.Cause.POPUP_TIMEOUT, wrong.reason());
                    assertFalse(main.isClosed());
                }
            }
        }
    }

    /** Verifies opt-in trust behavior against an actual untrusted CA, including recording's initial navigation. */
    public @Test void untrustedHttpsPolicyCoversRecordingAndLoginDirectAndThroughProxy(@org.junit.jupiter.api.io.TempDir Path directory) throws Exception {
        var ca = lab.auth.LabTls.prepare(directory.resolve("ca"));
        var material = lab.auth.LabTls.createServer(ca, directory.resolve("server"));
        try (var origin = new IntegrationFixtures.Origin(lab.auth.ControlledApplication.Origin.https(material.serverContext(), "localhost"))) {
            origin.route("/login", exchange -> IntegrationFixtures.respond(exchange, 200, "text/html",
                    "<button id='continue'>Continue</button><script>fetch('/token')</script>"));
            origin.route("/token", exchange -> IntegrationFixtures.respond(exchange, 200, "application/json", "{\"access_token\":\"tls-policy-token\"}"));
            origin.start();
            for (boolean proxied : List.of(false, true)) try (var proxy = new IntegrationFixtures.ForwardProxy(guard)) {
                var base = IntegrationFixtures.journey(origin, List.of());
                var configuredProxy = proxied ? new JourneyDefinition.Proxy(proxy.url()) : null;
                var strict = IntegrationFixtures.configured(base, base.authenticationUrl(),
                        new JourneyDefinition.Browser(true, configuredProxy, 5000, 1000), base.extraction(), null);
                try (var values = SecretStore.Values.empty()) {
                    var error = assertThrows(AuthenticationFailure.class, () -> run(strict, values));
                    assertEquals(AuthenticationFailure.Cause.TRUST, error.reason());
                    assertTrue(error.getMessage().contains("ERR_CERT_AUTHORITY_INVALID"));
                }
                var closed = new java.util.concurrent.CompletableFuture<bpsh.journey.JourneyRecording.Event>();
                try (var recorder = new BrowserJourneyRecorder(new BrowserSessionLauncher(runtime, httpTransport, guard, Clock.systemUTC()),
                        BrowserSessionLauncher.Visibility.HEADLESS, (context, control) -> fail("An untrusted initial navigation must not enter recording."))) {
                    recorder.start(recordingRequest(strict), SecretStore.Values.empty(), event -> {
                        if (event.state() == bpsh.journey.JourneyRecording.State.CLOSED || event.state() == bpsh.journey.JourneyRecording.State.REVIEW) closed.complete(event);
                    });
                    var result = closed.get(20, TimeUnit.SECONDS);
                    assertEquals(bpsh.journey.JourneyRecording.State.CLOSED, result.state());
                    assertNotNull(result.problem()); assertTrue(result.problem().message().contains("ERR_CERT_AUTHORITY_INVALID"));
                }
                var permitted = IntegrationFixtures.configured(base, base.authenticationUrl(),
                        new JourneyDefinition.Browser(true, configuredProxy, 5000, 1000, true), base.extraction(), null);
                try (var values = SecretStore.Values.empty()) { assertEquals("tls-policy-token", run(permitted, values).token()); }
                var captured = new java.util.concurrent.CompletableFuture<bpsh.journey.JourneyRecording.Result>();
                try (var recorder = new BrowserJourneyRecorder(new BrowserSessionLauncher(runtime, httpTransport, guard, Clock.systemUTC()),
                        BrowserSessionLauncher.Visibility.HEADLESS, (context, control) -> { context.pages().getFirst().locator("#continue").click(); control.stop(); })) {
                    recorder.start(recordingRequest(permitted), SecretStore.Values.empty(), recordingResult(captured));
                    try (var result = captured.get(25, TimeUnit.SECONDS)) { assertTrue(result.complete(), () -> result.problems().toString()); }
                }
                // An opted-in context must not grant trust to subsequent strict journeys.
                try (var values = SecretStore.Values.empty()) { assertEquals(AuthenticationFailure.Cause.TRUST, assertThrows(AuthenticationFailure.class, () -> run(strict, values)).reason()); }
                if (proxied) assertTrue(proxy.accepted.get() > 0);
            }
        }
    }

    public @Test void pinnedPrivateRecorderReceivesStructuredUpdatesAndFlushesFinalValue() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http(); var values = SecretStore.Values.empty()) {
            LoginFlows.journeyControls(origin.owner, cross.owner); cross.start(); origin.start();
            var base = IntegrationFixtures.journey(origin, List.of()); long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(25);
            var launcher = new BrowserSessionLauncher(runtime, httpTransport, guard, Clock.systemUTC());
            try (var session = launcher.open(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, base.id(), 1), bpsh.journey.BrowserSetup.from(base),
                    values, BrowserSessionLauncher.Visibility.HEADLESS, false, deadline, () -> false, ignored -> {});
                 var adapter = session.driver().recorder(session.context())) {
                adapter.start(5000); var page = session.context().newPage(); page.navigate(origin.url("/login").toString());
                page.waitForCondition(() -> Boolean.TRUE.equals(page.evaluate("async () => typeof window.__pw_recorderState === 'function' && (await window.__pw_recorderState()).mode === 'recording'")),
                        new com.microsoft.playwright.Page.WaitForConditionOptions().setTimeout(5000));
                page.locator("#enter").fill("first value"); page.locator("#enter").fill("final value");
                page.locator("#check").check(); page.locator("#single").selectOption("admin");
                page.locator("#enter").fill("tail draft"); page.locator("#enter").fill("last without blur");
                adapter.stop(5000); assertNull(adapter.failure());
                var names = new java.util.ArrayList<String>(); boolean updated = false; String lastFill = null;
                bpsh.browser.runtime.PlaywrightRecorderAdapter.Event event;
                while ((event = adapter.poll()) != null) {
                    try {
                        names.add(event.action().name());
                        if (event.action().name().equals("fill")) {
                            char[] text = event.action().value(); try { lastFill = new String(text); } finally { java.util.Arrays.fill(text, '\0'); }
                        }
                        updated |= event.kind() == bpsh.browser.runtime.PlaywrightRecorderAdapter.Kind.UPDATED;
                    } finally { event.close(); }
                }
                assertTrue(names.containsAll(List.of("fill", "check", "select"))); assertTrue(updated); assertEquals("last without blur", lastFill);
                page.locator("#enter").fill("after stop"); page.waitForTimeout(100); assertNull(adapter.poll());
            }
        }
    }

    public @Test void maintainedMetadataTracksPasswordHistoryAndActualNestedFrameSources() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http(); var values = SecretStore.Values.empty()) {
            LoginFlows.recording(origin.owner, cross.owner); cross.start(); origin.start();
            var base = IntegrationFixtures.journey(origin.url("/recording"), List.of());
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(40);
            var launcher = new BrowserSessionLauncher(runtime, httpTransport, guard, Clock.systemUTC());
            try (var session = launcher.open(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, base.id(), 1), bpsh.journey.BrowserSetup.from(base),
                    values, BrowserSessionLauncher.Visibility.HEADLESS, false, deadline, () -> false, ignored -> {})) {
                var context = session.context(); var sources = new java.util.HashMap<String, com.microsoft.playwright.Frame>();
                bpsh.browser.runtime.PlaywrightRecorderAdapter.installMetadata(context, (source, args) -> {
                    assertSame(context, source.context()); assertEquals(1, args.length); sources.put((String) args[0], source.frame()); return null;
                });
                try (var adapter = session.driver().recorder(context)) {
                    adapter.start(5000); var page = context.newPage(); page.navigate(base.authenticationUrl().toString());
                    page.waitForCondition(() -> Boolean.TRUE.equals(page.evaluate("async () => typeof window.__pw_recorderState === 'function' && (await window.__pw_recorderState()).mode === 'recording'")),
                            new com.microsoft.playwright.Page.WaitForConditionOptions().setTimeout(5000));
                    page.locator("#username").fill("ordinary-first"); page.locator("#password").fill("secret-first");
                    page.locator("#show").click(); page.locator("#password").fill("secret-revealed");
                    page.locator("#replace-same").click(); page.locator("#password").fill("replacement-needs-logical-protection");
                    page.locator("#add-text").click(); page.locator("#later-text").fill("unknown-new-target");
                    page.locator("#username").fill("ordinary-existing");
                    page.locator("#reveal-before-fill").click(); page.locator("#reveal-first").fill("secret-before-first-fill");
                    page.locator("#add-shadow").click(); page.locator("#shadow-password").fill("secret-shadow");
                    page.locator("#shadow-text").fill("unknown-late-shadow");
                    var nested = page.frameLocator("#outer").frameLocator("#inner").locator("#nested");
                    nested.fill("nested-final-source");
                    for (var frame : List.copyOf(page.frames())) {
                        var status = bpsh.browser.runtime.PlaywrightRecorderAdapter.metadataStatus(frame, true);
                        assertTrue(status.available()); assertFalse(status.failed()); assertEquals(0, status.pending());
                    }
                    adapter.stop(5000); assertNull(adapter.failure());
                    var classifications = new java.util.HashMap<String, bpsh.browser.runtime.PlaywrightRecorderAdapter.Classification>();
                    boolean nestedSource = false;
                    bpsh.browser.runtime.PlaywrightRecorderAdapter.Event event;
                    while ((event = adapter.poll()) != null) {
                        try {
                            if (!event.action().name().equals("fill")) continue;
                            char[] text = event.action().value();
                            try {
                                String value = new String(text); classifications.put(value, event.action().metadata().classification());
                                var actual = sources.get(event.action().metadata().sourceKey()); assertNotNull(actual);
                                if (value.equals("nested-final-source")) {
                                    var target = BrowserTargets.resolve(event.action().selector(), actual);
                                    assertEquals(2, target.frames().size()); assertFalse(target.anyFrame()); nestedSource = true;
                                }
                            } finally { java.util.Arrays.fill(text, '\0'); }
                        } finally { event.close(); }
                    }
                    for (String value : List.of("secret-first", "secret-revealed", "secret-before-first-fill", "secret-shadow"))
                        assertEquals(bpsh.browser.runtime.PlaywrightRecorderAdapter.Classification.SECRET, classifications.get(value));
                    for (String value : List.of("ordinary-first", "ordinary-existing", "nested-final-source"))
                        assertEquals(bpsh.browser.runtime.PlaywrightRecorderAdapter.Classification.ORDINARY, classifications.get(value));
                    for (String value : List.of("replacement-needs-logical-protection", "unknown-new-target", "unknown-late-shadow"))
                        assertEquals(bpsh.browser.runtime.PlaywrightRecorderAdapter.Classification.UNKNOWN, classifications.get(value));
                    assertTrue(nestedSource);
                }
            }
        }
    }

    private static bpsh.journey.JourneyRecording.Request recordingRequest(JourneyDefinition base) {
        var identity = new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, base.id(), 1);
        return new bpsh.journey.JourneyRecording.Request(identity,
                new bpsh.journey.JourneyRecording.Stamp(identity.key(), 1, UUID.randomUUID()), bpsh.journey.BrowserSetup.from(base));
    }

    private static java.util.function.Consumer<bpsh.journey.JourneyRecording.Event> recordingResult(
            java.util.concurrent.CompletableFuture<bpsh.journey.JourneyRecording.Result> result) {
        return event -> {
            if (event.state() == bpsh.journey.JourneyRecording.State.REVIEW) result.complete(event.result());
            if (event.state() == bpsh.journey.JourneyRecording.State.CLOSED) result.completeExceptionally(new AssertionError(event.problem() == null ? "Recording closed without review" : event.problem().message()));
        };
    }

    public @Test void recordingWorkerProtectsReplacementTargetsAndStopsAfterTheFinalNestedFill() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http()) {
            LoginFlows.recording(origin.owner, cross.owner); cross.start(); origin.start();
            var base = IntegrationFixtures.journey(origin.url("/recording"), List.of());
            var lifecycle = new java.util.concurrent.CopyOnWriteArrayList<BrowserSessionLauncher.Lifecycle>();
            var launcher = new BrowserSessionLauncher(runtime, httpTransport, guard, Clock.systemUTC(), lifecycle::add);
            try (var recorder = new BrowserJourneyRecorder(launcher, BrowserSessionLauncher.Visibility.HEADLESS, (context, control) -> {
                var page = context.pages().getFirst();
                page.locator("#username").fill("record-user"); page.locator("#password").fill("first-secret");
                page.locator("#show").click(); page.locator("#password").fill("revealed-secret");
                page.locator("#replace-same").click(); page.locator("#password").fill("replacement-secret");
                page.frameLocator("#outer").frameLocator("#inner").locator("#nested").fill("last nested value"); control.stop();
            })) {
                var frozen = new java.util.concurrent.CompletableFuture<bpsh.journey.JourneyRecording.Result>(); var setup = SecretStore.Values.empty();
                recorder.start(recordingRequest(base), setup, recordingResult(frozen));
                try (var result = frozen.get(45, TimeUnit.SECONDS); var values = result.copySecrets()) {
                    assertTrue(result.complete(), () -> result.problems().toString()); assertThrows(IllegalStateException.class, setup::pin);
                    var secrets = result.candidates().stream().filter(c -> c.step().type() == AuthStep.Type.SECURE_INPUT).toList();
                    assertEquals(3, secrets.size()); assertTrue(secrets.stream().noneMatch(bpsh.journey.JourneyRecording.Candidate::passwordUnclassified));
                    assertEquals(3, values.stepIds().size()); var captured = new java.util.HashSet<String>();
                    for (var step : secrets) {
                        char[] value = values.stepValue(step.step().id()); try { captured.add(new String(value)); } finally { java.util.Arrays.fill(value, '\0'); }
                    }
                    assertEquals(Set.of("first-secret", "revealed-secret", "replacement-secret"), captured);
                    assertTrue(result.candidates().stream().anyMatch(c -> c.step().type() == AuthStep.Type.INPUT && "last nested value".equals(c.step().value())));
                    bpsh.journey.AuthStepSequence.validate(result.candidates().stream().map(bpsh.journey.JourneyRecording.Candidate::step).toList());
                    assertEquals(BrowserSessionLauncher.ResourceEvent.BROWSER_CLOSED, lifecycle.getLast().event());
                    var rejected = SecretStore.Values.empty();
                    assertThrows(IllegalStateException.class, () -> recorder.start(recordingRequest(base), rejected, ignored -> {}));
                    assertThrows(IllegalStateException.class, rejected::pin);
                }
            }
        }
    }

    public @Test void rapidSubmitRecordingReplaysWithTheRetainedPasswordInAFreshContext() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http()) {
            var observed = LoginFlows.recording(origin.owner, cross.owner); cross.start(); origin.start();
            var base = IntegrationFixtures.journey(origin.url("/recording"), List.of());
            try (var recorder = new BrowserJourneyRecorder(new BrowserSessionLauncher(runtime, httpTransport, guard, Clock.systemUTC()), BrowserSessionLauncher.Visibility.HEADLESS, (context, control) -> {
                var page = context.pages().getFirst(); page.locator("#username").fill("record-user"); page.locator("#password").fill("record-secret");
                page.locator("#submit").click(); control.stop();
            })) {
                var frozen = new java.util.concurrent.CompletableFuture<bpsh.journey.JourneyRecording.Result>();
                recorder.start(recordingRequest(base), SecretStore.Values.empty(), recordingResult(frozen));
                try (var result = frozen.get(45, TimeUnit.SECONDS); var values = result.copySecrets()) {
                    assertTrue(result.complete(), () -> result.problems().toString()); var steps = result.candidates().stream().map(bpsh.journey.JourneyRecording.Candidate::step).toList();
                    assertEquals(List.of(AuthStep.Type.INPUT, AuthStep.Type.SECURE_INPUT, AuthStep.Type.CLICK), steps.stream().map(AuthStep.Definition::type).toList());
                    var replay = new JourneyDefinition(base.id(), base.displayName(), base.alias(), base.authenticationUrl(), false, steps, base.browser(),
                            new JourneyDefinition.JsonExtraction(base.extraction() instanceof JourneyDefinition.JsonExtraction json ? json.responseOrigin() : origin.url("/"), "/recording-submit", "access_token"),
                            base.injection(), base.cache(), null);
                    observed.recordedSubmission.set(null); assertEquals("recording-token", run(replay, values).token());
                    String body = java.net.URLDecoder.decode(observed.recordedSubmission.get(), java.nio.charset.StandardCharsets.UTF_8);
                    assertTrue(body.contains("username=record-user")); assertTrue(body.contains("password=record-secret"));
                }
            }
        }
    }

    public @Test void tabFocusNavigationIsRecordedAndReplayedWithTheRetainedPasswordInAFreshContext() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http()) {
            var observed = LoginFlows.recording(origin.owner, cross.owner); cross.start(); origin.start();
            var base = IntegrationFixtures.journey(origin.url("/recording"), List.of());
            try (var recorder = new BrowserJourneyRecorder(new BrowserSessionLauncher(runtime, httpTransport, guard, Clock.systemUTC()), BrowserSessionLauncher.Visibility.HEADLESS, (context, control) -> {
                var page = context.pages().getFirst(); page.locator("#username").fill("tab-user");
                page.locator("#username").press("Tab"); assertEquals("password", page.evaluate("document.activeElement.id"));
                page.locator("#password").press("Shift+Tab"); assertEquals("username", page.evaluate("document.activeElement.id"));
                page.locator("#username").press("Tab"); page.locator("#password").fill("tab-secret");
                page.locator("#submit").click(); control.stop();
            })) {
                var frozen = new java.util.concurrent.CompletableFuture<bpsh.journey.JourneyRecording.Result>();
                recorder.start(recordingRequest(base), SecretStore.Values.empty(), recordingResult(frozen));
                try (var result = frozen.get(45, TimeUnit.SECONDS); var values = result.copySecrets()) {
                    assertTrue(result.complete(), () -> result.problems().toString());
                    var steps = result.candidates().stream().map(bpsh.journey.JourneyRecording.Candidate::step).toList();
                    assertEquals(List.of("Tab", "Shift+Tab", "Tab"), steps.stream().filter(s -> s.type() == AuthStep.Type.PRESS_KEY).map(s -> ((AuthStep.Key) s.operation()).key()).toList());
                    var replay = new JourneyDefinition(base.id(), base.displayName(), base.alias(), base.authenticationUrl(), false, steps, base.browser(),
                            new JourneyDefinition.JsonExtraction(bpsh.authentication.credentials.TokenExtractor.origin(base.authenticationUrl()), "/recording-submit", "access_token"), base.injection(), base.cache(), null);
                    observed.recordedSubmission.set(null); assertEquals("recording-token", run(replay, values).token());
                    String body = java.net.URLDecoder.decode(observed.recordedSubmission.get(), java.nio.charset.StandardCharsets.UTF_8);
                    assertTrue(body.contains("username=tab-user")); assertTrue(body.contains("password=tab-secret"));
                }
            }
        }
    }

    public @Test void unsupportedRecordedKeyNamesTheOmissionAndKeepsCapturedStepsForManualCompletion() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http()) {
            var observed = LoginFlows.recording(origin.owner, cross.owner); cross.start(); origin.start();
            var base = IntegrationFixtures.journey(origin.url("/recording"), List.of());
            try (var recorder = new BrowserJourneyRecorder(new BrowserSessionLauncher(runtime, httpTransport, guard, Clock.systemUTC()), BrowserSessionLauncher.Visibility.HEADLESS, (context, control) -> {
                var page = context.pages().getFirst(); page.locator("#username").fill("partial-user"); page.locator("#username").press("Escape");
                page.locator("#password").fill("partial-secret"); page.locator("#submit").click(); control.stop();
            })) {
                var frozen = new java.util.concurrent.CompletableFuture<bpsh.journey.JourneyRecording.Result>();
                recorder.start(recordingRequest(base), SecretStore.Values.empty(), recordingResult(frozen));
                try (var result = frozen.get(45, TimeUnit.SECONDS); var values = result.copySecrets()) {
                    assertFalse(result.complete()); String warnings = String.join("\n", result.problems());
                    assertTrue(warnings.contains("pressed Escape")); assertTrue(warnings.contains("was not added as a step"));
                    assertFalse(warnings.contains("partial-user")); assertFalse(warnings.contains("partial-secret"));
                    var steps = result.candidates().stream().map(bpsh.journey.JourneyRecording.Candidate::step).toList();
                    assertEquals(List.of(AuthStep.Type.INPUT, AuthStep.Type.SECURE_INPUT, AuthStep.Type.CLICK), steps.stream().map(AuthStep.Definition::type).toList());
                    var replay = new JourneyDefinition(base.id(), base.displayName(), base.alias(), base.authenticationUrl(), false, steps, base.browser(),
                            new JourneyDefinition.JsonExtraction(bpsh.authentication.credentials.TokenExtractor.origin(base.authenticationUrl()), "/recording-submit", "access_token"), base.injection(), base.cache(), null);
                    observed.recordedSubmission.set(null); assertEquals("recording-token", run(replay, values).token());
                    assertTrue(java.net.URLDecoder.decode(observed.recordedSubmission.get(), java.nio.charset.StandardCharsets.UTF_8).contains("password=partial-secret"));
                }
            }
        }
    }

    public @Test void recordedControlsFramesAndPopupReplayInAFreshContext() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http(); var proxy = new IntegrationFixtures.ForwardProxy(guard)) {
            var observed = LoginFlows.journeyControls(origin.owner, cross.owner); cross.start(); origin.start();
            var initial = IntegrationFixtures.journey(origin, List.of());
            var base = IntegrationFixtures.configured(initial, initial.authenticationUrl(), new JourneyDefinition.Browser(true,
                    new JourneyDefinition.Proxy(proxy.url()), 5000, 1000), initial.extraction(), null);
            try (var recorder = new BrowserJourneyRecorder(new BrowserSessionLauncher(runtime, httpTransport, guard, Clock.systemUTC()), BrowserSessionLauncher.Visibility.HEADLESS, (context, control) -> {
                var page = context.pages().getFirst();
                page.locator("#check").check(); page.locator("#check").uncheck(); page.locator("#radio").check();
                page.locator("#single").selectOption("admin"); page.locator("#multi").selectOption(new String[0]);
                page.locator("#multi").selectOption(new String[]{"", "blue,green"}); page.locator("#enter").press("Control+Enter");
                var nested = page.frameLocator("#outer").frameLocator("#inner");
                nested.locator("#nested").fill("nested value"); nested.locator("#framebutton").click(); nested.locator("#frame-done").waitFor();
                var popup = page.waitForPopup(() -> page.locator("#open").click());
                popup.waitForCondition(() -> Boolean.TRUE.equals(popup.evaluate("async () => typeof window.__pw_recorderState === 'function' && (await window.__pw_recorderState()).mode === 'recording'")));
                popup.locator("#popup-text").fill("popup value"); popup.locator("#popup-text").press("Enter"); popup.locator("#submitted").waitFor();
                popup.close(); page.locator("#finish").click();
                page.waitForCondition(() -> observed.completed.get() == 1); control.stop();
            })) {
                var frozen = new java.util.concurrent.CompletableFuture<bpsh.journey.JourneyRecording.Result>();
                recorder.start(recordingRequest(base), SecretStore.Values.empty(), recordingResult(frozen));
                try (var result = frozen.get(45, TimeUnit.SECONDS); var values = result.copySecrets()) {
                    assertTrue(result.complete(), () -> result.problems().toString()); assertEquals(1, result.popups().size());
                    var popup = result.popups().getFirst();
                    var opening = result.candidates().stream().filter(c -> popup.openingSteps().contains(c.step().id())
                            && c.step().type() == AuthStep.Type.CLICK && c.frames().isEmpty()).toList();
                    assertEquals(1, opening.size(), "The actual opener must remain eligible for explicit review");
                    var raw = result.candidates().stream().map(c -> bpsh.journey.JourneyDraft.StepInput.fromDefinition(c.step())).toList();
                    var corrected = bpsh.journey.editing.JourneyDraftCompiler.placePopup(raw, popup.declarationId(), popup.pageRef(), opening.getFirst().step().id());
                    var steps = bpsh.journey.editing.JourneyDraftCompiler.executableSteps(corrected);
                    assertEquals(List.of(List.of(), List.of("", "blue,green")), steps.stream().filter(s -> s.type() == AuthStep.Type.SELECT_OPTIONS
                            && ((AuthStep.Options) s.operation()).values().size() != 1).map(s -> ((AuthStep.Options) s.operation()).values()).toList());
                    assertTrue(steps.stream().anyMatch(s -> s.type() == AuthStep.Type.CLOSE_PAGE));
                    var replay = new JourneyDefinition(base.id(), base.displayName(), base.alias(), base.authenticationUrl(), false, steps,
                            base.browser(), base.extraction(), base.injection(), base.cache(), null);
                    assertEquals(1, observed.popupSubmissions.get(), "One Enter gesture submits exactly once during recording");
                    assertEquals("controls-token", run(replay, values).token()); assertEquals(2, observed.completed.get());
                    assertEquals(2, observed.popupSubmissions.get(), "Replay must not duplicate Enter's implicit submit click");
                    assertTrue(proxy.seen.stream().map(IntegrationFixtures.Seen::path).toList().containsAll(List.of("/login", "/controls/outer", "/controls/inner", "/controls/popup")));
                    assertTrue(proxy.seen.stream().allMatch(s -> s.classification() == AuthTrafficGuard.Classification.OWNED));
                    assertTrue(proxy.seen.stream().allMatch(s -> s.agent().startsWith("Mozilla/") && !s.agent().contains("BPSHAuth/")));
                }
            }
        }
    }

    public @Test void closingAPopupImmediatelyAfterTypingRetainsTheFinalValueAndCloseOrder() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http()) {
            LoginFlows.journeyControls(origin.owner, cross.owner); cross.start(); origin.start();
            var base = IntegrationFixtures.journey(origin, List.of());
            try (var recorder = new BrowserJourneyRecorder(new BrowserSessionLauncher(runtime, httpTransport, guard, Clock.systemUTC()), BrowserSessionLauncher.Visibility.HEADLESS, (context, control) -> {
                var page = context.pages().getFirst(); var popup = page.waitForPopup(() -> page.locator("#open").click());
                popup.waitForCondition(() -> Boolean.TRUE.equals(popup.evaluate("async () => typeof window.__pw_recorderState === 'function' && (await window.__pw_recorderState()).mode === 'recording'")));
                popup.locator("#popup-text").fill("last popup value"); popup.close(); control.stop();
            })) {
                var frozen = new java.util.concurrent.CompletableFuture<bpsh.journey.JourneyRecording.Result>();
                recorder.start(recordingRequest(base), SecretStore.Values.empty(), recordingResult(frozen));
                try (var result = frozen.get(45, TimeUnit.SECONDS); var values = result.copySecrets()) {
                    assertTrue(result.complete(), () -> result.problems().toString());
                    var steps = result.candidates().stream().map(bpsh.journey.JourneyRecording.Candidate::step).toList();
                    int fill = java.util.stream.IntStream.range(0, steps.size()).filter(i -> steps.get(i).type().requiresInputValue()).findFirst().orElseThrow();
                    var input = steps.get(fill); char[] captured = input.type() == AuthStep.Type.SECURE_INPUT ? values.stepValue(input.id()) : input.value().toCharArray();
                    try { assertArrayEquals("last popup value".toCharArray(), captured); } finally { java.util.Arrays.fill(captured, '\0'); }
                    assertEquals(AuthStep.Type.CLOSE_PAGE, steps.get(fill + 1).type()); assertEquals(1, result.popups().size());
                }
            }
        }
    }

    public @Test void recordingCancellationClosesItsWorkerWithoutPublishingAReview() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http()) {
            LoginFlows.recording(origin.owner, cross.owner); cross.start(); origin.start();
            var base = IntegrationFixtures.journey(origin.url("/recording"), List.of());
            var recorder = new BrowserJourneyRecorder(new BrowserSessionLauncher(runtime, httpTransport, guard, Clock.systemUTC()), BrowserSessionLauncher.Visibility.HEADLESS, (context, control) -> control.cancel());
            try (recorder) {
                var finished = new java.util.concurrent.CompletableFuture<bpsh.journey.JourneyRecording.Event>(); var setup = SecretStore.Values.empty();
                recorder.start(recordingRequest(base), setup, event -> {
                    if (event.state() == bpsh.journey.JourneyRecording.State.REVIEW || event.state() == bpsh.journey.JourneyRecording.State.CLOSED) finished.complete(event);
                });
                var event = finished.get(30, TimeUnit.SECONDS); assertEquals(bpsh.journey.JourneyRecording.State.CLOSED, event.state());
                assertNull(event.result()); assertNull(event.problem()); assertThrows(IllegalStateException.class, setup::pin);
            }
            assertTrue(recorder.awaitClosed(5000));
        }
    }

    public @Test void sessionLossRecoveryUsesThreeSequentialFreshBrowsersAndReplaysEightActualRequestsOnce() throws Exception {
        var lifecycle = new java.util.concurrent.CopyOnWriteArrayList<BrowserFlowRunner.Lifecycle>();
        try (var origin = IntegrationFixtures.http(); var secrets = new SecretStore()) {
            var fixture = LoginFlows.recovery(origin.owner);
            var loginAttempts = fixture.loginAttempts; var issuances = fixture.issuances; var protectedIngress = fixture.protectedIngress; var acceptedActions = fixture.acceptedActions;
            var acceptedToken = fixture.acceptedToken; origin.start(); var definition = IntegrationFixtures.journey(origin, List.of()); var registry = new JourneyWorkspace(secrets); CoordinatorFixtures.load(registry, List.of(definition));
            var observedRunner = new BrowserFlowRunner(runtime, httpTransport, guard, Clock.systemUTC(), lifecycle::add);
            try (var coordinator = BrowserAuthentication.coordinator(registry, secrets, observedRunner, identities, RequestSettings.Controls.defaults()); var recovery = new SessionRecovery(coordinator)) {
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

    public @Test void retainedStepsAndSecureInputProduceNormalizedToken() throws Exception {
        var secure = step(AuthStep.Type.SECURE_INPUT, "#password", null);
        try (var origin = IntegrationFixtures.http()) {
            var posted = LoginFlows.normalizedForm(origin.owner); origin.start();
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
            LoginFlows.combinedOutputs(origin.owner, true, false).start();
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
    public @Test void anonymousCookiesCannotSkipConfiguredLoginSteps() throws Exception {
        for (boolean combined : List.of(false, true)) try (var origin = IntegrationFixtures.http(); var values = SecretStore.Values.empty()) {
            LoginFlows.probeForm(origin.owner, "signed-in-token", "signed-in-session", "anonymous-session").start();
            var steps = List.of(step(AuthStep.Type.WAIT_SELECTOR, "#user", null),
                    step(AuthStep.Type.INPUT, "#user", "fixture-user"), step(AuthStep.Type.WAIT_SELECTOR, "#submit", null),
                    step(AuthStep.Type.CLICK, "#submit", null), step(AuthStep.Type.WAIT_URL, null, "**/token"));
            var base = IntegrationFixtures.journey(origin, steps);
            JourneyDefinition.Extraction extraction = new JourneyDefinition.CookieExtraction(origin.url("/"), "session", null, "/");
            if (combined) extraction = new JourneyDefinition.CombinedExtraction(List.of(
                    new JourneyDefinition.NamedExtraction("access", base.extraction()),
                    new JourneyDefinition.NamedExtraction("session", extraction)));
            var journey = IntegrationFixtures.configured(base, base.authenticationUrl(), base.browser(), extraction, null);
            var result = run(journey, values);
            assertEquals("signed-in-session", result.cookies().get("session"));
            assertEquals(combined ? "signed-in-token" : "signed-in-session", result.token());
            assertEquals(0, result.skippedSteps(), "Cookie capture must wait for every configured login action");
        }
    }

    public @Test void anonymousCookiesCannotHideAFailedRequiredLoginStep() throws Exception {
        try (var origin = IntegrationFixtures.http(); var values = SecretStore.Values.empty()) {
            LoginFlows.probeForm(origin.owner, "signed-in-token", "signed-in-session", "anonymous-session").start();
            var required = step(AuthStep.Type.WAIT_SELECTOR, "#missing-login-control", null);
            var base = IntegrationFixtures.journey(origin, List.of(required));
            var journey = IntegrationFixtures.configured(base, base.authenticationUrl(),
                    new JourneyDefinition.Browser(true, null, 2500, 100),
                    new JourneyDefinition.CookieExtraction(origin.url("/"), "session", null, "/"), null);
            var failure = assertThrows(AuthenticationFailure.class, () -> run(journey, values));
            assertEquals(AuthenticationFailure.Phase.STEP, failure.phase());
            assertNotNull(failure.step()); assertEquals(required.id(), failure.step().id());
        }
    }

    public @Test void anonymousCookiesCannotHideAMissingExpectedPopup() throws Exception {
        try (var origin = IntegrationFixtures.http(); var values = SecretStore.Values.empty()) {
            LoginFlows.probeForm(origin.owner, "signed-in-token", "signed-in-session", "anonymous-session").start();
            var trigger = step(AuthStep.Type.CLICK, "#submit", null);
            var steps = List.of(operation(AuthStep.Type.EXPECT_POPUP, null, new AuthStep.Popup("login-popup", trigger.id())), trigger);
            var base = IntegrationFixtures.journey(origin, steps);
            var journey = IntegrationFixtures.configured(base, base.authenticationUrl(),
                    new JourneyDefinition.Browser(true, null, 2500, 100),
                    new JourneyDefinition.CookieExtraction(origin.url("/"), "session", null, "/"), null);
            var failure = assertThrows(AuthenticationFailure.class, () -> run(journey, values));
            assertEquals(AuthenticationFailure.Cause.POPUP_TIMEOUT, failure.reason());
        }
    }

    public @Test void responseOnlyCaptureCanStillCompleteBeforeConfiguredSteps() throws Exception {
        try (var origin = IntegrationFixtures.http(); var values = SecretStore.Values.empty()) {
            LoginFlows.probeForm(origin.owner, "signed-in-token", null).start();
            var base = IntegrationFixtures.journey(origin, List.of(step(AuthStep.Type.CLICK, "#must-not-run", null)));
            var journey = IntegrationFixtures.configured(base, origin.url("/token"), base.browser(), base.extraction(), null);
            var result = run(journey, values);
            assertEquals("signed-in-token", result.token()); assertEquals(1, result.skippedSteps());
        }
    }

    public @Test void earlyJsonAndCookieAttemptsStartWithFreshContextState() throws Exception {
        try (var origin = IntegrationFixtures.http(); var empty = SecretStore.Values.empty()) {
            var observation = LoginFlows.freshCookie(origin.owner); origin.start();
            JourneyDefinition j = IntegrationFixtures.journey(origin, List.of()); assertEquals("early-token", run(j, empty).token());
            JourneyDefinition cookie = IntegrationFixtures.configured(j, j.authenticationUrl(), j.browser(), new JourneyDefinition.CookieExtraction(origin.url("/"), "session", null, "/"), null);
            assertEquals("fresh-2", run(cookie, empty).token()); assertEquals("fresh-3", run(cookie, empty).token()); assertEquals(0, observation.oldCookies());
        }
    }
    public @Test void responseBodyRegexJsonAndCookiesCompleteOneBrowserLogin() throws Exception {
        try (var origin = IntegrationFixtures.http(); var values = SecretStore.Values.empty()) {
            LoginFlows.combinedOutputs(origin.owner, false, true).start();
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
            LoginFlows.tokenFetch(origin.owner, "coordinator-token", LoginFlows.TokenResponse.SUCCESS).start();
            var registry = new JourneyWorkspace(secrets); var journey = IntegrationFixtures.journey(origin, List.of()); CoordinatorFixtures.load(registry, List.of(journey));
            try (var coordinator = BrowserAuthentication.coordinator(registry, secrets, runner, identities, RequestSettings.Controls.defaults())) {
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
            LoginFlows.tokenFetch(origin.owner, "unused", status == 503 ? LoginFlows.TokenResponse.TEMPORARY_SERVICE : status == 401 ? LoginFlows.TokenResponse.AUTH_REJECTED : LoginFlows.TokenResponse.MISSING_OUTPUT).start();
            var ex = assertThrows(AuthenticationFailure.class, () -> run(IntegrationFixtures.journey(origin, List.of()), empty));
            assertEquals(status == 503 ? AuthenticationFailure.Cause.TEMPORARY_SERVICE : status == 401 ? AuthenticationFailure.Cause.AUTH_REJECTED : AuthenticationFailure.Cause.EXTRACTION, ex.reason());
            assertEquals(status == 503, ex.retryable()); if (status == 503) assertNotNull(ex.retryAfter());
        }
    }
    public @Test void unconfiguredSubresource503DoesNotBecomeAnAuthenticationRetry() throws Exception {
        try (var origin = IntegrationFixtures.http(); var empty = SecretStore.Values.empty()) {
            LoginFlows.unrelatedFailure(origin.owner, () -> {}, () -> {}); origin.start();
            var ex = assertThrows(AuthenticationFailure.class, () -> run(IntegrationFixtures.journey(origin, List.of()), empty));
            assertEquals(AuthenticationFailure.Cause.EXTRACTION, ex.reason()); assertFalse(ex.retryable());
        }
    }
    public @Test void elapsedAttemptPreservesRelevantServiceAndAuthenticationErrors() throws Exception {
        for (int status : List.of(503, 401)) try (var origin = IntegrationFixtures.http(); var empty = SecretStore.Values.empty()) {
            LoginFlows.tokenFetch(origin.owner, "unused", status == 503 ? LoginFlows.TokenResponse.TEMPORARY_SERVICE : LoginFlows.TokenResponse.AUTH_REJECTED).start();
            var j = IntegrationFixtures.journey(origin, List.of(step(AuthStep.Type.WAIT_SELECTOR, "#never-present", null)));
            j = IntegrationFixtures.configured(j, j.authenticationUrl(), new JourneyDefinition.Browser(true, null, 1000, 10_000), j.extraction(), null);
            JourneyDefinition journey = j;
            var ex = assertThrows(AuthenticationFailure.class, () -> runner.run(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, journey.id(), 1),
                    journey, empty, false, System.nanoTime() + TimeUnit.SECONDS.toNanos(4), () -> false));
            assertEquals(status == 503 ? AuthenticationFailure.Cause.TEMPORARY_SERVICE : AuthenticationFailure.Cause.AUTH_REJECTED, ex.reason());
        }
    }
    public @Test void actualUserAgentMarkerCoversRedirectsPopupsFramesFetchWorkersAndWebsocketHandshake() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http(); var proxy = new IntegrationFixtures.ForwardProxy(guard); var empty = SecretStore.Values.empty()) {
            var surfaces = LoginFlows.ownedBrowserSurfaces(origin.owner, cross.owner, exchange -> {
                var decision = guard.classify(exchange.getRequestHeaders().getFirst("User-Agent"), AuthTrafficGuard.Family.GLOBAL, 9_000_000);
                proxy.seen.add(new IntegrationFixtures.Seen("/ws", decision.userAgent(), decision.classification()));
            });
            var requiredPaths = surfaces.requiredPaths(); var reachedPaths = surfaces.reachedPaths();
            cross.start(); origin.start();
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
    public @Test void cancellationKillsOnlyTheOwnedDriverAndReturnsTypedCancellation() throws Exception {
        AtomicInteger requests = new AtomicInteger(); java.util.concurrent.atomic.AtomicBoolean cancel = new java.util.concurrent.atomic.AtomicBoolean();
        try (var origin = IntegrationFixtures.http(); var empty = SecretStore.Values.empty(); var timer = java.util.concurrent.Executors.newSingleThreadScheduledExecutor()) {
            LoginFlows.noOutput(origin.owner, () -> { requests.incrementAndGet(); cancel.set(true); }).start();
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
        try (var origin = LoginFlows.probeForm(lab.auth.ControlledApplication.Origin.http("localhost"), "packaged-owned-token", "packaged-owned-cookie").start();
             var loader = new URLClassLoader(new java.net.URL[]{jar.toUri().toURL(), Path.of("build/classes/java/test").toUri().toURL()}, ClassLoader.getPlatformClassLoader())) {
            loader.loadClass("bpsh.browser.BrowserJourneyIntegrationTest$PackagedProbe").getMethod("exercise", String.class).invoke(null, origin.url("/login").toString());
            assertThrows(ClassNotFoundException.class, () -> loader.loadClass("lab.auth.ControlledApplication"));
        }
    }

    /** Runs only against the candidate JAR, this test probe and JDK platform modules. */
    public static class PackagedProbe {
        /** Verifies actual scoped resources, pinned versions, form/JSON/cookies and fresh contexts. */
        public static void exercise(String loginUrl) throws Exception {
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
                    var page = context.newPage(); page.navigate(loginUrl);
                    page.fill("#user", "fixture"); page.click("#submit");
                    if (!page.textContent("body").contains("packaged-owned-token")) throw new AssertionError("Packaged form/JSON flow failed.");
                    if (context.cookies().stream().noneMatch(cookie -> cookie.name.equals("session") && cookie.value.equals("packaged-owned-cookie")))
                        throw new AssertionError("Packaged cookie capture failed.");
                    try (var fresh = browser.newContext()) { if (!fresh.cookies().isEmpty()) throw new AssertionError("Browser contexts shared cookies."); }
                }
            }
            if (instance.get(null) != before || !properties.equals(new java.util.HashMap<>(System.getProperties()))) throw new AssertionError("Driver singleton or JVM properties changed.");
        }
    }
}
