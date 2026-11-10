package bpsh.browser.mtls;
import bpsh.transport.tls.Pkcs11IdentityManager;

import bpsh.browser.proxy.ProxyCertificateFactory;
import bpsh.browser.proxy.BrowserProxyForwarder;

import lab.auth.LoginFlows;
import lab.auth.TransportFixtures;

import bpsh.browser.AuthTrafficGuard;
import bpsh.browser.BrowserFlowRunner;
import bpsh.authentication.credentials.TokenExtractor;
import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.JourneyKey;
import bpsh.browser.runtime.BrowserRuntimeManager;
import bpsh.browser.runtime.PlaywrightDriverAdapter;
import bpsh.journey.SecretStore;
import bpsh.support.IntegrationFixtures;
import bpsh.burp.ui.JourneyDialogs;
import bpsh.burp.ui.JourneyRegistryTest;
import bpsh.burp.ui.UiController;
import com.microsoft.playwright.BrowserType;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.security.Security;
import java.time.Clock;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import static org.junit.jupiter.api.Assertions.*;

/** Uses only an explicitly owned disposable SoftHSM store; physical middleware support is not claimed. */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class Pkcs11JourneyIntegrationTest {
    static com.fasterxml.jackson.databind.JsonNode fixture;
    static Path root;
    static Pkcs11IdentityManager identities;
    static BrowserRuntimeManager runtime;
    static AuthTrafficGuard guard;
    static BrowserFlowRunner runner;
    static bpsh.transport.httpauth.HttpTransportRuntime httpTransport;
    static SSLContext defaultContext;
    static List<String> providers;

    /** Requires real module/tools/fixture prerequisites; a missing fixture fails this explicit suite. */
    @BeforeAll static void setup() throws Exception {
        fixture = IntegrationFixtures.nativeFixture(); root = Path.of(fixture.path("root").textValue());
        providers = Arrays.stream(Security.getProviders()).map(p -> p.getName()).toList(); defaultContext = SSLContext.getDefault();
        identities = new Pkcs11IdentityManager(); httpTransport = new bpsh.transport.httpauth.HttpTransportRuntime(identities); runtime = new BrowserRuntimeManager(); guard = new AuthTrafficGuard();
        runtime.acquire(System.nanoTime() + TimeUnit.MINUTES.toNanos(5), () -> false); runner = new BrowserFlowRunner(runtime, httpTransport, guard, Clock.systemUTC());
    }
    /** Removes only owned providers/listeners; shared token logout/default TLS changes are prohibited. */
    @AfterAll static void shutdown() throws Exception {
        if (httpTransport != null) httpTransport.close(); if (identities != null) identities.close(); if (runtime != null) runtime.close(); if (guard != null) guard.close();
        if (defaultContext != null) assertSame(defaultContext, SSLContext.getDefault());
        if (providers != null) assertEquals(providers, Arrays.stream(Security.getProviders()).map(p -> p.getName()).toList());
    }
    /** @param name Disposable account identity. @param origins Exact HTTPS client-certificate origins. @param ca Additional fixture CA path or null. @return Native mTLS selection. */
    static JourneyDefinition.Mtls mtls(String name, List<URI> origins, String ca) {
        return new JourneyDefinition.Mtls(fixture.path("module").textValue(), new JourneyDefinition.Slot(JourneyDefinition.SlotKind.INDEX, 0),
                fixture.path("fingerprints").path(name).textValue(), origins, ca);
    }
    /** @return Fresh caller-owned copy of the disposable fixture PIN, never a real/user PIN. */
    static char[] pin() { return fixture.path("pin").textValue().toCharArray(); }
    /** @return Finite native/browser setup deadline. */
    static long deadline() { return System.nanoTime() + TimeUnit.SECONDS.toNanos(45); }
    /** @param definition Exact configured identity. @return Pinned production-manager selection after successful shared login. */
    static Pkcs11IdentityManager.Selected select(JourneyDefinition.Mtls definition) throws Exception {
        char[] pin = pin(); try { return identities.select(definition, pin, false, deadline(), () -> false); } finally { Arrays.fill(pin, '\0'); }
    }

    @Test @Order(1) void explicitRejectedPinLatchIsSharedAndOnlyOperatorRecoveryClearsIt() throws Exception {
        var employee = mtls("employee", List.of(URI.create("https://localhost")), root.resolve("ca.crt").toString());
        char[] wrong = "not-the-disposable-pin".toCharArray(), correct = pin();
        try {
            assertEquals(AuthenticationFailure.Cause.PIN_REJECTED, assertThrows(AuthenticationFailure.class,
                    () -> identities.listCertificates(employee, wrong, false, deadline(), () -> false)).reason());
            var admin = mtls("admin", employee.origins(), employee.trustedCaBundlePath());
            assertEquals(AuthenticationFailure.Cause.PIN_REJECTED, assertThrows(AuthenticationFailure.class,
                    () -> identities.select(admin, correct, false, deadline(), () -> false)).reason(), "another journey cannot resubmit automatically");
            var listed = identities.listCertificates(employee, correct, true, deadline(), () -> false);
            assertEquals(2, listed.size()); assertEquals(1, listed.stream().map(Pkcs11IdentityManager.CertificateInfo::subject).distinct().count());
            assertEquals(2, listed.stream().map(Pkcs11IdentityManager.CertificateInfo::sha256).distinct().count());
            for (String name : List.of("employee", "admin")) {
                var selected = select(mtls(name, employee.origins(), employee.trustedCaBundlePath()));
                String[] aliases = selected.keyManager().getClientAliases("RSA", null); assertNotNull(aliases); assertEquals(1, aliases.length);
                assertNull(selected.keyManager().getPrivateKey(aliases[0]).getEncoded(), "private key remains on SoftHSM");
            }
        } finally { Arrays.fill(wrong, '\0'); Arrays.fill(correct, '\0'); }
    }

    @Test @Order(2) void recordingReusesTheConfiguredCertificateAndPinAndClosesOnStopOrCancel() throws Exception {
        for (boolean cancel : new boolean[]{false, true}) try (var origin = IntegrationFixtures.https(root, false, true)) {
            String fingerprint = fixture.path("fingerprints").path("employee").asText();
            var observation = new TransportFixtures.CertificateObservation(fingerprint);
            origin.route("/login", observation::target).start();
            var base = IntegrationFixtures.journey(origin, List.of());
            var journey = IntegrationFixtures.configured(base, base.authenticationUrl(), base.browser(), base.extraction(),
                    mtls("employee", List.of(TokenExtractor.origin(origin.url("/"))), root.resolve("ca.crt").toString()));
            var lifecycle = new java.util.concurrent.CopyOnWriteArrayList<bpsh.browser.BrowserSessionLauncher.Lifecycle>();
            var launcher = new bpsh.browser.BrowserSessionLauncher(runtime, httpTransport, guard, Clock.systemUTC(), lifecycle::add);
            try (var recorder = new bpsh.browser.BrowserJourneyRecorder(launcher)) {
                var identity = new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, journey.id(), 1);
                var request = new bpsh.journey.JourneyRecording.Request(identity,
                        new bpsh.journey.JourneyRecording.Stamp(identity.key(), 1, java.util.UUID.randomUUID()), bpsh.journey.BrowserSetup.from(journey));
                var control = new java.util.concurrent.CompletableFuture<bpsh.journey.JourneyRecording.Control>();
                var finished = new java.util.concurrent.CompletableFuture<bpsh.journey.JourneyRecording.Event>();
                char[] supplied = pin(); var values = new SecretStore.Values(supplied, Map.of()); Arrays.fill(supplied, '\0');
                control.complete(recorder.start(request, values, event -> {
                    if (event.state() == bpsh.journey.JourneyRecording.State.RECORDING) {
                        if (cancel) control.join().cancel(); else control.join().stop();
                    }
                    if (event.state() == bpsh.journey.JourneyRecording.State.REVIEW || event.state() == bpsh.journey.JourneyRecording.State.CLOSED) finished.complete(event);
                }));
                var event = finished.get(45, TimeUnit.SECONDS);
                assertNull(event.problem()); assertEquals(cancel ? bpsh.journey.JourneyRecording.State.CLOSED : bpsh.journey.JourneyRecording.State.REVIEW, event.state());
                if (event.result() != null) try (var result = event.result()) { assertTrue(result.complete(), () -> result.problems().toString()); }
                assertEquals(List.of(fingerprint), observation.fingerprints(), "One real navigation uses the selected certificate; there is no preflight");
                assertThrows(IllegalStateException.class, values::pin);
                assertEquals(bpsh.browser.BrowserSessionLauncher.ResourceEvent.BROWSER_CLOSED, lifecycle.getLast().event());
            }
        }
    }

    @Test @Order(2) void twoConcurrentProductionJourneysKeepSameHostIdentityAcrossReuseAndReconnects() throws Exception {
        try (var application = new TransportFixtures.CertificateIssuer(Map.of(
                    fixture.path("fingerprints").path("employee").asText(), new TransportFixtures.CertificateIdentity("employee", "user"),
                    fixture.path("fingerprints").path("admin").asText(), new TransportFixtures.CertificateIdentity("admin", "admin")), 40);
             var issuer = IntegrationFixtures.https(root, false, true); var resource = IntegrationFixtures.http(); var workers = Executors.newFixedThreadPool(2)) {
            issuer.route("/", application::issuer).start();
            resource.route("/protected", exchange -> application.resource(exchange, false)).start();
            var tasks = List.of("employee", "admin").stream().map(role -> workers.submit(() -> {
                JourneyDefinition j = IntegrationFixtures.journey(issuer, List.of());
                var definition = mtls(role, List.of(TokenExtractor.origin(issuer.url("/"))), root.resolve("ca.crt").toString());
                j = IntegrationFixtures.configured(j, issuer.url("/login?identity=" + role), new JourneyDefinition.Browser(true, null, 15_000, 15_000), j.extraction(), definition);
                char[] pin = pin();
                try (var secrets = new SecretStore.Values(pin, Map.of())) {
                    return runner.run(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, j.id(), 1), j, secrets, false, deadline(), () -> false).token();
                } finally { Arrays.fill(pin, '\0'); }
            })).toList();
            for (int i = 0; i < tasks.size(); i++) {
                String token = tasks.get(i).get(50, TimeUnit.SECONDS), role = List.of("employee", "admin").get(i);
                var response = HttpClient.newHttpClient().send(HttpRequest.newBuilder(resource.url("/protected")).header("Authorization", "Bearer " + token).build(), HttpResponse.BodyHandlers.ofString());
                assertEquals(200, response.statusCode()); assertEquals(role, response.body());
            }
            var observation = application.metrics();
            assertTrue(observation.tlsRequests() >= 84, "both identities must reach repeated same-host requests");
            assertTrue(observation.allCertificatesMatched()); assertEquals(0, observation.proxyCredentialHeaders());
            assertEquals(Set.of("employee", "admin"), observation.certificateRoles());
            assertTrue(observation.sessionReusedAcrossReconnect(), "TLS session creation time must be reused across an upstream reconnect");
        }
    }

    @Test @Order(3) void explicitUpstreamUrlTunnelWorksWithoutLeakingAttemptCredentials() throws Exception {
        try (var origin = IntegrationFixtures.https(root, false, true); var upstream = new IntegrationFixtures.ForwardProxy(null)) {
            LoginFlows.tokenFetch(origin.owner, "chained-token", LoginFlows.TokenResponse.SUCCESS, exchange -> assertNull(exchange.getRequestHeaders().getFirst("Proxy-Authorization"))).start();
            var j = IntegrationFixtures.journey(origin, List.of()); j = IntegrationFixtures.configured(j, j.authenticationUrl(),
                    new JourneyDefinition.Browser(true, new JourneyDefinition.Proxy(upstream.url()), 10_000, 3000), j.extraction(),
                    mtls("employee", List.of(TokenExtractor.origin(origin.url("/"))), root.resolve("ca.crt").toString()));
            char[] pin = pin();
            try (var secrets = new SecretStore.Values(pin, Map.of())) {
                assertEquals("chained-token", runner.run(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, j.id(), 1), j, secrets, false, deadline(), () -> false).token());
                assertTrue(upstream.accepted.get() > 0);
            } finally { Arrays.fill(pin, '\0'); }
        }
    }

    @Test @Order(4) void wrongChainWrongHostnameAndUnlistedCertificateOriginFailClosed() throws Exception {
        for (int mode = 0; mode < 3; mode++) try (var origin = IntegrationFixtures.https(root, mode == 1, true)) {
            AtomicInteger reached = new AtomicInteger(); TransportFixtures.countingTarget(origin.owner, reached::incrementAndGet).start();
            var j = IntegrationFixtures.journey(origin, List.of()); var definition = mtls("employee", List.of(mode == 2 ? URI.create("https://localhost:1") : TokenExtractor.origin(origin.url("/"))), mode == 0 ? null : root.resolve("ca.crt").toString());
            j = IntegrationFixtures.configured(j, j.authenticationUrl(), new JourneyDefinition.Browser(true, null, 5000, 500), j.extraction(), definition);
            char[] pin = pin(); JourneyDefinition finalJourney = j;
            try (var secrets = new SecretStore.Values(pin, Map.of())) {
                var ex = assertThrows(AuthenticationFailure.class, () -> runner.run(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, finalJourney.id(), 1), finalJourney, secrets, false, deadline(), () -> false));
                assertFalse(ex.retryable()); assertNotEquals(AuthenticationFailure.Cause.PIN_REJECTED, ex.reason()); assertEquals(0, reached.get());
            } finally { Arrays.fill(pin, '\0'); }
        }
    }

    @Test @Order(4) void unavailableUnauthenticatedUpstreamNeverFallsBackToDirectOrigin() throws Exception {
        try (var origin = IntegrationFixtures.https(root, false, true);
                var upstream = new IntegrationFixtures.ForwardProxy(null)) {
            AtomicInteger reached = new AtomicInteger();
            TransportFixtures.countingTarget(origin.owner, reached::incrementAndGet).start();
            URI proxyUrl = upstream.url(); upstream.close();
            var j = IntegrationFixtures.journey(origin, List.of());
            j = IntegrationFixtures.configured(j, j.authenticationUrl(), new JourneyDefinition.Browser(true,
                    new JourneyDefinition.Proxy(proxyUrl), 5000, 500), j.extraction(),
                    mtls("employee", List.of(TokenExtractor.origin(origin.url("/"))), root.resolve("ca.crt").toString()));
            JourneyDefinition journey = j; char[] pin = pin();
            try (var secrets = new SecretStore.Values(pin, Map.of())) {
                var error = assertThrows(AuthenticationFailure.class, () -> runner.run(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, journey.id(), 1),
                        journey, secrets, false, System.nanoTime() + TimeUnit.SECONDS.toNanos(12), () -> false));
                assertEquals(AuthenticationFailure.Phase.PROXY, error.phase());
                assertEquals(AuthenticationFailure.Cause.TRANSPORT, error.reason());
                assertTrue(error.retryable());
                assertEquals(0, reached.get(), "a failed configured chain must never silently connect directly");
            } finally { Arrays.fill(pin, '\0'); }
        }
    }

    @Test @Order(4) void localEndpointRejectsMissingAndIncorrectAttemptCredentials() throws Exception {
        var definition = mtls("employee", List.of(URI.create("https://localhost")), root.resolve("ca.crt").toString());
        try (var httpTransport = new bpsh.transport.httpauth.HttpTransportRuntime();
             var proxy = bpsh.support.IntegrationFixtures.browserProxy(httpTransport, definition, select(definition), null, Clock.systemUTC())) {
            for (String header : List.of("", "Proxy-Authorization: Basic ZGlzcG9zYWJsZTppbmNvcnJlY3Q=\r\n")) {
                try (var socket = new java.net.Socket()) {
                    socket.connect(proxy.address(), 2000); socket.setSoTimeout(3000);
                    socket.getOutputStream().write(("CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n" + header + "\r\n").getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                    String status = new java.io.BufferedReader(new java.io.InputStreamReader(socket.getInputStream(), java.nio.charset.StandardCharsets.US_ASCII)).readLine();
                    assertNotNull(status); assertTrue(status.contains(" 407 "), "local credentials are required before opening upstream TLS");
                }
            }
        }
    }

    @Test @Order(5) void unlistedLocalProxySpkiIsRejectedByActualChromium() throws Exception {
        try (var origin = IntegrationFixtures.https(root, false, true); var foreign = new ProxyCertificateFactory(Clock.systemUTC())) {
            TransportFixtures.countingTarget(origin.owner, () -> {}).start();
            var definition = mtls("employee", List.of(TokenExtractor.origin(origin.url("/"))), root.resolve("ca.crt").toString());
            try (var httpTransport = new bpsh.transport.httpauth.HttpTransportRuntime();
             var proxy = bpsh.support.IntegrationFixtures.browserProxy(httpTransport, definition, select(definition), null, Clock.systemUTC());
                 var driver = PlaywrightDriverAdapter.open(runtime.acquire(deadline(), () -> false), deadline(), () -> false);
                 var browser = driver.playwright().chromium().launch(new BrowserType.LaunchOptions().setHeadless(true).setExecutablePath(runtime.acquire(deadline(), () -> false).browserExecutable())
                         .setProxy(proxy.browserProxy()).setArgs(List.of("--ignore-certificate-errors-spki-list=" + foreign.spkiSha256())));
                 var context = browser.newContext()) {
                var ex = assertThrows(com.microsoft.playwright.PlaywrightException.class, () -> context.newPage().navigate(origin.url("/login").toString()));
                var matcher = java.util.regex.Pattern.compile("ERR_[A-Z0-9_]+").matcher(ex.getMessage());
                String symbol = matcher.find() ? matcher.group() : "no browser symbol";
                assertTrue(ex.getMessage().contains("ERR_CERT_AUTHORITY_INVALID"), "Observed safe browser code: " + symbol + "; proxy: " + proxy.failure());
            }
        }
    }

    /** Tests local Swing/native integration with simulated modal decisions; this is separate from a manual Burp check. */
    @Test @Order(6) void certificatePickerListsDistinctSameSubjectIdentitiesAndHonorsSelectionAndCancel() throws Exception {
        var detected = identities.discoverTokens(fixture.path("module").textValue(), deadline(), () -> false);
        assertEquals(1, detected.size(), "The owned fixture exposes one initialized token; empty slots must be excluded.");
        assertFalse(detected.getFirst().label().isBlank());
        var h = new JourneyRegistryTest().new NativeUi(); h.root = java.nio.file.Files.createTempDirectory(root, "ui-picker-");
        try (var editor = h.new Editor(null)) {
            Map<String, String> fingerprints;
            char[] listingPin = pin();
            try { fingerprints = identities.listCertificates(mtls("employee", List.of(URI.create("https://localhost")), null), listingPin, false, deadline(), () -> false)
                    .stream().collect(java.util.stream.Collectors.toMap(Pkcs11IdentityManager.CertificateInfo::serial, Pkcs11IdentityManager.CertificateInfo::sha256)); }
            finally { Arrays.fill(listingPin, '\0'); }
            var apiField = UiController.class.getDeclaredField("api"); apiField.setAccessible(true); apiField.set(editor.ui, uiHost(burp.api.montoya.MontoyaApi.class));
            var selections = new AtomicInteger(); var chosen = new java.util.concurrent.atomic.AtomicReference<String>(); var accept = new java.util.concurrent.atomic.AtomicBoolean(true);
            var dialogs = UiController.class.getDeclaredField("dialogs"); dialogs.setAccessible(true); dialogs.set(editor.ui, new JourneyDialogs() {
                /** No file chooser is needed: this integration uses the explicitly owned fixture module. */
                @Override public Path file(java.awt.Component parent, boolean save) { throw new AssertionError("Unexpected file chooser"); }
                /** Selects a distinct certificate by its public serial; its fingerprint remains internal. */
                @Override public boolean confirm(java.awt.Component parent, Object content, String title) {
                    assertTrue(javax.swing.SwingUtilities.isEventDispatchThread()); assertEquals("Choose the exact client certificate", title);
                    var panel = (javax.swing.JPanel) content;
                    var table = (javax.swing.JTable) ((javax.swing.JScrollPane) panel.getComponent(0)).getViewport().getView(); assertEquals(2, table.getRowCount());
                    assertEquals(6, table.getColumnCount()); assertEquals(table.getValueAt(0, 0), table.getValueAt(1, 0));
                    @SuppressWarnings("unchecked") var choices = (List<Pkcs11IdentityManager.CertificateInfo>) table.getClientProperty("certificateChoices");
                    assertNotEquals(choices.get(0).serial(), choices.get(1).serial());
                    table.setRowSelectionInterval(1, 1); chosen.set(fingerprints.get(choices.get(1).serial())); assertNotNull(chosen.get());
                    selections.incrementAndGet(); return accept.get();
                }
                /** Any unplanned dialog is a test failure. */
                @Override public void inform(java.awt.Component parent, String text) { fail(text); }
            });
            h.edt(() -> {
                h.call(editor.ui, "newJourney", new Class<?>[]{}); editor.checks().get("mtls").doClick(); editor.fields().get("url").setText("https://localhost/login");
                editor.fields().get("module").setText(fixture.path("module").textValue());
            });
            h.await(() -> { try { return h.member(editor.ui, "displayedDevice") != null; } catch (Exception error) { return false; } });
            h.edt(() -> {
                char[] code = pin(); try { ((javax.swing.JPasswordField) h.member(editor.ui, "pin")).setText(new String(code)); } finally { Arrays.fill(code, '\0'); }
                h.call(editor.ui, "listCertificates", new Class<?>[]{boolean.class}, false);
            });
            h.await(() -> selections.get() == 1); h.edt(() -> { assertEquals(chosen.get(), h.member(editor.ui, "selectedCertificateSha256")); assertTrue(((javax.swing.JTextArea) h.member(editor.ui, "certificateDetails")).getText().contains("Issued by:")); assertTrue(((javax.swing.JButton) h.member(editor.ui, "inspectCertificateButton")).isVisible()); });
            String savedSelection = chosen.get(); accept.set(false); h.edt(() -> h.call(editor.ui, "listCertificates", new Class<?>[]{boolean.class}, false));
            h.await(() -> selections.get() == 2); h.edt(() -> assertEquals(savedSelection, h.member(editor.ui, "selectedCertificateSha256")));
            h.edt(() -> {
                ((javax.swing.JPasswordField) h.member(editor.ui, "pin")).setText("");
                assertEquals(savedSelection, h.member(editor.ui, "selectedCertificateSha256"));
                assertFalse(((javax.swing.JButton) h.member(editor.ui, "inspectCertificateButton")).isVisible());
                var details = (javax.swing.JTextArea) h.member(editor.ui, "certificateDetails");
                assertEquals("", details.getText()); assertFalse(details.isVisible()); assertFalse(((javax.swing.JLabel) details.getClientProperty("rowLabel")).isVisible());
                char[] code = pin(); try { ((javax.swing.JPasswordField) h.member(editor.ui, "pin")).setText(new String(code)); } finally { Arrays.fill(code, '\0'); }
                assertFalse(((javax.swing.JButton) h.member(editor.ui, "inspectCertificateButton")).isVisible(), "A re-entered PIN must not restore loaded-certificate state");
                h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false);
            });
            h.await(() -> { try { return editor.saved(); } catch (Exception error) { return false; } });
            JourneyKey savedKey = h.member(editor.ui, "editing");
            h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, savedKey));
            h.await(() -> { try { return !(boolean) h.member(editor.ui, "editorLoading") && h.member(editor.ui, "displayedDevice") != null; } catch (Exception error) { return false; } });
            h.edt(() -> assertFalse(((javax.swing.JButton) h.member(editor.ui, "inspectCertificateButton")).isVisible(), "Reloading must not restore loaded-certificate state from the saved fingerprint"));
            h.edt(() -> { editor.fields().get("module").setText(root.resolve("missing-owned-fixture.dll").toString()); h.call(editor.ui, "discoverDevices", new Class<?>[]{boolean.class}, true); });
            h.await(() -> { try { return editor.status().contains("middleware file was not found"); } catch (Exception ex) { return false; } }); assertEquals(2, selections.get());
        }
    }

    /** @param type Host SDK interface. @return Interface-only local UI boundary with no actual host window. */
    private static Object uiHost(Class<?> type) { return java.lang.reflect.Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (proxy, method, args) -> method.getReturnType().isInterface() ? uiHost(method.getReturnType()) : null); }
}
