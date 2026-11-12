package bpsh.browser.mtls;
import bpsh.transport.tls.Pkcs11IdentityManager;

import lab.auth.LoginFlows;
import lab.auth.TransportFixtures;

import bpsh.browser.AuthTrafficGuard;
import bpsh.browser.BrowserFlowRunner;
import bpsh.authentication.credentials.TokenExtractor;
import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.JourneyKey;
import bpsh.browser.runtime.BrowserRuntimeManager;
import bpsh.journey.SecretStore;
import bpsh.support.AuthLabSupport;
import bpsh.support.IntegrationFixtures;
import bpsh.support.ProductionLabAdapter;
import bpsh.burp.ui.JourneyDialogs;
import bpsh.burp.ui.JourneyRegistryTest;
import bpsh.burp.ui.UiController;
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
    private static ProductionLabAdapter.BrowserProcesses ownedProcesses;
    static SSLContext defaultContext;
    static List<String> providers;

    /** Requires real module/tools/fixture prerequisites; a missing fixture fails this explicit suite. */
    @BeforeAll static void setup() throws Exception {
        fixture = IntegrationFixtures.nativeFixture(); root = Path.of(fixture.path("root").textValue());
        providers = Arrays.stream(Security.getProviders()).map(p -> p.getName()).toList(); defaultContext = SSLContext.getDefault();
        identities = new Pkcs11IdentityManager(); httpTransport = new bpsh.transport.httpauth.HttpTransportRuntime(identities); runtime = new BrowserRuntimeManager(); guard = new AuthTrafficGuard();
        runtime.acquire(System.nanoTime() + TimeUnit.MINUTES.toNanos(5), () -> false); runner = new BrowserFlowRunner(runtime, bpsh.support.IntegrationFixtures.browserResolver(), httpTransport, guard, Clock.systemUTC());
    }
    private static boolean dynamicOwner(String method) {
        return Set.of("explicitUpstreamUrlTunnelWorksWithoutLeakingAttemptCredentials","wrongChainWrongHostnameAndUnlistedCertificateOriginFailClosed").contains(method);
    }
    @org.junit.jupiter.api.BeforeEach void observeOwnedProcesses(org.junit.jupiter.api.TestInfo test) {
        String method=test.getTestMethod().orElseThrow().getName();if(!dynamicOwner(method))ownedProcesses=ProductionLabAdapter.beginProcessObservation(method);
    }
    @org.junit.jupiter.api.AfterEach void retainOwnedProcessClosure(org.junit.jupiter.api.TestInfo test) throws Exception {
        String method=test.getTestMethod().orElseThrow().getName();if(dynamicOwner(method))return;
        int expected=method.equals("twoConcurrentProductionJourneysKeepSameHostIdentityAcrossReuseAndReconnects")?2:0;
        ProductionLabAdapter.finishProcessObservation(method,ownedProcesses,expected);
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
            }
            missingSelectedFingerprintFailsBeforeBrowserLaunch();
        } finally { Arrays.fill(wrong, '\0'); Arrays.fill(correct, '\0'); }
    }
    private static void missingSelectedFingerprintFailsBeforeBrowserLaunch() throws Exception {
        try(var origin=IntegrationFixtures.https(root,false,true)) {
            var reached=new AtomicInteger();TransportFixtures.countingTarget(origin.owner, reached::incrementAndGet).start();
            var selected=mtls("employee",List.of(TokenExtractor.origin(origin.url("/"))),root.resolve("ca.crt").toString());
            var absent=new JourneyDefinition.Mtls(selected.modulePath(),selected.slot(),"0".repeat(64),selected.origins(),selected.trustedCaBundlePath());
            var initial=IntegrationFixtures.journey(origin,List.of());var journey=IntegrationFixtures.configured(initial,initial.authenticationUrl(),initial.browser(),initial.extraction(),absent);
            char[] disposablePin=pin();
            try(var values=new SecretStore.Values(disposablePin,Map.of())) {
                var failure=assertThrows(AuthenticationFailure.class,()->runner.run(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT,journey.id(),1),journey,values,false,deadline(),()->false));
                assertEquals(AuthenticationFailure.Cause.CERTIFICATE,failure.reason());assertFalse(failure.retryable());assertEquals(0,reached.get());
                retainTransport("missing-fingerprint",Map.of("cause",failure.reason().name(),"retryable",failure.retryable(),"originRequests",reached.get()));
            }finally{Arrays.fill(disposablePin,'\0');}
        }
    }

    @Test @Order(2) void twoConcurrentProductionJourneysKeepSameHostIdentityAcrossReuseAndReconnects() throws Exception {
        try (var application=new lab.auth.TransportFixtures.CertificateIssuer(Map.of(
                    fixture.path("fingerprints").path("employee").asText(),new lab.auth.TransportFixtures.CertificateIdentity("employee","user"),
                    fixture.path("fingerprints").path("admin").asText(),new lab.auth.TransportFixtures.CertificateIdentity("admin","admin")),40);
             var issuer=IntegrationFixtures.https(root,false,true);var redirector=IntegrationFixtures.https(root,false,true);
             var resource=IntegrationFixtures.http();var workers=Executors.newFixedThreadPool(2)) {
            issuer.route("/",application::issuer).start();
            redirector.route("/login",exchange->application.redirect(exchange,issuer.url("/"))).start();
            resource.route("/protected",exchange->application.resource(exchange,true)).start();
            var tasks = List.of("employee", "admin").stream().map(role -> workers.submit(() -> {
                var definition = mtls(role, List.of(TokenExtractor.origin(redirector.url("/")),TokenExtractor.origin(issuer.url("/"))), root.resolve("ca.crt").toString());
                var j=ProductionLabAdapter.certificateDefinition(redirector.url("/login?identity="+role),TokenExtractor.origin(issuer.url("/")),definition,null,"fixture");
                char[] pin = pin();
                try (var secrets = new SecretStore.Values(pin, Map.of())) {
                    return runner.run(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, j.id(), 1), j, secrets, false, deadline(), () -> false).token();
                } finally { Arrays.fill(pin, '\0'); }
            })).toList();
            for (int i = 0; i < tasks.size(); i++) {
                String token = tasks.get(i).get(50, TimeUnit.SECONDS), role = List.of("employee", "admin").get(i);
                try(var http=HttpClient.newHttpClient()) {
                    var response = http.send(HttpRequest.newBuilder(resource.url("/protected")).header("Authorization", "Bearer " + token).build(), HttpResponse.BodyHandlers.ofString());
                    assertEquals(200, response.statusCode());var accepted=AuthLabSupport.JSON.readTree(response.body());
                    assertEquals(role,accepted.path("certificateIdentity").asText());assertEquals(i==0?"user":"admin",accepted.path("accountId").asText());
                }
            }
            var observed=application.metrics();
            assertTrue(observed.tlsRequests()>=84,"Both identities must reach repeated same-host requests.");assertTrue(observed.allCertificatesMatched());
            assertEquals(0,observed.proxyCredentialHeaders());assertEquals(Set.of("employee","admin"),observed.certificateRoles());
            assertTrue(observed.sessionReusedAcrossReconnect(),"TLS sessions must be reused across an upstream reconnect.");
            assertEquals(Set.of("employee","admin"),observed.redirectedRoles());assertEquals(Set.of("employee","admin"),observed.protectedRoles());
            retainTransport("selected-identities",Map.of("protectedAccountsVerified",observed.protectedRoles().size(),"allowedRedirectAccountsVerified",observed.redirectedRoles().size(),
                    "tlsRequestsObserved",observed.tlsRequests(),"allCertificatesMatched",observed.allCertificatesMatched(),"proxyCredentialsAtOrigin",observed.proxyCredentialHeaders(),
                    "tlsSessionReusedAcrossReconnect",observed.sessionReusedAcrossReconnect()));
        }
    }

    @org.junit.jupiter.api.TestFactory @Order(3)
    java.util.stream.Stream<org.junit.jupiter.api.DynamicTest> explicitUpstreamUrlTunnelWorksWithoutLeakingAttemptCredentials() {
        return java.util.stream.Stream.of(
                ProductionLabAdapter.processCase("TLS.proxy.connect",1,Pkcs11JourneyIntegrationTest::availableUnauthenticatedUpstream),
                ProductionLabAdapter.processCase("TLS.proxy.proxy-unavailable",1,Pkcs11JourneyIntegrationTest::unavailableUnauthenticatedUpstreamNeverFallsBackToDirectOrigin));
    }
    private static void availableUnauthenticatedUpstream() throws Exception {
        try (var origin = IntegrationFixtures.https(root, false, true); var upstream = new IntegrationFixtures.ForwardProxy(null)) {
            LoginFlows.tokenFetch(origin.owner, "chained-token", LoginFlows.TokenResponse.SUCCESS, exchange -> assertNull(exchange.getRequestHeaders().getFirst("Proxy-Authorization"))).start();
            var j = IntegrationFixtures.journey(origin, List.of()); j = IntegrationFixtures.configured(j, j.authenticationUrl(),
                    new JourneyDefinition.Browser(true, new JourneyDefinition.Proxy(upstream.url()), 10_000, 3000), j.extraction(),
                    mtls("employee", List.of(TokenExtractor.origin(origin.url("/"))), root.resolve("ca.crt").toString()));
            char[] pin = pin();
            try (var secrets = new SecretStore.Values(pin, Map.of())) {
                assertTrue("chained-token".equals(runner.run(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, j.id(), 1), j, secrets, false, deadline(), () -> false).token()),"The configured tunnel must return the expected output.");
                assertTrue(upstream.accepted.get() > 0);
                assertEquals(0,upstream.credentialHeaders(),"Internal mTLS attempt credentials must not reach the configured unauthenticated proxy.");
                retainTransport("available-upstream",Map.of("upstreamConnections",upstream.accepted.get(),"configuredProxyCredentialHeaders",upstream.credentialHeaders(),"expectedOutputReturned",true,"attemptCredentialsStrippedBeforeOrigin",true));
            } finally { Arrays.fill(pin, '\0'); }
        }
    }

    private static void unavailableUnauthenticatedUpstreamNeverFallsBackToDirectOrigin() throws Exception {
        try(var origin=IntegrationFixtures.https(root,false,true);var upstream=new IntegrationFixtures.ForwardProxy(null)) {
            var reached=new AtomicInteger();TransportFixtures.countingTarget(origin.owner, reached::incrementAndGet).start();
            URI unavailable=upstream.url();upstream.close();
            var initial=IntegrationFixtures.journey(origin,List.of());var journey=IntegrationFixtures.configured(initial,initial.authenticationUrl(),
                    new JourneyDefinition.Browser(true,new JourneyDefinition.Proxy(unavailable),5000,500),initial.extraction(),
                    mtls("employee",List.of(TokenExtractor.origin(origin.url("/"))),root.resolve("ca.crt").toString()));
            char[] disposablePin=pin();
            try(var secrets=new SecretStore.Values(disposablePin,Map.of())) {
                var failure=assertThrows(AuthenticationFailure.class,()->runner.run(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT,journey.id(),1),
                        journey,secrets,false,System.nanoTime()+TimeUnit.SECONDS.toNanos(12),()->false));
                retainTransport("unavailable-unauthenticated-route",Map.of("phase",failure.phase().name(),"cause",failure.reason().name(),
                        "retryable",failure.retryable(),"originRequests",reached.get(),"configuredProxyHadCredentials",false));
                assertEquals(0,reached.get(),"An unavailable configured route must not reach the origin directly.");
                assertEquals(AuthenticationFailure.Phase.PROXY,failure.phase());
                assertEquals(AuthenticationFailure.Cause.TRANSPORT,failure.reason(),"A closed unauthenticated proxy listener is a temporary connection failure.");
                assertTrue(failure.retryable(),"The existing coordinator retry policy must receive a retryable network failure.");
            }finally{Arrays.fill(disposablePin,'\0');}
        }
    }

    @org.junit.jupiter.api.TestFactory @Order(4)
    java.util.stream.Stream<org.junit.jupiter.api.DynamicTest> wrongChainWrongHostnameAndUnlistedCertificateOriginFailClosed() {
        return java.util.stream.Stream.of(
                ProductionLabAdapter.processCase("TLS.trust.untrusted-origin",1,()->upstreamTrustFailsBeforeOrigin(0)),
                ProductionLabAdapter.processCase("TLS.trust.wrong-host",1,()->upstreamTrustFailsBeforeOrigin(1)),
                ProductionLabAdapter.processCase("TLS.mtls.disallowed-origin",2,Pkcs11JourneyIntegrationTest::unlistedOriginReceivesNoClientCertificate));
    }
    private static void upstreamTrustFailsBeforeOrigin(int mode) throws Exception {
        try (var origin = IntegrationFixtures.https(root, mode == 1, true)) {
            AtomicInteger reached = new AtomicInteger(); TransportFixtures.countingTarget(origin.owner, reached::incrementAndGet).start();
            var j = IntegrationFixtures.journey(origin, List.of()); var definition = mtls("employee", List.of(TokenExtractor.origin(origin.url("/"))), mode == 0 ? null : root.resolve("ca.crt").toString());
            j = IntegrationFixtures.configured(j, j.authenticationUrl(), new JourneyDefinition.Browser(true, null, 5000, 500), j.extraction(), definition);
            char[] pin = pin(); JourneyDefinition finalJourney = j;
            try (var secrets = new SecretStore.Values(pin, Map.of())) {
                var ex = assertThrows(AuthenticationFailure.class, () -> runner.run(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, finalJourney.id(), 1), finalJourney, secrets, false, deadline(), () -> false));
                assertFalse(ex.retryable()); assertNotEquals(AuthenticationFailure.Cause.PIN_REJECTED, ex.reason()); assertEquals(0, reached.get());
                retainTransport("trust-mode-"+mode,Map.of("phase",ex.phase().name(),"cause",ex.reason().name(),"originRequests",reached.get(),"retryable",ex.retryable()));
            } finally { Arrays.fill(pin, '\0'); }
        }
    }

    private static void unlistedOriginReceivesNoClientCertificate() throws Exception {
        try(var origin=new IntegrationFixtures.Origin(TransportFixtures.https(root,false,TransportFixtures.ClientAuth.OPTIONAL));var redirector=IntegrationFixtures.https(root,false,true)) {
            String expected=fixture.path("fingerprints").path("employee").asText();
            var observation = new TransportFixtures.CertificateObservation(expected);
            origin.route("/login", observation::target).start();
            redirector.route("/login", exchange -> observation.redirect(exchange, origin.url("/login"))).start();
            var extraction=new JourneyDefinition.JsonExtraction(TokenExtractor.origin(origin.url("/")),"/login","access_token");
            for(boolean allowed:List.of(true,false)) {
                var initial=IntegrationFixtures.journey(origin,List.of());
                var start=allowed?origin.url("/login"):redirector.url("/login");
                var certificate=mtls("employee",List.of(TokenExtractor.origin(start)),root.resolve("ca.crt").toString());
                var journey=IntegrationFixtures.configured(initial,start,initial.browser(),extraction,certificate);
                ProductionLabAdapter.export(journey);char[] disposablePin=pin();
                try(var values=new SecretStore.Values(disposablePin,Map.of())) {
                    if(allowed)assertTrue("selected-certificate-proof".equals(runner.run(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT,journey.id(),1),journey,values,false,deadline(),()->false).token()),"The valid certificate comparison must return its output.");
                    else assertThrows(AuthenticationFailure.class,()->runner.run(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT,journey.id(),1),journey,values,false,deadline(),()->false));
                }finally{Arrays.fill(disposablePin,'\0');}
            }
            assertTrue(observation.allowedRedirectObserved(),"The negative journey must first authenticate at its allowed HTTPS login server.");
            assertEquals(List.of(expected,"NONE"),observation.fingerprints(),"A trusted unlisted origin must observe no client identity after the positive comparison.");
            retainTransport("unlisted-origin",Map.of("positiveExpectedFingerprintObserved",true,"unlistedOriginClientCertificateAbsent",true,"credentialReturnedForUnlistedOrigin",false));
        }
    }

    @Test @Order(4) void localEndpointRejectsMissingAndIncorrectAttemptCredentials() throws Exception {
        java.net.InetSocketAddress address,otherAddress;
        try(var target=new lab.auth.IngressSentinel(null)) {
            var origin=URI.create("https://localhost:"+target.address().getPort());
            var definition=mtls("employee",List.of(origin),root.resolve("ca.crt").toString());
            try(var httpTransport=new bpsh.transport.httpauth.HttpTransportRuntime();
                var proxy=IntegrationFixtures.browserProxy(httpTransport,definition,select(definition),null,Clock.systemUTC());
                var anotherLocalAttempt=IntegrationFixtures.browserProxy(httpTransport,definition,select(definition),null,Clock.systemUTC())) {
                address=proxy.address();otherAddress=anotherLocalAttempt.address();
                var credentials=anotherLocalAttempt.browserProxy();assertNotNull(credentials.username);assertNotNull(credentials.password);
                String otherAttempt="Proxy-Authorization: Basic "+java.util.Base64.getEncoder().encodeToString((credentials.username+":"+credentials.password).getBytes(java.nio.charset.StandardCharsets.UTF_8))+"\r\n";
                for(String header:List.of("","Proxy-Authorization: Basic ZGlzcG9zYWJsZTppbmNvcnJlY3Q=\r\n",otherAttempt))try(var socket=new java.net.Socket()) {
                    socket.connect(address,2000);socket.setSoTimeout(3000);
                    String authority="localhost:"+target.address().getPort();
                    socket.getOutputStream().write(("CONNECT "+authority+" HTTP/1.1\r\nHost: "+authority+"\r\n"+header+"\r\n").getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                    String status=new java.io.BufferedReader(new java.io.InputStreamReader(socket.getInputStream(),java.nio.charset.StandardCharsets.US_ASCII)).readLine();
                    assertNotNull(status);assertTrue(status.contains(" 407 "),"The local mTLS endpoint must reject missing/incorrect attempt credentials before connecting.");
                }
                assertEquals(0,target.snapshot().connections());assertEquals(0,target.snapshot().applicationBytes());
            }
        }
        for(var endpoint:List.of(address,otherAddress))try(var socket=new java.net.Socket()){assertThrows(java.io.IOException.class,()->socket.connect(endpoint,500),"The owned local mTLS listener must stop accepting connections after close.");}
        retainTransport("local-mtls-proxy",Map.of("missingAttemptCredentialsRejected",true,"incorrectAttemptCredentialsRejected",true,"otherAttemptCredentialsRejected",true,"targetConnections",0,"ownedListenersClosed",2));
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
            String failureStatus=editor.status().toLowerCase(java.util.Locale.ROOT);assertFalse(failureStatus.contains("connection failed"));assertFalse(failureStatus.contains("login succeeded"));
            retainTransport("native-picker",Map.of("explicitSelectionDialogs",selections.get(),"sameSubjectChoices",2,"distinctFingerprints",fingerprints.size(),
                    "explicitFingerprintSelected",true,"cancelPreservedSelection",true,"missingModuleReported",true,"moduleMessageCoherent",true));

        }
    }

    private static void retainTransport(String label,Map<String,Object> facts) throws Exception {ProductionLabAdapter.retainProcessFacts(label,facts);}

    /** @param type Host SDK interface. @return Interface-only local UI boundary with no actual host window. */
    private static Object uiHost(Class<?> type) { return java.lang.reflect.Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (proxy, method, args) -> method.getReturnType().isInterface() ? uiHost(method.getReturnType()) : null); }
}
