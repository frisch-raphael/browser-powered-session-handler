package bpsh.ui;

import bpsh.browser.AuthTrafficGuard;
import bpsh.browser.BrowserFailureClassifier;
import bpsh.browser.BrowserFlowRunner;
import bpsh.browser.BrowserJourneyIntegrationTest;
import bpsh.config.ConfigManager;
import bpsh.credentials.TokenExtractor;
import bpsh.diagnostics.Diagnostics;
import bpsh.model.AuthStep;
import bpsh.model.AuthenticationFailure;
import bpsh.model.JourneyDefinition;
import bpsh.model.JourneyKey;
import bpsh.runtime.RuntimeFixtures;
import bpsh.secrets.SecretStore;
import bpsh.session.CoordinatorFixtures;
import bpsh.support.AuthLabSupport;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Verifies actionable outcomes and repeated-warning suppression independently of Burp's logger. */
public class DiagnosticsTest {
    public @org.junit.jupiter.api.io.TempDir java.nio.file.Path temporary;
    public @org.junit.jupiter.api.TestFactory
    java.util.stream.Stream<org.junit.jupiter.api.DynamicTest> combinedOutputsRetainObservedStepFailureBeforeReportingMissingCredentials() {
        return List.of("none-captured","bearer-captured").stream().map(variant->org.junit.jupiter.api.DynamicTest.dynamicTest(variant,()-> {
            var base=CoordinatorFixtures.journey("employee");var selected=selection("incomplete-output-set");
            var journey=new JourneyDefinition(base.id(),base.displayName(),base.alias(),base.authenticationUrl(),false,presentationSteps("step-timeout-WAIT_SELECTOR"),
                    base.browser(),selected,JourneyDefinition.Injection.perToken(List.of(new JourneyDefinition.TokenInjection("access",JourneyDefinition.InjectionType.DISABLED,null))),base.cache(),null);
            var extractor=new TokenExtractor(selected,java.time.Clock.systemUTC());
            if(variant.equals("bearer-captured"))extractor.considerResponse("https://app.example/token", "{\"access_token\":\"CANARY_SELECTED_TOKEN\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8),true);
            var observed=stepFailure("step-timeout-WAIT_SELECTOR",journey);extractor.observe(observed);
            assertFalse(extractor.hasToken());var returned=assertThrows(AuthenticationFailure.class,extractor::result);
            assertAll("The actual failed action must remain actionable when several outputs are configured",
                    ()->assertEquals(AuthenticationFailure.Phase.STEP,returned.phase()),
                    ()->assertEquals(AuthenticationFailure.Cause.STEP_TIMEOUT,returned.reason()),
                    ()->assertEquals(observed.step(),returned.step()));
        }));
    }
    public @Test void missingCookieNamesTheSelectedOutputWithoutClaimingAConnectionFailure() throws Exception {
        checkPresentation("missing-cookie");
    }
    public @Test void observedConnectionFailureKeepsItsMeaningAndOrdinaryForwardingFeedback() throws Exception {
        checkPresentation("connection-refused");
    }
    public @org.junit.jupiter.api.TestFactory
    java.util.stream.Stream<org.junit.jupiter.api.DynamicTest> actualFailuresStayCoherentAcrossEventRowsDetailsStateAndRequestFeedback() {
        var variants = new ArrayList<>(List.of("tls-untrusted", "ambiguous-cookie", "missing-response-token", "invalid-response-format", "incomplete-output-set", "cancelled","navigation-timeout","login-rejected","unsupported-capability"));
        for (var type : AuthStep.Type.values()) variants.add("step-timeout-" + type.name());
        variants.addAll(List.of("step-ambiguous-CLICK", "step-unknown-INPUT", "step-missing-secret-SECURE_INPUT", "step-cancel-WAIT_TIME"));
        return variants.stream().map(variant -> org.junit.jupiter.api.DynamicTest.dynamicTest(variant.startsWith("step-") ? "[step=" + variant + "]" : "[case=CORE.diagnostics." + variant + "]", () -> checkPresentation(variant)));
    }
    public static AuthStep.Type stepType(String variant) { return AuthStep.Type.valueOf(variant.substring(variant.lastIndexOf('-') + 1)); }
    public static String stepLabel(AuthStep.Type type) {
        return switch (type) { case CLICK -> "Click element"; case INPUT -> "Fill field"; case SECURE_INPUT -> "Enter secret"; case WAIT_LOAD_STATE -> "Wait for page load";
            case WAIT_URL -> "Wait for URL"; case WAIT_TIME -> "Wait for duration"; case WAIT_SELECTOR -> "Wait for element"; };
    }
    public static List<AuthStep.Definition> presentationSteps(String variant) {
        if (!variant.startsWith("step-")) return List.of();
        var type = stepType(variant);
        var action = new AuthStep.Definition(java.util.UUID.randomUUID(), type, type.requiresSelector() ? "#CANARY_SELECTOR" : null,
                type == AuthStep.Type.INPUT ? "CANARY_PLAIN_SECRET" : null, type == AuthStep.Type.WAIT_LOAD_STATE ? "networkidle" : null,
                type == AuthStep.Type.WAIT_URL ? "https://app.example/CANARY_URL_SECRET/**" : null, type == AuthStep.Type.WAIT_TIME ? 1 : null);
        return List.of(BrowserJourneyIntegrationTest.step(AuthStep.Type.WAIT_TIME, null, "1"), action, BrowserJourneyIntegrationTest.step(AuthStep.Type.WAIT_TIME, null, "1"));
    }
    /** Maps typed SDK failures through the real runner; actual browser operations have separate operational checks. */
    public static AuthenticationFailure stepFailure(String variant, JourneyDefinition journey) throws Exception {
        var action = journey.steps().get(1);
        if (variant.startsWith("step-missing-secret")) {
            var method = BrowserFlowRunner.class.getDeclaredMethod("validateSecrets", JourneyDefinition.class, SecretStore.Values.class); method.setAccessible(true);
            try (var values = SecretStore.Values.empty()) {
                var wrapped = assertThrows(java.lang.reflect.InvocationTargetException.class, () -> method.invoke(null, journey, values));
                return assertInstanceOf(AuthenticationFailure.class, wrapped.getCause());
            }
        }
        if (variant.startsWith("step-cancel")) return assertThrows(AuthenticationFailure.class,
                () -> AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.STEP, Long.MAX_VALUE, () -> true))
                .atStep(new AuthenticationFailure.Step(action.id(), 2, action.type()));
        String raw = variant.startsWith("step-ambiguous") ? "strict mode violation: CANARY_SELECTOR CANARY_SECURE_SECRET https://app.example/CANARY_URL_SECRET" : "CANARY_SELECTOR CANARY_PLAIN_SECRET CANARY_SECURE_SECRET";
        com.microsoft.playwright.PlaywrightException sdk = variant.startsWith("step-timeout") ? new com.microsoft.playwright.TimeoutError(raw) : new com.microsoft.playwright.PlaywrightException(raw);
        var method = BrowserFailureClassifier.class.getDeclaredMethod("stepFailure", com.microsoft.playwright.PlaywrightException.class, AuthStep.Definition.class, int.class); method.setAccessible(true);
        return (AuthenticationFailure) method.invoke(null, sdk, action, 2);
    }
    private static JourneyDefinition.Extraction selection(String variant) {
        var json = new JourneyDefinition.JsonExtraction(java.net.URI.create("https://app.example"), "/token", "access_token");
        var cookie = new JourneyDefinition.CookieExtraction(java.net.URI.create("https://app.example/private?session=CANARY_URL_SECRET"), "LAB_C1", null, null);
        return switch (variant) {
            case "missing-cookie", "ambiguous-cookie" -> cookie;
            case "incomplete-output-set" -> new JourneyDefinition.CombinedExtraction(List.of(new JourneyDefinition.NamedExtraction("access", json), new JourneyDefinition.NamedExtraction("session", cookie)));
            default -> json;
        };
    }
    /** Produces real classified component failures; the fixture replaces only the browser acquisition boundary. */
    private static AuthenticationFailure actualFailure(String variant, JourneyDefinition.Extraction selected) throws Exception {
        if (variant.equals("connection-refused")) return BrowserFailureClassifier.networkFailure("ERR_CONNECTION_REFUSED");
        if (variant.equals("tls-untrusted")) return BrowserFailureClassifier.networkFailure("ERR_CERT_AUTHORITY_INVALID");
        if(variant.equals("navigation-timeout")) {
            var method=BrowserFailureClassifier.class.getDeclaredMethod("stepFailure",com.microsoft.playwright.PlaywrightException.class,AuthStep.Definition.class,int.class);method.setAccessible(true);
            return (AuthenticationFailure)method.invoke(null,new com.microsoft.playwright.TimeoutError("CANARY_URL_SECRET CANARY_PLAIN_SECRET"),null,0);
        }
        if(variant.equals("unsupported-capability"))return RuntimeFixtures.unsupportedPlatform();
        if (variant.equals("cancelled")) return assertThrows(AuthenticationFailure.class,
                () -> AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.LIFECYCLE, Long.MAX_VALUE, () -> true));
        var extractor = new TokenExtractor(selected, java.time.Clock.systemUTC());
        if(variant.equals("login-rejected")) {
            var request=(com.microsoft.playwright.Request)java.lang.reflect.Proxy.newProxyInstance(DiagnosticsTest.class.getClassLoader(),new Class<?>[]{com.microsoft.playwright.Request.class},(proxy,method,args)->{
                if(method.getName().equals("isNavigationRequest"))return false;throw new AssertionError("Unexpected login-response request access: "+method.getName());
            });
            var response=(com.microsoft.playwright.Response)java.lang.reflect.Proxy.newProxyInstance(DiagnosticsTest.class.getClassLoader(),new Class<?>[]{com.microsoft.playwright.Response.class},(proxy,method,args)->switch(method.getName()){
                case "url"->"https://app.example/token?session=CANARY_URL_SECRET";case "status"->401;case "request"->request;default->throw new AssertionError("Unexpected login-response access: "+method.getName());});
            var method=BrowserFlowRunner.class.getDeclaredMethod("observeStatus",com.microsoft.playwright.Response.class,JourneyDefinition.class,TokenExtractor.class);method.setAccessible(true);
            try(var guard=new AuthTrafficGuard()) {
                var runner=new BrowserFlowRunner(null,null,guard,java.time.Clock.systemUTC());var journey=CoordinatorFixtures.journey("employee");method.invoke(runner,response,journey,extractor);
            }
            return assertThrows(AuthenticationFailure.class,extractor::result);
        }
        if (variant.equals("ambiguous-cookie")) extractor.considerCookies(List.of(
                new com.microsoft.playwright.options.Cookie("LAB_C1", "CANARY_COOKIE_ONE").setDomain("app.example").setPath("/"),
                new com.microsoft.playwright.options.Cookie("LAB_C1", "CANARY_COOKIE_TWO").setDomain("app.example").setPath("/private")));
        else if (variant.equals("missing-cookie")) extractor.considerCookies(List.of());
        else {
            String body = variant.equals("invalid-response-format") ? "<html>CANARY_RESPONSE_BODY</html>" :
                    variant.equals("incomplete-output-set") ? "{\"access_token\":\"CANARY_SELECTED_TOKEN\"}" : "{\"unrelated\":\"CANARY_RESPONSE_BODY\"}";
            extractor.considerResponse("https://app.example/token?session=CANARY_URL_SECRET", body.getBytes(java.nio.charset.StandardCharsets.UTF_8), true);
            if (variant.equals("incomplete-output-set")) extractor.considerCookies(List.of());
        }
        assertFalse(extractor.hasToken(), "A missing/invalid selected output cannot establish complete extraction.");
        return assertThrows(AuthenticationFailure.class, extractor::result);
    }
    private static List<String> requiredWords(String variant) {
        if (variant.startsWith("step-")) {
            if (variant.startsWith("step-cancel")) return List.of("cancelled");
            var words = new ArrayList<>(List.of("Step 2", stepLabel(stepType(variant))));
            words.add(variant.startsWith("step-ambiguous") ? "matches several elements" : variant.startsWith("step-missing-secret") ? "no secret value" : variant.startsWith("step-timeout") ? "timed out" : "failed");
            return words;
        }
        return switch (variant) {
            case "connection-refused" -> List.of("connection", "refused");
            case "tls-untrusted" -> List.of("does not trust", "certificate");
            case "navigation-timeout"->List.of("Opening the login page","timed out");
            case "login-rejected"->List.of("login server","HTTP 401");
            case "unsupported-capability"->List.of("Supported targets", "Windows x64", "Linux x64", "Intel macOS");
            case "missing-cookie" -> List.of("cookie", "LAB_C1");
            case "ambiguous-cookie" -> List.of("more than one cookie");
            case "missing-response-token" -> List.of("no string", "configured JSON path");
            case "invalid-response-format" -> List.of("could not be read as JSON");
            case "incomplete-output-set" -> List.of("selected cookie", "LAB_C1", "not received");
            case "cancelled" -> List.of("cancelled"); default -> throw new IllegalArgumentException();
        };
    }
    private static List<String> forbiddenWords(String variant) {
        return switch (variant) {
            case "connection-refused", "tls-untrusted" -> List.of("cookie");
            case "navigation-timeout"->List.of("password rejected","incorrect password");
            case "unsupported-capability"->List.of("login failed","password rejected");
            case "ambiguous-cookie" -> List.of("not received", "connection");
            case "incomplete-output-set" -> List.of("login succeeded", "authenticated");
            default -> List.of("connection");
        };
    }
    private void checkPresentation(String variant) throws Exception {
        checkPresentation(variant, null, null);
    }
    /** Reuses the same presentation assertions for a failure returned by an actual browser operation. */
    public void checkPresentation(String variant, AuthenticationFailure supplied, JourneyDefinition suppliedJourney) throws Exception {
        long start = System.nanoTime(), ready, checked;
        var controls = CoordinatorFixtures.controls(null, null, 1000, 1000, 2000); // No retry fits; no clock advance or wait is introduced.
        var base = CoordinatorFixtures.journey("employee");
        var injection = JourneyDefinition.Injection.perToken(variant.equals("missing-cookie") || variant.equals("ambiguous-cookie") ? List.of() :
                List.of(new JourneyDefinition.TokenInjection(variant.equals("incomplete-output-set") ? "access" : null, JourneyDefinition.InjectionType.DISABLED, null)));
        var journey = suppliedJourney != null ? suppliedJourney : new JourneyDefinition(base.id(), base.displayName(), base.alias(), java.net.URI.create("https://app.example/login?access_token=CANARY_URL_SECRET"),
                false, presentationSteps(variant), base.browser(), selection(variant), injection, base.cache(), null);
        String stored;
        try (var document = new ConfigManager.NativeDocument(ConfigManager.DocumentKind.PROJECT, java.util.UUID.randomUUID(), List.of(journey), List.of(), controls, java.util.Map.of())) {
            stored = ConfigManager.nativeToJson(document);
        }
        var h = new JourneyRegistryTest().new NativeUi(); h.root = java.nio.file.Files.createTempDirectory(temporary, "presentation-");
        var produced = new java.util.concurrent.atomic.AtomicReference<AuthenticationFailure>(); var attempts = new java.util.concurrent.atomic.AtomicInteger();
        var captured = new java.util.concurrent.atomic.AtomicReference<java.util.Map<String, Object>>();
        try (var editor = h.new Editor(stored, controls, (entry, recovery, deadline, cancelled) -> {
            attempts.incrementAndGet(); AuthenticationFailure failure;
            try { failure = supplied != null ? supplied : variant.startsWith("step-") ? stepFailure(variant, entry.definition()) : actualFailure(variant, entry.definition().extraction()); }
            catch (Exception error) { throw new AssertionError("The controlled component must produce a classified failure.", error); }
            assertNotNull(failure); produced.set(failure); throw failure;
        })) {
            var entry = editor.registry.snapshot().resolve(journey.alias());
            h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, entry.identity().key()));
            h.await(() -> { try { return !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception error) { return false; } });
            ready = System.nanoTime();
            h.edt(() -> { javax.swing.JButton test = h.member(editor.ui, "testButton"); test.doClick(0); });
            h.await(() -> !editor.clock.workers.isEmpty()); editor.clock.runWorker();
            h.await(() -> editor.coordinator.status(entry.identity()).failure() != null); assertEquals(1, attempts.get());
            var failure = produced.get(); assertNotNull(failure);
            assertEquals(variant.startsWith("step-missing-secret")||variant.equals("unsupported-capability") ? AuthenticationFailure.Phase.SETUP : variant.startsWith("step-") ? AuthenticationFailure.Phase.STEP : List.of("connection-refused","tls-untrusted","navigation-timeout","login-rejected").contains(variant) ? AuthenticationFailure.Phase.NAVIGATION :
                    variant.equals("cancelled") ? AuthenticationFailure.Phase.LIFECYCLE : AuthenticationFailure.Phase.EXTRACTION, failure.phase());
            assertEquals(variant.startsWith("step-timeout")||variant.equals("navigation-timeout") ? AuthenticationFailure.Cause.STEP_TIMEOUT : variant.equals("login-rejected")?AuthenticationFailure.Cause.AUTH_REJECTED:variant.equals("unsupported-capability")?AuthenticationFailure.Cause.UNSUPPORTED_PLATFORM:variant.startsWith("step-missing-secret") ? AuthenticationFailure.Cause.MISSING_SECRET :
                    variant.startsWith("step-cancel") ? AuthenticationFailure.Cause.CANCELLED : variant.startsWith("step-") ? AuthenticationFailure.Cause.UNKNOWN : variant.equals("connection-refused") ? AuthenticationFailure.Cause.TRANSPORT : variant.equals("tls-untrusted") ? AuthenticationFailure.Cause.TRUST :
                    variant.equals("cancelled") ? AuthenticationFailure.Cause.CANCELLED : AuthenticationFailure.Cause.EXTRACTION, failure.reason());
            var tagged = editor.diagnostics.request(1, entry.definition().alias(), failure, true); var ordinary = editor.diagnostics.request(2, entry.definition().alias(), failure, false);
            h.edt(() -> {
                h.call(editor.ui, "refreshJourneyUi", new Class<?>[]{});
                SessionStatusBar bar = h.member(editor.ui, "status"); javax.swing.JToggleButton toggle = h.member(bar, "eventLog"); if (!bar.isLogOpen()) toggle.doClick(0);
                JourneyEventLogPanel panel = h.member(editor.ui, "eventLog"); javax.swing.JTable table = h.member(panel, "table"); javax.swing.JTextArea detail = h.member(panel, "detail");
                assertTrue(panel.isVisible()); assertTrue(bar.isLogOpen()); assertTrue(table.getRowCount() >= 3);
                int row = table.getRowCount() - 1; table.setRowSelectionInterval(row, row);
                String summary = table.getValueAt(row, 2).toString(), details = detail.getText();
                String rendered = ((javax.swing.JLabel) table.prepareRenderer(table.getCellRenderer(row, 2), row, 2)).getText();
                String severity = variant.equals("cancelled") || variant.startsWith("step-cancel") ? "Warning" : "Error";
                var state = editor.coordinator.status(entry.identity());
                var messages = List.of(summary, details, bar.getText(), tagged.text(), ordinary.text());
                boolean required = messages.stream().allMatch(message -> requiredWords(variant).stream().allMatch(word -> message.toLowerCase(java.util.Locale.ROOT).contains(word.toLowerCase(java.util.Locale.ROOT))));
                boolean forbidden = messages.stream().noneMatch(message -> forbiddenWords(variant).stream().anyMatch(word -> message.toLowerCase(java.util.Locale.ROOT).contains(word)));
                boolean redacted = messages.stream().noneMatch(message -> List.of("CANARY_SELECTOR", "CANARY_PLAIN_SECRET", "CANARY_SECURE_SECRET", "CANARY_URL_SECRET", "CANARY_RESPONSE_BODY", "CANARY_COOKIE_ONE", "CANARY_COOKIE_TWO", "CANARY_SELECTED_TOKEN", "https://app.example").stream().anyMatch(message::contains));
                var facts = new java.util.LinkedHashMap<String, Object>();
                facts.put("nativePhase", failure.phase().name()); facts.put("nativeCause", failure.reason().name());
                facts.put("summaryMatches", summary.equals(failure.getMessage()) && rendered.equals(summary) && table.getValueAt(row, 1).equals(severity));
                facts.put("detailsMatch", details.contains(failure.getMessage()) && details.contains("Type: " + severity));
                facts.put("stateMatches", state.failure() != null && state.failure().phase() == failure.phase() && state.failure().reason() == failure.reason() && bar.getText().equals(failure.getMessage()));
                facts.put("currentRevision", entry.identity().equals(h.member(editor.ui, "editingIdentity")) && editor.registry.snapshot().isCurrent(entry.identity()));
                facts.put("requestFeedbackMatches", tagged.requestStopped() && tagged.text().contains("Request was not sent.") && tagged.text().contains(entry.definition().canonicalAlias()) && !ordinary.requestStopped() && ordinary.text().contains("unchanged request was sent"));
                facts.put("requiredMessageMatches", required); facts.put("forbiddenClaimAbsent", forbidden); facts.put("redacted", redacted);
                facts.put("noPartialPublication", !state.usableToken() && editor.coordinator.peek(entry.identity()) == null); captured.set(facts);
                if (variant.startsWith("step-")) {
                    var action = entry.definition().steps().get(1); var attribution = failure.step();
                    var event = editor.coordinator.events().snapshot(entry.identity().key()).getLast();
                    facts.put("stepAttributionMatches", attribution != null && attribution.id().equals(action.id()) && attribution.number() == 2 && attribution.type() == action.type()
                            && state.failure().step().equals(attribution) && event.step() != null && event.step().journey().equals(entry.identity()) && event.step().id().equals(action.id()));
                    javax.swing.JButton go = h.member(panel, "goToStep"); facts.put("stepLinkCurrent", go.isVisible() && go.isEnabled()); go.doClick(0);
                } else assertFalse(((javax.swing.JButton) h.member(panel, "goToStep")).isVisible(), "A non-step failure must not offer an unrelated step target.");
            });
            if (variant.startsWith("step-")) {
                h.await(() -> { try { var index = new java.util.concurrent.atomic.AtomicInteger(); h.edt(() -> index.set(((javax.swing.JTabbedPane) h.member(editor.ui, "wizard")).getSelectedIndex())); return index.get() == 1; } catch (Exception error) { return false; } });
                h.edt(() -> editor.fields().get("name").setText("Updated step owner"));
                h.await(() -> { try { return editor.saved(); } catch (Exception error) { return false; } });
                h.edt(() -> {
                    JourneyEventLogPanel panel = h.member(editor.ui, "eventLog"); panel.refresh(entry.identity().key(), "employee"); javax.swing.JButton go = h.member(panel, "goToStep");
                    captured.get().put("stepLinkRetired", !editor.registry.snapshot().isCurrent(entry.identity()) && !go.isEnabled());
                });
                assertEquals(1, attempts.get()); assertTrue(editor.clock.workers.isEmpty(), "A saved edit must not acquire or replay credentials.");
            }
            checked = System.nanoTime();
        }
        var facts = captured.get(); assertNotNull(facts);
        AuthLabSupport.component("CORE.diagnostics." + variant, facts, java.util.Map.of("startupMs", java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(ready - start),
                "caseMs", java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(checked - ready), "cleanupMs", java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - checked)));
        if(variant.equals("step-missing-secret-SECURE_INPUT"))JourneyRegistryTest.configurationObservation("CORE.registry.missing-secret",facts,start);
        if(variant.equals("step-timeout-WAIT_SELECTOR"))AuthLabSupport.component("CORE.diagnostics.step-target-missing",facts,java.util.Map.of("startupMs",java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(ready-start),"caseMs",java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(checked-ready),"cleanupMs",java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-checked)));
        assertAll(facts.entrySet().stream().filter(e -> e.getValue() instanceof Boolean).map(e -> (org.junit.jupiter.api.function.Executable) () ->
                assertTrue((boolean) e.getValue(), "Actual production presentation must satisfy " + e.getKey() + " for " + variant)));
    }
    public @Test void errorsWithoutConfirmedRecoveryDisplayOnlyTheProblem() {
        var logs = new ArrayList<String>();
        try (var diagnostics = new Diagnostics(() -> 0, logs::add)) {
            var failure = new AuthenticationFailure(AuthenticationFailure.Phase.NAVIGATION,
                    AuthenticationFailure.Cause.UNKNOWN, "The browser could not open the login page.");
            assertEquals("", failure.recovery());
            assertEquals(failure.problem(), failure.getMessage());
            diagnostics.state("employee", failure);
            assertEquals(List.of("Journey employee: " + failure.problem()), logs);
        }
        var withAction = new AuthenticationFailure(AuthenticationFailure.Phase.SETUP,
                AuthenticationFailure.Cause.MISSING_SECRET, "The PIN is missing.", "Enter the PIN.");
        assertEquals("The PIN is missing. Enter the PIN.", withAction.getMessage());
    }
    public @Test void everyTaggedRequestKeepsItsAnnotationWhileRepeatedLogsAreCountedAndSuppressed() {
        AtomicLong now = new AtomicLong(); var logs = new ArrayList<String>();
        try (var diagnostics = new Diagnostics(now::get, logs::add)) {
            var failure = new AuthenticationFailure(AuthenticationFailure.Phase.QUEUE, AuthenticationFailure.Cause.CAPACITY, "The global waiting-request limit was reached.", "Let authentication finish and resend, or adjust the enabled global limit.");
            for (int i = 0; i < 20; i++) {
                var notice = diagnostics.request(i, "Employee", failure, true); assertTrue(notice.requestStopped()); assertTrue(notice.text().contains("not sent")); assertTrue(notice.text().contains("employee"));
            }
            assertEquals(1, logs.size()); now.set(5_000_000_000L); diagnostics.request(21, "employee", failure, true);
            assertEquals(2, logs.size()); assertTrue(logs.getLast().contains("19 similar messages suppressed"));
            var ordinary = diagnostics.request(22, "employee", failure, false); assertFalse(ordinary.requestStopped()); assertTrue(ordinary.text().contains("unchanged request was sent"));
        }
    }
    public @Test void unsafeAliasIsNotLoggedAndUnknownCauseRemainsUnknown() {
        var logs = new ArrayList<String>();
        try (var diagnostics = new Diagnostics(() -> 0, logs::add)) {
            var failure = CoordinatorFixtures.failure(AuthenticationFailure.Cause.UNKNOWN);
            var notice = diagnostics.request(1, "secret\r\nInjected: value", failure, true);
            assertFalse(notice.text().contains("secret")); assertFalse(notice.text().contains("password"));
            assertTrue(notice.text().contains(failure.problem())); assertTrue(notice.text().contains(failure.recovery()));
            assertEquals(AuthenticationFailure.Cause.UNKNOWN, failure.reason());
            assertFalse(notice.text().contains("phase ")); assertFalse(notice.text().contains("cause "));
        }
    }
    public @Test void brokenLoggingSinkCannotPreventAnAnnotationAndCloseStopsEmissions() {
        AtomicLong calls = new AtomicLong();
        var diagnostics = new Diagnostics(() -> 0, value -> { calls.incrementAndGet(); throw new IllegalStateException("host logger unavailable"); });
        assertNotNull(diagnostics.request(1, "employee", CoordinatorFixtures.failure(AuthenticationFailure.Cause.UNKNOWN), true)); diagnostics.close();
        assertNotNull(diagnostics.request(2, "admin", CoordinatorFixtures.failure(AuthenticationFailure.Cause.UNKNOWN), true)); assertEquals(1, calls.get());
    }
    public @Test void backgroundGuidanceIsRateLimitedWithoutClaimingARequestWasNotSent() {
        var logs = new ArrayList<String>();
        try (var diagnostics = new Diagnostics(() -> 0, logs::add)) {
            var failure = CoordinatorFixtures.failure(AuthenticationFailure.Cause.CONFIGURATION);
            diagnostics.state("employee", failure); diagnostics.state("employee", failure);
            assertEquals(1, logs.size()); assertFalse(logs.getFirst().contains("not sent")); assertTrue(logs.getFirst().contains("employee"));
        }
    }
}
