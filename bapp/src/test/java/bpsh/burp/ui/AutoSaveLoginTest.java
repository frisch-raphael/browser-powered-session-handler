package bpsh.burp.ui;

import bpsh.journey.persistence.JourneyDocument;
import bpsh.journey.persistence.JourneyJson;

import bpsh.browser.BrowserFailureClassifier;
import bpsh.journey.persistence.ProjectStore;
import bpsh.journey.editing.JourneyTransfer;
import bpsh.journey.persistence.UserLibraryStore;
import bpsh.authentication.credentials.AuthenticationResult;
import bpsh.authentication.credentials.CombinedCredentialsTest;
import bpsh.authentication.credentials.CredentialUse;
import bpsh.authentication.credentials.TokenExtractor;
import bpsh.authentication.credentials.TokenExtractorTest;
import bpsh.authentication.session.JourneyEventLog;
import bpsh.journey.AuthStep;
import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.JourneyDraft;
import bpsh.journey.JourneyKey;
import bpsh.journey.SecretStore;
import bpsh.authentication.session.AuthenticationCoordinator;
import bpsh.authentication.session.CoordinatorFixtures;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;
import java.util.stream.IntStream;
import javax.swing.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises save-before-login ordering with local storage and a browser worker that is never run. */
class AutoSaveLoginTest {
    @TempDir Path root;
    @Test void invalidCompiledRulesAndFailedStorageKeepTheAppliedPublication() throws Exception {
        var h=harness();
        try(var editor=h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT,false,false))) {
            var previous=editor.controls.snapshot();String disk=editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY);
            h.edt(()->{
                AutomaticRulesPanel rules=h.member(editor.ui,"automaticRules");
                var key=new bpsh.request.RequestSettings.JourneySelection(JourneyDefinition.Scope.PROJECT,JourneyRegistryTest.JOURNEY);
                rules.setRules(List.of(new bpsh.request.RequestSettings.AutomaticRule(true,key,new bpsh.request.RequestSettings.Regex("unfinished["),8081,
                        new JourneyDefinition.Recovery(true,JourneyDefinition.RecoveryMode.STATUS_CODE,401,null))));
                java.util.Map<String,JCheckBox> flags=h.member(editor.ui,"checks");flags.get("enabled").setSelected(true);
                h.call(editor.ui,"saveControls",new Class<?>[]{boolean.class},false);
            });
            awaitRuleIo(editor.ui);assertSame(previous,editor.controls.snapshot());assertEquals(disk,editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY));
            editor.failWrites.set(true);
            h.edt(()->{AutomaticRulesPanel rules=h.member(editor.ui,"automaticRules");rules.prefix.setText("/protected");h.call(editor.ui,"saveControls",new Class<?>[]{boolean.class},false);});
            awaitRuleIo(editor.ui);assertSame(previous,editor.controls.snapshot());assertEquals(disk,editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY));
            editor.failWrites.set(false);
            h.edt(()->h.call(editor.ui,"saveControls",new Class<?>[]{boolean.class},false));
            awaitRuleIo(editor.ui);assertNotSame(previous,editor.controls.snapshot());
            assertEquals(editor.controls.snapshot().controls(),editor.controls.snapshot().matcher().controls());
            try(var saved=JourneyJson.read(editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY),JourneyDocument.DocumentKind.PROJECT)) {
                assertEquals(saved.controls(),editor.controls.snapshot().controls());
            }
        }
    }

    @Test void rejectedAutomaticUrlRegexKeepsAppliedRulesAndShowsInlineGuidanceAtTheEditedUrl() throws Exception {
        var h=harness();
        try(var editor=h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT,false,false))) {
            var dialogs=loginResults(h,editor);
            h.edt(()->{
                AutomaticRulesPanel rules=h.member(editor.ui,"automaticRules");
                var key=new bpsh.request.RequestSettings.JourneySelection(JourneyDefinition.Scope.PROJECT,JourneyRegistryTest.JOURNEY);
                rules.setRules(List.of(new bpsh.request.RequestSettings.AutomaticRule(true,key,new bpsh.request.RequestSettings.Regex("/protected"),8081,
                        new JourneyDefinition.Recovery(true,JourneyDefinition.RecoveryMode.STATUS_CODE,401,null))));
                editor.checks().get("enabled").setSelected(true);h.call(editor.ui,"saveControls",new Class<?>[]{boolean.class},false);
            });
            awaitRuleIo(editor.ui);var previous=editor.controls.snapshot();String disk=editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY);
            var focus=java.awt.KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusOwner();
            h.edt(()->{
                AutomaticRulesPanel rules=h.member(editor.ui,"automaticRules");rules.prefix.setText("[");
                h.call(editor.ui,"saveControls",new Class<?>[]{boolean.class},false);
            });
            awaitRuleIo(editor.ui);
            assertSame(previous,editor.controls.snapshot());assertEquals(disk,editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY));
            h.edt(()->{
                AutomaticRulesPanel rules=h.member(editor.ui,"automaticRules");
                var error=(JTextArea)rules.prefix.getClientProperty("validationMessage");
                assertNotNull(error,"The automatic URL must own an inline validation surface.");
                assertTrue(error.isVisible());assertTrue(error.getText().contains("RE2"));
                assertFalse(error.getText().contains("["));assertFalse(error.getText().contains("controls.rules"));
                assertEquals(error.getText(),rules.prefix.getAccessibleContext().getAccessibleDescription());
                assertEquals(0,rules.table.getSelectedRow());assertSame(focus,java.awt.KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusOwner());
                assertTrue(dialogs.results.isEmpty());assertEquals("[",rules.prefix.getText());
                rules.prefix.setText("/corrected");assertFalse(error.isVisible());
                h.call(editor.ui,"saveControls",new Class<?>[]{boolean.class},false);
            });
            awaitRuleIo(editor.ui);
            assertEquals("/corrected",((bpsh.request.RequestSettings.Regex)editor.controls.snapshot().controls().rules().getFirst().url()).value());
        }
    }

    @Test void queuedValidationFailureCannotMarkAReplacementAutomaticRuleDraft() throws Exception {
        var h=harness();
        try(var editor=h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT,false,false))) {
            var key=new bpsh.request.RequestSettings.JourneySelection(JourneyDefinition.Scope.PROJECT,JourneyRegistryTest.JOURNEY);
            h.edt(()->{
                AutomaticRulesPanel rules=h.member(editor.ui,"automaticRules");
                rules.setRules(List.of(new bpsh.request.RequestSettings.AutomaticRule(true,key,new bpsh.request.RequestSettings.Regex("/valid"),null,
                        new JourneyDefinition.Recovery(true,JourneyDefinition.RecoveryMode.STATUS_CODE,401,null))));
                editor.checks().get("enabled").setSelected(true);h.call(editor.ui,"saveControls",new Class<?>[]{boolean.class},false);
            });
            awaitRuleIo(editor.ui);var previous=editor.controls.snapshot();var entered=new java.util.concurrent.CountDownLatch(1);var release=new java.util.concurrent.CountDownLatch(1);
            java.util.concurrent.ThreadPoolExecutor io=h.member(editor.ui,"io");
            io.execute(()->{entered.countDown();try{release.await(5,java.util.concurrent.TimeUnit.SECONDS);}catch(InterruptedException stopped){Thread.currentThread().interrupt();}});
            assertTrue(entered.await(5,java.util.concurrent.TimeUnit.SECONDS));
            try {
                h.edt(()->{
                    AutomaticRulesPanel rules=h.member(editor.ui,"automaticRules");rules.prefix.setText("private-old-expression[");
                    h.call(editor.ui,"saveControls",new Class<?>[]{boolean.class},false);
                    rules.prefix.setText("/new-draft");((Timer)h.member(editor.ui,"automaticDebounce")).stop();
                });
            }finally{release.countDown();}
            awaitRuleIo(editor.ui);assertSame(previous,editor.controls.snapshot());
            h.edt(()->{
                AutomaticRulesPanel rules=h.member(editor.ui,"automaticRules");
                assertEquals("/new-draft",rules.prefix.getText());assertEquals(0,rules.table.getSelectedRow());
                assertFalse(((JTextArea)rules.prefix.getClientProperty("validationMessage")).isVisible());
                var scroll=(JScrollPane)SwingUtilities.getAncestorOfClass(JScrollPane.class,rules.table);
                assertFalse(((JTextArea)scroll.getClientProperty("validationMessage")).isVisible());
                h.call(editor.ui,"saveControls",new Class<?>[]{boolean.class},false);
            });
            awaitRuleIo(editor.ui);
            assertEquals("/new-draft",((bpsh.request.RequestSettings.Regex)editor.controls.snapshot().controls().rules().getFirst().url()).value());
        }
    }

    @Test void compilerGuidanceNeverEchoesTheInvalidUrlOrResponseExpression() throws Exception {
        for(boolean response:List.of(false,true)) {
            var h=harness();
            try(var editor=h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT,false,false))) {
                h.edt(()->{
                    AutomaticRulesPanel rules=h.member(editor.ui,"automaticRules");
                    var key=new bpsh.request.RequestSettings.JourneySelection(JourneyDefinition.Scope.PROJECT,JourneyRegistryTest.JOURNEY);
                    rules.setRules(List.of(new bpsh.request.RequestSettings.AutomaticRule(true,key,new bpsh.request.RequestSettings.Regex("/valid"),null,
                            new JourneyDefinition.Recovery(true,JourneyDefinition.RecoveryMode.REGEX,null,"expired"))));
                    editor.checks().get("enabled").setSelected(true);
                    (response?rules.pattern:rules.prefix).setText("<html><img src='file:private-expression'>[");
                    h.call(editor.ui,"saveControls",new Class<?>[]{boolean.class},false);
                });
                awaitRuleIo(editor.ui);
                h.edt(()->{
                    AutomaticRulesPanel rules=h.member(editor.ui,"automaticRules");var field=response?rules.pattern:rules.prefix;
                    var error=(JTextArea)field.getClientProperty("validationMessage");assertTrue(error.isVisible());
                    assertFalse(error.getText().contains("private-expression"));assertFalse(error.getText().contains("<html>"));
                    assertFalse(error.getText().contains("controls.rules"));assertTrue(error.getText().contains("RE2"));
                    assertEquals(error.getText(),field.getAccessibleContext().getAccessibleDescription());
                });
            }
        }
    }

    @Test void listenerExportsAreCoalescedOffEdtWithoutSavingOrStartingAuthentication() throws Exception {
        var entered=new java.util.concurrent.CountDownLatch(1);var release=new java.util.concurrent.CountDownLatch(1);
        var exports=new java.util.concurrent.atomic.AtomicInteger();
        var api=(burp.api.montoya.MontoyaApi)java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(),new Class<?>[]{burp.api.montoya.MontoyaApi.class},(p,m,a)-> {
            if(!m.getName().equals("burpSuite"))throw new AssertionError(m.getName());
            return java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(),new Class<?>[]{m.getReturnType()},(suite,method,args)-> {
                assertEquals("exportProjectOptionsAsJson",method.getName());assertFalse(SwingUtilities.isEventDispatchThread());
                assertArrayEquals(new String[]{"proxy.request_listeners"},(String[])args[0]);exports.incrementAndGet();entered.countDown();
                assertTrue(release.await(5,java.util.concurrent.TimeUnit.SECONDS));
                return "{\"proxy\":{\"request_listeners\":[{\"listener_port\":8081,\"running\":true}]}}";
            });
        });
        var h=harness();
        try(var editor=h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT,false,false),null,null,null,new bpsh.burp.http.ProxyListeners(api))) {
            var before=editor.controls.snapshot();var disk=java.util.Map.copyOf(editor.disk);
            try {
                h.edt(()->{for(int i=0;i<5;i++)h.call(editor.ui,"refreshProxyListeners",new Class<?>[]{});});
                assertTrue(entered.await(5,java.util.concurrent.TimeUnit.SECONDS));assertEquals(1,exports.get());
            } finally {release.countDown();}
            awaitRuleIo(editor.ui);
            h.edt(()->{AutomaticRulesPanel rules=h.member(editor.ui,"automaticRules");assertEquals(2,rules.proxyPort.getItemCount());});
            assertSame(before,editor.controls.snapshot());assertEquals(disk,editor.disk);assertTrue(editor.clock.workers.isEmpty());
        }
    }

    private static void awaitRuleIo(UiController ui) throws Exception {
        var field=UiController.class.getDeclaredField("io");field.setAccessible(true);
        var io=(java.util.concurrent.ThreadPoolExecutor)field.get(ui);
        io.submit(()->{}).get(5,java.util.concurrent.TimeUnit.SECONDS);
        SwingUtilities.invokeAndWait(()->{});
    }

    @Test void requestPolicySelectorPersistsAndSurvivesOtherControlEdits() throws Exception {
        var h = harness();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            h.edt(() -> {
                JComboBox<bpsh.request.RequestSettings.RequestPolicy> policy = h.member(editor.ui, "requestPolicy");
                JTextArea explanation = h.member(editor.ui, "requestPolicyHelp");
                assertTrue(explanation.isVisible()); assertFalse(explanation.isEditable());
                assertNotNull(policy.getToolTipText());
                assertEquals(bpsh.request.RequestSettings.RequestPolicy.WAIT_FOR_LOGIN, policy.getSelectedItem());
                assertTrue(explanation.getText().contains("wait for login to finish"));
                policy.setSelectedItem(bpsh.request.RequestSettings.RequestPolicy.DO_NOT_WAIT);
                assertTrue(explanation.getText().contains("send the original request unchanged"));
                assertTrue(explanation.getText().contains("Later requests use the credentials"));
                assertTrue(explanation.getText().contains("valid cached token or cookie"));
                assertTrue(policy.getToolTipText().contains("send the original request unchanged"));
                h.call(editor.ui, "saveControls", new Class<?>[]{boolean.class}, true);
            });
            h.await(() -> editor.controls.snapshot().controls().requestPolicy() == bpsh.request.RequestSettings.RequestPolicy.DO_NOT_WAIT);
            h.edt(() -> h.call(editor.ui, "saveControls", new Class<?>[]{boolean.class}, false));
            java.util.concurrent.ThreadPoolExecutor io = h.member(editor.ui, "io");
            var complete = new java.util.concurrent.CountDownLatch(1); io.execute(complete::countDown);
            assertTrue(complete.await(5, java.util.concurrent.TimeUnit.SECONDS));
            try (var loaded = JourneyJson.read(editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY), JourneyDocument.DocumentKind.PROJECT)) {
                assertEquals(bpsh.request.RequestSettings.RequestPolicy.DO_NOT_WAIT, loaded.controls().requestPolicy());
            }
        }
    }

    @Test void secureInputAppearsImmediatelyAndTracksMissingVersusExplicitlyClearedValues() throws Exception {
        var h = harness(); var id = UUID.randomUUID();
        h.edt(() -> {
            var panel = new StepsPanel();
            try (var values = SecretStore.Values.empty()) { panel.setSteps(List.of(new AuthStep.Definition(id, AuthStep.Type.SECURE_INPUT, "#password", null, null, null, null)), values); }
            List<?> rows = h.member(panel, "rows"); Object row = rows.getFirst(); JPasswordField field = h.member(row, "secret");
            assertTrue(((JPanel) h.member(row, "secretLine")).isVisible()); assertTrue(field.isEnabled());
            try (var snapshot = panel.snapshot()) { assertFalse(snapshot.secrets.containsKey(id)); }
            field.setText("synthetic"); field.setText("");
            try (var snapshot = panel.snapshot()) { assertArrayEquals(new char[0], snapshot.secrets.get(id)); }
            ((JComboBox<?>) h.member(row, "type")).setSelectedItem(AuthStep.Type.CLICK);
            ((JComboBox<?>) h.member(row, "type")).setSelectedItem(AuthStep.Type.SECURE_INPUT);
            try (var snapshot = panel.snapshot()) { assertFalse(snapshot.secrets.containsKey(id)); }
        });
    }

    @Test void aRuntimeStepErrorRevealsTheActualSelectorWhileKeepingTheEventLogClosed() throws Exception {
        var h = harness();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false), (entry, recovery, deadline, cancelled) -> {
            var step = entry.definition().steps().getFirst();
            throw new AuthenticationFailure(AuthenticationFailure.Phase.STEP, AuthenticationFailure.Cause.STEP_TIMEOUT, "The configured input could not be found.")
                    .atStep(new AuthenticationFailure.Step(step.id(), 1, step.type()));
        })) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); open(h, editor, key);
            h.edt(() -> { WizardTestPages.select(((JTabbedPane) h.member(editor.ui, "wizard")), "Test & use"); ((JButton) h.member(editor.ui, "testButton")).doClick(0); });
            h.await(() -> !editor.clock.workers.isEmpty()); editor.clock.runWorker();
            h.await(() -> { try {
                List<?> rows = h.member((StepsPanel) h.member(editor.ui, "steps"), "rows");
                return ((JTextArea) ((JComponent) h.member(rows.getFirst(), "selector")).getClientProperty("validationMessage")).isVisible();
            } catch (Exception error) { return false; } });
            h.edt(() -> {
                List<?> rows = h.member((StepsPanel) h.member(editor.ui, "steps"), "rows");
                var selector = (JTextField) h.member(rows.getFirst(), "selector");
                var error = (JTextArea) selector.getClientProperty("validationMessage"); assertTrue(error.isVisible()); assertTrue(error.getText().contains("could not be found"));
                var secret = (JPasswordField) h.member(rows.getFirst(), "secret"); assertFalse(((JTextArea) secret.getClientProperty("validationMessage")).isVisible());
                assertFalse(((SessionStatusBar) h.member(editor.ui, "status")).isLogOpen());
            });
        }
    }

    private JourneyRegistryTest.NativeUi harness() {
        var h = new JourneyRegistryTest().new NativeUi(); h.root = root; return h;
    }

    /** Records only the public completion summary and the controls visible when it opens. */
    private static final class LoginResults implements JourneyDialogs {
        record Result(String title, String text, boolean error, boolean testEnabled, boolean cancelVisible) {}
        final List<Result> results = new java.util.concurrent.CopyOnWriteArrayList<>();
        JButton test, cancel; int closed;
        @Override public Path file(java.awt.Component parent, boolean save) { throw new AssertionError("Unexpected file chooser"); }
        @Override public boolean confirm(java.awt.Component parent, Object content, String title) { throw new AssertionError("Unexpected confirmation"); }
        @Override public void inform(java.awt.Component parent, String text) { throw new AssertionError("Unexpected information: " + text); }
        @Override public void loginResult(java.awt.Component parent, String title, String text, boolean error) {
            assertTrue(SwingUtilities.isEventDispatchThread());
            results.add(new Result(title, text, error, test.isEnabled(), cancel.isVisible()));
        }
        @Override public void closeLoginResult() { assertTrue(SwingUtilities.isEventDispatchThread()); closed++; }
    }

    private LoginResults loginResults(JourneyRegistryTest.NativeUi h, JourneyRegistryTest.NativeUi.Editor editor) throws Exception {
        var dialogs = new LoginResults();
        h.edt(() -> {
            dialogs.test = h.member(editor.ui, "testButton"); dialogs.cancel = h.member(editor.ui, "cancelButton");
            var field = UiController.class.getDeclaredField("dialogs"); field.setAccessible(true); field.set(editor.ui, dialogs);
        });
        return dialogs;
    }

    @ParameterizedTest @ValueSource(strings = {"json", "regex", "cookie", "named", "combined"})
    void completedTestSummarizesCapturedCredentialsWithoutTheirValues(String mode) throws Exception {
        var h = harness(); var clock = new java.util.concurrent.atomic.AtomicReference<CoordinatorFixtures.ManualRuntime>();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false), (entry, recovery, deadline, cancelled) ->
                new AuthenticationResult(entry.identity(), "private-ui-token", clock.get().instant(), clock.get().nanos(),
                        java.util.Map.of("symfony", "private-cookie-value"), java.util.Map.of("access", "private-ui-token", "session", "private-cookie-value"), java.util.OptionalLong.empty()))) {
            clock.set(editor.clock); open(h, editor, editor.registry.snapshot().resolve("employee").identity().key());
            var dialogs = loginResults(h, editor);
            var json = new JourneyDefinition.JsonExtraction(java.net.URI.create("https://login.example"), "/token", "token");
            var cookie = new JourneyDefinition.CookieExtraction(java.net.URI.create("https://login.example/"), "symfony", null, null);
            JourneyDefinition.Extraction extraction = switch (mode) {
                case "cookie" -> cookie;
                case "regex" -> new JourneyDefinition.RegexExtraction(java.net.URI.create("https://login.example"), "/token", "start", "end");
                case "named" -> new JourneyDefinition.CombinedExtraction(List.of(new JourneyDefinition.NamedExtraction("access", json)));
                case "combined" -> new JourneyDefinition.CombinedExtraction(List.of(new JourneyDefinition.NamedExtraction("access", json), new JourneyDefinition.NamedExtraction("session", cookie)));
                default -> json;
            };
            h.edt(() -> {
                ((CredentialsPanel) h.member(editor.ui, "credentials")).setDefinition(extraction);
                h.call(editor.ui, "edited", new Class<?>[]{}); dialogs.test.doClick(0);
            });
            h.await(() -> !editor.clock.workers.isEmpty()); editor.clock.runWorker();
            h.await(() -> dialogs.results.size() == 1);
            var result = dialogs.results.getFirst();
            assertEquals("Credentials captured", result.title()); assertFalse(result.error());
            assertTrue(result.text().contains("Employee")); assertFalse(result.text().contains("Open Journey cache"));
            assertFalse(result.text().contains("private-ui-token")); assertFalse(result.text().contains("private-cookie-value"));
            assertFalse(result.text().contains("Authenticated"));
            if (mode.equals("combined")) { assertTrue(result.text().contains("2 credentials")); assertTrue(result.text().contains("access")); assertTrue(result.text().contains("session")); }
            else if (mode.equals("named")) assertTrue(result.text().contains("access"));
            else assertTrue(result.text().contains(mode.equals("cookie") ? "1 cookie" : "1 token"));
            if (mode.equals("cookie") || mode.equals("combined")) assertTrue(result.text().contains("symfony"));
            assertTrue(result.testEnabled(), "The completed run must be reflected before the modal opens"); assertFalse(result.cancelVisible());
            h.edt(() -> assertFalse(((SessionStatusBar) h.member(editor.ui, "status")).isLogOpen()));
        }
    }

    @ParameterizedTest @ValueSource(booleans = {false, true})
    void completedTestSummarizesSafeFailureAndStepWithoutRawExceptionOrInput(boolean unexpected) throws Exception {
        var h = harness();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false), (entry, recovery, deadline, cancelled) -> {
            if (unexpected) throw new IllegalStateException("private-exception-token #password");
            var step = entry.definition().steps().getFirst();
            throw new AuthenticationFailure(AuthenticationFailure.Phase.STEP, AuthenticationFailure.Cause.STEP_TIMEOUT,
                    "The configured input could not be found.", "Review this step and test login again.")
                    .atStep(new AuthenticationFailure.Step(step.id(), 1, step.type()));
        })) {
            open(h, editor, editor.registry.snapshot().resolve("employee").identity().key()); var dialogs = loginResults(h, editor);
            h.edt(() -> dialogs.test.doClick(0)); h.await(() -> !editor.clock.workers.isEmpty()); editor.clock.runWorker();
            if (!unexpected) {
                h.await(() -> { try { return "Login steps".equals(WizardTestPages.selected(h.member(editor.ui, "wizard"))); } catch (Exception error) { return false; } });
                h.edt(() -> {
                    assertTrue(dialogs.results.isEmpty(), "A located step error must not open a popup");
                    List<?> rows = h.member((StepsPanel) h.member(editor.ui, "steps"), "rows");
                    var guidance = (JTextArea) ((JComponent) h.member(rows.getFirst(), "selector")).getClientProperty("validationMessage");
                    assertTrue(guidance.isVisible());
                    assertEquals("The configured input could not be found. Review this step and test login again.", guidance.getText());
                });
                return;
            }
            h.await(() -> dialogs.results.size() == 1); var result = dialogs.results.getFirst();
            assertEquals("Login failed", result.title()); assertTrue(result.error()); assertTrue(result.text().contains("Employee"));
            assertFalse(result.text().contains("private-exception-token")); assertFalse(result.text().contains("#password"));
            assertTrue(result.text().contains("Login failed."));
            assertTrue(result.testEnabled()); assertFalse(result.cancelVisible());
        }
    }

    @Test void invalidDraftExplainsWhyLoginCouldNotStartWithoutStartingABrowser() throws Exception {
        var h = harness();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            open(h, editor, editor.registry.snapshot().resolve("employee").identity().key()); var dialogs = loginResults(h, editor);
            h.edt(() -> { editor.fields().get("url").setText("invalid-private-input"); dialogs.test.doClick(0); });
            h.await(() -> { try { return ((JTextArea) editor.fields().get("url").getClientProperty("validationMessage")).isVisible(); } catch(Exception error) { return false; } });
            h.edt(() -> {
                var guidance = (JTextArea) editor.fields().get("url").getClientProperty("validationMessage");
                assertTrue(guidance.getText().contains("Login URL")); assertFalse(guidance.getText().contains("invalid-private-input"));
                assertTrue(dialogs.results.isEmpty()); assertEquals("Setup", WizardTestPages.selected(h.member(editor.ui,"wizard")));
            });
            assertTrue(editor.clock.workers.isEmpty());
        }
    }

    @ParameterizedTest @ValueSource(strings = {"edited", "cancelled", "shutdown"})
    void obsoleteOrCancelledTestCannotOpenACompletionPopup(String action) throws Exception {
        var h = harness(); var clock = new java.util.concurrent.atomic.AtomicReference<CoordinatorFixtures.ManualRuntime>();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false), (entry, recovery, deadline, cancelled) ->
                new AuthenticationResult(entry.identity(), "private-ui-token", clock.get().instant(), clock.get().nanos()))) {
            clock.set(editor.clock); var entry = editor.registry.snapshot().resolve("employee"); open(h, editor, entry.identity().key());
            var dialogs = loginResults(h, editor); h.edt(() -> dialogs.test.doClick(0)); h.await(() -> !editor.clock.workers.isEmpty());
            h.edt(() -> {
                if (action.equals("edited")) editor.fields().get("name").setText("Changed account");
                else if (action.equals("cancelled")) h.call(editor.ui, "selectedAction", new Class<?>[]{boolean.class}, true);
                else editor.ui.shutdown();
            });
            if (action.equals("cancelled")) h.await(() -> editor.coordinator.status(entry.identity()).phase() == AuthenticationCoordinator.Phase.COOLDOWN);
            editor.clock.runWorker(); h.edt(() -> assertTrue(dialogs.results.isEmpty()));
            if (action.equals("shutdown")) assertEquals(1, dialogs.closed);
        }
    }

    @Test void backgroundAcquisitionDoesNotOpenACompletionPopup() throws Exception {
        var h = harness(); var clock = new java.util.concurrent.atomic.AtomicReference<CoordinatorFixtures.ManualRuntime>();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false), (entry, recovery, deadline, cancelled) ->
                new AuthenticationResult(entry.identity(), "private-ui-token", clock.get().instant(), clock.get().nanos()))) {
            clock.set(editor.clock); var entry = editor.registry.snapshot().resolve("employee"); open(h, editor, entry.identity().key()); var dialogs = loginResults(h, editor);
            try (var ticket = editor.coordinator.acquire(List.of(entry))) {
                editor.clock.runWorker(); ticket.future().join(); h.edt(() -> assertTrue(dialogs.results.isEmpty()));
            }
        }
    }

    @Test void temporaryFailuresShowOnePopupOnlyAfterTheTestCycleFinishes() throws Exception {
        var h = harness(); var clock = new java.util.concurrent.atomic.AtomicReference<CoordinatorFixtures.ManualRuntime>();
        var attempts = new java.util.concurrent.atomic.AtomicInteger();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false), (entry, recovery, deadline, cancelled) -> {
            if (attempts.incrementAndGet() < 3) throw new AuthenticationFailure(AuthenticationFailure.Phase.NAVIGATION,
                    AuthenticationFailure.Cause.TRANSPORT, "The login connection was refused.");
            return new AuthenticationResult(entry.identity(), "private-ui-token", clock.get().instant(), clock.get().nanos());
        })) {
            clock.set(editor.clock); open(h, editor, editor.registry.snapshot().resolve("employee").identity().key()); var dialogs = loginResults(h, editor);
            h.edt(() -> dialogs.test.doClick(0)); h.await(() -> !editor.clock.workers.isEmpty());
            editor.clock.runWorker(); h.edt(() -> assertTrue(dialogs.results.isEmpty()));
            editor.clock.advance(5000); editor.clock.runWorker(); h.edt(() -> assertTrue(dialogs.results.isEmpty()));
            editor.clock.advance(15_000); editor.clock.runWorker(); h.await(() -> dialogs.results.size() == 1);
            assertEquals(3, attempts.get()); assertEquals("Credentials captured", dialogs.results.getFirst().title());
        }
    }

    @ParameterizedTest @ValueSource(strings = {"name", "url", "proxy", "navTimeout", "tokenWait", "maxAge", "skew"})
    void testRevealsEachInvalidJourneySettingAndItsCollapsedSection(String field) throws Exception {
        var h = harness();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            open(h, editor, editor.registry.snapshot().resolve("employee").identity().key());
            h.edt(() -> {
                editor.fields().get(field).setText(field.equals("name") ? "" : "invalid");
                WizardTestPages.select(((JTabbedPane) h.member(editor.ui, "wizard")), "Test & use");
                ((JButton) h.member(editor.ui, "testButton")).doClick(0);
            });
            h.await(() -> { try { return ((JTextArea) editor.fields().get(field).getClientProperty("validationMessage")).isVisible(); } catch (Exception error) { return false; } });
            h.edt(() -> {
                assertEquals(field.equals("maxAge") || field.equals("skew") ? "Capture credentials" : "Setup", WizardTestPages.selected(((JTabbedPane) h.member(editor.ui, "wizard"))));
                for (java.awt.Component component = editor.fields().get(field); component != null; component = component.getParent()) assertTrue(component.isVisible(), field);
                assertFalse(((SessionStatusBar) h.member(editor.ui, "status")).isLogOpen());
            });
            assertTrue(editor.clock.workers.isEmpty());
        }
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.EnumSource(AuthStep.Type.class)
    void runtimeErrorsRevealTheRelevantControlForEveryStepType(AuthStep.Type type) throws Exception {
        var h = harness(); var failingId = UUID.randomUUID(); var triggerId = UUID.randomUUID(); int rowIndex = type == AuthStep.Type.PARENT_FRAME ? 1 : 0;
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false), (entry, recovery, deadline, cancelled) -> {
            var step = entry.definition().steps().get(rowIndex);
            throw new AuthenticationFailure(AuthenticationFailure.Phase.STEP, AuthenticationFailure.Cause.STEP_TIMEOUT, "The action timed out.")
                    .atStep(new AuthenticationFailure.Step(step.id(), rowIndex + 1, step.type()));
        })) {
            open(h, editor, editor.registry.snapshot().resolve("employee").identity().key());
            h.edt(() -> {
                var panel = (StepsPanel) h.member(editor.ui, "steps"); var id = failingId;
                try (var values = SecretStore.Values.empty()) {
                    var definitions = new java.util.ArrayList<AuthStep.Definition>();
                    if (type == AuthStep.Type.PARENT_FRAME) definitions.add(new AuthStep.Definition(UUID.randomUUID(), AuthStep.Type.ENTER_FRAME, "#frame", null, null, null, null));
                    definitions.add(new AuthStep.Definition(id, type, type.requiresSelector() ? "#fixture" : null,
                            type == AuthStep.Type.INPUT ? "synthetic" : null,
                            type == AuthStep.Type.WAIT_SELECTOR ? "visible" : type == AuthStep.Type.WAIT_LOAD_STATE ? "load" : type == AuthStep.Type.WAIT_URL ? "exact" : null,
                            type == AuthStep.Type.WAIT_URL ? "https://login.example/done" : null, type == AuthStep.Type.WAIT_TIME ? 0 : null, type == AuthStep.Type.EXPECT_POPUP ? new AuthStep.Popup("popup-1", triggerId) : type == AuthStep.Type.SWITCH_PAGE ? new AuthStep.PageTarget("main") : AuthStep.defaultOperation(type, id)));
                    if (type == AuthStep.Type.EXPECT_POPUP) definitions.add(new AuthStep.Definition(triggerId, AuthStep.Type.CLICK, "#open", null, null, null, null));
                    panel.setSteps(definitions, values);
                }
                h.call(editor.ui, "edited", new Class<?>[]{});
                WizardTestPages.select(((JTabbedPane) h.member(editor.ui, "wizard")), "Test & use");
                ((JButton) h.member(editor.ui, "testButton")).doClick(0);
            });
            h.await(() -> !editor.clock.workers.isEmpty()); editor.clock.runWorker();
            h.await(() -> { try {
                List<?> rows = h.member((StepsPanel) h.member(editor.ui, "steps"), "rows");
                String expected = type.requiresSelector() ? "selector" : type == AuthStep.Type.WAIT_LOAD_STATE ? "state" : type == AuthStep.Type.EXPECT_POPUP ? "popupName" : type == AuthStep.Type.SWITCH_PAGE ? "pageChoice" : java.util.Set.of(AuthStep.Type.PARENT_FRAME, AuthStep.Type.MAIN_FRAME, AuthStep.Type.CLOSE_PAGE).contains(type) ? "type" : "value";
                return ((JTextArea) ((JComponent) h.member(rows.get(rowIndex), expected)).getClientProperty("validationMessage")).isVisible();
            } catch (Exception error) { return false; } });
            h.edt(() -> {
                List<?> rows = h.member((StepsPanel) h.member(editor.ui, "steps"), "rows"); Object row = rows.get(rowIndex);
                String expected = type.requiresSelector() ? "selector" : type == AuthStep.Type.WAIT_LOAD_STATE ? "state" : type == AuthStep.Type.EXPECT_POPUP ? "popupName" : type == AuthStep.Type.SWITCH_PAGE ? "pageChoice" : java.util.Set.of(AuthStep.Type.PARENT_FRAME, AuthStep.Type.MAIN_FRAME, AuthStep.Type.CLOSE_PAGE).contains(type) ? "type" : "value";
                JComponent field = h.member(row, expected);
                assertTrue(((JTextArea) field.getClientProperty("validationMessage")).isVisible());
                assertEquals("The action timed out.", ((JTextArea) field.getClientProperty("validationMessage")).getText());
                assertTrue(((JPanel) row).getMaximumSize().height >= ((JPanel) row).getPreferredSize().height, "The expanded row must fit the error guidance");
                assertFalse(((SessionStatusBar) h.member(editor.ui, "status")).isLogOpen());
            });
        }
    }

    private void open(JourneyRegistryTest.NativeUi h, JourneyRegistryTest.NativeUi.Editor editor, JourneyKey key) throws Exception {
        h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, key));
        h.await(() -> { try { return key.equals(h.member(editor.ui, "editing")) && !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception error) { return false; } });
    }

    @ParameterizedTest @ValueSource(strings = {"dns", "proxy", "json", "cookie", "missing", "service"})
    void observedRuntimeFailuresRevealOnlyTheirIdentifiedInput(String mode) throws Exception {
        var h = harness();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false), (entry, recovery, deadline, cancelled) -> {
            if (mode.equals("dns")) throw BrowserFailureClassifier.networkFailure("ERR_NAME_NOT_RESOLVED");
            if (mode.equals("proxy")) throw BrowserFailureClassifier.networkFailure("ERR_PROXY_CONNECTION_FAILED");
            if (mode.equals("service")) throw new AuthenticationFailure(AuthenticationFailure.Phase.SETUP, AuthenticationFailure.Cause.ASSET_MISSING, "The browser asset is missing.");
            var collector = new TokenExtractor(entry.definition().extraction(), TokenExtractorTest.CLOCK);
            collector.collectCookies(url -> mode.equals("cookie")
                    ? List.of(new bpsh.authentication.credentials.CapturedCookie("sid", "a", "login.example", "/", null), new bpsh.authentication.credentials.CapturedCookie("sid", "b", ".login.example", "/", null))
                    : List.of(new bpsh.authentication.credentials.CapturedCookie("sid", "a", "login.example", "/", null)));
            if (mode.equals("json")) collector.considerResponse("https://login.example/token", "{}".getBytes(java.nio.charset.StandardCharsets.UTF_8), true);
            collector.result(); throw new AssertionError("The fixture must fail extraction");
        })) {
            open(h, editor, editor.registry.snapshot().resolve("employee").identity().key());
            h.edt(() -> {
                ((CredentialsPanel) h.member(editor.ui, "credentials")).setInputs(List.of(
                        new JourneyDraft.CredentialInput("session", "cookie", "https://login.example/", "", "sid", "", "", "", "", "disabled", ""),
                        new JourneyDraft.CredentialInput("csrf", "json_path", "https://login.example", "/token", "token", "", "", "", "", "bearer", "")));
                h.call(editor.ui, "edited", new Class<?>[]{}); WizardTestPages.select(((JTabbedPane) h.member(editor.ui, "wizard")), "Test & use");
                ((JButton) h.member(editor.ui, "testButton")).doClick(0);
            });
            h.await(() -> !editor.clock.workers.isEmpty()); editor.clock.runWorker();
            h.await(() -> { try {
                if (mode.equals("service")) return editor.status().contains("browser asset is missing");
                JComponent field;
                if (mode.equals("dns") || mode.equals("proxy")) field = editor.fields().get(mode.equals("dns") ? "url" : "proxy");
                else {
                    List<?> rows = h.member((CredentialsPanel) h.member(editor.ui, "credentials"), "rows");
                    field = h.member(mode.equals("cookie") ? rows.getFirst() : rows.getLast(), mode.equals("cookie") ? "domain" : mode.equals("json") ? "selector" : "type");
                }
                return ((JTextArea) field.getClientProperty("validationMessage")).isVisible();
            } catch (Exception error) { return false; } });
            h.edt(() -> {
                String expectedTab = mode.equals("service") ? "Test & use" : mode.equals("dns") || mode.equals("proxy") ? "Setup" : "Capture credentials";
                assertEquals(expectedTab, WizardTestPages.selected(((JTabbedPane) h.member(editor.ui, "wizard"))));
                if (!mode.equals("service")) {
                    JComponent field;
                    if (mode.equals("dns") || mode.equals("proxy")) field = editor.fields().get(mode.equals("dns") ? "url" : "proxy");
                    else {
                        List<?> rows = h.member((CredentialsPanel) h.member(editor.ui, "credentials"), "rows");
                        Object row = mode.equals("cookie") ? rows.getFirst() : rows.getLast();
                        field = h.member(row, mode.equals("cookie") ? "domain" : mode.equals("json") ? "selector" : "type");
                        assertTrue(((JToggleButton) h.member(row, "expanded")).isSelected());
                    }
                    assertTrue(((JTextArea) field.getClientProperty("validationMessage")).isVisible());
                }
                assertFalse(((SessionStatusBar) h.member(editor.ui, "status")).isLogOpen());
            });
        }
    }

    @ParameterizedTest @ValueSource(booleans = {false, true})
    void testAndRetrySaveEditsBeforeQueuingAuthentication(boolean retry) throws Exception {
        var h = harness();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); open(h, editor, key);
            h.edt(() -> {
                editor.fields().get("name").setText("Updated account");
                editor.fields().get("url").setText("https://login.example/updated");
                assertTrue(((JButton) h.member(editor.ui, "testButton")).isEnabled());
                assertTrue(editor.clock.workers.isEmpty());
                if (retry) h.call(editor.ui, "authenticate", new Class<?>[]{boolean.class}, true);
                else ((JButton) h.member(editor.ui, "testButton")).doClick(0);
            });
            h.await(() -> { try { return editor.clock.workers.size() == 1 && editor.status().startsWith("Signing in"); } catch (Exception error) { return false; } });
            try (var saved = JourneyJson.read(editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY), JourneyDocument.DocumentKind.PROJECT)) {
                var journey = saved.journeys().getFirst();
                assertEquals("Updated account", journey.displayName()); assertEquals("updated-account", journey.alias());
                assertEquals("https://login.example/updated", journey.authenticationUrl().toString());
            }
            h.edt(() -> {
                assertFalse((boolean) h.member(editor.ui, "dirty"));
                assertEquals(editor.registry.snapshot().resolve(key).identity(), h.member(editor.ui, "editingIdentity"));
                assertFalse(((JButton) h.member(editor.ui, "testButton")).isEnabled());
                var status = (SessionStatusBar) h.member(editor.ui, "status");
                assertFalse(status.isLogOpen(), "Test and Retry must not automatically open the log.");
                assertFalse(((JPanel) h.member(editor.ui, "detailSurface")).isVisible());
                assertEquals("New test events available", ((JToggleButton) h.member(status, "eventLog")).getAccessibleContext().getAccessibleDescription());
            });
        }
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(strings = {"closed", "log", "cache"})
    void testingKeepsTheManuallyChosenDockAndHighlightsOnlyAClosedLog(String dock) throws Exception {
        var h = harness();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); open(h, editor, key);
            h.edt(() -> {
                var status = (SessionStatusBar) h.member(editor.ui, "status");
                if (dock.equals("log")) status.setLogOpen(true); else if (dock.equals("cache")) status.setCacheOpen(true);
                h.call(editor.ui, "showEventDock", new Class<?>[]{});
                ((JButton) h.member(editor.ui, "testButton")).doClick(0);
            });
            h.await(() -> editor.clock.workers.size() == 1);
            h.edt(() -> {
                var status = (SessionStatusBar) h.member(editor.ui, "status");
                assertEquals(dock.equals("log"), status.isLogOpen()); assertEquals(dock.equals("cache"), status.isCacheOpen());
                String attention = ((JToggleButton) h.member(status, "eventLog")).getAccessibleContext().getAccessibleDescription();
                if (dock.equals("log")) assertEquals("Show this journey's event history.", attention); else assertEquals("New test events available", attention);
            });
        }
    }

    @Test void aNewJourneyCanBeTestedWithoutSavingManuallyAndHasNoHelpTab() throws Exception {
        var h = harness();
        try (var editor = h.new Editor(null)) {
            h.edt(() -> {
                JTabbedPane tabs = h.member(editor.ui, "mainTabs");
                assertEquals(List.of("Journeys", "Session handling", "Settings"),
                        IntStream.range(0, tabs.getTabCount()).mapToObj(tabs::getTitleAt).toList());
                h.call(editor.ui, "newJourney", new Class<?>[]{});
                editor.fields().get("name").setText("New login"); editor.fields().get("url").setText("https://login.example/login");
                ((CredentialsPanel) h.member(editor.ui, "credentials")).setDefinition(CombinedCredentialsTest.JSON);
                JButton test = h.member(editor.ui, "testButton"); assertTrue(test.isEnabled()); test.doClick(0);
            });
            h.await(() -> editor.clock.workers.size() == 1);
            try (var saved = JourneyJson.read(editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY), JourneyDocument.DocumentKind.PROJECT)) {
                assertEquals("new-login", saved.journeys().getFirst().alias());
                assertEquals("New login", saved.journeys().getFirst().displayName());
            }
        }
    }

    @Test void executionSavesInvalidEditsThenShowsValidationWithoutStartingLogin() throws Exception {
        var h = harness();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); open(h, editor, key);
            String previous = editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY);
            h.edt(() -> {
                editor.fields().get("name").setText("");
                ((JButton) h.member(editor.ui, "testButton")).doClick(0);
            });
            h.await(() -> { try { return editor.status().startsWith("Display name"); } catch (Exception error) { return false; } });
            assertNotEquals(previous, editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY)); assertTrue(editor.clock.workers.isEmpty());
            try (var saved = JourneyJson.read(editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY), JourneyDocument.DocumentKind.PROJECT)) {
                assertEquals("", saved.journeys().getFirst().draft().text().get("name"));
            }
        }
    }

    @Test void plusImmediatelyPersistsAndSelectsANewJourneyWithoutALoginUrl() throws Exception {
        var h = harness();
        try (var editor = h.new Editor(null)) {
            h.edt(() -> h.call(editor.ui, "newJourney", new Class<?>[]{}));
            h.await(() -> { try { return editor.saved(); } catch (Exception e) { return false; } });
            JourneyKey key = h.member(editor.ui, "editing");
            assertEquals(1, editor.registry.snapshot().entries().size());
            try (var saved = JourneyJson.read(editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY), JourneyDocument.DocumentKind.PROJECT)) {
                assertEquals("", saved.journeys().getFirst().draft().text().get("url"));
                assertEquals(key.journeyId(), saved.journeys().getFirst().id());
            }
            h.edt(() -> {
                assertFalse((boolean) h.member(editor.ui, "dirty"));
                assertEquals(1, ((JList<?>) h.member(editor.ui, "saved")).getSelectedIndices().length);
                h.call(editor.ui, "newJourney", new Class<?>[]{});
            });
            h.await(() -> editor.registry.snapshot().entries().size() == 2);
            assertEquals(java.util.Set.of("new-journey", "new-journey-2"), editor.registry.snapshot().entries().values().stream()
                    .map(e -> e.definition().alias()).collect(java.util.stream.Collectors.toSet()));
            assertTrue(editor.clock.workers.isEmpty());
        }
    }

    @Test void saveAndReopenPreserveInvalidNumbersTokenSettingsAndWaitTextUntilExecution() throws Exception {
        var h = harness();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); open(h, editor, key);
            var waitId = UUID.randomUUID();
            h.edt(() -> {
                editor.fields().get("url").setText("unfinished URL"); editor.fields().get("navTimeout").setText("later");
                CredentialsPanel credentials = h.member(editor.ui, "credentials");
                credentials.setInputs(List.of(new JourneyDraft.CredentialInput("", "regex", "", "/", "", "", "", "[", "", "header", "")));
                StepsPanel steps = h.member(editor.ui, "steps");
                try (var values = SecretStore.Values.empty()) { steps.setDraft(List.of(new JourneyDraft.StepInput(waitId, AuthStep.Type.WAIT_TIME, "", "not ready", "load")), values); }
                h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false);
            });
            h.await(() -> { try { return editor.saved(); } catch (Exception e) { return false; } });
            String savedJson = editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY);
            assertTrue(savedJson.contains("not ready")); assertTrue(savedJson.contains("later"));
            assertTrue(editor.clock.workers.isEmpty());
            open(h, editor, key);
            h.edt(() -> {
                assertEquals("unfinished URL", editor.fields().get("url").getText()); assertEquals("later", editor.fields().get("navTimeout").getText());
                CredentialsPanel credentials = h.member(editor.ui, "credentials"); assertEquals("[", credentials.snapshot().getFirst().startRegex());
                StepsPanel steps = h.member(editor.ui, "steps"); try (var snapshot = steps.snapshot()) { assertEquals("not ready", snapshot.inputs.getFirst().value()); }
                ((JButton) h.member(editor.ui, "testButton")).doClick(0);
            });
            h.await(() -> { try { return editor.status().contains("Step 1, Duration"); } catch (Exception e) { return false; } });
            assertTrue(editor.clock.workers.isEmpty());
            var ticket = editor.coordinator.acquire(List.of(editor.registry.snapshot().resolve(key)));
            var failure = assertThrows(java.util.concurrent.CompletionException.class, () -> ticket.future().join());
            assertEquals(AuthenticationFailure.Cause.CONFIGURATION, ((AuthenticationFailure) failure.getCause()).reason());
            assertTrue(editor.clock.workers.isEmpty()); assertEquals(0, editor.coordinator.capacity().waitingRequests());
        }
    }

    @Test void repairingASavedIncompleteJourneyMakesItExecutable() throws Exception {
        var h = harness();
        try (var editor = h.new Editor(null)) {
            h.edt(() -> h.call(editor.ui, "newJourney", new Class<?>[]{}));
            h.await(() -> { try { return editor.saved(); } catch (Exception e) { return false; } });
            h.edt(() -> { editor.fields().get("url").setText("https://login.example/login"); ((CredentialsPanel) h.member(editor.ui, "credentials")).setDefinition(CombinedCredentialsTest.JSON); ((JButton) h.member(editor.ui, "testButton")).doClick(0); });
            h.await(() -> editor.clock.workers.size() == 1);
            try (var saved = JourneyJson.read(editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY), JourneyDocument.DocumentKind.PROJECT)) {
                assertNull(saved.journeys().getFirst().draft()); assertEquals("https://login.example/login", saved.journeys().getFirst().authenticationUrl().toString());
            }
        }
    }

    @Test void unfinishedJourneyKeepsSecureInputsSeparateAndRemapsThemOnImport() throws Exception {
        var h = harness();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); open(h, editor, key);
            h.edt(() -> {
                editor.fields().get("url").setText("");
                StepsPanel panel = h.member(editor.ui, "steps"); List<?> rows = h.member(panel, "rows"); Object row = rows.getFirst();
                ((JPasswordField) h.member(row, "secret")).setText("owned-draft-secret");
                h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false);
            });
            h.await(() -> { try { return editor.saved(); } catch (Exception error) { return false; } });
            assertFalse(editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY).contains("owned-draft-secret"));
            var entry = editor.registry.snapshot().resolve(key);
            String redacted = JourneyTransfer.exportJourneys(List.of(entry), editor.secrets, false);
            assertFalse(redacted.contains("owned-draft-secret"));
            String exported = JourneyTransfer.exportJourneys(List.of(entry), editor.secrets, true);
            assertTrue(exported.contains("owned-draft-secret"));
            try (var imported = JourneyTransfer.previewImport(exported, JourneyDefinition.Scope.LIBRARY, editor.registry, java.util.Map.of("employee", "draft-copy"))) {
                var copy = imported.journeys().getFirst(); assertNotEquals(entry.definition().id(), copy.id());
                assertEquals("draft-copy", copy.draft().text().get("alias")); assertFalse(copy.rememberSecrets());
                UUID originalStep = entry.definition().steps().getFirst().id(), copiedStep = copy.steps().getFirst().id();
                assertNotEquals(originalStep, copiedStep); assertEquals(copiedStep, copy.draft().steps().getFirst().id());
                try (var values = imported.secrets().get(copy.id()).copy()) { assertArrayEquals("owned-draft-secret".toCharArray(), values.stepValue(copiedStep)); }
                assertFalse(JourneyJson.write(imported).contains("owned-draft-secret"));
            }
            open(h, editor, key);
            h.edt(() -> { StepsPanel panel = h.member(editor.ui, "steps"); List<?> rows = h.member(panel, "rows"); assertArrayEquals("owned-draft-secret".toCharArray(), ((JPasswordField) h.member(rows.getFirst(), "secret")).getPassword()); });
        }
    }

    @Test void editsAutosaveWithoutStatusFeedbackAndSuccessfulWritesAreCoalescedInTheLog() throws Exception {
        var h = harness();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); open(h, editor, key);
            h.edt(() -> { editor.fields().get("name").setText("Automatic edit"); editor.fields().get("navTimeout").setText("unfinished"); });
            h.await(() -> { try { return editor.saved(); } catch (Exception error) { return false; } });
            try (var saved = JourneyJson.read(editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY), JourneyDocument.DocumentKind.PROJECT)) {
                assertEquals("unfinished", saved.journeys().getFirst().draft().text().get("navTimeout"));
            }
            assertTrue(editor.coordinator.events().snapshot(key).stream().anyMatch(e -> e.level() == JourneyEventLog.Level.INFO && e.message().equals("Changes saved.")));
            h.edt(() -> { editor.fields().get("navTimeout").setText("still unfinished"); h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false); });
            h.await(() -> { try { return editor.saved(); } catch (Exception error) { return false; } });
            assertEquals(1, editor.coordinator.events().snapshot(key).stream().filter(e -> e.message().equals("Changes saved.")).count());
            assertFalse(editor.status().contains("Saved")); assertFalse(editor.status().contains("Saving")); assertFalse(editor.status().contains("Unsaved"));
            h.edt(() -> { assertEquals("", ((JLabel) h.member(editor.ui, "draftState")).getText()); ((JButton) h.member(editor.ui, "testButton")).doClick(0); });
            h.await(() -> editor.coordinator.events().snapshot(key).stream().anyMatch(e -> e.level() == JourneyEventLog.Level.ERROR && e.message().contains("Browser action timeout")));
            assertTrue(editor.clock.workers.isEmpty());
        }
    }

    @Test void latestEditsAndNavigationWaitForAnEarlierSaveWithoutQueueingEverySnapshot() throws Exception {
        var h = harness();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); open(h, editor, key);
            var started = new java.util.concurrent.CountDownLatch(1); var release = new java.util.concurrent.CountDownLatch(1);
            java.util.concurrent.ThreadPoolExecutor io = h.member(editor.ui, "io");
            io.execute(() -> { started.countDown(); try { release.await(5, java.util.concurrent.TimeUnit.SECONDS); } catch (InterruptedException e) { Thread.currentThread().interrupt(); } });
            assertTrue(started.await(5, java.util.concurrent.TimeUnit.SECONDS));
            var navigated = new java.util.concurrent.atomic.AtomicBoolean();
            h.edt(() -> {
                editor.fields().get("name").setText("Earlier snapshot"); h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false);
                editor.fields().get("name").setText("Latest edit");
                h.call(editor.ui, "leaveDraft", new Class<?>[]{Runnable.class}, (Runnable) () -> {
                    assertEquals("Latest edit", editor.registry.snapshot().entries().get(key).definition().displayName()); navigated.set(true);
                });
                assertEquals(1, io.getQueue().size()); assertFalse(navigated.get());
            });
            release.countDown(); h.await(navigated::get); assertTrue(editor.saved());
            try (var saved = JourneyJson.read(editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY), JourneyDocument.DocumentKind.PROJECT)) { assertEquals("Latest edit", saved.journeys().getFirst().displayName()); }
        }
    }

    @Test void aBusyLibraryLogsAWarningAndAutomaticallyRetriesWithoutLosingEdits() throws Exception {
        var h = harness();
        try (var editor = h.new Editor(null)) {
            h.edt(() -> { ((JComboBox<?>) h.member(editor.ui, "destination")).setSelectedItem(JourneyDefinition.Scope.LIBRARY); h.call(editor.ui, "newJourney", new Class<?>[]{}); });
            h.await(() -> { try { return editor.saved(); } catch (Exception e) { return false; } });
            var key = (JourneyKey) h.member(editor.ui, "editing");
            var lockPath = root.resolve("library-v1.lock");
            try (var channel = java.nio.channels.FileChannel.open(lockPath, java.nio.file.StandardOpenOption.WRITE); var lock = channel.lock()) {
                h.edt(() -> { editor.fields().get("url").setText("unfinished URL"); h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false); });
                h.await(() -> editor.coordinator.events().snapshot(key).stream().anyMatch(e -> e.level() == JourneyEventLog.Level.WARNING && e.message().contains("automatic retry")));
                assertFalse(editor.saved()); assertFalse(editor.status().contains("could not be saved"));
            }
            h.await(() -> { try { return editor.saved(); } catch (Exception e) { return false; } });
            try (var saved = new UserLibraryStore(editor.library.path()).load()) { assertEquals("unfinished URL", saved.document().journeys().getFirst().draft().text().get("url")); }
            assertTrue(editor.coordinator.events().snapshot(key).stream().noneMatch(e -> e.level() == JourneyEventLog.Level.ERROR));
        }
    }

    @Test void unloadingFlushesEditsBeforeTheDebounceFires() throws Exception {
        var h = harness();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); open(h, editor, key);
            h.edt(() -> { editor.fields().get("name").setText("Final automatic save"); editor.fields().get("url").setText(""); editor.ui.shutdown(); });
            editor.ui.awaitSaves(5000);
            try (var saved = JourneyJson.read(editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY), JourneyDocument.DocumentKind.PROJECT)) {
                assertEquals("Final automatic save", saved.journeys().getFirst().displayName()); assertEquals("", saved.journeys().getFirst().draft().text().get("url"));
            }
        }
    }

    @Test void actualPausedJourneyFeedbackKeepsCauseAndAttemptsAcrossAutosaveThenExplicitTestResumes() throws Exception {
        var h = harness(); var clock = new java.util.concurrent.atomic.AtomicReference<CoordinatorFixtures.ManualRuntime>();
        var failed = new java.util.concurrent.atomic.AtomicBoolean(); var attempts = new java.util.concurrent.atomic.AtomicInteger();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false), (entry, recovery, deadline, cancelled) -> {
            attempts.incrementAndGet(); if (failed.get()) throw new AuthenticationFailure(AuthenticationFailure.Phase.NAVIGATION,
                    AuthenticationFailure.Cause.TRANSPORT, "The login connection was refused.");
            return new AuthenticationResult(entry.identity(), "private-ui-token", clock.get().instant(), clock.get().nanos());
        })) {
            clock.set(editor.clock); var entry = editor.registry.snapshot().resolve("employee"); var key = entry.identity().key(); open(h, editor, key);
            h.edt(() -> ((JButton) h.member(editor.ui, "testButton")).doClick(0));
            h.await(() -> !editor.clock.workers.isEmpty()); editor.clock.runWorker();
            h.await(() -> editor.coordinator.status(entry.identity()).phase() == AuthenticationCoordinator.Phase.READY);
            h.edt(() -> h.call(editor.ui, "refreshJourneyUi", new Class<?>[]{}));
            assertTrue(editor.status().contains("protected access unverified")); assertFalse(editor.status().contains("Authenticated"));
            var token = editor.coordinator.peek(entry.identity()); failed.set(true);
            editor.coordinator.recover(List.of(new CredentialUse(token.identity(), token.version(), new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null))));
            editor.clock.runWorker(); editor.clock.advance(5000); editor.clock.runWorker(); editor.clock.advance(15_000); editor.clock.runWorker();
            h.edt(() -> h.call(editor.ui, "refreshJourneyUi", new Class<?>[]{}));
            assertTrue(editor.status().contains("connection was refused")); assertTrue(editor.status().contains("3 attempts"));
            assertTrue(editor.status().contains("ordinary requests continue unchanged")); assertTrue(editor.status().contains("tagged requests are stopped"));
            assertFalse(editor.status().contains("private-ui-token"));
            h.edt(() -> editor.fields().get("name").setText("Pause retained on save"));
            h.await(() -> { try { return editor.saved(); } catch (Exception error) { return false; } });
            var current = editor.registry.snapshot().entries().get(key); assertEquals(AuthenticationCoordinator.Phase.PAUSED, editor.coordinator.status(current.identity()).phase());
            assertEquals(4, attempts.get()); failed.set(false);
            h.edt(() -> ((JButton) h.member(editor.ui, "testButton")).doClick(0));
            h.await(() -> !editor.clock.workers.isEmpty()); editor.clock.runWorker();
            h.await(() -> editor.coordinator.status(current.identity()).phase() == AuthenticationCoordinator.Phase.READY);
            h.edt(() -> h.call(editor.ui, "refreshJourneyUi", new Class<?>[]{}));
            assertTrue(editor.status().contains("protected access unverified")); assertFalse(editor.status().contains("connection was refused"));
            assertEquals(5, attempts.get());
            assertTrue(editor.coordinator.events().snapshot(key).stream().anyMatch(e -> e.level() == JourneyEventLog.Level.ERROR && e.message().contains("3 attempts")));
        }
    }

    @Test void aFailedSaveNeverStartsLoginOrOverwritesTheChangedProject() throws Exception {
        var h = harness();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); open(h, editor, key);
            String replacement = JourneyRegistryTest.edit(editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY), "", "revision", UUID.randomUUID().toString());
            editor.disk.put(ProjectStore.NATIVE_PROJECT_KEY, replacement);
            h.edt(() -> {
                editor.fields().get("name").setText("Updated account");
                ((JButton) h.member(editor.ui, "testButton")).doClick(0);
            });
            h.await(() -> { try { return editor.coordinator.events().snapshot(key).stream().anyMatch(e -> e.level() == JourneyEventLog.Level.ERROR && e.message().contains("Storage changed")); } catch (Exception error) { return false; } });
            assertEquals(replacement, editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY)); assertTrue(editor.clock.workers.isEmpty());
            assertEquals("Employee", editor.registry.snapshot().resolve(key).definition().displayName());
        }
    }
}
