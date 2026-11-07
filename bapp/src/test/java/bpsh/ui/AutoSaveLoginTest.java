package bpsh.ui;

import bpsh.browser.BrowserFailureClassifier;
import bpsh.config.ConfigManager;
import bpsh.config.JourneyTransfer;
import bpsh.config.UserLibraryStore;
import bpsh.credentials.AuthenticationResult;
import bpsh.credentials.CombinedCredentialsTest;
import bpsh.credentials.CredentialUse;
import bpsh.credentials.TokenExtractor;
import bpsh.credentials.TokenExtractorTest;
import bpsh.events.JourneyEventLog;
import bpsh.model.AuthStep;
import bpsh.model.AuthenticationFailure;
import bpsh.model.JourneyDefinition;
import bpsh.model.JourneyDraft;
import bpsh.model.JourneyKey;
import bpsh.secrets.SecretStore;
import bpsh.session.AuthenticationCoordinator;
import bpsh.session.CoordinatorFixtures;
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
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false), (entry, recovery, deadline, cancelled) -> {
            var step = entry.definition().steps().getFirst();
            throw new AuthenticationFailure(AuthenticationFailure.Phase.STEP, AuthenticationFailure.Cause.STEP_TIMEOUT, "The configured input could not be found.")
                    .atStep(new AuthenticationFailure.Step(step.id(), 1, step.type()));
        })) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); open(h, editor, key);
            h.edt(() -> { ((JTabbedPane) h.member(editor.ui, "wizard")).setSelectedIndex(4); ((JButton) h.member(editor.ui, "testButton")).doClick(0); });
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

    @ParameterizedTest @ValueSource(strings = {"name", "url", "proxy", "navTimeout", "tokenWait", "maxAge", "skew"})
    void testRevealsEachInvalidJourneySettingAndItsCollapsedSection(String field) throws Exception {
        var h = harness();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
            open(h, editor, editor.registry.snapshot().resolve("employee").identity().key());
            h.edt(() -> {
                editor.fields().get(field).setText(field.equals("name") ? "" : "invalid");
                ((JTabbedPane) h.member(editor.ui, "wizard")).setSelectedIndex(4);
                ((JButton) h.member(editor.ui, "testButton")).doClick(0);
            });
            h.await(() -> { try { return ((JTextArea) editor.fields().get(field).getClientProperty("validationMessage")).isVisible(); } catch (Exception error) { return false; } });
            h.edt(() -> {
                assertEquals(field.equals("maxAge") || field.equals("skew") ? 2 : 0, ((JTabbedPane) h.member(editor.ui, "wizard")).getSelectedIndex());
                for (java.awt.Component component = editor.fields().get(field); component != null; component = component.getParent()) assertTrue(component.isVisible(), field);
                assertFalse(((SessionStatusBar) h.member(editor.ui, "status")).isLogOpen());
            });
            assertTrue(editor.clock.workers.isEmpty());
        }
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.EnumSource(AuthStep.Type.class)
    void runtimeErrorsRevealTheRelevantControlForEveryStepType(AuthStep.Type type) throws Exception {
        var h = harness();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false), (entry, recovery, deadline, cancelled) -> {
            var step = entry.definition().steps().getFirst();
            throw new AuthenticationFailure(AuthenticationFailure.Phase.STEP, AuthenticationFailure.Cause.STEP_TIMEOUT, "The action timed out.")
                    .atStep(new AuthenticationFailure.Step(step.id(), 1, step.type()));
        })) {
            open(h, editor, editor.registry.snapshot().resolve("employee").identity().key());
            h.edt(() -> {
                var panel = (StepsPanel) h.member(editor.ui, "steps"); var id = UUID.randomUUID();
                try (var values = SecretStore.Values.empty()) {
                    panel.setSteps(List.of(new AuthStep.Definition(id, type, type.requiresSelector() ? "#fixture" : null,
                            type == AuthStep.Type.INPUT ? "synthetic" : null,
                            type == AuthStep.Type.WAIT_SELECTOR ? "visible" : type == AuthStep.Type.WAIT_LOAD_STATE ? "load" : type == AuthStep.Type.WAIT_URL ? "exact" : null,
                            type == AuthStep.Type.WAIT_URL ? "https://login.example/done" : null, type == AuthStep.Type.WAIT_TIME ? 0 : null)), values);
                }
                h.call(editor.ui, "edited", new Class<?>[]{});
                ((JTabbedPane) h.member(editor.ui, "wizard")).setSelectedIndex(4);
                ((JButton) h.member(editor.ui, "testButton")).doClick(0);
            });
            h.await(() -> !editor.clock.workers.isEmpty()); editor.clock.runWorker();
            h.await(() -> { try {
                List<?> rows = h.member((StepsPanel) h.member(editor.ui, "steps"), "rows");
                String expected = type.requiresSelector() ? "selector" : type == AuthStep.Type.WAIT_LOAD_STATE ? "state" : "value";
                return ((JTextArea) ((JComponent) h.member(rows.getFirst(), expected)).getClientProperty("validationMessage")).isVisible();
            } catch (Exception error) { return false; } });
            h.edt(() -> {
                List<?> rows = h.member((StepsPanel) h.member(editor.ui, "steps"), "rows"); Object row = rows.getFirst();
                String expected = type.requiresSelector() ? "selector" : type == AuthStep.Type.WAIT_LOAD_STATE ? "state" : "value";
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
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false), (entry, recovery, deadline, cancelled) -> {
            if (mode.equals("dns")) throw BrowserFailureClassifier.networkFailure("ERR_NAME_NOT_RESOLVED");
            if (mode.equals("proxy")) throw BrowserFailureClassifier.networkFailure("ERR_PROXY_CONNECTION_FAILED");
            if (mode.equals("service")) throw new AuthenticationFailure(AuthenticationFailure.Phase.SETUP, AuthenticationFailure.Cause.ASSET_MISSING, "The browser asset is missing.");
            var collector = new TokenExtractor(entry.definition().extraction(), TokenExtractorTest.CLOCK);
            collector.collectCookies(url -> mode.equals("cookie")
                    ? List.of(new com.microsoft.playwright.options.Cookie("sid", "a").setDomain("login.example").setPath("/"), new com.microsoft.playwright.options.Cookie("sid", "b").setDomain(".login.example").setPath("/"))
                    : List.of(new com.microsoft.playwright.options.Cookie("sid", "a").setDomain("login.example").setPath("/")));
            if (mode.equals("json")) collector.considerResponse("https://login.example/token", "{}".getBytes(java.nio.charset.StandardCharsets.UTF_8), true);
            collector.result(); throw new AssertionError("The fixture must fail extraction");
        })) {
            open(h, editor, editor.registry.snapshot().resolve("employee").identity().key());
            h.edt(() -> {
                ((CredentialsPanel) h.member(editor.ui, "credentials")).setInputs(List.of(
                        new JourneyDraft.CredentialInput("session", "cookie", "https://login.example/", "", "sid", "", "", "", "", "disabled", ""),
                        new JourneyDraft.CredentialInput("csrf", "json_path", "https://login.example", "/token", "token", "", "", "", "", "bearer", "")));
                h.call(editor.ui, "edited", new Class<?>[]{}); ((JTabbedPane) h.member(editor.ui, "wizard")).setSelectedIndex(4);
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
                int expectedTab = mode.equals("service") ? 4 : mode.equals("dns") || mode.equals("proxy") ? 0 : 2;
                assertEquals(expectedTab, ((JTabbedPane) h.member(editor.ui, "wizard")).getSelectedIndex());
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
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
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
            try (var saved = ConfigManager.parseNative(editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY), ConfigManager.DocumentKind.PROJECT)) {
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
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
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
            try (var saved = ConfigManager.parseNative(editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY), ConfigManager.DocumentKind.PROJECT)) {
                assertEquals("new-login", saved.journeys().getFirst().alias());
                assertEquals("New login", saved.journeys().getFirst().displayName());
            }
        }
    }

    @Test void executionSavesInvalidEditsThenShowsValidationWithoutStartingLogin() throws Exception {
        var h = harness();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); open(h, editor, key);
            String previous = editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY);
            h.edt(() -> {
                editor.fields().get("name").setText("");
                ((JButton) h.member(editor.ui, "testButton")).doClick(0);
            });
            h.await(() -> { try { return editor.status().startsWith("Display name"); } catch (Exception error) { return false; } });
            assertNotEquals(previous, editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY)); assertTrue(editor.clock.workers.isEmpty());
            try (var saved = ConfigManager.parseNative(editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY), ConfigManager.DocumentKind.PROJECT)) {
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
            try (var saved = ConfigManager.parseNative(editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY), ConfigManager.DocumentKind.PROJECT)) {
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
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
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
            String savedJson = editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY);
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
            try (var saved = ConfigManager.parseNative(editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY), ConfigManager.DocumentKind.PROJECT)) {
                assertNull(saved.journeys().getFirst().draft()); assertEquals("https://login.example/login", saved.journeys().getFirst().authenticationUrl().toString());
            }
        }
    }

    @Test void unfinishedJourneyKeepsSecureInputsSeparateAndRemapsThemOnImport() throws Exception {
        var h = harness();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); open(h, editor, key);
            h.edt(() -> {
                editor.fields().get("url").setText("");
                StepsPanel panel = h.member(editor.ui, "steps"); List<?> rows = h.member(panel, "rows"); Object row = rows.getFirst();
                ((JPasswordField) h.member(row, "secret")).setText("owned-draft-secret");
                h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false);
            });
            h.await(() -> { try { return editor.saved(); } catch (Exception error) { return false; } });
            assertFalse(editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY).contains("owned-draft-secret"));
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
                assertFalse(ConfigManager.nativeToJson(imported).contains("owned-draft-secret"));
            }
            open(h, editor, key);
            h.edt(() -> { StepsPanel panel = h.member(editor.ui, "steps"); List<?> rows = h.member(panel, "rows"); assertArrayEquals("owned-draft-secret".toCharArray(), ((JPasswordField) h.member(rows.getFirst(), "secret")).getPassword()); });
        }
    }

    @Test void editsAutosaveWithoutStatusFeedbackAndSuccessfulWritesAreCoalescedInTheLog() throws Exception {
        var h = harness();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); open(h, editor, key);
            h.edt(() -> { editor.fields().get("name").setText("Automatic edit"); editor.fields().get("navTimeout").setText("unfinished"); });
            h.await(() -> { try { return editor.saved(); } catch (Exception error) { return false; } });
            try (var saved = ConfigManager.parseNative(editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY), ConfigManager.DocumentKind.PROJECT)) {
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
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
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
            try (var saved = ConfigManager.parseNative(editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY), ConfigManager.DocumentKind.PROJECT)) { assertEquals("Latest edit", saved.journeys().getFirst().displayName()); }
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
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); open(h, editor, key);
            h.edt(() -> { editor.fields().get("name").setText("Final automatic save"); editor.fields().get("url").setText(""); editor.ui.shutdown(); });
            editor.ui.awaitSaves(5000);
            try (var saved = ConfigManager.parseNative(editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY), ConfigManager.DocumentKind.PROJECT)) {
                assertEquals("Final automatic save", saved.journeys().getFirst().displayName()); assertEquals("", saved.journeys().getFirst().draft().text().get("url"));
            }
        }
    }

    @Test void actualPausedJourneyFeedbackKeepsCauseAndAttemptsAcrossAutosaveThenExplicitTestResumes() throws Exception {
        var h = harness(); var clock = new java.util.concurrent.atomic.AtomicReference<CoordinatorFixtures.ManualRuntime>();
        var failed = new java.util.concurrent.atomic.AtomicBoolean(); var attempts = new java.util.concurrent.atomic.AtomicInteger();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false), (entry, recovery, deadline, cancelled) -> {
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
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); open(h, editor, key);
            String replacement = JourneyRegistryTest.edit(editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY), "", "revision", UUID.randomUUID().toString());
            editor.disk.put(ConfigManager.NATIVE_PROJECT_KEY, replacement);
            h.edt(() -> {
                editor.fields().get("name").setText("Updated account");
                ((JButton) h.member(editor.ui, "testButton")).doClick(0);
            });
            h.await(() -> { try { return editor.coordinator.events().snapshot(key).stream().anyMatch(e -> e.level() == JourneyEventLog.Level.ERROR && e.message().contains("Storage changed")); } catch (Exception error) { return false; } });
            assertEquals(replacement, editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY)); assertTrue(editor.clock.workers.isEmpty());
            assertEquals("Employee", editor.registry.snapshot().resolve(key).definition().displayName());
        }
    }
}
