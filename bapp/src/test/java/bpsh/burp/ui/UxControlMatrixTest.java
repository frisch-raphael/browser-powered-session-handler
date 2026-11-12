package bpsh.burp.ui;

import bpsh.journey.persistence.JourneyDocument;
import bpsh.journey.persistence.JourneyJson;

import bpsh.request.RequestSettings;
import bpsh.journey.persistence.ProjectStore;
import bpsh.journey.editing.JourneyDraftCompiler;
import bpsh.authentication.credentials.CombinedCredentialsTest;
import bpsh.journey.AuthStep;
import bpsh.journey.ConfigurationException;
import bpsh.journey.CredentialNames;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.JourneyDraft;
import bpsh.journey.JourneyKey;
import bpsh.journey.JourneyNames;
import bpsh.journey.SecretStore;
import java.awt.Component;
import java.awt.Container;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;
import javax.swing.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises actual local Swing actions across the finite mode-transition matrix. */
class UxControlMatrixTest {
    @Test void allActionFieldsRenderAtCompactAndWideEditorWidths() throws Exception {
        var h = harness(); h.edt(() -> {
            var output = Path.of("build", "ui-previews", "recording-actions"); java.nio.file.Files.createDirectories(output);
            var panel = new StepsPanel();
            try (var values = SecretStore.Values.empty()) {
                for (var type : AuthStep.Type.values()) {
                    var operation = type == AuthStep.Type.SELECT_OPTIONS ? new JourneyDraft.Options(List.of("", "admin")) : JourneyDraft.defaultOperation(type);
                    panel.setDraft(List.of(new JourneyDraft.StepInput(UUID.randomUUID(), type, "#field", "", "load", JourneyDraft.DurationUnit.SECONDS, operation)), values);
                    List<?> rows = h.member(panel, "rows"); var row = (JPanel) rows.getFirst();
                    for (int width : new int[]{640, 940}) {
                        panel.setSize(width, 520); layout(panel);
                        assertTrue(row.getPreferredSize().width <= width, type.label() + " must fit the editor width");
                        var image = new java.awt.image.BufferedImage(width, 520, java.awt.image.BufferedImage.TYPE_INT_RGB);
                        var graphics = image.createGraphics(); panel.printAll(graphics); graphics.dispose();
                        javax.imageio.ImageIO.write(image, "png", output.resolve(type.wire() + "-" + width + ".png").toFile());
                    }
                }
            }
            panel.clear();
        });
    }
    @Test void optionRowsRetainLiteralValuesAndActiveEditsAndUndoRestoresTheirPayload() throws Exception {
        var h = harness(); h.edt(() -> {
            var panel = new StepsPanel(); var id = UUID.randomUUID();
            var input = new JourneyDraft.StepInput(id, AuthStep.Type.SELECT_OPTIONS, "#roles", "", "", JourneyDraft.DurationUnit.SECONDS,
                    new JourneyDraft.Options(List.of("", "blue,green")));
            try (var values = SecretStore.Values.empty()) { panel.setDraft(List.of(input), values); }
            List<?> rows = h.member(panel, "rows"); Object row = rows.getFirst(); JTable table = h.member(row, "options");
            assertEquals("", table.getValueAt(0, 0)); assertEquals("blue,green", table.getValueAt(1, 0));
            assertTrue(table.getToolTipText().contains("not the visible labels"));
            assertTrue(table.editCellAt(1, 0)); ((JTextField) table.getEditorComponent()).setText(" changed value ");
            try (var snapshot = panel.snapshot()) {
                assertEquals(new JourneyDraft.Options(List.of("", " changed value ")), snapshot.inputs.getFirst().operation());
                assertTrue(table.isEditing(), "Autosave capture must not commit or move focus");
            }
            table.getCellEditor().stopCellEditing();
            ((JComboBox<?>) h.member(row, "type")).setSelectedItem(AuthStep.Type.CLICK);
            try (var snapshot = panel.snapshot()) { assertNull(snapshot.inputs.getFirst().operation()); }
            ((JButton) h.member(panel, "undoStep")).doClick(0);
            try (var snapshot = panel.snapshot()) { assertEquals(new JourneyDraft.Options(List.of("", " changed value ")), snapshot.inputs.getFirst().operation()); }
        });
    }

    @Test void newCheckedRowsRequireAChoiceAndTypeChangesClearHiddenOperationFields() throws Exception {
        var h = harness(); h.edt(() -> {
            var panel = new StepsPanel(); ((JComboBox<?>) h.member(panel, "typePicker")).setSelectedItem(AuthStep.Type.SET_CHECKED);
            ((JButton) h.member(panel, "addStep")).doClick(0);
            List<?> rows = h.member(panel, "rows"); Object row = rows.getFirst();
            try (var snapshot = panel.snapshot()) { assertEquals(new JourneyDraft.Checked(""), snapshot.inputs.getFirst().operation()); }
            ((JComboBox<?>) h.member(row, "checked")).setSelectedItem("false");
            try (var snapshot = panel.snapshot()) { assertEquals(new JourneyDraft.Checked("false"), snapshot.inputs.getFirst().operation()); }
            var picker = (JComboBox<?>) h.member(row, "type"); picker.setSelectedItem(AuthStep.Type.PRESS_KEY);
            ((JComboBox<?>) h.member(row, "key")).setSelectedItem("Shift+Tab"); picker.setSelectedItem(AuthStep.Type.CLICK); picker.setSelectedItem(AuthStep.Type.PRESS_KEY);
            try (var snapshot = panel.snapshot()) { assertEquals(new JourneyDraft.Key("Enter"), snapshot.inputs.getFirst().operation()); }
            assertTrue(((JComboBox<?>) h.member(row, "key")).getAccessibleContext().getAccessibleDescription().contains("Shift+Tab"));
        });
    }
    @Test void everySupportedKeySurvivesEditorPopulationAndSelection() throws Exception {
        var h = harness(); h.edt(() -> {
            var panel = new StepsPanel();
            for (String key : List.of("Enter", "Control+Enter", "Tab", "Shift+Tab")) {
                var definition = new AuthStep.Definition(UUID.randomUUID(), AuthStep.Type.PRESS_KEY, "#field", null, null, null, null, new AuthStep.Key(key));
                try (var values = SecretStore.Values.empty()) { panel.setSteps(List.of(definition), values); }
                try (var snapshot = panel.snapshot()) { assertEquals(new JourneyDraft.Key(key), snapshot.inputs.getFirst().operation()); }
                List<?> rows = h.member(panel, "rows"); ((JComboBox<?>) h.member(rows.getFirst(), "key")).setSelectedItem("Tab");
                try (var snapshot = panel.snapshot()) { assertEquals(new JourneyDraft.Key("Tab"), snapshot.inputs.getFirst().operation()); }
            }
        });
    }
    @Test void emptyStepsAndUndoRestoreOnlyTheChangedRowAndItsSecret() throws Exception {
        var h = harness(); h.edt(() -> {
            var panel = new StepsPanel(); var first = UUID.randomUUID(); var second = UUID.randomUUID();
            JTextArea empty = h.member(panel, "emptyHint"); assertTrue(empty.getText().contains("Add the actions needed to sign in")); assertTrue(empty.getText().contains("without further interaction")); assertNotNull(empty.getParent());
            try (var values = new SecretStore.Values(null, Map.of(first, "synthetic-secret".toCharArray()))) {
                panel.setSteps(List.of(new AuthStep.Definition(first, AuthStep.Type.SECURE_INPUT, "#password", null, null, null, null), new AuthStep.Definition(second, AuthStep.Type.INPUT, "#user", "before", null, null, null)), values);
            }
            List<?> rows = h.member(panel, "rows"); Object a = rows.getFirst(), b = rows.getLast();
            ((JButton) h.member(a, "remove")).doClick(0); ((JTextField) h.member(b, "value")).setText("after");
            JButton undo = h.member(panel, "undoStep"); assertNotNull(undo.getIcon()); assertTrue(undo.getText() == null || undo.getText().isEmpty());
            assertEquals("Undo", undo.getAccessibleContext().getAccessibleName()); assertTrue(undo.getToolTipText().contains("Alt+Backspace"));
            ((JButton) h.member(panel, "undoStep")).doClick(0);
            try (var snapshot = panel.snapshot()) { assertEquals(List.of(first, second), snapshot.inputs.stream().map(JourneyDraft.StepInput::id).toList()); assertEquals("after", snapshot.inputs.get(1).value()); assertArrayEquals("synthetic-secret".toCharArray(), snapshot.secrets.get(first)); }
            rows = h.member(panel, "rows"); a = rows.getFirst(); ((JComboBox<?>) h.member(a, "type")).setSelectedItem(AuthStep.Type.CLICK);
            try (var snapshot = panel.snapshot()) { assertFalse(snapshot.secrets.containsKey(first)); }
            ((JButton) h.member(panel, "undoStep")).doClick(0);
            try (var snapshot = panel.snapshot()) { assertEquals(AuthStep.Type.SECURE_INPUT, snapshot.inputs.getFirst().type()); assertTrue(snapshot.secrets.containsKey(first)); }
            panel.clear(); assertFalse(((JButton) h.member(panel, "undoStep")).isEnabled()); assertNotNull(empty.getParent());
        });
    }
    @Test void legacyWaitDraftsAndNewSecondsInputsKeepTheSameExecutableDuration() throws Exception {
        var h = harness(); h.edt(() -> {
            var panel = new StepsPanel(); var id = UUID.randomUUID();
            try (var values = SecretStore.Values.empty()) { panel.setDraft(List.of(new JourneyDraft.StepInput(id, AuthStep.Type.WAIT_TIME, "", "1500", "load")), values); }
            List<?> rows = h.member(panel, "rows"); JTextField value = h.member(rows.getFirst(), "value"); assertEquals("1.5", value.getText());
            try (var snapshot = panel.snapshot()) { assertEquals(1500, snapshot.definitions().getFirst().durationMs()); assertEquals(JourneyDraft.DurationUnit.SECONDS, snapshot.inputs.getFirst().durationUnit()); }
            value.setText("0.125"); try (var snapshot = panel.snapshot()) { assertEquals(125, snapshot.definitions().getFirst().durationMs()); }
            value.setText("0.0001"); try (var snapshot = panel.snapshot()) { assertThrows(IllegalArgumentException.class, snapshot::definitions); }
        });
    }
    @Test void newJourneyHasEmptyCaptureInputsAndNavigationAllowsIncompleteSettings() throws Exception {
        var h = harness(); try (var editor = h.new Editor(null)) {
            h.edt(() -> {
                h.call(editor.ui, "newJourney", new Class<?>[]{});
                var inputs = ((CredentialsPanel) h.member(editor.ui, "credentials")).snapshot(); assertEquals("", inputs.getFirst().origin()); assertEquals("", inputs.getFirst().selector()); assertEquals("", inputs.getFirst().path());
                h.call(editor.ui, "moveWizard", new Class<?>[]{int.class}, 1); assertEquals("Login steps", WizardTestPages.selected(((JTabbedPane) h.member(editor.ui, "wizard")))); assertTrue(editor.clock.workers.isEmpty());
            });
        }
    }
    @org.junit.jupiter.api.io.TempDir Path root;
    /** @return Temporary component harness with no installed-application automation. */
    private JourneyRegistryTest.NativeUi harness() { var h = new JourneyRegistryTest().new NativeUi(); h.root = root; return h; }
    /** @return Every ordered pair, including choosing the already-selected step type. */
    static Stream<Arguments> stepTypes() { return Stream.of(AuthStep.Type.values()).flatMap(a -> Stream.of(AuthStep.Type.values()).map(b -> Arguments.of(a, b))); }
    /** @return Every ordered JSON/cookie/regex source transition. */
    static Stream<Arguments> sourceTypes() { return Stream.of(0, 1, 2).flatMap(a -> Stream.of(0, 1, 2).map(b -> Arguments.of(a, b))); }
    /** @return Credential-name boundaries, syntax errors and literal markup. */
    static Stream<Arguments> credentialNames() {
        return Stream.of(Arguments.of("", "Enter a credential name."), Arguments.of("   ", "Enter a credential name."),
                Arguments.of("access.token", "Use only A-Z, a-z, 0-9, underscores or hyphens."), Arguments.of("my token", "Use only A-Z, a-z, 0-9, underscores or hyphens."),
                Arguments.of("token@1", "Use only A-Z, a-z, 0-9, underscores or hyphens."), Arguments.of("<html>token", "Use only A-Z, a-z, 0-9, underscores or hyphens."),
                Arguments.of("caf\u00e9", "Use only A-Z, a-z, 0-9, underscores or hyphens."), Arguments.of("token\ud83d\udd11", "Use only A-Z, a-z, 0-9, underscores or hyphens."),
                Arguments.of("_token", "Start with a letter or digit."), Arguments.of("-token", "Start with a letter or digit."),
                Arguments.of("a".repeat(65), "Use 64 characters or fewer."), Arguments.of("a".repeat(64), null),
                Arguments.of("0", null), Arguments.of(" Access_Token-1 ", null));
    }
    /** @return Exact duration boundaries plus malformed and sub-millisecond settings. */
    static Stream<Arguments> waitingDurations() {
        return Stream.of("request", "attempt", "cycle").flatMap(key -> {
            String max = key.equals("request") ? "600" : key.equals("attempt") ? "300" : "1800";
            return Stream.of(Arguments.of(key, "1", true), Arguments.of(key, max, true), Arguments.of(key, "61.501", true),
                    Arguments.of(key, "0.999", false), Arguments.of(key, Integer.toString(Integer.parseInt(max) + 1), false),
                    Arguments.of(key, "", false), Arguments.of(key, "-1", false), Arguments.of(key, "not-a-duration", false),
                    Arguments.of(key, "1.0001", false), Arguments.of(key, "999999999999", false));
        });
    }
    /** @return Duration/integer endpoints, neighbours, missing values, overflow and fractional precision. */
    static Stream<Arguments> journeyNumbers() {
        return Stream.of(new String[]{"navTimeout", "1", "300", "Browser action timeout"},
                new String[]{"tokenWait", "0.001", "300", "Final capture wait"},
                new String[]{"maxAge", "5", "86400", "Maximum cache age"},
                new String[]{"skew", "0", "3600", "Refresh before expiry"}).flatMap(spec -> {
                    boolean duration = spec[0].equals("navTimeout") || spec[0].equals("tokenWait");
                    var step = new java.math.BigDecimal(duration ? "0.001" : "1");
                    return Stream.of(Arguments.of(spec[0], spec[1], true, spec[3]), Arguments.of(spec[0], spec[2], true, spec[3]),
                            Arguments.of(spec[0], new java.math.BigDecimal(spec[1]).subtract(step).toPlainString(), false, spec[3]),
                            Arguments.of(spec[0], new java.math.BigDecimal(spec[2]).add(step).toPlainString(), false, spec[3]),
                            Arguments.of(spec[0], "", false, spec[3]), Arguments.of(spec[0], "1.5", duration, spec[3]),
                            Arguments.of(spec[0], "1.0001", false, spec[3]),
                            Arguments.of(spec[0], "abc", false, spec[3]), Arguments.of(spec[0], "9999999999999", false, spec[3]));
                });
    }
    /** @return Every automatic HTTP-tool selection, including none and all. */
    static Stream<Arguments> toolSelections() { return java.util.stream.IntStream.range(0, 32).mapToObj(Arguments::of); }


    /** @return All recovery-mode transitions, including reselection. */
    static Stream<Arguments> recoveryModes() { return Stream.of(JourneyDefinition.RecoveryMode.values()).flatMap(a -> Stream.of(JourneyDefinition.RecoveryMode.values()).map(b -> Arguments.of(a, b))); }
    /** @return Setup input boundaries and URL-only proxy shapes, including redacted embedded credentials. */
    static Stream<Arguments> setupInputs() {
        return Stream.of(Arguments.of("name", "", false, "Display name"), Arguments.of("name", "x".repeat(129), false, "Display name"), Arguments.of("name", "x".repeat(128), true, "Display name"),
                Arguments.of("url", "", false, "Login URL"), Arguments.of("url", "/login", false, "Login URL"), Arguments.of("url", "file:///test", false, "Login URL"), Arguments.of("url", "https://user:synthetic-password@login.example", false, "Login URL"), Arguments.of("url", "http://localhost:0/login", false, "Login URL"), Arguments.of("url", "http://localhost:65536/login", false, "Login URL"), Arguments.of("url", "http://[::1]:8443/login?query=value#fragment", true, "Login URL"),
                Arguments.of("proxy", "", true, "Proxy URL"), Arguments.of("proxy", "http://127.0.0.1:8080", true, "Proxy URL"), Arguments.of("proxy", "http://LOCALHOST:8080/", true, "Proxy URL"), Arguments.of("proxy", "https://localhost:8080", false, "Proxy URL"), Arguments.of("proxy", "socks5://localhost:1080", false, "Proxy URL"), Arguments.of("proxy", "http://user:synthetic-password@localhost:8080", false, "Proxy URL"), Arguments.of("proxy", "http://localhost:8080/path", false, "Proxy URL"), Arguments.of("proxy", "http://localhost:8080?query", false, "Proxy URL"));
    }

    @ParameterizedTest @MethodSource("setupInputs")
    void setupSavePreservesUnfinishedInputsAndExecutionReportsErrorsWithoutLeakingValues(String key, String value, boolean valid, String caption) throws Exception {
        var h = harness(); try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            var original = editor.registry.snapshot().resolve("employee");
            h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, original.identity().key()));
            h.await(() -> { try { return original.identity().key().equals(h.member(editor.ui, "editing")) && !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception ex) { return false; } });
            String before = editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY);
            h.edt(() -> { editor.fields().get(key).setText(value); h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false); });
            h.await(() -> { try { String feedback = editor.status(); return editor.saved() || feedback.startsWith(caption); } catch (Exception ex) { return false; } });
            if (valid) {
                var saved = editor.registry.snapshot().entries().get(original.identity().key()).definition();
                switch (key) { case "name" -> { assertEquals(value, saved.displayName()); assertEquals(JourneyNames.alias(value), saved.alias()); } case "url" -> assertEquals(value, saved.authenticationUrl().toString()); default -> { if (value.isEmpty()) assertNull(saved.browser().proxy()); else assertNotNull(saved.browser().proxy()); } }
            } else {
                assertNotEquals(before, editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY));
                assertEquals(value, editor.registry.snapshot().entries().get(original.identity().key()).definition().draft().text().get(key));
                assertTrue(editor.saved(), editor.status());
                h.edt(() -> ((JButton) h.member(editor.ui, "testButton")).doClick(0));
                h.await(() -> { try { return editor.status().startsWith(caption); } catch (Exception error) { return false; } });
                assertFalse(editor.status().contains("synthetic-password")); assertTrue(editor.clock.workers.isEmpty());
            }
        }
    }

    @ParameterizedTest @MethodSource("toolSelections")
    void everyHttpToolSelectionSavesWithoutChangingWaitingSettings(int mask) throws Exception {
        var h = harness(); try (var editor = h.new Editor(null)) {
            var expected = new java.util.ArrayList<RequestSettings.Tool>();
            h.edt(() -> {
                editor.checks().get("enabled").doClick(); Map<RequestSettings.Tool, JCheckBox> tools = h.member(editor.ui, "tools");
                for (int i = 0; i < RequestSettings.SUPPORTED_TOOLS.size(); i++) {
                    var tool = RequestSettings.SUPPORTED_TOOLS.get(i); boolean selected = (mask & (1 << i)) != 0;
                    if (selected) expected.add(tool); if (tools.get(tool).isSelected() != selected) tools.get(tool).doClick();
                }
                h.call(editor.ui, "saveControls", new Class<?>[]{boolean.class}, false);
            });
            h.await(() -> { try { return editor.disk.containsKey(ProjectStore.NATIVE_PROJECT_KEY) && editor.controls.snapshot().controls().enabled() && editor.controls.snapshot().controls().tools().equals(expected); } catch (Exception ex) { return false; } });
            assertEquals(expected, editor.controls.snapshot().controls().tools()); assertEquals(60_000, editor.controls.snapshot().controls().requestWaitTimeoutMs());
        }
    }

    @Test void finiteLimitsSaveAndRemainVisible() throws Exception {
        var h = harness(); try (var editor = h.new Editor(null)) {
            h.edt(() -> {
                assertEquals("64", editor.fields().get("control.global").getText());
                assertEquals("16", editor.fields().get("control.per").getText());
                editor.fields().get("control.global").setText("5");
                editor.fields().get("control.per").setText("2");
                h.call(editor.ui, "saveControls", new Class<?>[]{boolean.class}, true);
            });
            h.await(() -> editor.controls.snapshot().controls().maxWaitingRequestsGlobal() == 5 && editor.controls.snapshot().controls().maxWaitingRequestsPerJourney() == 2);
            h.edt(() -> {
                assertTrue(editor.fields().get("control.global").isVisible());
                assertTrue(editor.fields().get("control.per").isVisible());
            });
        }
    }

    @ParameterizedTest @MethodSource("recoveryModes")
    void recoveryTransitionsShowOnlyTheirInputsAndKeepUnchangedModeValues(JourneyDefinition.RecoveryMode from, JourneyDefinition.RecoveryMode to) throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var panel = new AutomaticRulesPanel(); var key = new RequestSettings.JourneySelection(JourneyDefinition.Scope.PROJECT, UUID.randomUUID());
            panel.setRules(List.of(new RequestSettings.AutomaticRule(true, key, new RequestSettings.BurpScope(), null, new JourneyDefinition.Recovery(true, from, from == JourneyDefinition.RecoveryMode.REGEX ? null : 403, from == JourneyDefinition.RecoveryMode.STATUS_CODE ? null : "expired"))));
            panel.recoveryMode.setSelectedItem(to);
            assertEquals(to != JourneyDefinition.RecoveryMode.REGEX, panel.failureStatus.isVisible());
            assertEquals(to != JourneyDefinition.RecoveryMode.STATUS_CODE, panel.pattern.isVisible());
            if (to == from && from != JourneyDefinition.RecoveryMode.REGEX) assertEquals("403", panel.failureStatus.getText());
            if (to == from && from != JourneyDefinition.RecoveryMode.STATUS_CODE) assertEquals("expired", panel.pattern.getText());
            panel.detect.doClick(); assertFalse(panel.recoveryMode.isVisible()); assertFalse(panel.pattern.isVisible()); assertFalse(panel.failureStatus.isVisible());
        });
    }

    @ParameterizedTest @MethodSource("journeyNumbers")
    void savePreservesEveryNumericFieldAndExecutionValidatesIt(String key, String value, boolean valid, String caption) throws Exception {
        var h = harness(); try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            var entry = editor.registry.snapshot().resolve("employee");
            h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, entry.identity().key()));
            h.await(() -> { try { return entry.identity().key().equals(h.member(editor.ui, "editing")) && !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception ex) { return false; } });
            String before = editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY);
            h.edt(() -> { editor.fields().get(key).setText(value); h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false); });
            h.await(() -> { try { String feedback = editor.status(); return editor.saved() || feedback.startsWith(caption); } catch (Exception ex) { return false; } });
            if (valid) {
                var definition = editor.registry.snapshot().resolve("employee").definition();
                boolean duration = key.equals("navTimeout") || key.equals("tokenWait");
                int expected = new java.math.BigDecimal(value).movePointRight(duration ? 3 : 0).intValueExact();
                assertEquals(expected, switch (key) { case "navTimeout" -> definition.browser().navigationTimeoutMs(); case "tokenWait" -> definition.browser().tokenWaitTimeoutMs(); case "maxAge" -> definition.cache().maxAgeSeconds(); case "skew" -> definition.cache().refreshSkewSeconds(); default -> throw new AssertionError(key); });
                if (duration) {
                    h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, entry.identity().key()));
                    h.await(() -> { try { return !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception error) { return false; } });
                    assertEquals(0, new java.math.BigDecimal(value).compareTo(new java.math.BigDecimal(editor.fields().get(key).getText())));
                }
            } else {
                assertNotEquals(before, editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY));
                assertEquals(value, editor.registry.snapshot().resolve("employee").definition().draft().text().get(key));
                assertTrue(editor.saved(), editor.status());
                h.edt(() -> ((JButton) h.member(editor.ui, "testButton")).doClick(0));
                h.await(() -> { try { return editor.status().startsWith(caption); } catch (Exception error) { return false; } });
                assertTrue(editor.clock.workers.isEmpty());
                if (key.equals("navTimeout") || key.equals("tokenWait")) { assertTrue(editor.status().contains("seconds"), editor.status()); assertFalse(editor.status().contains("TimeoutMs")); }
            }
        }
    }

    @ParameterizedTest @MethodSource("waitingDurations")
    void waitingDurationsApplyOnlyValidExactSecondsAndReportHumanLabels(String key, String value, boolean valid) throws Exception {
        var h = harness(); try (var editor = h.new Editor(null)) {
            h.edt(() -> {
                editor.fields().get("control.request").setText("1"); editor.fields().get("control.attempt").setText("1"); editor.fields().get("control.cycle").setText("1800");
                h.call(editor.ui, "saveControls", new Class<?>[]{boolean.class}, true);
            });
            h.await(() -> editor.controls.snapshot().controls().requestWaitTimeoutMs() == 1000 && editor.controls.snapshot().controls().cycleTimeoutMs() == 1800000);
            var prior = editor.controls.snapshot().controls();
            h.edt(() -> { editor.fields().get("control." + key).setText(value); h.call(editor.ui, "saveControls", new Class<?>[]{boolean.class}, true); });
            if (valid) {
                int expected = new java.math.BigDecimal(value).movePointRight(3).intValueExact();
                h.await(() -> expected == switch (key) { case "request" -> editor.controls.snapshot().controls().requestWaitTimeoutMs(); case "attempt" -> editor.controls.snapshot().controls().attemptTimeoutMs(); default -> editor.controls.snapshot().controls().cycleTimeoutMs(); });
            } else {
                var feedbackText = new java.util.concurrent.atomic.AtomicReference<String>("");
                h.await(() -> { try { h.edt(() -> feedbackText.set(((JTextArea) editor.fields().get("control." + key).getClientProperty("validationMessage")).getText())); return !feedbackText.get().isBlank(); } catch (Exception error) { return false; } });
                assertEquals(prior, editor.controls.snapshot().controls()); String feedback = feedbackText.get();
                assertTrue(feedback.startsWith(switch (key) { case "request" -> "Request wait"; case "attempt" -> "Login attempt timeout"; default -> "Total login timeout"; }), feedback);
                assertFalse(feedback.contains("TimeoutMs")); assertFalse(feedback.contains("control."));
            }
        }
    }

    @ParameterizedTest @MethodSource("stepTypes")
    void stepTypeTransitionsKeepIdentityAndClearOnlyObsoleteInputs(AuthStep.Type from, AuthStep.Type to) throws Exception {
        var h = harness(); var id = UUID.randomUUID();
        try (var values = new SecretStore.Values(null, from == AuthStep.Type.SECURE_INPUT ? Map.of(id, "qa-secret".toCharArray()) : Map.of())) {
            h.edt(() -> {
                var panel = new StepsPanel(); panel.setSteps(List.of(new AuthStep.Definition(id, from, from.requiresSelector() ? "#field" : null, from == AuthStep.Type.INPUT ? "qa-text" : null, from == AuthStep.Type.WAIT_LOAD_STATE ? "load" : null, from == AuthStep.Type.WAIT_URL ? "**/done" : null, from == AuthStep.Type.WAIT_TIME ? 1500 : null)), values);
                List<?> rows = h.member(panel, "rows"); Object row = rows.getFirst();
                ((JComboBox<?>) h.member(row, "type")).setSelectedItem(to);
                try (var snapshot = panel.snapshot()) {
                    assertEquals(id, snapshot.inputs.getFirst().id()); assertEquals(to, snapshot.inputs.getFirst().type());
                    assertEquals(to.requiresSelector(), ((JPanel) h.member(row, "selectorLine")).isVisible());
                    assertEquals(to == AuthStep.Type.WAIT_LOAD_STATE || to == AuthStep.Type.WAIT_SELECTOR || to == AuthStep.Type.WAIT_URL, ((JPanel) h.member(row, "stateLine")).isVisible());
                    assertEquals(to == AuthStep.Type.INPUT || to == AuthStep.Type.WAIT_URL || to == AuthStep.Type.WAIT_TIME, ((JPanel) h.member(row, "valueLine")).isVisible());
                    if (to != AuthStep.Type.SECURE_INPUT) { assertTrue(snapshot.secrets.isEmpty()); assertEquals(0, ((JPasswordField) h.member(row, "secret")).getPassword().length); }
                    if (to != from && !to.requiresSelector()) assertEquals("", snapshot.inputs.getFirst().selector());
                }
                panel.clear(); assertEquals(0, ((JPasswordField) h.member(row, "secret")).getPassword().length);
            });
        }
    }

    @Test void moveButtonsReflectBoundariesAndReorderingPreservesStableStepIds() throws Exception {
        var h = harness(); h.edt(() -> {
            var panel = new StepsPanel(); var first = UUID.randomUUID(); var second = UUID.randomUUID();
            try (var values = SecretStore.Values.empty()) { panel.setSteps(List.of(new AuthStep.Definition(first, AuthStep.Type.WAIT_TIME, null, null, null, null, 1000), new AuthStep.Definition(second, AuthStep.Type.WAIT_TIME, null, null, null, null, 2000)), values); }
            List<?> rows = h.member(panel, "rows"); Object a = rows.getFirst(), b = rows.getLast();
            assertFalse(((JButton) h.member(a, "up")).isEnabled()); assertTrue(((JButton) h.member(a, "down")).isEnabled());
            assertTrue(((JButton) h.member(b, "up")).isEnabled()); assertFalse(((JButton) h.member(b, "down")).isEnabled());
            ((JButton) h.member(a, "down")).doClick();
            try (var snapshot = panel.snapshot()) { assertEquals(List.of(second, first), snapshot.definitions().stream().map(AuthStep.Definition::id).toList()); }
            assertFalse(((JButton) h.member(b, "up")).isEnabled()); assertFalse(((JButton) h.member(a, "down")).isEnabled());
            find((Component) a, "Remove step").doClick(); assertFalse(((JButton) h.member(b, "up")).isEnabled()); assertFalse(((JButton) h.member(b, "down")).isEnabled());
            find((Component) b, "Remove step").doClick(); try (var snapshot = panel.snapshot()) { assertTrue(snapshot.inputs.isEmpty()); }
        });
    }

    @ParameterizedTest @MethodSource("sourceTypes")
    void sourceTypeTransitionsAndReselectionRespectFieldOwnership(int from, int to) throws Exception {
        var h = harness(); h.edt(() -> {
            var panel = new CredentialsPanel(); panel.setDefinition(CombinedCredentialsTest.JSON);
            List<?> rows = h.member(panel, "rows"); Object row = rows.getFirst(); var type = (JComboBox<?>) h.member(row, "type"); type.setSelectedIndex(from);
            ((JTextField) h.member(row, "origin")).setText("https://login.example"); ((JTextField) h.member(row, "path")).setText("/token");
            ((JTextField) h.member(row, "selector")).setText(from == 1 ? "sid" : "access_token"); ((JTextField) h.member(row, "startRegex")).setText("begin:"); ((JTextField) h.member(row, "endRegex")).setText(":end");
            type.setSelectedIndex(to); var input = panel.snapshot().getFirst();
            assertEquals(to == 1, ((JPanel) h.member(row, "domainLine")).isVisible()); assertEquals(to == 2, ((JPanel) h.member(row, "startLine")).isVisible());
            assertEquals(to != 2, ((JPanel) h.member(row, "selectorLine")).isVisible()); assertEquals(to != 1, ((JPanel) h.member(row, "injectionLine")).isVisible());
            assertEquals(to != 1, ((JPanel) h.member(row, "usePanel")).isVisible());
            if (to == 1) {
                assertNull(type.getToolTipText());
                assertEquals("Capture the cookie with this name. Its value replaces the cookie with the same name in matching requests.", ((JTextField) h.member(row, "selector")).getToolTipText());
                assertEquals(((JTextField) h.member(row, "selector")).getToolTipText(), ((JLabel) h.member(row, "selectorLabel")).getToolTipText());
            }
            if (from == to) { assertEquals(from == 1 ? "sid" : "access_token", input.selector()); assertEquals("begin:", input.startRegex()); }
            else { assertEquals("", input.selector()); assertEquals("", input.startRegex()); assertEquals("", input.endRegex()); }
            if (to == 1) assertFalse(((JTextField) h.member(row, "origin")).getToolTipText().contains("response"));
            else assertFalse(((JTextField) h.member(row, "origin")).getToolTipText().contains("cookie"));
        });
    }

    @ParameterizedTest @MethodSource("credentialNames")
    void credentialNamesValidateOnBlurPreserveInputAndAgreeWithTheNativeCodec(String value, String problem) throws Exception {
        var h = harness(); h.edt(() -> {
            var panel = new CredentialsPanel(); panel.setDefinition(CombinedCredentialsTest.SOURCES, CombinedCredentialsTest.INJECTION);
            List<?> rows = h.member(panel, "rows"); JTextField name = h.member(rows.getFirst(), "name");
            name.setText(value); JTextArea error = (JTextArea) name.getClientProperty("validationMessage");
            assertFalse(error.isVisible(), "Unfinished input stays quiet until the field is left");
            var blur = new java.awt.event.FocusEvent(name, java.awt.event.FocusEvent.FOCUS_LOST);
            for (var listener : name.getFocusListeners()) listener.focusLost(blur);
            assertEquals(problem != null, error.isVisible());
            assertEquals(problem == null ? "" : problem, error.getText());
            assertEquals(problem == null ? name.getToolTipText() : problem, name.getAccessibleContext().getAccessibleDescription());
            assertEquals(value, panel.snapshot().getFirst().name(), "Feedback must preserve the entered text");
            assertTrue(name.getToolTipText().contains("1-64")); assertTrue(name.getToolTipText().contains("ignoring case"));
            String encoded = JourneyRegistryTest.edit(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false), "/journeys/0", "extraction", JourneyDraftCompiler.extractionNode(panel.snapshot()));
            encoded = JourneyRegistryTest.edit(encoded, "/journeys/0", "injection", JourneyDraftCompiler.injectionNode(panel.snapshot()));
            final String json = encoded;
            if (problem == null) {
                try (var parsed = JourneyJson.read(json, JourneyDocument.DocumentKind.PROJECT)) {
                    assertEquals(value.trim().toLowerCase(java.util.Locale.ROOT), ((JourneyDefinition.CombinedExtraction) parsed.journeys().getFirst().extraction()).tokens().getFirst().name());
                }
            } else {
                assertEquals("extraction.tokens[0].name: " + problem, assertThrows(ConfigurationException.class, () -> JourneyJson.read(json, JourneyDocument.DocumentKind.PROJECT)).getMessage());
                for (int width : new int[]{640, 980}) {
                    panel.setSize(width, 620); layout(panel);
                    JPanel nameLine = h.member(rows.getFirst(), "nameLine");
                    var bounds = SwingUtilities.convertRectangle(error.getParent(), error.getBounds(), nameLine);
                    assertTrue(bounds.y >= 0 && bounds.y + bounds.height <= nameLine.getHeight(), "The inline error must fit below its input");
                    assertTrue(name.getHeight() >= name.getPreferredSize().height, "Showing an error must not squeeze the input");
                }
                name.setText("_fixed"); assertEquals("Start with a letter or digit.", error.getText()); assertTrue(error.isVisible());
                name.setText("fixed_name"); assertFalse(error.isVisible()); assertEquals(name.getToolTipText(), name.getAccessibleContext().getAccessibleDescription());
            }
        });
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(ints = {0, 1})
    void remainingCredentialNameStaysEditableAfterAnotherCredentialIsRemoved(int removedIndex) throws Exception {
        var h = harness(); var panel = new CredentialsPanel();
        h.edt(() -> {
            panel.setDefinition(CombinedCredentialsTest.SOURCES, CombinedCredentialsTest.INJECTION);
            List<?> rows = h.member(panel, "rows");
            ((JTextField) h.member(rows.getFirst(), "name")).setText("renamed_access");
            ((JTextField) h.member(rows.getLast(), "name")).setText("renamed_session");
            Object remaining = rows.get(1 - removedIndex);
            ((JButton) h.member(rows.get(removedIndex), "remove")).doClick(0);
            assertTrue(((JPanel) h.member(remaining, "nameLine")).isVisible(), "The retained name must remain editable");
            ((JTextField) h.member(remaining, "name")).setText("");
        });
        h.edt(() -> {
            List<?> rows = h.member(panel, "rows"); assertEquals(1, rows.size());
            Object remaining = rows.getFirst();
            assertTrue(((JPanel) h.member(remaining, "nameLine")).isVisible(), "Clearing the name must not hide the field during editing");
            ((JTextField) h.member(remaining, "name")).setText("final_name");
            assertEquals("final_name", panel.snapshot().getFirst().name());
            assertTrue(((JToggleButton) h.member(remaining, "expanded")).getText().startsWith("final_name"));
            panel.setInputs(panel.snapshot());
            assertTrue(((JPanel) h.member(rows.getFirst(), "nameLine")).isVisible(), "Reloading a named single credential must keep its name editable");
            assertEquals("final_name", panel.snapshot().getFirst().name());
        });
    }

    @Test void duplicateCredentialErrorsFollowOtherNameEditsAndRemoval() throws Exception {
        var h = harness(); h.edt(() -> {
            var panel = new CredentialsPanel(); panel.setDefinition(CombinedCredentialsTest.SOURCES, CombinedCredentialsTest.INJECTION);
            List<?> rows = h.member(panel, "rows"); Object first = rows.getFirst(), second = rows.getLast();
            JTextField a = h.member(first, "name"), b = h.member(second, "name"); b.setText(" ACCESS ");
            JTextArea error = (JTextArea) b.getClientProperty("validationMessage"); assertFalse(error.isVisible());
            var blur = new java.awt.event.FocusEvent(b, java.awt.event.FocusEvent.FOCUS_LOST); for (var listener : b.getFocusListeners()) listener.focusLost(blur);
            assertEquals(CredentialNames.DUPLICATE, error.getText());
            a.setText("primary"); assertFalse(error.isVisible());
            a.setText("Access"); assertTrue(error.isVisible()); assertEquals(CredentialNames.DUPLICATE, error.getText());
            assertFalse(((JTextArea) a.getClientProperty("validationMessage")).isVisible(), "An untouched field should stay quiet");
            ((JButton) h.member(first, "remove")).doClick(0); assertFalse(error.isVisible()); assertTrue(((JPanel) h.member(second, "nameLine")).isVisible());
            assertNull(panel.validateNames());
        });
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(strings = {"testButton", "copyReferenceButton"})
    void testAndCopyRevealTheFirstInvalidCredentialNameAfterSavingTheDraft(String action) throws Exception {
        var h = harness(); try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            var original = editor.registry.snapshot().resolve("employee");
            h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, original.identity().key()));
            h.await(() -> { try { return original.identity().key().equals(h.member(editor.ui, "editing")) && !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception error) { return false; } });
            h.edt(() -> {
                CredentialsPanel panel = h.member(editor.ui, "credentials"); panel.setDefinition(CombinedCredentialsTest.SOURCES, CombinedCredentialsTest.INJECTION);
                List<?> rows = h.member(panel, "rows"); ((JTextField) h.member(rows.getFirst(), "name")).setText("bad.name"); ((JTextField) h.member(rows.getLast(), "name")).setText("_second");
                JTabbedPane wizard = h.member(editor.ui, "wizard"); wizard.setSelectedIndex(wizard.getTabCount() - 1);
                ((JButton) h.member(editor.ui, action)).doClick(0);
            });
            h.await(() -> { try { return editor.saved() && editor.status().startsWith("Credential 1:"); } catch (Exception error) { return false; } });
            h.edt(() -> {
                CredentialsPanel panel = h.member(editor.ui, "credentials"); List<?> rows = h.member(panel, "rows");
                assertEquals("Capture credentials", WizardTestPages.selected(((JTabbedPane) h.member(editor.ui, "wizard"))));
                assertTrue(((JToggleButton) h.member(rows.getFirst(), "expanded")).isSelected()); assertFalse(((JToggleButton) h.member(rows.getLast(), "expanded")).isSelected());
                assertTrue(((JTextArea) ((JTextField) h.member(rows.getFirst(), "name")).getClientProperty("validationMessage")).isVisible());
            });
            try (var parsed = JourneyJson.read(editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY), JourneyDocument.DocumentKind.PROJECT)) {
                assertEquals(List.of("bad.name", "_second"), parsed.journeys().getFirst().draft().credentials().stream().map(JourneyDraft.CredentialInput::name).toList());
            }
            assertTrue(editor.clock.workers.isEmpty(), "Invalid names must be caught before login or tag copying");
        }
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(strings = {"CSRF", ""})
    void credentialNameErrorsIdentifyTheExactNamedOrUnnamedRow(String secondName) throws Exception {
        var h = harness(); try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            var original = editor.registry.snapshot().resolve("employee");
            h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, original.identity().key()));
            h.await(() -> { try { return original.identity().key().equals(h.member(editor.ui, "editing")) && !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception error) { return false; } });
            h.edt(() -> {
                CredentialsPanel panel = h.member(editor.ui, "credentials"); panel.setDefinition(CombinedCredentialsTest.SOURCES, CombinedCredentialsTest.INJECTION);
                List<?> rows = h.member(panel, "rows");
                ((JTextField) h.member(rows.getFirst(), "name")).setText("csrf");
                ((JTextField) h.member(rows.getLast(), "name")).setText(secondName);
                ((JButton) h.member(editor.ui, "testButton")).doClick(0);
            });
            String expected = secondName.isEmpty() ? "Credential 2:" : "Credential 1 \"csrf\":";
            h.await(() -> { try { return editor.status().startsWith(expected); } catch (Exception error) { return false; } });
            h.edt(() -> {
                CredentialsPanel panel = h.member(editor.ui, "credentials"); List<?> rows = h.member(panel, "rows");
                Object invalidRow = secondName.isEmpty() ? rows.getLast() : rows.getFirst();
                assertTrue(((JToggleButton) h.member(invalidRow, "expanded")).isSelected());
                assertTrue(((JTextArea) ((JTextField) h.member(invalidRow, "name")).getClientProperty("validationMessage")).isVisible());
                assertFalse(((SessionStatusBar) h.member(editor.ui, "status")).isLogOpen());
            });
            assertTrue(editor.clock.workers.isEmpty());
        }
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.CsvSource({
            "json_path,origin,invalid", "json_path,path,''", "json_path,selector,broken[",
            "cookie,origin,invalid", "cookie,selector,bad name", "cookie,selector,''",
            "regex,origin,invalid", "regex,path,''", "regex,startRegex,[", "regex,endRegex,[",
            "json_path,destination,bad name", "json_path,destination,Cookie"})
    void testRevealsTheExactCaptureOrInjectionFieldInTheSecondCredential(String type, String field, String invalid) throws Exception {
        var h = harness(); try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            var key = editor.registry.snapshot().resolve("employee").identity().key();
            h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, key));
            h.await(() -> { try { return key.equals(h.member(editor.ui, "editing")) && !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception error) { return false; } });
            h.edt(() -> {
                CredentialsPanel panel = h.member(editor.ui, "credentials");
                var first = new JourneyDraft.CredentialInput("session", "cookie", "https://login.example/", "", "sid", "", "", "", "", "disabled", "");
                var second = new JourneyDraft.CredentialInput("csrf", type, "https://login.example", "/token", type.equals("cookie") ? "csrf-cookie" : "token", "", "", "<token>", "</token>", field.equals("destination") ? "header" : "disabled", "X-CSRF");
                panel.setInputs(List.of(first, second)); List<?> rows = h.member(panel, "rows");
                ((JTextField) h.member(rows.getLast(), field)).setText(invalid); h.call(editor.ui, "edited", new Class<?>[]{});
                WizardTestPages.select(((JTabbedPane) h.member(editor.ui, "wizard")), "Test & use"); ((JButton) h.member(editor.ui, "testButton")).doClick(0);
            });
            h.await(() -> { try {
                List<?> rows = h.member((CredentialsPanel) h.member(editor.ui, "credentials"), "rows");
                return ((JTextArea) ((JComponent) h.member(rows.getLast(), field)).getClientProperty("validationMessage")).isVisible();
            } catch (Exception error) { return false; } });
            h.edt(() -> {
                List<?> rows = h.member((CredentialsPanel) h.member(editor.ui, "credentials"), "rows");
                assertEquals("Capture credentials", WizardTestPages.selected(((JTabbedPane) h.member(editor.ui, "wizard"))));
                assertTrue(((JToggleButton) h.member(rows.getLast(), "expanded")).isSelected());
                assertFalse(((JTextArea) ((JComponent) h.member(rows.getFirst(), "selector")).getClientProperty("validationMessage")).isVisible());
                assertFalse(((SessionStatusBar) h.member(editor.ui, "status")).isLogOpen());
            });
            assertTrue(editor.clock.workers.isEmpty());
        }
    }

    @Test void choosingTheCurrentHeaderDestinationDoesNotEraseItsName() throws Exception {
        var h = harness(); h.edt(() -> {
            var panel = new CredentialsPanel(); panel.setDefinition(CombinedCredentialsTest.JSON); List<?> rows = h.member(panel, "rows"); Object row = rows.getFirst();
            var mode = (JComboBox<?>) h.member(row, "injection"); mode.setSelectedItem("Header"); ((JTextField) h.member(row, "destination")).setText("X-CSRF-Token");
            mode.setSelectedItem("Header"); assertEquals("X-CSRF-Token", panel.snapshot().getFirst().destination());
            mode.setSelectedItem("Cookie"); assertEquals("", panel.snapshot().getFirst().destination());
            assertTrue(((JPanel) h.member(row, "destinationLine")).isVisible());
            mode.setSelectedItem("Disabled"); assertFalse(((JPanel) h.member(row, "destinationLine")).isVisible());
        });
    }

    @Test void credentialCreationLimitAndRemovalHaveHonestButtonStates() throws Exception {
        var h = harness(); h.edt(() -> {
            var panel = new CredentialsPanel(); panel.setDefinition(CombinedCredentialsTest.JSON); var add = find(panel, "Add token or cookie");
            List<?> rows = h.member(panel, "rows"); assertFalse(((JButton) h.member(rows.getFirst(), "remove")).isEnabled());
            for (int i = 1; i < 16; i++) add.doClick(); assertEquals(16, panel.snapshot().size()); assertFalse(add.isEnabled());
            add.doClick(); assertEquals(16, panel.snapshot().size());
            ((JButton) h.member(rows.getLast(), "remove")).doClick(); assertEquals(15, panel.snapshot().size()); assertTrue(add.isEnabled());
        });
    }

    @Test void stepCreationStopsAtTheSupportedCountAndRemovalOrClearAllowsAnotherStep() throws Exception {
        var h = harness(); h.edt(() -> {
            var panel = new StepsPanel(); var add = find(panel, "Add step");
            for (int i = 0; i < 256; i++) add.doClick(0);
            List<?> rows = h.member(panel, "rows"); assertEquals(256, rows.size()); assertFalse(add.isEnabled());
            add.doClick(0); assertEquals(256, rows.size()); find((Component) rows.getLast(), "Remove step").doClick(0); assertEquals(255, rows.size()); assertTrue(add.isEnabled());
            add.doClick(0); assertFalse(add.isEnabled()); panel.clear(); assertTrue(add.isEnabled()); add.doClick(0); assertEquals(1, rows.size());
        });
    }

    @Test void disablingClientCertificateClearsAllInputsAndDisplayedCertificateDetails() throws Exception {
        var h = harness(); try (var editor = h.new Editor(null)) {
            h.edt(() -> {
                h.call(editor.ui, "newJourney", new Class<?>[]{}); editor.checks().get("mtls").doClick();
                editor.fields().get("module").setText("C:/owned-test/middleware.dll");
                var slotValue = UiController.class.getDeclaredField("slotValue"); slotValue.setAccessible(true); slotValue.set(editor.ui, "1");
                editor.fields().get("origins").setText("https://login.example"); editor.fields().get("ca").setText("C:/owned-test/ca.pem");
                ((JPasswordField) h.member(editor.ui, "pin")).setText("synthetic-pin");
                ((JTextArea) h.member(editor.ui, "certificateDetails")).setText("Subject: old fixture identity");
                editor.checks().get("mtls").doClick(); editor.checks().get("mtls").doClick();
                for (String key : List.of("module", "origins", "ca")) assertEquals("", editor.fields().get(key).getText(), key);
                assertFalse(editor.fields().containsKey("slot")); assertEquals("0", h.member(editor.ui, "slotValue"));
                assertFalse(editor.checks().containsKey("pinSupplied")); assertFalse(editor.fields().containsKey("fingerprint"));
                assertEquals("", h.member(editor.ui, "selectedCertificateSha256")); assertEquals(0, ((JPasswordField) h.member(editor.ui, "pin")).getPassword().length);
                assertFalse(((JTextArea) h.member(editor.ui, "certificateDetails")).getText().contains("old fixture"));
            });
        }
    }

    @Test void certificateDefaultsNeedNoManualServerAndAdvancedGroupsAdditionalServersAndTrustedCa() throws Exception {
        var h = harness();
        String stored = JourneyRegistryTest.edit(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false), "/journeys/0", "mtls",
                Map.of("modulePath", "C:/owned-test/middleware.dll", "certificateSha256", "a".repeat(64), "origins", List.of()));
        try (var editor = h.new Editor(stored)) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, key));
            h.await(() -> { try { return key.equals(h.member(editor.ui, "editing")) && !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception error) { return false; } });
            h.edt(() -> {
                JPanel advanced = h.member(editor.ui, "certificateAdvanced"); JToggleButton toggle = h.member(editor.ui, "certificateAdvancedToggle");
                assertFalse(advanced.isVisible()); assertFalse(toggle.isSelected()); assertEquals("", editor.fields().get("origins").getText());
                JTextField ca = editor.fields().get("ca");
                assertEquals("Add a PEM CA file if the login server's certificate isn't already trusted.", ca.getToolTipText());
                assertEquals(ca.getToolTipText(), ((JLabel) ca.getClientProperty("rowLabel")).getToolTipText());
                assertTrue(SwingUtilities.isDescendingFrom(ca, advanced)); assertTrue(SwingUtilities.isDescendingFrom(editor.fields().get("origins"), advanced));
                assertFalse(texts(editor.component).contains("Use login origin"));
                WizardTestPages.select(((JTabbedPane) h.member(editor.ui, "wizard")), "Client certificate");
                for (boolean expanded : new boolean[]{false, true}) {
                    if (toggle.isSelected() != expanded) toggle.doClick(0);
                    for (int width : new int[]{980, 1280}) {
                        editor.component.setSize(width, 820); layout(editor.component);
                        var rendered = new java.awt.image.BufferedImage(width, 820, java.awt.image.BufferedImage.TYPE_INT_RGB); var graphics = rendered.createGraphics(); editor.component.printAll(graphics); graphics.dispose();
                        var output = java.nio.file.Path.of("build", "ui-previews"); java.nio.file.Files.createDirectories(output);
                        javax.imageio.ImageIO.write(rendered, "png", output.resolve("certificate-" + (expanded ? "advanced-" : "default-") + width + ".png").toFile());
                    }
                }
                editor.fields().get("url").setText("https://OTHER.example:8443/login"); h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false);
            });
            h.await(() -> { try { return editor.saved(); } catch (Exception error) { return false; } });
            assertEquals(List.of(java.net.URI.create("https://other.example:8443")), editor.registry.snapshot().entries().get(key).definition().mtls().origins());
            h.edt(() -> { editor.fields().get("origins").setText("https://identity.example"); editor.fields().get("ca").setText("C:/owned-test/ca.pem"); h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false); });
            h.await(() -> { try { return editor.saved(); } catch (Exception error) { return false; } });
            assertEquals(java.util.Set.of(java.net.URI.create("https://other.example:8443"), java.net.URI.create("https://identity.example")), java.util.Set.copyOf(editor.registry.snapshot().entries().get(key).definition().mtls().origins()));
            h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, key));
            h.await(() -> { try { return !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception error) { return false; } });
            h.edt(() -> {
                assertEquals("https://identity.example", editor.fields().get("origins").getText()); assertEquals("C:/owned-test/ca.pem", editor.fields().get("ca").getText());
                assertFalse(((JPanel) h.member(editor.ui, "certificateAdvanced")).isVisible()); assertFalse(((JToggleButton) h.member(editor.ui, "certificateAdvancedToggle")).isSelected());
            });
            assertTrue(editor.clock.workers.isEmpty());
        }
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(strings = {"origins", "ca"})
    void certificateAdvancedFieldErrorsRevealTheirCollapsedSettings(String field) throws Exception {
        var h = harness();
        String stored = JourneyRegistryTest.edit(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false), "/journeys/0", "mtls",
                Map.of("modulePath", "C:/owned-test/middleware.dll", "certificateSha256", "a".repeat(64), "origins", List.of()));
        try (var editor = h.new Editor(stored)) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, key));
            h.await(() -> { try { return key.equals(h.member(editor.ui, "editing")) && !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception error) { return false; } });
            h.edt(() -> {
                editor.fields().get(field).setText(field.equals("ca") ? "relative.pem" : "https://identity.example/login");
                assertFalse(((JPanel) h.member(editor.ui, "certificateAdvanced")).isVisible()); ((JButton) h.member(editor.ui, "testButton")).doClick(0);
            });
            h.await(() -> { try { return editor.status().startsWith(field.equals("ca") ? "Trusted CA:" : "Additional authentication servers:"); } catch (Exception error) { return false; } });
            h.edt(() -> {
                assertEquals("Client certificate", WizardTestPages.selected(((JTabbedPane) h.member(editor.ui, "wizard"))));
                assertTrue(((JPanel) h.member(editor.ui, "certificateAdvanced")).isVisible()); assertTrue(((JToggleButton) h.member(editor.ui, "certificateAdvancedToggle")).isSelected());
                assertTrue(((JTextArea) editor.fields().get(field).getClientProperty("validationMessage")).isVisible());
            });
            assertTrue(editor.clock.workers.isEmpty());
        }
    }

    @Test void journeyNamesRenderLiterallyEvenWhenTheyLookLikeHtml() throws Exception {
        var h = harness(); try (var editor = h.new Editor(null)) {
            h.edt(() -> {
                JList<?> list = h.member(editor.ui, "saved");
                @SuppressWarnings("rawtypes") var renderer = (ListCellRenderer) list.getCellRenderer();
                var label = (JLabel) renderer.getListCellRendererComponent(list, "<html><h1>Fixture name</h1>", 0, false, false);
                assertNull(label.getClientProperty("html"), "journey names must not become formatted markup");
                assertEquals("<html><h1>Fixture name</h1>", label.getText());
            });
        }
    }

    @Test void savedJourneyMaintenanceActionsAreUnavailableWithoutASavedSelection() throws Exception {
        var h = harness(); try (var editor = h.new Editor(null)) {
            h.edt(() -> {
                for (String key : List.of("reloadSelectedItem", "exportSelectedItem", "deleteSelectedItem")) assertFalse(((JMenuItem) h.member(editor.ui, key)).isEnabled(), key);
                h.call(editor.ui, "newJourney", new Class<?>[]{});
                for (String key : List.of("reloadSelectedItem", "exportSelectedItem", "deleteSelectedItem")) assertFalse(((JMenuItem) h.member(editor.ui, key)).isEnabled(), key);
            });
        }
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, key));
            h.await(() -> { try { return key.equals(h.member(editor.ui, "editing")) && !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception ex) { return false; } });
            h.edt(() -> {
                for (String name : List.of("reloadSelectedItem", "exportSelectedItem", "deleteSelectedItem")) assertTrue(((JMenuItem) h.member(editor.ui, name)).isEnabled(), name);
                editor.fields().get("name").setText("Draft");
                assertFalse(((JMenuItem) h.member(editor.ui, "exportSelectedItem")).isEnabled());
                assertTrue(((JMenuItem) h.member(editor.ui, "reloadSelectedItem")).isEnabled());
                assertTrue(((JMenuItem) h.member(editor.ui, "deleteSelectedItem")).isEnabled());
            });
        }
    }

    @Test void pendingDraftValidationCannotOverwriteTheFollowingAuthenticationStatus() throws Exception {
        var h = harness(); try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, key));
            h.await(() -> { try { return key.equals(h.member(editor.ui, "editing")) && !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception ex) { return false; } });
            h.edt(() -> { editor.fields().get("name").setText("Updated name"); h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false); });
            h.await(() -> { try { return editor.saved(); } catch (Exception ex) { return false; } });
            h.edt(() -> h.call(editor.ui, "authenticate", new Class<?>[]{boolean.class}, false));
            h.await(() -> { try { return editor.status().startsWith("Signing in"); } catch (Exception ex) { return false; } });
            var delay = new java.util.concurrent.CompletableFuture<Void>(); h.edt(() -> { var timer = new Timer(1200, e -> delay.complete(null)); timer.setRepeats(false); timer.start(); }); delay.get(3, java.util.concurrent.TimeUnit.SECONDS);
            assertTrue(editor.status().startsWith("Signing in"), editor.status());
        }
    }

    @Test void testPageHasNoSeparateResultOutput() throws Exception {
        var h = harness(); try (var editor = h.new Editor(null)) {
            h.edt(() -> {
                var page = (JScrollPane) h.call(editor.ui, "testAndUseForm", new Class<?>[]{});
                assertFalse(texts(page).contains("Last test result"));
                assertFalse(texts(page).contains("Not tested in this session."));
                assertNotNull(find(page, "Test login"));
                var clear = find(page, "Clear cached credentials");
                assertNotNull(clear.getIcon()); assertTrue(clear.getText() == null || clear.getText().isEmpty());
                assertEquals("Clear cached credentials", clear.getAccessibleContext().getAccessibleName());
                assertTrue(clear.getToolTipText().contains("HTTP authentication sessions"));
                assertEquals(clear.getToolTipText(), clear.getAccessibleContext().getAccessibleDescription());
            });
        }
    }

    /** @param component Owned UI subtree. @return Labels and plain text visible in that subtree. */
    private static String texts(Component component) {
        String text = component instanceof JLabel label ? label.getText() : component instanceof JTextArea area ? area.getText() : "";
        if (component instanceof Container container) for (var child : container.getComponents()) text += texts(child);
        return text;
    }
    /** Applies local layout managers recursively to check actual bounds, without an installed host window. @param component Owned component subtree. */
    private static void layout(Component component) { if (component instanceof Container container) { container.doLayout(); for (var child : container.getComponents()) layout(child); } }

    /** @param component Local test component. @param action Accessible action name. @return Matching native button. */
    private static JButton find(Component component, String action) {
        if (component instanceof JButton button && (action.equals(button.getAccessibleContext().getAccessibleName()) || action.equals(button.getName()))) return button;
        if (component instanceof Container container) for (var child : container.getComponents()) { var found = findOrNull(child, action); if (found != null) return found; }
        throw new AssertionError("No local action: " + action);
    }
    /** @param component Local subtree. @param action Accessible action name. @return Matching action or null. */
    private static JButton findOrNull(Component component, String action) {
        if (component instanceof JButton button && (action.equals(button.getAccessibleContext().getAccessibleName()) || action.equals(button.getName()))) return button;
        if (component instanceof Container container) for (var child : container.getComponents()) { var found = findOrNull(child, action); if (found != null) return found; }
        return null;
    }
}
