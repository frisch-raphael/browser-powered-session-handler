package bpsh.burp.ui;

import bpsh.journey.AuthStep;
import bpsh.journey.JourneyDraft;
import bpsh.journey.JourneyRecording;
import bpsh.journey.SecretStore;
import bpsh.journey.persistence.JourneyDocument;
import bpsh.journey.persistence.ProjectStore;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JPasswordField;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises the real native review/controller against the existing storage harness and a framework-free recorder double. */
class JourneyRecordingTest {
    @TempDir Path root;
    private JourneyRegistryTest.NativeUi harness() { var harness = new JourneyRegistryTest().new NativeUi(); harness.root = root; return harness; }
    private static String fixture() { return JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false); }
    private static JourneyRecording.Candidate secret(UUID id, boolean unknown) {
        return new JourneyRecording.Candidate(new AuthStep.Definition(id, AuthStep.Type.SECURE_INPUT, "#password", null, null, null, null), "main", List.of(), unknown);
    }
    private static JourneyRecording.Candidate text(UUID id, String value) {
        return new JourneyRecording.Candidate(new AuthStep.Definition(id, AuthStep.Type.INPUT, "#username", value, null, null, null), "main", List.of(), false);
    }

    private static final class Fake implements JourneyRecording {
        final AtomicInteger starts = new AtomicInteger(), cancellations = new AtomicInteger(), releases = new AtomicInteger();
        volatile Request request;
        volatile Consumer<Event> observer;
        volatile Result result;
        boolean onlyPin, active, ready = true;
        @Override public Control start(Request request, SecretStore.Values values, Consumer<Event> observer) {
            try {
                if (active) throw new IllegalStateException("A review is active.");
                onlyPin = values.stepIds().isEmpty(); this.request = request; this.observer = observer; active = true; starts.incrementAndGet();
                observer.accept(new Event(State.PREPARING, null, null)); if (ready) observer.accept(new Event(State.RECORDING, null, null));
                return new Control() {
                    @Override public void stop() { observer.accept(new Event(State.STOPPING, null, null)); }
                    @Override public void cancel() { cancellations.incrementAndGet(); active = false; if (result != null) result.close(); else observer.accept(new Event(State.CLOSED, null, null)); }
                };
            } finally { values.close(); }
        }
        Result review(List<Candidate> candidates, SecretStore.Values values) {
            return review(candidates, List.of(), List.of(), values);
        }
        Result review(List<Candidate> candidates, List<Popup> popups, List<String> problems, SecretStore.Values values) {
            result = new Result(request.stamp(), candidates, popups, problems, values, () -> { active = false; releases.incrementAndGet(); });
            observer.accept(new Event(State.REVIEW, result, null)); return result;
        }
        @Override public void close() { if (result != null) result.close(); active = false; }
    }

    private void open(JourneyRegistryTest.NativeUi h, JourneyRegistryTest.NativeUi.Editor editor) throws Exception {
        var key = editor.registry.snapshot().resolve("employee").identity().key();
        h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{bpsh.journey.JourneyKey.class}, key));
        h.await(() -> { try { return key.equals(h.member(editor.ui, "editing")) && !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception error) { return false; } });
    }
    private void start(JourneyRegistryTest.NativeUi h, JourneyRegistryTest.NativeUi.Editor editor, Fake fake) throws Exception {
        h.edt(() -> h.call(editor.ui, "recordSteps", new Class<?>[]{})); h.await(() -> fake.starts.get() == 1); h.edt(() -> {});
    }
    private JourneyRecordingDialog dialog(JourneyRegistryTest.NativeUi h, JourneyRegistryTest.NativeUi.Editor editor) throws Exception { return h.member(editor.ui, "recordingDialog"); }

    @Test void certificatePolicyIsOptInSavedAndSharedWithRecording() throws Exception {
        var h = harness(); try (var fake = new Fake(); var editor = h.new Editor(fixture(), null, null, fake)) {
            open(h, editor);
            h.edt(() -> {
                assertFalse(editor.checks().get("ignoreHttpsErrors").isSelected());
                editor.checks().get("ignoreHttpsErrors").doClick(0);
                h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false);
            });
            h.await(() -> { try { return editor.saved(); } catch (Exception error) { return false; } });
            var saved = editor.registry.snapshot().resolve("employee").definition();
            assertTrue(saved.browser().ignoreHttpsErrors());
            try (var stored = bpsh.journey.persistence.JourneyJson.read(editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY), JourneyDocument.DocumentKind.PROJECT)) {
                assertTrue(stored.journeys().getFirst().browser().ignoreHttpsErrors());
            }
            start(h, editor, fake); assertTrue(fake.request.setup().browser().ignoreHttpsErrors());
        }
    }

    @Test void startupProgressIdentifiesTheBlockedStageBeforeRecordingIsReady() throws Exception {
        var h = harness(); try (var fake = new Fake(); var editor = h.new Editor(fixture(), null, null, fake)) {
            fake.ready = false; open(h, editor); start(h, editor, fake);
            for (var phase : Map.of(JourneyRecording.State.EXTRACTING_BROWSER, "Extracting bundled driver files...",
                    JourneyRecording.State.STARTING_DRIVER, "Starting the browser driver...",
                    JourneyRecording.State.STARTING_BROWSER, "Starting Burp Browser...").entrySet()) {
                h.edt(() -> fake.observer.accept(new JourneyRecording.Event(phase.getKey(), null, null)));
                h.edt(() -> { assertEquals(phase.getValue(), dialog(h, editor).progress.getText()); assertFalse(dialog(h, editor).stop.isEnabled()); });
            }
            h.edt(() -> fake.observer.accept(new JourneyRecording.Event(JourneyRecording.State.CLOSED, null,
                    new JourneyRecording.Problem(JourneyRecording.Field.GENERAL, "The bundled driver runtime could not load."))));
            h.edt(() -> { assertNull(dialog(h, editor)); assertTrue(((SessionStatusBar) h.member(editor.ui, "status")).getText().contains("runtime could not load")); });
        }
    }

    @Test void reviewCorrectionsKeepTheCapturedValueBothWaysAndNeverAutosaveBeforeApply() throws Exception {
        var h = harness(); try (var fake = new Fake(); var editor = h.new Editor(fixture(), null, null, fake)) {
            open(h, editor); String before = editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY); start(h, editor, fake);
            UUID id = UUID.randomUUID(); h.edt(() -> fake.review(List.of(secret(id, true)), new SecretStore.Values(null, Map.of(id, " captured value ".toCharArray()))));
            h.edt(() -> {
                var dialog = dialog(h, editor); assertTrue(dialog.apply.isEnabled()); assertTrue(dialog.notes.getText().contains(JourneyRecordingDialog.UNKNOWN_FIELD));
                assertTrue(dialog.notes.getText().contains(JourneyRecordingDialog.NO_PASSWORD));
                List<?> rows = h.member(dialog.editor, "rows"); var picker = (JComboBox<?>) h.member(rows.getFirst(), "type");
                picker.setSelectedItem(AuthStep.Type.INPUT);
                try (var snapshot = dialog.editor.snapshot()) { assertEquals(" captured value ", snapshot.inputs.getFirst().value()); assertTrue(snapshot.secrets.isEmpty()); }
                assertFalse(dialog.notes.getText().contains(JourneyRecordingDialog.UNKNOWN_FIELD));
                picker.setSelectedItem(AuthStep.Type.SECURE_INPUT);
                try (var snapshot = dialog.editor.snapshot()) { assertArrayEquals(" captured value ".toCharArray(), snapshot.secrets.get(id)); assertEquals("", snapshot.inputs.getFirst().value()); }
                assertFalse(dialog.notes.getText().contains("captured value"));
            });
            assertEquals(before, editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY)); assertTrue(fake.onlyPin);
            h.edt(() -> dialog(h, editor).cancel.doClick(0)); assertEquals(before, editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY)); assertEquals(1, fake.releases.get());
        }
    }

    @Test void missingAndExplicitlyEmptyRecordedSecretsRemainDistinctDuringConversion() throws Exception {
        var h = harness(); h.edt(() -> {
            for (boolean present : new boolean[]{false, true}) {
                var id = UUID.randomUUID(); var owner = new bpsh.journey.JourneyKey(bpsh.journey.JourneyDefinition.Scope.PROJECT, UUID.randomUUID());
                var result = new JourneyRecording.Result(new JourneyRecording.Stamp(owner, 1, UUID.randomUUID()), List.of(secret(id, true)), List.of(), List.of(),
                        new SecretStore.Values(null, present ? Map.of(id, new char[0]) : Map.of()), () -> {});
                try (var dialog = new JourneyRecordingDialog(() -> {}, () -> {}, () -> {}, StepsPanel.Snapshot::close)) {
                    dialog.review(result); assertTrue(dialog.apply.isEnabled());
                    List<?> rows = h.member(dialog.editor, "rows"); var picker = (JComboBox<?>) h.member(rows.getFirst(), "type"); picker.setSelectedItem(AuthStep.Type.INPUT);
                    try (var snapshot = dialog.editor.snapshot()) { assertEquals(!present, snapshot.missingValues.contains(id)); assertEquals("", snapshot.inputs.getFirst().value()); }
                    picker.setSelectedItem(AuthStep.Type.SECURE_INPUT);
                    try (var snapshot = dialog.editor.snapshot()) { assertEquals(present, snapshot.secrets.containsKey(id)); }
                }
            }
        });
    }

    @Test void replacementAllocatesNewIdentitiesAndOneUndoRestoresOriginalStepsAndSecrets() throws Exception {
        var h = harness(); try (var fake = new Fake(); var editor = h.new Editor(fixture(), null, null, fake)) {
            var original = editor.registry.snapshot().resolve("employee"); var oldId = original.definition().steps().getFirst().id();
            try (var values = new SecretStore.Values(null, Map.of(oldId, "old-secret".toCharArray()))) { editor.secrets.put(original.identity().key(), values); }
            open(h, editor); start(h, editor, fake); var captured = UUID.randomUUID();
            h.edt(() -> fake.review(List.of(secret(captured, false)), new SecretStore.Values(null, Map.of(captured, "new-secret".toCharArray()))));
            h.edt(() -> dialog(h, editor).apply.doClick(0));
            h.await(() -> { try { return !editor.registry.snapshot().resolve("employee").definition().steps().getFirst().id().equals(oldId) && editor.saved(); } catch (Exception error) { return false; } });
            var changed = editor.registry.snapshot().resolve("employee"); UUID newId = changed.definition().steps().getFirst().id();
            assertNotEquals(captured, newId); assertFalse(editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY).contains("new-secret"));
            try (var values = editor.secrets.snapshot(changed.identity().key())) { assertArrayEquals("new-secret".toCharArray(), values.stepValue(newId)); assertNull(values.stepValue(oldId)); }
            h.edt(() -> { var panel = (StepsPanel) h.member(editor.ui, "steps"); ((JButton) h.member(panel, "undoStep")).doClick(0); });
            h.await(() -> { try { return editor.registry.snapshot().resolve("employee").definition().steps().getFirst().id().equals(oldId) && editor.saved(); } catch (Exception error) { return false; } });
            try (var values = editor.secrets.snapshot(original.identity().key())) { assertArrayEquals("old-secret".toCharArray(), values.stepValue(oldId)); assertNull(values.stepValue(newId)); }
            assertEquals(original.definition().authenticationUrl(), editor.registry.snapshot().resolve("employee").definition().authenticationUrl());
        }
    }

    @Test void editingDuringRecordingRejectsLateResultsAndKeepsTheExistingSequence() throws Exception {
        var h = harness(); try (var fake = new Fake(); var editor = h.new Editor(fixture(), null, null, fake)) {
            open(h, editor); var original = editor.registry.snapshot().resolve("employee").definition().steps(); start(h, editor, fake);
            var sink = fake.observer; var stamp = fake.request.stamp();
            h.edt(() -> editor.fields().get("url").setText("https://changed.example/login"));
            var late = new JourneyRecording.Result(stamp, List.of(text(UUID.randomUUID(), "late text")), List.of(), List.of(), SecretStore.Values.empty(), fake.releases::incrementAndGet);
            sink.accept(new JourneyRecording.Event(JourneyRecording.State.REVIEW, late, null)); h.edt(() -> {});
            assertThrows(IllegalStateException.class, late::copySecrets); assertTrue(fake.cancellations.get() > 0);
            h.edt(() -> { try (var snapshot = ((StepsPanel) h.member(editor.ui, "steps")).snapshot()) { assertEquals(original.getFirst().id(), snapshot.inputs.getFirst().id()); } });
        }
    }

    @Test void externalStorageRevisionIsCheckedBeforeReplacementNotOnlyDuringAutosave() throws Exception {
        var h = harness(); try (var fake = new Fake(); var editor = h.new Editor(fixture(), null, null, fake)) {
            open(h, editor); var originalId = editor.registry.snapshot().resolve("employee").definition().steps().getFirst().id(); start(h, editor, fake);
            h.edt(() -> fake.review(List.of(text(UUID.randomUUID(), "captured")), SecretStore.Values.empty()));
            var external = (com.fasterxml.jackson.databind.node.ObjectNode) JourneyRegistryTest.JSON.readTree(editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY));
            external.put("revision", UUID.randomUUID().toString()); String changed = external.toString(); editor.disk.put(ProjectStore.NATIVE_PROJECT_KEY, changed);
            h.edt(() -> dialog(h, editor).apply.doClick(0));
            h.await(() -> { try { return dialog(h, editor) == null; } catch (Exception error) { return false; } });
            assertEquals(changed, editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY));
            h.edt(() -> { try (var snapshot = ((StepsPanel) h.member(editor.ui, "steps")).snapshot()) { assertEquals(originalId, snapshot.inputs.getFirst().id()); } });
        }
    }

    @Test void failedAutosaveRetainsAppliedEditorValuesUntilTheNormalRetrySucceeds() throws Exception {
        var h = harness(); try (var fake = new Fake(); var editor = h.new Editor(fixture(), null, null, fake)) {
            open(h, editor); String before = editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY); start(h, editor, fake); UUID captured = UUID.randomUUID();
            h.edt(() -> fake.review(List.of(secret(captured, false)), new SecretStore.Values(null, Map.of(captured, "retained-secret".toCharArray()))));
            editor.failWrites.set(true); h.edt(() -> dialog(h, editor).apply.doClick(0));
            h.await(() -> { try { return (boolean) h.member(editor.ui, "savePaused"); } catch (Exception error) { return false; } });
            assertEquals(before, editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY));
            h.edt(() -> { try (var snapshot = ((StepsPanel) h.member(editor.ui, "steps")).snapshot()) {
                assertNotEquals(captured, snapshot.inputs.getFirst().id()); assertArrayEquals("retained-secret".toCharArray(), snapshot.secrets.get(snapshot.inputs.getFirst().id()));
            } });
            editor.failWrites.set(false); h.edt(() -> h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false)); h.await(() -> { try { return editor.saved(); } catch (Exception error) { return false; } });
            assertFalse(editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY).contains("retained-secret"));
            var entry = editor.registry.snapshot().resolve("employee"); try (var values = editor.secrets.snapshot(entry.identity().key())) { assertArrayEquals("retained-secret".toCharArray(), values.stepValue(entry.definition().steps().getFirst().id())); }
        }
    }

    @Test void setupAdmissionIgnoresUnfinishedOldStepsNamesAndCaptureWithoutCopyingOldSecrets() throws Exception {
        var h = harness(); try (var fake = new Fake(); var editor = h.new Editor(fixture(), null, null, fake)) {
            open(h, editor);
            h.edt(() -> {
                editor.fields().get("name").setText("");
                try (var values = SecretStore.Values.empty()) { ((StepsPanel) h.member(editor.ui, "steps")).setDraft(List.of(new JourneyDraft.StepInput(UUID.randomUUID(), AuthStep.Type.WAIT_TIME, "", "unfinished", "")), values); }
                h.call(editor.ui, "edited", new Class<?>[]{}); h.call(editor.ui, "recordSteps", new Class<?>[]{});
            });
            h.await(() -> fake.starts.get() == 1); assertTrue(fake.onlyPin); assertTrue(editor.clock.workers.isEmpty());
            assertEquals("https://login.example/login", fake.request.setup().authenticationUrl().toString());
            h.edt(() -> dialog(h, editor).cancel.doClick(0));
        }
    }

    @Test void unloadDiscardsTheReviewAndLateCompletionWithoutApplyingOrSavingCandidates() throws Exception {
        var h = harness(); try (var fake = new Fake(); var editor = h.new Editor(fixture(), null, null, fake)) {
            open(h, editor); String before = editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY); start(h, editor, fake);
            h.edt(() -> fake.review(List.of(text(UUID.randomUUID(), "uncommitted text")), SecretStore.Values.empty()));
            editor.ui.shutdown(); h.edt(() -> {}); assertEquals(1, fake.releases.get()); assertEquals(before, editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY));
        }
    }

    @Test void popupReviewAllowsTheEarlierOpeningActionPreservesEditsAndRemapsItsReference() throws Exception {
        var h = harness(); try (var fake = new Fake(); var editor = h.new Editor(fixture(), null, null, fake)) {
            open(h, editor); start(h, editor, fake);
            UUID a = UUID.randomUUID(), b = UUID.randomUUID(), declaration = UUID.randomUUID(), input = UUID.randomUUID();
            var first = new JourneyRecording.Candidate(new AuthStep.Definition(a, AuthStep.Type.CLICK, "#open-a", null, null, null, null), "main", List.of(), false);
            var second = new JourneyRecording.Candidate(new AuthStep.Definition(b, AuthStep.Type.CLICK, "#open-b", null, null, null, null), "main", List.of(), false);
            var expectation = new JourneyRecording.Candidate(new AuthStep.Definition(declaration, AuthStep.Type.EXPECT_POPUP, null, null, null, null, null, new AuthStep.Popup("popup-1", declaration)), "main", List.of(), false);
            var select = new JourneyRecording.Candidate(new AuthStep.Definition(UUID.randomUUID(), AuthStep.Type.SWITCH_PAGE, null, null, null, null, null, new AuthStep.PageTarget("popup-1")), "popup-1", List.of(), false);
            var field = new JourneyRecording.Candidate(secret(input, false).step(), "popup-1", List.of(), false);
            h.edt(() -> fake.review(List.of(first, second, expectation, select, field), List.of(new JourneyRecording.Popup(declaration, "popup-1", "main", List.of(a, b), null)), List.of(),
                    new SecretStore.Values(null, Map.of(input, "initial captured".toCharArray()))));
            h.edt(() -> {
                var dialog = dialog(h, editor); assertTrue(dialog.apply.isEnabled());
                List<?> rows = h.member(dialog.editor, "rows"); ((JPasswordField) h.member(rows.getLast(), "secret")).setText("edited captured");
                Map<UUID, JComboBox<?>> choices = h.member(dialog, "openingPickers"); assertTrue(choices.get(declaration).getItemAt(1).toString().contains("Step 1"));
                choices.get(declaration).setSelectedIndex(1);
                try (var snapshot = dialog.editor.snapshot()) {
                    assertEquals(declaration, snapshot.inputs.getFirst().id()); assertEquals(a, snapshot.inputs.get(1).id());
                    assertEquals(a.toString(), ((JourneyDraft.Popup) snapshot.inputs.getFirst().operation()).triggerStepId());
                    assertArrayEquals("edited captured".toCharArray(), snapshot.secrets.get(input));
                }
                assertTrue(dialog.apply.isEnabled()); dialog.apply.doClick(0);
            });
            h.await(() -> { try { return editor.saved() && editor.registry.snapshot().resolve("employee").definition().steps().getFirst().type() == AuthStep.Type.EXPECT_POPUP; } catch (Exception error) { return false; } });
            var changed = editor.registry.snapshot().resolve("employee"); var steps = changed.definition().steps();
            assertEquals(steps.get(1).id(), ((AuthStep.Popup) steps.getFirst().operation()).triggerStepId()); assertNotEquals(a, steps.get(1).id());
            try (var values = editor.secrets.snapshot(changed.identity().key())) { assertArrayEquals("edited captured".toCharArray(), values.stepValue(steps.getLast().id())); }
        }
    }

    @Test void incompleteRecordingCanReplaceUnresolvedStepsAsADraftAndKeepCapturedSecretsForManualRepair() throws Exception {
        var h = harness(); try (var fake = new Fake(); var editor = h.new Editor(fixture(), null, null, fake)) {
            open(h, editor); start(h, editor, fake);
            UUID input = UUID.randomUUID(), declaration = UUID.randomUUID();
            var expectation = new JourneyRecording.Candidate(new AuthStep.Definition(declaration, AuthStep.Type.EXPECT_POPUP, null, null, null, null, null,
                    new AuthStep.Popup("popup-1", declaration)), "main", List.of(), false);
            var selected = new JourneyRecording.Candidate(new AuthStep.Definition(UUID.randomUUID(), AuthStep.Type.SWITCH_PAGE, null, null, null, null, null,
                    new AuthStep.PageTarget("popup-1")), "popup-1", List.of(), false);
            h.edt(() -> fake.review(List.of(secret(input, false), expectation, selected), List.of(new JourneyRecording.Popup(declaration, "popup-1", "main", List.of(), null)),
                    List.of("Browser interaction 2 (pressed Escape) was not added as a step: this key is unsupported."),
                    new SecretStore.Values(null, Map.of(input, "partial-secret".toCharArray()))));
            h.edt(() -> { var dialog = dialog(h, editor); assertTrue(dialog.apply.isEnabled()); assertTrue(dialog.notes.getText().contains("pressed Escape")); dialog.apply.doClick(0); });
            h.await(() -> { try { return dialog(h, editor) == null && editor.saved(); } catch (Exception error) { return false; } });
            var changed = editor.registry.snapshot().resolve("employee"); assertNotNull(changed.definition().draft());
            var raw = changed.definition().draft().steps(); assertEquals(3, raw.size()); assertNotEquals(input, raw.getFirst().id());
            try (var values = editor.secrets.snapshot(changed.identity().key())) { assertArrayEquals("partial-secret".toCharArray(), values.stepValue(raw.getFirst().id())); }
            assertFalse(editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY).contains("partial-secret"));
            h.edt(() -> ((JButton) h.member(editor.ui, "testButton")).doClick(0));
            h.await(() -> { try {
                List<?> rows = h.member((StepsPanel) h.member(editor.ui, "steps"), "rows");
                var trigger = (JComboBox<?>) h.member(rows.get(1), "trigger");
                return ((javax.swing.JTextArea) trigger.getClientProperty("validationMessage")).isVisible();
            } catch (Exception error) { return false; } });
            assertTrue(editor.clock.workers.isEmpty(), "Testing must validate the unfinished draft before running it");
            h.edt(() -> {
                var panel = (StepsPanel) h.member(editor.ui, "steps"); List<?> rows = h.member(panel, "rows");
                ((JButton) h.member(rows.getLast(), "remove")).doClick(0); rows = h.member(panel, "rows"); ((JButton) h.member(rows.getLast(), "remove")).doClick(0);
            });
            h.await(() -> { try { return editor.saved() && editor.registry.snapshot().resolve("employee").definition().draft() == null; } catch (Exception error) { return false; } });
            assertEquals(1, editor.registry.snapshot().resolve("employee").definition().steps().size());
        }
    }

    @Test void partialReviewExplainsOmissionsAndAllowsReplacingCapturedStepsButNeedsAtLeastOneRow() throws Exception {
        var h = harness(); h.edt(() -> {
            UUID id = UUID.randomUUID(); var owner = new bpsh.journey.JourneyKey(bpsh.journey.JourneyDefinition.Scope.PROJECT, UUID.randomUUID());
            var result = new JourneyRecording.Result(new JourneyRecording.Stamp(owner, 1, UUID.randomUUID()), List.of(text(id, "captured text")), List.of(),
                    List.of("An unsupported key was recorded."), SecretStore.Values.empty(), () -> {});
            var applied = new AtomicInteger();
            try (var dialog = new JourneyRecordingDialog(() -> {}, () -> {}, () -> {}, snapshot -> { try (snapshot) { assertEquals(1, snapshot.inputs.size()); applied.incrementAndGet(); } })) {
                dialog.review(result); assertTrue(dialog.apply.isEnabled());
                assertTrue(dialog.notes.getText().contains("finish editing in Login steps"));
                assertTrue(dialog.notes.getText().contains("not the steps below")); dialog.editor.clear();
                h.call(dialog, "refreshReview", new Class<?>[]{}); assertFalse(dialog.apply.isEnabled()); assertTrue(dialog.notes.getText().contains("incomplete"));
                assertFalse(dialog.notes.getText().contains("captured text"));
                try (var values = SecretStore.Values.empty()) { dialog.editor.setSteps(List.of(text(UUID.randomUUID(), "captured text").step()), values); }
                h.call(dialog, "refreshReview", new Class<?>[]{}); assertTrue(dialog.apply.isEnabled()); dialog.apply.doClick(0); assertEquals(1, applied.get());
            }
        });
    }
}
