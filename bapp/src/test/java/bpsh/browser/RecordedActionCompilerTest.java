package bpsh.browser;

import bpsh.browser.runtime.PlaywrightRecorderAdapter;
import bpsh.journey.AuthStep;
import bpsh.journey.AuthStepSequence;
import bpsh.journey.ConfigurationException;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.JourneyKey;
import bpsh.journey.JourneyRecording;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Checks conversion, secret continuity, update identity and context lowering without a browser. */
class RecordedActionCompilerTest {
    private static JourneyRecording.Stamp stamp() {
        return new JourneyRecording.Stamp(new JourneyKey(JourneyDefinition.Scope.PROJECT, UUID.randomUUID()), 1, UUID.randomUUID());
    }
    private static RecordedActionCompiler.Target target(String page, long frame, long generation, List<String> frames, boolean reset, long order) {
        return new RecordedActionCompiler.Target(page, frame, generation, frames, "#field", true, reset, order);
    }
    private static PlaywrightRecorderAdapter.Event event(PlaywrightRecorderAdapter.Kind kind, String page, String name,
            String text, String field, PlaywrightRecorderAdapter.Classification classification) {
        return new PlaywrightRecorderAdapter.Event(kind, page,
                new PlaywrightRecorderAdapter.Action(name, "#field", List.of(), "Enter", 0, "left", 1, false, null, null,
                        new PlaywrightRecorderAdapter.Metadata("source_1", "document_1", field, classification), text == null ? null : text.toCharArray()), 512);
    }
    private static void fill(RecordedActionCompiler compiler, PlaywrightRecorderAdapter.Kind kind, String text, String field,
            PlaywrightRecorderAdapter.Classification classification, RecordedActionCompiler.Target target) {
        try (var event = event(kind, target.pageGuid(), "fill", text, field, classification)) { compiler.accept(event, target); }
    }
    private static void click(RecordedActionCompiler compiler, String page, long order) {
        try (var event = event(PlaywrightRecorderAdapter.Kind.ADDED, page, "click", null, "", PlaywrightRecorderAdapter.Classification.UNKNOWN)) {
            compiler.accept(event, target(page, 1, 1, List.of(), false, order));
        }
    }

    @Test void updatesReplaceOnlyTheSameNativeFieldAndRetainTheFinalSecretWithoutInlineText() {
        try (var compiler = new RecordedActionCompiler("main", "https://example.test")) {
            var target = target("main", 1, 1, List.of(), false, 1);
            fill(compiler, PlaywrightRecorderAdapter.Kind.ADDED, "secret-before", "field1", PlaywrightRecorderAdapter.Classification.SECRET, target);
            fill(compiler, PlaywrightRecorderAdapter.Kind.UPDATED, "secret-final", "field1", PlaywrightRecorderAdapter.Classification.ORDINARY, target);
            try (var result = compiler.freeze(stamp(), () -> {}); var values = result.copySecrets()) {
                assertTrue(result.complete()); assertEquals(1, result.candidates().size()); var candidate = result.candidates().getFirst();
                assertEquals(AuthStep.Type.SECURE_INPUT, candidate.step().type()); assertNull(candidate.step().value()); assertFalse(candidate.passwordUnclassified());
                char[] copy = values.stepValue(candidate.step().id()); try { assertArrayEquals("secret-final".toCharArray(), copy); } finally { java.util.Arrays.fill(copy, '\0'); }
                assertFalse(result.toString().contains("secret-final")); assertFalse(candidate.toString().contains("secret-final"));
            }
        }
    }

    @Test void exactProtectedLogicalTargetSurvivesReplacementWithoutWarningAndNeverLeaksAcrossFrameOrDocument() {
        try (var compiler = new RecordedActionCompiler("main", "https://example.test")) {
            var first = target("main", 11, 1, List.of(), false, 1);
            fill(compiler, PlaywrightRecorderAdapter.Kind.ADDED, "old", "old-node", PlaywrightRecorderAdapter.Classification.SECRET, first);
            fill(compiler, PlaywrightRecorderAdapter.Kind.UPDATED, "replacement", "new-node", PlaywrightRecorderAdapter.Classification.UNKNOWN, first);
            fill(compiler, PlaywrightRecorderAdapter.Kind.ADDED, "other-frame", "field1", PlaywrightRecorderAdapter.Classification.ORDINARY,
                    target("main", 22, 1, List.of("#frame"), false, 3));
            compiler.navigated("main", 11, true, 4);
            fill(compiler, PlaywrightRecorderAdapter.Kind.ADDED, "new-document", "field1", PlaywrightRecorderAdapter.Classification.ORDINARY,
                    target("main", 11, 2, List.of(), false, 5));
            try (var result = compiler.freeze(stamp(), () -> {}); var values = result.copySecrets()) {
                var fills = result.candidates().stream().filter(c -> c.step().type().requiresInputValue()).toList();
                assertEquals(4, fills.size()); assertEquals(AuthStep.Type.SECURE_INPUT, fills.get(1).step().type()); assertFalse(fills.get(1).passwordUnclassified());
                assertNotEquals(fills.get(0).step().id(), fills.get(1).step().id());
                assertEquals(AuthStep.Type.INPUT, fills.get(2).step().type()); assertEquals(AuthStep.Type.INPUT, fills.get(3).step().type());
                assertEquals(2, values.stepIds().size());
            }
        }
    }

    @Test void unknownStatusRetainsItsValueAndWarningAcrossAnUpdateUntilReview() {
        try (var compiler = new RecordedActionCompiler("main", "https://example.test")) {
            var target = target("main", 1, 1, List.of(), false, 1);
            fill(compiler, PlaywrightRecorderAdapter.Kind.ADDED, "", "unknown-field", PlaywrightRecorderAdapter.Classification.UNKNOWN, target);
            fill(compiler, PlaywrightRecorderAdapter.Kind.UPDATED, "kept once", "unknown-field", PlaywrightRecorderAdapter.Classification.ORDINARY, target);
            try (var result = compiler.freeze(stamp(), () -> {}); var values = result.copySecrets()) {
                assertTrue(result.complete()); assertEquals(1, result.candidates().size()); var candidate = result.candidates().getFirst();
                assertTrue(candidate.passwordUnclassified()); assertEquals(AuthStep.Type.SECURE_INPUT, candidate.step().type());
                char[] copy = values.stepValue(candidate.step().id()); try { assertArrayEquals("kept once".toCharArray(), copy); } finally { java.util.Arrays.fill(copy, '\0'); }
            }
        }
    }

    @Test void contextRowsDoNotInterceptUpdatesAndDetachedFramesUseAnExplicitMainFrameReset() {
        try (var compiler = new RecordedActionCompiler("main", "https://example.test")) {
            var nested = target("main", 3, 1, List.of("#outer", "#inner"), false, 1);
            fill(compiler, PlaywrightRecorderAdapter.Kind.ADDED, "before", "field1", PlaywrightRecorderAdapter.Classification.ORDINARY, nested);
            fill(compiler, PlaywrightRecorderAdapter.Kind.UPDATED, "after", "field1", PlaywrightRecorderAdapter.Classification.ORDINARY, nested);
            fill(compiler, PlaywrightRecorderAdapter.Kind.ADDED, "new frame", "field2", PlaywrightRecorderAdapter.Classification.ORDINARY,
                    target("main", 4, 1, List.of("#outer", "#inner"), true, 2));
            try (var result = compiler.freeze(stamp(), () -> {})) {
                var steps = result.candidates().stream().map(JourneyRecording.Candidate::step).toList();
                assertEquals(List.of(AuthStep.Type.ENTER_FRAME, AuthStep.Type.ENTER_FRAME, AuthStep.Type.INPUT, AuthStep.Type.MAIN_FRAME,
                        AuthStep.Type.ENTER_FRAME, AuthStep.Type.ENTER_FRAME, AuthStep.Type.INPUT), steps.stream().map(AuthStep.Definition::type).toList());
                assertEquals("after", steps.get(2).value()); AuthStepSequence.validate(steps);
            }
        }
    }

    @Test void oneOpeningActionIsSuggestedButDelayedPopupAfterTwoClicksRequiresAChoiceIncludingTheEarlierClick() {
        for (boolean ambiguous : new boolean[]{false, true}) try (var compiler = new RecordedActionCompiler("main", "https://example.test")) {
            click(compiler, "main", 10); if (ambiguous) click(compiler, "main", 15);
            compiler.pageOpened("child", "main", 20);
            fill(compiler, PlaywrightRecorderAdapter.Kind.ADDED, "popup text", "field", PlaywrightRecorderAdapter.Classification.ORDINARY,
                    target("child", 2, 1, List.of(), false, 30));
            try (var result = compiler.freeze(stamp(), () -> {})) {
                assertTrue(result.complete()); var popup = result.popups().getFirst(); assertEquals(ambiguous ? 2 : 1, popup.openingSteps().size());
                var steps = result.candidates().stream().map(JourneyRecording.Candidate::step).toList();
                if (ambiguous) { assertNull(popup.suggestedStep()); assertThrows(ConfigurationException.class, () -> AuthStepSequence.validate(steps)); }
                else { assertEquals(popup.openingSteps().getFirst(), popup.suggestedStep()); AuthStepSequence.validate(steps); }
            }
        }
    }

    @Test void unsupportedKeysAndLostUpdateAssociationMarkRecordingPartialWithoutDumpingValues() {
        try (var compiler = new RecordedActionCompiler("main", "https://example.test")) {
            try (var event = new PlaywrightRecorderAdapter.Event(PlaywrightRecorderAdapter.Kind.ADDED, "main",
                    new PlaywrightRecorderAdapter.Action("press", "#field", List.of(), "Escape", 0, "left", 1, false, null, null,
                            new PlaywrightRecorderAdapter.Metadata("", "", "", PlaywrightRecorderAdapter.Classification.UNKNOWN), null), 256)) {
                compiler.accept(event, target("main", 1, 1, List.of(), false, 1));
            }
            fill(compiler, PlaywrightRecorderAdapter.Kind.UPDATED, "CANARY", "field1", PlaywrightRecorderAdapter.Classification.SECRET,
                    target("main", 1, 1, List.of(), false, 2));
            try (var result = compiler.freeze(stamp(), () -> {})) {
                assertFalse(result.complete()); assertTrue(result.problems().stream().anyMatch(s -> s.contains("Browser interaction 1 (pressed Escape) was not added as a step")));
                assertFalse(result.problems().toString().contains("CANARY"));
            }
        }
    }

    @Test void tabAndShiftTabJoinTheSupportedEnterGesturesWithoutLosingTheirKeyChoice() {
        var keys = List.of("Enter", "Control+Enter", "Tab", "Shift+Tab");
        for (int i = 0; i < keys.size(); i++) try (var compiler = new RecordedActionCompiler("main", "https://example.test")) {
            String key = i < 2 ? "Enter" : "Tab"; int modifier = i == 1 ? 2 : i == 3 ? 8 : 0;
            try (var event = new PlaywrightRecorderAdapter.Event(PlaywrightRecorderAdapter.Kind.ADDED, "main",
                    new PlaywrightRecorderAdapter.Action("press", "#field", List.of(), key, modifier, "left", 1, false, null, null,
                            new PlaywrightRecorderAdapter.Metadata("", "", "", PlaywrightRecorderAdapter.Classification.UNKNOWN), null), 256)) {
                compiler.accept(event, target("main", 1, 1, List.of(), false, 1));
            }
            try (var result = compiler.freeze(stamp(), () -> {})) {
                assertTrue(result.complete(), () -> result.problems().toString());
                assertEquals(new AuthStep.Key(keys.get(i)), result.candidates().getFirst().step().operation());
            }
        }
    }

    @Test void omittedInteractionsDescribeKnownGesturesWithoutEchoingKeysSelectorsOrValues() {
        for (String gesture : List.of("double", "right", "modified", "private")) try (var compiler = new RecordedActionCompiler("main", "https://example.test")) {
            fill(compiler, PlaywrightRecorderAdapter.Kind.ADDED, "CANARY_VALUE", "field", PlaywrightRecorderAdapter.Classification.SECRET, target("main", 1, 1, List.of(), false, 1));
            boolean press = gesture.equals("modified") || gesture.equals("private");
            try (var event = new PlaywrightRecorderAdapter.Event(PlaywrightRecorderAdapter.Kind.ADDED, "main",
                    new PlaywrightRecorderAdapter.Action(press ? "press" : "click", "CANARY_SELECTOR", List.of(), gesture.equals("private") ? "CANARY_KEY" : "Enter",
                            gesture.equals("modified") ? 1 : 0, gesture.equals("right") ? "right" : "left", gesture.equals("double") ? 2 : 1, false, null, null,
                            new PlaywrightRecorderAdapter.Metadata("", "", "", PlaywrightRecorderAdapter.Classification.UNKNOWN), null), 256)) {
                compiler.accept(event, target("main", 1, 1, List.of(), false, 2));
            }
            try (var result = compiler.freeze(stamp(), () -> {})) {
                assertFalse(result.complete()); assertEquals(1, result.candidates().size(), "Successfully captured steps remain available");
                String warnings = String.join("\n", result.problems());
                assertTrue(warnings.contains("Browser interaction 2")); assertTrue(warnings.contains("was not added as a step"));
                assertTrue(warnings.contains(switch (gesture) { case "double" -> "double-click"; case "right" -> "right-click"; case "modified" -> "pressed Alt+Enter"; default -> "pressed a key or shortcut"; }));
                assertFalse(warnings.contains("CANARY")); assertFalse(warnings.contains("Recorded action"));
            }
        }
    }

    @Test void limitsIncludeInsertedContextRowsAndNeverReturnATruncatedApplicableSequence() {
        try (var compiler = new RecordedActionCompiler("main", "https://example.test")) {
            for (int i = 0; i < 257; i++) click(compiler, "main", i + 1);
            try (var result = compiler.freeze(stamp(), () -> {}); var values = result.copySecrets()) {
                assertFalse(result.complete()); assertTrue(result.candidates().isEmpty()); assertTrue(values.stepIds().isEmpty());
            }
        }
        try (var compiler = new RecordedActionCompiler("main", "https://example.test")) {
            var path = java.util.stream.IntStream.range(0, 16).mapToObj(i -> "#frame-" + i).toList();
            for (int i = 0; i < 20; i++) fill(compiler, PlaywrightRecorderAdapter.Kind.ADDED, "value", "field-" + i, PlaywrightRecorderAdapter.Classification.ORDINARY,
                    target("main", 1, 1, i % 2 == 0 ? path : List.of(), false, i + 1));
            try (var result = compiler.freeze(stamp(), () -> {})) { assertFalse(result.complete()); assertTrue(result.candidates().isEmpty()); }
        }
    }
}
