package bpsh.journey.persistence;

import bpsh.burp.ui.JourneyRegistryTest;
import bpsh.journey.AuthStep;
import bpsh.journey.ConfigurationException;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.JourneyDraft;
import bpsh.journey.editing.JourneyDraftCompiler;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Version-one typed steps and literal unfinished fields remain distinct at the strict persistence boundary. */
class RecordedJourneyCodecTest {
    private static final ObjectMapper JSON = new ObjectMapper();

    private static ObjectNode root() throws Exception {
        return (ObjectNode) JSON.readTree(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.EXPORT, false, false));
    }

    private static ObjectNode draft(ArrayNode steps) throws Exception {
        var root = root(); var journey = (ObjectNode) root.at("/journeys/0");
        journey.remove(List.of("authenticationUrl", "steps", "browser", "extraction", "injection", "cache"));
        var raw = JourneyDraft.capture(Map.of("url", "https://example.test"), Map.of(), JourneyDefinition.SlotKind.INDEX, "", List.of(), List.of());
        ObjectNode node = JSON.valueToTree(raw); node.set("steps", steps); journey.set("draft", node); return root;
    }

    private static ArrayNode inventory(String name) throws Exception {
        try (var input = RecordedJourneyCodecTest.class.getResourceAsStream("/bpsh/journey/" + name)) {
            assertNotNull(input); return (ArrayNode) JSON.readTree(input);
        }
    }

    private static JourneyDraft readDraft(ObjectNode root) {
        try (var document = JourneyJson.read(root.toString(), JourneyDocument.DocumentKind.EXPORT)) { return document.journeys().getFirst().draft(); }
    }

    @Test void legacyDraftInventoryRetainsDefaultsAndCanonicalWritesOmitOperation() throws Exception {
        var root = draft(inventory("legacy-step-drafts.json")); var before = readDraft(root);
        assertEquals(7, before.steps().size());
        assertTrue(before.steps().stream().allMatch(step -> step.operation() == null && step.durationUnit() == JourneyDraft.DurationUnit.MILLISECONDS));
        try (var document = JourneyJson.read(root.toString(), JourneyDocument.DocumentKind.EXPORT)) {
            var written = JSON.readTree(JourneyJson.write(document));
            for (var step : written.at("/journeys/0/draft/steps")) assertFalse(step.has("operation"));
            assertEquals(before, readDraft((ObjectNode) written));
        }
    }

    @Test void newDraftInventoryRetainsUnsetEmptyAndInvalidLiteralInputsAcrossRoundTrip() throws Exception {
        var root = draft(inventory("recorded-step-drafts.json")); var before = readDraft(root);
        assertEquals(new JourneyDraft.Checked(""), before.steps().get(0).operation());
        assertEquals(new JourneyDraft.Options(List.of("", " admin ", "a,b", "a,b")), before.steps().get(1).operation());
        assertEquals(new JourneyDraft.Key("Control+Enter"), before.steps().get(2).operation());
        assertEquals(new JourneyDraft.Popup("unfinished page", "not a UUID"), before.steps().get(3).operation());
        try (var document = JourneyJson.read(root.toString(), JourneyDocument.DocumentKind.EXPORT)) {
            assertEquals(before, readDraft((ObjectNode) JSON.readTree(JourneyJson.write(document))));
        }
        assertThrows(ConfigurationException.class, () -> JourneyDraftCompiler.steps(before.steps()));
        assertEquals(before.steps().size(), before.structuralSteps().size());
        assertEquals(before.steps().get(3).id(), ((AuthStep.Popup) before.structuralSteps().get(3).operation()).triggerStepId());
        assertNotNull(before.definition(UUID.randomUUID(), "Draft", "draft", false).draft());
    }

    @Test void missingOperationFieldsHaveActionSpecificDefaultsRatherThanAnInferredValue() throws Exception {
        var inputs = inventory("recorded-step-drafts.json"); inputs.forEach(step -> ((ObjectNode) step).remove("operation"));
        var raw = readDraft(draft(inputs));
        for (var step : raw.steps()) assertEquals(JourneyDraft.defaultOperation(step.type()), step.operation());
        var checked = (ObjectNode) inputs.get(0); checked.putObject("operation").put("checked", "false");
        assertNotEquals(raw.steps().getFirst().operation(), readDraft(draft(inputs)).steps().getFirst().operation());
        var options = (ObjectNode) inputs.get(1); options.putObject("operation").putArray("values").add("");
        assertEquals(new JourneyDraft.Options(List.of("")), readDraft(draft(inputs)).steps().get(1).operation());
        options.putObject("operation").putArray("values");
        assertEquals(new JourneyDraft.Options(List.of()), readDraft(draft(inputs)).steps().get(1).operation());
    }

    @Test void draftReaderRejectsUnknownWrongAndNullFieldsWithoutEchoingContent() throws Exception {
        for (String mutation : List.of("unknown", "operationNull", "wrongChecked", "wrongValues", "wrongKey", "unknownOperation", "nullValue", "nullUnit")) {
            var steps = inventory("recorded-step-drafts.json"); var row = (ObjectNode) steps.get(0);
            switch (mutation) {
                case "unknown" -> row.put("CANARY", "CANARY"); case "operationNull" -> row.putNull("operation");
                case "wrongChecked" -> row.putObject("operation").put("checked", false);
                case "wrongValues" -> ((ObjectNode) steps.get(1)).putObject("operation").putArray("values").addNull();
                case "wrongKey" -> ((ObjectNode) steps.get(2)).putObject("operation").put("holdCtrl", "false");
                case "unknownOperation" -> row.putObject("operation").put("CANARY", "CANARY");
                case "nullValue" -> row.putNull("value"); case "nullUnit" -> row.putNull("durationUnit");
            }
            var root = draft(steps);
            assertFalse(assertThrows(ConfigurationException.class, () -> readDraft(root)).getMessage().contains("CANARY"));
        }
        var old = inventory("legacy-step-drafts.json"); ((ObjectNode) old.get(0)).putObject("operation");
        var root = draft(old); assertThrows(ConfigurationException.class, () -> readDraft(root));
    }

    @Test void typedOperationsUseStrictVersionOneEncodingAndRoundTrip() throws Exception {
        var click = new AuthStep.Definition(UUID.randomUUID(), AuthStep.Type.CLICK, "#open", null, null, null, null);
        var sequence = List.of(
                typed(AuthStep.Type.SET_CHECKED, new AuthStep.Checked(false)), typed(AuthStep.Type.SELECT_OPTIONS, new AuthStep.Options(List.of("", "a,b"))),
                typed(AuthStep.Type.PRESS_KEY, new AuthStep.Key("Control+Enter")),
                typed(AuthStep.Type.ENTER_FRAME, new AuthStep.Context()), typed(AuthStep.Type.PARENT_FRAME, new AuthStep.Context()),
                typed(AuthStep.Type.MAIN_FRAME, new AuthStep.Context()),
                typed(AuthStep.Type.EXPECT_POPUP, new AuthStep.Popup("popup-1", click.id())), click,
                typed(AuthStep.Type.SWITCH_PAGE, new AuthStep.PageTarget("popup-1")), typed(AuthStep.Type.CLOSE_PAGE, new AuthStep.Context()),
                typed(AuthStep.Type.SWITCH_PAGE, new AuthStep.PageTarget("main")));
        var root = root(); var steps = ((ObjectNode) root.at("/journeys/0")).putArray("steps"); sequence.forEach(s -> steps.add(JourneyJson.stepNode(s)));
        assertEquals(1, root.path("schemaVersion").intValue());
        try (var document = JourneyJson.read(root.toString(), JourneyDocument.DocumentKind.EXPORT);
             var again = JourneyJson.read(JourneyJson.write(document), JourneyDocument.DocumentKind.EXPORT)) {
            assertEquals(sequence, again.journeys().getFirst().steps());
            assertEquals(sequence, JourneyDraftCompiler.steps(sequence.stream().map(JourneyDraft.StepInput::fromDefinition).toList()));
        }
        ((ObjectNode) steps.get(0)).put("value", "CANARY");
        assertFalse(assertThrows(ConfigurationException.class, () -> JourneyJson.read(root.toString(), JourneyDocument.DocumentKind.EXPORT)).getMessage().contains("CANARY"));
    }

    @Test void keyChoicesRoundTripAsExecutableStepsAndUnfinishedDraftsWithoutChangingTabToEnter() throws Exception {
        for (String key : List.of("Enter", "Control+Enter", "Tab", "Shift+Tab")) {
            var definition = typed(AuthStep.Type.PRESS_KEY, new AuthStep.Key(key));
            var nativeRoot = root(); var nativeSteps = ((ObjectNode) nativeRoot.at("/journeys/0")).putArray("steps"); nativeSteps.add(JourneyJson.stepNode(definition));
            try (var document = JourneyJson.read(nativeRoot.toString(), JourneyDocument.DocumentKind.EXPORT);
                 var written = JourneyJson.read(JourneyJson.write(document), JourneyDocument.DocumentKind.EXPORT)) {
                assertEquals(List.of(definition), written.journeys().getFirst().steps());
            }
            var rows = inventory("recorded-step-drafts.json"); ((ObjectNode) rows.get(2)).putObject("operation").put("key", key);
            var draftRoot = draft(rows); var raw = readDraft(draftRoot);
            assertEquals(new JourneyDraft.Key(key), raw.steps().get(2).operation());
            try (var document = JourneyJson.read(draftRoot.toString(), JourneyDocument.DocumentKind.EXPORT)) {
                assertEquals(raw, readDraft((ObjectNode) JSON.readTree(JourneyJson.write(document))));
            }
            assertEquals(List.of(definition), JourneyDraftCompiler.executableSteps(List.of(JourneyDraft.StepInput.fromDefinition(definition))));
        }
        var rows = inventory("recorded-step-drafts.json"); ((ObjectNode) rows.get(2)).putObject("operation").put("key", "Tab").put("holdCtrl", true);
        assertThrows(ConfigurationException.class, () -> readDraft(draft(rows)));
        var invalid = new JourneyDraft.StepInput(UUID.randomUUID(), AuthStep.Type.PRESS_KEY, "#field", "", "", JourneyDraft.DurationUnit.SECONDS, new JourneyDraft.Key("CANARY"));
        assertFalse(assertThrows(ConfigurationException.class, () -> JourneyDraftCompiler.executableSteps(List.of(invalid))).getMessage().contains("CANARY"));
    }

    @Test void remappingUsesOriginalRawReferencesAndLeavesInvalidReferencesLiteral() throws Exception {
        var rows = inventory("recorded-step-drafts.json"); var popup = (ObjectNode) rows.get(3);
        String destination = rows.get(2).path("id").textValue();
        for (String reference : List.of(destination, "", "not UUID", UUID.randomUUID().toString(), "1-1-1-1-1")) {
            popup.putObject("operation").put("pageRef", "popup-1").put("triggerStepId", reference);
            var raw = readDraft(draft(rows)); var copied = raw.structuralSteps().stream().map(s -> s.withId(UUID.randomUUID())).toList();
            var remapped = raw.remap(copied, "copy", false);
            assertEquals(reference.equals(destination) ? copied.get(2).id().toString() : reference,
                    ((JourneyDraft.Popup) remapped.steps().get(3).operation()).triggerStepId());
            assertThrows(ConfigurationException.class, () -> JourneyDraftCompiler.steps(remapped.steps()));
        }
    }

    private static AuthStep.Definition typed(AuthStep.Type type, AuthStep.Operation operation) {
        return new AuthStep.Definition(UUID.randomUUID(), type, type.requiresSelector() ? "#target" : null, null, null, null, null, operation);
    }
}
