package bpsh.journey.persistence;

import bpsh.journey.JourneyDefinition;
import bpsh.journey.BrowserSetup;
import bpsh.journey.AuthStep;
import com.fasterxml.jackson.databind.node.ObjectNode;

/** Strict JSON boundary shared by storage, authoring and native transfer. No storage access occurs here. */
public final class JourneyJson {
    private JourneyJson() {}
    /** @return Strictly validated setup without requiring a full journey, capture rules or storage access. */
    public static BrowserSetup readSetup(ObjectNode node) { return NativeJourneyCodec.parseSetup(node); }
    /** @return Canonical nonsecret step JSON shared by compilation and persistence. */
    public static ObjectNode stepNode(AuthStep.Definition step) { return NativeJourneyCodec.stepNode(step); }
    /** Validates a reviewed sequence independently of unfinished capture or cache settings. */
    public static java.util.List<AuthStep.Definition> validateSteps(java.util.List<AuthStep.Definition> steps) {
        var node = new com.fasterxml.jackson.databind.ObjectMapper().createArrayNode(); steps.forEach(step -> node.add(stepNode(step)));
        return NativeJourneyCodec.parseSteps(node, "steps");
    }
    /** @return A caller-owned validated envelope. */
    public static JourneyDocument read(String json, JourneyDocument.DocumentKind expected) { return NativeDocumentCodec.parseNative(json, expected); }
    /** @return Managed JSON using each journey's remembering consent. */
    public static String write(JourneyDocument document) { return NativeDocumentCodec.nativeToJson(document); }
    /** @return Export JSON using explicit secret inclusion consent. */
    public static String write(JourneyDocument document, boolean includeSecrets) { return NativeDocumentCodec.nativeToJson(document, includeSecrets); }
    /** @return An independent extraction JSON object. */
    public static ObjectNode extractionNode(JourneyDefinition.Extraction extraction) { return NativeJourneyCodec.extractionNode(extraction); }
    /** @return An independent injection JSON object. */
    public static ObjectNode injectionNode(JourneyDefinition.Injection injection) { return NativeJourneyCodec.injectionNode(injection); }
}
