package bpsh.config;

import bpsh.model.AuthStep;
import bpsh.model.ConfigurationException;
import bpsh.model.JourneyDefinition;
import bpsh.model.JourneyDraft;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.math.BigDecimal;
import java.util.*;

/** Compiles nonsecret editor snapshots through the strict native codec, independently of Swing. */
public final class JourneyDraftCompiler {
    private static final ObjectMapper JSON = new ObjectMapper();
    private JourneyDraftCompiler() {}
    /** Builds the executable representation through the same strict codec used by native imports. */
    public static JourneyDefinition compile(JourneyDraft draft, UUID id) {
        var text = draft.text(); var flags = draft.flags();
        var credentials = draft.credentials(); var slotKind = draft.slotKind(); var certificateSha256 = draft.certificateSha256();
        ObjectNode j = JSON.createObjectNode(); j.put("id", id.toString()); j.put("displayName", text.get("name")); j.put("alias", text.get("alias")); j.put("authenticationUrl", text.get("url").trim()); j.put("rememberSecrets", flags.get("remember"));
        var s = j.putArray("steps"); for (var step : steps(draft.steps())) {
            var n = s.addObject().put("id", step.id().toString()).put("type", step.type().wire());
            switch (step.type()) {
                case CLICK, SECURE_INPUT -> n.put("selector", step.selector()); case INPUT -> n.put("selector", step.selector()).put("value", step.value());
                case WAIT_SELECTOR -> { n.put("selector", step.selector()); if (step.state() != null) n.put("state", step.state()); }
                case WAIT_LOAD_STATE -> n.put("state", step.state()); case WAIT_URL -> { n.put("urlPattern", step.urlPattern()); if (step.state() != null) n.put("match", step.state()); } case WAIT_TIME -> n.put("durationMs", step.durationMs());
            }
        }
        var b = j.putObject("browser").put("headless", flags.get("headless")).put("navigationTimeoutMs", seconds(text, "navTimeout")).put("tokenWaitTimeoutMs", seconds(text, "tokenWait"));
        if (!text.get("proxy").isBlank()) b.putObject("proxy").put("url", text.get("proxy").trim());
        j.set("extraction", JourneyDraftCompiler.extractionNode(credentials));
        j.set("injection", JourneyDraftCompiler.injectionNode(credentials));
        j.putObject("cache").put("maxAgeSeconds", number(text, "maxAge")).put("refreshSkewSeconds", number(text, "skew"));
        if (flags.get("mtls")) {
            var m = j.putObject("mtls").put("modulePath", text.get("module").trim()).put("certificateSha256", certificateSha256);
            m.putObject("slot").put("kind", slotKind.name().toLowerCase(java.util.Locale.ROOT)).put("value", longNumber(text.get("slot"), "slot"));
            var origins = m.putArray("origins"); for (String origin : text.get("origins").split(",")) if (!origin.isBlank()) origins.add(origin.trim()); optional(m, "trustedCaBundlePath", text.get("ca"));
        }
        var root = JSON.createObjectNode().put("schemaVersion", 1).put("kind", "export").put("revision", UUID.randomUUID().toString()); root.putArray("journeys").add(j); root.putArray("retiredAliases");
        try (var parsed = ConfigManager.parseNative(root.toString(), ConfigManager.DocumentKind.EXPORT)) { return parsed.journeys().getFirst(); }
    }
    /**
     * Builds immutable steps off the EDT, preserving ordinary input whitespace and stable secret owners.
     * @return Ordered definitions, validated fully later by the native codec.
     */
    public static List<AuthStep.Definition> steps(List<JourneyDraft.StepInput> inputs) {
        var definitions = new ArrayList<AuthStep.Definition>();
        for (int index = 0; index < inputs.size(); index++) {
            var i = inputs.get(index); Integer duration = null;
            if (i.type() == AuthStep.Type.WAIT_TIME) try { duration = duration(i.value(), i.durationUnit()); }
            catch (IllegalArgumentException error) { throw new ConfigurationException("steps[" + index + "].durationMs: enter a duration from 0 to 300 seconds, with at most three decimal places."); }
            definitions.add(new AuthStep.Definition(i.id(), i.type(), i.type().requiresSelector() ? i.selector() : null,
                    i.type() == AuthStep.Type.INPUT ? i.value() : null, i.state() != null && (i.type() == AuthStep.Type.WAIT_LOAD_STATE || i.type() == AuthStep.Type.WAIT_SELECTOR && AuthStep.ELEMENT_STATES.contains(i.state()) || i.type() == AuthStep.Type.WAIT_URL && AuthStep.URL_MATCHES.contains(i.state())) ? i.state() : null,
                    i.type() == AuthStep.Type.WAIT_URL ? i.value() : null, duration));
        }
        return List.copyOf(definitions);
    }
/**
     * Converts integer milliseconds or explicit exact seconds without truncating fractional milliseconds.
     * @param value Raw wait editor text, optionally suffixed with ms or s.
     * @return Canonical integer milliseconds; the codec enforces the 0-300000 range.
     */
    public static int duration(String value, JourneyDraft.DurationUnit unit) {
        try {
            String text = value.trim().toLowerCase(java.util.Locale.ROOT);
            if (text.endsWith("ms")) return new BigDecimal(text.substring(0, text.length() - 2).trim()).intValueExact();
            if (text.endsWith("s")) { text = text.substring(0, text.length() - 1).trim(); unit = JourneyDraft.DurationUnit.SECONDS; }
            return new BigDecimal(text).multiply(BigDecimal.valueOf(unit == JourneyDraft.DurationUnit.SECONDS ? 1000 : 1)).intValueExact();
        } catch (RuntimeException ex) { throw new IllegalArgumentException("Wait time requires integer milliseconds or exact seconds such as 1.5s."); }
    }
    private static ObjectNode credentialNode(JourneyDraft.CredentialInput input) {
        var type = input.type(); var origin = input.origin(); var selector = input.selector(); var domain = input.domain();
        var cookiePath = input.cookiePath(); var path = input.path(); var startRegex = input.startRegex(); var endRegex = input.endRegex();
        var node = new com.fasterxml.jackson.databind.ObjectMapper().createObjectNode().put("type", type);
        if (input.cookie()) {
            node.put("originUrl", origin.trim()).put("name", selector.trim());
            if (!domain.isBlank()) node.put("domain", domain.trim());
            if (!cookiePath.isBlank()) node.put("path", cookiePath.trim());
        } else {
            node.put("responseOrigin", origin.trim()).put("pathSubstring", path);
            if (type.equals("regex")) node.put("startRegex", startRegex).put("endRegex", endRegex);
            else node.put("jsonPath", selector.trim());
        }
        return node;
    }
    public static ObjectNode extractionNode(List<JourneyDraft.CredentialInput> inputs) {
        if (inputs.size() == 1) return credentialNode(inputs.getFirst());
        var result = new com.fasterxml.jackson.databind.ObjectMapper().createObjectNode().put("type", "combined");
        var tokens = result.putArray("tokens");
        for (var input : inputs) tokens.addObject().put("name", input.name().trim()).set("selector", credentialNode(input));
        return result;
    }
    /** Captured cookies are implicit; every response token has an explicit destination, including Disabled. */
    public static ObjectNode injectionNode(List<JourneyDraft.CredentialInput> inputs) {
        var node = new com.fasterxml.jackson.databind.ObjectMapper().createObjectNode().put("type", "per_token");
        var tokens = node.putArray("tokens");
        for (var input : inputs) if (!input.cookie()) {
            var token = tokens.addObject().put("type", input.injection());
            if (inputs.size() > 1) token.put("tokenName", input.name().trim());
            if (input.injection().equals("header") || input.injection().equals("cookie")) token.put("name", input.destination().trim());
        }
        return node;
    }
    private static int seconds(Map<String, String> values, String key) {
        try { return new java.math.BigDecimal(values.get(key).trim()).multiply(java.math.BigDecimal.valueOf(1000)).intValueExact(); }
        catch (RuntimeException ex) { throw new ConfigurationException(key + ": enter a valid duration in seconds."); }
    }
    private static int number(Map<String, String> values, String key) {
        try { return Integer.parseInt(values.get(key).trim()); }
        catch (RuntimeException ex) { throw new ConfigurationException(key + ": enter a whole number."); }
    }
    private static long longNumber(String value, String key) {
        try { return Long.parseLong(value.trim()); }
        catch (RuntimeException ex) { throw new ConfigurationException(key + ": enter a whole number."); }
    }
    private static void optional(ObjectNode node, String key, String value) { if (!value.isBlank()) node.put(key, value.trim()); }
}
