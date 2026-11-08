package bpsh.journey.editing;

import bpsh.journey.persistence.JourneyDocument;
import bpsh.journey.persistence.JourneyJson;

import bpsh.journey.AuthStep;
import bpsh.journey.ConfigurationException;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.JourneyDraft;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.math.BigDecimal;
import java.util.*;

/** Compiles nonsecret editor snapshots through the strict native codec, independently of Swing. */
public final class JourneyDraftCompiler {
    private static final ObjectMapper JSON = new ObjectMapper();
    private JourneyDraftCompiler() {}
    /** New row identities and their complete mapping for one atomic recording replacement. */
    public record RemappedSteps(List<JourneyDraft.StepInput> inputs, Map<UUID, UUID> ids) {
        public RemappedSteps { inputs = List.copyOf(inputs); ids = Map.copyOf(ids); }
    }
    /** Validates only the proposed steps through the strict shared codec, off the EDT. */
    public static List<AuthStep.Definition> executableSteps(List<JourneyDraft.StepInput> inputs) { return JourneyJson.validateSteps(steps(inputs)); }
    /** Allocates all destination identities before remapping raw popup triggers. */
    public static RemappedSteps newStepIdentities(List<JourneyDraft.StepInput> inputs) {
        Map<UUID, UUID> ids = new HashMap<>(); inputs.forEach(input -> ids.put(input.id(), UUID.randomUUID()));
        return new RemappedSteps(inputs.stream().map(input -> input.remap(ids)).toList(), ids);
    }
    /** Moves a reviewed declaration immediately before the explicitly chosen opening action. */
    public static List<JourneyDraft.StepInput> placePopup(List<JourneyDraft.StepInput> inputs, UUID declaration, String pageRef, UUID trigger) {
        var rows = new ArrayList<>(inputs); rows.removeIf(row -> row.id().equals(declaration));
        for (int i = 0; i < rows.size(); i++) if (rows.get(i).id().equals(trigger)) {
            if (!Set.of(AuthStep.Type.CLICK, AuthStep.Type.PRESS_KEY).contains(rows.get(i).type())) break;
            rows.add(i, new JourneyDraft.StepInput(declaration, AuthStep.Type.EXPECT_POPUP, "", "", "", JourneyDraft.DurationUnit.SECONDS,
                    new JourneyDraft.Popup(pageRef, trigger.toString()))); return List.copyOf(rows);
        }
        throw new ConfigurationException("steps: choose an available Click element or Press key opening step.");
    }
    /** Builds the executable representation through the same strict codec used by native imports. */
    public static JourneyDefinition compile(JourneyDraft draft, UUID id) {
        var text = draft.text(); var flags = draft.flags();
        var credentials = draft.credentials();
        var definitions = steps(draft.steps());
        ObjectNode j = BrowserSetupCompiler.node(draft); j.put("id", id.toString()); j.put("displayName", text.get("name")); j.put("alias", text.get("alias")); j.put("authenticationUrl", text.get("url").trim()); j.put("rememberSecrets", flags.get("remember"));
        var s = j.putArray("steps"); definitions.forEach(step -> s.add(JourneyJson.stepNode(step)));
        ((ObjectNode) j.get("browser")).put("tokenWaitTimeoutMs", BrowserSetupCompiler.seconds(text, "tokenWait"));
        j.set("extraction", JourneyDraftCompiler.extractionNode(credentials));
        j.set("injection", JourneyDraftCompiler.injectionNode(credentials));
        j.putObject("cache").put("maxAgeSeconds", number(text, "maxAge")).put("refreshSkewSeconds", number(text, "skew"));
        var root = JSON.createObjectNode().put("schemaVersion", 1).put("kind", "export").put("revision", UUID.randomUUID().toString()); root.putArray("journeys").add(j); root.putArray("retiredAliases");
        try (var parsed = JourneyJson.read(root.toString(), JourneyDocument.DocumentKind.EXPORT)) { return parsed.journeys().getFirst(); }
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
                    i.type() == AuthStep.Type.WAIT_URL ? i.value() : null, duration, operation(i, index)));
        }
        bpsh.journey.AuthStepSequence.validate(definitions);
        return List.copyOf(definitions);
    }
    private static AuthStep.Operation operation(JourneyDraft.StepInput input, int index) {
        String path = "steps[" + index + "].";
        if (input.operation() == null) return AuthStep.defaultOperation(input.type(), input.id());
        return switch (input.operation()) {
            case JourneyDraft.Checked c -> {
                if (!Set.of("true", "false").contains(c.checked())) throw new ConfigurationException(path + "checked: choose Checked or Unchecked.");
                yield new AuthStep.Checked(Boolean.parseBoolean(c.checked()));
            }
            case JourneyDraft.Options o -> new AuthStep.Options(o.values());
            case JourneyDraft.Key k -> {
                if (!AuthStep.KEYS.contains(k.key())) throw new ConfigurationException(path + "key: choose Enter, Ctrl+Enter, Tab or Shift+Tab.");
                yield new AuthStep.Key(k.key());
            }
            case JourneyDraft.PageTarget p -> new AuthStep.PageTarget(p.pageRef());
            case JourneyDraft.Popup p -> {
                UUID trigger;
                try { trigger = UUID.fromString(p.triggerStepId()); if (!trigger.toString().equals(p.triggerStepId()) || trigger.version() != 4 || trigger.variant() != 2) throw new IllegalArgumentException(); }
                catch (IllegalArgumentException error) { throw new ConfigurationException(path + "triggerStepId: choose the next Click element or Press key step."); }
                yield new AuthStep.Popup(p.pageRef(), trigger);
            }
        };
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
        if (inputs.size() == 1 && inputs.getFirst().name().isBlank()) return credentialNode(inputs.getFirst());
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
            if (inputs.size() > 1 || !input.name().isBlank()) token.put("tokenName", input.name().trim());
            if (input.injection().equals("header") || input.injection().equals("cookie")) token.put("name", input.destination().trim());
        }
        return node;
    }
    private static int number(Map<String, String> values, String key) {
        try { return Integer.parseInt(values.get(key).trim()); }
        catch (RuntimeException ex) { throw new ConfigurationException(key + ": enter a whole number."); }
    }
}
