import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.util.*;

/** Nonsecret unfinished settings, preserved literally until the user executes the journey. */
record JourneyDraft(Map<String, String> text, Map<String, Boolean> flags,
        JourneyDefinition.SlotKind slotKind, String certificateSha256,
        List<StepsPanel.Input> steps, List<CredentialsPanel.Input> credentials) {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Set<String> FIELDS = Set.of("name", "alias", "url", "navTimeout", "tokenWait", "proxy", "maxAge", "skew", "module", "slot", "origins", "ca");
    private static final Set<String> FLAGS = Set.of("headless", "remember", "mtls");
    JourneyDraft {
        text = Map.copyOf(text); flags = Map.copyOf(flags); steps = List.copyOf(steps); credentials = List.copyOf(credentials);
        if (!text.keySet().equals(FIELDS) || !flags.keySet().equals(FLAGS) || slotKind == null || certificateSha256 == null
                || steps.size() > 256 || credentials.size() > 16) throw new IllegalArgumentException("Invalid journey draft structure.");
        var ids = new HashSet<UUID>();
        steps = steps.stream().map(s -> {
            if (s.id() == null || s.type() == null || s.selector() == null || s.value() == null || s.state() == null || !ids.add(s.id()))
                throw new IllegalArgumentException("Invalid draft step structure.");
            return new StepsPanel.Input(s.id(), s.type(), s.type().requiresSelector() ? s.selector() : "",
                    Set.of(AuthStep.Type.INPUT, AuthStep.Type.WAIT_URL, AuthStep.Type.WAIT_TIME).contains(s.type()) ? s.value() : "", s.state(), s.durationUnit());
        }).toList();
        for (var token : credentials) {
            if (!Set.of("json_path", "regex", "cookie").contains(token.type()) || !Set.of("disabled", "bearer", "header", "cookie").contains(token.injection())
                    || token.name() == null || token.origin() == null || token.path() == null || token.selector() == null || token.domain() == null
                    || token.cookiePath() == null || token.startRegex() == null || token.endRegex() == null || token.destination() == null)
                throw new IllegalArgumentException("Invalid draft token structure.");
        }
    }
    /** Filters project controls out of the journey's raw editor fields. */
    static JourneyDraft capture(Map<String, String> text, Map<String, Boolean> flags, JourneyDefinition.SlotKind slotKind,
            String certificate, List<StepsPanel.Input> steps, List<CredentialsPanel.Input> credentials) {
        var fields = new LinkedHashMap<String, String>(); FIELDS.forEach(k -> fields.put(k, text.getOrDefault(k, "")));
        var options = new LinkedHashMap<String, Boolean>(); FLAGS.forEach(k -> options.put(k, flags.getOrDefault(k, false)));
        return new JourneyDraft(fields, options, slotKind, certificate, steps, credentials);
    }
    /** Retains secure-step owners without interpreting unfinished numeric settings. */
    List<AuthStep.Definition> structuralSteps() {
        return steps.stream().map(s -> new AuthStep.Definition(s.id(), s.type(), s.selector(),
                s.type() == AuthStep.Type.INPUT ? s.value() : null, s.state(), s.type() == AuthStep.Type.WAIT_URL ? s.value() : null, 0)).toList();
    }
    private List<AuthStep.Definition> stepDefinitions() {
        try (var snapshot = new StepsPanel.Snapshot(steps, new HashMap<>())) { return snapshot.definitions(); }
    }
    /** Builds the executable representation through the same strict codec used by native imports. */
    JourneyDefinition compile(UUID id) {
        ObjectNode j = JSON.createObjectNode(); j.put("id", id.toString()); j.put("displayName", text.get("name")); j.put("alias", text.get("alias")); j.put("authenticationUrl", text.get("url").trim()); j.put("rememberSecrets", flags.get("remember"));
        var s = j.putArray("steps"); for (var step : stepDefinitions()) {
            var n = s.addObject().put("id", step.id().toString()).put("type", step.type().wire());
            switch (step.type()) {
                case CLICK, SECURE_INPUT -> n.put("selector", step.selector()); case INPUT -> n.put("selector", step.selector()).put("value", step.value());
                case WAIT_SELECTOR -> { n.put("selector", step.selector()); if (step.state() != null) n.put("state", step.state()); }
                case WAIT_LOAD_STATE -> n.put("state", step.state()); case WAIT_URL -> { n.put("urlPattern", step.urlPattern()); if (step.state() != null) n.put("match", step.state()); } case WAIT_TIME -> n.put("durationMs", step.durationMs());
            }
        }
        var b = j.putObject("browser").put("headless", flags.get("headless")).put("navigationTimeoutMs", seconds(text, "navTimeout")).put("tokenWaitTimeoutMs", seconds(text, "tokenWait"));
        if (!text.get("proxy").isBlank()) b.putObject("proxy").put("url", text.get("proxy").trim());
        j.set("extraction", CredentialsPanel.node(credentials));
        j.set("injection", CredentialsPanel.injectionNode(credentials));
        j.putObject("cache").put("maxAgeSeconds", number(text, "maxAge")).put("refreshSkewSeconds", number(text, "skew"));
        if (flags.get("mtls")) {
            var m = j.putObject("mtls").put("modulePath", text.get("module").trim()).put("certificateSha256", certificateSha256);
            m.putObject("slot").put("kind", slotKind.name().toLowerCase(java.util.Locale.ROOT)).put("value", longNumber(text.get("slot"), "slot"));
            var origins = m.putArray("origins"); for (String origin : text.get("origins").split(",")) if (!origin.isBlank()) origins.add(origin.trim()); optional(m, "trustedCaBundlePath", text.get("ca"));
        }
        var root = JSON.createObjectNode().put("schemaVersion", 1).put("kind", "export").put("revision", UUID.randomUUID().toString()); root.putArray("journeys").add(j); root.putArray("retiredAliases");
        try (var parsed = ConfigManager.parseNative(root.toString(), ConfigManager.DocumentKind.EXPORT)) { return parsed.journeys().getFirst(); }
    }
    /** Supplies only list identity and secret ownership; unfinished settings are never executed. */
    JourneyDefinition definition(UUID id, String displayName, String alias, boolean remember) {
        var mtls = flags.get("mtls") ? new JourneyDefinition.Mtls(text.get("module"), new JourneyDefinition.Slot(slotKind, 0), certificateSha256, List.of(), null) : null;
        return new JourneyDefinition(id, displayName, alias, URI.create(""), remember, structuralSteps(),
                new JourneyDefinition.Browser(flags.get("headless"), null, 30_000, 3000),
                new JourneyDefinition.CombinedExtraction(List.of()), JourneyDefinition.Injection.perToken(List.of()),
                new JourneyDefinition.Cache(1800, 10), mtls, this);
    }
    /** Changes persistence consent without changing the user's unfinished name or alias. */
    JourneyDraft withRemember(boolean remember) {
        var options = new LinkedHashMap<>(flags); options.put("remember", remember);
        return new JourneyDraft(text, options, slotKind, certificateSha256, steps, credentials);
    }
    /** Gives imports fresh step ownership and applies export/import secret preferences. */
    JourneyDraft remap(List<AuthStep.Definition> newSteps, String alias, boolean remember) {
        var raw = new ArrayList<StepsPanel.Input>();
        for (int i = 0; i < steps.size(); i++) { var s = steps.get(i); raw.add(new StepsPanel.Input(newSteps.get(i).id(), s.type(), s.selector(), s.value(), s.state(), s.durationUnit())); }
        var fields = new LinkedHashMap<>(text); fields.put("alias", alias);
        var options = new LinkedHashMap<>(flags); options.put("remember", remember);
        return new JourneyDraft(fields, options, slotKind, certificateSha256, raw, credentials);
    }
    private static int seconds(Map<String, String> values, String key) {
        try { return new java.math.BigDecimal(values.get(key).trim()).multiply(java.math.BigDecimal.valueOf(1000)).intValueExact(); }
        catch (RuntimeException ex) { throw new ConfigManager.NativeFormatException(key + ": enter a valid duration in seconds."); }
    }
    private static int number(Map<String, String> values, String key) {
        try { return Integer.parseInt(values.get(key).trim()); }
        catch (RuntimeException ex) { throw new ConfigManager.NativeFormatException(key + ": enter a whole number."); }
    }
    private static long longNumber(String value, String key) {
        try { return Long.parseLong(value.trim()); }
        catch (RuntimeException ex) { throw new ConfigManager.NativeFormatException(key + ": enter a whole number."); }
    }
    private static void optional(ObjectNode node, String key, String value) { if (!value.isBlank()) node.put(key, value.trim()); }
    @Override public String toString() { return "JourneyDraft[unfinished settings]"; }
}
