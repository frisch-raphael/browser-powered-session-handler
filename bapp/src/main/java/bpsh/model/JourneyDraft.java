package bpsh.model;

import java.net.URI;
import java.util.*;

/** Nonsecret unfinished settings, preserved literally until the user executes the journey. */
public record JourneyDraft(Map<String, String> text, Map<String, Boolean> flags,
        JourneyDefinition.SlotKind slotKind, String certificateSha256,
        List<StepInput> steps, List<CredentialInput> credentials) {
    /** Captures raw editor text without performing validation or JSON/storage work on the EDT. */
    public record StepInput(UUID id, AuthStep.Type type, String selector, String value, String state, DurationUnit durationUnit) {
        public StepInput { if (durationUnit == null) durationUnit = DurationUnit.MILLISECONDS; }
        public StepInput(UUID id, AuthStep.Type type, String selector, String value, String state) { this(id, type, selector, value, state, DurationUnit.MILLISECONDS); }
    }
    /** Old unfinished drafts retain milliseconds; newly captured UI text explicitly records seconds. */
    public enum DurationUnit { MILLISECONDS, SECONDS }
    /** Immutable EDT snapshot, validated by the background codec. */
    public record CredentialInput(String name, String type, String origin, String path, String selector, String domain,
                 String cookiePath, String startRegex, String endRegex, String injection, String destination) {
        public boolean cookie() { return type.equals("cookie"); }

        @Override public String toString() { return "CredentialInput[type=" + type + "]"; }
    }
    private static final Set<String> FIELDS = Set.of("name", "alias", "url", "navTimeout", "tokenWait", "proxy", "maxAge", "skew", "module", "slot", "origins", "ca");
    private static final Set<String> FLAGS = Set.of("headless", "remember", "mtls");
    public JourneyDraft {
        text = Map.copyOf(text); flags = Map.copyOf(flags); steps = List.copyOf(steps); credentials = List.copyOf(credentials);
        if (!text.keySet().equals(FIELDS) || !flags.keySet().equals(FLAGS) || slotKind == null || certificateSha256 == null
                || steps.size() > 256 || credentials.size() > 16) throw new IllegalArgumentException("Invalid journey draft structure.");
        var ids = new HashSet<UUID>();
        steps = steps.stream().map(s -> {
            if (s.id() == null || s.type() == null || s.selector() == null || s.value() == null || s.state() == null || !ids.add(s.id()))
                throw new IllegalArgumentException("Invalid draft step structure.");
            return new StepInput(s.id(), s.type(), s.type().requiresSelector() ? s.selector() : "",
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
    public static JourneyDraft capture(Map<String, String> text, Map<String, Boolean> flags, JourneyDefinition.SlotKind slotKind,
            String certificate, List<StepInput> steps, List<CredentialInput> credentials) {
        var fields = new LinkedHashMap<String, String>(); FIELDS.forEach(k -> fields.put(k, text.getOrDefault(k, "")));
        var options = new LinkedHashMap<String, Boolean>(); FLAGS.forEach(k -> options.put(k, flags.getOrDefault(k, false)));
        return new JourneyDraft(fields, options, slotKind, certificate, steps, credentials);
    }
    /** Retains secure-step owners without interpreting unfinished numeric settings. */
    public List<AuthStep.Definition> structuralSteps() {
        return steps.stream().map(s -> new AuthStep.Definition(s.id(), s.type(), s.selector(),
                s.type() == AuthStep.Type.INPUT ? s.value() : null, s.state(), s.type() == AuthStep.Type.WAIT_URL ? s.value() : null, 0)).toList();
    }


    /** Supplies only list identity and secret ownership; unfinished settings are never executed. */
    public JourneyDefinition definition(UUID id, String displayName, String alias, boolean remember) {
        var mtls = flags.get("mtls") ? new JourneyDefinition.Mtls(text.get("module"), new JourneyDefinition.Slot(slotKind, 0), certificateSha256, List.of(), null) : null;
        return new JourneyDefinition(id, displayName, alias, URI.create(""), remember, structuralSteps(),
                new JourneyDefinition.Browser(flags.get("headless"), null, 30_000, 3000),
                new JourneyDefinition.CombinedExtraction(List.of()), JourneyDefinition.Injection.perToken(List.of()),
                new JourneyDefinition.Cache(1800, 10), mtls, this);
    }
    /** Changes persistence consent without changing the user's unfinished name or alias. */
    public JourneyDraft withRemember(boolean remember) {
        var options = new LinkedHashMap<>(flags); options.put("remember", remember);
        return new JourneyDraft(text, options, slotKind, certificateSha256, steps, credentials);
    }
    /** Gives imports fresh step ownership and applies export/import secret preferences. */
    public JourneyDraft remap(List<AuthStep.Definition> newSteps, String alias, boolean remember) {
        var raw = new ArrayList<StepInput>();
        for (int i = 0; i < steps.size(); i++) { var s = steps.get(i); raw.add(new StepInput(newSteps.get(i).id(), s.type(), s.selector(), s.value(), s.state(), s.durationUnit())); }
        var fields = new LinkedHashMap<>(text); fields.put("alias", alias);
        var options = new LinkedHashMap<>(flags); options.put("remember", remember);
        return new JourneyDraft(fields, options, slotKind, certificateSha256, raw, credentials);
    }




    @Override public String toString() { return "JourneyDraft[unfinished settings]"; }
}
