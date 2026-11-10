package bpsh.journey;

import java.net.URI;
import java.util.*;

/** Nonsecret unfinished settings, preserved literally until the user executes the journey. */
public record JourneyDraft(Map<String, String> text, Map<String, Boolean> flags,
        JourneyDefinition.SlotKind slotKind, String certificateSha256,
        List<StepInput> steps, List<CredentialInput> credentials) {
    /** Captures raw editor text without performing validation or JSON/storage work on the EDT. */
    public record StepInput(UUID id, AuthStep.Type type, String selector, String value, String state, DurationUnit durationUnit, Operation operation) {
        public StepInput {
            if (durationUnit == null) durationUnit = DurationUnit.MILLISECONDS;
            if (operation == null) operation = defaultOperation(type);
            var expected = defaultOperation(type);
            if (expected == null ? operation != null : expected.getClass() != operation.getClass())
                throw new IllegalArgumentException("Invalid draft operation structure.");
        }
        public StepInput(UUID id, AuthStep.Type type, String selector, String value, String state, DurationUnit durationUnit) { this(id, type, selector, value, state, durationUnit, null); }
        public StepInput(UUID id, AuthStep.Type type, String selector, String value, String state) { this(id, type, selector, value, state, DurationUnit.MILLISECONDS); }
        /** Supplies identity-only placeholders without compiling unfinished user input. */
        public AuthStep.Definition structuralStep() {
            return new AuthStep.Definition(id, type, selector, type == AuthStep.Type.INPUT ? value : null,
                    state, type == AuthStep.Type.WAIT_URL ? value : null, 0, AuthStep.defaultOperation(type, id));
        }
        /** Remaps raw references without making invalid text executable or rebinding unresolved owners. */
        public StepInput remap(Map<UUID, UUID> ids) {
            var payload = operation;
            if (payload instanceof Popup popup) {
                String trigger = popup.triggerStepId();
                try {
                    UUID original = UUID.fromString(trigger);
                    if (original.toString().equals(trigger) && original.version() == 4 && original.variant() == 2 && ids.containsKey(original)) trigger = ids.get(original).toString();
                } catch (IllegalArgumentException ignored) { /* retain literal unfinished input */ }
                payload = new Popup(popup.pageRef(), trigger);
            }
            return new StepInput(ids.getOrDefault(id, id), type, selector, value, state, durationUnit, payload);
        }
        /** Captures a validated definition as raw editor fields, keeping secret text separate. */
        public static StepInput fromDefinition(AuthStep.Definition s) {
            Operation operation = s.operation() == null ? null : switch (s.operation()) {
                case AuthStep.Checked c -> new Checked(Boolean.toString(c.checked()));
                case AuthStep.Options o -> new Options(o.values());
                case AuthStep.Key k -> new Key(k.key());
                case AuthStep.Popup p -> new Popup(p.pageRef(), p.triggerStepId().toString());
                case AuthStep.PageTarget p -> new PageTarget(p.pageRef());
                case AuthStep.Context ignored -> null;
            };
            String value = switch (s.type()) {
                case INPUT -> s.value() == null ? "" : s.value(); case WAIT_URL -> s.urlPattern() == null ? "" : s.urlPattern();
                case WAIT_TIME -> s.durationMs() == null ? "" : s.durationMs().toString(); default -> "";
            };
            return new StepInput(s.id(), s.type(), s.selector() == null ? "" : s.selector(), value,
                    s.state() == null ? "" : s.state(), DurationUnit.MILLISECONDS, operation);
        }
        @Override public String toString() { return "StepInput[id=" + id + ", type=" + type + "]"; }
    }
    /** Literal nonsecret inputs for unfinished operations. */
    public sealed interface Operation permits Checked, Options, Key, Popup, PageTarget {}
    /** Empty means no state has been chosen. */
    public record Checked(String checked) implements Operation { public Checked { Objects.requireNonNull(checked); } }
    /** One exact option value per row, including empty rows. */
    public record Options(List<String> values) implements Operation {
        public Options { values = List.copyOf(values); }
        @Override public String toString() { return "Options[count=" + values.size() + "]"; }
    }
    /** Literal selection from the supported key choices, retained while a draft is unfinished. */
    public record Key(String key) implements Operation { public Key { Objects.requireNonNull(key); } }
    /** Raw names and trigger text remain editable even while invalid. */
    public record Popup(String pageRef, String triggerStepId) implements Operation {
        public Popup { Objects.requireNonNull(pageRef); Objects.requireNonNull(triggerStepId); }
        @Override public String toString() { return "Popup[unfinished reference]"; }
    }
    /** Empty is distinct from explicitly selecting the initial page. */
    public record PageTarget(String pageRef) implements Operation {
        public PageTarget { Objects.requireNonNull(pageRef); }
        @Override public String toString() { return "PageTarget[unfinished reference]"; }
    }
    /** @return Empty fields belonging to the selected action only. */
    public static Operation defaultOperation(AuthStep.Type type) {
        if (type == null) return null;
        return switch (type) {
            case SET_CHECKED -> new Checked(""); case SELECT_OPTIONS -> new Options(List.of());
            case PRESS_KEY -> new Key("Enter"); case EXPECT_POPUP -> new Popup("", "");
            case SWITCH_PAGE -> new PageTarget(""); default -> null;
        };
    }
    /** Old unfinished drafts retain milliseconds; newly captured UI text explicitly records seconds. */
    public enum DurationUnit { MILLISECONDS, SECONDS }
    /** Immutable EDT snapshot, validated by the background codec. */
    public record CredentialInput(String name, String type, String origin, String path, String selector, String domain,
                 String cookiePath, String startRegex, String endRegex, String injection, String destination) {
        public boolean cookie() { return type.equals("cookie"); }

        @Override public String toString() { return "CredentialInput[type=" + type + "]"; }
    }
    private static final Set<String> FIELDS = Set.of("name", "alias", "url", "navTimeout", "tokenWait", "proxy", "maxAge", "skew", "module", "slot", "origins", "ca", "httpProtocol", "httpUsername", "httpDomain", "httpWorkstation", "httpOrigins");
    private static final Set<String> FLAGS = Set.of("headless", "remember", "mtls", "ignoreHttpsErrors", "httpAuthentication", "formAuthentication");
    public JourneyDraft {
        if (!flags.containsKey("ignoreHttpsErrors")) { flags = new LinkedHashMap<>(flags); flags.put("ignoreHttpsErrors", false); }
        // Schema-1 drafts acquire disabled HTTP settings without changing their existing fields.
        if (!flags.containsKey("httpAuthentication")) { flags = new LinkedHashMap<>(flags); flags.put("httpAuthentication", false); }
        if (!flags.containsKey("formAuthentication")) { flags = new LinkedHashMap<>(flags); flags.put("formAuthentication", defaultFormAuthentication(flags, !steps.isEmpty())); }
        if (!text.containsKey("httpProtocol")) {
            text = new LinkedHashMap<>(text); text.put("httpProtocol", "NTLM_V2");
            for (String field : List.of("httpUsername", "httpDomain", "httpWorkstation", "httpOrigins")) text.put(field, "");
        }
        text = Map.copyOf(text); flags = Map.copyOf(flags); steps = List.copyOf(steps); credentials = List.copyOf(credentials);
        if (!text.keySet().equals(FIELDS) || !flags.keySet().equals(FLAGS) || slotKind == null || certificateSha256 == null
                || steps.size() > 256 || credentials.size() > 16) throw new IllegalArgumentException("Invalid journey draft structure.");
        var ids = new HashSet<UUID>();
        steps = steps.stream().map(s -> {
            if (s.id() == null || s.type() == null || s.selector() == null || s.value() == null || s.state() == null || !ids.add(s.id()))
                throw new IllegalArgumentException("Invalid draft step structure.");
            return new StepInput(s.id(), s.type(), s.type().requiresSelector() ? s.selector() : "",
                    Set.of(AuthStep.Type.INPUT, AuthStep.Type.WAIT_URL, AuthStep.Type.WAIT_TIME).contains(s.type()) ? s.value() : "",
                    Set.of(AuthStep.Type.CLICK, AuthStep.Type.INPUT, AuthStep.Type.SECURE_INPUT, AuthStep.Type.WAIT_LOAD_STATE, AuthStep.Type.WAIT_URL, AuthStep.Type.WAIT_TIME, AuthStep.Type.WAIT_SELECTOR).contains(s.type()) ? s.state() : "", s.durationUnit(), s.operation());
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
        var fields = new LinkedHashMap<String, String>(); FIELDS.forEach(k -> fields.put(k, text.getOrDefault(k, k.equals("httpProtocol") ? "NTLM_V2" : "")));
        var options = new LinkedHashMap<String, Boolean>();
        FLAGS.forEach(k -> options.put(k, flags.getOrDefault(k, k.equals("formAuthentication") && defaultFormAuthentication(flags, !steps.isEmpty()))));
        return new JourneyDraft(fields, options, slotKind, certificate, steps, credentials);
    }
    /** Infers legacy method choices while retaining every previously configured login step. */
    private static boolean defaultFormAuthentication(Map<String, Boolean> flags, boolean hasSteps) {
        return hasSteps || !(flags.getOrDefault("mtls", false) || flags.getOrDefault("httpAuthentication", false));
    }
    /** Retains secure-step owners without interpreting unfinished numeric settings. */
    public List<AuthStep.Definition> structuralSteps() {
        return steps.stream().map(StepInput::structuralStep).toList();
    }


    /** Supplies only list identity and secret ownership; unfinished settings are never executed. */
    public JourneyDefinition definition(UUID id, String displayName, String alias, boolean remember) {
        var mtls = flags.get("mtls") ? new JourneyDefinition.Mtls(text.get("module"), new JourneyDefinition.Slot(slotKind, 0), certificateSha256, List.of(), null) : null;
        return new JourneyDefinition(id, displayName, alias, URI.create(""), remember, structuralSteps(),
                new JourneyDefinition.Browser(flags.get("headless"), null, 30_000, 3000, flags.get("ignoreHttpsErrors"), flags.get("formAuthentication")),
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
        var ids = new HashMap<UUID, UUID>();
        for (int i = 0; i < steps.size(); i++) ids.put(steps.get(i).id(), newSteps.get(i).id());
        steps.forEach(step -> raw.add(step.remap(ids)));
        var fields = new LinkedHashMap<>(text); fields.put("alias", alias);
        var options = new LinkedHashMap<>(flags); options.put("remember", remember);
        return new JourneyDraft(fields, options, slotKind, certificateSha256, raw, credentials);
    }




    @Override public String toString() { return "JourneyDraft[unfinished settings]"; }
}
