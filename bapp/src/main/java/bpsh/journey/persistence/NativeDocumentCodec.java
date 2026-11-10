package bpsh.journey.persistence;

import bpsh.request.RequestSettings;

import bpsh.journey.persistence.JourneyDocument.DocumentKind;
import bpsh.journey.persistence.JourneyDocument;
import bpsh.journey.persistence.JourneyDocument.RetiredAlias;
import bpsh.authentication.credentials.RecoveryPattern;
import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.ConfigurationException;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.SecretStore;
import bpsh.request.RequestSettings.Tool;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import static bpsh.journey.persistence.NativeJourneyCodec.*;
import static bpsh.journey.persistence.NativeJson.*;

/** Strict native JSON codec. Project persistence and revision checks remain in ProjectStore. */
final class NativeDocumentCodec {
    private static final ObjectMapper NATIVE = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(SerializationFeature.INDENT_OUTPUT);
    private NativeDocumentCodec() {}
    /**
     * Parses one strict native envelope without coercion, legacy import or silent recovery.
     *
     * Rejects unknown/duplicate fields, wrong types, unsupported versions and invalid ownership.
     * Loaded alias collisions are intentionally preserved for registry repair; duplicate internal
     * IDs are rejected. Partially allocated secret buffers are closed on every failed parse, and
     * errors discard raw parser causes that might disclose input values.
     *
     * @param json One native JSON object to parse.
     * @param expected Exact kind required by the managed loader or transfer operation.
     * @return Validated caller-owned document; close its secret snapshots after use.
     * @throws bpsh.journey.ConfigurationException If syntax, envelope kind or any native semantic rule is invalid.
     */
    public static JourneyDocument parseNative(String json, DocumentKind expected) {
        Map<UUID, SecretStore.Values> secrets = new HashMap<>();
        try {
            JsonNode root = NATIVE.readTree(json);
            object(root, "$", "schemaVersion", "kind", "revision", "journeys", "retiredAliases", "controls");
            long schemaVersion = number(root.get("schemaVersion"), "schemaVersion", 1, 2);
            DocumentKind kind = enumeration(text(root, "kind", "$"), DocumentKind.class, "kind");
            if (kind != expected) throw invalid("kind", "wrong document type; use Export journeys for transfer");
            UUID revision = uuid(root.get("revision"), "revision");
            List<JourneyDefinition> journeys = new ArrayList<>();
            Set<UUID> ids = new HashSet<>();
            for (JsonNode n : array(root.get("journeys"), "journeys")) {
                if (schemaVersion == 1 && (n.has("httpAuthentication") || n.path("secrets").has("httpPassword")))
                    throw invalid("schemaVersion", "HTTP authentication requires schema version 2");
                JourneyDefinition journey = parseJourney(n);
                if (!ids.add(journey.id())) throw invalid("journeys.id", "duplicate identity");
                journeys.add(journey);
                if (n.has("secrets")) {
                    SecretStore.Values values = parseSecrets(n.get("secrets"), journey);
                    secrets.put(journey.id(), values);
                    if (kind != DocumentKind.EXPORT && !journey.rememberSecrets())
                        throw invalid("journeys.secrets", "requires Remember secrets in managed storage");
                }
            }
            List<RetiredAlias> retired = new ArrayList<>();
            Set<String> retiredNames = new HashSet<>();
            for (JsonNode n : array(root.get("retiredAliases"), "retiredAliases")) {
                object(n, "retiredAliases", "alias", "formerJourneyId", "retiredAt");
                String name = alias(text(n, "alias", "retiredAliases"));
                if (!retiredNames.add(name.toLowerCase(Locale.ROOT))) throw invalid("retiredAliases.alias", "duplicate alias");
                String timestamp = text(n, "retiredAt", "retiredAliases");
                Instant when;
                try {
                    if (!timestamp.endsWith("Z")) throw new IllegalArgumentException();
                    when = Instant.parse(timestamp);
                } catch (RuntimeException ex) { throw invalid("retiredAliases.retiredAt", "requires a UTC ISO-8601 timestamp"); }
                retired.add(new RetiredAlias(name, uuid(n.get("formerJourneyId"), "retiredAliases.formerJourneyId"), when));
            }
            if (kind == DocumentKind.EXPORT && !retired.isEmpty()) throw invalid("retiredAliases", "exports cannot contain retired aliases");
            RequestSettings.Controls controls = null;
            if (kind == DocumentKind.PROJECT) controls = parseControls(root.get("controls"));
            else if (root.has("controls")) throw invalid("controls", "only project documents may contain controls");
            // Conflicting aliases on disk remain visible to the registry, which blocks their resolution.
            return new JourneyDocument(kind, revision, journeys, retired, controls, secrets);
        } catch (ConfigurationException ex) {
            secrets.values().forEach(SecretStore.Values::close); throw ex;
        } catch (Exception ex) {
            secrets.values().forEach(SecretStore.Values::close);
            throw invalid("$", "invalid native JSON; check syntax, duplicate fields and value types");
        }
    }



    /** Validates expiration detection for a session-handling rule. */
    private static JourneyDefinition.Recovery parseRecovery(JsonNode r, String p) {
        String mode = text(r, "mode", p);
        JourneyDefinition.Recovery recovery;
        if (JourneyDefinition.RecoveryMode.STATUS_CODE.matches(mode)) {
            object(r, p, "enabled", "mode", "statusCode");
            recovery = new JourneyDefinition.Recovery(bool(r, "enabled", true), JourneyDefinition.RecoveryMode.STATUS_CODE,
                    integer(r, "statusCode", 401, 100, 599), null);
        } else if (JourneyDefinition.RecoveryMode.REGEX.matches(mode) || JourneyDefinition.RecoveryMode.BOTH.matches(mode)) {
            if (JourneyDefinition.RecoveryMode.BOTH.matches(mode)) object(r, p, "enabled", "mode", "pattern", "statusCode");
            else object(r, p, "enabled", "mode", "pattern");
            String pattern = nonblank(text(r, "pattern", p), p + ".pattern");
            try { RecoveryPattern.compile(pattern); }
            catch (AuthenticationFailure ex) { throw invalid(p + ".pattern", ex.problem()); }
            recovery = new JourneyDefinition.Recovery(bool(r, "enabled", true), JourneyDefinition.RecoveryMode.BOTH.matches(mode) ? JourneyDefinition.RecoveryMode.BOTH : JourneyDefinition.RecoveryMode.REGEX, JourneyDefinition.RecoveryMode.BOTH.matches(mode) ? integer(r, "statusCode", 401, 100, 599) : null, pattern);
        } else throw invalid(p + ".mode", "unsupported value");
        return recovery;
    }


















    /**
     * Validates project-only injection controls, deadlines and independent waiter limits.
     *
     * Request and attempt timeouts must each fit within the cycle budget. Missing/null limits mean
     * Unlimited independently. Selected journey existence is resolved by the registry, not here.
     *
     * @param n Required project controls object; absent members use their defined defaults.
     * @return Immutable controls with canonical enum choices and nullable unlimited limits.
     * @throws bpsh.journey.ConfigurationException If fields, tools, URL mode, deadlines or limits are invalid.
     */
    private static RequestSettings.Controls parseControls(JsonNode n) {
        object(n, "controls", "requestPolicy", "enabled", "rules", "tools", "requestWaitTimeoutMs",
                "attemptTimeoutMs", "cycleTimeoutMs", "maxWaitingRequestsGlobal", "maxWaitingRequestsPerJourney");
        List<RequestSettings.AutomaticRule> rules = new ArrayList<>(); Set<RequestSettings.JourneySelection> identities = new HashSet<>();
        if (n.has("rules")) for (JsonNode rule : array(n.get("rules"), "controls.rules")) {
            String p = "controls.rules[" + rules.size() + "]";
            if (rules.size() == 64) throw invalid("controls.rules", "maximum count is 64");
            object(rule, p, "enabled", "journey", "urlMode", "urlPrefix", "recovery");
            JsonNode j = rule.get("journey"); object(j, p + ".journey", "scope", "id");
            var selection = new RequestSettings.JourneySelection(enumeration(text(j, "scope", p + ".journey"), JourneyDefinition.Scope.class, p + ".journey.scope"), uuid(j.get("id"), p + ".journey.id"));
            if (!identities.add(selection)) throw invalid(p + ".journey", "a journey may appear only once; edit its existing rule");
            RequestSettings.UrlMode mode = enumeration(text(rule, "urlMode", p), RequestSettings.UrlMode.class, p + ".urlMode");
            URI prefix = present(rule, "urlPrefix") ? httpUri(text(rule, "urlPrefix", p), p + ".urlPrefix") : null;
            if ((mode == RequestSettings.UrlMode.SINGLE_URL) != (prefix != null)) throw invalid(p + ".urlPrefix", "required only for single_url mode");
            rules.add(new RequestSettings.AutomaticRule(bool(rule, "enabled", true), selection, mode, prefix, parseRecovery(rule.get("recovery"), p + ".recovery")));
        }
        List<Tool> tools = RequestSettings.Controls.defaults().tools();
        if (n.has("tools")) {
            tools = new ArrayList<>();
            List<String> allowed = RequestSettings.SUPPORTED_TOOLS.stream().map(Tool::name).toList();
            for (JsonNode v : array(n.get("tools"), "controls.tools")) {
                if (!v.isTextual() || !allowed.contains(v.textValue())) throw invalid("controls.tools", "unsupported tool");
                Tool type = Tool.valueOf(v.textValue());
                if (tools.contains(type)) throw invalid("controls.tools", "duplicate tool"); tools.add(type);
            }
        }
        int request = integer(n, "requestWaitTimeoutMs", 60_000, 1000, 600_000);
        int attempt = integer(n, "attemptTimeoutMs", 60_000, 1000, 300_000);
        int cycle = integer(n, "cycleTimeoutMs", 300_000, 1000, 1_800_000);
        if (request > cycle || attempt > cycle) throw invalid("controls.cycleTimeoutMs", "must cover request and attempt timeouts");
        return new RequestSettings.Controls(bool(n, "enabled", false), rules, tools, request, attempt, cycle,
                limit(n, "maxWaitingRequestsGlobal"), limit(n, "maxWaitingRequestsPerJourney"),
                present(n, "requestPolicy") ? enumeration(text(n, "requestPolicy", "controls"), RequestSettings.RequestPolicy.class, "controls.requestPolicy") : RequestSettings.RequestPolicy.WAIT_FOR_LOGIN);
    }

    /**
     * Serializes a native document without enabling the separate export-secret choice.
     *
     * Managed documents still include supplied remembered values. Exports omit all secret values
     * regardless of Remember secrets; use the explicit overload only after Include secrets consent.
     *
     * @param document Caller-owned document; this method does not consume its snapshots.
     * @return Validated native JSON.
     * @throws bpsh.journey.ConfigurationException If the envelope or serialized definitions are invalid.
     */
    public static String nativeToJson(JourneyDocument document) { return nativeToJson(document, false); }
    /**
     * Writes canonical native JSON and validates it before returning any output.
     *
     * Rejects dangling secret ownership. Alias collisions remain editable and block execution. Managed values are included only for
     * Remember secrets; export inclusion is controlled solely by includeExportSecrets. Export
     * remembering flags/retirements are cleared. Closing the validation round-trip cannot close
     * source snapshots, and the original document remains caller-owned.
     *
     * @param d Document whose immutable definitions and owned snapshots are being serialized.
     * @param includeExportSecrets Explicit Include secrets choice, ignored for managed kinds.
     * @return Native JSON with explicit defaults and only consented readable secret values.
     * @throws bpsh.journey.ConfigurationException If collisions, ownership or serialized native fields are invalid.
     */
    public static String nativeToJson(JourneyDocument d, boolean includeExportSecrets) {
        Set<UUID> ids = new HashSet<>();
        for (JourneyDefinition j : d.journeys()) {
            ids.add(j.id());
        }
        if (!ids.containsAll(d.secrets().keySet())) throw invalid("secrets", "secret owner is missing");
        ObjectNode root = NATIVE.createObjectNode(); root.put("schemaVersion", 2); root.put("kind", d.kind().wire()); root.put("revision", d.revision().toString());
        ArrayNode journeys = root.putArray("journeys");
        for (JourneyDefinition j : d.journeys()) {
            ObjectNode n = journeyJson(j, d.kind() == DocumentKind.EXPORT);
            SecretStore.Values secret = d.secrets().get(j.id());
            if (secret != null) bpsh.journey.JourneySecrets.validateSecretOwnership(j, secret);
            if (secret != null && !secret.isEmpty() && (d.kind() == DocumentKind.EXPORT ? includeExportSecrets : j.rememberSecrets()))
                n.set("secrets", secretsJson(secret));
            journeys.add(n);
        }
        root.putArray("retiredAliases"); // Retained schema field only; old reservations have no effect.
        if (d.kind() == DocumentKind.PROJECT) {
            if (d.controls() == null) throw invalid("controls", "project controls are required");
            ObjectNode c = NATIVE.valueToTree(d.controls()); c.put("requestPolicy", d.controls().requestPolicy().name().toLowerCase(Locale.ROOT)); ArrayNode rules = c.putArray("rules");
            for (var rule : d.controls().rules()) {
                ObjectNode r = NATIVE.valueToTree(rule); r.put("urlMode", rule.urlMode().wire());
                ((ObjectNode) r.get("journey")).put("scope", rule.journey().scope().wire());
                ((ObjectNode) r.get("recovery")).put("mode", rule.recovery().mode().wire());
                if (rule.recovery().mode() == JourneyDefinition.RecoveryMode.REGEX) ((ObjectNode) r.get("recovery")).remove("statusCode");
                if (rule.recovery().mode() == JourneyDefinition.RecoveryMode.STATUS_CODE) ((ObjectNode) r.get("recovery")).remove("pattern");
                rules.add(r);
            }
            root.set("controls", c);
        } else if (d.controls() != null) throw invalid("controls", "only project documents may contain controls");
        try {
            String json = NATIVE.writeValueAsString(root);
            try (JourneyDocument checked = parseNative(json, d.kind())) { return json; }
        } catch (JsonProcessingException ex) { throw invalid("$", "could not serialize native configuration"); }
    }
































}
