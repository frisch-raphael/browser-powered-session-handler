package bpsh.config;

import bpsh.credentials.TokenExtractor;
import bpsh.model.AuthStep;
import bpsh.model.AuthenticationFailure;
import bpsh.model.ConfigurationException;
import bpsh.model.CredentialNames;
import bpsh.model.JourneyDefinition;
import bpsh.model.JourneyDraft;
import bpsh.secrets.SecretStore;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import static bpsh.config.NativeJson.*;

/** Native journey, credential and secret encoding, independent of project persistence. */
final class NativeJourneyCodec {
    private static final ObjectMapper NATIVE = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(SerializationFeature.INDENT_OUTPUT);
    private NativeJourneyCodec() {}
    /**
     * Validates a journey definition while keeping secret values outside the returned model.
     *
     * Checks type-specific fields, step identities/count, proxy URL, extraction selectors, cache
     * bounds and RE2 syntax/size/program limits. Secret ownership is parsed separately afterward.
     *
     * @param n Journey object within a native envelope.
     * @return Immutable definition with canonicalized origins and explicit defaults.
     * @throws bpsh.model.ConfigurationException If any definition field or mode-specific combination is invalid.
     */
    static JourneyDefinition parseJourney(JsonNode n) {
        String p = "journeys";
        if (n != null && n.has("draft")) {
            object(n, p, "id", "displayName", "alias", "rememberSecrets", "draft", "secrets");
            try {
                JourneyDraft draft = NATIVE.treeToValue(n.get("draft"), JourneyDraft.class);
                boolean remember = bool(n, "rememberSecrets", false);
                if (draft == null || draft.flags().get("remember") != remember) throw invalid("journeys.draft", "invalid draft structure");
                return draft.definition(uuid(n.get("id"), p + ".id"), nonblank(text(n, "displayName", p), p + ".displayName"), alias(text(n, "alias", p)), remember);
            } catch (ConfigurationException ex) { throw ex; }
            catch (Exception ex) { throw invalid("journeys.draft", "invalid draft structure"); }
        }
        object(n, p, "id", "displayName", "alias", "authenticationUrl", "rememberSecrets", "steps", "browser",
                "extraction", "injection", "cache", "mtls", "secrets");
        UUID id = uuid(n.get("id"), p + ".id");
        String display = nonblank(text(n, "displayName", p), p + ".displayName");
        if (display.codePointCount(0, display.length()) > 128) throw invalid(p + ".displayName", "maximum length is 128");
        List<AuthStep.Definition> steps = new ArrayList<>(); Set<UUID> stepIds = new HashSet<>();
        for (JsonNode step : array(n.get("steps"), p + ".steps")) {
            if (steps.size() == 256) throw invalid(p + ".steps", "maximum count is 256");
            AuthStep.Definition value;
            try { value = parseStep(step); }
            catch (ConfigurationException error) { throw new ConfigurationException(error.getMessage().replaceFirst("^steps", "steps[" + steps.size() + "]")); }
            if (!stepIds.add(value.id())) throw invalid(p + ".steps.id", "duplicate identity");
            steps.add(value);
        }
        JsonNode b = n.get("browser");
        object(b, "browser", "headless", "proxy", "navigationTimeoutMs", "tokenWaitTimeoutMs");
        JourneyDefinition.Proxy proxy = null;
        if (present(b, "proxy")) {
            JsonNode q = b.get("proxy");
            if (q != null && q.has("username")) throw invalid("browser.proxy", "supports a proxy URL only; remove username/password fields and use a proxy listener that requires no authentication");
            object(q, "browser.proxy", "url");
            URI url = origin(text(q, "url", "browser.proxy"), "browser.proxy.url", false);
            if (!"http".equals(url.getScheme())) throw invalid("browser.proxy.url", "requires an HTTP proxy");
            proxy = new JourneyDefinition.Proxy(url);
        }
        JourneyDefinition.Browser browser = new JourneyDefinition.Browser(bool(b, "headless", false), proxy,
                integer(b, "navigationTimeoutMs", 30_000, 1000, 300_000), integer(b, "tokenWaitTimeoutMs", 3000, 1, 300_000));
        JourneyDefinition.Extraction extraction = parseExtraction(n.get("extraction"));
        JourneyDefinition.Injection injection = parseInjection(n.get("injection"), extraction);
        JsonNode c = n.get("cache"); object(c, "cache", "maxAgeSeconds", "refreshSkewSeconds");
        JourneyDefinition.Cache cache = new JourneyDefinition.Cache(integer(c, "maxAgeSeconds", 1800, 5, 86400), integer(c, "refreshSkewSeconds", 10, 0, 3600));
        URI authenticationUrl = httpUri(text(n, "authenticationUrl", p), p + ".authenticationUrl");
        return new JourneyDefinition(id, display, alias(text(n, "alias", p)), authenticationUrl,
                bool(n, "rememberSecrets", false), steps, browser, extraction, injection, cache,
                present(n, "mtls") ? parseMtls(n.get("mtls"), authenticationUrl) : null);
    }
    /** Validates one explicit mapping per response token and rejects conflicting destinations. */
    static JourneyDefinition.Injection parseInjection(JsonNode in, JourneyDefinition.Extraction extraction) {
        String injectionType = text(in, "type", "injection");
        if (!"per_token".equals(injectionType)) throw invalid("injection.type", "use per_token injection with a destination for every response token");
        object(in, "injection", "type", "tokens");
        JsonNode tokens = in.get("tokens");
        if (tokens == null || !tokens.isArray() || tokens.size() > 16) throw invalid("injection.tokens", "requires at most 16 token mappings");
        var sources = new java.util.LinkedHashMap<String, JourneyDefinition.Extraction>();
        if (extraction instanceof JourneyDefinition.CombinedExtraction combined) combined.tokens().forEach(t -> sources.put(t.name(), t.selector()));
        else sources.put("", extraction);
        var cookies = new HashSet<String>(); var headers = new HashSet<String>();
        sources.values().forEach(s -> { if (s instanceof JourneyDefinition.CookieExtraction c) cookies.add(c.name()); });
        var mapped = new HashSet<String>(); var result = new ArrayList<JourneyDefinition.TokenInjection>();
        for (JsonNode token : tokens) {
            String path = "injection.tokens[" + result.size() + "]";
            String name = optionalNonblank(token, "tokenName", path);
            if (name != null) name = name.toLowerCase(Locale.ROOT);
            String key = name == null ? "" : name;
            if (!sources.containsKey(key) || sources.get(key) instanceof JourneyDefinition.CookieExtraction) throw invalid(path + ".tokenName", "choose a captured JSON or regex token; captured cookies use their original names");
            if (!mapped.add(key)) throw invalid(path + ".tokenName", "configure each response token only once");
            String type = text(token, "type", path); JourneyDefinition.InjectionType kind;
            try { kind = JourneyDefinition.InjectionType.valueOf(type.toUpperCase(Locale.ROOT)); }
            catch (IllegalArgumentException ex) { throw invalid(path + ".type", "choose Disabled, Bearer, Header or Cookie"); }
            if (!kind.wire().equals(type)) throw invalid(path + ".type", "choose Disabled, Bearer, Header or Cookie");
            String destination = null;
            switch (kind) {
                case HEADER, COOKIE -> {
                    object(token, path, "tokenName", "type", "name");
                    destination = text(token, "name", path);
                    if (!destination.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+")) throw invalid(path + ".name", "enter a valid header or cookie name");
                    if (kind == JourneyDefinition.InjectionType.HEADER) {
                        if (destination.equalsIgnoreCase("Cookie")) throw invalid(path + ".name", "choose the Cookie destination to insert a named cookie");
                        if (!headers.add(destination.toLowerCase(Locale.ROOT))) throw invalid(path + ".name", "another token already targets this header");
                    } else if (!cookies.add(destination)) throw invalid(path + ".name", "another token or captured cookie already targets this cookie");
                }
                case BEARER, DISABLED -> {
                    object(token, path, "tokenName", "type");
                    if (kind == JourneyDefinition.InjectionType.BEARER && !headers.add("authorization")) throw invalid(path + ".type", "another token already targets the Authorization header");
                }
                default -> throw invalid(path + ".type", "choose Disabled, Bearer, Header or Cookie");
            }
            result.add(new JourneyDefinition.TokenInjection(name, kind, destination));
        }
        for (var source : sources.entrySet()) if (!(source.getValue() instanceof JourneyDefinition.CookieExtraction) && !mapped.contains(source.getKey())) throw invalid("injection.tokens", "choose an injection destination or Disabled for every response token");
        return JourneyDefinition.Injection.perToken(result);
    }
    /**
     * Validates a single selector or a bounded set of explicitly named credentials.
     * @param e Native extraction object, never runtime values.
     * @return Immutable validated selectors.
     * @throws bpsh.model.ConfigurationException For invalid selectors, duplicate names or nested sets.
     */
    static JourneyDefinition.Extraction parseExtraction(JsonNode e) {
        String extractionType = text(e, "type", "extraction");
        JourneyDefinition.Extraction extraction;
        if (Config.ExtractionType.JSON_PATH.matches(extractionType)) {
            object(e, "extraction", "type", "responseOrigin", "pathSubstring", "jsonPath");
            String path = nonblank(text(e, "jsonPath", "extraction"), "extraction.jsonPath");
            validateJsonPath(path);
            extraction = new JourneyDefinition.JsonExtraction(origin(text(e, "responseOrigin", "extraction"), "extraction.responseOrigin", false),
                    nonempty(text(e, "pathSubstring", "extraction"), "extraction.pathSubstring"), path);
        } else if ("regex".equals(extractionType)) {
            object(e, "extraction", "type", "responseOrigin", "pathSubstring", "startRegex", "endRegex");
            String start = text(e, "startRegex", "extraction"), end = text(e, "endRegex", "extraction");
            for (String field : List.of("startRegex", "endRegex")) {
                try { TokenExtractor.compileRegex(field.equals("startRegex") ? start : end); }
                catch (AuthenticationFailure ex) { throw invalid("extraction." + field, ex.problem()); }
            }
            extraction = new JourneyDefinition.RegexExtraction(origin(text(e, "responseOrigin", "extraction"), "extraction.responseOrigin", false),
                    nonempty(text(e, "pathSubstring", "extraction"), "extraction.pathSubstring"), start, end);
        } else if (Config.ExtractionType.COOKIE.matches(extractionType)) {
            object(e, "extraction", "type", "originUrl", "name", "domain", "path");
            extraction = new JourneyDefinition.CookieExtraction(httpUri(text(e, "originUrl", "extraction"), "extraction.originUrl"),
                    cookieName(text(e, "name", "extraction")), optionalNonblank(e, "domain", "extraction"), optionalNonblank(e, "path", "extraction"));
        } else if ("combined".equals(extractionType)) {
            object(e, "extraction", "type", "tokens");
            JsonNode tokens = e.get("tokens");
            if (tokens == null || !tokens.isArray() || tokens.isEmpty() || tokens.size() > 16) throw invalid("extraction.tokens", "requires 1-16 named tokens");
            var selected = new ArrayList<JourneyDefinition.NamedExtraction>(); var names = new java.util.HashSet<String>(); var cookies = new java.util.HashSet<String>();
            for (JsonNode token : tokens) {
                String tokenPath = "extraction.tokens[" + selected.size() + "]";
                object(token, tokenPath, "name", "selector"); String name = text(token, "name", "extraction.tokens");
                String nameProblem = CredentialNames.problem(name);
                if (nameProblem != null) throw new ConfigurationException(tokenPath + ".name: " + nameProblem);
                name = name.toLowerCase(Locale.ROOT);
                if (!names.add(name)) throw new ConfigurationException(tokenPath + ".name: " + CredentialNames.DUPLICATE);
                JsonNode selector = token.get("selector");
                if (selector != null && "combined".equals(selector.path("type").asText())) throw invalid("extraction.tokens.selector", "nested token collections are unsupported");
                JourneyDefinition.Extraction parsed;
                try { parsed = parseExtraction(selector); }
                catch (ConfigurationException failure) {
                    String message = failure.getMessage();
                    throw new ConfigurationException(message.startsWith("extraction") ? tokenPath + ".selector" + message.substring("extraction".length()) : tokenPath + ".selector: " + message);
                }
                if (parsed instanceof JourneyDefinition.CookieExtraction cookie && !cookies.add(cookie.name())) throw invalid(tokenPath + ".selector.name", "use distinct cookie names for automatic injection");
                selected.add(new JourneyDefinition.NamedExtraction(name, parsed));
            }
            extraction = new JourneyDefinition.CombinedExtraction(selected);
        } else throw invalid("extraction.type", "unsupported value");
        return extraction;
    }
    /**
     * Validates one step against the exact fields permitted for its type.
     *
     * Secure inputs contain an ID/selector but no inline value. Durations require integral
     * milliseconds; this native path never applies the legacy fractional-seconds truncation.
     *
     * @param n Step object from a journey's ordered list.
     * @return Immutable step with a stable UUID and explicit load-state default.
     * @throws bpsh.model.ConfigurationException If identity, fields, selector, load state or duration is invalid.
     */
    static AuthStep.Definition parseStep(JsonNode n) {
        String p = "steps";
        AuthStep.Type type = enumeration(text(n, "type", p), AuthStep.Type.class, p + ".type");
        UUID id = uuid(n.get("id"), p + ".id");
        String selector = null, value = null, state = null, url = null; Integer duration = null;
        switch (type) {
            case CLICK, INPUT, SECURE_INPUT -> {
                if (type == AuthStep.Type.INPUT) object(n, p, "id", "type", "selector", "value");
                else object(n, p, "id", "type", "selector");
                selector = nonblank(text(n, "selector", p), p + ".selector");
                if (type == AuthStep.Type.INPUT) value = text(n, "value", p);
            }
            case WAIT_LOAD_STATE -> {
                object(n, p, "id", "type", "state"); state = n.has("state") ? text(n, "state", p) : AuthStep.DEFAULT_LOAD_STATE;
                if (!AuthStep.LOAD_STATES.contains(state)) throw invalid(p + ".state", "unsupported load state");
            }
            case WAIT_SELECTOR -> { object(n, p, "id", "type", "selector", "state"); selector = nonblank(text(n, "selector", p), p + ".selector"); if (n.has("state")) { state = text(n, "state", p); if (!AuthStep.ELEMENT_STATES.contains(state)) throw invalid(p + ".state", "choose visible, hidden, attached or detached"); } }
            case WAIT_URL -> { object(n, p, "id", "type", "urlPattern", "match"); url = nonblank(text(n, "urlPattern", p), p + ".urlPattern"); if (n.has("match")) { state = text(n, "match", p); if (!AuthStep.URL_MATCHES.contains(state)) throw invalid(p + ".match", "choose exact or glob"); } }
            case WAIT_TIME -> { object(n, p, "id", "type", "durationMs"); duration = (int) number(n.get("durationMs"), p + ".durationMs", 0, 300_000); }
        }
        return new AuthStep.Definition(id, type, selector, value, state, url, duration);
    }
    /**
     * Validates portable PKCS#11 identity selection without loading middleware or touching a token.
     *
     * Requires a lowercase SHA-256 certificate fingerprint and unique exact HTTPS origins. Slot
     * index/id bounds are distinct. Absolute path syntax is checked here; local availability and
     * PIN submission belong to asynchronous setup/authentication.
     *
     * @param n Nonnull mTLS configuration object.
     * @param authenticationUrl Validated login URL, whose HTTPS server is included automatically.
     * @return Immutable configuration with slot index zero when omitted.
     * @throws bpsh.model.ConfigurationException If paths, slot, fingerprint, origins or fields are invalid.
     */
    static JourneyDefinition.Mtls parseMtls(JsonNode n, URI authenticationUrl) {
        object(n, "mtls", "modulePath", "slot", "certificateSha256", "origins", "trustedCaBundlePath");
        JourneyDefinition.Slot slot = new JourneyDefinition.Slot(JourneyDefinition.SlotKind.INDEX, 0);
        if (n.has("slot")) {
            JsonNode s = n.get("slot"); object(s, "mtls.slot", "kind", "value");
            JourneyDefinition.SlotKind kind = enumeration(text(s, "kind", "mtls.slot"), JourneyDefinition.SlotKind.class, "mtls.slot.kind");
            slot = new JourneyDefinition.Slot(kind, number(s.get("value"), "mtls.slot.value", 0,
                    kind == JourneyDefinition.SlotKind.INDEX ? Integer.MAX_VALUE : Long.MAX_VALUE));
        }
        String fingerprint = text(n, "certificateSha256", "mtls");
        if (!fingerprint.matches("[0-9a-f]{64}")) throw invalid("mtls.certificateSha256", "requires 64 lowercase hex characters");
        List<URI> origins = new ArrayList<>();
        for (JsonNode v : array(n.get("origins"), "mtls.origins")) {
            if (!v.isTextual()) throw invalid("mtls.origins", "requires origin strings");
            URI uri;
            try { uri = origin(v.textValue(), "mtls.origins", true); }
            catch (ConfigurationException error) { throw invalid("mtls.origins", "enter an HTTPS server address without a page path, query or fragment"); }
            if (origins.contains(uri)) throw invalid("mtls.origins", "enter each authentication server only once"); origins.add(uri);
        }
        URI loginOrigin = certificateLoginOrigin(authenticationUrl);
        if (loginOrigin != null && !origins.contains(loginOrigin)) origins.add(loginOrigin);
        if (origins.isEmpty()) throw invalid("mtls.origins", "use an HTTPS Login URL or add an HTTPS authentication server");
        String ca = optionalNonblank(n, "trustedCaBundlePath", "mtls");
        return new JourneyDefinition.Mtls(absolutePath(text(n, "modulePath", "mtls"), "mtls.modulePath"), slot, fingerprint,
                origins, ca == null ? null : absolutePath(ca, "mtls.trustedCaBundlePath"));
    }
    /** @param loginUrl Validated login URL. @return Its canonical HTTPS server, or null for a non-HTTPS URL. */
    static URI certificateLoginOrigin(URI loginUrl) {
        return loginUrl != null && "https".equalsIgnoreCase(loginUrl.getScheme()) ? TokenExtractor.origin(loginUrl) : null;
    }
    /**
     * Parses only secrets owned by the associated journey's secure steps, mTLS or proxy login.
     *
     * Missing runtime values are allowed. Remember secrets policy is checked by the envelope parser,
     * not this helper. Temporary character arrays are wiped after Values has copied them, including
     * when validation fails.
     *
     * @param n SecretValues object containing only the fixed supported fields.
     * @param journey Validated definition whose ownership relationships govern the supplied values.
     * @return Caller-owned, independent buffers to close after transfer/use.
     * @throws bpsh.model.ConfigurationException If a field, value type or secret association is invalid.
     */
    static SecretStore.Values parseSecrets(JsonNode n, JourneyDefinition journey) {
        if (n != null && n.has("proxyPassword")) throw invalid("secrets.proxyPassword", "is unsupported; use a proxy URL that requires no authentication and remove this field");
        object(n, "secrets", "mtlsPin", "stepValues");
        Map<UUID, char[]> values = new HashMap<>(); char[] pin = null;
        try {
            if (n.has("mtlsPin")) {
                if (journey.mtls() == null) throw invalid("secrets.mtlsPin", "requires mTLS configuration");
                pin = text(n, "mtlsPin", "secrets").toCharArray();
            }
            if (n.has("stepValues")) {
                JsonNode steps = n.get("stepValues");
                if (!steps.isObject()) throw invalid("secrets.stepValues", "requires an object");
                var names = steps.fieldNames();
                while (names.hasNext()) {
                    String key = names.next(); UUID stepId = uuid(NATIVE.getNodeFactory().textNode(key), "secrets.stepValues");
                    if (journey.steps().stream().noneMatch(s -> s.id().equals(stepId) && s.type() == AuthStep.Type.SECURE_INPUT))
                        throw invalid("secrets.stepValues", "value must belong to a secure step in this journey");
                    values.put(stepId, text(steps, key, "secrets.stepValues").toCharArray());
                }
            }
            return new SecretStore.Values(pin, values);
        } finally {
            if (pin != null) Arrays.fill(pin, '\0');
            values.values().forEach(v -> Arrays.fill(v, '\0'));
        }
    }
    /**
     * Checks typed secret ownership without creating JSON strings for unremembered values.
     *
     * Temporary PIN copies are wiped; step validation needs only IDs. Missing required
     * runtime values remain permitted at this configuration-validation stage.
     *
     * @param journey Validated definition owning the candidate values.
     * @param values Open caller-owned snapshot; neither consumed nor modified.
     * @throws bpsh.model.ConfigurationException If values refer to absent mTLS configuration or nonsecure steps.
     * @throws IllegalStateException If the snapshot is closed.
     */
    static void validateSecretOwnership(JourneyDefinition journey, SecretStore.Values values) {
        char[] pin = values.pin();
        try {
            if (pin != null && journey.mtls() == null) throw invalid("secrets.mtlsPin", "requires mTLS configuration");
            Set<UUID> secure = new HashSet<>();
            journey.steps().stream().filter(s -> s.type() == AuthStep.Type.SECURE_INPUT).forEach(s -> secure.add(s.id()));
            if (!secure.containsAll(values.stepIds())) throw invalid("secrets.stepValues", "value must belong to a secure step in this journey");
        } finally {
            if (pin != null) Arrays.fill(pin, '\0');
        }
    }
    /**
     * Requires every configured secret when an explicit complete-secret export is requested.
     *
     * Errors identify the journey and secure-step position with remediation, never a supplied value.
     * Returned accessor copies are wiped after checking presence; empty supplied arrays are present.
     *
     * @param journey Definition whose mTLS and secure-input requirements must be satisfied.
     * @param values Open session snapshot to inspect without consuming it.
     * @throws bpsh.model.ConfigurationException If a required value is absent.
     * @throws IllegalStateException If the snapshot is closed.
     */
    static void requireCompleteSecrets(JourneyDefinition journey, SecretStore.Values values) {
        String owner = "journey " + alias(journey.alias()) + ".secrets";
        if (journey.mtls() != null) requireSecret(values.pin(), "mTLS PIN", owner);
        for (int i = 0; i < journey.steps().size(); i++) {
            AuthStep.Definition step = journey.steps().get(i);
            if (step.type() == AuthStep.Type.SECURE_INPUT) requireSecret(values.stepValue(step.id()), "secure-input value at step " + (i + 1), owner);
        }
    }
    /**
     * Checks presence and wipes an accessor copy without logging its content.
     *
     * @param value Caller-owned temporary buffer to wipe, or null when missing.
     * @param field Safe human-readable field description, optionally including a step position.
     * @param owner Validated journey/field label for actionable diagnostics.
     * @throws bpsh.model.ConfigurationException If value is null, with guidance to enter it or omit secret inclusion.
     */
    static void requireSecret(char[] value, String field, String owner) {
        if (value == null) throw invalid(owner, "missing " + field + "; enter it in the journey configuration or export without Include secrets");
        Arrays.fill(value, '\0');
    }
    /**
     * Builds only the allowed nonsecret wire fields for each journey/step mode.
     *
     * Live scope, generation, tokens and secret values are excluded. The enclosing writer decides
     * whether to attach SecretValues after applying managed/export consent rules.
     *
     * @param j Validated immutable definition to serialize.
     * @param exported Whether Remember secrets must be cleared in the output.
     * @return Newly allocated JSON object containing the journey definition.
     */
    static ObjectNode journeyJson(JourneyDefinition j, boolean exported) {
        ObjectNode n = NATIVE.createObjectNode(); n.put("id", j.id().toString()); n.put("displayName", j.displayName());
        n.put("alias", j.alias());
        if (j.draft() != null) {
            boolean remember = !exported && j.rememberSecrets(); n.put("rememberSecrets", remember);
            n.set("draft", NATIVE.valueToTree(j.draft().withRemember(remember))); return n;
        }
        n.put("authenticationUrl", j.authenticationUrl().toString()); n.put("rememberSecrets", !exported && j.rememberSecrets());
        ArrayNode steps = n.putArray("steps");
        for (AuthStep.Definition s : j.steps()) {
            ObjectNode a = steps.addObject(); a.put("id", s.id().toString()); a.put("type", s.type().wire());
            switch (s.type()) {
                case CLICK, SECURE_INPUT -> a.put("selector", s.selector());
                case WAIT_SELECTOR -> { a.put("selector", s.selector()); if (s.state() != null) a.put("state", s.state()); }
                case INPUT -> { a.put("selector", s.selector()); a.put("value", s.value()); }
                case WAIT_LOAD_STATE -> a.put("state", s.state());
                case WAIT_URL -> { a.put("urlPattern", s.urlPattern()); if (s.state() != null) a.put("match", s.state()); }
                case WAIT_TIME -> a.put("durationMs", s.durationMs());
            }
        }
        n.set("browser", NATIVE.valueToTree(j.browser()));
        n.set("extraction", extractionNode(j.extraction()));
        n.set("injection", injectionNode(j.injection()));
        n.set("cache", NATIVE.valueToTree(j.cache()));
        n.putNull("mtls");
        if (j.mtls() != null) {
            ObjectNode m = NATIVE.valueToTree(j.mtls()); ((ObjectNode) m.get("slot")).put("kind", j.mtls().slot().kind().name().toLowerCase(Locale.ROOT)); n.set("mtls", m);
        }
        return n;
    }
    /**
     * Writes selectors without runtime credentials, preserving names and order.
     * @param selector Validated extraction definition.
     * @return Canonical native extraction object.
     */
    static ObjectNode extractionNode(JourneyDefinition.Extraction selector) {
        ObjectNode e = NATIVE.createObjectNode();
        if (selector instanceof JourneyDefinition.JsonExtraction x) {
            e.put("type", "json_path").put("responseOrigin", x.responseOrigin().toString()).put("pathSubstring", x.pathSubstring()).put("jsonPath", x.jsonPath());
        } else if (selector instanceof JourneyDefinition.RegexExtraction x) {
            e.put("type", "regex").put("responseOrigin", x.responseOrigin().toString()).put("pathSubstring", x.pathSubstring()).put("startRegex", x.startRegex()).put("endRegex", x.endRegex());
        } else if (selector instanceof JourneyDefinition.CookieExtraction x) {
            e.put("type", "cookie").put("originUrl", x.originUrl().toString()).put("name", x.name());
            if (x.domain() != null) e.put("domain", x.domain()); if (x.path() != null) e.put("path", x.path());
        } else if (selector instanceof JourneyDefinition.CombinedExtraction x) {
            e.put("type", "combined"); var tokens = e.putArray("tokens");
            for (var token : x.tokens()) { var item = tokens.addObject().put("name", token.name()); item.set("selector", extractionNode(token.selector())); }
        }
        return e;
    }
    /** Serializes configured destinations only; token values never enter saved documents. */
    static ObjectNode injectionNode(JourneyDefinition.Injection injection) {
        ObjectNode node = NATIVE.createObjectNode().put("type", "per_token");
        var tokens = node.putArray("tokens");
        for (var mapping : injection.tokens()) {
            var item = tokens.addObject().put("type", mapping.type().wire());
            if (mapping.tokenName() != null) item.put("tokenName", mapping.tokenName());
            if (mapping.name() != null) item.put("name", mapping.name());
        }
        return node;
    }
    /**
     * Serializes explicitly included secret buffers, wiping each temporary accessor copy.
     *
     * The returned node necessarily owns readable Java strings, which cannot be securely wiped.
     * Call only after the enclosing writer has made its persistence/export inclusion decision.
     *
     * @param values Open caller-owned snapshot, retained by its owner.
     * @return Newly allocated SecretValues object containing the supplied fields.
     * @throws IllegalStateException If the snapshot is closed.
     */
    static ObjectNode secretsJson(SecretStore.Values values) {
        ObjectNode n = NATIVE.createObjectNode(); putSecret(n, "mtlsPin", values.pin());
        if (!values.stepIds().isEmpty()) {
            ObjectNode steps = n.putObject("stepValues");
            values.stepIds().stream().sorted().forEach(id -> putSecret(steps, id.toString(), values.stepValue(id)));
        }
        return n;
    }
    /**
     * Adds one supplied secret as a JSON string and always wipes its temporary array.
     *
     * @param node Destination object whose lifetime now includes the readable string.
     * @param field Fixed secret field name or validated secure-step UUID.
     * @param value Caller-owned accessor copy, or null to omit the field.
     */
    static void putSecret(ObjectNode node, String field, char[] value) {
        if (value == null) return;
        try { node.put(field, new String(value)); } finally { Arrays.fill(value, '\0'); }
    }
}
