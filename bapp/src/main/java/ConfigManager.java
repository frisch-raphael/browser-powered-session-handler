import burp.api.montoya.persistence.PersistedObject;
import com.fasterxml.jackson.core.JsonProcessingException;
import burp.api.montoya.core.ToolType;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.net.URI;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

/**
 * Validates and persists only the native project/journey formats, leaving previous stored data untouched.
 * File, JSON and persistence operations belong off Swing's EDT; secret-bearing documents must be closed.
 */
public final class ConfigManager {
    private final PersistedObject storage;

    /**
     * Binds the native project store without reading or converting any other persistence keys.
     * @param storage Burp extension data; its lifetime is temporary without a saved project file.
     */
    public ConfigManager(PersistedObject storage) { this.storage = Objects.requireNonNull(storage); }

    /**
     * Stores native project envelopes separately from untouched legacy configuration.
     */
    public static final String NATIVE_PROJECT_KEY = "bpsh_project_v3";
    /**
     * Rejects duplicate keys and trailing JSON values before native field-level validation.
     */
    private static final ObjectMapper NATIVE = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(SerializationFeature.INDENT_OUTPUT);

    /**
     * Discriminates project storage, user-library storage and native transfer envelopes.
     */
    public enum DocumentKind {
        PROJECT, LIBRARY, EXPORT;
        /**
         * Returns the exact lowercase discriminator used in native JSON.
         *
         * @return project, library or export; independent of the host locale.
         */
        public String wire() { return name().toLowerCase(Locale.ROOT); }
    }
    /**
     * Reports native format failures using safe field paths and reasons, without raw secret values.
     */
    public static final class NativeFormatException extends IllegalArgumentException {
        /**
         * Creates a validation failure from an already redacted message.
         *
         * @param message Safe field-path/reason text; never a raw parser exception or secret value.
         */
        NativeFormatException(String message) { super(message); }
    }
    /**
     * Reads retirement metadata from older native files for compatibility; it no longer reserves a name.
     *
     * @param alias Original validated spelling; comparisons use its canonical ASCII form.
     * @param formerJourneyId Internal UUID of the former owner.
     * @param retiredAt UTC retirement instant used for managed-storage history.
     */
    public record RetiredAlias(String alias, UUID formerJourneyId, Instant retiredAt) {
        /**
         * Produces the comparison key for a previously validated retirement record.
         *
         * @return Locale-independent lowercase alias; this method does not validate new input.
         */
        public String canonicalAlias() { return alias.toLowerCase(Locale.ROOT); }
    }
    /**
     * Owns a native envelope and any secret snapshots attached to its definitions.
     *
     * Collections are defensively copied, but Values instances are adopted rather than deep-cloned.
     * Close after transferring copies into the session store. The redacted view shares immutable
     * definitions only; withRevision creates independent secret copies. Full schema validation is
     * performed by the codec, not by this record constructor.
     *
     * @param kind Container discriminator; exports have no project controls.
     * @param revision Envelope UUID used for persistence conflicts, not a token generation.
     * @param journeys Immutable definitions without embedded runtime state.
     * @param retiredAliases Legacy metadata accepted on read; all new writes serialize an empty array.
     * @param controls Project-wide controls, or null for library/export documents.
     * @param secrets Owned values indexed by journey UUID; may include session-only values before writing.
     */
    public record NativeDocument(DocumentKind kind, UUID revision, List<JourneyDefinition> journeys,
                                 List<RetiredAlias> retiredAliases, Config.Controls controls,
                                 Map<UUID, SecretStore.Values> secrets) implements AutoCloseable {
        /**
         * Copies envelope collections and requires kind/revision without consuming supplied Values.
         */
        public NativeDocument {
            Objects.requireNonNull(kind); Objects.requireNonNull(revision);
            journeys = List.copyOf(journeys); retiredAliases = List.copyOf(retiredAliases);
            secrets = Map.copyOf(secrets);
        }
        /**
         * Creates an empty envelope with a fresh revision and scope-appropriate defaults.
         *
         * @param kind Requested container type.
         * @return Secret-free document; only project documents receive default controls.
         */
        public static NativeDocument empty(DocumentKind kind) {
            return new NativeDocument(kind, UUID.randomUUID(), List.of(), List.of(),
                    kind == DocumentKind.PROJECT ? Config.Controls.defaults() : null, Map.of());
        }
        /**
         * Drops all secret values while retaining definitions, revision and retirement history.
         *
         * @return A view with an empty secret map; closing it cannot close this document's values.
         */
        public NativeDocument redacted() {
            return new NativeDocument(kind, revision, journeys, retiredAliases, controls, Map.of());
        }
        /**
         * Copies the envelope under a replacement revision, cloning every owned secret snapshot.
         *
         * @param value Revision for the new envelope.
         * @return Independently owned document that its caller must close.
         * @throws IllegalStateException If any source secret snapshot is already closed.
         */
        public NativeDocument withRevision(UUID value) {
            Map<UUID, SecretStore.Values> copies = new HashMap<>();
            secrets.forEach((id, secret) -> copies.put(id, secret.copy()));
            return new NativeDocument(kind, value, journeys, retiredAliases, controls, copies);
        }
        /**
         * Wipes every adopted secret snapshot; definitions and redacted views remain usable.
         */
        @Override public void close() { secrets.values().forEach(SecretStore.Values::close); }
        /**
         * Returns only envelope kind and revision for diagnostics.
         *
         * @return Metadata with no definitions or secret values.
         */
        @Override public String toString() { return "NativeDocument[kind=" + kind + ", revision=" + revision + "]"; }
    }

    /**
     * Loads only the native project key, preserving malformed data for explicit repair.
     *
     * No legacy key is consulted and no default is silently substituted for invalid native JSON.
     *
     * @return Empty if the native key is absent; otherwise a caller-owned document to close.
     * @throws NativeFormatException If stored native data is malformed or has the wrong kind.
     */
    public Optional<NativeDocument> loadNativeProject() {
        String json = storage.getString(NATIVE_PROJECT_KEY);
        return json == null ? Optional.empty() : Optional.of(parseNative(json, DocumentKind.PROJECT));
    }

    /**
     * Commits a native project edit only when its captured revision still matches.
     *
     * Saves are serialized within this manager. Capture expectedRevision when editing begins; a stale
     * editor must reload instead of overwriting a later save. The legacy key remains untouched.
     * Remembered values follow native writer policy; the returned document retains session values.
     *
     * @param edited Validated project document; caller retains ownership.
     * @param expectedRevision Previously loaded revision, or null only when the native key was absent.
     * @return Independently owned committed document with a fresh revision; caller closes it.
     * @throws NativeFormatException If kind, revision or native data is invalid/stale.
     */
    public synchronized NativeDocument saveNativeProject(NativeDocument edited, UUID expectedRevision) {
        if (edited.kind() != DocumentKind.PROJECT) throw invalid("kind", "must be project");
        Optional<NativeDocument> current = loadNativeProject();
        try {
            UUID disk = current.map(NativeDocument::revision).orElse(null);
            if (!Objects.equals(disk, expectedRevision))
                throw invalid("revision", "project changed; reload and reapply the edit");
            NativeDocument next = edited.withRevision(UUID.randomUUID());
            try { storage.setString(NATIVE_PROJECT_KEY, nativeToJson(next)); return next; }
            catch (RuntimeException ex) { next.close(); throw ex; }
        } finally { current.ifPresent(NativeDocument::close); }
    }

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
     * @throws NativeFormatException If syntax, envelope kind or any native semantic rule is invalid.
     */
    public static NativeDocument parseNative(String json, DocumentKind expected) {
        Map<UUID, SecretStore.Values> secrets = new HashMap<>();
        try {
            JsonNode root = NATIVE.readTree(json);
            object(root, "$", "schemaVersion", "kind", "revision", "journeys", "retiredAliases", "controls");
            number(root.get("schemaVersion"), "schemaVersion", 1, 1);
            DocumentKind kind = enumeration(text(root, "kind", "$"), DocumentKind.class, "kind");
            if (kind != expected) throw invalid("kind", "wrong document type; use Export journeys for transfer");
            UUID revision = uuid(root.get("revision"), "revision");
            List<JourneyDefinition> journeys = new ArrayList<>();
            Set<UUID> ids = new HashSet<>();
            for (JsonNode n : array(root.get("journeys"), "journeys")) {
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
            Config.Controls controls = null;
            if (kind == DocumentKind.PROJECT) controls = parseControls(root.get("controls"));
            else if (root.has("controls")) throw invalid("controls", "only project documents may contain controls");
            // Conflicting aliases on disk remain visible to the registry, which blocks their resolution.
            return new NativeDocument(kind, revision, journeys, retired, controls, secrets);
        } catch (NativeFormatException ex) {
            secrets.values().forEach(SecretStore.Values::close); throw ex;
        } catch (Exception ex) {
            secrets.values().forEach(SecretStore.Values::close);
            throw invalid("$", "invalid native JSON; check syntax, duplicate fields and value types");
        }
    }

    /**
     * Validates a journey definition while keeping secret values outside the returned model.
     *
     * Checks type-specific fields, step identities/count, proxy URL, extraction selectors, cache
     * bounds and RE2 syntax/size/program limits. Secret ownership is parsed separately afterward.
     *
     * @param n Journey object within a native envelope.
     * @return Immutable definition with canonicalized origins and explicit defaults.
     * @throws NativeFormatException If any definition field or mode-specific combination is invalid.
     */
    private static JourneyDefinition parseJourney(JsonNode n) {
        String p = "journeys";
        if (n != null && n.has("draft")) {
            object(n, p, "id", "displayName", "alias", "rememberSecrets", "draft", "secrets");
            try {
                JourneyDraft draft = NATIVE.treeToValue(n.get("draft"), JourneyDraft.class);
                boolean remember = bool(n, "rememberSecrets", false);
                if (draft == null || draft.flags().get("remember") != remember) throw invalid("journeys.draft", "invalid draft structure");
                return draft.definition(uuid(n.get("id"), p + ".id"), nonblank(text(n, "displayName", p), p + ".displayName"), alias(text(n, "alias", p)), remember);
            } catch (NativeFormatException ex) { throw ex; }
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
            catch (NativeFormatException error) { throw new NativeFormatException(error.getMessage().replaceFirst("^steps", "steps[" + steps.size() + "]")); }
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
            try { SessionRecovery.compile(pattern); }
            catch (AuthenticationFailure ex) { throw invalid(p + ".pattern", ex.problem()); }
            recovery = new JourneyDefinition.Recovery(bool(r, "enabled", true), JourneyDefinition.RecoveryMode.BOTH.matches(mode) ? JourneyDefinition.RecoveryMode.BOTH : JourneyDefinition.RecoveryMode.REGEX, JourneyDefinition.RecoveryMode.BOTH.matches(mode) ? integer(r, "statusCode", 401, 100, 599) : null, pattern);
        } else throw invalid(p + ".mode", "unsupported value");
        return recovery;
    }

    /** Validates one explicit mapping per response token and rejects conflicting destinations. */
    private static JourneyDefinition.Injection parseInjection(JsonNode in, JourneyDefinition.Extraction extraction) {
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
     * @throws NativeFormatException For invalid selectors, duplicate names or nested sets.
     */
    private static JourneyDefinition.Extraction parseExtraction(JsonNode e) {
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
                if (nameProblem != null) throw new NativeFormatException(tokenPath + ".name: " + nameProblem);
                name = name.toLowerCase(Locale.ROOT);
                if (!names.add(name)) throw new NativeFormatException(tokenPath + ".name: " + CredentialNames.DUPLICATE);
                JsonNode selector = token.get("selector");
                if (selector != null && "combined".equals(selector.path("type").asText())) throw invalid("extraction.tokens.selector", "nested token collections are unsupported");
                JourneyDefinition.Extraction parsed;
                try { parsed = parseExtraction(selector); }
                catch (NativeFormatException failure) {
                    String message = failure.getMessage();
                    throw new NativeFormatException(message.startsWith("extraction") ? tokenPath + ".selector" + message.substring("extraction".length()) : tokenPath + ".selector: " + message);
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
     * @throws NativeFormatException If identity, fields, selector, load state or duration is invalid.
     */
    private static AuthStep.Definition parseStep(JsonNode n) {
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
     * @throws NativeFormatException If paths, slot, fingerprint, origins or fields are invalid.
     */
    private static JourneyDefinition.Mtls parseMtls(JsonNode n, URI authenticationUrl) {
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
            catch (NativeFormatException error) { throw invalid("mtls.origins", "enter an HTTPS server address without a page path, query or fragment"); }
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
     * @throws NativeFormatException If a field, value type or secret association is invalid.
     */
    private static SecretStore.Values parseSecrets(JsonNode n, JourneyDefinition journey) {
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
     * @throws NativeFormatException If values refer to absent mTLS configuration or nonsecure steps.
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
     * @throws NativeFormatException If a required value is absent.
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
     * @throws NativeFormatException If value is null, with guidance to enter it or omit secret inclusion.
     */
    private static void requireSecret(char[] value, String field, String owner) {
        if (value == null) throw invalid(owner, "missing " + field + "; enter it in the journey configuration or export without Include secrets");
        Arrays.fill(value, '\0');
    }

    /**
     * Validates project-only injection controls, deadlines and independent waiter limits.
     *
     * Request and attempt timeouts must each fit within the cycle budget. Missing/null limits mean
     * Unlimited independently. Selected journey existence is resolved by the registry, not here.
     *
     * @param n Required project controls object; absent members use their defined defaults.
     * @return Immutable controls with canonical enum choices and nullable unlimited limits.
     * @throws NativeFormatException If fields, tools, URL mode, deadlines or limits are invalid.
     */
    private static Config.Controls parseControls(JsonNode n) {
        object(n, "controls", "enabled", "rules", "tools", "requestWaitTimeoutMs",
                "attemptTimeoutMs", "cycleTimeoutMs", "maxWaitingRequestsGlobal", "maxWaitingRequestsPerJourney");
        List<Config.AutomaticRule> rules = new ArrayList<>(); Set<Config.JourneySelection> identities = new HashSet<>();
        if (n.has("rules")) for (JsonNode rule : array(n.get("rules"), "controls.rules")) {
            String p = "controls.rules[" + rules.size() + "]";
            if (rules.size() == 64) throw invalid("controls.rules", "maximum count is 64");
            object(rule, p, "enabled", "journey", "urlMode", "urlPrefix", "recovery");
            JsonNode j = rule.get("journey"); object(j, p + ".journey", "scope", "id");
            var selection = new Config.JourneySelection(enumeration(text(j, "scope", p + ".journey"), JourneyDefinition.Scope.class, p + ".journey.scope"), uuid(j.get("id"), p + ".journey.id"));
            if (!identities.add(selection)) throw invalid(p + ".journey", "a journey may appear only once; edit its existing rule");
            Config.UrlMode mode = enumeration(text(rule, "urlMode", p), Config.UrlMode.class, p + ".urlMode");
            URI prefix = present(rule, "urlPrefix") ? httpUri(text(rule, "urlPrefix", p), p + ".urlPrefix") : null;
            if ((mode == Config.UrlMode.SINGLE_URL) != (prefix != null)) throw invalid(p + ".urlPrefix", "required only for single_url mode");
            rules.add(new Config.AutomaticRule(bool(rule, "enabled", true), selection, mode, prefix, parseRecovery(rule.get("recovery"), p + ".recovery")));
        }
        List<ToolType> tools = Config.Controls.defaults().tools();
        if (n.has("tools")) {
            tools = new ArrayList<>();
            List<String> allowed = Config.SUPPORTED_TOOLS.stream().map(ToolType::name).toList();
            for (JsonNode v : array(n.get("tools"), "controls.tools")) {
                if (!v.isTextual() || !allowed.contains(v.textValue())) throw invalid("controls.tools", "unsupported tool");
                ToolType type = ToolType.valueOf(v.textValue());
                if (tools.contains(type)) throw invalid("controls.tools", "duplicate tool"); tools.add(type);
            }
        }
        int request = integer(n, "requestWaitTimeoutMs", 60_000, 1000, 600_000);
        int attempt = integer(n, "attemptTimeoutMs", 60_000, 1000, 300_000);
        int cycle = integer(n, "cycleTimeoutMs", 300_000, 1000, 1_800_000);
        if (request > cycle || attempt > cycle) throw invalid("controls.cycleTimeoutMs", "must cover request and attempt timeouts");
        return new Config.Controls(bool(n, "enabled", false), rules, tools, request, attempt, cycle,
                limit(n, "maxWaitingRequestsGlobal"), limit(n, "maxWaitingRequestsPerJourney"));
    }

    /**
     * Serializes a native document without enabling the separate export-secret choice.
     *
     * Managed documents still include supplied remembered values. Exports omit all secret values
     * regardless of Remember secrets; use the explicit overload only after Include secrets consent.
     *
     * @param document Caller-owned document; this method does not consume its snapshots.
     * @return Validated native JSON.
     * @throws NativeFormatException If the envelope or serialized definitions are invalid.
     */
    public static String nativeToJson(NativeDocument document) { return nativeToJson(document, false); }
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
     * @throws NativeFormatException If collisions, ownership or serialized native fields are invalid.
     */
    public static String nativeToJson(NativeDocument d, boolean includeExportSecrets) {
        Set<UUID> ids = new HashSet<>();
        for (JourneyDefinition j : d.journeys()) {
            ids.add(j.id());
        }
        if (!ids.containsAll(d.secrets().keySet())) throw invalid("secrets", "secret owner is missing");
        ObjectNode root = NATIVE.createObjectNode(); root.put("schemaVersion", 1); root.put("kind", d.kind().wire()); root.put("revision", d.revision().toString());
        ArrayNode journeys = root.putArray("journeys");
        for (JourneyDefinition j : d.journeys()) {
            ObjectNode n = journeyJson(j, d.kind() == DocumentKind.EXPORT);
            SecretStore.Values secret = d.secrets().get(j.id());
            if (secret != null) validateSecretOwnership(j, secret);
            if (secret != null && !secret.isEmpty() && (d.kind() == DocumentKind.EXPORT ? includeExportSecrets : j.rememberSecrets()))
                n.set("secrets", secretsJson(secret));
            journeys.add(n);
        }
        root.putArray("retiredAliases"); // Retained schema field only; old reservations have no effect.
        if (d.kind() == DocumentKind.PROJECT) {
            if (d.controls() == null) throw invalid("controls", "project controls are required");
            ObjectNode c = NATIVE.valueToTree(d.controls()); ArrayNode rules = c.putArray("rules");
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
            try (NativeDocument checked = parseNative(json, d.kind())) { return json; }
        } catch (JsonProcessingException ex) { throw invalid("$", "could not serialize native configuration"); }
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
    private static ObjectNode journeyJson(JourneyDefinition j, boolean exported) {
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
    private static ObjectNode secretsJson(SecretStore.Values values) {
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
    private static void putSecret(ObjectNode node, String field, char[] value) {
        if (value == null) return;
        try { node.put(field, new String(value)); } finally { Arrays.fill(value, '\0'); }
    }

    /**
     * Constructs a field-level failure without attaching potentially secret-bearing causes.
     *
     * @param path Safe schema path or validated journey label; never arbitrary input values.
     * @param reason Safe explanation and, where relevant, recovery guidance.
     * @return Exception for the caller to throw; this helper itself does not throw it.
     */
    private static NativeFormatException invalid(String path, String reason) { return new NativeFormatException(path + ": " + reason + "."); }
    /**
     * Distinguishes configured optional values from absent or explicitly null fields.
     *
     * @param n Nonnull containing object validated by its caller.
     * @param name Known field name to inspect.
     * @return True only when the member exists and is not JSON null.
     */
    private static boolean present(JsonNode n, String name) { return n.has(name) && !n.get(name).isNull(); }
    /**
     * Requires an object and rejects unknown keys without echoing their potentially sensitive names.
     *
     * Allowed fields are not automatically required; each accessor applies that field's required,
     * optional or default rule afterward.
     *
     * @param n Candidate JSON node, including null for a missing object.
     * @param path Safe containing schema path used in errors.
     * @param fields Complete set of allowed member names for this mode.
     * @throws NativeFormatException If the node is not an object or contains an unsupported member.
     */
    private static void object(JsonNode n, String path, String... fields) {
        if (n == null || !n.isObject()) throw invalid(path, "requires an object");
        Set<String> allowed = Set.of(fields); var names = n.fieldNames();
        while (names.hasNext()) if (!allowed.contains(names.next())) throw invalid(path, "contains an unsupported field");
    }
    /**
     * Requires an array without coercing a scalar or treating missing/null as empty.
     *
     * @param n Candidate JSON node.
     * @param path Safe schema path used in errors.
     * @return The same validated node for iteration.
     * @throws NativeFormatException If the node is absent, null or not an array.
     */
    private static JsonNode array(JsonNode n, String path) { if (n == null || !n.isArray()) throw invalid(path, "requires an array"); return n; }
    /**
     * Reads a required string without coercion or including its value in an error.
     *
     * @param n Containing object, or null when its container is missing.
     * @param name Known member name, or a previously validated secure-step UUID.
     * @param path Safe container path to qualify the field error.
     * @return Exact string content, including empty strings; content rules are separate.
     * @throws NativeFormatException If the member is absent, null or not a string.
     */
    private static String text(JsonNode n, String name, String path) {
        JsonNode value = n == null ? null : n.get(name);
        if (value == null || !value.isTextual()) throw invalid(path + "." + name, "requires a string"); return value.textValue();
    }
    /**
     * Reads an optional selector/path while keeping null distinct from an empty implicit mode.
     *
     * @param n Validated containing object.
     * @param name Known optional field name.
     * @param path Safe container path for errors.
     * @return Null for absent/null, otherwise the exact nonblank string without trimming.
     * @throws NativeFormatException If a supplied member is nontextual or blank.
     */
    private static String optionalNonblank(JsonNode n, String name, String path) { return present(n, name) ? nonblank(text(n, name, path), path + "." + name) : null; }
    /**
     * Rejects an empty or whitespace-only value without trimming the accepted content.
     *
     * @param v Nonnull string already read with a typed accessor.
     * @param p Safe schema path for failure reporting.
     * @return The unchanged nonblank string.
     * @throws NativeFormatException If the string is blank.
     */
    private static String nonblank(String v, String p) { if (v.isBlank()) throw invalid(p, "requires a nonblank string"); return v; }
    /**
     * Requires content while preserving meaningful whitespace in path-substring matching.
     *
     * @param v Nonnull string already read with a typed accessor.
     * @param p Safe schema path for failure reporting.
     * @return The unchanged string, including whitespace-only content.
     * @throws NativeFormatException If the string is empty.
     */
    private static String nonempty(String v, String p) { if (v.isEmpty()) throw invalid(p, "requires a nonempty string"); return v; }
    /**
     * Reads an exact boolean, using its default only when the member is absent.
     *
     * @param n Validated containing object.
     * @param name Known boolean field.
     * @param fallback Default for an absent member; explicit null is not a default request.
     * @return Configured boolean or fallback.
     * @throws NativeFormatException If a present member is null or not boolean.
     */
    private static boolean bool(JsonNode n, String name, boolean fallback) {
        if (!n.has(name)) return fallback; if (!n.get(name).isBoolean()) throw invalid(name, "requires a boolean"); return n.get(name).booleanValue();
    }
    /**
     * Requires a JSON integral-number node within inclusive signed-long bounds.
     *
     * Strings and floating-point representations are rejected even when numerically integral.
     *
     * @param n Candidate number node.
     * @param p Safe schema path for errors.
     * @param min Inclusive minimum.
     * @param max Inclusive maximum.
     * @return Validated long value without narrowing or truncation.
     * @throws NativeFormatException If the node is absent, mistyped, overflowing or outside bounds.
     */
    private static long number(JsonNode n, String p, long min, long max) {
        if (n == null || !n.isIntegralNumber() || !n.canConvertToLong() || n.longValue() < min || n.longValue() > max)
            throw invalid(p, "requires an integer from " + min + " through " + max); return n.longValue();
    }
    /**
     * Reads a bounded integer with a default for an absent member only.
     *
     * @param n Validated containing object.
     * @param name Known numeric member.
     * @param fallback Default when the member is absent.
     * @param min Inclusive integer minimum.
     * @param max Inclusive integer maximum.
     * @return Validated int or fallback.
     * @throws NativeFormatException If a supplied member fails strict integral-number validation.
     */
    private static int integer(JsonNode n, String name, int fallback, int min, int max) { return n.has(name) ? (int) number(n.get(name), name, min, max) : fallback; }
    /**
     * Reads a positive admission limit while preserving explicit Unlimited semantics.
     *
     * @param n Validated controls object.
     * @param name Known global or per-journey waiting-limit field.
     * @return Null for absent/null (Unlimited), otherwise an integer from one through Integer.MAX_VALUE.
     * @throws NativeFormatException If a supplied finite limit is mistyped or out of range.
     */
    private static Integer limit(JsonNode n, String name) { return present(n, name) ? (int) number(n.get(name), name, 1, Integer.MAX_VALUE) : null; }
    /**
     * Requires canonical lowercase UUID v4 syntax and the standard UUID variant.
     *
     * This validates representation only, not whether an identity exists in the registry.
     *
     * @param n Candidate string node.
     * @param p Safe schema path for errors.
     * @return Parsed UUID without normalizing an invalid spelling.
     * @throws NativeFormatException If the node or UUID syntax is invalid.
     */
    private static UUID uuid(JsonNode n, String p) {
        if (n == null || !n.isTextual() || !n.textValue().matches("[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"))
            throw invalid(p, "requires a canonical UUID v4"); return UUID.fromString(n.textValue());
    }
    /**
     * Validates the shared ASCII alias grammar without changing its display spelling.
     *
     * Accepted aliases have 1-64 letters/digits/underscores/hyphens and start with a letter or digit.
     * Case folding is a separate registry/model operation; validation never silently renames aliases.
     *
     * @param v Nonnull candidate alias.
     * @return The unchanged valid spelling.
     * @throws NativeFormatException If the candidate does not follow the native grammar.
     */
    public static String alias(String v) { if (!v.matches("[A-Za-z0-9][A-Za-z0-9_-]{0,63}")) throw invalid("alias", "use 1-64 ASCII letters, digits, underscores or hyphens, starting with a letter or digit"); return v; }
    /**
     * Matches an exact lowercase native discriminator against a model enum.
     *
     * @param <T> Enum type representing the supported choices.
     * @param v Exact wire spelling; case-insensitive coercion is not performed.
     * @param type Enum class to inspect.
     * @param p Safe schema path for an unsupported-value error.
     * @return Matching enum constant.
     * @throws NativeFormatException If no supported constant has that wire spelling.
     */
    private static <T extends Enum<T>> T enumeration(String v, Class<T> type, String p) {
        for (T constant : type.getEnumConstants()) if (constant.name().toLowerCase(Locale.ROOT).equals(v)) return constant;
        throw invalid(p, "unsupported value");
    }
    /**
     * Validates an absolute HTTP(S) URL with a host and usable port, excluding embedded credentials.
     *
     * The URL's path/query/fragment are retained; origin-only restrictions are applied separately.
     * No DNS lookup or network request is performed.
     *
     * @param value Candidate URL text, never echoed on failure.
     * @param p Safe schema path used for diagnostics.
     * @return Parsed URI retaining its configured URL semantics.
     * @throws NativeFormatException If scheme, host, userinfo, port or URI syntax is invalid.
     */
    private static URI httpUri(String value, String p) {
        try {
            URI uri = URI.create(nonblank(value, p));
            if (!Set.of("http", "https").contains(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null
                    || uri.getPort() < -1 || uri.getPort() == 0 || uri.getPort() > 65535) throw new IllegalArgumentException();
            return uri;
        } catch (RuntimeException ex) { throw invalid(p, "requires an absolute HTTP(S) URL without embedded credentials"); }
    }
    /**
     * Validates an exact origin and canonicalizes hostname case and default ports.
     *
     * Only an absent path or slash is allowed, with no query/fragment. Origin matching never expands
     * wildcards or infers an mTLS scope from an arbitrary URL.
     *
     * @param value Candidate HTTP(S) origin.
     * @param p Safe schema path used for errors.
     * @param httpsOnly Whether plain HTTP must be rejected, as for certificate origins.
     * @return URI containing scheme, lowercase host and any nondefault port only.
     * @throws NativeFormatException If URL/origin restrictions are violated.
     */
    private static URI origin(String value, String p, boolean httpsOnly) {
        URI uri = httpUri(value, p);
        if ((httpsOnly && !uri.getScheme().equals("https")) || uri.getRawQuery() != null || uri.getRawFragment() != null
                || !(uri.getRawPath().isEmpty() || uri.getRawPath().equals("/"))) throw invalid(p, "requires an exact origin");
        int port = uri.getPort(); if ((uri.getScheme().equals("http") && port == 80) || (uri.getScheme().equals("https") && port == 443)) port = -1;
        try { return new URI(uri.getScheme(), null, uri.getHost().toLowerCase(Locale.ROOT), port, null, null, null); }
        catch (Exception ex) { throw invalid(p, "requires an exact origin"); }
    }
    /**
     * Requires an ASCII HTTP token suitable for a cookie name.
     *
     * @param value Candidate name; delimiters, whitespace and non-ASCII characters are rejected.
     * @return The unchanged valid cookie name.
     * @throws NativeFormatException If the name is empty or contains an invalid character.
     */
    private static String cookieName(String value) {
        if (!value.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+")) throw invalid("extraction.name", "requires a valid HTTP cookie name"); return value;
    }
    /**
     * Checks portable absolute-path syntax without requiring local middleware or PEM availability.
     *
     * Accepts POSIX absolute, Windows drive-qualified and UNC forms to allow cross-platform import.
     * It does not read files, load a module or normalize the path for another operating system.
     *
     * @param value Candidate path string.
     * @param p Safe schema path used for errors.
     * @return The unchanged accepted absolute string.
     * @throws NativeFormatException If the path syntax is invalid or relative.
     */
    private static String absolutePath(String value, String p) {
        try {
            if (!Path.of(value).isAbsolute() && !value.matches("[A-Za-z]:[\\\\/].+") && !value.matches("\\\\\\\\[^\\\\]+\\\\[^\\\\]+.*") && !value.startsWith("/"))
                throw new IllegalArgumentException();
            return value;
        } catch (RuntimeException ex) { throw invalid(p, "requires an absolute middleware or PEM path"); }
    }
    /**
     * Validates the limited dotted-key/numeric-index grammar without evaluating it.
     *
     * Keys begin with an ASCII letter/underscore and may contain digits/hyphens. Numeric segments
     * and bracket indices have no leading zeros and fit signed 32-bit range. Wildcards, quoted keys,
     * recursive descent and dollar-root syntax are unsupported. Iterative scanning avoids recursive
     * regex matching on long configured paths.
     *
     * @param path Extraction selector such as data.tokens[0].value or data.tokens.0.value.
     * @throws NativeFormatException If segment syntax, delimiters or an index bound is invalid.
     */
    public static void validateJsonPath(String path) {
        if (path == null || path.isEmpty()) throw invalid("extraction.jsonPath", "requires a key or index");
        int i = 0;
        while (i < path.length()) {
            boolean bracket = path.charAt(i) == '[';
            if (bracket) i++;
            if (i == path.length()) throw invalid("extraction.jsonPath", "missing index");
            char first = path.charAt(i);
            if (first >= '0' && first <= '9') {
                int start = i; long index = 0;
                while (i < path.length() && path.charAt(i) >= '0' && path.charAt(i) <= '9') {
                    index = index * 10 + path.charAt(i++) - '0';
                    if (index > Integer.MAX_VALUE) throw invalid("extraction.jsonPath", "array indices must fit a signed 32-bit integer");
                }
                if (first == '0' && i - start > 1) throw invalid("extraction.jsonPath", "indices cannot contain leading zeros");
            } else if (!bracket && keyStart(first)) {
                i++;
                while (i < path.length() && (keyStart(path.charAt(i)) || (path.charAt(i) >= '0' && path.charAt(i) <= '9') || path.charAt(i) == '-')) i++;
            } else throw invalid("extraction.jsonPath", "use dotted keys or numeric indices only");
            if (bracket) {
                if (i == path.length() || path.charAt(i++) != ']') throw invalid("extraction.jsonPath", "missing closing bracket");
            }
            if (i == path.length()) return;
            if (path.charAt(i) == '[') continue;
            if (path.charAt(i++) != '.' || i == path.length() || path.charAt(i) == '[')
                throw invalid("extraction.jsonPath", "use dotted keys or numeric indices only");
        }
    }
    /**
     * Recognizes the ASCII first-character rule shared by JSON-path key segments.
     *
     * @param c Candidate first character; Unicode letters are intentionally not accepted.
     * @return True for an ASCII letter or underscore.
     */
    private static boolean keyStart(char c) { return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }

}
