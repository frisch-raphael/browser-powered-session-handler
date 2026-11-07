import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.playwright.options.Cookie;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.OptionalLong;

/**
 * Collects the first valid token on its browser worker, retaining safe failures for a final result.
 *
 * Matching malformed/expired candidates may be superseded by a later valid candidate. JSON parsing
 * is bounded to 1 MiB after retrieval; Playwright may already have materialized an unknown-length
 * response. This component does not claim a streaming browser-body API or validate JWT signatures.
 */
public final class TokenExtractor {
    static final int MAX_JSON_BYTES = 1 << 20;
    static final int MAX_TOKEN_BYTES = 64 << 10;
    private static final ObjectMapper JSON = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private final JourneyDefinition.Extraction definition;
    private final Clock clock;
    private String token;
    private final List<TokenExtractor> parts;
    private final com.google.re2j.Pattern startPattern, endPattern;
    private long cookieExpiry = Long.MAX_VALUE;
    private AuthenticationFailure failure;

    /**
     * Creates empty attempt state; all methods remain confined to the owning browser worker.
     * @param definition Validated JSON/regex response or applicable-cookie selector.
     * @param clock Wall clock used only to reject already-expired JWT metadata/cookies.
     */
    public TokenExtractor(JourneyDefinition.Extraction definition, Clock clock) {
        this.definition = definition; this.clock = clock;
        try {
            startPattern = definition instanceof JourneyDefinition.RegexExtraction r ? compileRegex(r.startRegex()) : null;
            endPattern = definition instanceof JourneyDefinition.RegexExtraction r ? compileRegex(r.endRegex()) : null;
        } catch (AuthenticationFailure ex) { throw new IllegalArgumentException("Invalid response extraction boundaries."); }
        if (definition instanceof JourneyDefinition.CombinedExtraction combined) {
            var collectors = new java.util.ArrayList<TokenExtractor>();
            combined.tokens().forEach(c -> collectors.add(new TokenExtractor(c.selector(), clock))); parts = List.copyOf(collectors);
        } else parts = List.of();
    }

    /**
     * Applies the exact origin and encoded-path substring filter without considering query/fragment.
     * @param url Observed response URL; irrelevant/malformed URLs are simply not candidates.
     * @return True only for a configured JSON or regex response candidate.
     */
    public boolean matchesResponse(String url) {
        if (!parts.isEmpty()) return parts.stream().anyMatch(p -> p.matchesResponse(url));
        URI responseOrigin; String path;
        if (definition instanceof JourneyDefinition.JsonExtraction json) { responseOrigin = json.responseOrigin(); path = json.pathSubstring(); }
        else if (definition instanceof JourneyDefinition.RegexExtraction regex) { responseOrigin = regex.responseOrigin(); path = regex.pathSubstring(); }
        else return false;
        try { URI uri = URI.create(url); return origin(uri).equals(responseOrigin) && (uri.getRawPath() == null ? "/" : uri.getRawPath()).contains(path); }
        catch (RuntimeException ex) { return false; }
    }

    /** Retains the JSON-only helper used by existing integrations. */
    public boolean matchesJson(String url) {
        if (!parts.isEmpty()) return parts.stream().anyMatch(p -> p.matchesJson(url));
        return definition instanceof JourneyDefinition.JsonExtraction && matchesResponse(url);
    }

    /** Validates bounded, linear-time boundary expressions without exposing configured text. */
    static com.google.re2j.Pattern compileRegex(String source) throws AuthenticationFailure {
        if (source == null || source.isEmpty() || source.getBytes(StandardCharsets.UTF_8).length > 4096)
            throw extraction("The boundary expression must contain 1-4096 UTF-8 bytes.", "Use an expression between 1 and 4096 UTF-8 bytes.");
        try {
            var compiled = com.google.re2j.Pattern.compile(source, com.google.re2j.Pattern.DOTALL);
            if (compiled.programSize() > 10_000) throw extraction("The token boundary expression is too complex.", "Simplify the expression.");
            return compiled;
        } catch (com.google.re2j.PatternSyntaxException ex) {
            throw extraction("The token boundary expression is invalid.", "Correct the expression using supported RE2 syntax.");
        }
    }

    /**
     * Rejects a declared oversized/malformed matching body before calling Playwright Response.body.
     * @param contentLength Optional Content-Length header; absent permits the post-retrieval guard.
     * @throws AuthenticationFailure If a supplied length is invalid or exceeds 1 MiB.
     */
    public static void checkDeclaredLength(String contentLength) throws AuthenticationFailure {
        if (contentLength == null) return;
        try { if (!contentLength.matches("[0-9]+") || Long.parseLong(contentLength) > MAX_JSON_BYTES) throw new IllegalArgumentException(); }
        catch (RuntimeException ex) { throw extraction("A matching token response has an invalid or oversized Content-Length.", ""); }
    }

    /**
     * Parses a matching retrieved body, keeping a safe failure if no valid token has arrived yet.
     * @param body Exact response bytes already materialized by Playwright.
     */
    public void considerJson(byte[] body) {
        considerJson(body, true);
    }

    /**
     * Parses a candidate while distinguishing error-response bodies from malformed token responses.
     * @param body Retrieved matching bytes within the post-retrieval ceiling.
     * @param missingIsFailure Whether absent paths/invalid JSON establish a separate extraction error;
     *     false for HTTP error pages whose relevant status already explains the missing token.
     */
    void considerJson(byte[] body, boolean missingIsFailure) {
        if (!parts.isEmpty()) { parts.stream().filter(p -> p.definition instanceof JourneyDefinition.JsonExtraction).forEach(p -> p.considerJson(body, missingIsFailure)); return; }
        if (token != null) return;
        try {
            if (!(definition instanceof JourneyDefinition.JsonExtraction json) || body.length > MAX_JSON_BYTES)
                throw extraction("The matching JSON response exceeds the extraction limit.", "");
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(body)).toString();
            JsonNode current = JSON.readTree(text); String selector = json.jsonPath(); ConfigManager.validateJsonPath(selector);
            int i = 0;
            while (i < selector.length()) {
                if (selector.charAt(i) == '.') i++;
                boolean bracket = selector.charAt(i) == '['; if (bracket) i++;
                int start = i;
                while (i < selector.length() && selector.charAt(i) != '.' && selector.charAt(i) != '[' && selector.charAt(i) != ']') i++;
                String part = selector.substring(start, i); if (bracket) i++;
                if (current == null) break;
                if (current.isArray()) current = part.matches("0|[1-9][0-9]*") ? current.get(Integer.parseInt(part)) : null;
                else current = current.isObject() && !bracket ? current.get(part) : null;
            }
            if (current == null && !missingIsFailure) return;
            if (current == null || !current.isTextual()) throw extraction("The matching response has no string at the configured JSON path.", "Select a JSON path whose value is a token string.").atInput(AuthenticationFailure.Input.JSON_PATH);
            token = normalize(current.textValue(), clock);
        } catch (AuthenticationFailure ex) { observe(ex); }
        catch (Exception ex) { if (missingIsFailure) observe(extraction("The selected token response could not be read as JSON.", "")); }
    }

    /**
     * Delivers a response only to the named JSON selectors whose origin/path actually match it.
     * @param url Observed response URL, never logged.
     * @param body Bounded response bytes.
     * @param missingIsFailure Whether a missing JSON path establishes an extraction failure.
     */
    void considerJson(String url, byte[] body, boolean missingIsFailure) {
        if (!parts.isEmpty()) parts.stream().filter(p -> p.matchesJson(url)).forEach(p -> p.considerJson(body, missingIsFailure));
        else if (matchesJson(url)) considerJson(body, missingIsFailure);
    }

    /** Routes each bounded response to its own JSON or regex collectors. Bodies are decoded as UTF-8. */
    void considerResponse(String url, byte[] body, boolean missingIsFailure) {
        if (!parts.isEmpty()) { parts.stream().filter(p -> p.matchesResponse(url)).forEach(p -> p.considerResponse(url, body, missingIsFailure)); return; }
        if (!matchesResponse(url) || token != null) return;
        if (!(definition instanceof JourneyDefinition.RegexExtraction)) { considerJson(body, missingIsFailure); return; }
        try {
            if (body.length > MAX_JSON_BYTES) throw extraction("The matching response exceeds the extraction limit.", "Keep token responses within 1 MiB.");
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(body)).toString();
            var start = startPattern.matcher(text);
            if (!start.find()) return;
            var end = endPattern.matcher(text);
            if (!end.find(start.end()) || end.start() == start.end()) return;
            token = normalize(text.substring(start.end(), end.start()), clock);
        } catch (AuthenticationFailure ex) { observe(ex); }
        catch (java.nio.charset.CharacterCodingException ex) { if (missingIsFailure) observe(extraction("A matching response is not valid UTF-8 text.", "Use a UTF-8 response body for regex extraction.")); }
    }

    /**
     * Selects only from cookies already made applicable to originUrl by Playwright.
     * @param applicable Result of context.cookies(configured originUrl), never an unfiltered cookie jar.
     */
    public void considerCookies(List<Cookie> applicable) {
        if (!(definition instanceof JourneyDefinition.CookieExtraction cookie)) return;
        token = null; cookieExpiry = Long.MAX_VALUE;
        try {
            Map<List<String>, String> candidates = new HashMap<>();
            for (Cookie c : applicable) if (cookie.name().equals(c.name) && (cookie.domain() == null || cookie.domain().equals(c.domain))
                    && (cookie.path() == null || cookie.path().equals(c.path))) {
                if (c.expires != null && c.expires >= 0 && c.expires <= clock.instant().getEpochSecond()) continue;
                List<String> identity = List.of(c.name, c.domain, c.path); String previous = candidates.put(identity, c.value);
                if (previous != null && !previous.equals(c.value)) throw extraction("The browser returned conflicting values for the same cookie.", "");
            }
            if (candidates.size() > 1) throw extraction("More than one cookie matches the token settings.", "Set the cookie domain and path in Capture credentials to select one cookie.").atInput(AuthenticationFailure.Input.COOKIE_FILTERS);
            if (candidates.size() == 1) {
                token = normalize(candidates.values().iterator().next(), clock);
                for (Cookie c : applicable) if (cookie.name().equals(c.name) && token.equals(c.value) && c.expires != null && c.expires >= 0) cookieExpiry = Math.min(cookieExpiry, (long) Math.floor(c.expires));
            }
        } catch (AuthenticationFailure ex) { observe(ex); }
    }

    /**
     * Retains the highest-priority established failure without logging browser/native exception text.
     * @param candidate Typed safe failure; valid token results still take precedence at completion.
     */
    public void observe(AuthenticationFailure candidate) { if (failure == null || candidate.priority() < failure.priority()) failure = candidate; }

    /**
     * Returns whether a normalized valid candidate has been captured; no token content is disclosed.
     *
     * @return Whether a normalized valid candidate has been captured; no token content is disclosed.
     */
    public boolean hasToken() { return parts.isEmpty() ? token != null && clock.instant().getEpochSecond() < cookieExpiry : parts.stream().allMatch(TokenExtractor::hasToken); }

    /**
     * Reads each selected cookie only from its own applicable URL; collectors remain on their browser worker.
     * @param reader Browser-context cookie reader.
     */
    void collectCookies(java.util.function.Function<String, List<Cookie>> reader) {
        if (!parts.isEmpty()) parts.forEach(p -> p.collectCookies(reader));
        else if (definition instanceof JourneyDefinition.CookieExtraction cookie) considerCookies(reader.apply(cookie.originUrl().toString()));
    }

    /** @return Exact configured cookie values, kept separate from the primary JSON token and diagnostics. */
    Map<String, String> cookieValues() {
        Map<String, String> result = new java.util.LinkedHashMap<>();
        if (!parts.isEmpty()) parts.forEach(p -> result.putAll(p.cookieValues()));
        else if (definition instanceof JourneyDefinition.CookieExtraction cookie && token != null) result.put(cookie.name(), token);
        return Map.copyOf(result);
    }

    /** @return User-named credentials from the complete selection; no values are logged or exported. */
    Map<String, String> namedValues() {
        Map<String, String> values = new java.util.LinkedHashMap<>();
        if (definition instanceof JourneyDefinition.CombinedExtraction combined) for (int i = 0; i < parts.size(); i++) values.put(combined.tokens().get(i).name(), parts.get(i).token);
        return Map.copyOf(values);
    }

    /** @return Earliest cookie or JWT expiry so one expired credential invalidates the complete set. */
    OptionalLong expirySeconds() {
        long expiry = cookieExpiry;
        if (token != null) { var jwt = jwtExpiry(token); if (jwt.isPresent()) expiry = Math.min(expiry, jwt.getAsLong()); }
        for (var part : parts) { var candidate = part.expirySeconds(); if (candidate.isPresent()) expiry = Math.min(expiry, candidate.getAsLong()); }
        return expiry == Long.MAX_VALUE ? OptionalLong.empty() : OptionalLong.of(expiry);
    }

    /**
     * Rechecks expiry at completion so a token captured early cannot expire while steps finish.
     * @return Normalized token string for deliberate use by the coordinator.
     * @throws AuthenticationFailure If no token succeeded or its JWT metadata is now expired.
     */
    public String result() throws AuthenticationFailure {
        if (!parts.isEmpty() && hasToken()) return parts.stream().filter(p -> !(p.definition instanceof JourneyDefinition.CookieExtraction)).findFirst().orElse(parts.getFirst()).result();
        if (hasToken()) return normalize(token, clock);
        AuthenticationFailure observed = failure;
        for (int index = 0; index < parts.size(); index++) {
            var child = parts.get(index);
            if (child.hasToken() || child.failure == null) continue;
            var candidate = child.failure.forCredential(index);
            if (observed == null || candidate.priority() < observed.priority()) observed = candidate;
        }
        if (observed != null) throw observed.phase() == AuthenticationFailure.Phase.EXTRACTION && observed.input() == null
                ? observed.atInput(AuthenticationFailure.Input.CAPTURE_SOURCE) : observed;
        if (!parts.isEmpty()) for (int index = 0; index < parts.size(); index++) if (!parts.get(index).hasToken()) {
            try { parts.get(index).result(); }
            catch (AuthenticationFailure error) { throw error.forCredential(index); }
        }
        if (definition instanceof JourneyDefinition.CookieExtraction cookie)
            throw extraction("The selected cookie " + cookie.name() + " was not received.", "").atInput(AuthenticationFailure.Input.CAPTURE_SOURCE);
        throw extraction("A configured token or cookie was not received.", "").atInput(AuthenticationFailure.Input.CAPTURE_SOURCE);
    }

    /**
     * Applies retained trim/leading-Bearer normalization and bounds token text before publication.
     * @param raw Extracted string, never included in exceptions.
     * @param clock Current wall clock for JWT-expiry metadata.
     * @return Nonempty normalized text with no ASCII control characters and at most 64 KiB UTF-8.
     * @throws AuthenticationFailure If empty, oversized, control-bearing or already expired.
     */
    static String normalize(String raw, Clock clock) throws AuthenticationFailure {
        String value = raw.trim();
        if (value.equalsIgnoreCase("Bearer")) value = "";
        else if (value.regionMatches(true, 0, "Bearer ", 0, 7)) value = value.substring(7).trim();
        if (value.isEmpty())
            throw extraction("The extracted token is empty.", "");
        if (value.getBytes(StandardCharsets.UTF_8).length > MAX_TOKEN_BYTES)
            throw extraction("The extracted token exceeds 64 KiB.", "");
        if (value.chars().anyMatch(c -> c < 32 || c == 127))
            throw extraction("The extracted token contains control characters.", "");
        OptionalLong exp = jwtExpiry(value);
        if (exp.isPresent() && exp.getAsLong() <= clock.instant().getEpochSecond())
            throw new AuthenticationFailure(AuthenticationFailure.Phase.EXTRACTION, AuthenticationFailure.Cause.TOKEN_EXPIRED,
                    "The login returned an expired token.", "");
        return value;
    }

    /**
     * Reads bounded JWT exp metadata only; opaque/malformed/nonintegral metadata has no JWT expiry.
     * @param value Already size-bounded token text; this helper also guards independent callers.
     * @return Optional epoch seconds, without claiming algorithm/signature validation.
     */
    static OptionalLong jwtExpiry(String value) {
        try {
            if (value.length() > MAX_TOKEN_BYTES) return OptionalLong.empty();
            String[] parts = value.split("\\.", -1); if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty()) return OptionalLong.empty();
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]); if (payload.length > MAX_TOKEN_BYTES) return OptionalLong.empty();
            JsonNode n = JSON.readTree(payload), exp = n == null ? null : n.get("exp");
            return exp != null && exp.isIntegralNumber() && exp.canConvertToLong() ? OptionalLong.of(exp.longValue()) : OptionalLong.empty();
        } catch (Exception ex) { return OptionalLong.empty(); }
    }

    /**
     * Canonicalizes origin identity without DNS lookup, wildcard matching or URL-path inclusion.
     * @param uri Absolute HTTP(S) URL.
     * @return Scheme/lowercase-host/effective-port origin.
     * @throws IllegalArgumentException If the input is not a usable HTTP(S) origin source.
     */
    static URI origin(URI uri) {
        try {
            String scheme = uri.getScheme().toLowerCase(Locale.ROOT); int port = uri.getPort();
            if ((!scheme.equals("http") && !scheme.equals("https")) || uri.getHost() == null || uri.getUserInfo() != null || port == 0 || port > 65535) throw new IllegalArgumentException();
            if ((scheme.equals("https") && port == 443) || (scheme.equals("http") && port == 80)) port = -1;
            return new URI(scheme, null, uri.getHost().toLowerCase(Locale.ROOT), port, null, null, null);
        } catch (Exception ex) { throw new IllegalArgumentException("Invalid HTTP origin."); }
    }

    /**
     * Builds a terminal extraction result without retaining response contents or token values.
     *
     * @param safe Safe extraction explanation.
     * @param recovery Concrete selector/step guidance.
     * @return Redacted terminal extraction failure.
     */
    private static AuthenticationFailure extraction(String safe, String recovery) { return new AuthenticationFailure(AuthenticationFailure.Phase.EXTRACTION, AuthenticationFailure.Cause.EXTRACTION, safe, recovery); }
}
