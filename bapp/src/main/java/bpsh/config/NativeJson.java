package bpsh.config;

import bpsh.credentials.JsonPathSelector;
import bpsh.model.ConfigurationException;
import com.fasterxml.jackson.databind.JsonNode;
import java.net.URI;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import static bpsh.config.ConfigManager.*;

/** Exact field readers and bounded scalar validation shared by the native codecs. */
final class NativeJson {
    private NativeJson() {}
    /**
     * Constructs a field-level failure without attaching potentially secret-bearing causes.
     *
     * @param path Safe schema path or validated journey label; never arbitrary input values.
     * @param reason Safe explanation and, where relevant, recovery guidance.
     * @return Exception for the caller to throw; this helper itself does not throw it.
     */
    static ConfigurationException invalid(String path, String reason) { return new ConfigurationException(path + ": " + reason + "."); }
    /**
     * Distinguishes configured optional values from absent or explicitly null fields.
     *
     * @param n Nonnull containing object validated by its caller.
     * @param name Known field name to inspect.
     * @return True only when the member exists and is not JSON null.
     */
    static boolean present(JsonNode n, String name) { return n.has(name) && !n.get(name).isNull(); }
    /**
     * Requires an object and rejects unknown keys without echoing their potentially sensitive names.
     *
     * Allowed fields are not automatically required; each accessor applies that field's required,
     * optional or default rule afterward.
     *
     * @param n Candidate JSON node, including null for a missing object.
     * @param path Safe containing schema path used in errors.
     * @param fields Complete set of allowed member names for this mode.
     * @throws bpsh.model.ConfigurationException If the node is not an object or contains an unsupported member.
     */
    static void object(JsonNode n, String path, String... fields) {
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
     * @throws bpsh.model.ConfigurationException If the node is absent, null or not an array.
     */
    static JsonNode array(JsonNode n, String path) { if (n == null || !n.isArray()) throw invalid(path, "requires an array"); return n; }
    /**
     * Reads a required string without coercion or including its value in an error.
     *
     * @param n Containing object, or null when its container is missing.
     * @param name Known member name, or a previously validated secure-step UUID.
     * @param path Safe container path to qualify the field error.
     * @return Exact string content, including empty strings; content rules are separate.
     * @throws bpsh.model.ConfigurationException If the member is absent, null or not a string.
     */
    static String text(JsonNode n, String name, String path) {
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
     * @throws bpsh.model.ConfigurationException If a supplied member is nontextual or blank.
     */
    static String optionalNonblank(JsonNode n, String name, String path) { return present(n, name) ? nonblank(text(n, name, path), path + "." + name) : null; }
    /**
     * Rejects an empty or whitespace-only value without trimming the accepted content.
     *
     * @param v Nonnull string already read with a typed accessor.
     * @param p Safe schema path for failure reporting.
     * @return The unchanged nonblank string.
     * @throws bpsh.model.ConfigurationException If the string is blank.
     */
    static String nonblank(String v, String p) { if (v.isBlank()) throw invalid(p, "requires a nonblank string"); return v; }
    /**
     * Requires content while preserving meaningful whitespace in path-substring matching.
     *
     * @param v Nonnull string already read with a typed accessor.
     * @param p Safe schema path for failure reporting.
     * @return The unchanged string, including whitespace-only content.
     * @throws bpsh.model.ConfigurationException If the string is empty.
     */
    static String nonempty(String v, String p) { if (v.isEmpty()) throw invalid(p, "requires a nonempty string"); return v; }
    /**
     * Reads an exact boolean, using its default only when the member is absent.
     *
     * @param n Validated containing object.
     * @param name Known boolean field.
     * @param fallback Default for an absent member; explicit null is not a default request.
     * @return Configured boolean or fallback.
     * @throws bpsh.model.ConfigurationException If a present member is null or not boolean.
     */
    static boolean bool(JsonNode n, String name, boolean fallback) {
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
     * @throws bpsh.model.ConfigurationException If the node is absent, mistyped, overflowing or outside bounds.
     */
    static long number(JsonNode n, String p, long min, long max) {
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
     * @throws bpsh.model.ConfigurationException If a supplied member fails strict integral-number validation.
     */
    static int integer(JsonNode n, String name, int fallback, int min, int max) { return n.has(name) ? (int) number(n.get(name), name, min, max) : fallback; }
    /**
     * Reads a positive admission limit while preserving explicit Unlimited semantics.
     *
     * @param n Validated controls object.
     * @param name Known global or per-journey waiting-limit field.
     * @return Null for absent/null (Unlimited), otherwise an integer from one through Integer.MAX_VALUE.
     * @throws bpsh.model.ConfigurationException If a supplied finite limit is mistyped or out of range.
     */
    static Integer limit(JsonNode n, String name) { return present(n, name) ? (int) number(n.get(name), name, 1, Integer.MAX_VALUE) : null; }
    /**
     * Requires canonical lowercase UUID v4 syntax and the standard UUID variant.
     *
     * This validates representation only, not whether an identity exists in the registry.
     *
     * @param n Candidate string node.
     * @param p Safe schema path for errors.
     * @return Parsed UUID without normalizing an invalid spelling.
     * @throws bpsh.model.ConfigurationException If the node or UUID syntax is invalid.
     */
    static UUID uuid(JsonNode n, String p) {
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
     * @throws bpsh.model.ConfigurationException If the candidate does not follow the native grammar.
     */
    static String alias(String v) { if (!v.matches("[A-Za-z0-9][A-Za-z0-9_-]{0,63}")) throw invalid("alias", "use 1-64 ASCII letters, digits, underscores or hyphens, starting with a letter or digit"); return v; }
    /**
     * Matches an exact lowercase native discriminator against a model enum.
     *
     * @param <T> Enum type representing the supported choices.
     * @param v Exact wire spelling; case-insensitive coercion is not performed.
     * @param type Enum class to inspect.
     * @param p Safe schema path for an unsupported-value error.
     * @return Matching enum constant.
     * @throws bpsh.model.ConfigurationException If no supported constant has that wire spelling.
     */
    static <T extends Enum<T>> T enumeration(String v, Class<T> type, String p) {
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
     * @throws bpsh.model.ConfigurationException If scheme, host, userinfo, port or URI syntax is invalid.
     */
    static URI httpUri(String value, String p) {
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
     * @throws bpsh.model.ConfigurationException If URL/origin restrictions are violated.
     */
    static URI origin(String value, String p, boolean httpsOnly) {
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
     * @throws bpsh.model.ConfigurationException If the name is empty or contains an invalid character.
     */
    static String cookieName(String value) {
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
     * @throws bpsh.model.ConfigurationException If the path syntax is invalid or relative.
     */
    static String absolutePath(String value, String p) {
        try {
            if (!Path.of(value).isAbsolute() && !value.matches("[A-Za-z]:[\\\\/].+") && !value.matches("\\\\\\\\[^\\\\]+\\\\[^\\\\]+.*") && !value.startsWith("/"))
                throw new IllegalArgumentException();
            return value;
        } catch (RuntimeException ex) { throw invalid(p, "requires an absolute middleware or PEM path"); }
    }
    static void validateJsonPath(String path) { JsonPathSelector.validate(path); }
}
