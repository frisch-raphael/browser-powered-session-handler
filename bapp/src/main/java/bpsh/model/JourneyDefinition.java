package bpsh.model;

import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;

/**
 * Describes a native authentication journey without secret values or live browser/token state.
 *
 * Executable definitions have codec-validated field semantics; unfinished definitions retain a nonsecret draft. This record only enforces basic
 * non-null identity and copies the ordered step list; it does not perform setup or authentication.
 * Secure inputs refer to separate values by step UUID. Ordinary input text remains saved configuration.
 *
 * @param id Stable journey UUID within its managed scope.
 * @param displayName User-facing name; changing it alone does not change authenticated identity.
 * @param alias Validated readable tag alias, preserving display spelling.
 * @param authenticationUrl Initial absolute HTTP(S) login URL.
 * @param rememberSecrets Explicit readable-secret persistence choice; independent of export consent.
 * @param steps Ordered immutable step definitions.
 * @param browser Browser/proxy/deadline options for an attempt.
 * @param extraction JSON-response or applicable-cookie token selection.
 * @param injection Credential form for ordinary automatic injection; tags return raw normalized token text.
 * @param cache Maximum token age and configured pre-expiry refresh skew.
 * @param mtls Explicit PKCS#11 identity settings, or null when mTLS is disabled.
 * @param draft Unfinished nonsecret editor input, or null for an executable definition.
 */
public record JourneyDefinition(
        UUID id, String displayName, String alias, URI authenticationUrl,
        boolean rememberSecrets, List<AuthStep.Definition> steps, Browser browser,
        Extraction extraction, Injection injection, Cache cache, Mtls mtls, JourneyDraft draft) {
    /** Creates an executable definition without an unfinished editor snapshot. */
    public JourneyDefinition(UUID id, String displayName, String alias, URI authenticationUrl,
            boolean rememberSecrets, List<AuthStep.Definition> steps, Browser browser,
            Extraction extraction, Injection injection, Cache cache, Mtls mtls) {
        this(id, displayName, alias, authenticationUrl, rememberSecrets, steps, browser, extraction, injection, cache, mtls, null);
    }

    /**
     * Requires an internal identity and defensively copies the ordered step list.
     */
    public JourneyDefinition {
        Objects.requireNonNull(id);
        steps = List.copyOf(steps);
    }

    /**
     * Names the managed ownership boundary used with UUIDs for isolation.
     */
    public enum Scope {
        PROJECT("project"), LIBRARY("library");
        /**
         * Retains the exact native JSON spelling independently of enum display names.
         */
        private final String wire;
        /**
         * Binds a supported managed scope to its fixed wire discriminator.
         *
         * @param wire Exact lowercase JSON representation.
         */
        Scope(String wire) { this.wire = wire; }
        /**
         * Returns the stable native representation of this managed scope.
         *
         * @return project or library.
         */
        public String wire() { return wire; }
    }

    /**
     * Captures the exact configuration generation to which work and token results belong.
     *
     * Scope plus UUID distinguishes equal IDs in different containers. A positive generation prevents
     * late results for an older definition/secret state from becoming usable after an edit.
     *
     * @param scope Managed ownership boundary.
     * @param journeyId Stable internal journey UUID.
     * @param generation Positive runtime configuration generation; never serialized into native JSON.
     */
    public record Identity(Scope scope, UUID journeyId, long generation) {
        /**
         * Requires complete ownership and a positive generation.
         *
         * @throws IllegalArgumentException If generation is below one.
         */
        public Identity {
            Objects.requireNonNull(scope);
            Objects.requireNonNull(journeyId);
            if (generation < 1) throw new IllegalArgumentException("Invalid configuration generation.");
        }
        /**
         * Finds the stable secret owner while deliberately dropping the work's generation.
         *
         * @return Scoped journey key; effective secret changes replace values and advance the registry generation.
         */
        public JourneyKey key() { return new JourneyKey(scope, journeyId); }
    }

    /**
     * Describes an explicitly configured HTTP proxy; absence of this object means direct browsing.
     *
     * @param url Validated HTTP origin with no userinfo, path beyond slash, query or fragment.
     */
    public record Proxy(URI url) {}
    /**
     * Carries per-attempt browser settings independently of any live Playwright objects.
     *
     * @param headless Whether the owned browser should run without a visible window.
     * @param proxy Explicit HTTP proxy, or null for direct traffic.
     * @param navigationTimeoutMs Navigation timeout in milliseconds, later capped by the attempt budget.
     * @param tokenWaitTimeoutMs Token-observation wait in milliseconds, later capped by the attempt budget.
     */
    public record Browser(boolean headless, Proxy proxy, int navigationTimeoutMs, int tokenWaitTimeoutMs) {}
    /**
     * Restricts token selection to response JSON, response regex, applicable cookies or a named collection.
     */
    public sealed interface Extraction permits JsonExtraction, RegexExtraction, CookieExtraction, CombinedExtraction {}
    /**
     * Requires every configured credential before completing one login.
     * @param tokens Ordered named JSON/regex/cookie selectors.
     */
    public record CombinedExtraction(List<NamedExtraction> tokens) implements Extraction {
        /** Copies selectors; parsing enforces a nonempty, bounded credential selection. */
        public CombinedExtraction { tokens = List.copyOf(tokens); }
    }
    /**
     * Names one credential independently of its JSON path or actual cookie name.
     * @param name User-defined token name used by request tags.
     * @param selector One JSON, regex or cookie selector; nested collections are forbidden.
     */
    public record NamedExtraction(String name, Extraction selector) {}
    /**
     * Selects a JSON response using an exact origin, encoded path substring and limited JSON path.
     *
     * @param responseOrigin Canonical HTTP(S) origin; no wildcard or path.
     * @param pathSubstring Nonempty case-sensitive match against encoded response path, excluding query/fragment.
     * @param jsonPath Validated dotted-key/numeric-index selector, not a general JSONPath expression.
     */
    public record JsonExtraction(URI responseOrigin, String pathSubstring, String jsonPath) implements Extraction {}
    /** Captures text between the first start match and the next end match in a response body. */
    public record RegexExtraction(URI responseOrigin, String pathSubstring, String startRegex, String endRegex) implements Extraction {
        @Override public String toString() { return "RegexExtraction[response body boundaries]"; }
    }
    /**
     * Selects from cookies applicable to a configured HTTP(S) URL.
     *
     * @param originUrl Absolute URL used to establish cookie applicability.
     * @param name Exact valid cookie name.
     * @param domain Optional exact domain selector; null leaves the selector unspecified.
     * @param path Optional exact path selector; null leaves the selector unspecified.
     */
    public record CookieExtraction(URI originUrl, String name, String domain, String path) implements Extraction {}
    /**
     * Names the supported credential destinations for ordinary request-local injection.
     */
    public enum InjectionType {
        BEARER("bearer"), HEADER("header"), COOKIE("cookie"), DISABLED("disabled");

        private final String wire;

        InjectionType(String wire) { this.wire = wire; }

        public String wire() { return wire; }

        public boolean matches(String value) { return wire.equals(value); }
    }
    /** One explicit destination per response token; captured cookies retain their original names. */
    public record Injection(List<TokenInjection> tokens) {
        public Injection { tokens = List.copyOf(tokens); }
        public static Injection perToken(List<TokenInjection> tokens) { return new Injection(tokens); }
    }
    /** Maps one response token to a destination, or leaves it available only through explicit tags. */
    public record TokenInjection(String tokenName, InjectionType type, String name) {}
    /**
     * Carries expiry/refresh policy inputs without storing a token or scheduling work.
     *
     * @param maxAgeSeconds Finite maximum cached age validated by the native codec.
     * @param refreshSkewSeconds Requested pre-expiry refresh window in seconds.
     */
    public record Cache(int maxAgeSeconds, int refreshSkewSeconds) {}
    /**
     * Chooses status-code detection or bounded RE2 response-body matching.
     */
    public enum RecoveryMode {
        STATUS_CODE("status_code"), REGEX("regex"), BOTH("both");

        private final String wire;

        RecoveryMode(String wire) { this.wire = wire; }

        public String wire() { return wire; }

        public boolean matches(String value) { return wire.equals(value); }
    }
    /**
     * Describes how an attributed response can signal session loss.
     *
     * @param enabled Whether recovery detection is enabled for this journey.
     * @param mode Status-code comparison or RE2 pattern matching.
     * @param statusCode Expected failure status only for STATUS_CODE; null for REGEX.
     * @param pattern Validated RE2 pattern only for REGEX; null for STATUS_CODE.
     */
    public record Recovery(boolean enabled, RecoveryMode mode, Integer statusCode, String pattern) {
        /**
         * Returns the selected recovery mode without echoing a configured expression.
         *
         * @return Diagnostic mode label only.
         */
        @Override public String toString() { return "Recovery[mode=" + mode + "]"; }
    }
    /**
     * Distinguishes a provider slot-list index from an explicit PKCS#11 slot ID.
     */
    public enum SlotKind { INDEX, ID }
    /**
     * Selects a PKCS#11 slot without conflating index and provider identity.
     *
     * @param kind Interpretation of value: INDEX or ID.
     * @param value Nonnegative index bounded to signed 32-bit, or ID bounded to signed 64-bit.
     */
    public record Slot(SlotKind kind, long value) {}
    /**
     * Describes Java-owned PKCS#11 certificate selection without retaining a PIN or private key.
     *
     * Paths remain portable strings until asynchronous setup checks availability. The origin list
     * is copied; no provider is loaded and no token operation occurs during model construction.
     *
     * @param modulePath Absolute vendor middleware path.
     * @param slot Explicit slot selection; the codec supplies index zero when omitted.
     * @param certificateSha256 Exact lowercase certificate fingerprint; no common-name fallback.
     * @param origins Nonempty canonical HTTPS origins allowed to use this identity, including the HTTPS Login URL's server after codec validation.
     * @param trustedCaBundlePath Optional absolute PEM trust-bundle path; null uses the normal trust setup.
     */
    public record Mtls(String modulePath, Slot slot, String certificateSha256,
                       List<URI> origins, String trustedCaBundlePath) {
        /**
         * Defensively copies the certificate-origin allowlist.
         */
        public Mtls { origins = List.copyOf(origins); }
        /**
         * Returns a configuration marker without exposing module, certificate or origin details.
         *
         * @return A fixed configured label.
         */
        @Override public String toString() { return "Mtls[configured]"; }
    }

    /**
     * Case-folds an already validated ASCII alias for collision checks and lookup.
     *
     * @return Locale-independent lowercase comparison spelling.
     */
    public String canonicalAlias() { return alias.toLowerCase(Locale.ROOT); }

    /**
     * Compares fields whose effective changes require a new registry generation.
     *
     * Includes identity, canonical alias, login/steps/browser/extraction/injection/cache/mTLS.
     * Display-name edits, case-only alias spelling and Remember secrets alone are excluded. Secret
     * values are owned separately and must be compared by the registry's SecretStore path.
     *
     * @param other Candidate definition, or null.
     * @return True when these effective nonsecret configuration fields match.
     */
    public boolean sameAuthenticationConfiguration(JourneyDefinition other) {
        return other != null && id.equals(other.id)
                && canonicalAlias().equals(other.canonicalAlias())
                && Objects.equals(authenticationUrl, other.authenticationUrl)
                && steps.equals(other.steps) && Objects.equals(browser, other.browser)
                && Objects.equals(extraction, other.extraction) && Objects.equals(injection, other.injection)
                && Objects.equals(cache, other.cache)
                && Objects.equals(mtls, other.mtls) && Objects.equals(draft, other.draft);
    }

    /**
     * Copies a definition with replacement journey/step identities and a chosen persistence flag.
     *
     * This does not allocate IDs, remap secrets or validate the replacement list; the import/transfer
     * caller performs those operations explicitly before publishing.
     *
     * @param newId Destination journey UUID.
     * @param newSteps Ordered steps carrying their destination UUIDs.
     * @param remember Destination Remember secrets choice; native import supplies false.
     * @return A new definition retaining the remaining immutable configuration.
     */
    public JourneyDefinition withIdentity(UUID newId, List<AuthStep.Definition> newSteps, boolean remember) {
        return new JourneyDefinition(newId, displayName, alias, authenticationUrl, remember,
                newSteps, browser, extraction, injection, cache, mtls, draft == null ? null : draft.remap(newSteps, alias, remember));
    }

    /**
     * Returns only the journey ID and validated alias for diagnostics.
     *
     * @return A short identity label without URLs, steps or secret values.
     */
    @Override public String toString() { return "JourneyDefinition[id=" + id + ", alias=" + alias + "]"; }
}
