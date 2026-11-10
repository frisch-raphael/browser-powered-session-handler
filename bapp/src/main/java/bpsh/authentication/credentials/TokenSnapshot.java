package bpsh.authentication.credentials;

import bpsh.journey.JourneyDefinition;
import java.time.Instant;
import java.util.Objects;

/** Holds one immutable, versioned credential; diagnostic representations never disclose its value. */
public final class TokenSnapshot {
    private final JourneyDefinition.Identity identity;
    private final bpsh.journey.HttpAuthentication.Protocol httpProtocol;
    public bpsh.journey.HttpAuthentication.Protocol httpProtocol() { return httpProtocol; }
    private final java.util.List<bpsh.authentication.http.HttpAuthenticationEvidence> httpObservations;
    public java.util.List<bpsh.authentication.http.HttpAuthenticationEvidence> httpObservations() {return httpObservations;}
    private final long version;
    private final String value;
    private final TokenLifetime.Window lifetime;
    private final JourneyDefinition.Extraction extraction;
    private final java.util.Map<String, String> cookies, namedTokens;

    /**
     * Binds a normalized value and lifetime to one exact configuration generation and token version.
     * @param identity Runtime identity permitted to use this result.
     * @param version Positive coordinator-issued token version.
     * @param value Normalized token text for deliberate request insertion or explicitly opened cache inspection.
     * @param lifetime Acquired immutable expiry/refresh metadata.
     */
    public TokenSnapshot(JourneyDefinition.Identity identity, long version, String value, TokenLifetime.Window lifetime) {
        this(identity, version, value, lifetime, java.util.Map.of(), java.util.Map.of());
    }
    /**
     * Binds all acquired cookies and the primary token to one atomic cache publication.
     * @param identity Exact configured identity.
     * @param version Coordinator-issued version.
     * @param value Primary JSON token, or first cookie for a cookie-only journey.
     * @param lifetime Earliest expiry across the complete set.
     * @param namedTokens User-named values selected by token attributes.
     * @param cookies Configured cookie values for explicit or automatic insertion.
     */
    public TokenSnapshot(JourneyDefinition.Identity identity, long version, String value, TokenLifetime.Window lifetime, java.util.Map<String, String> cookies, java.util.Map<String, String> namedTokens) {
        this(identity, version, value, lifetime, cookies, namedTokens, null);
    }
    /** Binds captured source metadata so unfinished edits can still display the existing cache accurately. */
    public TokenSnapshot(JourneyDefinition.Identity identity, long version, String value, TokenLifetime.Window lifetime, java.util.Map<String, String> cookies, java.util.Map<String, String> namedTokens, JourneyDefinition.Extraction extraction) {
        this(identity, version, value, lifetime, cookies, namedTokens, extraction, null);
    }
    public TokenSnapshot(JourneyDefinition.Identity identity, long version, String value, TokenLifetime.Window lifetime, java.util.Map<String,String> cookies, java.util.Map<String,String> namedTokens, JourneyDefinition.Extraction extraction, bpsh.journey.HttpAuthentication.Protocol httpProtocol) {
        this(identity,version,value,lifetime,cookies,namedTokens,extraction,httpProtocol,java.util.List.of());
    }
    public TokenSnapshot(JourneyDefinition.Identity identity,long version,String value,TokenLifetime.Window lifetime,java.util.Map<String,String> cookies,
            java.util.Map<String,String> namedTokens,JourneyDefinition.Extraction extraction,bpsh.journey.HttpAuthentication.Protocol httpProtocol,
            java.util.List<bpsh.authentication.http.HttpAuthenticationEvidence> observations) {
        this.httpObservations=java.util.List.copyOf(observations);
        this.httpProtocol = httpProtocol;
        if (version < 1) throw new IllegalArgumentException("Invalid token version.");
        this.identity = Objects.requireNonNull(identity); this.version = version;
        this.value = Objects.requireNonNull(value); this.lifetime = Objects.requireNonNull(lifetime);
        this.cookies = java.util.Map.copyOf(cookies); this.namedTokens = java.util.Map.copyOf(namedTokens);
        this.extraction = extraction;
    }
    /** @return Sources associated with the captured values, or null for a caller without source metadata. */
    public JourneyDefinition.Extraction extraction() { return extraction; }
    /** @return Immutable values for request insertion or explicit cache inspection, never diagnostic output. */
    public java.util.Map<String, String> namedTokens() { return namedTokens; }
    /** @return Cookie values for request insertion or explicit cache inspection, never diagnostic output. */
    public java.util.Map<String, String> cookies() { return cookies; }

    /**
     * Returns the exact scoped journey generation permitted to use this snapshot.
     *
     * @return Exact scoped journey generation permitted to use this snapshot.
     */
    public JourneyDefinition.Identity identity() { return identity; }
    /**
     * Returns unique coordinator version used for precise response invalidation.
     *
     * @return Unique coordinator version used for precise response invalidation.
     */
    public long version() { return version; }
    /**
     * Returns token text for deliberate insertion or explicit cache inspection, never general logging or export.
     *
     * @return Token text for deliberate insertion or explicit cache inspection, never general logging or export.
     */
    public String value() { return value; }
    /**
     * Returns token-free immutable scheduling metadata.
     *
     * @return Token-free immutable scheduling metadata.
     */
    public TokenLifetime.Window lifetime() { return lifetime; }

    /**
     * Reuses captured values under an edited configuration without extending their acquired lifetime.
     * Exact selectors associate renamed/reordered retained outputs; a newly required source needs a fresh login.
     * @param current New generation of the same scoped journey.
     * @param previous Sources associated with the captured values.
     * @param replacement New selection to satisfy from those values.
     * @return Rebound snapshot, or null when the new complete selection cannot be satisfied unambiguously.
     */
    public TokenSnapshot reconfigure(JourneyDefinition.Identity current, JourneyDefinition.Extraction previous,
            JourneyDefinition.Extraction replacement) {
        var old = selections(previous); var selected = selections(replacement);
        if (selected.isEmpty()) return null;
        var named = new java.util.LinkedHashMap<String, String>(); var retainedCookies = new java.util.LinkedHashMap<String, String>();
        String primary = null, first = null;
        for (var target : selected) {
            String captured = null;
            for (var source : old) if (source.selector().equals(target.selector())) {
                String candidate = source.name() == null ? value : namedTokens.get(source.name());
                if (candidate == null || captured != null && !captured.equals(candidate)) return null;
                captured = candidate;
            }
            if (captured == null) return null;
            if (first == null) first = captured;
            if (target.name() != null) named.put(target.name(), captured);
            if (target.selector() instanceof JourneyDefinition.CookieExtraction cookie) retainedCookies.put(cookie.name(), captured);
            else if (primary == null) primary = captured;
        }
        return new TokenSnapshot(current, version, primary == null ? first : primary, lifetime, retainedCookies, named, replacement,httpProtocol,httpObservations);
    }

    public TokenSnapshot withoutHttpObservations() {
        return new TokenSnapshot(identity,version,value,lifetime,cookies,namedTokens,extraction,null,java.util.List.of());
    }

    private static java.util.List<JourneyDefinition.NamedExtraction> selections(JourneyDefinition.Extraction extraction) {
        return extraction instanceof JourneyDefinition.CombinedExtraction combined ? combined.tokens()
                : java.util.List.of(new JourneyDefinition.NamedExtraction(null, extraction));
    }

    /**
     * Applies both hard-expiry clocks without consulting a mutable browser or cache entry.
     * @param nowNanos Current monotonic reading.
     * @param now Current wall-clock instant.
     * @return True only while the acquired window remains usable.
     */
    public boolean usable(long nowNanos, Instant now) { return lifetime.usable(nowNanos, now); }

    /**
     * Returns identity and version only; token contents are intentionally excluded.
     *
     * @return Identity and version only; token contents are intentionally excluded.
     */
    @Override public String toString() { return "TokenSnapshot[identity=" + identity + ", version=" + version + "]"; }
}
