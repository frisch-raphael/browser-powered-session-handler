import java.time.Instant;
import java.util.Objects;

/** Holds one immutable, versioned credential; diagnostic representations never disclose its value. */
public final class TokenSnapshot {
    private final JourneyDefinition.Identity identity;
    private final long version;
    private final String value;
    private final TokenLifetime.Window lifetime;
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
        if (version < 1) throw new IllegalArgumentException("Invalid token version.");
        this.identity = Objects.requireNonNull(identity); this.version = version;
        this.value = Objects.requireNonNull(value); this.lifetime = Objects.requireNonNull(lifetime);
        this.cookies = java.util.Map.copyOf(cookies); this.namedTokens = java.util.Map.copyOf(namedTokens);
    }
    /** @return Immutable values for request insertion or explicit cache inspection, never diagnostic output. */
    public java.util.Map<String, String> namedTokens() { return namedTokens; }
    /** @return Cookie values for request insertion or explicit cache inspection, never diagnostic output. */
    public java.util.Map<String, String> cookies() { return cookies; }

    /**
     * Returns exact scoped journey generation that produced this snapshot.
     *
     * @return Exact scoped journey generation that produced this snapshot.
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
