package bpsh.browser;

import bpsh.model.AuthenticationFailure;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;

/**
 * Marks owned proxied browser attempts and keeps global/Proxy response provenance independent.
 *
 * The opaque suffix avoids recursion; it is deliberately not an application-authentication
 * security boundary. A copied active marker can suppress this extension's handling. Values are
 * never persisted/exported/logged and expire when their attempt lease closes.
 */
public final class AuthTrafficGuard implements AutoCloseable {
    private static final String PRODUCT = "BPSHAuth/";
    private static final Pattern RESERVED = Pattern.compile("(?:^|\\s)(?i:BPSHAuth)/([^\\s]*)");
    private static final long RETENTION_MS = 300_000;
    private static final int MAX_IDS = 10_000;
    private final Set<String> active = ConcurrentHashMap.newKeySet();
    private final Set<String> replay = ConcurrentHashMap.newKeySet();
    private final Ledger global, proxy;
    private volatile boolean closed;

    /** Names independent ID spaces; equal numeric IDs across hooks must never alias each other. */
    public enum Family { GLOBAL, PROXY }
    /** Distinguishes ordinary traffic, validated ownership and reserved-but-invalid suffixes. */
    public enum Classification { NORMAL, OWNED, INVALID }

    /**
     * Reports classification and the exact agent after removing only a valid appended suffix.
     * @param classification Ownership disposition.
     * @param userAgent Clean original agent for OWNED, original input otherwise.
     * @param failure Safe guidance for INVALID, otherwise null.
     */
    public record Decision(Classification classification, String userAgent, AuthenticationFailure failure, String replayKey) {
        public Decision(Classification classification, String userAgent, AuthenticationFailure failure) { this(classification, userAgent, failure, null); }
        /**
         * Returns classification only; diagnostic output never reproduces a reserved nonce.
         *
         * @return Classification only; diagnostic output never reproduces a reserved nonce.
         */
        @Override public String toString() { return "AuthTrafficDecision[" + classification + "]"; }
    }

    /**
     * Owns one random marker from actual browser attempt start through deterministic cleanup.
     * Instances expose decoration only; toString does not disclose marker material.
     */
    public final class Lease implements AutoCloseable {
        private final String nonce;
        private boolean released;
        /**
         * Binds a newly registered marker to its owning guard; closing it revokes active ownership.
         *
         * @param nonce Fresh unpadded 32-byte random marker registered by its enclosing guard.
         */
        private Lease(String nonce) { this.nonce = nonce; }

        /**
         * Adds the marker while preserving an existing full/custom agent exactly.
         * @param agent Actual default/context/request User-Agent, without another attempt's suffix.
         * @return Agent carrying exactly this active lease's suffix.
         * @throws AuthenticationFailure If the lease is stale or a reserved suffix is ambiguous/unowned.
         */
        public String decorate(String agent) throws AuthenticationFailure {
            if (released || closed || !active.contains(nonce)) throw invalid();
            String base = agent == null ? "" : agent; var matcher = RESERVED.matcher(base);
            if (matcher.find()) {
                String found = matcher.group(1); int end = matcher.end();
                if (end == base.length() && found.equals(nonce) && !matcher.find()) return base;
                throw invalid();
            }
            return base + " " + PRODUCT + nonce;
        }
        /** Removes active ownership; late/stale requests carrying this suffix must stop. */
        @Override public void close() { released = true; active.remove(nonce); replay.remove(nonce); }
        public String key() { return nonce; }
        /**
         * Returns fixed safe lease label.
         *
         * @return Fixed safe lease label.
         */
        @Override public String toString() { return "AuthTrafficLease[redacted]"; }
    }

    /** Creates bounded ledgers using the real wall clock for five-minute provenance retention. */
    public AuthTrafficGuard() { this(System::currentTimeMillis); }

    /**
     * Creates independent bounded provenance ledgers with the supplied retention clock.
     *
     * @param clock Deterministic millisecond clock used only for provenance expiry tests.
     */
    AuthTrafficGuard(LongSupplier clock) { global = new Ledger(clock); proxy = new Ledger(clock); }

    /**
     * Registers 32 random bytes for an actual proxied authentication attempt.
     * @return Caller-owned lease to close after browser/proxy cleanup.
     * @throws AuthenticationFailure If extension shutdown already revoked ownership.
     */
    public Lease begin() throws AuthenticationFailure { return begin(false); }
    /** Marks one extension-generated application replay without granting authentication self-traffic privileges. */
    public Lease beginReplay() throws AuthenticationFailure { return begin(true); }
    private Lease begin(boolean replayRequest) throws AuthenticationFailure {
        if (closed) throw invalid();
        byte[] bytes = new byte[32]; String nonce;
        do { new SecureRandom().nextBytes(bytes); nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); } while (!active.add(nonce));
        if (replayRequest) replay.add(nonce);
        if (closed) { active.remove(nonce); replay.remove(nonce); throw invalid(); }
        return new Lease(nonce);
    }

    /**
     * Classifies a request before tags/scope/injection and records valid ownership in one hook family.
     * @param agent Original User-Agent, or null.
     * @param family Independent hook-ID namespace.
     * @param id Host message ID used later to suppress that hook's response handling.
     * @return Clean agent for global forwarding; Proxy callers retain their original suffix until global send.
     */
    public Decision classify(String agent, Family family, long id) {
        if (agent == null) return new Decision(Classification.NORMAL, null, null);
        var matcher = RESERVED.matcher(agent); if (!matcher.find()) return new Decision(Classification.NORMAL, agent, null);
        String nonce = matcher.group(1); int start = matcher.start(), end = matcher.end();
        if (closed || end != agent.length() || matcher.find() || !nonce.matches("[A-Za-z0-9_-]{43}") || !active.contains(nonce))
            return new Decision(Classification.INVALID, agent, invalid());
        if (replay.contains(nonce)) return new Decision(Classification.OWNED, agent.substring(0, start), null, nonce);
        (family == Family.GLOBAL ? global : proxy).add(id);
        return new Decision(Classification.OWNED, agent.substring(0, start), null);
    }

    /**
     * Consumes only the matching hook family's retained response ownership entry.
     * @param family Global or Proxy ID namespace.
     * @param id Response-correlated message ID from that same hook family.
     * @return True for an unexpired owned request, false for unknown/expired/evicted IDs.
     */
    public boolean consumeResponse(Family family, long id) { return (family == Family.GLOBAL ? global : proxy).consume(id); }

    /**
     * Detects reserved native syntax on internal auth traffic without resolving it or logging contents.
     * @param value URL, header value or text body inspected by the caller.
     * @return True for a native tag/wrapper prefix that internal requests must not execute.
     */
    public static boolean containsNativeTag(String value) { return value != null && value.contains("<@"); }

    /**
     * Builds a reserved-suffix error without echoing the unknown, expired or copied marker.
     * @return Terminal configuration failure with explicit Retry/remove-suffix guidance.
     */
    private static AuthenticationFailure invalid() {
        return new AuthenticationFailure(AuthenticationFailure.Phase.LIFECYCLE, AuthenticationFailure.Cause.CONFIGURATION,
                "The request has an invalid or expired BPSHAuth marker in its User-Agent header.", "Retry the journey. For a manually edited request, remove the BPSHAuth marker before resending.");
    }

    /** Stores only IDs/expiry, never requests, headers, marker values or credentials. */
    private static final class Ledger {
        private final LongSupplier clock;
        private final LinkedHashMap<Long, Long> ids = new LinkedHashMap<>();
        private long observedTime = Long.MIN_VALUE;
        /**
         * Creates an insertion-ordered ledger whose IDs are scoped to one host hook family.
         *
         * @param clock Millisecond retention clock.
         */
        Ledger(LongSupplier clock) { this.clock = clock; }
        /**
         * Records or renews an owned request and evicts the oldest entry at the fixed capacity.
         *
         * @param id Owned request ID; oldest entries are evicted at the fixed cap.
         */
        synchronized void add(long id) { prune(); ids.remove(id); ids.put(id, observedTime); while (ids.size() > MAX_IDS) ids.pollFirstEntry(); }
        /**
         * Expires old entries and consumes a matching response attribution at most once.
         *
         * @param id Same-family response ID.
         * @return Whether an unexpired entry was consumed.
         */
        synchronized boolean consume(long id) { prune(); return ids.remove(id) != null; }
        /** Removes expired or rollback-ambiguous entries before admission/lookups. */
        private void prune() {
            long now = clock.getAsLong();
            if (now < observedTime) ids.clear();
            observedTime = now;
            while (!ids.isEmpty() && now - ids.firstEntry().getValue() >= RETENTION_MS) ids.pollFirstEntry();
        }
        /** Revokes every outstanding response attribution during unload. */
        synchronized void clear() { ids.clear(); }
    }

    /** Revokes active attempts and both response ledgers without changing Burp interception settings. */
    @Override public void close() { closed = true; active.clear(); replay.clear(); global.clear(); proxy.clear(); }
}
