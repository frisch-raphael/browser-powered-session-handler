package bpsh.authentication.credentials;

import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.JourneyDefinition;
import java.time.Clock;
import java.time.Instant;
import java.util.OptionalLong;
import java.util.concurrent.TimeUnit;

/** Computes finite token lifetime from monotonic age and optional, untrusted JWT expiry metadata. */
public final class TokenLifetime {
    /** Prevents instances of the stateless lifetime policy. */
    private TokenLifetime() {}

    /**
     * Describes immutable deadlines relative to the original acquisition, without token contents.
     * @param acquiredAt Original wall-clock acquisition instant.
     * @param acquiredNanos Original monotonic acquisition time.
     * @param usableNanos Acquired usable lifetime; cannot exceed the finite maximum age.
     * @param refreshNanos Age at which proactive refresh is due, with skew capped at half the lifetime.
     * @param jwtExpiry Optional epoch seconds read as metadata, never signature validation.
     */
    public record Window(Instant acquiredAt, long acquiredNanos, long usableNanos, long refreshNanos, OptionalLong jwtExpiry) {
        /**
         * Rechecks both independent expiry clocks; a wall-clock rollback never extends acquired age.
         * @param nowNanos Current monotonic reading from the same clock domain.
         * @param now Current wall clock.
         * @return Whether the token is still usable at this observation.
         */
        public boolean usable(long nowNanos, Instant now) {
            long age = nowNanos - acquiredNanos;
            return age >= 0 && age < usableNanos && (jwtExpiry.isEmpty() || now.getEpochSecond() < jwtExpiry.getAsLong());
        }

        /**
         * Computes one refresh delay without granting more lifetime after a clock adjustment.
         * @param nowNanos Current monotonic reading.
         * @param now Current wall clock.
         * @return Nonnegative nanoseconds until refresh, or zero when already due/expired.
         */
        public long refreshDelay(long nowNanos, Instant now) {
            long age = nowNanos - acquiredNanos;
            if (age < 0 || !usable(nowNanos, now)) return 0;
            long delay = Math.max(0, refreshNanos - age);
            if (jwtExpiry.isPresent()) {
                long untilExpiry = remainingJwtNanos(jwtExpiry.getAsLong(), now);
                long skew = usableNanos - refreshNanos;
                delay = Math.min(delay, Math.max(0, untilExpiry - skew));
            }
            return delay;
        }
    }

    /**
     * Validates normalized token text and captures scheduling metadata for a newly acquired result.
     * @param token Result supplied deliberately by the browser worker.
     * @param policy Validated finite cache-age/refresh-skew policy.
     * @param now Wall-clock acquisition instant.
     * @param nowNanos Monotonic acquisition instant.
     * @return Acquired immutable lifetime window.
     * @throws AuthenticationFailure If the result is invalid or already expired.
     */
    public static Window acquire(String token, JourneyDefinition.Cache policy, Instant now, long nowNanos) throws AuthenticationFailure {
        return acquire(token, policy, now, nowNanos, OptionalLong.empty());
    }
    /**
     * Limits the whole credential set by its earliest observed cookie/JWT expiry.
     * @param token Primary token.
     * @param policy Finite cache policy.
     * @param now Acquisition wall clock.
     * @param nowNanos Acquisition monotonic clock.
     * @param credentialExpiry Earliest additional credential expiry, if available.
     * @return Shared expiry window for all acquired credentials.
     * @throws AuthenticationFailure If any credential is already expired.
     */
    public static Window acquire(String token, JourneyDefinition.Cache policy, Instant now, long nowNanos, OptionalLong credentialExpiry) throws AuthenticationFailure {
        if (policy.maxAgeSeconds() < 5 || policy.maxAgeSeconds() > 86_400 || policy.refreshSkewSeconds() < 0 || policy.refreshSkewSeconds() > 3600)
            throw new IllegalArgumentException("Invalid finite token lifetime policy.");
        String normalized = TokenExtractor.normalize(token, Clock.fixed(now, java.time.ZoneOffset.UTC));
        OptionalLong exp = TokenExtractor.jwtExpiry(normalized);
        if (credentialExpiry.isPresent()) exp = OptionalLong.of(exp.isPresent() ? Math.min(exp.getAsLong(), credentialExpiry.getAsLong()) : credentialExpiry.getAsLong());
        long lifetime = TimeUnit.SECONDS.toNanos(policy.maxAgeSeconds());
        if (exp.isPresent()) lifetime = Math.min(lifetime, remainingJwtNanos(exp.getAsLong(), now));
        if (lifetime <= 0) throw new AuthenticationFailure(AuthenticationFailure.Phase.EXTRACTION, AuthenticationFailure.Cause.TOKEN_EXPIRED,
                "The login returned an expired token.", "");
        long skew = Math.min(TimeUnit.SECONDS.toNanos(policy.refreshSkewSeconds()), lifetime / 2);
        return new Window(now, nowNanos, lifetime, lifetime - skew, exp);
    }

    /**
     * Bounds JWT wall-clock distance without overflowing on adversarial integral exp metadata.
     * @param expiry Integral epoch seconds from the bounded JWT payload.
     * @param now Current wall time.
     * @return Remaining nanoseconds saturated at the maximum configured cache lifetime.
     */
    private static long remainingJwtNanos(long expiry, Instant now) {
        if (expiry <= now.getEpochSecond()) return 0;
        long seconds;
        try { seconds = Math.subtractExact(expiry, now.getEpochSecond()); }
        catch (ArithmeticException ex) { return TimeUnit.DAYS.toNanos(1); }
        if (seconds > 86_400) return TimeUnit.DAYS.toNanos(1);
        return Math.max(0, TimeUnit.SECONDS.toNanos(seconds) - now.getNano());
    }
}
