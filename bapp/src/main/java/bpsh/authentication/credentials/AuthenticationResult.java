package bpsh.authentication.credentials;

import bpsh.journey.JourneyDefinition;
import java.time.Instant;
import java.util.Map;

/**
 * Carries a deliberate token result without making diagnostic output disclose it.
 * @param identity Configuration generation used by the attempt; caller rechecks before publication.
 * @param token Normalized extracted text for explicit use by the coordinator.
 * @param acquiredAt Wall time at successful completion.
 * @param acquiredNanos Monotonic acquisition time, so cleanup cannot extend the cache's maximum age.
 * @param cookies Configured cookie values, never diagnostic output.
 * @param namedTokens All user-named credentials used by explicit request tags.
 * @param expiresAt Earliest cookie/JWT expiry across the complete result.
 * @param skippedSteps Actions not started because all configured credentials were already captured.
 */
public record AuthenticationResult(JourneyDefinition.Identity identity, String token, Instant acquiredAt, long acquiredNanos,
                      Map<String, String> cookies, Map<String, String> namedTokens, java.util.OptionalLong expiresAt, int skippedSteps, bpsh.journey.HttpAuthentication.Protocol httpProtocol,java.util.List<bpsh.authentication.http.HttpAuthenticationEvidence> httpObservations) {
    public AuthenticationResult(JourneyDefinition.Identity identity,String token,Instant acquiredAt,long acquiredNanos,Map<String,String> cookies,
            Map<String,String> namedTokens,java.util.OptionalLong expiresAt,int skippedSteps,bpsh.journey.HttpAuthentication.Protocol httpProtocol) {
        this(identity,token,acquiredAt,acquiredNanos,cookies,namedTokens,expiresAt,skippedSteps,httpProtocol,java.util.List.of());
    }
    public AuthenticationResult(JourneyDefinition.Identity identity, String token, Instant acquiredAt, long acquiredNanos, Map<String,String> cookies, Map<String,String> namedTokens, java.util.OptionalLong expiresAt, int skippedSteps) {
        this(identity, token, acquiredAt, acquiredNanos, cookies, namedTokens, expiresAt, skippedSteps, null);
    }
    /** Defensively copies the complete credential set without exposing values in diagnostics. */
    public AuthenticationResult { cookies = Map.copyOf(cookies); namedTokens = Map.copyOf(namedTokens);httpObservations=java.util.List.copyOf(httpObservations); }
    /** Keeps adapters without execution metadata source-compatible. */
    public AuthenticationResult(JourneyDefinition.Identity identity, String token, Instant acquiredAt, long acquiredNanos,
                   Map<String, String> cookies, Map<String, String> namedTokens, java.util.OptionalLong expiresAt) {
        this(identity, token, acquiredAt, acquiredNanos, cookies, namedTokens, expiresAt, 0);
    }
    /**
     * Retains the single-token constructor for adapters with no additional cookie result.
     * @param identity Exact journey generation.
     * @param token Primary credential.
     * @param acquiredAt Acquisition wall clock.
     * @param acquiredNanos Acquisition monotonic clock.
     */
    public AuthenticationResult(JourneyDefinition.Identity identity, String token, Instant acquiredAt, long acquiredNanos) { this(identity, token, acquiredAt, acquiredNanos, Map.of(), Map.of(), java.util.OptionalLong.empty()); }
    /**
     * Returns identity-only diagnostics; no token or browser state.
     *
     * @return Identity-only diagnostics; no token or browser state.
     */
    @Override public String toString() { return "AuthenticationOutcome[identity=" + identity + "]"; }
}
