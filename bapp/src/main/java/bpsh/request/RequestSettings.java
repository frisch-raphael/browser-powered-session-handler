package bpsh.request;

import bpsh.journey.JourneyDefinition;

import java.util.List;

/** Defines immutable native project controls; journey definitions and secret values are stored separately. */
public final class RequestSettings {
    /** Prevents the former mutable configuration object from being instantiated after native cutover. */
    private RequestSettings() {}
    /** Automatic handling behavior when a credential is unavailable; explicit tags always wait. */
    public enum RequestPolicy {
        WAIT_FOR_LOGIN, DO_NOT_WAIT;
        /** Returns the operator-facing label even when Burp replaces Swing renderers. */
        @Override public String toString() { return this == DO_NOT_WAIT ? "Send immediately" : "Wait for login"; }
    }

    /** Host-independent eligible request origins; wire names match the native document format. */
    public enum Tool { SCANNER, PROXY, REPEATER, EXTENSIONS, INTRUDER }
    public static final List<Tool> SUPPORTED_TOOLS = List.of(Tool.SCANNER, Tool.PROXY,
            Tool.REPEATER, Tool.EXTENSIONS, Tool.INTRUDER);

    /** One typed URL restriction; matching and regex compilation belong to concrete boundaries. */
    public sealed interface UrlCondition permits AllRequests, BurpScope, Prefix, Regex {}
    /** Matches every URL without reading a host URL helper. */
    public record AllRequests() implements UrlCondition {}
    /** Matches the host's current target scope. */
    public record BurpScope() implements UrlCondition {}
    /** @param value Absolute HTTP(S) URL matched as a literal prefix. */
    public record Prefix(java.net.URI value) implements UrlCondition {
        /** Validates only JDK URL structure; preserves the exact supplied spelling. */
        public Prefix {
            java.util.Objects.requireNonNull(value);
            if (!java.util.Set.of("http", "https").contains(value.getScheme()) || value.getHost() == null
                    || value.getUserInfo() != null || value.getPort() < -1 || value.getPort() == 0 || value.getPort() > 65535)
                throw new IllegalArgumentException("Enter an absolute HTTP(S) URL prefix without embedded credentials.");
        }
    }
    /** @param value RE2 source; concrete persistence/runtime boundaries validate grammar and bounds. */
    public record Regex(String value) implements UrlCondition {
        /** Requires a value without introducing a third-party compiler into domain contracts. */
        public Regex { java.util.Objects.requireNonNull(value); }
    }

    /** Names the supported native extraction discriminators. */
    public enum ExtractionType {
        JSON_PATH("json_path"), REGEX("regex"), COOKIE("cookie"), COMBINED("combined");

        private final String wire;

        /**
         * Binds a supported extraction kind to its exact native discriminator without migration coercion.
         *
         * @param wire Fixed native extraction discriminator; no migration or coercion is performed.
         */
        ExtractionType(String wire) { this.wire = wire; }

        /**
         * Returns exact JSON-response or cookie extraction wire spelling.
         *
         * @return Exact JSON-response or cookie extraction wire spelling.
         */
        public String wire() { return wire; }

        /**
         * Compares a candidate with the fixed supported wire spelling rather than applying a fallback.
         *
         * @param value Candidate native extraction discriminator.
         * @return Whether the exact supported spelling matches.
         */
        public boolean matches(String value) { return wire.equals(value); }
    }

    /**
     * Selects an ordinary-injection journey by scoped UUID without an implicit fallback.
     *
     * @param scope Project or library ownership boundary.
     * @param id Stable journey UUID; existence/availability is checked by the registry.
     */
    public record JourneySelection(JourneyDefinition.Scope scope, java.util.UUID id) {}
    /**
     * One ordered automatic-authentication rule; later matching rules overwrite earlier destinations.
     * @param enabled Whether this rule participates without removing its configuration.
     * @param journey Explicit saved scoped identity.
     * @param url Typed URL eligibility for this rule.
     * @param proxyPort Incoming Proxy listener port, or null for any listener.
     * @param recovery Response-based expiration detection attributed to this rule's used token version.
     */
    public record AutomaticRule(boolean enabled, JourneySelection journey, UrlCondition url,
                                Integer proxyPort, JourneyDefinition.Recovery recovery) {
        /** Rejects incomplete domain values and invalid incoming ports before publication. */
        public AutomaticRule {
            java.util.Objects.requireNonNull(journey); java.util.Objects.requireNonNull(url); java.util.Objects.requireNonNull(recovery);
            if (proxyPort != null && (proxyPort < 1 || proxyPort > 65535))
                throw new IllegalArgumentException("Proxy port must be an integer from 1 through 65535.");
        }
    }

    /**
     * Immutable ordered rules, eligible tools and shared finite authentication budgets.
     * @param enabled Master automatic-injection switch; explicit tags remain independent.
     * @param rules User-ordered automatic rules, including disabled rows.
     * @param tools Eligible Burp tools.
     * @param requestWaitTimeoutMs One request deadline across all matching journeys.
     * @param attemptTimeoutMs Per-attempt budget.
     * @param cycleTimeoutMs Per-journey cycle budget.
     * @param maxWaitingRequestsGlobal Global finite request limit; null selects the default.
     * @param maxWaitingRequestsPerJourney Per-journey finite request limit; null selects the default.
     * @param requestPolicy Whether automatic requests wait for authentication or continue unchanged.
     */
    public record Controls(boolean enabled, List<AutomaticRule> rules, List<Tool> tools, int requestWaitTimeoutMs,
                           int attemptTimeoutMs, int cycleTimeoutMs, Integer maxWaitingRequestsGlobal,
                           Integer maxWaitingRequestsPerJourney, RequestPolicy requestPolicy) implements bpsh.authentication.AuthenticationPolicy {
        /**
         * Copies the eligible tool list so later editor changes cannot mutate published controls.
         */
        /** Creates controls with the default bounded waiting policy. */
        public Controls(boolean enabled, List<AutomaticRule> rules, List<Tool> tools, int requestWaitTimeoutMs,
                        int attemptTimeoutMs, int cycleTimeoutMs, Integer maxWaitingRequestsGlobal, Integer maxWaitingRequestsPerJourney) {
            this(enabled, rules, tools, requestWaitTimeoutMs, attemptTimeoutMs, cycleTimeoutMs, maxWaitingRequestsGlobal, maxWaitingRequestsPerJourney, RequestPolicy.WAIT_FOR_LOGIN);
        }
        public Controls {
            maxWaitingRequestsGlobal = maxWaitingRequestsGlobal == null ? 64 : maxWaitingRequestsGlobal;
            maxWaitingRequestsPerJourney = maxWaitingRequestsPerJourney == null ? 16 : maxWaitingRequestsPerJourney;
            if (maxWaitingRequestsGlobal < 1 || maxWaitingRequestsPerJourney < 1) throw new IllegalArgumentException("Request limits must be positive integers.");
            java.util.Objects.requireNonNull(requestPolicy); rules = List.copyOf(rules); tools = List.copyOf(tools); }
        /**
         * Creates native controls with ordinary injection off and no selected journey.
         *
         * @return Default supported tools, Burp scope, finite deadlines and waiter limits of 64 globally and 16 per journey.
         */
        public static Controls defaults() {
            return new Controls(false, List.of(), SUPPORTED_TOOLS,
                    60_000, 60_000, 300_000, null, null);
        }
    }

}
