import burp.api.montoya.core.ToolType;


import java.util.List;

/** Defines immutable native project controls; journey definitions and secret values are stored separately. */
public final class Config {
    /** Prevents the former mutable configuration object from being instantiated after native cutover. */
    private Config() {}
    static final List<ToolType> SUPPORTED_TOOLS = List.of(ToolType.SCANNER, ToolType.PROXY,
            ToolType.REPEATER, ToolType.EXTENSIONS, ToolType.INTRUDER);

    /**
     * Selects ordinary automatic-injection URL handling; native tags are independent of this scope.
     */
    public enum UrlMode {
        BURP_SCOPE("burp_scope"), ALL_REQUESTS("all_requests"), SINGLE_URL("single_url");

        private final String wire;

        /**
         * Binds an ordinary URL handling mode to its exact native project discriminator.
         *
         * @param wire Exact native project discriminator for ordinary URL handling.
         */
        UrlMode(String wire) { this.wire = wire; }

        /**
         * Returns case-sensitive native project spelling, independent of enum display names.
         *
         * @return Case-sensitive native project spelling, independent of enum display names.
         */
        public String wire() { return wire; }

        /**
         * Compares a candidate with the fixed supported wire spelling rather than applying a fallback.
         *
         * @param value Candidate native discriminator.
         * @return Whether it exactly names this ordinary URL mode.
         */
        public boolean matches(String value) { return wire.equals(value); }
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
     * @param urlMode URL eligibility for this rule.
     * @param urlPrefix Absolute HTTP(S) prefix for SINGLE_URL only.
     * @param recovery Response-based expiration detection attributed to this rule's used token version.
     */
    public record AutomaticRule(boolean enabled, JourneySelection journey, UrlMode urlMode,
                                java.net.URI urlPrefix, JourneyDefinition.Recovery recovery) {}

    /**
     * Immutable ordered rules, eligible tools and shared finite authentication budgets.
     * @param enabled Master automatic-injection switch; explicit tags remain independent.
     * @param rules User-ordered automatic rules, including disabled rows.
     * @param tools Eligible Burp tools.
     * @param requestWaitTimeoutMs One request deadline across all matching journeys.
     * @param attemptTimeoutMs Per-attempt budget.
     * @param cycleTimeoutMs Per-journey cycle budget.
     * @param maxWaitingRequestsGlobal Global waiter limit, null for Unlimited.
     * @param maxWaitingRequestsPerJourney Per-journey waiter limit, null for Unlimited.
     */
    public record Controls(boolean enabled, List<AutomaticRule> rules, List<ToolType> tools, int requestWaitTimeoutMs,
                           int attemptTimeoutMs, int cycleTimeoutMs, Integer maxWaitingRequestsGlobal,
                           Integer maxWaitingRequestsPerJourney) {
        /**
         * Copies the eligible tool list so later editor changes cannot mutate published controls.
         */
        public Controls { rules = List.copyOf(rules); tools = List.copyOf(tools); }
        /**
         * Creates native controls with ordinary injection off and no selected journey.
         *
         * @return Default supported tools, Burp scope, finite deadlines and both waiter limits Unlimited.
         */
        public static Controls defaults() {
            return new Controls(false, List.of(), SUPPORTED_TOOLS,
                    60_000, 60_000, 300_000, null, null);
        }
    }

}
