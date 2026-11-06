
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/** Defines the seven native step kinds and stable-ID immutable configuration, without secret values. */
final class AuthStep {
    static final String DEFAULT_LOAD_STATE = "load";
    static final List<String> LOAD_STATES = List.of(
            DEFAULT_LOAD_STATE, "domcontentloaded", "networkidle");
    static final List<String> ELEMENT_STATES = List.of("visible", "hidden", "attached", "detached");
    static final List<String> URL_MATCHES = List.of("exact", "glob");

    /**
     * Lists exact native step kinds; each wire spelling has its own permitted field set.
     */
    enum Type {
        CLICK("click"), INPUT("input"), SECURE_INPUT("secure_input"), WAIT_LOAD_STATE("wait_load_state"),
        WAIT_URL("wait_url"), WAIT_TIME("wait_time"), WAIT_SELECTOR("wait_selector");
        /**
         * Retains the exact case-sensitive native step discriminator.
         */
        private final String wire;
        /**
         * Binds an internal step kind to its fixed native discriminator.
         *
         * @param wire Exact lowercase JSON type value.
         */
        Type(String wire) { this.wire = wire; }
        /**
         * Returns the exact native discriminator without deriving it from a display label.
         *
         * @return Supported step type spelling used by the native codec.
         */
        String wire() { return wire; }
        /** @return Consistent safe action name for the editor and runtime feedback. */
        String label() {
            return switch (this) {
                case CLICK -> "Click element"; case INPUT -> "Fill field"; case SECURE_INPUT -> "Enter secret";
                case WAIT_LOAD_STATE -> "Wait for page load"; case WAIT_URL -> "Wait for URL";
                case WAIT_TIME -> "Wait for duration"; case WAIT_SELECTOR -> "Wait for element";
            };
        }

        /**
         * Compares a candidate with the fixed supported wire spelling rather than applying a fallback.
         *
         * @param value Candidate native step discriminator.
         * @return Whether the exact supported spelling matches.
         */
        boolean matches(String value) { return wire.equals(value); }

        /**
         * Returns whether this kind owns a CSS selector in both the immutable model and visible editor.
         *
         * @return Whether this kind owns a CSS selector in both the immutable model and visible editor.
         */
        boolean requiresSelector() {
            return switch (this) {
                case CLICK, INPUT, SECURE_INPUT, WAIT_SELECTOR -> true;
                default -> false;
            };
        }

        /**
         * Returns whether the step fills ordinary text or a separately owned secure-input value.
         *
         * @return Whether the step fills ordinary text or a separately owned secure-input value.
         */
        boolean requiresInputValue() { return this == INPUT || this == SECURE_INPUT; }

        /**
         * Finds a supported step kind without accepting or normalizing an unknown discriminator.
         *
         * @param value Exact case-sensitive native discriminator.
         * @return Supported kind, with no fallback for an unknown step.
         */
        static Optional<Type> fromWire(String value) {
            return Arrays.stream(values()).filter(type -> type.matches(value)).findFirst();
        }
    }

    /**
     * Carries one immutable step with stable secret association by UUID.
     *
     * The codec enforces type-specific fields: unused members are null, secure inputs have no inline
     * value, and durations are canonical integer milliseconds. Moving a step retains its ID; copying
     * one requires a new ID and does not automatically copy its secret.
     *
     * @param id Stable step UUID within the owning journey.
     * @param type Native step kind.
     * @param selector Nonblank selector for click/input/secure_input/wait_selector, otherwise null.
     * @param value Ordinary saved input text only; secure values live in SecretStore instead.
     * @param state Load event, element condition or URL match mode for the relevant wait; null keeps legacy defaults.
     * @param urlPattern Playwright URL pattern for wait_url, otherwise null.
     * @param durationMs Integral wait_time duration, otherwise null.
     */
    record Definition(java.util.UUID id, Type type, String selector, String value,
                      String state, String urlPattern, Integer durationMs) {
        /**
         * Requires step identity and kind; type-specific semantic validation belongs to the codec.
         */
        Definition { java.util.Objects.requireNonNull(id); java.util.Objects.requireNonNull(type); }
        /**
         * Copies the step under an explicitly supplied destination UUID without accessing secrets.
         *
         * @param newId Fresh ID chosen for a duplicate or imported step.
         * @return A new step with unchanged nonsecret configuration.
         */
        Definition withId(java.util.UUID newId) {
            return new Definition(newId, type, selector, value, state, urlPattern, durationMs);
        }
        /**
         * Returns only step ID and kind, excluding selectors and ordinary input content.
         *
         * @return Safe diagnostic identity label.
         */
        @Override public String toString() { return "AuthStep[id=" + id + ", type=" + type + "]"; }
    }

    /** Prevents instances of the immutable step-definition namespace. */
    private AuthStep() {}
}
