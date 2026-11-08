package bpsh.journey;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/** Defines native step kinds and stable-ID immutable configuration, without secret values. */
public final class AuthStep {
    public static final String DEFAULT_LOAD_STATE = "load";
    public static final List<String> LOAD_STATES = List.of(
            DEFAULT_LOAD_STATE, "domcontentloaded", "networkidle");
    public static final List<String> ELEMENT_STATES = List.of("visible", "hidden", "attached", "detached");
    public static final List<String> URL_MATCHES = List.of("exact", "glob");
    public static final List<String> KEYS = List.of("Enter", "Control+Enter", "Tab", "Shift+Tab");

    /**
     * Lists exact native step kinds; each wire spelling has its own permitted field set.
     */
    public enum Type {
        CLICK("click"), INPUT("input"), SECURE_INPUT("secure_input"), WAIT_LOAD_STATE("wait_load_state"),
        WAIT_URL("wait_url"), WAIT_TIME("wait_time"), WAIT_SELECTOR("wait_selector"),
        SET_CHECKED("set_checked"), SELECT_OPTIONS("select_options"), PRESS_KEY("press_key"),
        EXPECT_POPUP("expect_popup"), SWITCH_PAGE("switch_page"), CLOSE_PAGE("close_page"),
        ENTER_FRAME("enter_frame"), PARENT_FRAME("parent_frame"), MAIN_FRAME("main_frame");
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
        public String wire() { return wire; }
        /** @return Consistent safe action name for the editor and runtime feedback. */
        public String label() {
            return switch (this) {
                case CLICK -> "Click element"; case INPUT -> "Fill field"; case SECURE_INPUT -> "Enter secret";
                case WAIT_LOAD_STATE -> "Wait for page load"; case WAIT_URL -> "Wait for URL";
                case WAIT_TIME -> "Wait for duration"; case WAIT_SELECTOR -> "Wait for element";
                case SET_CHECKED -> "Set checkbox or radio"; case SELECT_OPTIONS -> "Choose dropdown options";
                case PRESS_KEY -> "Press key"; case EXPECT_POPUP -> "Expect popup"; case SWITCH_PAGE -> "Switch page";
                case ENTER_FRAME -> "Enter frame"; case PARENT_FRAME -> "Leave frame";
                case MAIN_FRAME -> "Leave all frames"; case CLOSE_PAGE -> "Close page";
            };
        }

        /**
         * Compares a candidate with the fixed supported wire spelling rather than applying a fallback.
         *
         * @param value Candidate native step discriminator.
         * @return Whether the exact supported spelling matches.
         */
        public boolean matches(String value) { return wire.equals(value); }

        /**
         * Returns whether this kind owns a CSS selector in both the immutable model and visible editor.
         *
         * @return Whether this kind owns a CSS selector in both the immutable model and visible editor.
         */
        public boolean requiresSelector() {
            return switch (this) {
                case CLICK, INPUT, SECURE_INPUT, WAIT_SELECTOR, SET_CHECKED, SELECT_OPTIONS, PRESS_KEY, ENTER_FRAME -> true;
                default -> false;
            };
        }

        /**
         * Returns whether the step fills ordinary text or a separately owned secure-input value.
         *
         * @return Whether the step fills ordinary text or a separately owned secure-input value.
         */
        public boolean requiresInputValue() { return this == INPUT || this == SECURE_INPUT; }

        /**
         * Finds a supported step kind without accepting or normalizing an unknown discriminator.
         *
         * @param value Exact case-sensitive native discriminator.
         * @return Supported kind, with no fallback for an unknown step.
         */
        public static Optional<Type> fromWire(String value) {
            return Arrays.stream(values()).filter(type -> type.matches(value)).findFirst();
        }
    }

    /** Immutable, operation-specific configuration; secret text never belongs here. */
    public sealed interface Operation permits Checked, Options, Key, Popup, PageTarget, Context {}
    /** Desired control state, rather than a toggle. */
    public record Checked(boolean checked) implements Operation {}
    /** Exact native option values, including an empty list or an empty option value. */
    public record Options(List<String> values) implements Operation {
        public Options { values = List.copyOf(values); }
        @Override public String toString() { return "Options[count=" + values.size() + "]"; }
    }
    /** Supported submission or focus-navigation gesture. */
    public record Key(String key) implements Operation {
        public Key { if (!KEYS.contains(key)) throw new IllegalArgumentException("Unsupported key."); }
    }
    /** Journey-local popup declaration and its immediately following trigger. */
    public record Popup(String pageRef, java.util.UUID triggerStepId) implements Operation {
        public Popup { java.util.Objects.requireNonNull(pageRef); java.util.Objects.requireNonNull(triggerStepId); }
        @Override public String toString() { return "Popup[reference]"; }
    }
    /** Journey-local page selection; never a browser handle or URL. */
    public record PageTarget(String pageRef) implements Operation {
        public PageTarget { java.util.Objects.requireNonNull(pageRef); }
        @Override public String toString() { return "PageTarget[reference]"; }
    }
    /** Context operation without additional persisted fields. */
    public record Context() implements Operation {}

    /** @return Type-compatible placeholders for structural ownership and empty editor rows only. */
    public static Operation defaultOperation(Type type, java.util.UUID id) {
        return switch (type) {
            case SET_CHECKED -> new Checked(false); case SELECT_OPTIONS -> new Options(List.of());
            case PRESS_KEY -> new Key("Enter"); case EXPECT_POPUP -> new Popup("", id);
            case SWITCH_PAGE -> new PageTarget("");
            case ENTER_FRAME, PARENT_FRAME, MAIN_FRAME, CLOSE_PAGE -> new Context();
            default -> null;
        };
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
    public record Definition(java.util.UUID id, Type type, String selector, String value,
                      String state, String urlPattern, Integer durationMs, Operation operation) {
        /**
         * Requires step identity and kind; type-specific semantic validation belongs to the codec.
         */
        public Definition {
            java.util.Objects.requireNonNull(id); java.util.Objects.requireNonNull(type);
            var expected = defaultOperation(type, id);
            if (expected == null ? operation != null : operation == null || expected.getClass() != operation.getClass())
                throw new IllegalArgumentException("Step operation does not match its type.");
        }
        /** Retains the existing constructor for legacy callers and structural editor rows. */
        public Definition(java.util.UUID id, Type type, String selector, String value, String state, String urlPattern, Integer durationMs) {
            this(id, type, selector, value, state, urlPattern, durationMs, defaultOperation(type, id));
        }
        /**
         * Copies the step under an explicitly supplied destination UUID without accessing secrets.
         *
         * @param newId Fresh ID chosen for a duplicate or imported step.
         * @return A new step with unchanged nonsecret configuration.
         */
        public Definition withId(java.util.UUID newId) {
            return new Definition(newId, type, selector, value, state, urlPattern, durationMs, operation);
        }
        /** Allocates identity and trigger references together after the complete destination map exists. */
        public Definition remap(java.util.Map<java.util.UUID, java.util.UUID> ids) {
            var payload = operation instanceof Popup popup
                    ? new Popup(popup.pageRef(), ids.getOrDefault(popup.triggerStepId(), popup.triggerStepId())) : operation;
            return new Definition(ids.getOrDefault(id, id), type, selector, value, state, urlPattern, durationMs, payload);
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
