import java.time.Instant;
import java.util.Objects;
import java.util.function.BooleanSupplier;

/**
 * Carries an observed authentication outcome without retaining secret-bearing vendor exceptions.
 *
 * Callers supply safe symbolic descriptions, never raw selectors, token values, PINs or exception
 * messages. Retryability is restricted to positively classified transport/service observations;
 * the coordinator must additionally apply shared PIN-state and remaining-cycle safeguards.
 * Recovery text is optional: include an action only when the observed failure supports it.
 * Unknown failures report the error alone, without speculative troubleshooting.
 */
public final class AuthenticationFailure extends Exception {
    private static final long serialVersionUID = 1L;

    /** Identifies the operation that established the failure, rather than guessing its root cause. */
    public enum Phase { SETUP, PROVIDER, PIN, PROXY, NAVIGATION, STEP, EXTRACTION, QUEUE, LIFECYCLE }

    /** Distinguishes terminal conditions from the two positively temporary categories. */
    public enum Cause {
        CONFIGURATION, MISSING_SECRET, ASSET_MISSING, ASSET_CORRUPT, UNSUPPORTED_PLATFORM, CACHE_BUSY,
        CERTIFICATE, TRUST, PROXY_AUTH, PIN_REJECTED, PIN_INDETERMINATE, PIN_IN_PROGRESS,
        TRANSPORT, TEMPORARY_SERVICE, AUTH_REJECTED, EXTRACTION, TOKEN_EXPIRED,
        STEP_TIMEOUT, TIMEOUT, CANCELLED, CAPACITY, CLOSED, STALE, UNKNOWN
    }

    private final Phase phase;
    private final Cause reason;
    private final String problem;
    private final String recovery;
    private final Integer httpStatus;
    private final Instant retryAfter;
    private final JourneyDefinition.Identity journey;
    /** Safe stable action attribution; selectors and input values are deliberately excluded. */
    record Step(java.util.UUID id, int number, AuthStep.Type type) {}
    private final Step step;
    /** Configuration inputs identified by the failing operation, never inferred from display text. */
    enum Input { LOGIN_URL, PROXY_URL, MIDDLEWARE, SECURITY_DEVICE, MTLS_PIN, CERTIFICATE, TRUSTED_CA,
        JSON_PATH, COOKIE_FILTERS, CAPTURE_SOURCE }
    /** Safe input identity, with an optional zero-based credential row. */
    record InputTarget(Input input, Integer credential) {}
    private final InputTarget input;

    /**
     * Creates a safe failure with optional HTTP retry metadata, without attaching a raw cause.
     *
     * @param phase Operation that observed the condition.
     * @param reason Typed disposition used by the coordinator.
     * @param problem Safe explanation of what failed.
     * @param recovery Confirmed user action or retry guidance; empty when the failure supports no instruction.
     * @param httpStatus Relevant observed authentication status, or null.
     * @param retryAfter Parsed absolute retry time, or null; never an unvalidated header string.
     */
    public AuthenticationFailure(Phase phase, Cause reason, String problem, String recovery,
                                 Integer httpStatus, Instant retryAfter) {
        this(phase, reason, problem, recovery, httpStatus, retryAfter, null, null, null);
    }

    /**
     * Retains optional safe journey attribution without attaching a secret-bearing raw cause.
     * @param phase Known operation phase.
     * @param reason Classified disposition.
     * @param problem Safe description.
     * @param recovery Confirmed next action, or empty to report the error alone.
     * @param httpStatus Relevant status, or null.
     * @param retryAfter Parsed retry time, or null.
     * @param journey Exact failing generation, or null for a request-wide condition.
     */
    private AuthenticationFailure(Phase phase, Cause reason, String problem, String recovery,
                                  Integer httpStatus, Instant retryAfter, JourneyDefinition.Identity journey, Step step, InputTarget input) {
        super(message(problem, recovery));
        this.phase = Objects.requireNonNull(phase); this.reason = Objects.requireNonNull(reason); this.problem = problem;
        this.recovery = recovery; this.httpStatus = httpStatus; this.retryAfter = retryAfter; this.journey = journey;
        this.step = step;
        this.input = input;
    }

    /**
     * Creates a failure without HTTP metadata.
     * @param phase Operation that observed the condition.
     * @param reason Typed failure category.
     * @param problem Safe description, excluding raw exception text.
     * @param recovery Confirmed recovery action, or empty to report the error alone.
     */
    public AuthenticationFailure(Phase phase, Cause reason, String problem, String recovery) {
        this(phase, reason, problem, recovery, null, null);
    }

    /** @param phase Observed operation. @param reason Failure category. @param problem Known error information, without speculative advice. */
    public AuthenticationFailure(Phase phase, Cause reason, String problem) {
        this(phase, reason, problem, "");
    }

    /** @param problem Known error information. @param recovery Optional evidence-based action. @return Message without empty guidance or trailing whitespace. */
    private static String message(String problem, String recovery) {
        Objects.requireNonNull(problem);
        Objects.requireNonNull(recovery);
        return recovery.isBlank() ? problem : problem + " " + recovery;
    }

    /**
     * Returns the operation that established this failure.
     *
     * @return The operation that established this failure.
     */
    public Phase phase() { return phase; }
    /**
     * Returns safe symbolic cause; never a raw native/browser exception.
     *
     * @return Safe symbolic cause; never a raw native/browser exception.
     */
    public Cause reason() { return reason; }
    /** @return Known safe problem description without duplicated recovery instructions. */
    public String problem() { return problem; }
    /** @return Exact failing generation when known, otherwise null for a request-wide condition. */
    public JourneyDefinition.Identity journey() { return journey; }
    /**
     * Attributes an established safe outcome to its actual failed cycle, preserving classification.
     * @param identity Known failing journey generation, never guessed from the current UI selection.
     * @return Independently immutable failure with no raw exception cause.
     */
    public AuthenticationFailure forJourney(JourneyDefinition.Identity identity) { return new AuthenticationFailure(phase, reason, problem, recovery, httpStatus, retryAfter, Objects.requireNonNull(identity), step, input); }
    /** @return Safe action attribution when the failed operation is known. */
    Step step() { return step; }
    /** @param step Established action identity. @return Same failure with safe action attribution preserved. */
    AuthenticationFailure atStep(Step step) { return new AuthenticationFailure(phase, reason, problem, recovery, httpStatus, retryAfter, journey, step, input); }
    /** @return Positively identified configuration input, or null for service/lifecycle failures. */
    InputTarget input() { return input; }
    /** @param field Input established by the operation. @return Same outcome carrying no user-entered input text. */
    AuthenticationFailure atInput(Input field) { return new AuthenticationFailure(phase, reason, problem, recovery, httpStatus, retryAfter, journey, step, new InputTarget(Objects.requireNonNull(field), null)); }
    /** @param index Exact credential collector's zero-based position. @return Same failure attributed to that collector. */
    AuthenticationFailure forCredential(int index) {
        return new AuthenticationFailure(phase, reason, problem, recovery, httpStatus, retryAfter, journey, step,
                new InputTarget(input == null ? Input.CAPTURE_SOURCE : input.input(), index));
    }
    /** @param guidance Safe recovery instructions. @return Same classified outcome and attribution with updated guidance. */
    AuthenticationFailure withRecovery(String guidance) { return new AuthenticationFailure(phase, reason, problem, guidance, httpStatus, retryAfter, journey, step, input); }
    /**
     * Returns concrete correction or recovery guidance.
     *
     * @return Concrete correction or recovery guidance.
     */
    public String recovery() { return recovery; }
    /**
     * Returns relevant authentication HTTP status, or null.
     *
     * @return Relevant authentication HTTP status, or null.
     */
    public Integer httpStatus() { return httpStatus; }
    /**
     * Parses server retry guidance without changing the attempt or cycle deadline.
     *
     * @return Parsed server retry time, or null.
     */
    public Instant retryAfter() { return retryAfter; }
    /**
     * Returns whether the observation is positively temporary, before shared PIN/budget checks.
     *
     * @return Whether the observation is positively temporary, before shared PIN/budget checks.
     */
    public boolean retryable() { return reason == Cause.TRANSPORT || reason == Cause.TEMPORARY_SERVICE; }

    /**
     * Orders established failures when an attempt has several observations and no valid token.
     * @return Lower values take precedence; incidental temporary responses cannot mask PIN/trust errors.
     */
    public int priority() {
        return switch (reason) {
            case PIN_REJECTED, PIN_INDETERMINATE, PIN_IN_PROGRESS -> 0;
            case CONFIGURATION, MISSING_SECRET, ASSET_MISSING, ASSET_CORRUPT, UNSUPPORTED_PLATFORM,
                    CACHE_BUSY, CERTIFICATE, TRUST, PROXY_AUTH, AUTH_REJECTED -> 1;
            case EXTRACTION, TOKEN_EXPIRED -> 2;
            case TRANSPORT, TEMPORARY_SERVICE -> 3;
            default -> 4;
        };
    }

    /**
     * Checks cooperative cancellation and an elapsed-time deadline before another bounded operation.
     * @param phase Operation about to run.
     * @param deadlineNanos Absolute System.nanoTime deadline from the original attempt budget.
     * @param cancelled Cancellation predicate owned by the cycle/extension.
     * @throws AuthenticationFailure If cancelled/interrupted or the budget is exhausted.
     */
    static void checkpoint(Phase phase, long deadlineNanos, BooleanSupplier cancelled) throws AuthenticationFailure {
        if (Thread.currentThread().isInterrupted() || cancelled.getAsBoolean())
            throw new AuthenticationFailure(phase, Cause.CANCELLED, "Authentication was cancelled.", "Use Retry when ready.");
        if (deadlineNanos - System.nanoTime() <= 0)
            throw new AuthenticationFailure(phase, Cause.TIMEOUT, "The login attempt timed out.");
    }

    /**
     * Caps a browser operation's timeout without restarting the overall attempt budget.
     * @param configuredMs Positive operation timeout in milliseconds.
     * @param deadlineNanos Original monotonic attempt deadline.
     * @param cancelled Cycle cancellation predicate.
     * @return Positive fractional milliseconds accepted by Playwright.
     * @throws AuthenticationFailure If no budget remains or cancellation was requested.
     */
    static double remainingMs(int configuredMs, long deadlineNanos, BooleanSupplier cancelled) throws AuthenticationFailure {
        checkpoint(Phase.STEP, deadlineNanos, cancelled);
        return Math.max(0.001, Math.min(configuredMs, (deadlineNanos - System.nanoTime()) / 1_000_000.0));
    }
}
