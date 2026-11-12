package bpsh.burp.http;

import bpsh.journey.JourneyNames;

import bpsh.authentication.AuthenticationFailure;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.function.Consumer;
import java.util.function.LongSupplier;

/** Produces actionable request outcomes while suppressing repeated safe cycle warnings for five seconds. */
public final class Diagnostics implements AutoCloseable {
    private static final long WINDOW = java.util.concurrent.TimeUnit.SECONDS.toNanos(5);
    private static final int MAX_KEYS = 1000;
    /** Safe per-request annotation; drop-request annotations remain available even when logs are suppressed. */
    public record Notice(RequestExchange requestId, boolean dropRequested, String text) {}
    /** Distinguishes genuinely different failures without storing requests, tokens or browser objects. */
    private record Key(String alias, AuthenticationFailure.Phase phase, AuthenticationFailure.Cause cause, String problem, String recovery, String channel) {}
    /** Counts suppressed repeats until the next eligible warning. */
    private static final class Repetition {
        long at;
        int suppressed;
        /**
         * Starts a warning window without retaining any request or credential objects.
         * @param at Last emission time on the suppression clock.
         */
        Repetition(long at) { this.at = at; }
    }
    private final LongSupplier nanos;
    private final Consumer<String> log;
    private final LinkedHashMap<Key, Repetition> repetitions = new LinkedHashMap<>();
    private boolean closed;

    /**
     * Creates a bounded safe-warning sink with an injectable monotonic suppression clock.
     *
     * @param log Host logging callback that receives only the safe formatted message.
     */
    public Diagnostics(Consumer<String> log) { this(System::nanoTime, log); }
    /**
     * Creates a bounded safe-warning sink with an injectable monotonic suppression clock.
     *
     * @param nanos Controlled monotonic suppression clock.
     * @param log Safe output sink.
     */
    public Diagnostics(LongSupplier nanos, Consumer<String> log) { this.nanos = nanos; this.log = log; }

    /**
     * Formats and optionally logs a known typed outcome; raw exception/body/URL inputs are not accepted.
     * @param requestId Correlated host message ID.
     * @param alias Validated readable alias, or null for a syntax/unresolved-selection failure.
     * @param failure Typed safe phase/cause/problem/next action from native components.
     * @param tagged Whether the whole request was stopped by explicit-tag policy.
     * @return Per-request annotation regardless of rate limiting.
     */
    public Notice request(RequestExchange requestId, String alias, AuthenticationFailure failure, boolean tagged) {
        String name = safeAlias(alias), outcome = tagged
                ? "Burp was asked to drop this request."
                : "BPSH left the request unchanged.";
        String text = outcome + " " + detail(name, failure);
        emit(new Key(name, failure.phase(), failure.reason(), failure.problem(), failure.recovery(), tagged ? "stopped" : "ordinary"), requestId + ": " + text);
        return new Notice(requestId, tagged, text);
    }

    /**
     * Reports a background cycle/recovery condition without claiming that an application request failed.
     * @param alias Current safe alias, or null when unavailable.
     * @param failure Known safe state or skipped-recovery guidance.
     */
    public void state(String alias, AuthenticationFailure failure) {
        String name = safeAlias(alias);
        emit(new Key(name, failure.phase(), failure.reason(), failure.problem(), failure.recovery(), "state"), detail(name, failure));
    }

    /**
     * Emits one bounded category of safe message per five-second window, counting suppressed repeats.
     * @param key Token/request-free suppression identity.
     * @param text Already formatted safe output.
     */
    private void emit(Key key, String text) {
        String emission = null;
        synchronized (this) {
            if (!closed) {
                long now = nanos.getAsLong();
                Repetition repetition = repetitions.get(key);
                if (repetition == null || now - repetition.at < 0 || now - repetition.at >= WINDOW) {
                    int suppressed = repetition == null ? 0 : repetition.suppressed;
                    repetitions.remove(key); repetitions.put(key, new Repetition(now)); while (repetitions.size() > MAX_KEYS) repetitions.pollFirstEntry();
                    emission = text + (suppressed == 0 ? "" : " (" + suppressed + " similar messages suppressed.)");
                } else if (repetition.suppressed < Integer.MAX_VALUE) repetition.suppressed++;
            }
        }
        if (emission != null) try { log.accept(emission); } catch (RuntimeException ignored) { /* logging must not strand request callers */ }
    }

    /**
     * Formats the journey, problem and next action without exposing internal classification labels.
     * @param alias Already sanitized alias.
     * @param failure Known safe native result.
     * @return Actionable common detail for UI/background and request messages.
     */
    static String detail(String alias, AuthenticationFailure failure) {
        String name = safeAlias(alias);
        return (name == null ? "" : "Journey " + name + ": ") + failure.getMessage();
    }

    /**
     * Accepts only readable alias characters before a value can reach a log or annotation.
     * @param alias Caller-provided alias or null.
     * @return Canonical safe alias, or null when no valid alias is known.
     */
    private static String safeAlias(String alias) {
        try { return JourneyNames.validateAlias(alias).toLowerCase(Locale.ROOT); }
        catch (RuntimeException ex) { return null; }
    }
    /** Stops further log emissions and releases bounded repetition state. */
    @Override public synchronized void close() { closed = true; repetitions.clear(); }
}
