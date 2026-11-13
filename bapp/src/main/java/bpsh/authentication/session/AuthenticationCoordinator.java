package bpsh.authentication.session;

import bpsh.authentication.AuthenticationPolicy;
import bpsh.journey.JourneyCatalog;
import bpsh.authentication.credentials.AuthenticationResult;
import bpsh.authentication.credentials.CredentialUse;
import bpsh.authentication.credentials.TokenExtractor;
import bpsh.authentication.credentials.TokenLifetime;
import bpsh.authentication.credentials.TokenSnapshot;
import bpsh.authentication.session.JourneyEventLog;
import bpsh.authentication.AuthenticationFailure;
import bpsh.authentication.AuthenticationStage;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.JourneyKey;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

/**
 * Shares bounded background authentication without moving browser work into HTTP callbacks.
 *
 * A short monitor protects admission/cycle state only. Browser/native calls, future completions and
 * user continuations execute outside it. Tokens are immutable atomic publications. Cancelling a
 * caller detaches that caller; operator Cancel invalidates the selected journey's shared cycle.
 */
public final class AuthenticationCoordinator implements AutoCloseable {
    static final int WORKERS = 2, MAX_QUEUED = 32;
    static final long COOLDOWN = TimeUnit.SECONDS.toNanos(60);
    private static final int[] RETRY_SECONDS = {5, 15};

    /** Cancels one owned timer without interrupting unrelated work. */
    public interface Timer {
        /** Cancels this timer only, without interrupting a running browser or another caller. */
        void cancel();
    }

    /** Supplies monotonic/wall clocks and asynchronous scheduling for deterministic coordinator tests. */
    interface Runtime extends AutoCloseable {
        /**
         * Returns current monotonic reading from the attempt/cache clock domain.
         *
         * @return Current monotonic reading from the attempt/cache clock domain.
         */
        long nanos();
        /**
         * Returns current wall instant for JWT metadata and Retry-After.
         *
         * @return Current wall instant for JWT metadata and Retry-After.
         */
        Instant instant();
        /**
         * Schedules one cancellable lifecycle callback without executing it inline on the caller.
         *
         * @param task Callback that must never run inline.
         * @param delayNanos Nonnegative delay.
         * @return Owned timer.
         */
        Timer schedule(Runnable task, long delayNanos);
        /**
         * Submits one admitted attempt to the owned bounded browser-worker service.
         *
         * @param task One actual browser attempt admitted into a worker slot.
         */
        void work(Runnable task);
        /** Stops owned scheduling and rejects further work. */
        @Override void close();
        /** @param millis Bounded off-EDT join budget; deterministic runtimes own no live workers. */
        default void await(long millis) {}
    }

    /** Executes one attempt; the coordinator owns retry policy and deliberately supplies fresh budgets. */
    public @FunctionalInterface interface Attempt {
        /**
         * Runs on an admitted browser worker, outside the coordinator monitor.
         * @param entry Captured immutable generation/definition.
         * @param recovery Explicit operator PIN recovery, only on the first attempt.
         * @param deadline Earlier of the attempt and original cycle deadline.
         * @param cancelled Predicate rejecting cancelled, closed or stale work.
         * @return Actual acquisition with original clock metadata.
         * @throws AuthenticationFailure On a safe classified failure.
         */
        AuthenticationResult run(JourneyCatalog.Entry entry, boolean recovery, long deadline, BooleanSupplier cancelled) throws AuthenticationFailure;
        /** Reports setup while preserving existing four-argument attempt implementations.
         * @param entry Captured immutable generation.
         * @param recovery Explicit recovery permission.
         * @param deadline Original effective attempt deadline.
         * @param cancelled Lifecycle predicate.
         * @param observer Fixed setup-state callback.
         * @return Acquired credentials.
         * @throws AuthenticationFailure On an attempt failure.
         */
        default AuthenticationResult run(JourneyCatalog.Entry entry, boolean recovery, long deadline,
                BooleanSupplier cancelled, java.util.function.Consumer<AuthenticationStage> observer) throws AuthenticationFailure {
            return run(entry, recovery, deadline, cancelled);
        }

    }

    /** Checks shared native state on the worker before permitting a positively temporary retry. */
    public @FunctionalInterface interface RetryGate {
        /**
         * Checks shared device suppression before another attempt or token publication is permitted.
         *
         * @param entry Journey whose device state is checked.
         * @return Blocking safe PIN failure, or null.
         */
        AuthenticationFailure blocked(JourneyCatalog.Entry entry);
    }

    /** Names token-free UI phases; no live Playwright objects escape through status. */
    public enum Phase { IDLE, QUEUED, RUNNING, BACKOFF, READY, FAILED, COOLDOWN, PAUSED, CLOSED }
    /** Safe current state for a journey; waitingRequests excludes Test/UI callers. */
    public record Status(Phase phase, boolean usableToken, int waitingRequests, AuthenticationFailure failure,
                         int attempts, boolean recovery, boolean acceptedUse, AuthenticationStage setupStage) {}
    /** Current admitted waiter and browser capacity. */
    public record Capacity(int waitingRequests, int runningAttempts, int queuedCycles) {}

    /** Owns a single request-wide completion and cancellation handle, not the shared browser cycle. */
    public final class Ticket implements AutoCloseable {
        private final Caller caller;
        /**
         * Binds a request-wide completion to its detachable reservation ownership.
         *
         * @param caller Registered caller state, completed immediately on a cache-only request.
         */
        private Ticket(Caller caller) { this.caller = caller; }
        /**
         * Returns one future containing all requested immutable snapshots, or a typed terminal cause.
         *
         * @return One future containing all requested immutable snapshots, or a typed terminal cause.
         */
        public CompletableFuture<Map<JourneyDefinition.Identity, TokenSnapshot>> future() { return caller.future; }
        /** Detaches this caller and releases its reservations without cancelling anyone else's cycle. */
        @Override public void close() { detach(caller, failure(AuthenticationFailure.Cause.CANCELLED, "Waiting for login was cancelled.", "Resend the request when ready.")); }
    }

    /** Stores one generation's independently readable token and monitor-protected lifecycle state. */
    private static final class State {
        final JourneyCatalog.Entry entry;
        final AtomicReference<TokenSnapshot> token = new AtomicReference<>();
        Cycle cycle;
        Timer refresh;
        long cooldown;
        AuthenticationFailure lastFailure;
        int waiters;
        int attempts;
        boolean acceptedUse;
        Episode episode;
        final Set<Caller> reservations = new LinkedHashSet<>();
        /**
         * Creates empty runtime state for one immutable journey generation.
         *
         * @param entry Immutable generation/definition retained while work belongs to it.
         */
        State(JourneyCatalog.Entry entry) { this.entry = entry; }
    }

    /** Owns one shared queue/attempt/backoff epoch and its original finite deadline. */
    private static final class Cycle {
        final State state;
        final long deadline;
        final int attemptMs;
        final boolean recovery;
        boolean operator, sessionLoss;
        final Set<Caller> callers = new LinkedHashSet<>();
        volatile boolean cancelled;
        Phase phase = Phase.QUEUED;
        AuthenticationStage setupStage;
        int attempts;
        Timer expiry, retry;
        /**
         * Captures an authentication epoch with a fixed admission deadline and per-attempt budget.
         *
         * @param state Generation owner.
         * @param deadline Admission-time deadline.
         * @param attemptMs Attempt cap.
         * @param recovery Explicit PIN recovery.
         */
        Cycle(State state, long deadline, int attemptMs, boolean recovery) { this.state = state; this.deadline = deadline; this.attemptMs = attemptMs; this.recovery = recovery; }
    }

    /** One shared loss/replacement episode; publication alone never establishes accepted use. */
    private static final class Episode {
        final long id, rejectedVersion;
        long replacementVersion;
        boolean accepted;
        Episode(long id, long rejectedVersion) { this.id = id; this.rejectedVersion = rejectedVersion; }
    }
    /** Stable journey ownership keeps a pause across configuration generations and ordinary saves. */
    private record Pause(AuthenticationFailure failure, int attempts) {}

    /** Holds one atomic multi-journey waiter reservation and immutable success snapshots. */
    private static final class Caller {
        final CompletableFuture<Map<JourneyDefinition.Identity, TokenSnapshot>> future = new CompletableFuture<>();
        final Map<JourneyDefinition.Identity, TokenSnapshot> results = new LinkedHashMap<>();
        final Set<State> reserved = new LinkedHashSet<>();
        final Set<Cycle> waiting = new LinkedHashSet<>();
        final java.util.ArrayDeque<State> pending = new java.util.ArrayDeque<>();
        boolean admitted, done;
        Timer expiry;
    }

    private final Object lock = new Object();
    private final JourneyEventLog events = new JourneyEventLog();
    private final JourneyCatalog registry;
    private final Runtime runtime;
    private final Attempt attempt;
    private final RetryGate retryGate;
    private final ConcurrentHashMap<JourneyDefinition.Identity, State> states = new ConcurrentHashMap<>();
    private final LinkedHashSet<Cycle> cycles = new LinkedHashSet<>();
    private volatile AuthenticationPolicy controls;
    private volatile boolean closed;
    private int waiters, running;
    private long versions, episodeIds;
    private final Set<JourneyKey> activeWorkers = new LinkedHashSet<>();
    private final Map<JourneyKey, Pause> paused = new LinkedHashMap<>();



    /**
     * Injects a deterministic clock/worker boundary; ownership transfers to this coordinator.
     * @param registry Current generations, checked before both acquisition and publication.
     * @param controls Validated scheduling/admission controls.
     * @param attempt One-attempt executor without built-in retries.
     * @param retryGate Shared device suppression check, executed on the worker.
     */
    public AuthenticationCoordinator(JourneyCatalog registry, AuthenticationPolicy controls, Attempt attempt, RetryGate retryGate) {
        this(registry, controls, new ExecutorAuthenticationRuntime(), attempt, retryGate);
    }

    public AuthenticationCoordinator(JourneyCatalog registry, AuthenticationPolicy controls, Runtime runtime, Attempt attempt, RetryGate retryGate) {
        validate(controls); this.registry = registry; this.controls = controls; this.runtime = runtime; this.attempt = attempt; this.retryGate = retryGate;
    }

    /**
     * Reads a usable atomic publication without waiting for browser work or acquiring the monitor.
     * @param identity Exact generation required by the caller.
     * @return Current usable snapshot, or null if missing, stale, invalidated or expired.
     */
    public TokenSnapshot peek(JourneyDefinition.Identity identity) {
        if (closed || !registry.snapshot().isCurrent(identity)) return null;
        State state = states.get(identity); TokenSnapshot token = state == null ? null : state.token.get();
        return token != null && token.usable(runtime.nanos(), runtime.instant()) ? token : null;
    }

    /**
     * Validates a whole prepared request against one short metadata critical section and registry view.
     * @param snapshots Distinct snapshots actually inserted into the prepared request.
     * @return Whether every used version is current and usable at the final commit boundary.
     */
    public boolean current(Collection<TokenSnapshot> snapshots) {
        synchronized (lock) {
            if (closed) return false;
            var view = registry.snapshot(); long now = runtime.nanos(); Instant wall = runtime.instant();
            for (TokenSnapshot used : snapshots) {
                State state = states.get(used.identity()); TokenSnapshot token = state == null ? null : state.token.get();
                if (token == null || token.version() != used.version() || !view.isCurrent(used.identity()) || !token.usable(now, wall)) return false;
            }
            return registry.snapshot() == view;
        }
    }

    /**
     * Resolves all distinct requested journeys under one original HTTP wait deadline and reservation.
     * @param entries Entries resolved consistently before admission; repeated identities count once.
     * @return Request-owned ticket; admission errors are represented by its completed exceptional future.
     */
    public Ticket acquire(Collection<JourneyCatalog.Entry> entries) { return request(entries, false, false, true, false); }

    /**
     * Acquires automatic sessions in list order under one deadline and all-or-none waiter reservation.
     * @param entries Distinct saved journeys in user order.
     * @return Detachable atomic request ticket; no later login starts after this caller fails.
     */
    public Ticket acquireOrdered(Collection<JourneyCatalog.Entry> entries) { return request(entries, false, false, true, true); }

    /**
     * Starts or joins background acquisition without retaining an HTTP waiter.
     * @param entries Validated request bindings.
     * @return Already completed credential ticket.
     * @throws AuthenticationFailure When credentials are not ready; shared browser work continues.
     */
    public Ticket acquireImmediately(Collection<JourneyCatalog.Entry> entries) throws AuthenticationFailure {
        var ticket = request(entries, false, false, false, false);
        if (ticket.future().isDone()) return ticket;
        ticket.close();
        throw failure(AuthenticationFailure.Cause.NOT_READY, "Credentials are not ready. Login is running in the background.", "Later requests will use the credentials when login succeeds.");
    }

    /** @return Bounded metadata-only session history shared by automatic authentication and the editor. */
    public JourneyEventLog events() { return events; }

    /** @param entry Exact event owner. @param level Safe severity. @param message Sanitized constant or classified guidance. */
    private void event(JourneyCatalog.Entry entry, JourneyEventLog.Level level, String message) { events.append(entry.identity().key(), runtime.instant(), level, message); }

    /**
     * Joins or starts a bounded UI test cycle, even if a usable token is already cached.
     * @param entry Captured saved generation.
     * @param explicitRecovery Whether the operator explicitly chose Retry/PIN recovery.
     * @return Test-owned ticket; it consumes cycle capacity but no HTTP waiter reservation.
     */
    public Ticket test(JourneyCatalog.Entry entry, boolean explicitRecovery) { return request(List.of(entry), explicitRecovery, true, false, false); }

    /**
     * Reserves all unresolved generations before creating any cycles or attaching caller state.
     * @param entries Requested definitions.
     * @param recovery Explicit operator recovery.
     * @param force Whether cache hits still require a fresh/joined Test cycle.
     * @param counted Whether this is a waiting HTTP request.
     * @param ordered Whether unresolved sessions must be acquired sequentially.
     * @return Caller ticket after all immediate completion actions have run outside the monitor.
     */
    /** Joins one recovery per rejected publication; all affected identities are checked before admission. */
    public Ticket recover(Collection<CredentialUse> lost) {
        var entries = new ArrayList<JourneyCatalog.Entry>();
        for (var used : lost) {
            var entry = registry.snapshot().entries().get(used.identity().key());
            if (entry != null) entries.add(entry);
        }
        return request(entries, false, false, true, true, List.copyOf(lost));
    }
    private Ticket request(Collection<JourneyCatalog.Entry> entries, boolean recovery, boolean force, boolean counted, boolean ordered) {
        return request(entries, recovery, force, counted, ordered, List.of());
    }
    private Ticket request(Collection<JourneyCatalog.Entry> entries, boolean recovery, boolean force, boolean counted, boolean ordered, List<CredentialUse> lost) {
        Caller caller = new Caller(); List<Runnable> after = new ArrayList<>();
        long callerDeadline = runtime.nanos() + TimeUnit.MILLISECONDS.toNanos(counted ? controls.requestWaitTimeoutMs() : controls.cycleTimeoutMs());
        synchronized (lock) {
            try {
                if (closed) throw closedFailure();
                reconcileConfiguration(after);
                for (var used : lost) prepareRecovery(used);
                Map<JourneyDefinition.Identity, State> needed = new LinkedHashMap<>();
                for (var entry : entries) {
                    if (!registry.snapshot().isCurrent(entry.identity())) throw stale();
                    if (entry.definition().transportOnly()) throw new AuthenticationFailure(AuthenticationFailure.Phase.SETUP,
                            AuthenticationFailure.Cause.CONFIGURATION, "This journey has no captured token or cookie to insert.",
                            "For HTTP or client-certificate authentication, use automatic session handling or the BPSP-HTTP-AUTHENT header instead of a token tag.").forJourney(entry.identity());
                    if (entry.definition().draft() != null) throw new AuthenticationFailure(AuthenticationFailure.Phase.SETUP,
                            AuthenticationFailure.Cause.CONFIGURATION, "This journey has incomplete or invalid settings.",
                            "Review the journey settings, then test login.").forJourney(entry.identity());
                    State state = states.computeIfAbsent(entry.identity(), ignored -> new State(entry));
                    TokenSnapshot token = peek(entry.identity());
                    if (token != null && !force) caller.results.put(entry.identity(), token); else needed.put(entry.identity(), state);
                }
                if (needed.isEmpty()) finishCaller(caller, null, after);
                else {
                    if (counted && controls.maxWaitingRequestsGlobal() != null && waiters >= controls.maxWaitingRequestsGlobal())
                        throw capacity("Too many requests are waiting for login.", "Wait for login to finish, then resend. You can increase the global waiting-request limit in Settings.");
                    for (State state : needed.values()) {
                        if (counted && controls.maxWaitingRequestsPerJourney() != null && state.waiters >= controls.maxWaitingRequestsPerJourney())
                            throw capacity("Too many requests are waiting for this journey to log in.", "Wait for this login to finish, then resend. You can increase the per-journey waiting-request limit in Settings.").forJourney(state.entry.identity());
                        if (state.cycle == null) eligible(state, recovery || force);
                    }
                    long newCycles = (ordered ? needed.values().stream().limit(1) : needed.values().stream()).filter(s -> s.cycle == null).count();
                    long available = (ordered ? needed.values().stream().limit(1) : needed.values().stream())
                            .filter(s -> s.cycle == null && !activeWorkers.contains(s.entry.identity().key())).limit(Math.max(0, WORKERS - running)).count();
                    if (queued() + Math.max(0, newCycles - available) > MAX_QUEUED)
                        throw capacity("The login queue is full.", "Wait for the current logins to finish, then try again.");
                    if (counted) { caller.admitted = true; waiters++; caller.reserved.addAll(needed.values()); needed.values().forEach(s -> { s.waiters++; s.reservations.add(caller); }); }
                    if (ordered) { caller.pending.addAll(needed.values()); advanceOrdered(caller, after); }
                    else for (State state : needed.values()) {
                        if (state.cycle == null) start(state, recovery);
                        if (force) state.cycle.operator = true;
                        state.cycle.callers.add(caller); caller.waiting.add(state.cycle);
                    }
                    caller.expiry = runtime.schedule(() -> detach(caller, failure(AuthenticationFailure.Cause.TIMEOUT,
                            "The request timed out while waiting for login.", "Check the login progress in Journeys, then resend the request when login finishes.")),
                            Math.max(0, callerDeadline - runtime.nanos()));
                    dispatch(after);
                }
            } catch (AuthenticationFailure ex) {
                for (var entry : entries) if (ex.journey() == null || ex.journey().equals(entry.identity())) event(entry, JourneyEventLog.Level.WARNING, ex.getMessage());
                finishCaller(caller, ex, after);
            }
        }
        after.forEach(Runnable::run);
        caller.future.whenComplete((result, error) -> { if (caller.future.isCancelled()) detach(caller, failure(AuthenticationFailure.Cause.CANCELLED, "Waiting for login was cancelled.", "Resend when ready.")); });
        return new Ticket(caller);
    }

    /** Attaches only the next unresolved automatic session while retaining the original request deadline. */
    private void advanceOrdered(Caller caller, List<Runnable> after) throws AuthenticationFailure {
        while (!caller.pending.isEmpty()) {
            State state = caller.pending.removeFirst();
            if (!registry.snapshot().isCurrent(state.entry.identity())) throw stale().forJourney(state.entry.identity());
            TokenSnapshot cached = peek(state.entry.identity());
            if (cached != null) { caller.results.put(cached.identity(), cached); continue; }
            if (state.cycle == null) {
                eligible(state, false);
                if (queued() >= MAX_QUEUED && (running >= WORKERS || activeWorkers.contains(state.entry.identity().key()))) throw capacity("The login queue is full.", "Wait for login to finish, then resend.").forJourney(state.entry.identity());
                start(state, false);
            }
            state.cycle.callers.add(caller); caller.waiting.add(state.cycle); return;
        }
        finishCaller(caller, null, after);
    }

    /**
     * Rejects automatic restarts of terminal failures and requests inside the shared cooldown.
     * @param state Target generation.
     * @param recovery Explicit Test/Retry bypass for terminal state and cooldown only.
     * @throws AuthenticationFailure If automatic demand must remain paused.
     */
    private void eligible(State state, boolean recovery) throws AuthenticationFailure {
        if (recovery) return;
        Pause pause = paused.get(state.entry.identity().key());
        if (pause != null) throw pause.failure().forJourney(state.entry.identity());
        if (state.lastFailure != null && state.cooldown - runtime.nanos() > 0) throw state.lastFailure != null ? state.lastFailure : failure(AuthenticationFailure.Cause.CANCELLED,
                "Login is paused briefly after cancellation.", "Wait a few seconds or choose Retry to start again.");
        if (state.lastFailure != null && !state.lastFailure.retryable() && state.lastFailure.reason() != AuthenticationFailure.Cause.CANCELLED)
            throw state.lastFailure;
    }

    /**
     * Admits a new shared epoch and starts its original queue/backoff deadline immediately.
     * @param state Target generation with no current cycle.
     * @param recovery Operator-requested PIN recovery flag.
     */
    private void start(State state, boolean recovery) {
        cancel(state.refresh); state.refresh = null;
        Cycle cycle = new Cycle(state, runtime.nanos() + TimeUnit.MILLISECONDS.toNanos(controls.cycleTimeoutMs()), controls.attemptTimeoutMs(), recovery);
        cycle.sessionLoss = state.episode != null && state.episode.replacementVersion == 0;
        state.cycle = cycle; state.lastFailure = null; state.attempts = 0; cycles.add(cycle);
        event(state.entry, JourneyEventLog.Level.INFO, "Authentication queued.");
        cycle.expiry = runtime.schedule(() -> expire(cycle), TimeUnit.MILLISECONDS.toNanos(controls.cycleTimeoutMs()));
    }

    /**
     * Assigns available slots to FIFO-ready cycles; no worker is released before its attempt returns.
     * @param after Actions submitted after leaving the admission monitor.
     */
    private void dispatch(List<Runnable> after) {
        if (closed) return;
        for (Cycle cycle : cycles) {
            if (running >= WORKERS) break;
            if (cycle.phase != Phase.QUEUED || cycle.cancelled || activeWorkers.contains(cycle.state.entry.identity().key())) continue;
            cycle.phase = Phase.RUNNING; cycle.attempts++; cycle.state.attempts = cycle.attempts; running++; activeWorkers.add(cycle.state.entry.identity().key());
            event(cycle.state.entry, JourneyEventLog.Level.INFO, "Login attempt " + cycle.attempts + " started.");
            long deadline = runtime.nanos() + Math.min(TimeUnit.MILLISECONDS.toNanos(cycle.attemptMs), Math.max(0, cycle.deadline - runtime.nanos()));
            after.add(() -> {
                try { runtime.work(() -> run(cycle, deadline)); }
                catch (RuntimeException ex) { completed(cycle, null, failure(AuthenticationFailure.Cause.CLOSED, "The login browser could not start.", "")); }
            });
        }
    }

    /**
     * Executes browser and PIN-state observations off the monitor and reports only typed safe data.
     * @param cycle Admitted epoch.
     * @param deadline Captured effective attempt deadline.
     */
    private void run(Cycle cycle, long deadline) {
        AuthenticationResult outcome = null; AuthenticationFailure error = null;
        try {
            if (cancelled(cycle)) throw stale();
            if (cycle.attempts > 1) { AuthenticationFailure blocked = retryGate.blocked(cycle.state.entry); if (blocked != null) throw blocked; }
            int attemptNumber = cycle.attempts;
            outcome = attempt.run(cycle.state.entry, cycle.recovery && attemptNumber == 1, deadline, () -> cancelled(cycle),
                    stage -> observeSetup(cycle, attemptNumber, stage));
            AuthenticationFailure blocked = retryGate.blocked(cycle.state.entry);
            if (blocked != null) { error = blocked; outcome = null; }
        } catch (AuthenticationFailure ex) {
            error = ex;
            if (ex.retryable()) try { AuthenticationFailure blocked = retryGate.blocked(cycle.state.entry); if (blocked != null) error = blocked; }
            catch (RuntimeException failure) { error = unknown(); }
        } catch (Exception | LinkageError ex) { error = unknown(); }
        completed(cycle, outcome, error);
    }

    /** Accepts only fixed metadata from the exact running attempt and current generation.
     * @param cycle Captured authentication epoch.
     * @param attemptNumber Captured attempt number.
     * @param stage Fixed local preparation state.
     */
    private void observeSetup(Cycle cycle, int attemptNumber, AuthenticationStage stage) {
        synchronized (lock) {
            if (stage == null || cancelled(cycle) || states.get(cycle.state.entry.identity()) != cycle.state
                    || cycle.state.cycle != cycle || cycle.phase != Phase.RUNNING || cycle.attempts != attemptNumber
                    || cycle.setupStage == stage) return;
            cycle.setupStage = stage;
            event(cycle.state.entry, JourneyEventLog.Level.INFO, stage.description());
        }
    }

    /**
     * Publishes a still-current usable result or schedules a positively temporary bounded retry.
     * @param cycle Finished attempt epoch; it may already have been cancelled or replaced.
     * @param outcome Successful acquisition, or null.
     * @param error Classified error, or null for success.
     */
    private void completed(Cycle cycle, AuthenticationResult outcome, AuthenticationFailure error) {
        List<Runnable> after = new ArrayList<>();
        synchronized (lock) {
            cycle.setupStage = null;
            running--; activeWorkers.remove(cycle.state.entry.identity().key());
            // Cancellation revokes publication before the owner finishes cleanup. Report that
            // independent lifecycle outcome even when this cycle has already been detached.
            if (error != null && error.cleanupIncomplete())
                event(cycle.state.entry, JourneyEventLog.Level.ERROR, AuthenticationFailure.cleanupProblem());
            if (!cancelled(cycle) && cycle.state.cycle == cycle) {
                if (cycle.deadline - runtime.nanos() <= 0 && error == null) error = failure(AuthenticationFailure.Cause.TIMEOUT, "The total login timeout was reached.", "");
                if (error == null) try {
                    if (outcome == null || !outcome.identity().equals(cycle.state.entry.identity())) throw stale();
                    String normalized = TokenExtractor.normalize(outcome.token(), Clock.fixed(runtime.instant(), java.time.ZoneOffset.UTC));
                    var lifetime = TokenLifetime.acquire(normalized, cycle.state.entry.definition().cache(), outcome.acquiredAt(), outcome.acquiredNanos(), outcome.expiresAt());
                    if (!lifetime.usable(runtime.nanos(), runtime.instant())) throw new AuthenticationFailure(AuthenticationFailure.Phase.EXTRACTION, AuthenticationFailure.Cause.TOKEN_EXPIRED,
                            "The token expired before it could be used.", "Run Test login to obtain a fresh token.");
                    TokenSnapshot token = new TokenSnapshot(outcome.identity(), ++versions, normalized, lifetime, outcome.cookies(), outcome.namedTokens(), cycle.state.entry.definition().extraction(), outcome.httpProtocol(),outcome.httpObservations());
                    cycle.state.token.set(token);
                    cycle.state.lastFailure = null; cycle.state.cooldown = 0; cycle.state.acceptedUse = false;
                    if (cycle.operator) { paused.remove(token.identity().key()); cycle.state.episode = null; }
                    else if (cycle.sessionLoss && cycle.state.episode != null) cycle.state.episode.replacementVersion = token.version();
                    event(cycle.state.entry, JourneyEventLog.Level.INFO, "Credentials captured.");
                    if (outcome.skippedSteps() > 0) event(cycle.state.entry, JourneyEventLog.Level.INFO,
                            "All configured credentials were captured. " + outcome.skippedSteps() + (outcome.skippedSteps() == 1 ? " remaining step was skipped." : " remaining steps were skipped."));
                    for (Caller caller : List.copyOf(cycle.callers)) {
                        caller.results.put(token.identity(), token); caller.waiting.remove(cycle); cycle.callers.remove(caller);
                        if (caller.waiting.isEmpty()) {
                            try { advanceOrdered(caller, after); }
                            catch (AuthenticationFailure failure) { finishCaller(caller, failure, after); }
                        }
                    }
                    end(cycle); scheduleRefresh(cycle.state, lifetime.refreshDelay(runtime.nanos(), runtime.instant()));
                } catch (AuthenticationFailure ex) { error = ex; }
                catch (RuntimeException | LinkageError ex) { error = unknown(); }
                if (error != null) {
                    long delay = retryDelay(cycle, error);
                    if (delay >= 0 && queued() < MAX_QUEUED) {
                        cycle.phase = Phase.BACKOFF;
                        event(cycle.state.entry, JourneyEventLog.Level.WARNING, error.getMessage() + " Retrying in " + TimeUnit.NANOSECONDS.toSeconds(delay) + " seconds.");
                        cycle.retry = runtime.schedule(() -> ready(cycle), delay);
                    } else failCycle(cycle, delay >= 0 ? capacity("The login retry queue is full.", "Wait for the current logins to finish, then choose Retry.") : error, after);
                }
            } else if (cycle.state.cycle == cycle) failCycle(cycle, closed ? closedFailure() : stale(), after);
            dispatch(after);
        }
        after.forEach(Runnable::run);
    }

    /**
     * Computes a retry only when its entire delay fits the unchanged cycle budget.
     * @param cycle Current epoch with at least one completed attempt.
     * @param error Positively classified outcome and optional Retry-After.
     * @return Nonnegative nanosecond delay, or -1 for a terminal/exhausted cycle.
     */
    private long retryDelay(Cycle cycle, AuthenticationFailure error) {
        if (!error.retryable() || cycle.attempts > RETRY_SECONDS.length) return -1;
        long delay = TimeUnit.SECONDS.toNanos(RETRY_SECONDS[cycle.attempts - 1]);
        if (error.retryAfter() != null && (Integer.valueOf(429).equals(error.httpStatus()) || Integer.valueOf(503).equals(error.httpStatus()))) {
            try { delay = Math.max(delay, java.time.Duration.between(runtime.instant(), error.retryAfter()).toNanos()); }
            catch (ArithmeticException ex) { return -1; }
        }
        return delay < cycle.deadline - runtime.nanos() ? delay : -1;
    }

    /**
     * Makes one delayed retry eligible without extending any budget or consuming a worker during backoff.
     * @param cycle Epoch whose single retry timer fired.
     */
    private void ready(Cycle cycle) {
        List<Runnable> after = new ArrayList<>();
        synchronized (lock) {
            if (cycle.state.cycle == cycle && !cancelled(cycle)) { cycle.retry = null; cycle.phase = Phase.QUEUED; dispatch(after); }
        }
        after.forEach(Runnable::run);
    }

    /**
     * Releases all owners at the cycle deadline even when a browser/native worker has not returned.
     * @param cycle Original admission epoch.
     */
    private void expire(Cycle cycle) {
        List<Runnable> after = new ArrayList<>();
        synchronized (lock) {
            if (cycle.state.cycle == cycle) failCycle(cycle, failure(AuthenticationFailure.Cause.TIMEOUT, "The total login timeout was reached.", ""), after);
            dispatch(after);
        }
        after.forEach(Runnable::run);
    }

    /**
     * Ends a failed epoch, retaining a still-usable older token and pausing automatic repeated failures.
     * @param cycle Epoch to supersede.
     * @param error Terminal classified result.
     * @param after Caller completions to invoke outside the monitor.
     */
    private void failCycle(Cycle cycle, AuthenticationFailure error, List<Runnable> after) {
        if (cycle.sessionLoss || error.retryable() && cycle.attempts >= 3 || cycle.operator && paused.containsKey(cycle.state.entry.identity().key())) {
            error = pause(cycle.state, error, cycle.attempts);
        }
        error = error.forJourney(cycle.state.entry.identity());
        cycle.state.lastFailure = error; cycle.state.cooldown = runtime.nanos() + COOLDOWN;
        events.append(cycle.state.entry.identity().key(), runtime.instant(), error.reason() == AuthenticationFailure.Cause.CANCELLED ? JourneyEventLog.Level.WARNING : JourneyEventLog.Level.ERROR,
                error.getMessage(), error.step() == null ? null : new JourneyEventLog.StepTarget(cycle.state.entry.identity(), error.step().id()));
        for (Caller caller : List.copyOf(cycle.callers)) finishCaller(caller, error, after);
        end(cycle);
    }

    /**
     * Revokes publication before cancelling queue/backoff timers, leaving running ownership until return.
     * @param cycle Selected epoch; other journeys and their workers are untouched.
     */
    private void end(Cycle cycle) {
        cycle.setupStage = null; cycle.cancelled = true; cancel(cycle.expiry); cancel(cycle.retry); cycles.remove(cycle);
        if (cycle.state.cycle == cycle) cycle.state.cycle = null;
    }

    /**
     * Completes one atomic request result and releases every reservation on all terminal paths.
     * @param caller Original request/Test owner.
     * @param error Failure, or null when every requested snapshot is ready.
     * @param after Completions invoked only after leaving the monitor.
     */
    private void finishCaller(Caller caller, AuthenticationFailure error, List<Runnable> after) {
        if (caller.done) return; caller.done = true; cancel(caller.expiry);
        if (caller.admitted) { waiters--; caller.reserved.forEach(s -> { s.waiters--; s.reservations.remove(caller); }); caller.reserved.clear(); caller.admitted = false; }
        caller.waiting.forEach(c -> c.callers.remove(caller)); caller.waiting.clear();
        caller.pending.clear();
        if (error == null) { var result = Map.copyOf(caller.results); after.add(() -> caller.future.complete(result)); }
        else after.add(() -> caller.future.completeExceptionally(error));
    }

    /**
     * Cancels only one caller without stopping useful shared work.
     * @param caller Request/Test state.
     * @param error Typed detachment outcome.
     */
    private void detach(Caller caller, AuthenticationFailure error) {
        List<Runnable> after = new ArrayList<>(); synchronized (lock) { finishCaller(caller, error, after); } after.forEach(Runnable::run);
    }

    /**
     * Keeps at most one proactive/deferred timer per successfully activated journey.
     * @param state Activated generation.
     * @param delay Nonnegative monotonic delay.
     */
    private void scheduleRefresh(State state, long delay) {
        cancel(state.refresh); if (paused.containsKey(state.entry.identity().key())) { state.refresh = null; return; }
        state.refresh = runtime.schedule(() -> refresh(state), Math.max(0, delay));
    }

    /**
     * Starts one proactive cycle or coalesces capacity deferral; an exhausted cycle is not restarted here.
     * @param state Generation activated by a prior successful Test/use.
     */
    private void refresh(State state) {
        List<Runnable> after = new ArrayList<>();
        synchronized (lock) {
            state.refresh = null;
            if (closed || !registry.snapshot().isCurrent(state.entry.identity()) || state.cycle != null) return;
            long cooldown = state.lastFailure == null ? 0 : state.cooldown - runtime.nanos();
            if (cooldown > 0) { scheduleRefresh(state, cooldown); return; }
            try {
                eligible(state, false);
                if (queued() + (running >= WORKERS ? 1 : 0) > MAX_QUEUED) { scheduleRefresh(state, COOLDOWN); return; }
                start(state, false); dispatch(after);
            } catch (AuthenticationFailure ignored) { /* terminal setup/PIN failures stay idle until explicit recovery */ }
        }
        after.forEach(Runnable::run);
    }

    /**
     * Cancels a selected shared cycle, retains a usable token and applies the operator cooldown.
     * @param identity Exact selected generation; idle Cancel is a no-op.
     * @return Whether an active cycle was actually superseded; false does not apply a cooldown.
     */
    public boolean cancelAuthentication(JourneyDefinition.Identity identity) {
        List<Runnable> after = new ArrayList<>();
        boolean cancelled = false;
        synchronized (lock) {
            State state = states.get(identity);
            if (state != null && state.cycle != null) {
                cancelled = true;
                failCycle(state.cycle, failure(AuthenticationFailure.Cause.CANCELLED, "This journey's login was cancelled.", "Choose Retry to start login again."), after);
                if (state.token.get() != null) scheduleRefresh(state, COOLDOWN);
            }
            dispatch(after);
        }
        after.forEach(Runnable::run);
        return cancelled;
    }

    /**
     * Clears a manually invalidated token and supersedes its cycle without clearing shared PIN state.
     * @param identity Selected generation.
     */
    public void invalidate(JourneyDefinition.Identity identity) {
        List<Runnable> after = new ArrayList<>();
        synchronized (lock) {
            State state = states.get(identity);
            if (state != null) {
                state.token.set(null); cancel(state.refresh); state.refresh = null;
                event(state.entry, JourneyEventLog.Level.INFO, "Cached credentials cleared.");
                if (state.cycle != null) failCycle(state.cycle, failure(AuthenticationFailure.Cause.CANCELLED,
                        "The cached token was cleared and the current login was cancelled.", "Choose Retry to sign in again."), after);
            }
            dispatch(after);
        }
        after.forEach(Runnable::run);
    }

    /**
     * Invalidates only the exact token version used by a recovery response, preserving healthy refresh.
     * @param identity Used journey generation.
     * @param version Used token version.
     * @return Whether this response removed the current snapshot.
     */
    public boolean invalidateVersion(JourneyDefinition.Identity identity, long version) {
        synchronized (lock) {
            State state = states.get(identity); TokenSnapshot token = state == null ? null : state.token.get();
            if (token == null || token.version() != version) return false;
            state.token.compareAndSet(token, null); cancel(state.refresh); state.refresh = null;
            event(state.entry, JourneyEventLog.Level.WARNING, "Session recovery detected an expired session. Cached credentials were invalidated."); return true;
        }
    }

    /** Captures whether this request is validating newly issued replacement credentials. */
    public CredentialUse provenance(CredentialUse used, boolean replay) {
        synchronized (lock) {
            State state = states.get(used.identity()); Episode episode = state == null ? null : state.episode;
            long validation = episode != null && episode.replacementVersion == used.version() && (replay || !episode.accepted) ? episode.id : 0;
            return new CredentialUse(used.identity(), used.version(), used.rule(), validation, replay);
        }
    }
    /** Records an attributed 2xx response without claiming that the application verified authentication. */
    public void accepted(CredentialUse used, int status) {
        synchronized (lock) {
            State state = states.get(used.identity()); TokenSnapshot token = state == null ? null : state.token.get();
            if (token == null || token.version() != used.version() || paused.containsKey(used.identity().key())) return;
            if (!state.acceptedUse) event(state.entry, JourneyEventLog.Level.INFO, "Request using this journey's credentials returned HTTP " + status + ".");
            state.acceptedUse = true;
            if (state.episode != null && state.episode.replacementVersion == used.version()) state.episode.accepted = true;
        }
    }
    /** Rejects the replacement once, permanently pausing this owner until an explicit successful Test. */
    public void rejectedReplacement(CredentialUse used, int status) {
        List<Runnable> after = new ArrayList<>();
        synchronized (lock) {
            State state = states.get(used.identity()); Episode episode = state == null ? null : state.episode;
            TokenSnapshot current = state == null ? null : state.token.get();
            if (current == null || current.version() != used.version()) return;
            if (used.validationEpisode() != 0) {
                if (episode == null || episode.id != used.validationEpisode() || episode.replacementVersion != used.version()) return;
            } else {
                // A late original can replay with a newer publication from an independent refresh/Test.
                // Rejection still pauses that replacement, but never a subsequently published version.
                if (!used.replay()) return;
            }
            var failure = new AuthenticationFailure(AuthenticationFailure.Phase.EXTRACTION, AuthenticationFailure.Cause.AUTH_REJECTED,
                    "The application rejected replacement credentials.", "", status, null);
            pause(state, failure, state.attempts); state.token.set(null); state.acceptedUse = false;
            if (state.cycle != null) failCycle(state.cycle, failure, after);
            event(state.entry, JourneyEventLog.Level.ERROR, paused.get(used.identity().key()).failure().getMessage());
        }
        after.forEach(Runnable::run);
    }
    /** Validates the exact failed publication before invalidating or joining its existing episode. */
    private void prepareRecovery(CredentialUse used) throws AuthenticationFailure {
        if (!registry.snapshot().isCurrent(used.identity())) throw stale().forJourney(used.identity());
        var entry = registry.snapshot().entries().get(used.identity().key());
        State state = states.computeIfAbsent(used.identity(), ignored -> new State(entry));
        Pause pause = paused.get(used.identity().key()); if (pause != null) throw pause.failure().forJourney(used.identity());
        if (used.validationEpisode() != 0 || used.replay()) throw failure(AuthenticationFailure.Cause.AUTH_REJECTED,
                "Replacement credentials were rejected; this request cannot be replayed again.", "Run Test login to recover the affected journey.").forJourney(used.identity());
        TokenSnapshot current = state.token.get();
        if (state.episode != null && state.episode.rejectedVersion == used.version()) return;
        if (current != null && current.version() != used.version() || current == null && state.episode != null) return;
        state.episode = new Episode(++episodeIds, used.version()); state.acceptedUse = false;
        if (current != null) state.token.compareAndSet(current, null);
        cancel(state.refresh); state.refresh = null;
        if (state.cycle != null) state.cycle.sessionLoss = true;
        event(state.entry, JourneyEventLog.Level.WARNING, "Session loss detected. Starting shared reauthentication; each affected request may replay once.");
    }
    /** Retains the observed cause and stage while adding bounded-attempt and caller-policy guidance. */
    private AuthenticationFailure pause(State state, AuthenticationFailure cause, int attempts) {
        var failure = cause.withRecovery(
                "Automatic recovery is paused after " + attempts + (attempts == 1 ? " attempt. " : " attempts. ")
                        + "Run Test login to try again; saving does not resume recovery or resend previous requests. "
                        + "Without usable credentials, ordinary requests continue unchanged with a warning and unresolved tagged requests are stopped. " + cause.recovery()).forJourney(state.entry.identity());
        paused.put(state.entry.identity().key(), new Pause(failure, attempts)); state.lastFailure = failure;
        cancel(state.refresh); state.refresh = null; return failure;
    }

    /**
     * Revokes obsolete work after an edit while retaining usable, compatible captured credentials.
     * Publication predicates independently reject late work even before this notification arrives.
     */
    public void configurationChanged() {
        List<Runnable> after = new ArrayList<>();
        synchronized (lock) {
            reconcileConfiguration(after);
            dispatch(after);
        }
        after.forEach(Runnable::run);
    }

    /** Reconciles committed edits under the coordinator lock before admission or explicit notification. */
    private void reconcileConfiguration(List<Runnable> after) {
        for (State state : List.copyOf(states.values())) if (!registry.snapshot().isCurrent(state.entry.identity())) {
            TokenSnapshot captured = state.token.getAndSet(null); cancel(state.refresh); state.refresh = null;
            for (Caller caller : List.copyOf(state.reservations)) finishCaller(caller, stale().forJourney(state.entry.identity()), after);
            if (state.cycle != null) failCycle(state.cycle, stale(), after);
            states.remove(state.entry.identity(), state);
            var view = registry.snapshot(); var replacement = view.entries().get(state.entry.identity().key());
            if (captured != null && captured.usable(runtime.nanos(), runtime.instant()) && replacement != null
                    && replacement.identity().generation() == state.entry.identity().generation() + 1 && view.isCurrent(replacement.identity())) {
                boolean draft = replacement.definition().draft() != null;
                TokenSnapshot retained = draft ? new TokenSnapshot(replacement.identity(), captured.version(), captured.value(), captured.lifetime(),
                        captured.cookies(), captured.namedTokens(), captured.extraction(),captured.httpProtocol(),captured.httpObservations()) : captured.reconfigure(replacement.identity(), captured.extraction(), replacement.definition().extraction());
                if(retained!=null && !state.entry.sameHttpAuthentication(replacement))retained=retained.withoutHttpObservations();
                if (retained != null) {
                    State current = states.computeIfAbsent(replacement.identity(), ignored -> new State(replacement));
                    if (current.token.compareAndSet(null, retained)) {
                        current.acceptedUse = state.acceptedUse; current.episode = state.episode; current.attempts = state.attempts;
                        if (!draft) scheduleRefresh(current, retained.lifetime().refreshDelay(runtime.nanos(), runtime.instant()));
                    }
                }
            }
        }
        paused.keySet().removeIf(key -> !registry.snapshot().entries().containsKey(key));
    }

    /**
     * Applies validated live limits without evicting admitted callers or restarting captured budgets.
     * @param replacement New project controls; invalid values leave the current controls unchanged.
     */
    public void updateControls(AuthenticationPolicy replacement) { validate(replacement); synchronized (lock) { controls = replacement; } }

    /**
     * Reads safe per-generation phase and admission counts for background UI refresh.
     * @param identity Selected generation.
     * @return State without a credential value or device object.
     */
    public Status status(JourneyDefinition.Identity identity) {
        synchronized (lock) {
            State state = states.get(identity); boolean usable = peek(identity) != null;
            Pause pause = paused.get(identity.key());
            Phase phase = closed ? Phase.CLOSED : state != null && state.cycle != null ? state.cycle.phase : pause != null ? Phase.PAUSED : state == null ? Phase.IDLE
                    : usable ? Phase.READY : state.lastFailure != null && state.cooldown - runtime.nanos() > 0 ? Phase.COOLDOWN : state.lastFailure != null ? Phase.FAILED : Phase.IDLE;
            return new Status(phase, usable, state == null ? 0 : state.waiters, pause != null && (state == null || state.cycle == null) ? pause.failure().forJourney(identity) : state == null ? null : state.lastFailure,
                    state == null ? pause == null ? 0 : pause.attempts() : state.attempts,
                    state != null && state.episode != null, state != null && state.acceptedUse,
                    phase == Phase.RUNNING && state != null && state.cycle != null ? state.cycle.setupStage : null);
        }
    }

    /**
     * Returns current capacity counts; running includes cancelled workers that have not returned yet.
     *
     * @return Current capacity counts; running includes cancelled workers that have not returned yet.
     */
    public Capacity capacity() { synchronized (lock) { return new Capacity(waiters, running, queued()); } }

    /**
     * Returns ready/backoff cycle count, excluding actual running attempts. Monitor must be held.
     *
     * @return Ready/backoff cycle count, excluding actual running attempts. Monitor must be held.
     */
    private int queued() { return (int) cycles.stream().filter(c -> c.phase != Phase.RUNNING).count(); }
    /**
     * Rejects work whose epoch, extension lifecycle or registry generation is no longer current.
     *
     * @param cycle Attempt epoch.
     * @return Whether cancellation, unload or registry replacement rejects it.
     */
    private boolean cancelled(Cycle cycle) { return closed || cycle.cancelled || !registry.snapshot().isCurrent(cycle.state.entry.identity()); }
    /**
     * Cancels an optional owned timer without affecting another request or shared cycle.
     *
     * @param timer Optional owned timer to cancel.
     */
    private static void cancel(Timer timer) { if (timer != null) timer.cancel(); }

    /**
     * Checks scheduling/admission bounds even for callers constructing controls without the native codec.
     * @param c Proposed immutable controls.
     * @throws IllegalArgumentException If deadlines, relationships or finite waiter limits are invalid.
     */
    private static void validate(AuthenticationPolicy c) {
        if (c == null || c.requestWaitTimeoutMs() < 1000 || c.requestWaitTimeoutMs() > 600_000 || c.attemptTimeoutMs() < 1000 || c.attemptTimeoutMs() > 300_000
                || c.cycleTimeoutMs() < 1000 || c.cycleTimeoutMs() > 1_800_000 || c.requestWaitTimeoutMs() > c.cycleTimeoutMs() || c.attemptTimeoutMs() > c.cycleTimeoutMs()
                || (c.maxWaitingRequestsGlobal() != null && c.maxWaitingRequestsGlobal() < 1) || (c.maxWaitingRequestsPerJourney() != null && c.maxWaitingRequestsPerJourney() < 1))
            throw new IllegalArgumentException("Invalid authentication deadline/waiter controls.");
    }

    /**
     * Returns redacted stale-generation guidance used for late work and deleted definitions.
     *
     * @return Redacted stale-generation guidance used for late work and deleted definitions.
     */
    private static AuthenticationFailure stale() { return failure(AuthenticationFailure.Cause.STALE, "The journey changed while login was running.", "Resend the request to use the current saved journey."); }
    /**
     * Returns redacted unknown-cause guidance without a raw worker exception.
     *
     * @return Redacted unknown-cause guidance without a raw worker exception.
     */
    private static AuthenticationFailure unknown() { return failure(AuthenticationFailure.Cause.UNKNOWN, "Login failed.", ""); }
    /**
     * Returns typed unload outcome for all attached callers.
     *
     * @return Typed unload outcome for all attached callers.
     */
    private static AuthenticationFailure closedFailure() { return failure(AuthenticationFailure.Cause.CLOSED, "The login service has stopped.", "Reload the extension before authentication."); }
    /**
     * Builds actionable guidance distinguishing an enabled waiter limit from the finite cycle queue.
     *
     * @param problem Safe capacity description.
     * @param recovery Specific finite-queue/limit guidance.
     * @return Typed admission failure.
     */
    private static AuthenticationFailure capacity(String problem, String recovery) { return failure(AuthenticationFailure.Cause.CAPACITY, problem, recovery); }
    /**
     * Constructs a safe typed coordinator result without attaching raw worker exception data.
     *
     * @param cause Typed safe disposition.
     * @param problem Known problem.
     * @param recovery Concrete next action.
     * @return Failure without raw cause.
     */
    private static AuthenticationFailure failure(AuthenticationFailure.Cause cause, String problem, String recovery) { return new AuthenticationFailure(AuthenticationFailure.Phase.QUEUE, cause, problem, recovery); }

    /** Stops admission/timers, releases every caller and revokes publication before shutting down owned executors. */
    @Override public void close() {
        List<Runnable> after = new ArrayList<>();
        synchronized (lock) {
            if (closed) return; closed = true;
            for (State state : states.values()) { state.token.set(null); cancel(state.refresh); if (state.cycle != null) failCycle(state.cycle, closedFailure(), after); }
        }
        after.forEach(Runnable::run); events.close(); runtime.close();
    }

    /**
     * Allows the extension lifecycle to wait briefly for owned browser cleanup before removing native providers.
     * @param millis Maximum elapsed join time; callers must keep this off Swing's EDT.
     */
    public void awaitWorkers(long millis) { runtime.await(Math.max(0, Math.min(5000, millis))); }


}
