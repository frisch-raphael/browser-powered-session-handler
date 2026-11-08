package bpsh.browser;

import bpsh.authentication.AuthenticationFailure;
import bpsh.browser.runtime.PlaywrightRecorderAdapter;
import bpsh.journey.JourneyRecording;
import bpsh.journey.SecretStore;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.Frame;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.PlaywrightException;
import com.microsoft.playwright.TimeoutError;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import static bpsh.journey.JourneyRecording.Limits.*;

/** Owns one independent recording worker and an unsaved review, without authentication admission or storage access. */
public final class BrowserJourneyRecorder implements JourneyRecording {
    private final BrowserSessionLauncher launcher;
    private final BrowserSessionLauncher.Visibility visibility;
    private final BiConsumer<BrowserContext, Control> ready;
    private final java.util.concurrent.ExecutorService worker = Executors.newSingleThreadExecutor(task -> {
        var thread = new Thread(task, "bpsh-journey-recorder"); thread.setDaemon(true); return thread;
    });
    private final AtomicReference<Run> active = new AtomicReference<>();
    private final AtomicBoolean closed = new AtomicBoolean();

    /** Production recordings always open a visible browser without changing the saved background setting. */
    public BrowserJourneyRecorder(BrowserSessionLauncher launcher) {
        this(launcher, BrowserSessionLauncher.Visibility.HEADED, (context, control) -> {});
    }

    /** Package-owned qualification seam runs scripted interactions on the actual browser owner, never another thread. */
    BrowserJourneyRecorder(BrowserSessionLauncher launcher, BrowserSessionLauncher.Visibility visibility, BiConsumer<BrowserContext, Control> ready) {
        this.launcher = java.util.Objects.requireNonNull(launcher); this.visibility = visibility; this.ready = ready;
    }

    @Override public Control start(Request request, SecretStore.Values setupValues, Consumer<JourneyRecording.Event> observer) {
        try {
            if (closed.get()) throw new IllegalStateException("Browser recording is closed.");
            if (!setupValues.stepIds().isEmpty()) throw new IllegalArgumentException("Recording setup must not contain previous step secrets.");
            var run = new Run(request, setupValues, observer);
            if (!active.compareAndSet(null, run)) throw new IllegalStateException("Another recording or review is open. Finish or cancel it first.");
            try { worker.execute(run::execute); } catch (RejectedExecutionException error) { active.compareAndSet(run, null); throw new IllegalStateException("The recording worker is unavailable."); }
            return run;
        } catch (RuntimeException error) { setupValues.close(); throw error; }
    }

    private enum Command { STOP, CANCEL }
    private record Source(Frame frame, String pageGuid, long identity, long generation, long order) {}
    private record Pending(PlaywrightRecorderAdapter.Event event, long received) {}
    private static final class FrameState {
        final long identity;
        long generation = 1;
        FrameState(long identity) { this.identity = identity; }
    }

    private final class Run implements Control {
        final Request request;
        final SecretStore.Values setupValues;
        final Consumer<JourneyRecording.Event> observer;
        final AtomicBoolean stopped = new AtomicBoolean(), cancelled = new AtomicBoolean();
        final AtomicLong stopDeadline = new AtomicLong(Long.MAX_VALUE), operationDeadline = new AtomicLong(Long.MAX_VALUE);
        final AtomicReference<Problem> fatal = new AtomicReference<>();
        final ConcurrentLinkedQueue<Command> commands = new ConcurrentLinkedQueue<>();
        final long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(LIFETIME_MS);
        final Map<String, Source> sources = new HashMap<>();
        final Map<Frame, FrameState> frames = new IdentityHashMap<>();
        final Map<String, Frame> previousFrames = new HashMap<>();
        final ArrayDeque<Pending> pending = new ArrayDeque<>();
        volatile Result review;
        RecordedActionCompiler compiler;
        PlaywrightRecorderAdapter adapter;
        BrowserContext context;
        String mainGuid;
        long identities, order;
        int pendingBytes;
        boolean collecting;
        AuthenticationFailure network;

        Run(Request request, SecretStore.Values setupValues, Consumer<JourneyRecording.Event> observer) {
            this.request = java.util.Objects.requireNonNull(request); this.setupValues = setupValues; this.observer = java.util.Objects.requireNonNull(observer);
        }
        @Override public synchronized void stop() {
            if (!stopped.get()) { stopDeadline.set(System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(STOP_MS)); stopped.set(true); commands.add(Command.STOP); }
        }
        @Override public void cancel() {
            if (cancelled.compareAndSet(false, true)) commands.add(Command.CANCEL);
            Result current = review; if (current != null) current.close();
        }
        boolean revoked() {
            long now = System.nanoTime();
            return cancelled.get() || closed.get() || fatal.get() != null || now >= deadline || now >= stopDeadline.get() || now >= operationDeadline.get();
        }
        void event(State state, Result result, Problem problem) {
            try { observer.accept(new JourneyRecording.Event(state, result, problem)); }
            catch (RuntimeException error) { if (result != null) result.close(); }
        }
        void fail(Problem problem) { fatal.compareAndSet(null, problem); }

        void execute() {
            BrowserSessionLauncher.Session session = null; boolean completed = false; Problem failure = null;
            event(State.PREPARING, null, null);
            try {
                try (setupValues) {
                    session = launcher.open(request.identity(), request.setup(), setupValues, visibility, false, deadline, this::revoked, ignored -> {});
                }
                context = session.context(); collecting = true;
                context.onPage(this::pageOpened);
                context.onRequestFailed(failed -> {
                    if (!collecting || !failed.isNavigationRequest()) return;
                    var observed = BrowserFailureClassifier.networkFailure(failed.failure(), request.setup().mtls() != null);
                    if (observed != null && (network == null || observed.priority() < network.priority())) network = observed;
                });
                PlaywrightRecorderAdapter.installMetadata(context, (source, args) -> {
                    if (!collecting) return null;
                    if (source.context() != context || args.length != 1 || !(args[0] instanceof String key) || !key.matches("[A-Za-z0-9_-]{1,128}")) {
                        metadataFailure(); return null;
                    }
                    if (sources.containsKey(key) || sources.size() >= QUEUED_EVENTS) { metadataFailure(); return null; }
                    var state = track(source.frame());
                    sources.put(key, new Source(source.frame(), PlaywrightRecorderAdapter.pageGuid(source.page()), state.identity, state.generation, ++order)); return null;
                });
                adapter = session.driver().recorder(context); adapter.start(remainingAction());
                Page main = context.newPage(); mainGuid = PlaywrightRecorderAdapter.pageGuid(main);
                compiler = new RecordedActionCompiler(mainGuid, request.setup().authenticationUrl().toString());
                compiler.queuedBytes(() -> pendingBytes + adapter.queuedBytes());
                adapter.retainedBudget(() -> Math.max(0, compiler.remainingBytes() - pendingBytes));
                context.setDefaultTimeout(remainingAction()); context.setDefaultNavigationTimeout(remainingAction());
                operationDeadline.set(actionDeadline());
                try { main.navigate(request.setup().authenticationUrl().toString()); }
                finally { operationDeadline.set(Long.MAX_VALUE); }
                if (network != null) throw network;
                collect(false); session.checkTraffic();
                if (revoked()) throw new IllegalStateException("Recording preparation ended.");
                event(State.RECORDING, null, null); ready.accept(context, this);
                while (!revoked() && !stopped.get()) {
                    collect(false); session.checkTraffic();
                    if (network != null) throw network;
                    if (adapter.failure() != null) { compiler.incomplete(adapter.failure()); stop(); break; }
                    pump(PUMP_MS);
                }
                if (cancelled.get() || closed.get() || fatal.get() != null) throw new IllegalStateException("Recording was revoked.");
                if (!stopped.get()) { fail(new Problem(Field.GENERAL, "Recording stopped after its time limit. Record the login again.")); throw new IllegalStateException("Recording expired."); }
                event(State.STOPPING, null, null);
                try {
                    for (var page : List.copyOf(context.pages())) for (var frame : List.copyOf(page.frames())) {
                        if (frame.isDetached() || page.isClosed()) continue;
                        try {
                            var status = PlaywrightRecorderAdapter.metadataStatus(frame, true, remainingStop());
                            if (!status.available() || status.failed() || status.pending() != 0)
                                compiler.incomplete("Some browser actions could not be collected. Record the login again.");
                        } catch (PlaywrightException error) {
                            if (!frame.isDetached() && !page.isClosed()) compiler.incomplete("The recording could not collect the final browser actions. Record the login again.");
                        }
                        collect(false);
                    }
                    adapter.stop(remainingStop());
                    while (!pending.isEmpty() && System.nanoTime() < stopDeadline.get()) { collect(false); if (!pending.isEmpty()) pump(Math.min(25, remainingStop())); }
                    collect(true);
                    if (!sources.isEmpty()) compiler.incomplete("Some browser actions were not delivered before their page closed. Record the login again.");
                } catch (RuntimeException error) { compiler.incomplete("Recording did not finish within five seconds. Record the login again."); }
                if (adapter.failure() != null) compiler.incomplete(adapter.failure());
                session.checkTraffic();
                if (session.transportFailure() != null) throw session.transportFailure();
                completed = !cancelled.get() && !closed.get() && fatal.get() == null;
            } catch (AuthenticationFailure error) {
                failure = network == null ? problem(error) : problem(network);
            } catch (RuntimeException error) {
                failure = network != null ? problem(network) : fatal.get() != null ? fatal.get()
                        : new Problem(Field.GENERAL, "The browser could not finish recording. Record the login again.");
            } finally {
                collecting = false; setupValues.close();
                operationDeadline.set(System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(STOP_MS)); stopDeadline.set(Long.MAX_VALUE);
                if (adapter != null) adapter.close();
                if (session != null) try { session.close(); }
                catch (AuthenticationFailure error) { if (compiler != null && completed) compiler.incomplete(error.getMessage()); else if (failure == null) failure = problem(error); }
                pending.forEach(item -> item.event().close()); pending.clear(); sources.clear(); frames.clear(); previousFrames.clear(); pendingBytes = 0;
            }
            if (completed && compiler != null && !cancelled.get() && !closed.get()) {
                review = compiler.freeze(request.stamp(), () -> active.compareAndSet(this, null));
                if (cancelled.get() || closed.get()) { review.close(); event(State.CLOSED, null, null); }
                else event(State.REVIEW, review, null);
            } else {
                if (compiler != null) compiler.close(); active.compareAndSet(this, null);
                if (System.nanoTime() >= deadline && !cancelled.get() && !closed.get()) failure = new Problem(Field.GENERAL, "Recording stopped after 30 minutes. Record the login again.");
                event(State.CLOSED, null, cancelled.get() || closed.get() ? null : failure);
            }
        }

        private void metadataFailure() {
            if (compiler != null) compiler.incomplete("Browser action metadata was missing or conflicting. Record the login again.");
            else fail(new Problem(Field.GENERAL, "The browser recording could not identify its action sources. Record the login again."));
            stop();
        }
        private FrameState track(Frame frame) {
            var state = frames.get(frame);
            if (state == null) {
                if (frames.size() >= METADATA_FIELDS) { metadataFailure(); return new FrameState(++identities); }
                state = new FrameState(++identities); frames.put(frame, state);
            }
            return state;
        }
        private void pageOpened(Page page) {
            if (!collecting) return;
            String guid = PlaywrightRecorderAdapter.pageGuid(page); track(page.mainFrame());
            if (compiler != null) {
                Page opener = page.opener(); compiler.pageOpened(guid, opener == null ? null : PlaywrightRecorderAdapter.pageGuid(opener), ++order);
            }
            page.onFrameNavigated(frame -> {
                var state = frames.get(frame); if (state != null) state.generation++;
                if (collecting && compiler != null) compiler.navigated(guid, state == null ? 0 : state.identity, frame == page.mainFrame(), ++order);
            });
            page.onFrameDetached(frame -> {
                var state = frames.remove(frame); if (collecting && compiler != null && state != null) compiler.forgetFrame(state.identity);
            });
            page.onClose(ignored -> {
                if (!collecting) return;
                if (compiler != null) {
                    collect(false); compiler.pageClosed(guid);
                    // The pinned programmatic API drops closePage after removing the page from context.pages().
                    // Keep the actual owned lifecycle event in the same ordered queue as native actions.
                    var action = new PlaywrightRecorderAdapter.Action("closePage", null, List.of(), "", 0, "", 0, false, null, null,
                            new PlaywrightRecorderAdapter.Metadata("", "", "", PlaywrightRecorderAdapter.Classification.UNKNOWN), null);
                    var event = new PlaywrightRecorderAdapter.Event(PlaywrightRecorderAdapter.Kind.ADDED, guid, action, 256);
                    if (pending.size() >= QUEUED_EVENTS) { event.close(); metadataFailure(); }
                    else { pending.addLast(new Pending(event, System.nanoTime())); pendingBytes += event.bytes(); collect(false); }
                }
                if (guid.equals(mainGuid)) fail(new Problem(Field.GENERAL, "The initial tab closed before recording finished. Your existing steps were kept."));
            });
        }
        private void collect(boolean finalPass) {
            PlaywrightRecorderAdapter.Event event;
            while ((event = adapter.poll()) != null) {
                if (pending.size() >= QUEUED_EVENTS) { event.close(); metadataFailure(); break; }
                pending.addLast(new Pending(event, System.nanoTime())); pendingBytes += event.bytes();
            }
            while (!pending.isEmpty()) {
                var next = pending.peekFirst(); var action = next.event().action(); String key = action.metadata().sourceKey();
                boolean sourceNeeded = action.selector() != null && !key.isEmpty();
                if (sourceNeeded && !sources.containsKey(key) && !finalPass && System.nanoTime() - next.received() < TimeUnit.MILLISECONDS.toNanos(STOP_MS)) return;
                pending.removeFirst(); pendingBytes -= next.event().bytes();
                try (var captured = next.event()) { compiler.accept(captured, target(captured, sources.remove(key))); }
            }
        }
        private RecordedActionCompiler.Target target(PlaywrightRecorderAdapter.Event event, Source source) {
            if (event.action().selector() == null) return null;
            try {
                if (source != null && !source.pageGuid().equals(event.pageGuid())) return null;
                operationDeadline.set(actionDeadline());
                var parsed = source == null ? BrowserTargets.parse(event.action().selector()) : BrowserTargets.resolve(event.action().selector(), source.frame());
                if (parsed.anyFrame()) return null;
                Frame previous = previousFrames.get(event.pageGuid()); boolean reset = previous != null && previous.isDetached();
                if (source != null) previousFrames.put(event.pageGuid(), source.frame());
                return new RecordedActionCompiler.Target(event.pageGuid(), source == null ? 0 : source.identity(), source == null ? 0 : source.generation(),
                        parsed.frames(), parsed.selector(), source != null, reset, source == null ? 0 : source.order());
            } catch (RuntimeException error) { return null; }
            finally { operationDeadline.set(Long.MAX_VALUE); }
        }
        private long actionDeadline() { return Math.min(deadline, System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(request.setup().browser().navigationTimeoutMs())); }
        private double remainingAction() { return Math.max(1, (actionDeadline() - System.nanoTime()) / 1_000_000.0); }
        private double remainingStop() {
            double remaining = (stopDeadline.get() - System.nanoTime()) / 1_000_000.0;
            if (remaining <= 0) throw new IllegalStateException("The recording Stop budget ended."); return remaining;
        }
        private void pump(double milliseconds) {
            try { context.waitForCondition(() -> revoked() || !commands.isEmpty() || adapter.queuedBytes() > 0,
                    new BrowserContext.WaitForConditionOptions().setTimeout(Math.max(1, milliseconds))); }
            catch (TimeoutError ignored) { /* bounded owner event-pump slice */ }
            Command command; while ((command = commands.poll()) != null) if (command == Command.CANCEL) cancelled.set(true);
        }
    }

    private static Problem problem(AuthenticationFailure failure) {
        Field field = failure.input() == null ? Field.GENERAL : switch (failure.input().input()) {
            case LOGIN_URL -> Field.LOGIN_URL; case PROXY_URL -> Field.PROXY_URL; case MIDDLEWARE -> Field.MIDDLEWARE;
            case SECURITY_DEVICE -> Field.SECURITY_DEVICE; case MTLS_PIN -> Field.PIN; case CERTIFICATE -> Field.CLIENT_CERTIFICATE;
            case TRUSTED_CA -> Field.TRUSTED_CA; default -> Field.GENERAL;
        };
        return new Problem(field, failure.getMessage());
    }
    @Override public void close() {
        if (!closed.compareAndSet(false, true)) return;
        Run run = active.get(); if (run != null) run.cancel(); worker.shutdownNow();
    }
    /** Waits only during owned unload cleanup, never while Swing handles recording commands. */
    public boolean awaitClosed(long timeoutMs) {
        try { return worker.awaitTermination(timeoutMs, TimeUnit.MILLISECONDS); }
        catch (InterruptedException error) { Thread.currentThread().interrupt(); return false; }
    }
}
