package bpsh.authentication.session;

import java.time.Instant;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/** Owns one scheduling thread and exactly two bounded daemon browser workers. */
final class ExecutorAuthenticationRuntime implements AuthenticationCoordinator.Runtime {
    private final ScheduledThreadPoolExecutor scheduler = new ScheduledThreadPoolExecutor(1, r -> daemon(r, "bpsh-auth-clock"));
    private final ThreadPoolExecutor workers = new ThreadPoolExecutor(AuthenticationCoordinator.WORKERS, AuthenticationCoordinator.WORKERS, 0, TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<>(AuthenticationCoordinator.WORKERS), r -> daemon(r, "bpsh-auth-browser"), new ThreadPoolExecutor.AbortPolicy());
    /** Enables removal of cancelled timers so edited/finished callers do not retain scheduler entries. */
    ExecutorAuthenticationRuntime() { scheduler.setRemoveOnCancelPolicy(true); }
    /**
     * Returns real monotonic reading shared with BrowserFlowRunner.
     *
     * @return Real monotonic reading shared with BrowserFlowRunner.
     */
    @Override public long nanos() { return System.nanoTime(); }
    /**
     * Returns current JVM wall-clock instant.
     *
     * @return Current JVM wall-clock instant.
     */
    @Override public Instant instant() { return Instant.now(); }
    /**
     * Schedules one cancellable lifecycle callback without executing it inline on the caller.
     *
     * @param task Deferred lifecycle callback.
     * @param delayNanos Nonnegative delay.
     * @return Owned cancellation handle.
     */
    @Override public AuthenticationCoordinator.Timer schedule(Runnable task, long delayNanos) { var future = scheduler.schedule(task, Math.max(0, delayNanos), TimeUnit.NANOSECONDS); return () -> future.cancel(false); }
    /**
     * Submits one admitted attempt to the owned bounded browser-worker service.
     *
     * @param task Admitted attempt to run on a bounded worker.
     */
    @Override public void work(Runnable task) { workers.execute(task); }
    /** Stops only owned services; running browser cleanup cooperates through the revoked epoch. */
    @Override public void close() { scheduler.shutdownNow(); workers.shutdown(); }
    /** @param millis Off-EDT total budget for observing worker and clock termination. */
    @Override public void await(long millis) {
        long end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(millis);
        try {
            for (var executor : java.util.List.of(workers, scheduler))
                if (!executor.awaitTermination(Math.max(0, end - System.nanoTime()), TimeUnit.NANOSECONDS))
                    throw new IllegalStateException("Authentication workers did not terminate within the cleanup budget.");
        } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw new IllegalStateException("Authentication cleanup was interrupted."); }
    }
    /**
     * Creates an extension-owned daemon thread without taking ownership of the host JVM lifecycle.
     *
     * @param task Owned service task.
     * @param name Safe thread label.
     * @return Daemon thread without host lifecycle ownership.
     */
    private static Thread daemon(Runnable task, String name) { Thread thread = new Thread(task, name); thread.setDaemon(true); return thread; }
}
