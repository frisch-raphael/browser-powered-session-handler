package bpsh.transport.tls;

import java.util.concurrent.TimeUnit;

/** Terminates only owned middleware helpers and observes their exit within one cleanup budget. */
final class Pkcs11Processes {
    private Pkcs11Processes() {}
    /** Cleanup observes termination even when the worker entered with its interrupt flag set. */
    static void stop(Process process) {
        if (process == null) return;
        boolean interrupted = Thread.interrupted();
        long end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(2500);
        try {
            var descendants = process.descendants().toList();
            descendants.forEach(ProcessHandle::destroyForcibly);
            if (process.isAlive()) process.destroyForcibly();
            if (!process.waitFor(Math.max(0, end - System.nanoTime()), TimeUnit.NANOSECONDS))
                throw new IllegalStateException("The owned security-device helper did not terminate.");
            for (var child : descendants) if (child.isAlive()) child.onExit().get(Math.max(1, end - System.nanoTime()), TimeUnit.NANOSECONDS);
        } catch (InterruptedException stopped) {
            interrupted = true; throw new IllegalStateException("Security-device cleanup was interrupted.");
        } catch (java.util.concurrent.ExecutionException | java.util.concurrent.TimeoutException failure) {
            throw new IllegalStateException("An owned security-device descendant did not terminate.");
        } finally { if (interrupted) Thread.currentThread().interrupt(); }
    }
}
