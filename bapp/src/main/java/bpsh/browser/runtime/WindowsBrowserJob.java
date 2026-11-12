package bpsh.browser.runtime;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.win32.StdCallLibrary;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

/** Owns a Windows driver tree without relying on access to sandboxed child process handles. */
final class WindowsBrowserJob {
    /** Kill all job members when its last, noninherited handle closes. */
    private static final int KILL_ON_CLOSE = 0x2000;
    /** Exact x64 JOBOBJECT_EXTENDED_LIMIT_INFORMATION size and LimitFlags offset. */
    private static final int EXTENDED_LIMIT_BYTES = 144, LIMIT_FLAGS_OFFSET = 16;
    /** Exact JOBOBJECT_BASIC_ACCOUNTING_INFORMATION size and ActiveProcesses offset. */
    private static final int ACCOUNTING_BYTES = 48, ACTIVE_PROCESSES_OFFSET = 40;
    private final Kernel kernel;
    private final java.util.Map<Long, Pointer> members = new java.util.LinkedHashMap<>();
    private Pointer handle;

    /** Kernel entry points; this interface is loaded only on Windows. */
    interface Kernel extends StdCallLibrary {
        Pointer CreateJobObjectW(Pointer attributes, Pointer name);
        boolean SetInformationJobObject(Pointer job, int kind, Pointer information, int bytes);
        boolean AssignProcessToJobObject(Pointer job, Pointer process);
        boolean TerminateJobObject(Pointer job, int exitCode);
        boolean QueryInformationJobObject(Pointer job, int kind, Pointer information, int bytes, Pointer returned);
        Pointer OpenProcess(int access, boolean inherit, int processId);
        boolean IsProcessInJob(Pointer process, Pointer job, IntByReference included);
        int WaitForSingleObject(Pointer handle, int milliseconds);
        boolean CloseHandle(Pointer handle);
        int GetLastError();
    }

    /** Defers native library loading until an actual Windows attempt. */
    private static final class Binding {
        static final Kernel KERNEL = Native.load("kernel32", Kernel.class);
    }

    /** @param kernel Native boundary. @param handle Unnamed, attempt-owned job. */
    private WindowsBrowserJob(Kernel kernel, Pointer handle) { this.kernel = kernel; this.handle = handle; }

    /**
     * Assigns the newly started driver before its protocol can launch a browser.
     * @param process Exact Process created by this attempt, never an enumerated PID.
     * @return Owned job on Windows, or null on another supported platform.
     * @throws IOException If containment cannot be established.
     */
    static WindowsBrowserJob attach(Process process) throws IOException {
        if (!Platform.isWindows()) return null;
        if (Native.POINTER_SIZE != 8) throw new IOException("Windows browser containment requires x64.");
        Kernel kernel = Binding.KERNEL;
        Pointer job = kernel.CreateJobObjectW(null, null);
        if (job == null) throw error(kernel, "create");
        boolean assigned = false;
        try (Memory limits = new Memory(EXTENDED_LIMIT_BYTES)) {
            limits.clear(); limits.setInt(LIMIT_FLAGS_OFFSET, KILL_ON_CLOSE);
            if (!kernel.SetInformationJobObject(job, 9, limits, EXTENDED_LIMIT_BYTES)) throw error(kernel, "configure");
            // AssignProcessToJobObject requires SET_QUOTA and TERMINATE, not access to child processes.
            Pointer driver = kernel.OpenProcess(0x0100 | 0x0001, false, Math.toIntExact(process.pid()));
            if (driver == null) throw error(kernel, "open driver");
            try {
                if (!kernel.AssignProcessToJobObject(job, driver)) throw error(kernel, "assign driver");
                assigned = true;
                return new WindowsBrowserJob(kernel, job);
            } finally { kernel.CloseHandle(driver); }
        } finally { if (!assigned) kernel.CloseHandle(job); }
    }

    /**
     * Terminates and observes the entire job within the caller's existing cleanup budget.
     * @param deadline Absolute monotonic process-cleanup deadline.
     * @throws IOException If termination, accounting, or handle release fails.
     */
    synchronized void close(long deadline) throws IOException {
        if (handle == null) return;
        boolean interrupted = Thread.interrupted();
        IOException problem = null;
        try {
            captureMembers();
            if (!kernel.TerminateJobObject(handle, 1)) throw error(kernel, "terminate");
            for (Pointer member : members.values()) {
                int remaining = (int) Math.max(0, Math.min(Integer.MAX_VALUE,
                        TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime())));
                int outcome = kernel.WaitForSingleObject(member, remaining);
                if (outcome != 0) throw new IOException("Windows browser termination did not complete within the cleanup budget.");
            }
            try (Memory accounting = new Memory(ACCOUNTING_BYTES)) {
                while (true) {
                    accounting.clear();
                    if (!kernel.QueryInformationJobObject(handle, 1, accounting, ACCOUNTING_BYTES, null)) throw error(kernel, "observe termination");
                    if (accounting.getInt(ACTIVE_PROCESSES_OFFSET) == 0) break;
                    if (deadline - System.nanoTime() <= 0) throw new IOException("Windows browser processes did not terminate within the cleanup budget.");
                    try { TimeUnit.MILLISECONDS.sleep(10); } catch (InterruptedException stopped) { interrupted = true; }
                }
            }
        } catch (IOException failure) { problem = failure; }
        finally {
            for (Pointer member : members.values())
                if (!kernel.CloseHandle(member) && problem == null) problem = error(kernel, "release process");
            members.clear();
            Pointer owned = handle; handle = null;
            if (!kernel.CloseHandle(owned) && problem == null) problem = error(kernel, "release");
            if (interrupted) Thread.currentThread().interrupt();
        }
        if (problem != null) throw problem;
    }

    /**
     * Retains synchronization handles before protocol shutdown can detach children.
     * @throws IOException If job membership cannot be safely observed.
     */
    synchronized void captureMembers() throws IOException {
        if (handle == null) return;
        // The selected Windows runtime is x64. The first two DWORDs precede ULONG_PTR member IDs.
        try (Memory list = new Memory(128 * 1024)) {
            list.clear();
            if (!kernel.QueryInformationJobObject(handle, 3, list, (int) list.size(), null)) throw error(kernel, "enumerate members");
            int count = list.getInt(4);
            if (count < 0 || count > (list.size() - 8) / 8) throw new IOException("Windows browser membership exceeds the observation bound.");
            for (int index = 0; index < count; index++) {
                long pid = list.getLong(8L + index * 8L);
                if (members.containsKey(pid)) continue;
                // Avoid the additional process-duplication rights requested by the JDK implementation.
                Pointer process = kernel.OpenProcess(0x00100000 | 0x1000, false, Math.toIntExact(pid));
                if (process == null) {
                    if (kernel.GetLastError() == 87) continue; // Member exited before its handle was opened.
                    throw error(kernel, "observe member");
                }
                var included = new IntByReference();
                if (!kernel.IsProcessInJob(process, handle, included)) {
                    IOException failure = error(kernel, "verify member"); kernel.CloseHandle(process); throw failure;
                }
                if (included.getValue() != 0) members.put(pid, process);
                else kernel.CloseHandle(process); // A reused PID outside this job is never retained or terminated.
            }
        }
    }

    /** @param kernel Native boundary. @param operation Fixed operation label. @return No arguments or profile data. */
    private static IOException error(Kernel kernel, String operation) {
        return new IOException("Windows browser containment could not " + operation + " (" + kernel.GetLastError() + ").");
    }
}
