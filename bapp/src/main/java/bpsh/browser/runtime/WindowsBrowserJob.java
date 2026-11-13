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

    /** Closed attribution labels; none contain process, profile or vendor-provided text. */
    enum Operation {
        /** Unsupported native pointer width. */ UNSUPPORTED_PLATFORM,
        /** Job creation. */ CREATE,
        /** Job limit configuration. */ CONFIGURE,
        /** Opening the exact owned driver. */ OPEN_DRIVER,
        /** Assigning that driver to this job. */ ASSIGN_DRIVER,
        /** Querying member identifiers. */ ENUMERATE_MEMBERS,
        /** Member count exceeds the existing fixed buffer. */ MEMBER_BOUND,
        /** Opening a reported member for observation. */ OPEN_MEMBER,
        /** Verifying a member still belongs to this job. */ VERIFY_MEMBER,
        /** Terminating the job. */ TERMINATE,
        /** Waiting for a verified member. */ WAIT_MEMBER,
        /** Querying remaining active processes. */ OBSERVE_TERMINATION,
        /** Active processes remain at the existing deadline. */ DRAIN_DEADLINE,
        /** Releasing a captured member handle. */ RELEASE_MEMBER,
        /** Releasing the job handle. */ RELEASE_JOB,
        /** Unattributed observation failure; original throwable is discarded. */ OBSERVATION_UNATTRIBUTED,
        /** Unattributed close failure; original throwable is discarded. */ CLOSE_UNATTRIBUTED
    }

    /** Fixed operation and unsigned native results only; no original throwable is retained. */
    static final class Failure extends IOException {
        /** Serialization identity for this bounded diagnostic type. */
        private static final long serialVersionUID = 1L;
        /** Exact authored operation. */
        final Operation operation;
        /** Optional unsigned GetLastError value. */
        final Long nativeCode;
        /** Optional unsigned WaitForSingleObject result. */
        final Long waitResult;
        /** Whether the existing wait or accounting deadline elapsed. */
        final boolean deadline;

        /**
         * Creates a bounded diagnostic without accepting vendor text or causes.
         * @param operation Closed authored operation.
         * @param nativeCode Optional unsigned DWORD error code.
         * @param waitResult Optional unsigned DWORD wait result.
         * @param deadline Whether the existing deadline elapsed.
         */
        Failure(Operation operation, Long nativeCode, Long waitResult, boolean deadline) {
            super(message(operation, nativeCode, waitResult, deadline));
            this.operation = operation; this.nativeCode = nativeCode; this.waitResult = waitResult; this.deadline = deadline;
        }

        /**
         * Validates numeric bounds before constructing the fixed message.
         * @param operation Closed authored operation.
         * @param nativeCode Optional unsigned DWORD error code.
         * @param waitResult Optional unsigned DWORD wait result.
         * @param deadline Whether the existing deadline elapsed.
         * @return Fixed labels and numeric values only.
         */
        private static String message(Operation operation, Long nativeCode, Long waitResult, boolean deadline) {
            java.util.Objects.requireNonNull(operation);
            for (Long value : new Long[]{nativeCode, waitResult})
                if (value != null && (value < 0 || value > 0xffff_ffffL)) throw new IllegalArgumentException("WINDOWS_JOB_DIAGNOSTIC_BOUNDS");
            return "Windows browser containment: " + operation.name() + "; nativeCode=" + nativeCode
                    + "; waitResult=" + waitResult + "; deadline=" + deadline + ".";
        }
    }

    /** Keeps at most one sanitized observation failure and one sanitized close failure per session. */
    static final class Diagnostics {
        /** First observation failure, independent of later repeated observations. */
        private Failure observation;
        /** First native close failure. */
        private Failure close;
        /** Prevents repeated attachment from growing the suppression list. */
        private boolean attached;

        /** @param failure Observation failure; only known fixed fields are copied. */
        void observation(Throwable failure) {
            if (observation == null) observation = copy(failure, Operation.OBSERVATION_UNATTRIBUTED);
        }
        /** @param failure Close failure; only known fixed fields are copied. */
        void close(Throwable failure) {
            if (close == null) close = copy(failure, Operation.CLOSE_UNATTRIBUTED);
        }
        /** @param target Existing lifecycle failure receiving at most two sanitized suppressed causes. */
        void suppressOn(Throwable target) {
            if (attached) return;
            attached = true;
            if (observation != null) target.addSuppressed(observation);
            if (close != null) target.addSuppressed(close);
        }
        /**
         * Copies fixed fields rather than retaining even a known exception's cause or suppression graph.
         * @param failure Borrowed failure, never stored.
         * @param fallback Closed operation used for every unknown vendor failure.
         * @return Independent fixed diagnostic with no cause or suppressed exceptions.
         */
        private static Failure copy(Throwable failure, Operation fallback) {
            return failure instanceof Failure known
                    ? new Failure(known.operation, known.nativeCode, known.waitResult, known.deadline)
                    : new Failure(fallback, null, null, false);
        }
    }

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

    /** Initializes required Windows native support before a driver process can be started. */
    static void initialize() throws IOException {
        if (!Platform.isWindows()) return;
        if (Native.POINTER_SIZE != 8) throw new Failure(Operation.UNSUPPORTED_PLATFORM, null, null, false);
        java.util.Objects.requireNonNull(Binding.KERNEL);
    }

    /** @param kernel Native boundary. @param handle Unnamed, attempt-owned job. */
    WindowsBrowserJob(Kernel kernel, Pointer handle) { this.kernel = kernel; this.handle = handle; }

    /**
     * Assigns the newly started driver before its protocol can launch a browser.
     * @param process Exact Process created by this attempt, never an enumerated PID.
     * @return Owned job on Windows, or null on another supported platform.
     * @throws IOException If containment cannot be established.
     */
    static WindowsBrowserJob attach(Process process) throws IOException {
        if (!Platform.isWindows()) return null;
        if (Native.POINTER_SIZE != 8) throw new Failure(Operation.UNSUPPORTED_PLATFORM, null, null, false);
        Kernel kernel = Binding.KERNEL;
        Pointer job = kernel.CreateJobObjectW(null, null);
        if (job == null) throw error(kernel, Operation.CREATE);
        boolean assigned = false;
        try (Memory limits = new Memory(EXTENDED_LIMIT_BYTES)) {
            limits.clear(); limits.setInt(LIMIT_FLAGS_OFFSET, KILL_ON_CLOSE);
            if (!kernel.SetInformationJobObject(job, 9, limits, EXTENDED_LIMIT_BYTES)) throw error(kernel, Operation.CONFIGURE);
            // AssignProcessToJobObject requires SET_QUOTA and TERMINATE, not access to child processes.
            Pointer driver = kernel.OpenProcess(0x0100 | 0x0001, false, Math.toIntExact(process.pid()));
            if (driver == null) throw error(kernel, Operation.OPEN_DRIVER);
            try {
                if (!kernel.AssignProcessToJobObject(job, driver)) throw error(kernel, Operation.ASSIGN_DRIVER);
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
            if (!kernel.TerminateJobObject(handle, 1)) throw error(kernel, Operation.TERMINATE);
            for (Pointer member : members.values()) {
                int remaining = (int) Math.max(0, Math.min(Integer.MAX_VALUE,
                        TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime())));
                int outcome = kernel.WaitForSingleObject(member, remaining);
                if (outcome != 0) throw new Failure(Operation.WAIT_MEMBER,
                        outcome == -1 ? Integer.toUnsignedLong(kernel.GetLastError()) : null,
                        Integer.toUnsignedLong(outcome), outcome == 258);
            }
            try (Memory accounting = new Memory(ACCOUNTING_BYTES)) {
                while (true) {
                    accounting.clear();
                    if (!kernel.QueryInformationJobObject(handle, 1, accounting, ACCOUNTING_BYTES, null)) throw error(kernel, Operation.OBSERVE_TERMINATION);
                    if (accounting.getInt(ACTIVE_PROCESSES_OFFSET) == 0) break;
                    if (deadline - System.nanoTime() <= 0) throw new Failure(Operation.DRAIN_DEADLINE, null, null, true);
                    try { TimeUnit.MILLISECONDS.sleep(10); } catch (InterruptedException stopped) { interrupted = true; }
                }
            }
        } catch (IOException failure) { problem = failure; }
        finally {
            for (Pointer member : members.values())
                if (!kernel.CloseHandle(member) && problem == null) problem = error(kernel, Operation.RELEASE_MEMBER);
            members.clear();
            Pointer owned = handle; handle = null;
            if (!kernel.CloseHandle(owned) && problem == null) problem = error(kernel, Operation.RELEASE_JOB);
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
            if (!kernel.QueryInformationJobObject(handle, 3, list, (int) list.size(), null)) throw error(kernel, Operation.ENUMERATE_MEMBERS);
            int count = list.getInt(4);
            if (count < 0 || count > (list.size() - 8) / 8) throw new Failure(Operation.MEMBER_BOUND, null, null, false);
            for (int index = 0; index < count; index++) {
                long pid = list.getLong(8L + index * 8L);
                if (members.containsKey(pid)) continue;
                // Avoid the additional process-duplication rights requested by the JDK implementation.
                Pointer process = kernel.OpenProcess(0x00100000 | 0x1000, false, Math.toIntExact(pid));
                if (process == null) {
                    int nativeCode = kernel.GetLastError();
                    if (nativeCode == 87) continue; // Member exited before its handle was opened.
                    throw new Failure(Operation.OPEN_MEMBER, Integer.toUnsignedLong(nativeCode), null, false);
                }
                var included = new IntByReference();
                if (!kernel.IsProcessInJob(process, handle, included)) {
                    IOException failure = error(kernel, Operation.VERIFY_MEMBER); kernel.CloseHandle(process); throw failure;
                }
                if (included.getValue() != 0) members.put(pid, process);
                else kernel.CloseHandle(process); // A reused PID outside this job is never retained or terminated.
            }
        }
    }

    /** @param kernel Native boundary. @param operation Fixed operation label. @return No arguments or profile data. */
    private static Failure error(Kernel kernel, Operation operation) {
        return new Failure(operation, Integer.toUnsignedLong(kernel.GetLastError()), null, false);
    }
}
