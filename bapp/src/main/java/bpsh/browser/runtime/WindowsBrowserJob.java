package bpsh.browser.runtime;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
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
    private final java.util.Map<Long, Long> members = new java.util.LinkedHashMap<>();
    private long handle;

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

    /** Native boundary with Java-owned buffers and opaque x64 handle values. */
    interface Kernel {
        long CreateJobObjectW(long attributes, long name);
        boolean SetInformationJobObject(long job, int kind, ByteBuffer information, int bytes);
        boolean AssignProcessToJobObject(long job, long process);
        boolean TerminateJobObject(long job, int exitCode);
        boolean QueryInformationJobObject(long job, int kind, ByteBuffer information, int bytes, long returned);
        long OpenProcess(int access, boolean inherit, int processId);
        boolean IsProcessInJob(long process, long job, ByteBuffer included);
        int WaitForSingleObject(long handle, int milliseconds);
        boolean CloseHandle(long handle);
        int GetLastError();
    }

    /** Defers native linking until a Windows attempt; Java 22+ never loads JNA here. */
    private static final class Binding {
        static final Kernel KERNEL = Runtime.version().feature() >= 22 ? new WindowsForeignKernel() : new WindowsJnaKernel();
    }

    /** Initializes required Windows native support before a driver process can be started. */
    static void initialize() throws IOException {
        if (!isWindows()) return;
        if (!System.getProperty("os.arch", "").matches("amd64|x86_64"))
            throw new Failure(Operation.UNSUPPORTED_PLATFORM, null, null, false);
        java.util.Objects.requireNonNull(Binding.KERNEL);
    }

    /** @return Whether this attempt needs Windows native containment. */
    private static boolean isWindows() { return System.getProperty("os.name", "").startsWith("Windows"); }

    /** @param bytes Bounded Windows struct size. @return Zeroed little-endian struct storage. */
    private static ByteBuffer buffer(int bytes) { return ByteBuffer.allocate(bytes).order(ByteOrder.LITTLE_ENDIAN); }

    /** @param kernel Native boundary. @param handle Unnamed, attempt-owned job. */
    WindowsBrowserJob(Kernel kernel, long handle) { this.kernel = kernel; this.handle = handle; }

    /**
     * Assigns the newly started driver before its protocol can launch a browser.
     * @param process Exact Process created by this attempt, never an enumerated PID.
     * @return Owned job on Windows, or null on another supported platform.
     * @throws IOException If containment cannot be established.
     */
    static WindowsBrowserJob attach(Process process) throws IOException {
        if (!isWindows()) return null;
        initialize();
        Kernel kernel = Binding.KERNEL;
        long job = kernel.CreateJobObjectW(0, 0);
        if (job == 0) throw error(kernel, Operation.CREATE);
        boolean assigned = false;
        try {
            ByteBuffer limits = buffer(EXTENDED_LIMIT_BYTES);
            limits.putInt(LIMIT_FLAGS_OFFSET, KILL_ON_CLOSE);
            if (!kernel.SetInformationJobObject(job, 9, limits, EXTENDED_LIMIT_BYTES)) throw error(kernel, Operation.CONFIGURE);
            // AssignProcessToJobObject requires SET_QUOTA and TERMINATE, not access to child processes.
            long driver = kernel.OpenProcess(0x0100 | 0x0001, false, Math.toIntExact(process.pid()));
            if (driver == 0) throw error(kernel, Operation.OPEN_DRIVER);
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
        if (handle == 0) return;
        boolean interrupted = Thread.interrupted();
        IOException problem = null;
        try {
            captureMembers();
            if (!kernel.TerminateJobObject(handle, 1)) throw error(kernel, Operation.TERMINATE);
            for (long member : members.values()) {
                int remaining = (int) Math.max(0, Math.min(Integer.MAX_VALUE,
                        TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime())));
                int outcome = kernel.WaitForSingleObject(member, remaining);
                if (outcome != 0) throw new Failure(Operation.WAIT_MEMBER,
                        outcome == -1 ? Integer.toUnsignedLong(kernel.GetLastError()) : null,
                        Integer.toUnsignedLong(outcome), outcome == 258);
            }
            {
                ByteBuffer accounting = buffer(ACCOUNTING_BYTES);
                while (true) {
                    if (!kernel.QueryInformationJobObject(handle, 1, accounting, ACCOUNTING_BYTES, 0)) throw error(kernel, Operation.OBSERVE_TERMINATION);
                    if (accounting.getInt(ACTIVE_PROCESSES_OFFSET) == 0) break;
                    if (deadline - System.nanoTime() <= 0) throw new Failure(Operation.DRAIN_DEADLINE, null, null, true);
                    try { TimeUnit.MILLISECONDS.sleep(10); } catch (InterruptedException stopped) { interrupted = true; }
                }
            }
        } catch (IOException failure) { problem = failure; }
        finally {
            for (long member : members.values())
                if (!kernel.CloseHandle(member) && problem == null) problem = error(kernel, Operation.RELEASE_MEMBER);
            members.clear();
            long owned = handle; handle = 0;
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
        if (handle == 0) return;
        // The selected Windows runtime is x64. The first two DWORDs precede ULONG_PTR member IDs.
        {
            ByteBuffer list = buffer(128 * 1024);
            if (!kernel.QueryInformationJobObject(handle, 3, list, list.capacity(), 0)) throw error(kernel, Operation.ENUMERATE_MEMBERS);
            int count = list.getInt(4);
            if (count < 0 || count > (list.capacity() - 8) / 8) throw new Failure(Operation.MEMBER_BOUND, null, null, false);
            for (int index = 0; index < count; index++) {
                long pid = list.getLong(8 + index * 8);
                if (members.containsKey(pid)) continue;
                // Avoid the additional process-duplication rights requested by the JDK implementation.
                long process = kernel.OpenProcess(0x00100000 | 0x1000, false, Math.toIntExact(pid));
                if (process == 0) {
                    int nativeCode = kernel.GetLastError();
                    if (nativeCode == 87) continue; // Member exited before its handle was opened.
                    throw new Failure(Operation.OPEN_MEMBER, Integer.toUnsignedLong(nativeCode), null, false);
                }
                var included = buffer(4);
                if (!kernel.IsProcessInJob(process, handle, included)) {
                    IOException failure = error(kernel, Operation.VERIFY_MEMBER); kernel.CloseHandle(process); throw failure;
                }
                if (included.getInt(0) != 0) members.put(pid, process);
                else kernel.CloseHandle(process); // A reused PID outside this job is never retained or terminated.
            }
        }
    }

    /** @param kernel Native boundary. @param operation Fixed operation label. @return No arguments or profile data. */
    private static Failure error(Kernel kernel, Operation operation) {
        return new Failure(operation, Integer.toUnsignedLong(kernel.GetLastError()), null, false);
    }
}
