package bpsh.browser.runtime;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.win32.StdCallLibrary;
import java.nio.ByteBuffer;

/** Java 21 compatibility binding; newer Java runtimes do not initialize JNA for browser containment. */
final class WindowsJnaKernel implements WindowsBrowserJob.Kernel {
    private final Api api;
    /** Initializes only on the Java 21 compatibility path. */
    WindowsJnaKernel() {
        if (Native.POINTER_SIZE != 8) throw new LinkageError("Windows native pointer width is unsupported.");
        api = Native.load("kernel32", Api.class);
    }
    /** Exact Windows x64 signatures; native pointer types stay inside this compatibility implementation. */
    interface Api extends StdCallLibrary {
        Pointer CreateJobObjectW(Pointer attributes, Pointer name);
        boolean SetInformationJobObject(Pointer job, int kind, Pointer information, int bytes);
        boolean AssignProcessToJobObject(Pointer job, Pointer process);
        boolean TerminateJobObject(Pointer job, int exitCode);
        boolean QueryInformationJobObject(Pointer job, int kind, Pointer information, int bytes, Pointer returned);
        Pointer OpenProcess(int access, boolean inherit, int processId);
        boolean IsProcessInJob(Pointer process, Pointer job, Pointer included);
        int WaitForSingleObject(Pointer handle, int milliseconds);
        boolean CloseHandle(Pointer handle);
        int GetLastError();
    }
    private final ThreadLocal<Integer> lastError = ThreadLocal.withInitial(() -> 0);
    /** Copies a bounded job struct into attempt-local native memory. */
    private static Memory memory(ByteBuffer source) {
        var result = new Memory(source.capacity());
        result.getByteBuffer(0, source.capacity()).put(source.duplicate().clear()); return result;
    }
    /** Snapshots last error before memory release or another native operation can change it. */
    private boolean result(boolean value) { lastError.set(api.GetLastError()); return value; }
    @Override public long CreateJobObjectW(long attributes, long name) { Pointer value = api.CreateJobObjectW(new Pointer(attributes), new Pointer(name)); lastError.set(api.GetLastError()); return Pointer.nativeValue(value); }
    @Override public boolean SetInformationJobObject(long job, int kind, ByteBuffer data, int bytes) { try (Memory nativeData = memory(data)) { return result(api.SetInformationJobObject(new Pointer(job), kind, nativeData, bytes)); } }
    @Override public boolean AssignProcessToJobObject(long job, long process) { return result(api.AssignProcessToJobObject(new Pointer(job), new Pointer(process))); }
    @Override public boolean TerminateJobObject(long job, int code) { return result(api.TerminateJobObject(new Pointer(job), code)); }
    @Override public boolean QueryInformationJobObject(long job, int kind, ByteBuffer data, int bytes, long returned) { try (Memory nativeData = memory(data)) { boolean success = result(api.QueryInformationJobObject(new Pointer(job), kind, nativeData, bytes, new Pointer(returned))); data.duplicate().clear().put(nativeData.getByteBuffer(0, data.capacity())); return success; } }
    @Override public long OpenProcess(int access, boolean inherit, int pid) { Pointer value = api.OpenProcess(access, inherit, pid); lastError.set(api.GetLastError()); return Pointer.nativeValue(value); }
    @Override public boolean IsProcessInJob(long process, long job, ByteBuffer included) { try (Memory nativeData = memory(included)) { boolean success = result(api.IsProcessInJob(new Pointer(process), new Pointer(job), nativeData)); included.duplicate().clear().put(nativeData.getByteBuffer(0, included.capacity())); return success; } }
    @Override public int WaitForSingleObject(long handle, int milliseconds) { int value = api.WaitForSingleObject(new Pointer(handle), milliseconds); lastError.set(api.GetLastError()); return value; }
    @Override public boolean CloseHandle(long handle) { return result(api.CloseHandle(new Pointer(handle))); }
    @Override public int GetLastError() { return lastError.get(); }
}
