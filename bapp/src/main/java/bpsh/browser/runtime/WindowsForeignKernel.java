package bpsh.browser.runtime;

import java.lang.invoke.MethodHandle;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.HashMap;
import java.util.Map;

/**
 * Windows x64 job calls through the stable Java 22 foreign-function API.
 * Public API reflection keeps the extension loadable on Java 21, whose backend is JNA.
 * No dispatch DLL is extracted and no host-wide JNA setting is read or changed.
 */
final class WindowsForeignKernel implements WindowsBrowserJob.Kernel {
    private final Map<String, MethodHandle> calls = new HashMap<>();
    private final Method newArena, allocate, closeArena, address, ofAddress, asBuffer;
    private final long stateBytes, stateAlignment, errorOffset;
    private final ThreadLocal<Integer> lastError = ThreadLocal.withInitial(() -> 0);

    /** Links only the fixed kernel32 entry points used by the containment owner. */
    WindowsForeignKernel() {
        try {
            Class<?> arena = Class.forName("java.lang.foreign.Arena");
            Class<?> segment = Class.forName("java.lang.foreign.MemorySegment");
            Class<?> layout = Class.forName("java.lang.foreign.MemoryLayout");
            Class<?> valueLayout = Class.forName("java.lang.foreign.ValueLayout");
            Class<?> linkerType = Class.forName("java.lang.foreign.Linker");
            Class<?> option = Class.forName("java.lang.foreign.Linker$Option");
            Class<?> lookupType = Class.forName("java.lang.foreign.SymbolLookup");
            Class<?> descriptor = Class.forName("java.lang.foreign.FunctionDescriptor");
            Object pointer = valueLayout.getField("ADDRESS").get(null);
            if ((long) layout.getMethod("byteSize").invoke(pointer) != 8)
                throw new LinkageError("Windows native pointer width is unsupported.");
            Object integer = valueLayout.getField("JAVA_INT").get(null);
            newArena = arena.getMethod("ofConfined"); closeArena = arena.getMethod("close");
            allocate = Class.forName("java.lang.foreign.SegmentAllocator").getMethod("allocate", long.class, long.class);
            address = segment.getMethod("address"); ofAddress = segment.getMethod("ofAddress", long.class);
            asBuffer = segment.getMethod("asByteBuffer");
            Object linker = linkerType.getMethod("nativeLinker").invoke(null);
            // kernel32 is already a Windows runtime dependency. The global arena keeps its lookup valid.
            Object lookup = lookupType.getMethod("libraryLookup", String.class, arena)
                    .invoke(null, "kernel32", arena.getMethod("global").invoke(null));
            Object state = option.getMethod("captureStateLayout").invoke(null);
            stateBytes = (long) layout.getMethod("byteSize").invoke(state);
            stateAlignment = (long) layout.getMethod("byteAlignment").invoke(state);
            Class<?> pathElement = Class.forName("java.lang.foreign.MemoryLayout$PathElement");
            Object path = Array.newInstance(pathElement, 1);
            Array.set(path, 0, pathElement.getMethod("groupElement", String.class).invoke(null, "GetLastError"));
            errorOffset = (long) layout.getMethod("byteOffset", path.getClass()).invoke(state, path);
            Object options = Array.newInstance(option, 1);
            Array.set(options, 0, option.getMethod("captureCallState", String[].class)
                    .invoke(null, (Object) new String[]{"GetLastError"}));
            Method find = lookupType.getMethod("find", String.class);
            Class<?> layoutArray = Array.newInstance(layout, 0).getClass();
            Method describe = descriptor.getMethod("of", layout, layoutArray);
            Method downcall = linkerType.getMethod("downcallHandle", segment, descriptor, options.getClass());
            for (String signature : new String[]{"CreateJobObjectW:PPP", "SetInformationJobObject:IPIPI",
                    "AssignProcessToJobObject:IPP", "TerminateJobObject:IPI", "QueryInformationJobObject:IPIPIP",
                    "OpenProcess:PIII", "IsProcessInJob:IPPP", "WaitForSingleObject:IPI", "CloseHandle:IP"}) {
                String[] parts = signature.split(":"); String types = parts[1];
                Object arguments = Array.newInstance(layout, types.length() - 1);
                for (int i = 1; i < types.length(); i++) Array.set(arguments, i - 1, types.charAt(i) == 'P' ? pointer : integer);
                Object function = describe.invoke(null, types.charAt(0) == 'P' ? pointer : integer, arguments);
                Object symbol = ((java.util.Optional<?>) find.invoke(lookup, parts[0])).orElseThrow();
                calls.put(parts[0], (MethodHandle) downcall.invoke(linker, symbol, function, options));
            }
        } catch (ReflectiveOperationException failure) { throw linkage(failure); }
    }

    /** Calls a fixed signature, copies bounded structs, and snapshots GetLastError before returning to Java. */
    private long call(String name, Object... arguments) {
        Object arena = null;
        try {
            arena = newArena.invoke(null);
            Object state = allocate.invoke(arena, stateBytes, stateAlignment);
            Object[] actual = new Object[arguments.length + 1]; actual[0] = state;
            Map<ByteBuffer, Object> buffers = new java.util.IdentityHashMap<>();
            for (int i = 0; i < arguments.length; i++) {
                Object argument = arguments[i];
                if (argument instanceof Long pointer) actual[i + 1] = ofAddress.invoke(null, pointer.longValue());
                else if (argument instanceof ByteBuffer buffer) {
                    Object nativeBuffer = allocate.invoke(arena, (long) buffer.capacity(), 8L);
                    ((ByteBuffer) asBuffer.invoke(nativeBuffer)).put(buffer.duplicate().clear());
                    buffers.put(buffer, nativeBuffer); actual[i + 1] = nativeBuffer;
                } else actual[i + 1] = argument;
            }
            Object result = calls.get(name).invokeWithArguments(actual);
            lastError.set(((ByteBuffer) asBuffer.invoke(state)).order(ByteOrder.LITTLE_ENDIAN).getInt(Math.toIntExact(errorOffset)));
            for (var entry : buffers.entrySet())
                entry.getKey().duplicate().clear().put((ByteBuffer) asBuffer.invoke(entry.getValue()));
            return result instanceof Integer value ? value.longValue() : (long) address.invoke(result);
        } catch (Throwable failure) { throw linkage(failure); }
        finally {
            if (arena != null) try { closeArena.invoke(arena); }
            catch (ReflectiveOperationException failure) { throw linkage(failure); }
        }
    }

    /** Unwraps public-API reflection without hiding fatal errors or native-access refusal. */
    private static LinkageError linkage(Throwable failure) {
        if (failure instanceof InvocationTargetException invocation) failure = invocation.getCause();
        if (failure instanceof Error error) throw error;
        if (failure instanceof RuntimeException runtime) throw runtime;
        var error = new LinkageError("Windows foreign-function binding failed."); error.initCause(failure); return error;
    }

    @Override public long CreateJobObjectW(long attributes, long name) { return call("CreateJobObjectW", attributes, name); }
    @Override public boolean SetInformationJobObject(long job, int kind, ByteBuffer data, int bytes) { return call("SetInformationJobObject", job, kind, data, bytes) != 0; }
    @Override public boolean AssignProcessToJobObject(long job, long process) { return call("AssignProcessToJobObject", job, process) != 0; }
    @Override public boolean TerminateJobObject(long job, int code) { return call("TerminateJobObject", job, code) != 0; }
    @Override public boolean QueryInformationJobObject(long job, int kind, ByteBuffer data, int bytes, long returned) { return call("QueryInformationJobObject", job, kind, data, bytes, returned) != 0; }
    @Override public long OpenProcess(int access, boolean inherit, int pid) { return call("OpenProcess", access, inherit ? 1 : 0, pid); }
    @Override public boolean IsProcessInJob(long process, long job, ByteBuffer included) { return call("IsProcessInJob", process, job, included) != 0; }
    @Override public int WaitForSingleObject(long handle, int milliseconds) { return (int) call("WaitForSingleObject", handle, milliseconds); }
    @Override public boolean CloseHandle(long handle) { return call("CloseHandle", handle) != 0; }
    @Override public int GetLastError() { return lastError.get(); }
}
