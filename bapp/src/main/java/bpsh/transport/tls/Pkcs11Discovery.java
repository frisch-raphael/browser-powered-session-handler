package bpsh.transport.tls;

import bpsh.authentication.AuthenticationFailure;
import com.sun.jna.Function;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;
import com.sun.jna.NativeLong;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.NativeLongByReference;
import com.sun.jna.ptr.PointerByReference;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** PIN-free PKCS#11 discovery through the standard function table; no session, login or finalization calls. */
final class Pkcs11Discovery {
    private static final int MAX_SLOTS = 256;
    private final Map<Path, Module> modules = new ConcurrentHashMap<>();

    /** @param path Canonical middleware file. @return Initialized tokens with their actual slot IDs. @throws Exception On a native discovery error. */
    List<Pkcs11IdentityManager.TokenInfo> tokens(Path path) throws Exception {
        Module module = modules.computeIfAbsent(path, p -> new Module(NativeLibrary.getInstance(p.toString())));
        return module.tokens();
    }

    /** Retains the loaded library while its function pointers are in use; never finalizes another provider's module. */
    private static final class Module {
        private final NativeLibrary library;
        private Function initialize, slots, tokenInfo;

        /** @param library Strong library reference retained for all calls through its function table. */
        Module(NativeLibrary library) { this.library = library; }

        /** @return Stable public token snapshot; concurrent discovery on one module is serialized. @throws Exception On native initialization or enumeration failure. */
        synchronized List<Pkcs11IdentityManager.TokenInfo> tokens() throws Exception {
            if (initialize == null) {
                var pointer = new PointerByReference();
                check(call(library.getFunction("C_GetFunctionList"), pointer));
                Pointer table = pointer.getValue();
                if (table == null || Byte.toUnsignedInt(table.getByte(0)) < 2)
                    throw problem("The middleware does not expose a supported PKCS#11 function table.", "Choose a PKCS#11 version 2 or later middleware library.");
                // Windows Cryptoki structs are packed to one byte; Unix uses native pointer alignment.
                long first = Platform.isWindows() ? 2 : Native.POINTER_SIZE;
                initialize = function(table, first, 0);
                slots = function(table, first, 4);
                tokenInfo = function(table, first, 6);
            }
            try (var args = new Memory(5L * Native.POINTER_SIZE + NativeLong.SIZE)) {
                args.clear(); args.setNativeLong(4L * Native.POINTER_SIZE, new NativeLong(2)); // CKF_OS_LOCKING_OK, no Java callbacks.
                long result = call(initialize, args);
                if (result != 0x191) check(result); // An already initialized module belongs to all of its users.
            }
            for (int attempt = 0; attempt < 3; attempt++) {
                var count = new NativeLongByReference();
                check(call(slots, (byte) 1, null, count));
                long size = unsigned(count.getValue());
                if (size < 0 || size > MAX_SLOTS) throw problem("The middleware reported more slots than device discovery supports.", "Use middleware exposing at most 256 slots.");
                if (size == 0) return List.of();
                try (var ids = new Memory(size * NativeLong.SIZE); var info = new Memory(256)) {
                    long result = call(slots, (byte) 1, ids, count);
                    if (result == 0x150) continue; // Hotplug can grow the list between the two calls.
                    check(result);
                    long actual = unsigned(count.getValue());
                    if (actual < 0 || actual > size) throw problem("The middleware returned an invalid device-list size.", "Check the middleware's compatibility and diagnostics.");
                    var found = new ArrayList<Pkcs11IdentityManager.TokenInfo>();
                    for (int index = 0; index < actual; index++) {
                        NativeLong id = ids.getNativeLong((long) index * NativeLong.SIZE);
                        long slot = unsigned(id);
                        if (slot < 0) throw problem("The middleware returned a device identifier outside Java's supported range.", "");
                        info.clear(); result = call(tokenInfo, id, info);
                        if (result == 0xe0 || result == 0x32 || result == 3) continue; // Token disappeared during discovery.
                        check(result);
                        long flags = unsigned(info.getNativeLong(96));
                        if ((flags & 0x400) == 0) continue; // Empty/uninitialized software-token slots are not usable devices.
                        found.add(new Pkcs11IdentityManager.TokenInfo(slot, text(info, 0, 32), text(info, 32, 32), text(info, 64, 16), text(info, 80, 16)));
                    }
                    return List.copyOf(found);
                }
            }
            throw problem("The list of connected security devices kept changing during discovery.", "Wait for device connections to settle, then choose the certificate again.");
        }
    }

    /** @param table Standard v2-compatible function table. @param first Offset after CK_VERSION. @param index Function ordinal. @return C calling-convention function. */
    private static Function function(Pointer table, long first, int index) throws AuthenticationFailure {
        Pointer pointer = table.getPointer(first + (long) index * Native.POINTER_SIZE);
        if (pointer == null) throw problem("The middleware's PKCS#11 discovery interface is incomplete.", "Choose compatible middleware for the device.");
        return Function.getFunction(pointer, Function.C_CONVENTION);
    }
    /** @param function Native function. @param args ABI-mapped arguments. @return Unsigned CK_RV represented in a Java long. */
    private static long call(Function function, Object... args) { return unsigned((NativeLong) function.invoke(NativeLong.class, args)); }
    /** @param value C unsigned long, 32-bit on Windows and native long elsewhere. @return Unsigned 32-bit value or supported signed-range 64-bit value. */
    private static long unsigned(NativeLong value) { return NativeLong.SIZE == 4 ? Integer.toUnsignedLong(value.intValue()) : value.longValue(); }
    /** @param memory CK_TOKEN_INFO buffer. @param offset Fixed character-field offset. @param length Field length. @return Plain public text without control characters. */
    private static String text(Memory memory, long offset, int length) { return new String(memory.getByteArray(offset, length), StandardCharsets.UTF_8).replaceAll("\\p{Cntrl}", "").strip(); }
    /** @param result Standard numeric PKCS#11 outcome. @throws Exception On any non-success; only fixed symbolic text is propagated. */
    private static void check(long result) throws Exception {
        if (result == 0) return;
        String code = switch ((int) result) {
            case 2 -> "CKR_HOST_MEMORY"; case 3 -> "CKR_SLOT_ID_INVALID"; case 5 -> "CKR_GENERAL_ERROR"; case 6 -> "CKR_FUNCTION_FAILED";
            case 7 -> "CKR_ARGUMENTS_BAD"; case 0xa -> "CKR_CANT_LOCK"; case 0x30 -> "CKR_DEVICE_ERROR"; case 0x31 -> "CKR_DEVICE_MEMORY";
            case 0x32 -> "CKR_DEVICE_REMOVED"; case 0x54 -> "CKR_FUNCTION_NOT_SUPPORTED"; case 0xe0 -> "CKR_TOKEN_NOT_PRESENT";
            case 0xe1 -> "CKR_TOKEN_NOT_RECOGNIZED"; case 0x190 -> "CKR_CRYPTOKI_NOT_INITIALIZED"; default -> null;
        };
        if (code == null || result < 0 || result > 0xffffffffL)
            throw problem("The middleware rejected device discovery (PKCS#11 code 0x" + Long.toUnsignedString(result, 16) + ").", "Check the middleware's own diagnostics for this code.");
        throw new Exception(code);
    }
    /** @param text Controlled discovery observation. @param recovery Supported next action. @return Safe failure with no raw native cause. */
    private static AuthenticationFailure problem(String text, String recovery) { return new AuthenticationFailure(AuthenticationFailure.Phase.PROVIDER, AuthenticationFailure.Cause.CONFIGURATION, text, recovery); }
}
