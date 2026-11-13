package bpsh.browser.runtime;

import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Native-loader text is converted to closed reasons, never copied into product diagnostics. */
class NativeLoadReasonTest {
    @Test void recognizesLoaderReasonsWithoutReturningPathsOrVendorText() {
        var cases = List.of(
                new Case("Native Library fixture-secret already loaded in another classloader", NativeLoadReason.CLASSLOADER_CONFLICT),
                new Case("JNA temporary directory 'fixture-secret' is not writable", NativeLoadReason.TEMP_DIRECTORY),
                new Case("Failed to create temporary file for jnidispatch library: fixture-secret", NativeLoadReason.TEMP_DIRECTORY),
                new Case("Native library (com/sun/jna/win32-x86-64/jnidispatch.dll) not found in resource path (fixture-secret)", NativeLoadReason.RESOURCE_MISSING),
                new Case("fixture-secret: This program is blocked by group policy", NativeLoadReason.POLICY_BLOCKED),
                new Case("fixture-secret: Ce programme est bloqué par une stratégie de groupe", NativeLoadReason.POLICY_BLOCKED),
                new Case("fixture-secret: Windows cannot verify the digital signature", NativeLoadReason.POLICY_BLOCKED),
                new Case("fixture-secret: Access is denied", NativeLoadReason.ACCESS_DENIED),
                new Case("fixture-secret: L'accès est refusé", NativeLoadReason.ACCESS_DENIED),
                new Case("fixture-secret is not a valid Win32 application", NativeLoadReason.IMAGE_FORMAT),
                new Case("fixture-secret: Can't find dependent libraries", NativeLoadReason.MODULE_MISSING),
                new Case("fixture-secret: Le module spécifié est introuvable", NativeLoadReason.MODULE_MISSING),
                new Case("fixture-secret: Une routine d’initialisation d’une bibliothèque de liens dynamiques a échoué", NativeLoadReason.DLL_INITIALIZATION),
                new Case("fixture-secret: error=5", NativeLoadReason.ACCESS_DENIED),
                new Case("fixture-secret: error code 126", NativeLoadReason.MODULE_MISSING),
                new Case("fixture-secret: Win32: 193", NativeLoadReason.IMAGE_FORMAT),
                new Case("fixture-secret: error 577", NativeLoadReason.POLICY_BLOCKED),
                new Case("fixture-secret: error 1260", NativeLoadReason.POLICY_BLOCKED),
                new Case("fixture-secret: error 1114", NativeLoadReason.DLL_INITIALIZATION),
                new Case("'long com.sun.jna.Native.invokePointer(fixture-secret)'", NativeLoadReason.JNI_ENTRYPOINT));
        for (var item : cases) {
            var reason = NativeLoadReason.observe(List.of(new UnsatisfiedLinkError(item.message())), new NativeLoadReason.Settings(false, false));
            assertEquals(item.reason(), reason);
            assertFalse(reason.problem.contains("fixture-secret")); assertFalse(reason.recovery.contains("fixture-secret"));
        }
    }

    @Test void reportsDisabledResourceSettingsWithoutChangingTheJvm() {
        var unknown = List.<Throwable>of(new UnsatisfiedLinkError("fixture-secret"));
        assertEquals(NativeLoadReason.CLASSPATH_DISABLED, NativeLoadReason.observe(unknown, new NativeLoadReason.Settings(true, false)));
        assertEquals(NativeLoadReason.UNPACK_DISABLED, NativeLoadReason.observe(unknown, new NativeLoadReason.Settings(false, true)));
        assertEquals(NativeLoadReason.UNKNOWN, NativeLoadReason.observe(unknown, new NativeLoadReason.Settings(false, false)));
        assertEquals(NativeLoadReason.ACCESS_DENIED, NativeLoadReason.observe(List.of(new UnsatisfiedLinkError("Access is denied")), new NativeLoadReason.Settings(true, true)));
    }

    @Test void classifiesJnasPlainVersionErrorWithoutCatchingUnrelatedFatalErrors() {
        var mismatch = new Error("There is an incompatible JNA native library installed on this system\nfixture-secret");
        assertTrue(NativeLoadReason.incompatibleVersionError(mismatch));
        var failure = DriverStartupFailures.classify(mismatch, DriverStartupFailures.Stage.NATIVE_SUPPORT);
        assertNotNull(failure); assertTrue(failure.getMessage().contains("NATIVE_LIBRARY_VERSION_MISMATCH"));
        assertFalse(failure.getMessage().contains("fixture-secret")); assertNull(failure.getCause());
        var wrapper = new LinkageError("JNA native ABI initialization failed."); wrapper.initCause(mismatch);
        var wrapped = DriverStartupFailures.classify(wrapper, DriverStartupFailures.Stage.NATIVE_SUPPORT);
        assertEquals(failure.getMessage(), wrapped.getMessage()); assertNull(wrapped.getCause());
        for (var fatal : List.of(new Error("fixture-secret"), new OutOfMemoryError("fixture-secret"), new StackOverflowError("fixture-secret"))) {
            assertFalse(NativeLoadReason.incompatibleVersionError(fatal));
            assertNull(DriverStartupFailures.classify(fatal, DriverStartupFailures.Stage.NATIVE_SUPPORT));
        }
    }

    @Test void unknownOrOversizedMessagesDoNotBecomeInventedWindowsErrors() {
        assertEquals(NativeLoadReason.UNKNOWN, NativeLoadReason.observe(List.of(new UnsatisfiedLinkError("fixture-secret-126")), new NativeLoadReason.Settings(false, false)));
        assertEquals(NativeLoadReason.UNKNOWN, NativeLoadReason.observe(List.of(new UnsatisfiedLinkError("x".repeat(9000) + "error 577")), new NativeLoadReason.Settings(false, false)));
    }

    private record Case(String message, NativeLoadReason reason) {}
}
