package bpsh.browser.runtime;

import bpsh.authentication.AuthenticationFailure;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Checks useful loading attribution while preserving the no-vendor-text boundary. */
class DriverStartupFailuresTest {
    @Test void distinguishesLoadingFamiliesAndNeverRetainsVendorText() {
        var cases = List.of(
                new Case(new UnsatisfiedLinkError("fixture-secret"), "NATIVE_LIBRARY"),
                new Case(new NoClassDefFoundError("fixture-secret"), "CLASS_MISSING"),
                new Case(new ClassNotFoundException("fixture-secret"), "CLASS_MISSING"),
                new Case(new UnsupportedClassVersionError("fixture-secret"), "JAVA_VERSION"),
                new Case(new NoSuchMethodError("fixture-secret"), "LIBRARY_VERSION"),
                new Case(new NoSuchFieldError("fixture-secret"), "LIBRARY_VERSION"),
                new Case(new IllegalAccessError("fixture-secret"), "JAVA_ACCESS"),
                new Case(new IllegalAccessException("fixture-secret"), "JAVA_ACCESS"),
                new Case(new NoSuchMethodException("fixture-secret"), "DRIVER_API"),
                new Case(new ExceptionInInitializerError(new IllegalStateException("fixture-secret")), "CLASS_INITIALIZATION"),
                new Case(new LinkageError("fixture-secret"), "JAVA_LINKAGE"));
        for (var item : cases) {
            var failure = DriverStartupFailures.classify(item.error(), DriverStartupFailures.Stage.PLAYWRIGHT_PROTOCOL);
            assertNotNull(failure); assertEquals(AuthenticationFailure.Cause.CONFIGURATION, failure.reason());
            assertTrue(failure.getMessage().contains("Diagnostic: PLAYWRIGHT_PROTOCOL/" + item.code() + "."), item.code());
            assertFalse(failure.getMessage().contains("fixture-secret")); assertNull(failure.getCause());
            assertEquals(0, failure.getSuppressed().length);
        }
    }

    @Test void unwrapsNestedInitializationFailuresBeforeChoosingRecovery() {
        var error = new InvocationTargetException(new ExceptionInInitializerError(new UnsatisfiedLinkError("fixture-secret")));
        var failure = DriverStartupFailures.classify(error, DriverStartupFailures.Stage.NATIVE_SUPPORT);
        assertTrue(failure.getMessage().contains("NATIVE_SUPPORT/NATIVE_LIBRARY"));
        assertFalse(failure.getMessage().contains("fixture-secret"));
        assertFalse(failure.getMessage().contains("Reload the complete"));
        assertNull(failure.getCause());
    }

    @Test void explainsCachedInitializationAndIdentifiesJavaNativeAccessRefusal() {
        var cached = DriverStartupFailures.classify(new NoClassDefFoundError("Could not initialize class fixture.secret"), DriverStartupFailures.Stage.NATIVE_SUPPORT);
        assertTrue(cached.getMessage().contains("CLASS_INITIALIZATION"));
        assertTrue(cached.getMessage().contains("Restart Burp completely"));
        assertFalse(cached.getMessage().contains("fixture.secret"));
        var denied = DriverStartupFailures.classify(new ExceptionInInitializerError(new IllegalCallerException("fixture-secret")), DriverStartupFailures.Stage.NATIVE_SUPPORT);
        assertTrue(denied.getMessage().contains("NATIVE_SUPPORT/NATIVE_ACCESS"));
        assertFalse(denied.getMessage().contains("fixture-secret"));
    }

    @Test void retainsOnlyKnownWindowsOperationAndNativeNumbers() {
        var error = new WindowsBrowserJob.Failure(WindowsBrowserJob.Operation.ASSIGN_DRIVER, 5L, null, false);
        error.addSuppressed(new IllegalStateException("fixture-secret"));
        var failure = DriverStartupFailures.classify(error, DriverStartupFailures.Stage.NATIVE_SUPPORT);
        assertTrue(failure.getMessage().contains("WINDOWS_JOB_ASSIGN_DRIVER; Windows error 5"));
        assertFalse(failure.getMessage().contains("fixture-secret")); assertNull(failure.getCause());
        assertEquals(0, failure.getSuppressed().length);
    }

    @Test void boundsCyclicCauseGraphsAndLeavesUnknownErrorsToTheProcessClassifier() {
        var first = new Exception("fixture-secret"); var second = new Exception("fixture-secret");
        first.initCause(second); second.initCause(first);
        assertTimeoutPreemptively(java.time.Duration.ofSeconds(1), () ->
                assertNull(DriverStartupFailures.classify(first, DriverStartupFailures.Stage.DRIVER_PROCESS)));
        assertNull(DriverStartupFailures.classify(new java.io.IOException("fixture-secret"), DriverStartupFailures.Stage.DRIVER_PROCESS));
    }

    @Test @org.junit.jupiter.api.condition.EnabledOnOs(org.junit.jupiter.api.condition.OS.WINDOWS)
    void aRealLockedCleanupFileDoesNotReplaceThePrimaryLoadingDiagnosis(@org.junit.jupiter.api.io.TempDir java.nio.file.Path root) throws Exception {
        var directory = java.nio.file.Files.createDirectory(root.resolve("owned-attempt"));
        var primary = PlaywrightDriverAdapter.startupFailure(new UnsatisfiedLinkError("fixture-secret"), false);
        String diagnosis = primary.problem();
        var watchdog = java.util.concurrent.Executors.newSingleThreadScheduledExecutor();
        try (var locked = java.nio.channels.FileChannel.open(directory.resolve("locked"), java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.WRITE, com.sun.nio.file.ExtendedOpenOption.NOSHARE_DELETE)) {
            var method = PlaywrightDriverAdapter.class.getDeclaredMethod("cleanupFailedStartup", Process.class,
                    WindowsBrowserJob.class, java.nio.file.Path.class, java.util.concurrent.ScheduledExecutorService.class, AuthenticationFailure.class);
            method.setAccessible(true); method.invoke(null, null, null, directory, watchdog, primary);
            assertEquals(diagnosis, primary.problem()); assertTrue(primary.cleanupIncomplete());
            assertTrue(primary.getMessage().contains("NATIVE_LIBRARY"));
            assertFalse(primary.getMessage().contains("fixture-secret")); assertNull(primary.getCause());
        } finally { watchdog.shutdownNow(); }
    }

    /** One authored expected category, without invoking any native loader. */
    private record Case(Throwable error, String code) {}
}
