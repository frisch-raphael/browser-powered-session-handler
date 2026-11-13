package bpsh.browser;

import bpsh.authentication.AuthenticationFailure;
import bpsh.browser.runtime.PlaywrightDriverAdapter;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import static org.junit.jupiter.api.Assertions.*;

/** Uses a separate JVM to reproduce denied JNA loading without changing the host JVM or OS policy. */
public class BrowserJourneyIntegrationTestDriverStartup {
    @Test @EnabledOnOs(OS.WINDOWS)
    void deniedNativeDispatchIsDiagnosedBeforeAnyDriverProcessIsStarted() throws Exception {
        var builder = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java.exe").toString(),
                "-Djna.noclasspath=true", "-Djna.nosys=true", "-cp", System.getProperty("bpsh.probeClasspath"), NativeDispatchDeniedProbe.class.getName());
        for (String key : java.util.List.of("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS")) builder.environment().remove(key);
        builder.redirectError(ProcessBuilder.Redirect.DISCARD);
        Process child = builder.start();
        try {
            assertTrue(child.waitFor(20, TimeUnit.SECONDS), "The isolated native-loading probe must finish");
            String report = new String(child.getInputStream().readNBytes(8192), java.nio.charset.StandardCharsets.UTF_8);
            assertEquals(0, child.exitValue(), report);
            assertTrue(report.contains("NATIVE_SUPPORT/NATIVE_LIBRARY"), report);
            assertTrue(report.contains("NO_DRIVER_CHILDREN"), report);
        } finally { child.destroyForcibly(); assertTrue(child.waitFor(5, TimeUnit.SECONDS)); }
    }

    /** Entry point loaded from the actual test classpath and selected packaged extension JAR. */
    public static final class NativeDispatchDeniedProbe {
        /** @param args Unused. @throws Exception On an unexpected startup or leaked child process. */
        public static void main(String[] args) throws Exception {
            try {
                // A null selector must never be accessed: native support is checked before driver setup.
                PlaywrightDriverAdapter.open(null, System.nanoTime() + TimeUnit.SECONDS.toNanos(10), () -> false);
                throw new AssertionError("Native loading unexpectedly succeeded");
            } catch (AuthenticationFailure failure) {
                System.out.println(failure.getMessage());
                if (!failure.getMessage().contains("NATIVE_SUPPORT/NATIVE_LIBRARY")) throw new AssertionError("Unexpected classification");
            }
            try (var children = ProcessHandle.current().children()) {
                if (children.findAny().isPresent()) throw new AssertionError("Driver process started before native support was available");
            }
            System.out.println("NO_DRIVER_CHILDREN");
        }
    }
}
