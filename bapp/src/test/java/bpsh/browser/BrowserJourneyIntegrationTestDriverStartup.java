package bpsh.browser;

import bpsh.authentication.AuthenticationFailure;
import bpsh.browser.runtime.PlaywrightDriverAdapter;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;
import static org.junit.jupiter.api.Assertions.*;

/** Reproduces host JNA settings in separate JVMs without changing the test host's native-loading policy. */
public class BrowserJourneyIntegrationTestDriverStartup {
    @Test @EnabledOnOs(OS.WINDOWS)
    @EnabledForJreRange(max = JRE.JAVA_21)
    void deniedNativeDispatchIsDiagnosedBeforeAnyDriverProcessIsStarted() throws Exception {
        var builder = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java.exe").toString(),
                "-Djna.noclasspath=true", "-Djna.nosys=true", "-cp", System.getProperty("bpsh.probeClasspath"), NativeDispatchDeniedProbe.class.getName());
        for (String key : java.util.List.of("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS")) builder.environment().remove(key);
        builder.redirectErrorStream(true);
        Process child = builder.start();
        try {
            assertTrue(child.waitFor(20, TimeUnit.SECONDS), "The isolated native-loading probe must finish");
            String report = new String(child.getInputStream().readNBytes(8192), java.nio.charset.StandardCharsets.UTF_8);
            assertEquals(0, child.exitValue(), report);
            assertTrue(report.contains("NATIVE_SUPPORT/NATIVE_LIBRARY"), report);
            assertTrue(report.contains("NO_DRIVER_CHILDREN"), report);
        } finally { child.destroyForcibly(); assertTrue(child.waitFor(5, TimeUnit.SECONDS)); }
    }

    @Test @EnabledOnOs(OS.WINDOWS)
    void loginAndSandboxedCleanupWorkWithJnaClasspathAndSystemLoadingDisabled() throws Exception {
        String javaExecutable = System.getProperty("bpsh.test.foreignJavaExecutable", "");
        org.junit.jupiter.api.Assumptions.assumeTrue(Runtime.version().feature() >= 22 || !javaExecutable.isBlank(),
                "This check requires Java 22+ or an explicit bpsh.test.foreignJavaExecutable.");
        if (javaExecutable.isBlank()) javaExecutable = Path.of(System.getProperty("java.home"), "bin", "java.exe").toString();
        // Keep the maintained HTTP lab in the full test JDK: Burp's bundled runtime omits jdk.httpserver.
        try (var origin = bpsh.support.IntegrationFixtures.http()) {
            var posted = lab.auth.LoginFlows.normalizedForm(origin.owner); origin.start();
            var builder = new ProcessBuilder(javaExecutable,
                    "-Djna.noclasspath=true", "-Djna.nosys=true", "-Djna.nounpack=true",
                    "-Dbpsh.test.burpBrowserExecutable=" + System.getProperty("bpsh.test.burpBrowserExecutable", ""),
                    "-Dbpsh.packagedJar=" + System.getProperty("bpsh.packagedJar", ""),
                    "-cp", System.getProperty("bpsh.probeClasspath"), NativeDispatchDisabledProbe.class.getName(), origin.url("/login").toString());
            for (String key : java.util.List.of("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS")) builder.environment().remove(key);
            builder.redirectErrorStream(true);
            Process child = builder.start();
            try {
                assertTrue(child.waitFor(60, TimeUnit.SECONDS), "The isolated login and cleanup probe must finish");
                String report = new String(child.getInputStream().readNBytes(16384), java.nio.charset.StandardCharsets.UTF_8);
                assertEquals(0, child.exitValue(), report);
                assertTrue(report.contains("LOGIN_SANDBOX_CLEANUP_WITHOUT_JNA=PASS"), report);
                assertEquals(1, posted.get(), "The shared lab must receive the completed secret-input login");
            } finally { child.destroyForcibly(); assertTrue(child.waitFor(5, TimeUnit.SECONDS)); }
        }
    }

    /** Runs maintained lab fixtures against the selected packaged JAR under the production failure settings. */
    public static final class NativeDispatchDisabledProbe {
        /** @param args Parent-owned lab login URL. @throws Exception On failed authentication, sandbox ownership, cleanup or settings isolation. */
        public static void main(String[] args) throws Exception {
            assertTrue(Runtime.version().feature() >= 22, "The foreign-function probe requires Java 22 or later");
            String loadedBefore = System.getProperty("jna.loaded");
            String pathBefore = System.getProperty("jnidispatch.path");
            try {
                BrowserJourneyIntegrationTest.setup();
                var checks = new BrowserJourneyIntegrationTest();
                var secure = BrowserJourneyIntegrationTest.step(bpsh.journey.AuthStep.Type.SECURE_INPUT, "#password", null);
                var journey = bpsh.support.IntegrationFixtures.journey(java.net.URI.create(args[0]), java.util.List.of(
                        BrowserJourneyIntegrationTest.step(bpsh.journey.AuthStep.Type.INPUT, "#name", "fixture-user"), secure,
                        BrowserJourneyIntegrationTest.step(bpsh.journey.AuthStep.Type.CLICK, "#submit", null),
                        BrowserJourneyIntegrationTest.step(bpsh.journey.AuthStep.Type.WAIT_URL, null, "**/done")));
                journey = bpsh.support.IntegrationFixtures.configured(journey, journey.authenticationUrl(),
                        new bpsh.journey.JourneyDefinition.Browser(true, null, 5000, 3000), journey.extraction(), null);
                try (var values = new bpsh.journey.SecretStore.Values(null,
                        java.util.Map.of(secure.id(), "fixture-password".toCharArray()))) {
                    var result = BrowserJourneyIntegrationTest.run(journey, values);
                    assertEquals("fixture-token", result.token()); assertFalse(result.toString().contains("fixture-token"));
                }
                checks.launchedBrowsersUseDistinctOwnedProfilesAndSandbox();
                checks.cleanupRetainsBrowserChildrenAfterTheirDriverExits();
            } finally { BrowserJourneyIntegrationTest.shutdown(); }
            assertEquals(loadedBefore, System.getProperty("jna.loaded"));
            assertEquals(pathBefore, System.getProperty("jnidispatch.path"));
            for (String setting : java.util.List.of("jna.noclasspath", "jna.nosys", "jna.nounpack"))
                assertEquals("true", System.getProperty(setting));
            System.out.println("LOGIN_SANDBOX_CLEANUP_WITHOUT_JNA=PASS");
        }
    }

    /** Entry point loaded from the actual test classpath and selected packaged extension JAR. */
    public static final class NativeDispatchDeniedProbe {
        /** @param args Unused. @throws Exception On an unexpected startup or leaked child process. */
        public static void main(String[] args) throws Exception {
            java.util.Set<Long> previousChildren;
            // Windows can report older processes that retain a reused parent PID. Never adopt or stop them.
            try (var children = ProcessHandle.current().children()) {
                previousChildren = children.map(ProcessHandle::pid).collect(java.util.stream.Collectors.toSet());
            }
            try {
                // A null selector must never be accessed: native support is checked before driver setup.
                PlaywrightDriverAdapter.open(null, System.nanoTime() + TimeUnit.SECONDS.toNanos(10), () -> false);
                throw new AssertionError("Native loading unexpectedly succeeded");
            } catch (AuthenticationFailure failure) {
                System.out.println(failure.getMessage());
                if (!failure.getMessage().contains("NATIVE_SUPPORT/NATIVE_LIBRARY")) throw new AssertionError("Unexpected classification");
            }
            try (var children = ProcessHandle.current().children()) {
                if (children.anyMatch(child -> !previousChildren.contains(child.pid()))) throw new AssertionError("Driver process started before native support was available");
            }
            System.out.println("NO_DRIVER_CHILDREN");
        }
    }
}
