package bpsh.browser.runtime;

import bpsh.authentication.AuthenticationFailure;
import java.nio.file.*;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class BurpBrowserResolverTest {
    @TempDir Path temporary;
    private long deadline() { return System.nanoTime() + TimeUnit.SECONDS.toNanos(10); }
    private Path browser(Path installation, String relative) throws Exception {
        Path executable = installation.resolve("burpbrowser").resolve(relative);
        Files.createDirectories(executable.getParent()); Files.writeString(executable, "synthetic executable");
        return executable.toRealPath();
    }
    private BurpBrowserResolver resolver(String platform, List<Path> active, List<Path> known, String override) {
        return new BurpBrowserResolver(new BurpBrowserResolver.Environment(platform, active, known), () -> override, p -> true);
    }
    @Test void explicitMissingBrowserDoesNotFallBack() throws Exception {
        Path install = temporary.resolve("BurpSuiteDesktop"); browser(install, "156.0.1.0/chrome.exe");
        String missing = install.resolve("burpbrowser/999.0.0.0/chrome.exe").toString();
        var error = assertThrows(AuthenticationFailure.class, () -> resolver("windows-x64", List.of(install), List.of(), missing).resolve(deadline(), () -> false));
        assertEquals(AuthenticationFailure.Cause.ASSET_MISSING, error.reason()); assertFalse(error.getMessage().contains(missing));
    }
    @Test void activeInstallWithoutBrowserDoesNotSelectOtherEdition() throws Exception {
        Path active = Files.createDirectory(temporary.resolve("BurpSuiteDesktop"));
        Path other = temporary.resolve("BurpSuitePro"); browser(other, "145.0.0.0/chrome.exe");
        assertThrows(AuthenticationFailure.class, () -> resolver("windows-x64", List.of(active), List.of(other), "").resolve(deadline(), () -> false));
    }
    @Test void sharedJavaHomeDoesNotIdentifyBurp() {
        var environment = BurpBrowserResolver.environment("windows-x64", temporary, List.of(temporary.resolve("Java/jdk/bin/java.exe")), List.of());
        assertTrue(environment.activeInstallations().isEmpty());
    }
    @Test void multipleKnownInstallsRequireSelection() throws Exception {
        Path first = temporary.resolve("BurpSuitePro"), second = temporary.resolve("BurpSuiteCommunity");
        browser(first, "145.0.0.0/chrome.exe"); browser(second, "156.0.0.0/chrome.exe");
        var error = assertThrows(AuthenticationFailure.class, () -> resolver("windows-x64", List.of(), List.of(first, second), "").resolve(deadline(), () -> false));
        assertEquals(AuthenticationFailure.Cause.CONFIGURATION, error.reason());
    }
    @Test void numericVersionsAndCanonicalAliases() throws Exception {
        Path install = temporary.resolve("BurpSuiteDesktop"); browser(install, "99.9.0.0/chrome.exe");
        Path newest = browser(install, "156.0.10.0/chrome.exe"); browser(install, "156.0.9.0/chrome.exe");
        Files.createDirectories(install.resolve("burpbrowser/999.0.0.0"));
        var selection = resolver("windows-x64", List.of(), List.of(install, install.resolve(".")), "").resolve(deadline(), () -> false);
        assertEquals(newest, selection.executable()); assertEquals("156.0.10.0", selection.version());
        assertEquals(BurpBrowserResolver.Source.KNOWN_INSTALLATION, selection.source());
    }
    @Test void supportedDirectAndVersionedLayouts() throws Exception {
        String[][] cases = {{"windows-x64", "156.0.8078.48/chrome.exe"}, {"linux-x64", "156.0.8078.47/chrome"},
                {"linux-x64", "chrome"}, {"macos-x64", "156.0.0.0/Burp Browser.app/Contents/MacOS/Burp Browser"},
                {"macos-x64", "145.0.0.0/Chromium.app/Contents/MacOS/Chromium"}};
        for (int i = 0; i < cases.length; i++) {
            Path install = temporary.resolve("custom-" + i); Path executable = browser(install, cases[i][1]);
            var automatic = resolver(cases[i][0], List.of(install), List.of(), "").resolve(deadline(), () -> false);
            assertEquals(executable, automatic.executable()); assertEquals(BurpBrowserResolver.Source.ACTIVE_INSTALLATION, automatic.source());
            assertEquals(executable, resolver(cases[i][0], List.of(), List.of(), executable.toString()).resolve(deadline(), () -> false).executable());
        }
    }
    @Test void rejectsUnrelatedChromeAndNonExecutableFile() throws Exception {
        Path unrelated = Files.writeString(temporary.resolve("chrome.exe"), "not a Burp installation");
        assertThrows(AuthenticationFailure.class, () -> resolver("windows-x64", List.of(), List.of(), unrelated.toString()).resolve(deadline(), () -> false));
        Path install = temporary.resolve("custom"); Path executable = browser(install, "156.0.0.0/chrome.exe");
        var denied = new BurpBrowserResolver(new BurpBrowserResolver.Environment("windows-x64", List.of(), List.of()), () -> executable.toString(), p -> false);
        assertEquals(AuthenticationFailure.Cause.CONFIGURATION, assertThrows(AuthenticationFailure.class, () -> denied.resolve(deadline(), () -> false)).reason());
        assertThrows(AuthenticationFailure.class, () -> resolver("windows-x64", List.of(), List.of(), "relative/chrome.exe").resolve(deadline(), () -> false));
    }
    @Test void updateBetweenAttemptsIsRediscovered() throws Exception {
        Path install = temporary.resolve("custom"); Path old = browser(install, "155.0.0.0/chrome.exe");
        var resolver = resolver("windows-x64", List.of(install), List.of(), ""); var selected = resolver.resolve(deadline(), () -> false);
        Files.delete(old); Path updated = browser(install, "156.0.0.0/chrome.exe");
        assertEquals(old, selected.executable()); assertEquals(updated, resolver.resolve(deadline(), () -> false).executable());
    }
    @Test void cancelledAndExpiredDiscoveryStops() {
        var resolver = resolver("linux-x64", List.of(), List.of(), "");
        assertEquals(AuthenticationFailure.Cause.CANCELLED, assertThrows(AuthenticationFailure.class, () -> resolver.resolve(deadline(), () -> true)).reason());
        assertEquals(AuthenticationFailure.Cause.TIMEOUT, assertThrows(AuthenticationFailure.class, () -> resolver.resolve(System.nanoTime() - 1, () -> false)).reason());
    }
    @Test void currentProcessJarIdentifiesCustomInstallWithoutInspectingProfiles() throws Exception {
        Path install = temporary.resolve("custom"); browser(install, "156.0.0.0/chrome");
        Path jar = Files.writeString(install.resolve("burpsuite_community.jar"), "synthetic application");
        var environment = BurpBrowserResolver.environment("linux-x64", temporary, List.of(jar), List.of());
        assertEquals(List.of(install.toRealPath()), environment.activeInstallations());
    }
}
