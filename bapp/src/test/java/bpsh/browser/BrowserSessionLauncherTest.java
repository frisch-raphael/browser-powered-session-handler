package bpsh.browser;

import bpsh.authentication.AuthenticationFailure;
import bpsh.browser.runtime.*;
import bpsh.journey.*;
import java.nio.file.Path;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class BrowserSessionLauncherTest {
    @Test void failedLaunchKeepsSanitizedCleanupAfterAttributionWithoutRetainingThrowables() throws Exception {
        var primary = BrowserCleanupFixtures.failedLaunch(new AuthenticationFailure(AuthenticationFailure.Phase.SETUP,
                AuthenticationFailure.Cause.ASSET_MISSING, "The browser could not start."));
        var attributed = primary.forJourney(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, UUID.randomUUID(), 1))
                .atInput(AuthenticationFailure.Input.BROWSER_EXECUTABLE).forCredential(0).withRecovery("Choose the installed browser.");
        assertEquals(AuthenticationFailure.Cause.ASSET_MISSING, attributed.reason());
        assertTrue(attributed.getMessage().contains("could not finish closing"), attributed.getMessage());
        assertFalse(attributed.getMessage().contains("PRIVATE_CLOSE_CANARY"));
        assertEquals(0, primary.getSuppressed().length, "retain bounded outcome metadata, not throwable graphs");
        assertEquals(0, attributed.getSuppressed().length);
        assertNull(attributed.getCause());
    }
    @Test void missingExplicitBrowserFailsBeforeDriverPreparationAndIsResolvedForEachAttempt() throws Exception {
        var reads = new AtomicInteger();
        var resolver = new BurpBrowserResolver(new BurpBrowserResolver.Environment("windows-x64", List.of(), List.of()),
                () -> { reads.incrementAndGet(); return Path.of("absent-burp-browser.exe").toAbsolutePath().toString(); });
        try (var runtime = new BrowserRuntimeManager(); var values = new SecretStore.Values(null, Map.of())) {
            runtime.close(); // Acquiring this driver would produce CLOSED, rather than the browser prerequisite.
            var launcher = new BrowserSessionLauncher(runtime, resolver, null, new AuthTrafficGuard(), Clock.systemUTC());
            var identity = new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, UUID.randomUUID(), 1);
            var setup = new BrowserSetup(java.net.URI.create("http://localhost/login"), new JourneyDefinition.Browser(true, null, 5000, 1000), null);
            for (int i = 0; i < 2; i++) {
                var failure = assertThrows(AuthenticationFailure.class, () -> launcher.open(identity, setup, values,
                        BrowserSessionLauncher.Visibility.HEADLESS, false, System.nanoTime() + TimeUnit.SECONDS.toNanos(10), () -> false, ignored -> {}));
                assertEquals(AuthenticationFailure.Cause.ASSET_MISSING, failure.reason());
            }
            assertEquals(2, reads.get());
        }
    }
}
