package bpsh.browser;

import bpsh.authentication.AuthenticationFailure;
import com.microsoft.playwright.PlaywrightException;
import com.microsoft.playwright.TimeoutError;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Checks that startup feedback reports evidence without speculative advice or vendor secrets. */
class BrowserFailureClassifierTest {
    @Test void launchFailuresPointAtInstalledBrowserSettingsWithoutBlamingCredentials() {
        var failure = BrowserFailureClassifier.launchFailure(new PlaywrightException("CANARY_PASSWORD"));
        assertNotNull(failure.input(), "A browser launch failure must identify its Settings group");
        assertEquals(AuthenticationFailure.Input.BROWSER_EXECUTABLE, failure.input().input());
        assertEquals(AuthenticationFailure.Cause.UNKNOWN, failure.reason()); assertFalse(failure.getMessage().contains("CANARY"));
    }
    @Test void nativeLinuxSandboxFatalGetsActionableGuidanceWithoutVendorData() {
        for(String prefix:new String[]{"","[pid=123][err] "}) {
            String diagnostic=prefix+"[123:123:1112/120000.000000:FATAL:content/browser/zygote_host/zygote_host_impl_linux.cc:128] No usable sandbox! CANARY_PASSWORD /PRIVATE_PATH\n";
            var failure=BrowserFailureClassifier.launchFailure(new PlaywrightException(diagnostic));
            assertEquals(AuthenticationFailure.Cause.CONFIGURATION,failure.reason());
            assertEquals("Chromium's sandbox is unavailable in this Linux environment.",failure.problem());
            assertTrue(failure.recovery().contains("AppArmor"));assertTrue(failure.recovery().contains("user namespace"));
            assertFalse(failure.getMessage().contains("CANARY"));assertFalse(failure.getMessage().contains("PRIVATE"));assertNull(failure.getCause());
        }
    }
    @Test void sandboxWordsInArgumentsOrUnrelatedErrorsDoNotEstablishSandboxFailure() {
        for(String diagnostic:new String[]{"--user-data-dir=/tmp/No usable sandbox!", "No usable sandbox!", "unrelated text [123:FATAL:zygote_host_impl_linux.cc:128] No usable sandbox!"})
            assertEquals(AuthenticationFailure.Cause.UNKNOWN,BrowserFailureClassifier.launchFailure(new PlaywrightException(diagnostic)).reason());
    }
    @Test void unknownLaunchFailureDoesNotInventSandboxOrOperatingSystemAdvice() {
        var failure = BrowserFailureClassifier.launchFailure(new PlaywrightException("sandbox CANARY_PASSWORD https://secret.example/token"));
        assertEquals(AuthenticationFailure.Cause.UNKNOWN, failure.reason());
        assertEquals("Burp Browser could not start. Check Burp Browser in Settings, then use Test login to try again.", failure.getMessage());
        assertNull(failure.getCause());
    }

    @Test void typedLaunchTimeoutIsReportedWithoutExposingVendorText() {
        var failure = BrowserFailureClassifier.launchFailure(new TimeoutError("CANARY_PASSWORD"));
        assertEquals(AuthenticationFailure.Cause.TIMEOUT, failure.reason());
        assertEquals("Burp Browser did not start within the browser startup timeout.", failure.problem());
        assertFalse(failure.getMessage().contains("CANARY"));
    }
}
