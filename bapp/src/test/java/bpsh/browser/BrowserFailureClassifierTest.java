package bpsh.browser;

import bpsh.authentication.AuthenticationFailure;
import com.microsoft.playwright.PlaywrightException;
import com.microsoft.playwright.TimeoutError;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Checks that startup feedback reports evidence without speculative advice or vendor secrets. */
class BrowserFailureClassifierTest {
    @Test void unknownLaunchFailureDoesNotInventSandboxOrOperatingSystemAdvice() {
        var failure = BrowserFailureClassifier.launchFailure(new PlaywrightException("sandbox CANARY_PASSWORD https://secret.example/token"));
        assertEquals(AuthenticationFailure.Cause.UNKNOWN, failure.reason());
        assertEquals("Chromium could not start. Open this journey and use Test login to try again.", failure.getMessage());
        assertNull(failure.getCause());
    }

    @Test void typedLaunchTimeoutIsReportedWithoutExposingVendorText() {
        var failure = BrowserFailureClassifier.launchFailure(new TimeoutError("CANARY_PASSWORD"));
        assertEquals(AuthenticationFailure.Cause.TIMEOUT, failure.reason());
        assertEquals("Chromium did not start within the browser startup timeout.", failure.problem());
        assertFalse(failure.getMessage().contains("CANARY"));
    }
}
