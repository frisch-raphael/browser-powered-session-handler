package lab.auth.gui;

import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

class HostGuiAssertionsTest {
    @Test void assertionsRequireTheVisibleActionableMessageRatherThanGenericFailure() {
        assertTrue(HostGuiAssertions.message("RECOVERY_PAUSED","Automatic recovery is paused after 1 attempt. Use Test login to retry."));
        assertFalse(HostGuiAssertions.message("RECOVERY_PAUSED","Automatic recovery is paused after 1 attempt."));
        assertFalse(HostGuiAssertions.message("RECOVERY_PAUSED","Login failed."));
        assertTrue(HostGuiAssertions.message("URL_REGEX_INVALID","Rule 1, URL: requires supported RE2 syntax."));
        assertTrue(HostGuiAssertions.message("URL_REGEX_INVALID","Rule 2, URL: requires supported RE2 syntax at position 0."));
        assertTrue(HostGuiAssertions.message("URL_REGEX_INVALID","Rule 64, URL: requires supported RE2 syntax at position 2."));
        assertFalse(HostGuiAssertions.message("URL_REGEX_INVALID","Rule 1, Response text pattern: requires supported RE2 syntax."));
        assertFalse(HostGuiAssertions.message("URL_REGEX_INVALID","controls.rules[0].url.value: requires supported RE2 syntax."));
        assertFalse(HostGuiAssertions.message("URL_REGEX_INVALID","PRIVATE_INPUT requires supported RE2 syntax."));
        assertFalse(HostGuiAssertions.message("URL_REGEX_INVALID","Enter a URL."));
        assertThrows(HostGuiSelectors.Failure.class,()->HostGuiAssertions.message("UNSUPPORTED","success"));
    }
    @Test void unchangedFeedbackMustNameTheSelectedJourneyAndActualForwardingOutcome() {
        assertTrue(HostGuiAssertions.unchangedMessage("host_failure_a","BPSH left the request unchanged. Journey host_failure_a: Login failed."));
        assertFalse(HostGuiAssertions.unchangedMessage("host_failure_b","BPSH left the request unchanged. Journey host_failure_a: Login failed."));
        assertFalse(HostGuiAssertions.unchangedMessage("host_failure_a","Journey host_failure_a: Login failed."));
    }
}
