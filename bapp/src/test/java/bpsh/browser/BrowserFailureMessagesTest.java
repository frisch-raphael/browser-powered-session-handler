package bpsh.browser;

import bpsh.authentication.AuthenticationFailure;
import bpsh.browser.mtls.JourneyTlsProxy;
import bpsh.browser.runtime.BrowserRuntimeManager;
import bpsh.browser.runtime.PlaywrightDriverAdapter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.*;

/** Checks evidence-based browser diagnostics without launching a browser or making network requests. */
class BrowserFailureMessagesTest {
    @Test void clientCertificateErrorsUsePositiveSymbolsAndCurrentConfiguration() {
        for (boolean configured : new boolean[]{false, true}) {
            var required = BrowserFailureClassifier.networkFailure("net::ERR_SSL_CLIENT_AUTH_CERT_NEEDED", configured);
            assertEquals(AuthenticationFailure.Cause.CLIENT_CERTIFICATE_REQUIRED, required.reason());
            assertEquals(AuthenticationFailure.Input.CERTIFICATE, required.input().input()); assertEquals(1, required.priority());
            assertEquals(!configured, required.getMessage().contains("Enable Client certificate"));
            var failed = BrowserFailureClassifier.networkFailure("ERR_BAD_SSL_CLIENT_AUTH_CERT", configured);
            assertEquals(AuthenticationFailure.Cause.CLIENT_CERTIFICATE_FAILED, failed.reason());
            assertEquals(!configured, failed.getMessage().contains("Enable Client certificate"));
            assertFalse(failed.retryable());
        }
        for (String symbol : new String[]{"ERR_CONNECTION_RESET", "ERR_SSL_PROTOCOL_ERROR", "ERR_CONNECTION_TIMED_OUT"}) {
            var unknown = BrowserFailureClassifier.networkFailure(symbol, false);
            assertNotEquals(AuthenticationFailure.Cause.CLIENT_CERTIFICATE_REQUIRED, unknown.reason());
            assertNotEquals(AuthenticationFailure.Cause.CLIENT_CERTIFICATE_FAILED, unknown.reason());
        }
        assertNull(BrowserFailureClassifier.networkFailure("CANARY ERR_SSL_CLIENT_AUTH_CERT_NEEDED"));
    }
    @Test void unavailableMtlsUpstreamIsTemporaryOnlyWithPositiveSocketEvidence() {
        for (var cause : new Throwable[]{new java.net.ConnectException("CANARY_CONNECTION"), new java.net.SocketTimeoutException("CANARY_TIMEOUT"),
                new RuntimeException("CANARY_WRAPPER", new java.net.ConnectException("CANARY_NESTED"))}) {
            var failure = JourneyTlsProxy.upstreamFailure(cause);
            assertEquals(AuthenticationFailure.Phase.PROXY, failure.phase());
            assertEquals(AuthenticationFailure.Cause.TRANSPORT, failure.reason()); assertTrue(failure.retryable());
            assertFalse(failure.getMessage().contains("CANARY"));
        }
        var unknown = JourneyTlsProxy.upstreamFailure(new IllegalStateException("CANARY_UNKNOWN"));
        assertEquals(AuthenticationFailure.Cause.UNKNOWN, unknown.reason()); assertFalse(unknown.retryable());
        assertFalse(unknown.getMessage().contains("CANARY"));
    }
    @Test
    void dnsFailureExplainsHostnameResolutionWithoutUnrelatedTroubleshooting() {
        var failure = BrowserFailureClassifier.networkFailure("net::ERR_NAME_NOT_RESOLVED");
        assertNotNull(failure);
        assertTrue(failure.problem().contains("hostname could not be resolved"));
        assertTrue(failure.problem().contains("ERR_NAME_NOT_RESOLVED"));
        assertEquals("", failure.recovery());
        assertEquals(failure.problem(), failure.getMessage());
        for (String irrelevant : new String[]{"PIN", "TLS", "proxy", "VPN", "main-frame", "retryable"})
            assertFalse(failure.getMessage().contains(irrelevant), failure.getMessage());
        assertEquals(AuthenticationFailure.Cause.UNKNOWN, failure.reason());
        assertFalse(failure.retryable());
    }

    @ParameterizedTest
    @CsvSource({
            "ERR_CONNECTION_REFUSED, TRANSPORT, true, was refused",
            "ERR_CONNECTION_TIMED_OUT, TRANSPORT, true, timed out",
            "ERR_CONNECTION_RESET, TRANSPORT, true, connection closed",
            "ERR_CONNECTION_CLOSED, TRANSPORT, true, connection closed",
            "ERR_NETWORK_CHANGED, TRANSPORT, true, network connection",
            "ERR_INTERNET_DISCONNECTED, TRANSPORT, true, network connection",
            "ERR_PROXY_CONNECTION_FAILED, UNKNOWN, false, connect to the configured proxy",
            "ERR_TUNNEL_CONNECTION_FAILED, UNKNOWN, false, proxy could not connect",
            "ERR_CERT_AUTHORITY_INVALID, TRUST, false, does not trust",
            "ERR_CERT_COMMON_NAME_INVALID, TRUST, false, hostname",
            "ERR_CERT_DATE_INVALID, TRUST, false, validity dates",
            "ERR_CERT_REVOKED, TRUST, false, has been revoked",
            "ERR_SSL_PROTOCOL_ERROR, UNKNOWN, false, secure connection",
            "ERR_SSL_VERSION_OR_CIPHER_MISMATCH, UNKNOWN, false, secure connection"
    })
    void browserErrorsReportObservedFactsAndPreserveRetryPolicy(String code, AuthenticationFailure.Cause cause,
                                                                boolean retryable, String relevantDetail) {
        var failure = BrowserFailureClassifier.networkFailure(code);
        assertNotNull(failure);
        assertEquals(cause, failure.reason());
        assertEquals(retryable, failure.retryable());
        assertEquals(AuthenticationFailure.Phase.NAVIGATION, failure.phase());
        assertTrue(failure.getMessage().contains(code));
        assertTrue(failure.getMessage().contains(relevantDetail), failure.getMessage());
        assertEquals("", failure.recovery());
        assertEquals(failure.problem(), failure.getMessage());
        assertFalse(failure.getMessage().contains("PIN"));
    }

    @ParameterizedTest
    @CsvSource({"ERR_INVALID_AUTH_CREDENTIALS", "ERR_PROXY_AUTH_UNSUPPORTED"})
    void proxyAuthenticationRetainsItsTerminalCategory(String code) {
        var failure = BrowserFailureClassifier.networkFailure(code);
        assertNotNull(failure);
        assertEquals(AuthenticationFailure.Phase.PROXY, failure.phase());
        assertEquals(AuthenticationFailure.Cause.PROXY_AUTH, failure.reason());
        assertFalse(failure.retryable());
        assertTrue(failure.problem().contains(code));
        assertEquals("", failure.recovery());
    }

    @Test
    void unknownBrowserCodeKeepsTheCodeWithoutInventingACause() {
        var failure = BrowserFailureClassifier.networkFailure("net::ERR_UNRECOGNIZED_BROWSER_ERROR");
        assertNotNull(failure);
        assertTrue(failure.problem().contains("ERR_UNRECOGNIZED_BROWSER_ERROR"));
        assertEquals(AuthenticationFailure.Cause.UNKNOWN, failure.reason());
        assertFalse(failure.retryable());
        assertEquals("", failure.recovery());
        assertEquals(failure.problem(), failure.getMessage());
    }

    @Test
    void rawBrowserMessagesAndMalformedSymbolsAreNeverEchoed() {
        for (String symbol : new String[]{null, "", "net::", "ERR_", "selector contains ERR_CONNECTION_RESET",
                "ERR_CERT_INVALID fixture-secret", "ERR_CERT_INVALID\nfixture-secret", "net::ERR_" + "A".repeat(101)})
            assertNull(BrowserFailureClassifier.networkFailure(symbol));
    }

    @Test void setupAndDriverFailuresUseTypedEvidenceWithoutEchoingSecrets() {
        for (Exception error : java.util.List.of(new java.io.IOException("fixture-secret"),
                new java.nio.file.AccessDeniedException("fixture-secret"), new java.nio.file.NoSuchFileException("fixture-secret"))) {
            var setup = BrowserRuntimeManager.setupFailure(error, "Local setup failed.");
            var driver = PlaywrightDriverAdapter.startupFailure(error, false);
            assertEquals(error instanceof java.nio.file.AccessDeniedException ? AuthenticationFailure.Cause.CONFIGURATION
                    : error instanceof java.nio.file.NoSuchFileException ? AuthenticationFailure.Cause.ASSET_CORRUPT : AuthenticationFailure.Cause.UNKNOWN, setup.reason());
            assertEquals(error instanceof java.nio.file.AccessDeniedException ? AuthenticationFailure.Cause.CONFIGURATION
                    : error instanceof java.nio.file.NoSuchFileException ? AuthenticationFailure.Cause.ASSET_MISSING : AuthenticationFailure.Cause.UNKNOWN, driver.reason());
            assertFalse(setup.getMessage().contains("fixture-secret")); assertFalse(driver.getMessage().contains("fixture-secret"));
            assertNull(setup.getCause()); assertNull(driver.getCause());
        }
        assertTrue(PlaywrightDriverAdapter.startupFailure(new java.io.IOException("fixture-secret"), true).getMessage().contains("exited during initialization"));
    }

    @Test void navigationMetadataRequiresAnEstablishedMainFrame() {
        var frameType = com.microsoft.playwright.Frame.class;
        var frame = (com.microsoft.playwright.Frame) java.lang.reflect.Proxy.newProxyInstance(
                frameType.getClassLoader(), new Class<?>[]{frameType}, (proxy, method, args) -> {
                    if (method.getName().equals("parentFrame")) return null;
                    throw new AssertionError("Unexpected frame inspection");
                });
        var childFrame = (com.microsoft.playwright.Frame) java.lang.reflect.Proxy.newProxyInstance(
                frameType.getClassLoader(), new Class<?>[]{frameType}, (proxy, method, args) -> {
                    if (method.getName().equals("parentFrame")) return frame;
                    throw new AssertionError("Unexpected child-frame inspection");
                });
        for (int scenario = 0; scenario < 5; scenario++) {
            int selected = scenario;
            var requestType = com.microsoft.playwright.Request.class;
            var request = (com.microsoft.playwright.Request) java.lang.reflect.Proxy.newProxyInstance(
                    requestType.getClassLoader(), new Class<?>[]{requestType}, (proxy, method, args) -> {
                        if (method.getName().equals("isNavigationRequest")) return selected != 0;
                        if (method.getName().equals("frame")) {
                            if (selected == 1) throw new com.microsoft.playwright.PlaywrightException("Unavailable frame fixture");
                            if (selected == 2) return null;
                            return selected == 4 ? childFrame : frame;
                        }
                        throw new AssertionError("Unexpected request inspection");
                    });
            assertEquals(selected == 3, BrowserFlowRunner.mainFrameNavigation(request));
        }
    }

}
