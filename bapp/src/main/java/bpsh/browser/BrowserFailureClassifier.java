package bpsh.browser;

import bpsh.journey.AuthStep;
import bpsh.authentication.AuthenticationFailure;
import com.microsoft.playwright.PlaywrightException;
import com.microsoft.playwright.TimeoutError;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.Set;

/** Safe browser failure attribution and retry metadata, independent of browser lifecycle. */
public final class BrowserFailureClassifier {
    private static final String AMBIGUOUS_SELECTOR = "strict mode violation:";
    private BrowserFailureClassifier() {}
    /**
     * Maps browser main-frame request-failure symbols only, never selector/exception prose.
     * @param symbol Playwright Request.failure observation.
     * @return Typed positive transport/trust observation, or null for an unmapped outcome.
     */
    public static AuthenticationFailure networkFailure(String symbol) {
        return networkFailure(symbol, false);
    }
    /** Classifies actual connection evidence using the current certificate configuration. */
    public static AuthenticationFailure networkFailure(String symbol, boolean clientCertificateConfigured) {
        if (symbol == null) return null;
        String code = symbol.startsWith("net::") ? symbol.substring(5) : symbol;
        if (!code.matches("ERR_[A-Z0-9_]{1,100}")) return null;
        switch (code) {
            case "ERR_SSL_CLIENT_AUTH_CERT_NEEDED" -> {
                return new AuthenticationFailure(AuthenticationFailure.Phase.NAVIGATION, AuthenticationFailure.Cause.CLIENT_CERTIFICATE_REQUIRED,
                        clientCertificateConfigured ? "This server requires a client certificate. Check the selected certificate and allowed authentication servers in Client certificate."
                                : "This server requires a client certificate. Enable Client certificate in Setup, then choose a certificate and enter its PIN.")
                        .atInput(AuthenticationFailure.Input.CERTIFICATE);
            }
            case "ERR_BAD_SSL_CLIENT_AUTH_CERT" -> {
                return new AuthenticationFailure(AuthenticationFailure.Phase.NAVIGATION, AuthenticationFailure.Cause.CLIENT_CERTIFICATE_FAILED,
                        clientCertificateConfigured ? "Client-certificate authentication failed. Check the selected certificate and allowed authentication servers in Client certificate."
                                : "Client-certificate authentication failed. Enable Client certificate in Setup and configure a certificate and PIN.")
                        .atInput(AuthenticationFailure.Input.CERTIFICATE);
            }
            case "ERR_NAME_NOT_RESOLVED" -> {
                return navigationFailure(AuthenticationFailure.Cause.UNKNOWN, code,
                        "The login server's hostname could not be resolved");
            }
            case "ERR_CONNECTION_REFUSED" -> {
                return navigationFailure(AuthenticationFailure.Cause.TRANSPORT, code,
                        "The connection to the login server was refused");
            }
            case "ERR_CONNECTION_TIMED_OUT" -> {
                return navigationFailure(AuthenticationFailure.Cause.TRANSPORT, code,
                        "The connection to the login server timed out");
            }
            case "ERR_CONNECTION_RESET", "ERR_CONNECTION_CLOSED" -> {
                return navigationFailure(AuthenticationFailure.Cause.TRANSPORT, code,
                        "The connection closed before the login page loaded");
            }
            case "ERR_NETWORK_CHANGED" -> {
                return navigationFailure(AuthenticationFailure.Cause.TRANSPORT, code,
                        "The browser's network connection changed while loading the login page");
            }
            case "ERR_INTERNET_DISCONNECTED" -> {
                return navigationFailure(AuthenticationFailure.Cause.TRANSPORT, code,
                        "The browser lost its network connection");
            }
            case "ERR_PROXY_CONNECTION_FAILED" -> {
                return navigationFailure(AuthenticationFailure.Cause.UNKNOWN, code,
                        "The browser could not connect to the configured proxy");
            }
            case "ERR_TUNNEL_CONNECTION_FAILED" -> {
                return navigationFailure(AuthenticationFailure.Cause.UNKNOWN, code,
                        "The proxy could not connect to the login server");
            }
            case "ERR_CERT_AUTHORITY_INVALID" -> {
                return navigationFailure(AuthenticationFailure.Cause.TRUST, code,
                        "The browser does not trust the login server's certificate");
            }
            case "ERR_CERT_COMMON_NAME_INVALID" -> {
                return navigationFailure(AuthenticationFailure.Cause.TRUST, code,
                        "The server's certificate does not match the login hostname");
            }
            case "ERR_CERT_DATE_INVALID" -> {
                return navigationFailure(AuthenticationFailure.Cause.TRUST, code,
                        "The server's certificate is outside its validity dates");
            }
            case "ERR_CERT_REVOKED" -> {
                return navigationFailure(AuthenticationFailure.Cause.TRUST, code,
                        "The login server's certificate has been revoked");
            }
        }
        if (code.startsWith("ERR_CERT_"))
            return navigationFailure(AuthenticationFailure.Cause.TRUST, code,
                    "The browser rejected the login server's certificate");
        if (code.equals("ERR_INVALID_AUTH_CREDENTIALS") || code.equals("ERR_PROXY_AUTH_UNSUPPORTED"))
            return new AuthenticationFailure(AuthenticationFailure.Phase.PROXY, AuthenticationFailure.Cause.PROXY_AUTH,
                    code.equals("ERR_PROXY_AUTH_UNSUPPORTED")
                            ? "The browser could not use the proxy's authentication method (" + code + ")."
                            : "The browser rejected authentication (" + code + ").").atInput(AuthenticationFailure.Input.PROXY_URL);
        if (code.equals("ERR_SSL_PROTOCOL_ERROR") || code.equals("ERR_SSL_VERSION_OR_CIPHER_MISMATCH"))
            return navigationFailure(AuthenticationFailure.Cause.UNKNOWN, code,
                    "Could not establish a secure connection. Check the server certificate settings and whether a client certificate is required");
        return navigationFailure(AuthenticationFailure.Cause.UNKNOWN, code,
                "The browser could not open the login page");
    }
    /** Reports only the observed browser failure and its safe code. */
    private static AuthenticationFailure navigationFailure(AuthenticationFailure.Cause cause, String code, String problem) {
        var result = new AuthenticationFailure(AuthenticationFailure.Phase.NAVIGATION, cause, problem + " (" + code + ").");
        if (code.contains("PROXY") || code.equals("ERR_TUNNEL_CONNECTION_FAILED")) return result.atInput(AuthenticationFailure.Input.PROXY_URL);
        if (Set.of("ERR_NETWORK_CHANGED", "ERR_INTERNET_DISCONNECTED").contains(code)) return result;
        return result.atInput(AuthenticationFailure.Input.LOGIN_URL);
    }
    /**
     * Parses server retry guidance without changing the attempt or cycle deadline.
     *
     * @param value Relevant Retry-After header.
     * @param now Observation wall time.
     * @return Parsed nonnegative delta/date, or null for invalid input.
     */
    public static Instant retryAfter(String value, Instant now) {
        if (value == null) return null;
        try { return value.matches("[0-9]+") ? now.plusSeconds(Long.parseLong(value)) : ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant(); }
        catch (RuntimeException ex) { return null; }
    }
    /**
     * Reports a safe step index and timeout category without retaining raw browser exception text.
     *
     * @param error Browser operation exception, inspected only for timeout type.
     * @param index One-based step or zero for initial navigation.
     * @param step Exact configured action, or null for initial navigation.
     * @return Safe terminal operation result.
     */
    static AuthenticationFailure stepFailure(PlaywrightException error, AuthStep.Definition step, int index) {
        boolean ambiguous = step != null && error.getMessage() != null && error.getMessage().contains(AMBIGUOUS_SELECTOR);
        String action = step == null ? "Opening the login page" : "Step " + index + " — " + step.type().label();
        var failure = new AuthenticationFailure(index == 0 ? AuthenticationFailure.Phase.NAVIGATION : AuthenticationFailure.Phase.STEP,
                error instanceof TimeoutError ? AuthenticationFailure.Cause.STEP_TIMEOUT : AuthenticationFailure.Cause.UNKNOWN,
                action + (ambiguous ? ": the selector matches several elements." : error instanceof TimeoutError ? " timed out." : " failed."));
        return step == null ? failure.atInput(AuthenticationFailure.Input.LOGIN_URL) : failure.atStep(new AuthenticationFailure.Step(step.id(), index, step.type()));
    }
}
