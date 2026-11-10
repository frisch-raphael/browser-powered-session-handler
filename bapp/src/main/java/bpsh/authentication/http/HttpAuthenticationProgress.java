package bpsh.authentication.http;

import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.HttpAuthentication;
import bpsh.journey.JourneyOrigins;
import java.net.URI;
import java.time.Instant;
import java.util.Objects;

/** Fixed transport facts for inspection and logs; never carries messages, headers or account secrets. */
public record HttpAuthenticationProgress(Stage stage, HttpAuthentication.Protocol protocol, URI origin, Instant time, int httpStatus) {
    public enum Stage {
        STARTED, NEGOTIATE_SENT, CHALLENGE_RECEIVED, AUTHENTICATE_SENT, BASIC_SENT,
        ACCEPTED, CONNECTION_REUSED, UNCONFIRMED,
        REJECTED, INVALID_CHALLENGE, RESPONSE_FAILED, CONNECTION_CLOSED, TLS_FAILED,
        CONNECTION_FAILED, TIMED_OUT, CAPACITY, CANCELLED, SETUP_FAILED, MISSING_SECRET,
        ORIGIN_BLOCKED, AUTHORIZATION_CONFLICT, PROXY_AUTH_REQUIRED, APPLICATION_DENIED, SERVER_ERROR, FAILED;

        public boolean failure() { return switch (this) {
            case STARTED, NEGOTIATE_SENT, CHALLENGE_RECEIVED, AUTHENTICATE_SENT, BASIC_SENT,
                    ACCEPTED, CONNECTION_REUSED, UNCONFIRMED, CANCELLED -> false;
            default -> true;
        }; }
    }

    public HttpAuthenticationProgress {
        Objects.requireNonNull(stage); Objects.requireNonNull(protocol); Objects.requireNonNull(time);
        if (origin != null) origin = JourneyOrigins.authenticationOrigin(origin);
        if (httpStatus != 0 && (httpStatus < 100 || httpStatus > 599)) throw new IllegalArgumentException("Invalid HTTP status.");
    }

    /** Safe, actionable text shared by every delivery path; selected NTLM variants are labeled explicitly. */
    public String message() {
        String name = protocol.toString();
        return switch (stage) {
            case STARTED -> name + " authentication started.";
            case NEGOTIATE_SENT -> name + " negotiate message (type 1) sent.";
            case CHALLENGE_RECEIVED -> name + " server challenge (type 2) received and validated.";
            case AUTHENTICATE_SENT -> name + " authentication response (type 3) sent.";
            case BASIC_SENT -> "Basic authentication credentials sent.";
            case ACCEPTED -> name + " authentication accepted by the server" + status() + ".";
            case CONNECTION_REUSED -> name + " authenticated connection reused" + status() + ".";
            case UNCONFIRMED -> "The server did not confirm " + name + " authentication" + status() + ". Check the selected protocol and allowed origins.";
            case REJECTED -> name + " authentication rejected" + status() + ". Check the username, password, domain and selected protocol.";
            case INVALID_CHALLENGE -> "The server supplied an invalid or unexpected NTLM challenge. Check the server's NTLM configuration and selected protocol.";
            case RESPONSE_FAILED -> "Could not construct the selected NTLM authentication response. Check the protocol, credentials and server challenge.";
            case CONNECTION_CLOSED -> "The server changed or closed the connection during HTTP authentication. Check keep-alive and proxy settings. Delivery may be unconfirmed; check the server-side result before resending.";
            case TLS_FAILED -> "HTTP authentication could not establish TLS. Check server trust, hostname and client-certificate settings.";
            case CONNECTION_FAILED -> "HTTP authentication could not connect to the server or proxy. Check the address, listener and network access.";
            case TIMED_OUT -> "HTTP authentication timed out. Check the server and proxy; delivery may be unconfirmed.";
            case CAPACITY -> "HTTP authentication capacity is exhausted. Wait for active requests to finish, then retry.";
            case CANCELLED -> "HTTP authentication cancelled.";
            case SETUP_FAILED -> "HTTP authentication setup failed. Check the saved identity, proxy and certificate settings.";
            case MISSING_SECRET -> "HTTP authentication setup is missing a password or client-certificate PIN. Enter it in the journey.";
            case ORIGIN_BLOCKED -> "HTTP authentication is not allowed for this exact origin. Review the journey's allowed origins.";
            case AUTHORIZATION_CONFLICT -> "Application Authorization prevented HTTP authentication. Review the application's authorization and journey configuration.";
            case PROXY_AUTH_REQUIRED -> "The proxy requires authentication. Use a proxy listener that does not require credentials.";
            case APPLICATION_DENIED -> "The application denied access (HTTP 403). Check the account's permissions; HTTP authentication and application authorization are separate results.";
            case SERVER_ERROR -> "The server returned an error" + status() + ". Check the application or proxy before retrying.";
            case FAILED -> "The authenticated HTTP exchange failed. Delivery may be unconfirmed; check the server-side result before resending a state-changing request.";
        };
    }

    private String status() { return httpStatus == 0 ? "" : " (HTTP " + httpStatus + ")"; }

    /** Classifies exception types only; vendor text and authentication payloads never become display data. */
    public static Stage failureStage(Throwable failure, boolean setup) {
        for (int depth = 0; failure != null && depth < 12; depth++, failure = failure.getCause()) {
            if (failure instanceof java.util.concurrent.TimeoutException || failure instanceof java.net.SocketTimeoutException) return Stage.TIMED_OUT;
            if (failure instanceof java.util.concurrent.CancellationException || failure instanceof InterruptedException) return Stage.CANCELLED;
            if (failure instanceof javax.net.ssl.SSLException) return Stage.TLS_FAILED;
            if (failure instanceof java.net.ConnectException || failure instanceof java.net.UnknownHostException || failure instanceof java.net.NoRouteToHostException) return Stage.CONNECTION_FAILED;
            if (failure instanceof java.net.SocketException) return Stage.CONNECTION_CLOSED;
            if (failure instanceof java.util.concurrent.RejectedExecutionException) return Stage.CAPACITY;
            if (failure instanceof AuthenticationFailure safe) return switch (safe.reason()) {
                case TIMEOUT -> Stage.TIMED_OUT;
                case CANCELLED, CLOSED, STALE -> Stage.CANCELLED;
                case CAPACITY -> Stage.CAPACITY;
                case TRUST, CERTIFICATE, CLIENT_CERTIFICATE_FAILED, CLIENT_CERTIFICATE_REQUIRED -> Stage.TLS_FAILED;
                case MISSING_SECRET -> Stage.MISSING_SECRET;
                case PROXY_AUTH -> Stage.PROXY_AUTH_REQUIRED;
                case AUTH_REJECTED -> Stage.REJECTED;
                default -> setup ? Stage.SETUP_FAILED : Stage.FAILED;
            };
        }
        return setup ? Stage.SETUP_FAILED : Stage.FAILED;
    }
}
