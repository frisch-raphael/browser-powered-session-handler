package bpsh.transport.httpauth;

import bpsh.journey.HttpAuthentication;
import bpsh.authentication.http.HttpAuthenticationProgress.Stage;
import org.apache.hc.client5.http.auth.AuthChallenge;
import org.apache.hc.client5.http.auth.AuthScheme;
import org.apache.hc.client5.http.auth.AuthenticationException;
import org.apache.hc.client5.http.auth.CredentialsProvider;
import org.apache.hc.client5.http.auth.MalformedChallengeException;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.protocol.HttpContext;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.util.Base64;
import java.util.function.Supplier;

/** HttpClient's supported connection-authentication SPI; no deprecated Apache NTLM engine. */
final class NtlmAuthScheme implements AuthScheme {
    private final HttpAuthentication settings;
    private final Supplier<char[]> password;
    private final Principal principal;
    private byte[] negotiate, challenge;
    private boolean terminal;
    private final java.util.function.BiConsumer<HttpContext,Stage> progress;

    NtlmAuthScheme(HttpAuthentication settings, Supplier<char[]> password, Principal principal) {
        this(settings,password,principal,(context,stage)->{});
    }
    NtlmAuthScheme(HttpAuthentication settings, Supplier<char[]> password, Principal principal,
            java.util.function.BiConsumer<HttpContext,Stage> progress) {
        this.settings = settings; this.password = password; this.principal = principal;
        this.progress=progress;
    }
    @Override public String getName() { return "NTLM"; }
    @Override public boolean isConnectionBased() { return true; }
    @Override public String getRealm() { return null; }
    @Override public Principal getPrincipal() { return principal; }
    @Override public boolean isChallengeComplete() { return terminal; }

    @Override public void processChallenge(AuthChallenge value, HttpContext context) throws MalformedChallengeException {
        try {
            if (terminal) return;
            String token = value.getValue();
            if (token == null || token.isBlank()) {
                if (negotiate != null) throw new IOException("NTLM negotiation was restarted by the server.");
            } else {
                if (negotiate == null || challenge != null || token.length() > ((NtlmMessages.MAX_CHALLENGE + 2) / 3) * 4)
                    throw new IOException("Unexpected NTLM challenge.");
                challenge = Base64.getDecoder().decode(token);
                NtlmMessages.validateChallenge(challenge);
                progress.accept(context,Stage.CHALLENGE_RECEIVED);
            }
        } catch (IOException | IllegalArgumentException e) {
            terminal = true;
            progress.accept(context,Stage.INVALID_CHALLENGE);
            throw new MalformedChallengeException("The server supplied an invalid NTLM challenge.");
        }
    }

    @Override public boolean isResponseReady(HttpHost host, CredentialsProvider provider, HttpContext context) {
        return !terminal && settings.allows(java.net.URI.create(host.toURI()));
    }

    @Override public String generateAuthResponse(HttpHost host, HttpRequest request, HttpContext context) throws AuthenticationException {
        try {
            if (challenge == null) {
                negotiate = NtlmMessages.negotiate(settings.protocol());
                return "NTLM " + Base64.getEncoder().encodeToString(negotiate);
            }
            char[] secret = password.get();
            try {
                byte[] binding = TlsChannelBinding.from(HttpClientContext.castOrCreate(context).getSSLSession());
                byte[] response = NtlmMessages.authenticate(settings, secret, negotiate, challenge, host.getHostName(), binding);
                terminal = true;
                return "NTLM " + Base64.getEncoder().encodeToString(response);
            } finally { java.util.Arrays.fill(secret, '\0'); }
        } catch (IOException | GeneralSecurityException | IllegalStateException e) {
            terminal = true;
            progress.accept(context,Stage.RESPONSE_FAILED);
            throw new AuthenticationException("Could not construct the selected NTLM authentication response.");
        }
    }
}
