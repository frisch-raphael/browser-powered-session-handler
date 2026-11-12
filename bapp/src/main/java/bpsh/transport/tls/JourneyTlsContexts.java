package bpsh.transport.tls;

import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.JourneyOrigins;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.*;

/** Destination TLS policy shared by browser forwarding and direct HTTP authentication. */
public final class JourneyTlsContexts {
    private final JourneyDefinition.Mtls configuration;
    private final SSLContext ordinary, selected;
    private final Pkcs11IdentityManager.Selected identity;
    private final AtomicReference<AuthenticationFailure> failures = new AtomicReference<>();
    public JourneyTlsContexts(JourneyDefinition.Mtls configuration, Pkcs11IdentityManager.Selected identity) throws AuthenticationFailure {
        this(configuration,identity,false);
    }
    /** Explicit browser-only consent; mTLS always validates destination chain and hostname. */
    public JourneyTlsContexts(JourneyDefinition.Mtls configuration, Pkcs11IdentityManager.Selected identity, boolean browserBypass) throws AuthenticationFailure {
        this.configuration = configuration;
        this.identity = identity;
        try {
            var roots = browserBypass && configuration == null ? new TrustManager[]{new X509TrustManager() {
                @Override public void checkClientTrusted(X509Certificate[] chain,String auth) throws CertificateException {throw new CertificateException("No client trust.");}
                @Override public void checkServerTrusted(X509Certificate[] chain,String auth) { }
                @Override public X509Certificate[] getAcceptedIssuers() {return new X509Certificate[0];}
            }} : trust(configuration == null ? null : configuration.trustedCaBundlePath(), failures);
            ordinary = context(new KeyManager[0], roots);
            selected = configuration == null ? ordinary : context(new KeyManager[]{identity.keyManager()}, roots);
        } catch (AuthenticationFailure failure) { throw failure; }
        catch (Exception failure) { throw problem(AuthenticationFailure.Cause.TRUST, "Destination TLS could not be initialized.", "Review the client certificate and trusted CA settings."); }
    }
    /** A selected client identity is never offered outside its exact configured HTTPS origins. */
    public SSLContext forOrigin(URI uri) {
        return configuration != null && configuration.origins().contains(JourneyOrigins.authenticationOrigin(uri)) ? selected : ordinary;
    }
    public AuthenticationFailure failure() { return failures.get(); }
    /** A replaced native helper cannot be reused through an otherwise idle cached TLS context. */
    public boolean usable() { return identity == null || identity.usable(); }

    /** Classifies structured destination TLS failures without displaying peer-controlled exception text. */
    public static AuthenticationFailure destinationFailure(Throwable cause, boolean clientCertificate) {
        boolean handshake=false;
        var seen=java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<Throwable,Boolean>());
        for(int depth=0;cause!=null && depth<16 && seen.add(cause);depth++,cause=cause.getCause()) {
            if (cause instanceof AuthenticationFailure safe && (safe.phase() == AuthenticationFailure.Phase.PROVIDER || safe.phase() == AuthenticationFailure.Phase.PIN)) return safe;
            if(cause instanceof SSLPeerUnverifiedException)return problem(AuthenticationFailure.Cause.TRUST,
                    "The login server's certificate does not match its destination.","Review the Login URL and the server certificate.").atInput(AuthenticationFailure.Input.LOGIN_URL);
            if(cause instanceof CertificateException)return problem(AuthenticationFailure.Cause.TRUST,
                    "The login server's certificate could not be validated.","Review the trusted CA settings.").atInput(AuthenticationFailure.Input.TRUSTED_CA);
            handshake|=cause instanceof SSLHandshakeException;
        }
        return handshake?problem(AuthenticationFailure.Cause.CONFIGURATION,
                "The TLS handshake with the login server failed.",clientCertificate?
                "Review the server certificate and the client certificate's allowed origins.":"Review the server's HTTPS configuration and certificate."):null;
    }
    private static SSLContext context(KeyManager[] keys, TrustManager[] trust) throws Exception {
        SSLContext context = SSLContext.getInstance("TLS"); context.init(keys, trust, new SecureRandom());
        context.getClientSessionContext().setSessionCacheSize(64); context.getClientSessionContext().setSessionTimeout(300); return context;
    }

    /**
     * Combines normal CA validation with an optional bounded PEM bundle, never trust-all.
     * @param pem Additional user-configured CA path, or null for normal JVM trust only.
     * @param failures Attempt-local destination for safe trust-failure observations.
     * @return Independent validating trust manager array; engine hostname checks remain mandatory.
     * @throws Exception If the PEM bundle is unavailable/malformed or no X.509 manager exists.
     */
    private static TrustManager[] trust(String pem, AtomicReference<AuthenticationFailure> failures) throws Exception {
        TrustManagerFactory defaults = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); defaults.init((KeyStore) null);
        X509TrustManager normal = Arrays.stream(defaults.getTrustManagers()).filter(X509TrustManager.class::isInstance).map(X509TrustManager.class::cast).findFirst().orElseThrow();
        List<X509TrustManager> validators = new java.util.ArrayList<>(List.of(normal));
        if (pem != null) {
            try {
            Path path = Path.of(pem); if (Files.size(path) > 4L << 20) throw new CertificateException("CA bundle exceeds setup limit.");
            KeyStore store = KeyStore.getInstance("JKS"); store.load(null, null);
            try (var input = Files.newInputStream(path)) {
                var certs = CertificateFactory.getInstance("X.509").generateCertificates(input); if (certs.isEmpty() || certs.size() > 256) throw new CertificateException("Invalid CA bundle size.");
                int index = 0; for (var cert : certs) store.setCertificateEntry("additional-" + index++, cert);
            }
            TrustManagerFactory extra = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); extra.init(store);
            validators.add(Arrays.stream(extra.getTrustManagers()).filter(X509TrustManager.class::isInstance).map(X509TrustManager.class::cast).findFirst().orElseThrow());
            } catch (Exception error) {
                throw problem(AuthenticationFailure.Cause.TRUST, "The configured trusted CA bundle could not be read as PEM certificates.",
                        "Choose a readable PEM CA bundle.").atInput(AuthenticationFailure.Input.TRUSTED_CA);
            }
        }
        return new TrustManager[]{new X509TrustManager() {
            /**
             * Accepts a server chain validated by normal or additional roots, otherwise records a terminal trust failure.
             *
             * @param chain Peer chain.
             * @param auth Authentication algorithm.
             * @throws CertificateException Unless normal or additional roots validate it.
             */
            @Override public void checkServerTrusted(X509Certificate[] chain, String auth) throws CertificateException {
                for (X509TrustManager validator : validators) try { validator.checkServerTrusted(chain, auth); return; } catch (CertificateException ignored) { /* try only explicitly configured anchors */ }
                failures.compareAndSet(null, problem(AuthenticationFailure.Cause.TRUST, "The login server's certificate chain is not trusted.", "").atInput(AuthenticationFailure.Input.TRUSTED_CA));
                throw new CertificateException("Upstream trust validation failed.");
            }
            /**
             * Delegates client certificate validation to the unchanged platform trust manager.
             *
             * @param chain Client chain.
             * @param auth Algorithm.
             * @throws CertificateException If normal client validation fails.
             */
            @Override public void checkClientTrusted(X509Certificate[] chain, String auth) throws CertificateException { normal.checkClientTrusted(chain, auth); }
            /**
             * Returns normal and explicitly configured public CA certificates.
             *
             * @return Normal and explicitly configured public CA certificates.
             */
            @Override public X509Certificate[] getAcceptedIssuers() { return validators.stream().flatMap(v -> Arrays.stream(v.getAcceptedIssuers())).toArray(X509Certificate[]::new); }
        }};
    }

    public static AuthenticationFailure upstreamFailure(Throwable cause) {
        var seen = java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<Throwable, Boolean>());
        for (int depth = 0; cause != null && depth < 16 && seen.add(cause); depth++, cause = cause.getCause()) {
            if (cause instanceof java.net.ConnectException || cause instanceof java.net.NoRouteToHostException
                    || cause instanceof java.net.SocketTimeoutException || cause instanceof java.nio.channels.ClosedChannelException
                    || cause instanceof io.netty.channel.ConnectTimeoutException)
                return problem(AuthenticationFailure.Cause.TRANSPORT, "The connection to the configured proxy could not be established.", "")
                        .atInput(AuthenticationFailure.Input.PROXY_URL);
        }
        return problem(AuthenticationFailure.Cause.UNKNOWN, "The configured proxy could not connect to the login server.", "")
                .atInput(AuthenticationFailure.Input.PROXY_URL);
    }
    private static AuthenticationFailure problem(AuthenticationFailure.Cause cause, String safe, String recovery) {
        return new AuthenticationFailure(AuthenticationFailure.Phase.PROXY, cause, safe, recovery);
    }
}
