import com.microsoft.playwright.options.Proxy;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.util.AttributeKey;
import org.littleshoot.proxy.ChainedProxyAdapter;
import org.littleshoot.proxy.HttpFilters;
import org.littleshoot.proxy.HttpFiltersAdapter;
import org.littleshoot.proxy.HttpFiltersSourceAdapter;
import org.littleshoot.proxy.HttpProxyServer;
import org.littleshoot.proxy.MitmManager;
import org.littleshoot.proxy.ProxyAuthenticator;
import org.littleshoot.proxy.impl.DefaultHttpProxyServer;
import org.littleshoot.proxy.impl.ThreadPoolConfiguration;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Owns a fresh authenticated loopback LittleProxy endpoint and immutable TLS identity per attempt.
 *
 * Only mTLS journeys create this transport. Selected and no-client-identity upstream contexts have
 * independent session caches, strict CA/hostname checks and no hostless fallback. Ordinary browser
 * journeys bypass this class entirely. No proxy is cloned/rebound and no JVM default context changes.
 */
public final class JourneyTlsProxy implements AutoCloseable, MitmManager {
    private final JourneyDefinition.Mtls definition;
    private final SSLContext selected, ordinary;
    private final ProxyCertificateFactory certificates;
    private final AtomicReference<AuthenticationFailure> failure = new AtomicReference<>();
    private final String username = random(), password = random();
    private final AtomicInteger clients = new AtomicInteger();
    private static final AttributeKey<Boolean> ADMITTED = AttributeKey.valueOf(JourneyTlsProxy.class, "admitted");
    private final HttpProxyServer server;

    /**
     * Binds one attempt's selected key and optional explicit upstream chain before accepting clients.
     * @param definition Validated certificate-origin allowlist and additional CA settings.
     * @param identity Fingerprint-pinned key manager selected by Pkcs11IdentityManager.
     * @param upstream Explicit HTTP proxy or null for direct upstream TLS.
     * @param clock Certificate validity clock.
     * @throws AuthenticationFailure On trust/proxy setup failure; no direct fallback is installed.
     */
    public JourneyTlsProxy(JourneyDefinition.Mtls definition, Pkcs11IdentityManager.Selected identity,
                           JourneyDefinition.Proxy upstream, Clock clock) throws AuthenticationFailure {
        this.definition = definition; ProxyCertificateFactory owned = null;
        try {
            TrustManager[] trust = trust(definition.trustedCaBundlePath(), failure);
            selected = context(new KeyManager[]{identity.keyManager()}, trust); ordinary = context(new KeyManager[0], trust);
            owned = new ProxyCertificateFactory(clock); certificates = owned;
            var bootstrap = DefaultHttpProxyServer.bootstrap().withName("BPSH-owned-mtls").withAddress(new InetSocketAddress("127.0.0.1", 0))
                    .withAllowLocalOnly(true).withManInTheMiddle(this).withConnectTimeout(10_000).withIdleConnectionTimeout(30)
                    .withThreadPoolConfiguration(new ThreadPoolConfiguration().withAcceptorThreads(1).withClientToProxyWorkerThreads(2).withProxyToServerWorkerThreads(2))
                    .withProxyAuthenticator(new ProxyAuthenticator() {
                        /**
                         * Checks the two attempt-local proxy credentials without accepting upstream proxy credentials.
                         *
                         * @param user Local proxy username.
                         * @param pass Local proxy password.
                         * @return Exact attempt-credential match only.
                         */
                        @Override public boolean authenticate(String user, String pass) { return equal(username, user) && equal(password, pass); }
                        /**
                         * Returns safe realm without journey, key or credential details.
                         *
                         * @return Safe realm without journey, key or credential details.
                         */
                        @Override public String getRealm() { return "BPSH owned authentication"; }
                    })
                    .withFiltersSource(new HttpFiltersSourceAdapter() {
                        /**
                         * Creates per-request filtering while accounting admission once per local client connection.
                         *
                         * @param request Initial HTTP/CONNECT request.
                         * @param ctx Owned client channel.
                         * @return Per-request credential stripping and connection guards.
                         */
                        @Override public HttpFilters filterRequest(HttpRequest request, ChannelHandlerContext ctx) {
                            Boolean existing = ctx == null ? Boolean.FALSE : ctx.channel().attr(ADMITTED).get();
                            if (existing == null) {
                                existing = clients.incrementAndGet() <= 64; ctx.channel().attr(ADMITTED).set(existing);
                                ctx.channel().closeFuture().addListener(ignored -> clients.decrementAndGet());
                            }
                            boolean admitted = existing;
                            return new HttpFiltersAdapter(request, ctx) {
                                /**
                                 * Rejects excess local client connections before forwarding their authentication traffic.
                                 *
                                 * @param object Client request frame.
                                 * @return Rejection if the attempt's local connection guard is exceeded.
                                 */
                                @Override public HttpResponse clientToProxyRequest(HttpObject object) {
                                    if (!admitted) failure.compareAndSet(null, problem(AuthenticationFailure.Cause.CAPACITY, "The login page opened too many proxy connections.", ""));
                                    return admitted ? null : new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.SERVICE_UNAVAILABLE);
                                }
                                /**
                                 * Removes attempt-local proxy credentials before any upstream or origin request.
                                 *
                                 * @param object Outbound frame.
                                 * @return Null to continue after removing local proxy-only credentials.
                                 */
                                @Override public HttpResponse proxyToServerRequest(HttpObject object) {
                                    if (object instanceof HttpRequest outgoing) {
                                        outgoing.headers().remove(HttpHeaderNames.PROXY_AUTHORIZATION);
                                    }
                                    return null;
                                }
                                /** Records a generic terminal handshake failure without guessing incorrect PIN or temporary transport. */
                                @Override public void proxyToServerConnectionFailed() {
                                    failure.compareAndSet(null, problem(AuthenticationFailure.Cause.UNKNOWN, "The client-certificate proxy could not connect to the server.", ""));
                                }
                            };
                        }
                    });
            if (upstream != null) {
                if (!upstream.url().getScheme().equals("http") || upstream.url().getUserInfo() != null)
                    throw problem(AuthenticationFailure.Cause.PROXY_AUTH, "The proxy URL is invalid.", "Enter an HTTP proxy URL without a username or password, or leave Proxy URL empty for a direct connection.").atInput(AuthenticationFailure.Input.PROXY_URL);
                var address = new InetSocketAddress(upstream.url().getHost(), upstream.url().getPort() == -1 ? 80 : upstream.url().getPort());
                bootstrap.withChainProxyManager((request, chain, client) -> chain.add(new ChainedProxyAdapter() {
                    /**
                     * Returns only the configured HTTP upstream; a direct-fallback entry is never appended.
                     *
                     * @return Only the configured HTTP upstream; a direct-fallback entry is never appended.
                     */
                    @Override public InetSocketAddress getChainedProxyAddress() { return address; }
                    /**
                     * Retains safe explicit-chain failure guidance without keeping credential-bearing Netty error text.
                     *
                     * @param cause Raw chain error inspected only for safe classification, never logged here.
                     */
                    @Override public void connectionFailed(Throwable cause) {
                        failure.compareAndSet(null, problem(AuthenticationFailure.Cause.PROXY_AUTH, "The configured proxy could not connect to the login server.", "").atInput(AuthenticationFailure.Input.PROXY_URL));
                    }
                }));
            }
            server = bootstrap.start();
        } catch (AuthenticationFailure ex) { if (owned != null) owned.close(); throw ex; }
        catch (Exception ex) { if (owned != null) owned.close(); throw problem(AuthenticationFailure.Cause.TRUST, "The client-certificate proxy could not start.", ""); }
    }

    /**
     * Binds an explicit HTTP proxy to this owned browser, preventing Chromium's implicit loopback bypass.
     *
     * @return Borrowed explicit browser-to-local-proxy credentials for this attempt only.
     */
    public Proxy browserProxy() { return new Proxy("http://127.0.0.1:" + server.getListenAddress().getPort()).setUsername(username).setPassword(password).setBypass("<-loopback>"); }
    /**
     * Returns only this attempt's browser-facing generated key exception.
     *
     * @return Only this attempt's browser-facing generated key exception.
     */
    public String spkiSha256() { return certificates.spkiSha256(); }
    /**
     * Builds a typed failure with operator recovery guidance and no raw exception cause.
     *
     * @return Established safe proxy failure, or null; no raw Netty exception is retained.
     */
    public AuthenticationFailure failure() { return failure.get(); }
    /**
     * Returns bound loopback endpoint for identity-isolation acceptance tests.
     *
     * @return Bound loopback endpoint for identity-isolation acceptance tests.
     */
    InetSocketAddress address() { return server.getListenAddress(); }

    /**
     * Creates a peer-aware verified upstream engine, selecting client identity only for exact origins.
     * @param host TLS peer hostname/IP supplied by LittleProxy, never an inferred global selection.
     * @param port Target HTTPS port.
     * @return Fresh client-mode engine from an attempt-owned context/session cache.
     */
    @Override public SSLEngine serverSslEngine(String host, int port) {
        try {
            URI origin = TokenExtractor.origin(new URI("https", null, host, port, null, null, null));
            SSLContext context = definition.origins().contains(origin) ? selected : ordinary;
            SSLEngine engine = context.createSSLEngine(host, port); engine.setUseClientMode(true);
            var parameters = engine.getSSLParameters(); parameters.setEndpointIdentificationAlgorithm("HTTPS"); parameters.setApplicationProtocols(new String[]{"http/1.1"}); engine.setSSLParameters(parameters); return engine;
        } catch (Exception ex) {
            failure.compareAndSet(null, problem(AuthenticationFailure.Cause.CONFIGURATION, "The HTTPS connection could not be initialized.", ""));
            throw new IllegalArgumentException("Invalid peer-aware TLS target.");
        }
    }

    /**
     * Refuses hostless upstream TLS because certificate-origin and hostname checks require the peer.
     *
     * @return Never returns an insecure hostless engine; the peer-aware path is mandatory.
     * @throws IllegalStateException Always; callers must use the peer-aware overload.
     */
    @Override public SSLEngine serverSslEngine() { throw new IllegalStateException("Hostless upstream TLS is disabled."); }

    /**
     * Creates a browser-facing host leaf only after upstream TLS has passed CA/hostname validation.
     * @param request Original CONNECT request.
     * @param session Verified upstream handshake session, containing its exact peer host.
     * @return Owned server-mode engine using the attempt's ephemeral proxy key.
     */
    @Override public SSLEngine clientSslEngineFor(HttpRequest request, SSLSession session) {
        try { return certificates.engine(session.getPeerHost()); }
        catch (Exception ex) {
            failure.compareAndSet(null, problem(AuthenticationFailure.Cause.TRUST, "The proxy could not create its temporary certificate for the login browser.", ""));
            throw new IllegalStateException("Owned proxy certificate issuance failed.");
        }
    }

    /**
     * Creates an independent TLS context/session cache without touching default SSLContext/provider order.
     * @param keys Selected client key or an empty array for destinations outside the allowlist.
     * @param trust Strict normal/additional-CA trust managers.
     * @return Attempt-owned context with bounded sessions.
     * @throws Exception If JDK TLS initialization fails.
     */
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

    /**
     * Returns fresh independent local proxy credential component; never a journey alias or saved secret.
     *
     * @return Fresh independent local proxy credential component; never a journey alias or saved secret.
     */
    private static String random() { byte[] bytes = new byte[32]; new SecureRandom().nextBytes(bytes); return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
    /**
     * Compares nonnull credential bytes with constant-time equality without logging either value.
     *
     * @param expected Owned random credential.
     * @param actual Candidate.
     * @return Constant-time byte equality for nonnull input.
     */
    private static boolean equal(String expected, String actual) { return actual != null && MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), actual.getBytes(StandardCharsets.UTF_8)); }
    /**
     * Builds an actionable proxy failure without attaching raw handshake or credential-bearing errors.
     *
     * @param cause Typed transport category.
     * @param safe Safe problem text.
     * @param recovery Concrete correction.
     * @return Redacted terminal proxy error.
     */
    private static AuthenticationFailure problem(AuthenticationFailure.Cause cause, String safe, String recovery) { return new AuthenticationFailure(AuthenticationFailure.Phase.PROXY, cause, safe, recovery); }

    /** Aborts this endpoint/pools without logging out a shared token provider or deleting cached browsers. */
    @Override public void close() { server.abort(); certificates.close(); }
}
