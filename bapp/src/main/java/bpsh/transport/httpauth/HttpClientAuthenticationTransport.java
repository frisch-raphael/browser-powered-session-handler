package bpsh.transport.httpauth;

import bpsh.authentication.http.HttpAuthenticationEvidence;
import bpsh.authentication.http.HttpAuthenticationService;
import bpsh.authentication.http.HttpMessageBody;
import bpsh.authentication.http.HttpAuthenticationProgress;
import bpsh.authentication.http.HttpAuthenticationProgress.Stage;
import bpsh.journey.HttpAuthentication;
import org.apache.hc.client5.http.auth.AuthSchemeFactory;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.auth.BasicScheme;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.io.ManagedHttpClientConnection;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.io.HttpResponseInformationCallback;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.http.impl.io.HttpRequestExecutor;
import org.apache.hc.core5.http.io.HttpClientConnection;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
import javax.net.ssl.SSLContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.URI;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.WeakHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

/** An identity-owned HttpClient pool. Browser attempts and direct-request identities own separate instances. */
public final class HttpClientAuthenticationTransport implements HttpAuthenticationService {
    public static final int MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
    private static final String DELIVERY = HttpClientAuthenticationTransport.class.getName() + ".delivery";
    private static final Set<String> HOP_HEADERS = Set.of("connection", "proxy-connection", "keep-alive", "te", "trailer",
            "transfer-encoding", "upgrade", "proxy-authorization", "proxy-authenticate");
    private final HttpTransportAdmission admission;
    private final Set<Lease> leases=ConcurrentHashMap.newKeySet();
    private final HttpAuthentication settings;
    private final boolean permitOtherOrigins;
    private final char[] password;
    private final java.util.function.Consumer<HttpAuthenticationProgress> progress;
    private final ExecutorService workers;
    private final ScheduledExecutorService deadlines;
    private final CloseableHttpClient client;
    private final org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager manager;
    private volatile long lastUsed;
    private final Object userToken = new Object();
    private final AtomicBoolean closed = new AtomicBoolean();
    private final Set<CompletableFuture<Response>> pending = ConcurrentHashMap.newKeySet();
    private final Map<Socket, HttpAuthentication.Protocol> established = Collections.synchronizedMap(new WeakHashMap<>());

    /** Executors belong to the extension lifecycle; closing a scope does not stop other identities. */
    public HttpClientAuthenticationTransport(HttpAuthentication settings, char[] password, SSLContext tls,
                                             ExecutorService workers, ScheduledExecutorService deadlines) {
        this(java.util.Objects.requireNonNull(settings), password, tls, null, workers, deadlines);
    }

    /** Explicit routing has no direct fallback if an upstream proxy fails. */
    public HttpClientAuthenticationTransport(HttpAuthentication settings, char[] password, SSLContext tls, URI upstream,
                                             ExecutorService workers, ScheduledExecutorService deadlines) {
        this(settings, password, ignored -> tls, upstream, workers, deadlines);
    }

    /** The TLS owner chooses client-certificate context for the actual destination of each pooled connection. */
    public HttpClientAuthenticationTransport(HttpAuthentication settings, char[] password, java.util.function.Function<URI,SSLContext> tls, URI upstream,
                                             ExecutorService workers, ScheduledExecutorService deadlines) {
        this(settings, password, tls, upstream, workers, deadlines, false);
    }

    HttpClientAuthenticationTransport(HttpAuthentication settings, char[] password, java.util.function.Function<URI,SSLContext> tls, URI upstream,
            ExecutorService workers, ScheduledExecutorService deadlines, boolean permitOtherOrigins) {
        this(settings,password,tls,upstream,workers,deadlines,permitOtherOrigins,false);
    }
    HttpClientAuthenticationTransport(HttpAuthentication settings, char[] password, java.util.function.Function<URI,SSLContext> tls, URI upstream,
            ExecutorService workers, ScheduledExecutorService deadlines, boolean permitOtherOrigins, boolean bypassHostname) {
        this(settings,password,tls,upstream,workers,deadlines,permitOtherOrigins,bypassHostname,new HttpTransportAdmission());
    }
    HttpClientAuthenticationTransport(HttpAuthentication settings,char[] password,java.util.function.Function<URI,SSLContext> tls,URI upstream,
            ExecutorService workers,ScheduledExecutorService deadlines,boolean permitOtherOrigins,boolean bypassHostname,HttpTransportAdmission admission) {
        this(settings,password,tls,upstream,workers,deadlines,permitOtherOrigins,bypassHostname,admission,ignored->{});
    }
    HttpClientAuthenticationTransport(HttpAuthentication settings,char[] password,java.util.function.Function<URI,SSLContext> tls,URI upstream,
            ExecutorService workers,ScheduledExecutorService deadlines,boolean permitOtherOrigins,boolean bypassHostname,HttpTransportAdmission admission,
            java.util.function.Consumer<HttpAuthenticationProgress> progress) {
        if(upstream!=null && (!"http".equalsIgnoreCase(upstream.getScheme()) || upstream.getHost()==null || upstream.getUserInfo()!=null || upstream.getPort()==0 || upstream.getPort()>65535))
            throw new IllegalArgumentException("The upstream proxy must be an HTTP URL without credentials.");
        this.admission=admission;this.lastUsed=admission.clock.getAsLong();
        this.settings = settings;
        this.progress=progress;
        this.permitOtherOrigins = permitOtherOrigins;
        this.password = password == null ? new char[0] : password.clone(); this.workers = workers; this.deadlines = deadlines;
        Principal principal = new ScopePrincipal(UUID.randomUUID().toString());
        var registry = RegistryBuilder.<AuthSchemeFactory>create()
                .register("Basic", context -> new BasicScheme())
                .register("NTLM", context -> new NtlmAuthScheme(settings, this::copyPassword, principal,
                        (raw,stage)->report((Observation)raw.getAttribute(DELIVERY),stage,0))).build();
        manager = PoolingHttpClientConnectionManagerBuilder.create()
                .setConnectionFactory(admission.connections)
                .setMaxConnTotal(4).setMaxConnPerRoute(4)
                .setDefaultConnectionConfig(ConnectionConfig.custom().setConnectTimeout(Timeout.ofSeconds(10))
                        .setSocketTimeout(Timeout.ofSeconds(30)).setValidateAfterInactivity(TimeValue.ofSeconds(1)).build())
                .setTlsSocketStrategy((socket, host, port, attachment, context) -> {
                    URI destination;
                    try { destination = new URI("https", null, host, port, null, null, null); }
                    catch (java.net.URISyntaxException invalid) { throw new IOException("Invalid TLS destination."); }
                    Object ownedDelivery=context.getAttribute(DELIVERY);
                    if(ownedDelivery instanceof Observation delivery) {
                        long left=delivery.deadlineNanos-System.nanoTime();
                        if(left<=0)throw new java.net.SocketTimeoutException("TLS setup timed out.");
                        socket.setSoTimeout((int)Math.min(Integer.MAX_VALUE,Math.max(1,TimeUnit.NANOSECONDS.toMillis(left))));
                    }
                    var strategy=ClientTlsStrategyBuilder.create().setSslContext(tls.apply(destination));
                    if(bypassHostname) {
                        strategy.setHostnameVerificationPolicy(org.apache.hc.client5.http.ssl.HostnameVerificationPolicy.CLIENT);
                        strategy.setHostnameVerifier(org.apache.hc.client5.http.ssl.NoopHostnameVerifier.INSTANCE);
                    }
                    return strategy.buildClassic().upgrade(socket, host, port, attachment, context);
                }).build();
        var builder = HttpClients.custom().setConnectionManager(manager)
                .setDefaultAuthSchemeRegistry(registry)
                .setDefaultCredentialsProvider((scope, context) -> {
                    if (settings == null || settings.protocol() != HttpAuthentication.Protocol.BASIC) return null;
                    var origin = new HttpHost(scope.getProtocol(), scope.getHost(), scope.getPort());
                    if (!settings.allows(URI.create(origin.toURI()))) return null;
                    synchronized (this.password) {
                        if (closed.get()) return null;
                        return new UsernamePasswordCredentials(settings.username(), this.password);
                    }
                })
                .setRequestExecutor(new EvidenceExecutor())
                .disableAutomaticRetries().disableRedirectHandling().disableCookieManagement()
                .disableContentCompression().disableAuthCaching().disableDefaultUserAgent();
        if (upstream != null) {
            if (!"http".equalsIgnoreCase(upstream.getScheme()) || upstream.getHost() == null || upstream.getUserInfo() != null)
                throw new IllegalArgumentException("The upstream proxy must be an HTTP URL without credentials.");
            builder.setProxy(new HttpHost("http", upstream.getHost(), upstream.getPort() == -1 ? 80 : upstream.getPort()));
        }
        client = builder.build();
    }

    @Override public boolean isIdle() {return leases.isEmpty();}
    long lastUsed() {return lastUsed;}
    void closeIdle(TimeValue age) {manager.closeExpired();manager.closeIdle(age);}
    @Override public boolean isOpen() {return !closed.get();}
    @Override public HttpAuthenticationService.Delivery admit(long deadlineNanos) throws IOException {
        if(closed.get())throw new IOException("This HTTP authentication identity has been retired.");
        if(deadlineNanos-System.nanoTime()<=0)throw new IOException("HTTP delivery deadline expired before admission.");
        var permit=admission.acquire(userToken);
        Lease lease;
        try {lease=new Lease(permit,deadlineNanos);}
        catch(RuntimeException failure) {permit.close();throw failure;}
        lastUsed=admission.clock.getAsLong();leases.add(lease);
        if(closed.get() || lease.result.isDone())lease.close();
        return lease;
    }

    private CompletableFuture<Response> perform(Request request,long deadlineNanos,Lease lease) {
        CompletableFuture<Response> result=lease.result;
        try {
        if (request.method().equalsIgnoreCase("TRACE")) {
            result.completeExceptionally(new IOException("HTTP authentication does not support TRACE requests."));
            return result;
        }
        try { bpsh.journey.JourneyOrigins.authenticationOrigin(request.uri()); }
        catch (IllegalArgumentException invalid) { result.completeExceptionally(new IOException("Invalid HTTP destination.")); return result; }
        if ((!permitOtherOrigins && settings != null && !settings.allows(request.uri())) || request.uri().getRawFragment() != null) {
            report(lease.observation,Stage.ORIGIN_BLOCKED,0);
            result.completeExceptionally(new IOException("HTTP authentication is not allowed for this exact origin.")); return result;
        }
        if (closed.get()) { result.completeExceptionally(new IOException("This HTTP authentication identity has been retired.")); return result; }
        long remaining = deadlineNanos - System.nanoTime();
        if (remaining <= 0) { result.completeExceptionally(new TimeoutException("HTTP authentication timed out.")); return result; }
        lease.requestBody=request.body().retain();
        HttpUriRequestBase outbound = new HttpUriRequestBase(request.method(), request.uri());
        lease.outbound=outbound;
        Observation delivery = lease.observation;
        delivery.deadlineNanos=deadlineNanos;
        delivery.selectedOrigin = settings != null && settings.allows(request.uri());
        long authorizations = request.headers().stream().filter(h->h.name().equalsIgnoreCase("Authorization")).count();
        boolean preserve = request.authorizationPolicy() == AuthorizationPolicy.PRESERVE_APPLICATION;
        if(preserve && authorizations > 1) {
            result.completeExceptionally(new IOException("The browser request has multiple Authorization headers."));return result;
        }
        delivery.authenticate = delivery.selectedOrigin && !(preserve && authorizations == 1);
        Set<String> removed = hopHeaders(request.headers());
        removed.addAll(Set.of("bpsp-http-authent", "host", "content-length", "expect"));
        if (delivery.authenticate) removed.add("authorization");
        for (Header header : request.headers()) if (!removed.contains(header.name().toLowerCase(Locale.ROOT)))
            outbound.addHeader(header.name(), header.value());
        if(lease.requestBody.length()>0 || request.method().equalsIgnoreCase("POST") || request.method().equalsIgnoreCase("PUT"))
            outbound.setEntity(new HttpBodyEntity(lease.requestBody));
        var timeout = Timeout.ofMilliseconds(Math.max(1, TimeUnit.NANOSECONDS.toMillis(remaining)));
        outbound.setConfig(RequestConfig.custom().setConnectionRequestTimeout(timeout).setResponseTimeout(timeout)
                .setExpectContinueEnabled(false)
                .setAuthenticationEnabled(delivery.authenticate)
                .setTargetPreferredAuthSchemes(List.of(settings != null && settings.protocol() == HttpAuthentication.Protocol.BASIC ? "Basic" : "NTLM")).build());
        HttpClientContext context = HttpClientContext.create();
        context.setUserToken(userToken); context.setAttribute(DELIVERY, delivery);
        pending.add(result);
        result.whenComplete((response, failure) -> {
            pending.remove(result);
            if (failure != null) outbound.cancel();
        });
        if (closed.get()) { result.completeExceptionally(new IOException("This HTTP authentication identity has been retired.")); return result; }
        try {
            var work = new Work(lease,() -> {
                if (result.isDone()) return;
                try {
                    Response response = client.execute(outbound, context, incoming -> {
                        int status = incoming.getCode();
                        if (status == 101) throw new IOException("HTTP authentication does not support protocol upgrades.");
                        ArrayList<Header> headers = new ArrayList<>();
                        for (var header : incoming.getHeaders()) headers.add(new Header(header.getName(), header.getValue()));
                        Set<String> excluded = hopHeaders(headers);
                        // Transfer framing is reconstructed by each adapter from the complete entity.
                        headers.removeIf(header -> excluded.contains(header.name().toLowerCase(Locale.ROOT)));
                        HttpMessageBody entity = readBounded(incoming, outbound::cancel, admission.bodies);
                        HttpAuthenticationEvidence.Status evidence = delivery.selectedOrigin && status == 401 ? HttpAuthenticationEvidence.Status.REJECTED :
                                (delivery.accepted ? HttpAuthenticationEvidence.Status.ACCEPTED : HttpAuthenticationEvidence.Status.UNCONFIRMED);
                        return new Response(status, headers, entity, new HttpAuthenticationEvidence(
                                evidence == HttpAuthenticationEvidence.Status.ACCEPTED ? settings.protocol() : null,evidence,
                                bpsh.journey.JourneyOrigins.authenticationOrigin(request.uri()),null,0,java.time.Instant.now(),status,
                                delivery.selectedOrigin && preserve && authorizations==1 && status==401));
                    });
                    if (closed.get()) {response.close();result.completeExceptionally(new IOException("This HTTP authentication identity has been retired."));}
                    else if(!result.complete(response))response.close();
                } catch (Exception failure) {
                    String message = delivery.attempted
                            ? "The HTTP request may have reached the server. Its outcome is uncertain; it was not automatically retried."
                            : "The authenticated HTTP exchange failed before delivery.";
                    if (failure instanceof java.net.SocketTimeoutException) {
                        var timeoutFailure = new TimeoutException(message);
                        timeoutFailure.initCause(failure);
                        result.completeExceptionally(timeoutFailure);
                    } else result.completeExceptionally(new bpsh.authentication.http.HttpDeliveryFailure(delivery.attempted, failure));
                }
            });
            lease.work=work;
            workers.execute(work);
            if(result.isCompletedExceptionally() || result.isCancelled())lease.cancelWork();
        } catch (RejectedExecutionException rejected) {
            result.completeExceptionally(new IOException("HTTP authentication capacity is exhausted."));
            if(lease.work!=null)lease.work.close();
        }
        return result;
        } finally {if(lease.work==null)lease.release();}
    }

    private final class Lease implements HttpAuthenticationService.Delivery {
        final HttpTransportAdmission.Permit permit;
        final long deadline;
        final CompletableFuture<Response> result=new CompletableFuture<>();
        final AtomicBoolean used=new AtomicBoolean(),released=new AtomicBoolean();
        volatile Work work;
        volatile HttpUriRequestBase outbound;
        volatile HttpMessageBody requestBody;
        volatile java.util.concurrent.ScheduledFuture<?> expiry;
        Observation observation;
        Lease(HttpTransportAdmission.Permit permit,long deadline) {
            this.permit=permit;this.deadline=deadline;
            result.whenComplete((response,failure)->{
                if(expiry!=null)expiry.cancel(false);
                if(failure!=null) {cancelWork();if(!used.get())release();}
            });
            expiry=deadlines.schedule(()->result.completeExceptionally(new TimeoutException(
                    "The HTTP request timed out; delivery could not be confirmed.")),Math.max(1,deadline-System.nanoTime()),TimeUnit.NANOSECONDS);
        }
        @Override public CompletableFuture<Response> exchange(Request request) {
            if(!used.compareAndSet(false,true))return CompletableFuture.failedFuture(new IllegalStateException("HTTP delivery is single-use."));
            observation=new Observation();
            try {observation.origin=bpsh.journey.JourneyOrigins.authenticationOrigin(request.uri());}
            catch(IllegalArgumentException ignored) { /* The normal request validator rejects it. */ }
            Observation observed=observation;
            var published=new CompletableFuture<Response>();
            published.whenComplete((response,failure)->{if(failure!=null)result.cancel(true);});
            result.whenComplete((response,failure)->{
                if(failure!=null) {
                    if(observed.reportedFailure==null)report(observed,HttpAuthenticationProgress.failureStage(failure,false),0);
                } else {
                    Stage outcome=response.authentication().applicationAuthorizationConflict()?Stage.AUTHORIZATION_CONFLICT:
                            response.status()==407?Stage.PROXY_AUTH_REQUIRED:switch(response.authentication().status()) {
                        case ACCEPTED -> observed.sentProof?Stage.ACCEPTED:Stage.CONNECTION_REUSED;
                        case REJECTED -> Stage.REJECTED;
                        case UNCONFIRMED -> Stage.UNCONFIRMED;
                    };
                    if(observed.reportedFailure==null)report(observed,outcome,response.status());
                    if(response.status()==403)report(observed,Stage.APPLICATION_DENIED,403);
                    else if(response.status()>=500)report(observed,Stage.SERVER_ERROR,response.status());
                }
                if(failure!=null)published.completeExceptionally(failure);
                else if(!published.complete(response))response.close();
            });
            if(result.isDone()) {release();return published;}
            try {perform(request,deadline,this);return published;}
            catch(RuntimeException failure) {result.completeExceptionally(failure);release();return published;}
        }
        void cancelWork() {
            if(outbound!=null)outbound.cancel();
            Work current=work;
            if(current!=null) {
                if(workers instanceof java.util.concurrent.ThreadPoolExecutor pool && pool.remove(current))current.close();
                else if(current.runner!=null)current.runner.interrupt();
            }
        }
        void release() {
            if(!released.compareAndSet(false,true)) {leases.remove(this);return;}
            if(expiry!=null)expiry.cancel(false);
            if(requestBody!=null)requestBody.close();
            lastUsed=admission.clock.getAsLong();permit.close();leases.remove(this);
        }
        @Override public void close() {
            if(!result.isDone())report(observation,Stage.CANCELLED,0);
            if(!result.isDone())result.completeExceptionally(new IOException("HTTP delivery was cancelled."));
            if(!used.get())release();
        }
    }
    private final class Work implements Runnable,AutoCloseable {
        final Lease lease;
        final Runnable operation;
        final AtomicBoolean claimed=new AtomicBoolean();
        volatile Thread runner;
        Work(Lease lease,Runnable operation) {this.lease=lease;this.operation=operation;}
        @Override public void run() {
            if(!claimed.compareAndSet(false,true))return;
            runner=Thread.currentThread();
            try {if(!lease.result.isDone()) {admission.beforeConnect();operation.run();}}
            finally {runner=null;lease.release();}
        }
        @Override public void close() {
            if(claimed.compareAndSet(false,true))lease.release();
            else if(runner!=null)runner.interrupt();
        }
    }

    private static Set<String> hopHeaders(List<Header> headers) {
        Set<String> result = new HashSet<>(HOP_HEADERS);
        for (Header header : headers) if (header.name().equalsIgnoreCase("connection"))
            for (String name : header.value().split(",")) result.add(name.trim().toLowerCase(Locale.ROOT));
        return result;
    }

    private static HttpMessageBody readBounded(ClassicHttpResponse response,Runnable abort,HttpMessageBody.Allocator allocator) throws IOException {
        var entity=response.getEntity();
        try(var builder=allocator.builder(MAX_RESPONSE_BYTES)) {
            if(entity==null)return builder.finish();
            if(entity.getContentLength()>MAX_RESPONSE_BYTES) {abort.run();throw new IOException("The HTTP response exceeds the 16 MiB limit.");}
            try(var input=entity.getContent()) {
                byte[] buffer=new byte[8192];int count;
                while((count=input.read(buffer))!=-1)builder.append(java.nio.ByteBuffer.wrap(buffer,0,count));
            }
            return builder.finish();
        }
    }

    private char[] copyPassword() {
        synchronized (password) {
            if (closed.get()) throw new IllegalStateException("This identity has been retired.");
            return password.clone();
        }
    }

    @Override public void close() {
        if (!closed.compareAndSet(false, true)) return;
        try {
            var cleanup = new ArrayList<Runnable>();
            for (var lease : leases) cleanup.add(lease::close);
            for (var delivery : pending) cleanup.add(() -> delivery.completeExceptionally(new IOException("This HTTP authentication identity has been retired.")));
            cleanup.add(() -> client.close(CloseMode.IMMEDIATE));
            bpsh.authentication.ServiceCleanup.close(cleanup.toArray(Runnable[]::new));
        } finally { synchronized (password) { Arrays.fill(password, '\0'); } established.clear(); }
    }

    private record ScopePrincipal(String name) implements Principal { @Override public String getName() { return name; } }
    private static final class Observation {
        int exchanges; long deadlineNanos; Socket socket; URI origin;
        boolean accepted,authenticate,selectedOrigin,sentProof; volatile boolean attempted;
        volatile Stage reportedFailure;
    }

    private void report(Observation observation,Stage stage,int status) {
        if(settings==null || observation==null)return;
        if(observation.origin!=null && !settings.allows(observation.origin) && stage!=Stage.ORIGIN_BLOCKED)return;
        if(stage.failure() || stage==Stage.CANCELLED)observation.reportedFailure=stage;
        try {progress.accept(new HttpAuthenticationProgress(stage,settings.protocol(),stage==Stage.ORIGIN_BLOCKED?null:observation.origin,java.time.Instant.now(),status));}
        catch(RuntimeException ignored) { /* An inspection listener cannot change delivery. */ }
    }

    /** Evidence is attached to the actual socket, not the identity or a previous request context. */
    private final class EvidenceExecutor extends HttpRequestExecutor {
        @Override public ClassicHttpResponse execute(ClassicHttpRequest request, HttpClientConnection connection,
                HttpResponseInformationCallback information, HttpContext rawContext) throws IOException, HttpException {
            // CONNECT runs before MainClientExec installs the destination route, and
            // before the plain proxy socket is upgraded to TLS. It is proxy setup,
            // not a destination authentication transmission or accepted identity.
            if(request.getMethod().equalsIgnoreCase("CONNECT")) {
                var response=boundedResponse(super.execute(request,connection,information,rawContext),connection);
                if(response.getCode()!=200 && response.getEntity()!=null) {
                    // ConnectExec otherwise materializes a refused tunnel's entire body.
                    // Drain it through the limit; proxy failures expose safe diagnostics.
                    response.getEntity().close();response.setEntity(null);
                }
                return response;
            }
            var context = HttpClientContext.castOrCreate(rawContext);
            Observation delivery = (Observation) context.getAttribute(DELIVERY);
            if (delivery != null && ++delivery.exchanges > 4) throw new IOException("Too many HTTP authentication exchanges.");
            Socket socket = ((ManagedHttpClientConnection) connection).getSocket();
            if(delivery!=null && delivery.authenticate && delivery.exchanges==1 &&
                    (settings.protocol()==HttpAuthentication.Protocol.BASIC || established.get(socket)!=settings.protocol()))
                report(delivery,Stage.STARTED,0);
            if (delivery != null && delivery.authenticate && settings.protocol() != HttpAuthentication.Protocol.BASIC && delivery.socket != null && delivery.socket != socket) {
                report(delivery,Stage.CONNECTION_CLOSED,0);
                throw new IOException("The server closed the connection during NTLM authentication.");
            }
            if (delivery != null) { delivery.socket = socket; delivery.attempted = true; }
            var auth = context.getAuthExchange(context.getHttpRoute().getTargetHost()).getAuthScheme();
            boolean sentProof = delivery != null && delivery.authenticate && request.containsHeader("Authorization") && auth != null && auth.isChallengeComplete();
            if(delivery!=null && delivery.authenticate && request.containsHeader("Authorization")) {
                report(delivery,settings.protocol()==HttpAuthentication.Protocol.BASIC?Stage.BASIC_SENT:
                        sentProof?Stage.AUTHENTICATE_SENT:Stage.NEGOTIATE_SENT,0);
                delivery.sentProof|=sentProof;
            }
            ClassicHttpResponse response;
            try {response = super.execute(request, connection, information, rawContext);}
            catch(org.apache.hc.core5.http.ConnectionClosedException closed) {report(delivery,Stage.CONNECTION_CLOSED,0);throw closed;}
            boundedResponse(response,connection);
            if (delivery == null || !delivery.selectedOrigin) return response;
            if (response.getCode() >= 200 && response.getCode() < 400) {
                if (sentProof && settings.protocol() != HttpAuthentication.Protocol.BASIC) established.put(socket, settings.protocol());
                delivery.accepted = sentProof || (settings.protocol() != HttpAuthentication.Protocol.BASIC && established.get(socket) == settings.protocol());
            } else {
                if (response.getCode() == 401) established.remove(socket);
                delivery.accepted = response.getCode() != 401 && settings.protocol() != HttpAuthentication.Protocol.BASIC && established.get(socket) == settings.protocol();
            }
            return response;
        }

        private ClassicHttpResponse boundedResponse(ClassicHttpResponse response,HttpClientConnection connection) throws IOException {
            if(response.getEntity()!=null)response.setEntity(new BoundedResponseEntity(response.getEntity(),
                    ()->connection.close(CloseMode.IMMEDIATE)));
            return response;
        }
    }
}
