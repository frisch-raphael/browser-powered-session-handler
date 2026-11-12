package bpsh.transport.httpauth;

import bpsh.authentication.AuthenticationFailure;
import bpsh.authentication.http.*;
import bpsh.journey.*;
import bpsh.transport.tls.JourneyTlsContexts;
import bpsh.transport.tls.Pkcs11IdentityManager;
import org.apache.hc.core5.util.TimeValue;
import javax.net.ssl.SSLContext;
import java.net.URI;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import java.util.function.LongSupplier;

/** One owner for setup, delivery, buffers, connections and independently retired identity scopes. */
public final class HttpTransportRuntime implements HttpTransportFactory {
    private final ThreadPoolExecutor workers=new ThreadPoolExecutor(16,16,0,TimeUnit.MILLISECONDS,new ArrayBlockingQueue<>(48),
            task->daemon(task,"bpsh-http-transport"));
    private final ThreadPoolExecutor setup=new ThreadPoolExecutor(4,4,0,TimeUnit.MILLISECONDS,new ArrayBlockingQueue<>(32),
            task->daemon(task,"bpsh-http-setup"));
    private final ScheduledThreadPoolExecutor deadlines=new ScheduledThreadPoolExecutor(1,task->daemon(task,"bpsh-http-deadline"));
    private final HttpTransportAdmission admission;
    private final Pkcs11IdentityManager identities;
    private final LongSupplier clock;
    private final long idleNanos;
    private final Function<ScopeSpec,java.util.function.Consumer<HttpAuthenticationProgress>> observer;
    private final Set<Scope> scopes=new HashSet<>();
    private final Set<SetupTask> opens=ConcurrentHashMap.newKeySet();
    private final AtomicBoolean closed=new AtomicBoolean(),maintenanceQueued=new AtomicBoolean();
    private int claims;
    private static Thread daemon(Runnable task,String name) {var thread=new Thread(task,name);thread.setDaemon(true);return thread;}
    public HttpTransportRuntime() {this(null);}
    public HttpTransportRuntime(Pkcs11IdentityManager identities) {this(identities,spec->ignored->{});}
    public HttpTransportRuntime(Pkcs11IdentityManager identities,Function<ScopeSpec,java.util.function.Consumer<HttpAuthenticationProgress>> observer) {
        this(identities,System::nanoTime,TimeUnit.SECONDS.toNanos(30),observer);
    }
    HttpTransportRuntime(Pkcs11IdentityManager identities,LongSupplier clock,long idleNanos) {
        this(identities,clock,idleNanos,spec->ignored->{});
    }
    private HttpTransportRuntime(Pkcs11IdentityManager identities,LongSupplier clock,long idleNanos,
            Function<ScopeSpec,java.util.function.Consumer<HttpAuthenticationProgress>> observer) {
        this.observer=Objects.requireNonNull(observer);
        this.identities=identities;this.clock=clock;this.idleNanos=idleNanos;admission=new HttpTransportAdmission(clock);
        admission.reclaimIdle=this::reclaimIdleConnections;deadlines.setRemoveOnCancelPolicy(true);
        deadlines.scheduleWithFixedDelay(()->{
            if(closed.get() || !maintenanceQueued.compareAndSet(false,true))return;
            try {setup.execute(()->{try {maintain();}finally {maintenanceQueued.set(false);}});}
            catch(RejectedExecutionException stopping) {maintenanceQueued.set(false);}
        },1,1,TimeUnit.SECONDS);
    }
    @Override public HttpMessageBody.Allocator bodies() {return admission.bodies;}
    private final class Claim implements AutoCloseable {
        private boolean released;
        @Override public void close() {synchronized(HttpTransportRuntime.this) {if(!released) {released=true;claims--;}}}
    }
    private Claim claim() {
        for(;;) {
            Scope victim=null;
            synchronized(this) {
                if(closed.get())throw new IllegalStateException("HTTP transport is closed.");
                if(claims<32) {claims++;return new Claim();}
                var ordered=scopes.stream().sorted(Comparator.comparingLong(s->s.client.lastUsed())).toList();
                for(Scope scope:ordered)if(scope.retireIdle(false)) {victim=scope;break;}
                if(victim==null)throw new IllegalStateException("Too many HTTP authentication scopes are active.");
            }
            // Disposal may touch sockets; never do it under global capacity accounting.
            victim.close();
        }
    }
    private final class Scope implements HttpAuthenticationService {
        final HttpClientAuthenticationTransport client;
        final Claim claim;
        final boolean pinned;
        final java.util.function.Supplier<AuthenticationFailure> failure;
        private boolean retired,disposed;
        volatile java.util.function.BooleanSupplier usable = () -> true;
        final ScopeSpec spec;
        final Map<URI,HttpAuthenticationEvidence> observations=new ConcurrentHashMap<>();
        Scope(HttpClientAuthenticationTransport client,Claim claim,boolean pinned,java.util.function.Supplier<AuthenticationFailure> failure,ScopeSpec spec) {
            this.spec=spec;
            this.client=client;this.claim=claim;this.pinned=pinned;this.failure=failure;
        }
        synchronized boolean retireIdle(boolean expire) {
            if(retired || disposed || pinned || !client.isIdle() || expire && clock.getAsLong()-client.lastUsed()<idleNanos)return false;
            retired=true;return true;
        }
        @Override public synchronized boolean isIdle() {return client.isIdle();}
        @Override public synchronized boolean isOpen() {return !retired && !disposed && usable.getAsBoolean() && client.isOpen();}
        @Override public synchronized Delivery admit(long deadline) throws java.io.IOException {
            if(!isOpen())throw new java.io.IOException("This HTTP scope has been retired.");
            var admitted=client.admit(deadline);
            return new Delivery() {
                @Override public CompletableFuture<Response> exchange(Request request) {
                    var source=admitted.exchange(request);var result=new CompletableFuture<Response>();
                    result.whenComplete((response,error)->{if(error!=null)source.cancel(true);});
                    source.whenComplete((response,error)->{
                        if(error!=null) {result.completeExceptionally(error);return;}
                        var evidence=spec==null?response.authentication():response.authentication().attributed(spec.identity(),spec.invalidationEpoch());
                        Response attributed=response;
                        if(spec!=null) {attributed=new Response(response.status(),response.headers(),response.body().retain(),evidence);response.close();}
                        synchronized(Scope.this) {
                            if(evidence.origin()!=null && evidence.status()!=HttpAuthenticationEvidence.Status.UNCONFIRMED && isOpen())observations.put(evidence.origin(),evidence);
                        }
                        if(!result.complete(attributed))attributed.close();
                    });return result;
                }
                @Override public void close() {admitted.close();}
            };
        }
        @Override public List<HttpAuthenticationEvidence> observations() {return observations.values().stream().sorted(Comparator.comparing(e->e.origin().toString())).toList();}
        @Override public AuthenticationFailure failure() {return failure.get();}
        @Override public void close() {
            synchronized(this) {retired=true;if(disposed)return;disposed=true;}
            try {client.close();}
            finally {synchronized(HttpTransportRuntime.this) {scopes.remove(this);}observations.clear();claim.close();}
        }
    }
    private Scope create(Claim claim,HttpAuthentication settings,char[] password,Function<URI,SSLContext> tls,URI upstream,
                         boolean browser,boolean bypass,java.util.function.Supplier<AuthenticationFailure> failure,ScopeSpec spec) {
        return create(claim,settings,password,tls,upstream,browser,bypass,failure,spec,ignored->{});
    }
    private Scope create(Claim claim,HttpAuthentication settings,char[] password,Function<URI,SSLContext> tls,URI upstream,
                         boolean browser,boolean bypass,java.util.function.Supplier<AuthenticationFailure> failure,ScopeSpec spec,
                         java.util.function.Consumer<HttpAuthenticationProgress> progress) {
        var client=new HttpClientAuthenticationTransport(settings,password,tls,upstream,workers,deadlines,browser,bypass,admission,progress);
        var scope=new Scope(client,claim,browser,failure,spec);
        synchronized(this) {if(!closed.get()) {scopes.add(scope);return scope;}}
        scope.close();throw new IllegalStateException("HTTP transport is closing.");
    }
    /** Concrete native qualification seam; application setup uses the asynchronous core port. */
    public HttpAuthenticationService open(HttpAuthentication settings,char[] password,Function<URI,SSLContext> tls,URI upstream) {
        Claim claim=claim();try {return create(claim,settings,password,tls,upstream,false,false,()->null,null);}
        catch(RuntimeException|Error failure) {claim.close();throw failure;}
    }
    public HttpAuthenticationService openBrowser(HttpAuthentication settings,char[] password,Function<URI,SSLContext> tls,URI upstream) {
        return openBrowser(settings,password,tls,upstream,false);
    }
    public HttpAuthenticationService openBrowser(HttpAuthentication settings,char[] password,Function<URI,SSLContext> tls,URI upstream,boolean bypass) {
        Claim claim=claim();try {return create(claim,settings,password,tls,upstream,true,bypass,()->null,null);}
        catch(RuntimeException|Error failure) {claim.close();throw failure;}
    }
    @Override public CompletableFuture<HttpAuthenticationService> open(ScopeSpec spec,SecretStore.Values input,long deadline) {
        java.util.function.Consumer<HttpAuthenticationProgress> progress;
        try {progress=observer.apply(spec);}catch(RuntimeException unavailable) {progress=ignored->{};}
        final var observed=progress;
        Claim claim;
        try {claim=claim();}catch(RuntimeException failure) {
            setupFailure(spec,observed,closed.get()?HttpAuthenticationProgress.Stage.CANCELLED:HttpAuthenticationProgress.Stage.CAPACITY);
            return CompletableFuture.failedFuture(failure);
        }
        SecretStore.Values owned;
        try {owned=input.copy();}catch(RuntimeException failure) {claim.close();setupFailure(spec,observed,HttpAuthenticationProgress.Stage.SETUP_FAILED);return CompletableFuture.failedFuture(failure);}
        var task=new SetupTask(spec,owned,claim,deadline);opens.add(task);
        task.result.whenComplete((service,error)->{
            if(error!=null)setupFailure(spec,observed,HttpAuthenticationProgress.failureStage(error,true));
        });
        task.progress=observed;
        if(closed.get())task.close();else task.start();
        return task.result;
    }
    private static void setupFailure(ScopeSpec spec,java.util.function.Consumer<HttpAuthenticationProgress> observer,HttpAuthenticationProgress.Stage stage) {
        if(!spec.setup().httpAuthenticationEnabled())return;
        try {observer.accept(new HttpAuthenticationProgress(stage,spec.setup().httpAuthentication().protocol(),null,java.time.Instant.now(),0));}
        catch(RuntimeException ignored) { /* Diagnostics cannot fail authentication. */ }
    }
    private final class SetupTask implements Runnable,AutoCloseable {
        final ScopeSpec spec;
        final SecretStore.Values owned;
        final Claim claim;
        final long deadline;
        final CompletableFuture<HttpAuthenticationService> result=new CompletableFuture<>();
        final AtomicBoolean claimed=new AtomicBoolean();
        volatile ScheduledFuture<?> expiry;
        boolean installed;
        java.util.function.Consumer<HttpAuthenticationProgress> progress=ignored->{};
        SetupTask(ScopeSpec spec,SecretStore.Values owned,Claim claim,long deadline) {this.spec=spec;this.owned=owned;this.claim=claim;this.deadline=deadline;}
        void start() {
            result.whenComplete((scope,error)->{
                if(expiry!=null)expiry.cancel(false);
                if(error!=null && setup.remove(this))close();
            });
            try {
                long left=deadline-System.nanoTime();
                if(left<=0) {result.completeExceptionally(new TimeoutException("HTTP setup timed out."));close();return;}
                expiry=deadlines.schedule(()->result.completeExceptionally(new TimeoutException("HTTP setup timed out.")),left,TimeUnit.NANOSECONDS);
                if(result.isDone())close();else setup.execute(this);
            } catch(RejectedExecutionException rejected) {result.completeExceptionally(new java.io.IOException("HTTP setup capacity is exhausted or closing."));close();}
        }
        @Override public void run() {
            if(!claimed.compareAndSet(false,true))return;
            char[] pin=null,password=null;
            try(owned) {
                if(result.isDone() || closed.get()) {if(!result.isDone())result.cancel(true);return;}
                BrowserSetup configuration=spec.setup();password=owned.httpPassword();
                if(configuration.httpAuthenticationEnabled() && password==null)throw new AuthenticationFailure(AuthenticationFailure.Phase.SETUP,
                        AuthenticationFailure.Cause.MISSING_SECRET,"The journey is missing its HTTP authentication password.").atInput(AuthenticationFailure.Input.HTTP_PASSWORD);
                Pkcs11IdentityManager.Selected certificate=null;
                if(configuration.mtls()!=null) {
                    pin=owned.pin();
                    if(pin==null)throw new AuthenticationFailure(AuthenticationFailure.Phase.SETUP,AuthenticationFailure.Cause.MISSING_SECRET,"The journey is missing its mTLS PIN.").atInput(AuthenticationFailure.Input.MTLS_PIN);
                    if(identities==null)throw new IllegalStateException("No shared security-device manager.");
                    certificate=identities.select(configuration.mtls(),pin,spec.explicitRecovery(),deadline,()->closed.get() || result.isDone());
                }
                if(result.isDone() || closed.get()) {if(!result.isDone())result.cancel(true);return;}
                boolean browser=spec.purpose()==Purpose.BROWSER || spec.purpose()==Purpose.RECORDING;
                boolean bypass=browser && configuration.mtls()==null && configuration.browser().ignoreHttpsErrors();
                var tls=new JourneyTlsContexts(configuration.mtls(),certificate,bypass);var route=configuration.browser().proxy();
                var scope=create(claim,configuration.httpAuthenticationEnabled()?configuration.httpAuthentication():null,password,tls::forOrigin,
                        route==null?null:route.url(),browser,bypass,tls::failure,spec,progress);
                scope.usable = tls::usable;
                installed=true;
                if(closed.get() || !result.complete(scope))scope.close();
            } catch(Throwable failure) {
                result.completeExceptionally(failure);
                if(failure instanceof VirtualMachineError fatal)throw fatal;
            } finally {
                if(pin!=null)Arrays.fill(pin,'\0');if(password!=null)Arrays.fill(password,'\0');cleanup();
            }
        }
        private void cleanup() {owned.close();if(!installed)claim.close();opens.remove(this);if(expiry!=null)expiry.cancel(false);}
        @Override public void close() {result.cancel(true);if(claimed.compareAndSet(false,true))cleanup();}
    }
    private synchronized List<Scope> snapshot() {return List.copyOf(scopes);}
    void maintain() {
        for(Scope scope:snapshot()) {
            if(scope.retireIdle(true))scope.close();
            else if(scope.isOpen())scope.client.closeIdle(TimeValue.ofSeconds(30));
        }
    }
    private void reclaimIdleConnections() {
        var ordered=snapshot().stream().filter(scope->scope.isOpen() && scope.client.isIdle())
                .sorted(Comparator.comparingLong(scope->scope.client.lastUsed())).toList();
        for(Scope scope:ordered) {
            if(admission.connections.used()<16)break;
            scope.client.closeIdle(TimeValue.ZERO_MILLISECONDS);
        }
    }
    public record Capacity(int scopes,int opening,int activeSetup,int queuedSetup,long bufferedBytes,int admittedDeliveries,int connections,int peakConnections) { }
    public synchronized Capacity capacity() {return new Capacity(scopes.size(),opens.size(),setup.getActiveCount(),setup.getQueue().size(),
            bodies().usedBytes(),admission.admitted(),admission.connections.used(),admission.connections.peak());}
    @Override public void close() {
        if(!closed.compareAndSet(false,true))return;
        var cleanup = new ArrayList<Runnable>();
        for (SetupTask task : opens) cleanup.add(task::close);
        cleanup.add(() -> discard(setup.shutdownNow()));
        for (Scope scope : snapshot()) cleanup.add(scope::close);
        cleanup.add(() -> discard(workers.shutdownNow())); cleanup.add(deadlines::shutdownNow);
        bpsh.authentication.ServiceCleanup.close(cleanup.toArray(Runnable[]::new));
    }
    /** Releases abandoned task ownership while still attempting every remaining cleanup. */
    private static void discard(List<Runnable> abandoned) {
        var cleanup = new ArrayList<Runnable>();
        for (Runnable task : abandoned) if (task instanceof AutoCloseable owned) cleanup.add(() -> {
            try { owned.close(); } catch (Exception failure) { throw new IllegalStateException("An abandoned HTTP task did not close."); }
        });
        bpsh.authentication.ServiceCleanup.close(cleanup.toArray(Runnable[]::new));
    }
    /** Observes owned worker termination within one total budget, away from the Swing event thread. */
    public void awaitClosed(long millis) {
        long end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(millis);
        try {
            for (var executor : List.of(setup, workers, deadlines))
                if (!executor.awaitTermination(Math.max(0, end - System.nanoTime()), TimeUnit.NANOSECONDS))
                    throw new IllegalStateException("HTTP transport workers did not terminate within the cleanup budget.");
        } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw new IllegalStateException("HTTP transport cleanup was interrupted."); }
    }
}
