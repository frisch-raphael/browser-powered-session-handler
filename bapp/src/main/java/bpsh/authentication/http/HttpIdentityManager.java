package bpsh.authentication.http;

import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.JourneyCatalog;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.JourneyKey;
import bpsh.journey.SecretStore;
import bpsh.journey.BrowserSetup;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/** Owns direct identity selection and epochs; concrete setup and delivery belong to the shared factory. */
public final class HttpIdentityManager implements AutoCloseable {
    public record Selection(JourneyCatalog.Entry entry,long epoch) { }
    private final JourneyCatalog catalog;
    private final SecretStore secrets;
    private final HttpTransportFactory factory;
    private final HttpAuthenticationActivity activity;
    private final Map<JourneyKey,Long> epochs=new HashMap<>();
    private final Map<JourneyDefinition.Identity,Scope> scopes=new HashMap<>();
    private final Set<Scope> tests=new HashSet<>();
    private final AtomicInteger pending=new AtomicInteger();
    private final ScheduledThreadPoolExecutor timer=new ScheduledThreadPoolExecutor(1,task->{
        var thread=new Thread(task,"bpsh-http-identity-deadline");thread.setDaemon(true);return thread;
    });
    private boolean closed;
    private static final class Scope {
        final JourneyDefinition.Identity identity;
        final CompletableFuture<HttpAuthenticationService> service=new CompletableFuture<>();
        final Set<CompletableFuture<?>> waiting=ConcurrentHashMap.newKeySet();
        final Set<HttpAuthenticationService.Delivery> leases=ConcurrentHashMap.newKeySet();
        volatile boolean retired;
        volatile CompletableFuture<HttpAuthenticationService> opening;
        volatile long lastUse=System.nanoTime();
        Scope(JourneyDefinition.Identity identity) {this.identity=identity;}
        void retire() {
            synchronized(this) {if(retired)return;retired=true;}
            for(var future:waiting)future.completeExceptionally(new IOException("The HTTP identity changed or was cleared."));
            for(var lease:leases)lease.close();
            var setup=opening;if(setup!=null)setup.cancel(true);
            service.thenAccept(HttpAuthenticationService::close);
        }
    }
    public HttpIdentityManager(JourneyCatalog catalog,SecretStore secrets,HttpTransportFactory factory) {
        this(catalog,secrets,factory,null);
    }
    public HttpIdentityManager(JourneyCatalog catalog,SecretStore secrets,HttpTransportFactory factory,HttpAuthenticationActivity activity) {
        this.catalog=catalog;this.secrets=secrets;this.factory=factory;timer.setRemoveOnCancelPolicy(true);
        this.activity=activity;
    }
    public HttpMessageBody.Allocator bodies() {return factory.bodies();}
    public synchronized Selection select(JourneyCatalog.Entry entry) {
        return new Selection(entry,epochs.getOrDefault(entry.identity().key(),0L));
    }
    private synchronized boolean current(Selection selection) {
        return !closed && catalog.snapshot().isCurrent(selection.entry().identity()) &&
                epochs.getOrDefault(selection.entry().identity().key(),0L)==selection.epoch();
    }
    /** Selection is captured before dependent credential waits; body allocation follows this admission. */
    public CompletableFuture<HttpAuthenticationService.Delivery> admit(Selection selection,long deadline) {
        return reserve(selection,deadline,false,false);
    }
    private CompletableFuture<HttpAuthenticationService.Delivery> reserve(Selection selection,long deadline,boolean fresh,boolean recovery) {
        var result=new CompletableFuture<HttpAuthenticationService.Delivery>();
        if(pending.incrementAndGet()>64) {pending.decrementAndGet();return CompletableFuture.failedFuture(new IOException("HTTP identity waiting capacity is exhausted."));}
        result.whenComplete((value,error)->pending.decrementAndGet());
        Scope scope;
        synchronized(this) {
            reconcile();
            var entry=selection.entry();
            if(!current(selection) || entry.definition().draft()!=null || !entry.definition().transportAuthenticationEnabled()) {
                result.completeExceptionally(new IOException("This HTTP identity is no longer current."));return result;
            }
            scope=fresh?null:scopes.get(entry.identity());
            if(scope!=null && scope.service.isDone() && !scope.service.isCompletedExceptionally() && !scope.service.join().isOpen()) {
                scope.retire();scopes.remove(entry.identity());scope=null;
            }
            if(scope==null) {
                if(scopes.size()+tests.size()>=32) {
                    var idle=scopes.values().stream().filter(candidate->candidate.waiting.isEmpty() && candidate.leases.isEmpty() && candidate.service.isDone()
                            && !candidate.service.isCompletedExceptionally() && candidate.service.join().isIdle())
                            .min(Comparator.comparingLong(candidate->candidate.lastUse));
                    if(idle.isEmpty()) {result.completeExceptionally(new IOException("Too many HTTP identities are active."));return result;}
                    Scope retired=idle.get();scopes.remove(retired.identity,retired);retired.retire();
                }
                scope=new Scope(entry.identity());Scope created=scope;
                if(fresh)tests.add(scope);else scopes.put(entry.identity(),scope);
                try(var values=secrets.snapshot(entry.identity().key())) {
                    var spec=new HttpTransportFactory.ScopeSpec(UUID.randomUUID(),fresh?HttpTransportFactory.Purpose.TEST:HttpTransportFactory.Purpose.DIRECT,
                            entry.identity(),selection.epoch(),BrowserSetup.from(entry.definition()),recovery);
                    var opening=factory.open(spec,values,deadline);created.opening=opening;
                    if(created.retired)opening.cancel(true);
                    opening.whenComplete((service,error)->{
                        if(error!=null) {
                            created.service.completeExceptionally(error);
                            synchronized(HttpIdentityManager.this) {scopes.remove(entry.identity(),created);tests.remove(created);}
                        } else if(created.retired || !current(selection)) {
                            service.close();created.service.completeExceptionally(new IOException("This HTTP identity is no longer current."));
                        } else if(!created.service.complete(service))service.close();
                    });
                } catch(Exception error) {
                    scopes.remove(entry.identity(),created);tests.remove(created);created.service.completeExceptionally(error);
                }
            }
            if(scope.waiting.size()>=16) {result.completeExceptionally(new IOException("This identity has too many waiting requests."));return result;}
            scope.lastUse=System.nanoTime();scope.waiting.add(result);
        }
        Scope selected=scope;
        result.whenComplete((value,error)->{
            selected.waiting.remove(result);
            if(error!=null && fresh)retireTest(selected);
        });
        long remaining=deadline-System.nanoTime();
        if(remaining<=0) {result.completeExceptionally(new TimeoutException("HTTP identity admission timed out."));return result;}
        try {
            var expiry=timer.schedule(()->result.completeExceptionally(new TimeoutException("HTTP identity admission timed out.")),remaining,TimeUnit.NANOSECONDS);
            result.whenComplete((value,error)->expiry.cancel(false));
            selected.service.whenComplete((service,error)->{
                if(result.isDone())return;
                if(error!=null) {result.completeExceptionally(error);return;}
                try {
                    HttpAuthenticationService.Delivery admitted;
                    synchronized(HttpIdentityManager.this) {
                        if(selected.retired || !current(selection))throw new IOException("This HTTP identity is no longer current.");
                        admitted=service.admit(deadline);
                    }
                    var wrapped=new HttpAuthenticationService.Delivery() {
                        private final AtomicBoolean used=new AtomicBoolean(),released=new AtomicBoolean();
                        private volatile CompletableFuture<HttpAuthenticationService.Response> active;
                        @Override public CompletableFuture<HttpAuthenticationService.Response> exchange(HttpAuthenticationService.Request request) {
                            if(released.get() || !used.compareAndSet(false,true))return CompletableFuture.failedFuture(new IOException("HTTP delivery is single-use."));
                            var response=new CompletableFuture<HttpAuthenticationService.Response>();active=response;selected.waiting.add(response);
                            response.whenComplete((value,failure)->selected.waiting.remove(response));
                            synchronized(HttpIdentityManager.this) {
                                if(selected.retired || !current(selection)) {response.completeExceptionally(new IOException("This HTTP identity is no longer current."));close();return response;}
                                try {
                                    var definition=selection.entry().definition();
                                    if(!definition.httpAuthenticationEnabled() && (definition.mtls()==null ||
                                            !definition.mtls().origins().contains(bpsh.journey.JourneyOrigins.authenticationOrigin(request.uri())))) {
                                        response.completeExceptionally(new IOException("The destination is outside this journey's client-certificate origins."));close();return response;
                                    }
                                    var operation=admitted.exchange(request);
                                    response.whenComplete((value,failure)->{if(failure!=null)operation.cancel(true);});
                                    operation.whenComplete((value,failure)->{
                                        if(failure!=null)response.completeExceptionally(failure);
                                        else if(!response.complete(value))value.close();
                                    });
                                } catch(RuntimeException failure) {response.completeExceptionally(new IOException("HTTP delivery could not start."));close();}
                            }
                            return response;
                        }
                        @Override public void close() {
                            if(!released.compareAndSet(false,true))return;
                            if(active!=null && !active.isDone())active.completeExceptionally(new IOException("HTTP delivery was cancelled."));
                            admitted.close();selected.lastUse=System.nanoTime();selected.leases.remove(this);
                            if(fresh)retireTest(selected);
                        }
                    };
                    selected.leases.add(wrapped);
                    if(selected.retired || !result.complete(wrapped))wrapped.close();
                } catch(IOException|RuntimeException failure) {result.completeExceptionally(failure);}
            });
        } catch(RejectedExecutionException failure) {result.completeExceptionally(new IOException("HTTP identity admission is closing."));}
        return result;
    }
    private synchronized void retireTest(Scope scope) {tests.remove(scope);scope.retire();}
    /** Explicit HTTP-only tests own a fresh scope and return a complete response to their caller. */
    public CompletableFuture<HttpAuthenticationService.Response> test(JourneyCatalog.Entry entry,long deadline,boolean recovery) {
        var result=new CompletableFuture<HttpAuthenticationService.Response>();
        var admitted=reserve(select(entry),deadline,true,recovery);
        result.whenComplete((value,error)->{if(error!=null)admitted.cancel(true);});
        admitted.whenComplete((lease,error)->{
            if(error!=null) {result.completeExceptionally(error);return;}
            if(result.isDone()) {lease.close();return;}
            try(var builder=bodies().builder(0)) {
                var body=builder.finish();
                var operation=lease.exchange(new HttpAuthenticationService.Request(entry.definition().authenticationUrl(),"GET",List.of(),body));
                result.whenComplete((value,failure)->{if(failure!=null)operation.cancel(true);});
                operation.whenComplete((value,failure)->{
                    body.close();
                    if(failure!=null)result.completeExceptionally(failure);
                    else if(!result.complete(value))value.close();
                    lease.close();
                });
            } catch(RuntimeException failure) {lease.close();result.completeExceptionally(failure);}
        });
        return result;
    }
    public synchronized void invalidate(JourneyDefinition.Identity identity) {
        if(activity!=null)activity.clear(identity);
        epochs.merge(identity.key(),1L,Long::sum);
        Scope scope=scopes.remove(identity);if(scope!=null)scope.retire();
        for(var test:List.copyOf(tests))if(test.identity.equals(identity))retireTest(test);
    }
    public synchronized boolean cancelTests(JourneyDefinition.Identity identity) {
        boolean cancelled=false;
        for(var test:List.copyOf(tests))if(test.identity.equals(identity)) {
            for(var future:test.waiting)future.completeExceptionally(new AuthenticationFailure(AuthenticationFailure.Phase.QUEUE,
                    AuthenticationFailure.Cause.CANCELLED,"HTTP authentication test cancelled."));
            retireTest(test);cancelled=true;
        }
        return cancelled;
    }
    public synchronized void reconcile() {
        for(var entry:List.copyOf(scopes.entrySet())) {
            var scope=entry.getValue();
            if(!catalog.snapshot().isCurrent(entry.getKey()) || scope.service.isDone() && !scope.service.isCompletedExceptionally() && !scope.service.join().isOpen()) {
                scopes.remove(entry.getKey(),scope);scope.retire();
            }
        }
    }
    @Override public void close() {
        List<Scope> retired;
        synchronized(this) {
            if(closed)return;closed=true;
            retired=new ArrayList<>(scopes.values());retired.addAll(tests);scopes.clear();tests.clear();
        }
        var cleanup = new ArrayList<Runnable>();
        retired.forEach(scope -> cleanup.add(scope::retire)); cleanup.add(timer::shutdownNow);
        bpsh.authentication.ServiceCleanup.close(cleanup.toArray(Runnable[]::new));
    }
    /** Observes timer termination during off-EDT service cleanup. */
    public void awaitClosed(long millis) {
        try {
            if (!timer.awaitTermination(millis, TimeUnit.MILLISECONDS)) throw new IllegalStateException("HTTP identity timer did not terminate.");
        } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw new IllegalStateException("HTTP identity cleanup was interrupted."); }
    }
}
