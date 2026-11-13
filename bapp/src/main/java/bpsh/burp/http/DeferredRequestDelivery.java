package bpsh.burp.http;

import bpsh.authentication.AuthenticationFailure;
import bpsh.browser.AuthTrafficGuard;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.message.requests.HttpRequest;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.LongSupplier;

/** Transfers an exact, pinned delivery across callback families without sharing host IDs or annotations. */
final class DeferredRequestDelivery implements AutoCloseable {
    /** A trusted owner retains the clean request and all generation/admission validators. */
    interface Plan extends AutoCloseable {
        HttpRequest clean();
        default ToolType tool() { return null; }
        SessionRequestProcessor.Result deliver(HttpRequestToBeSent callback)
                throws AuthenticationFailure, ExecutionException, InterruptedException;
        @Override void close();
    }
    private final AuthTrafficGuard guard;
    private final AtomicBoolean closed;
    private final LongSupplier clock;
    private final int maxPlans;
    private final long maxBytes;
    private final Map<String,Handle> plans = new HashMap<>();
    private long retained;
    private boolean stopped;
    private final ScheduledThreadPoolExecutor expiry = new ScheduledThreadPoolExecutor(1, task -> {
        var thread = new Thread(task,"bpsh-deferred-delivery-expiry"); thread.setDaemon(true); return thread;
    });

    DeferredRequestDelivery(AuthTrafficGuard guard, AtomicBoolean closed) {
        this(guard,closed,System::nanoTime,256,32L<<20);
    }
    DeferredRequestDelivery(AuthTrafficGuard guard, AtomicBoolean closed, LongSupplier clock, int maxPlans, long maxBytes) {
        this.guard=guard;this.closed=closed;this.clock=clock;this.maxPlans=maxPlans;this.maxBytes=maxBytes;
        expiry.setRemoveOnCancelPolicy(true);
    }

    /** Ownership transfers only on successful publication; an unclaimed plan expires within its original deadline. */
    synchronized Handle publish(Plan plan,long deadline) throws AuthenticationFailure {
        long left=deadline-clock.getAsLong();
        if(stopped || closed.get() || left<=0)throw SessionRequestProcessor.unavailable();
        int bytes=plan.clean().toByteArray().length();
        if(bytes>NativeTagParser.MAX_OUTPUT_BYTES || plans.size()>=maxPlans || 2L*bytes>maxBytes-retained)
            throw SessionRequestProcessor.configuration("The deferred authentication delivery capacity is exhausted.","Reduce request size or concurrency and retry.");
        var lease=guard.beginReplay();
        try {
            var clean=plan.clean();String agent=lease.decorate(clean.headerValue("User-Agent"));
            var marked=clean.hasHeader("User-Agent")?clean.withUpdatedHeader("User-Agent",agent):clean.withAddedHeader("User-Agent",agent);
            int weight=Math.addExact(bytes,marked.toByteArray().length());
            if(weight>maxBytes-retained)throw SessionRequestProcessor.configuration("The deferred authentication delivery byte budget is exhausted.","Reduce request size or concurrency and retry.");
            var handle=new Handle(plan,lease,marked,deadline,weight);
            plans.put(lease.key(),handle);retained+=weight;
            try { handle.expiration=expiry.schedule(handle::close,left,TimeUnit.NANOSECONDS); }
            catch(RuntimeException error) { handle.close();throw SessionRequestProcessor.unavailable(); }
            return handle;
        } catch(AuthenticationFailure|RuntimeException|LinkageError error) {lease.close();throw error;}
    }

    /** Validates destination, exact marked bytes, permitted source and one-time claim before invoking the owner. */
    SessionRequestProcessor.Result deliver(HttpRequestToBeSent request,AuthTrafficGuard.Decision ownership)
            throws AuthenticationFailure,ExecutionException,InterruptedException {
        Handle handle;
        synchronized(this) {
            handle=plans.get(ownership.replayKey());
            if(stopped || closed.get() || handle==null)throw SessionRequestProcessor.unavailable();
            if(clock.getAsLong()>=handle.deadline) {handle.close();throw SessionRequestProcessor.unavailable();}
            var expected=handle.marked.httpService();var actual=request.httpService();
            if(ownership.classification()!=AuthTrafficGuard.Classification.OWNED || handle.claimed ||
                    expected==null || actual==null || expected.secure()!=actual.secure() || expected.port()!=actual.port() || !expected.host().equalsIgnoreCase(actual.host()) ||
                    handle.plan.tool()!=null && (request.toolSource()==null || request.toolSource().toolType()!=handle.plan.tool()) ||
                    request.toByteArray().length()!=handle.bytes || !MessageDigest.isEqual(handle.digest,digest(request)))
                throw SessionRequestProcessor.configuration("The deferred authentication request changed or was already consumed.","Resend the original request without internal ownership markers.");
            handle.claimed=true;
        }
        return handle.plan.deliver(request);
    }

    synchronized int pendingCount() {return plans.size();}
    private static byte[] digest(HttpRequest request) {
        try {return MessageDigest.getInstance("SHA-256").digest(request.toByteArray().getBytes());}
        catch(java.security.NoSuchAlgorithmException impossible) {throw new IllegalStateException(impossible);}
    }

    /** The producer closes this after its actual delivery; expiry also closes dropped or abandoned requests. */
    final class Handle implements AutoCloseable {
        private final Plan plan;
        private final AuthTrafficGuard.Lease lease;
        private final HttpRequest marked;
        private final byte[] digest;
        private final long deadline;
        private final int bytes,weight;
        private boolean claimed,released;
        private java.util.concurrent.ScheduledFuture<?> expiration;
        private Handle(Plan plan,AuthTrafficGuard.Lease lease,HttpRequest marked,long deadline,int weight) {
            this.plan=plan;this.lease=lease;this.marked=marked;this.deadline=deadline;this.weight=weight;
            this.bytes=marked.toByteArray().length();this.digest=digest(marked);
        }
        HttpRequest marked() {return marked;}
        String key() {return lease.key();}
        @Override public void close() {
            synchronized(DeferredRequestDelivery.this) {
                if(released)return;released=true;plans.remove(lease.key(),this);retained-=weight;
                if(expiration!=null)expiration.cancel(false);lease.close();
            }
            plan.close();
        }
    }
    /** Observes owned expiry-worker termination within the shared cleanup deadline. */
    void awaitClosed(long millis) {
        try {if(!expiry.awaitTermination(millis,TimeUnit.MILLISECONDS))throw new IllegalStateException("Deferred delivery expiry did not terminate within the cleanup deadline.");}
        catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new IllegalStateException("Deferred delivery cleanup was interrupted.");}
    }
    @Override public void close() {
        java.util.List<Handle> remaining;
        synchronized(this) {if(stopped)return;stopped=true;remaining=java.util.List.copyOf(plans.values());}
        var cleanup=new java.util.ArrayList<Runnable>();remaining.forEach(handle->cleanup.add(handle::close));
        cleanup.add(expiry::shutdownNow);bpsh.authentication.ServiceCleanup.close(cleanup.toArray(Runnable[]::new));
    }
}
