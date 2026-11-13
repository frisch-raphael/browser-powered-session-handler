package bpsh.burp.http;

import bpsh.browser.AuthTrafficGuard;
import bpsh.journey.JourneyCatalog;
import bpsh.authentication.AuthenticationFailure;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.*;
import java.io.ByteArrayInputStream;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static bpsh.burp.http.SessionRequestProcessor.*;

/** Owns bounded one-time application replay delivery and response attribution for both callback families. */
public final class RecoveryReplayDelivery implements AutoCloseable {
    /** Actual replay send; response hooks retain the original response independently. */
    @FunctionalInterface public interface ReplayTransport { void send(HttpRequest request, long responseTimeoutMs) throws Exception; }
    private final JourneyCatalog registry;
    private final DeferredRequestDelivery deferred;
    private final HttpAuthenticationDelivery direct;
    private final SessionRequestProcessor processor;
    private final AuthTrafficGuard guard;
    private final SessionRecovery recovery;
    private final Diagnostics diagnostics;
    private final RequestControlState controls;
    private final AtomicBoolean closed;
    private final ReplayTransport transport;
    private final java.util.concurrent.ThreadPoolExecutor replayWorkers = new java.util.concurrent.ThreadPoolExecutor(2, 2, 0,
            java.util.concurrent.TimeUnit.MILLISECONDS, new java.util.concurrent.ArrayBlockingQueue<>(256), r -> { var t = new Thread(r, "bpsh-recovery-replay"); t.setDaemon(true); return t; });
    private final java.util.concurrent.ConcurrentHashMap<String, ReplayJob> replayDeliveries = new java.util.concurrent.ConcurrentHashMap<>();

    /** Wires shared replay policy, cleanup state and actual host transport. */
    RecoveryReplayDelivery(JourneyCatalog registry, AuthTrafficGuard guard, SessionRecovery recovery, Diagnostics diagnostics,
                           RequestControlState controls, AtomicBoolean closed, ReplayTransport transport, DeferredRequestDelivery deferred,HttpAuthenticationDelivery direct,SessionRequestProcessor processor) {
        this.direct=direct;this.processor=processor;this.deferred=deferred;this.registry=registry;this.guard=guard;this.recovery=recovery;this.diagnostics=diagnostics;this.controls=controls;this.closed=closed;this.transport=transport;
    }

    /** @param request Owned global replay. @param ownership Guard decision. @return Pinned delivery without matching browser rules. @throws AuthenticationFailure When replay provenance is stale or unavailable. */
    private SessionRequestProcessor.Result deliver(HttpRequestToBeSent request, ReplayJob replay) throws AuthenticationFailure,java.util.concurrent.ExecutionException,InterruptedException {
        if(closed.get()||replay==null||!replay.dispatched.compareAndSet(false,true))throw unavailable();
        replay.plan.validateForDelivery();
        recovery.record(new RequestExchange(AuthTrafficGuard.Family.GLOBAL,request.messageId()),replay.plan.uses(),false);
        replay.actualId=request.messageId();
        appendNote(replay.originalNotes,"BPSH recovery replay submitted to Burp: GLOBAL request "+request.messageId()+". Original response kept.");
        var notes=request.annotations();appendNote(notes,"BPSH recovery replay of "+replay.plan.originalId()+".");
        if(replay.plan.transport()!=null) {
            var cfg=controls.snapshot().controls();byte[] complete=replay.clean.toByteArray().getBytes();
            try(var admission=processor.capacity.admit(cfg,List.of(replay.plan.transport().entry().identity().key()),4L*complete.length+(16L<<20))) {
                var framed=HttpAuthenticationDirective.prepare(complete);
                var selected=replay.plan.transport();
                byte[] outgoing=selected.entry().definition().httpAuthenticationEnabled()?framed.request():framed.applicationAuthorizationRequest();
                var sent=direct.deliverResolved(replay.clean,notes,selected,outgoing,
                        System.nanoTime()+java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(cfg.requestWaitTimeoutMs()),admission,
                        replay.plan::validateForDelivery,()->{},bpsh.authentication.http.HttpAuthenticationService.ChallengePolicy.CHALLENGE);
                observedDirect(new RequestExchange(AuthTrafficGuard.Family.GLOBAL,request.messageId()),sent.response(),sent.annotations(),replay.clean);
                return new SessionRequestProcessor.Result(replay.clean,sent.annotations(),null,sent.response());
            }
        }
        return SessionRequestProcessor.Result.continueWith(replay.clean,notes);
    }

    /** Native direct delivery observes its actual response once, independently of host callbacks for spoofed responses. */
    void observedDirect(RequestExchange exchange,burp.api.montoya.http.message.responses.HttpResponse response,Annotations notes,HttpRequest original) {
        try {response(exchange,response,notes,original);}
        catch(RuntimeException|LinkageError failure) {
            var safe=new AuthenticationFailure(AuthenticationFailure.Phase.LIFECYCLE,AuthenticationFailure.Cause.UNKNOWN,
                    "Response recovery could not be processed. The original server response was retained.");
            diagnostics.state(null,safe);appendNote(notes,safe.problem());
        }
    }

    /** @param exchange Actual family-qualified response. @param response Original response. @param notes Host notes. @param initiatingRequest Original request metadata. @return Whether owned login traffic bypasses Proxy interception. */
    boolean response(RequestExchange exchange, burp.api.montoya.http.message.responses.HttpResponse response, Annotations notes, HttpRequest initiatingRequest) {
        boolean internal = guard.consumeResponse(exchange.family(), exchange.id());
        // Active jobs already own bounded replay correlation; never retain a second response ledger.
        for (var replay : replayDeliveries.values()) if (exchange.family() == AuthTrafficGuard.Family.GLOBAL && replay.actualId == exchange.id()) {
            appendNote(notes, "BPSH recovery replay of " + replay.plan.originalId() + "."); break;
        }
        if (!closed.get()) {
            var decision = recovery.receivedPlan(exchange, response.statusCode(), () -> {
                int actualBytes = response.toByteArray().length() - response.bodyOffset();
                return new SessionRecovery.Response(response.statusCode(), response.headerValue("Content-Type"), response.headerValue("Content-Encoding"),
                        actualBytes, () -> new ByteArrayInputStream(response.body().getBytes()));
            }, internal, controls.snapshot().controls().enabled());
            if (decision.matched()) appendNote(notes, "BPSH: This response matched the expired-session rule (HTTP " + response.statusCode() + "). Original response kept."
                    + (decision.replay() == null ? " No replay was scheduled for this request." : " Login and one recovery replay were requested."));
            if (decision.replay() != null) {
                appendNote(notes, "BPSH recovery reference: " + exchange + ".");
                var initiating = initiatingRequest; var service = initiating == null ? null : initiating.httpService();
                decision.replay().whenComplete((plan, error) -> {
                    if (error != null) { replayFailure(notes, error); return; }
                    var job = new ReplayJob(plan, service, notes);
                    if (closed.get() || transport == null) { job.close(); replayFailure(notes, unavailable()); return; }
                    try { replayWorkers.execute(job); }
                    catch (RuntimeException failure) { job.close(); replayFailure(notes, new AuthenticationFailure(AuthenticationFailure.Phase.QUEUE,
                            AuthenticationFailure.Cause.CAPACITY, "The recovery replay queue is full. The original response was retained.")); }
                });
            }
        }
        return internal;
    }

    private final class ReplayJob implements Runnable, AutoCloseable {
        final SessionRecovery.ReplayPlan plan;
        final burp.api.montoya.http.HttpService service;
        final Annotations originalNotes;
        final AtomicBoolean dispatched = new AtomicBoolean();
        volatile HttpRequest clean;
        volatile DeferredRequestDelivery.Handle lease;
        final AtomicBoolean released=new AtomicBoolean();
        volatile long actualId = -1;
        ReplayJob(SessionRecovery.ReplayPlan plan, burp.api.montoya.http.HttpService service, Annotations originalNotes) { this.plan = plan; this.service = service; this.originalNotes = originalNotes; }
        @Override public void run() {
            try {
                if (closed.get() || !controls.snapshot().controls().enabled()) return;
                clean = HttpRequest.httpRequest(service, ByteArray.byteArray(plan.claim()));
                long timeout=controls.snapshot().controls().requestWaitTimeoutMs();
                lease=deferred.publish(new DeferredRequestDelivery.Plan(){
                    public HttpRequest clean(){return clean;}
                    public SessionRequestProcessor.Result deliver(HttpRequestToBeSent callback) throws AuthenticationFailure,java.util.concurrent.ExecutionException,InterruptedException {
                        return RecoveryReplayDelivery.this.deliver(callback,ReplayJob.this);
                    }
                    public void close(){ReplayJob.this.close();}
                },System.nanoTime()+java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(timeout));
                replayDeliveries.put(lease.key(),this);
                if(released.get() || closed.get()) {replayDeliveries.remove(lease.key(),this);return;}
                transport.send(lease.marked(),timeout);
            } catch (Exception | LinkageError error) { replayFailure(originalNotes, error); }
            finally { close(); }
        }
        @Override public void close() {
            if(!released.compareAndSet(false,true))return;
            var marker = lease; if (marker != null) { replayDeliveries.remove(marker.key(), this); marker.close(); } plan.close();
        }
    }
    private void replayFailure(Annotations notes, Throwable error) {
        if (closed.get()) return;
        Throwable cause = error instanceof java.util.concurrent.CompletionException && error.getCause() != null ? error.getCause() : error;
        var safe = cause instanceof AuthenticationFailure known ? known : new AuthenticationFailure(AuthenticationFailure.Phase.LIFECYCLE,
                AuthenticationFailure.Cause.UNKNOWN, "The recovery replay did not complete. The original response was retained.");
        var entry = safe.journey() == null ? null : registry.snapshot().entries().get(safe.journey().key());
        String alias = entry == null ? null : entry.definition().alias();
        diagnostics.state(alias, safe); appendNote(notes, "BPSH recovery failed. Original response kept. " + Diagnostics.detail(alias, safe));
    }

    /** Observes replay worker termination within the cleanup budget. */
    public void awaitClosed(long millis) {
        try {
            if (!replayWorkers.awaitTermination(millis, java.util.concurrent.TimeUnit.MILLISECONDS))
                throw new IllegalStateException("Recovery replay workers did not terminate within the cleanup budget.");
        } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw new IllegalStateException("Recovery replay cleanup was interrupted."); }
    }

    /** Cancels owned replay workers and plans; leaves global stop rejection to its adapter. */
    @Override public void close() {
        closed.set(true);
        var cleanup=new java.util.ArrayList<Runnable>();
        for(var task:replayWorkers.shutdownNow())if(task instanceof ReplayJob job)cleanup.add(job::close);
        java.util.List.copyOf(replayDeliveries.values()).forEach(job->cleanup.add(job::close));
        bpsh.authentication.ServiceCleanup.close(cleanup.toArray(Runnable[]::new));
    }
}
