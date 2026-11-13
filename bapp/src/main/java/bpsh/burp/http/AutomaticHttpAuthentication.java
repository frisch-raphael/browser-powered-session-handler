package bpsh.burp.http;

import bpsh.authentication.AuthenticationFailure;
import bpsh.authentication.http.HttpIdentityManager;
import bpsh.browser.AuthTrafficGuard;
import bpsh.journey.JourneyCatalog;
import bpsh.journey.JourneyKey;
import bpsh.request.RequestSettings;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import static bpsh.burp.http.SessionRequestProcessor.*;

/** Selects automatic request authentication once, independently of reusable captured-token acquisition. */
final class AutomaticHttpAuthentication {
    private final JourneyCatalog catalog;
    private final NativeTagResolver resolver;
    private final HttpIdentityManager identities;
    private final HttpAuthenticationDelivery delivery;
    private final SessionRequestProcessor processor;
    private final DeferredRequestDelivery deferred;
    private final AtomicBoolean closed;
    private final SessionRecovery recovery;
    private final RecoveryReplayDelivery responses;

    AutomaticHttpAuthentication(JourneyCatalog catalog,NativeTagResolver resolver,HttpIdentityManager identities,
                                HttpAuthenticationDelivery delivery,SessionRequestProcessor processor,
                                DeferredRequestDelivery deferred,AtomicBoolean closed,SessionRecovery recovery,RecoveryReplayDelivery responses) {
        this.catalog=catalog;this.resolver=resolver;this.identities=identities;this.delivery=delivery;
        this.processor=processor;this.deferred=deferred;this.closed=closed;this.recovery=recovery;this.responses=responses;
    }

    /** Null leaves ordinary capture/tag processing with its existing owner. */
    Result prepare(HttpRequest request,Annotations notes,RequestRuleMatcher.Context context,RequestControlState.Applied applied,
                   List<RequestSettings.AutomaticRule> matching,boolean proxy) {
        Pending plan=null;
        try {
            plan=plan(request,context,applied,matching);
            if(plan==null)return null;
            if(!proxy)return plan.execute(notes,context.exchange());
            var handle=deferred.publish(plan,plan.deadline);plan.handle=handle;
            if(plan.released.get()) {handle.close();throw unavailable();}
            return Result.continueWith(handle.marked(),notes);
        } catch(AuthenticationFailure|RuntimeException|LinkageError error) {
            if(plan!=null)plan.close();
            if(proxy && plan!=null && plan.controls.requestPolicy()==RequestSettings.RequestPolicy.WAIT_FOR_LOGIN &&
                    error instanceof AuthenticationFailure safe && (safe.phase()==AuthenticationFailure.Phase.QUEUE ||
                            safe.reason()==AuthenticationFailure.Cause.STALE || safe.reason()==AuthenticationFailure.Cause.CLOSED))
                return processor.stopped(request,notes,context.exchange(),plan.selection.entry().definition().canonicalAlias(),safe);
            return processor.failed(request,notes,context.exchange(),null,plan!=null && plan.dispatched.get(),
                    error instanceof AuthenticationFailure safe?safe:unknown());
        }
    }

    private Pending plan(HttpRequest request,RequestRuleMatcher.Context context,RequestControlState.Applied applied,List<RequestSettings.AutomaticRule> matching)
            throws AuthenticationFailure {
        if(closed.get() || matching.isEmpty())return null;
        var snapshot=catalog.snapshot();var entries=new ArrayList<JourneyCatalog.Entry>();
        JourneyCatalog.Entry transport=null;
        for(var rule:matching) {
            JourneyCatalog.Entry entry;
            try {entry=snapshot.resolve(new JourneyKey(rule.journey().scope(),rule.journey().id()));}
            catch(IllegalStateException missing) {throw configuration("An enabled automatic journey is unavailable.","Review its rule in Session handling.");}
            if(entry.definition().draft()!=null)throw configuration("An enabled automatic journey has incomplete settings.","Complete its settings and save the journey.").forJourney(entry.identity());
            entries.add(entry);
            if(entry.definition().transportOnly())transport=entry;
        }
        if(transport==null)return null;
        if(identities==null)throw configuration("HTTP authentication is unavailable.","Reload the current extension build.");
        if(transport.definition().draft()!=null)throw configuration("This automatic authentication journey has incomplete settings.","Complete its settings and save the journey.");
        var destination=bpsh.journey.JourneyOrigins.authenticationOrigin(java.net.URI.create(request.url()));
        transport=null;
        for(var candidate:entries) {
            var definition=candidate.definition();
            if(!definition.transportOnly())continue;
            if(definition.httpAuthenticationEnabled()?definition.httpAuthentication().allows(destination):definition.mtls().origins().contains(destination))transport=candidate;
        }
        if(transport==null)return null;
        boolean replacesAuthorization=transport.definition().httpAuthenticationEnabled();
        var captures=new ArrayList<NativeTagResolver.Automatic>();
        for(int i=0;i<matching.size();i++)if(entries.get(i).definition().extraction()!=null) {
            var source=new NativeTagResolver.Automatic(entries.get(i),matching.get(i).recovery(),replacesAuthorization);
            if(source.requiresCapture())captures.add(source);
        }
        int bytes=request.toByteArray().length();
        if(bytes>NativeTagParser.MAX_OUTPUT_BYTES)throw configuration("The automatic authenticated request exceeds the 4 MiB message ceiling.","Reduce the request size or send it without this automatic rule.");
        var keys=new ArrayList<JourneyKey>();keys.add(transport.identity().key());captures.forEach(source->keys.add(source.entry().identity().key()));
        var clean=HttpRequest.httpRequest(request.httpService(),ByteArray.byteArray(request.toByteArray().getBytes()));
        long deadline=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(applied.controls().requestWaitTimeoutMs());
        return new Pending(clean,identities.select(transport),List.copyOf(captures),applied.controls(),List.copyOf(keys),deadline,context);
    }

    private final class Pending implements DeferredRequestDelivery.Plan {
        private final HttpRequest clean;
        private final HttpIdentityManager.Selection selection;
        private final List<NativeTagResolver.Automatic> captures;
        private final RequestSettings.Controls controls;
        private final List<JourneyKey> keys;
        private volatile RequestCapacity.Lease admission;
        private final long deadline;
        private final RequestRuleMatcher.Context context;
        private final AtomicBoolean released=new AtomicBoolean(),dispatched=new AtomicBoolean();
        private volatile NativeTagResolver.Operation acquisition;
        private volatile DeferredRequestDelivery.Handle handle;
        Pending(HttpRequest clean,HttpIdentityManager.Selection selection,List<NativeTagResolver.Automatic> captures,
                RequestSettings.Controls controls,List<JourneyKey> keys,long deadline,RequestRuleMatcher.Context context) {
            this.clean=clean;this.selection=selection;this.captures=captures;this.controls=controls;
            this.keys=keys;this.deadline=deadline;this.context=context;
        }
        @Override public HttpRequest clean(){return clean;}
        @Override public ToolType tool(){return context.exchange().family()==AuthTrafficGuard.Family.PROXY?ToolType.PROXY:null;}
        @Override public Result deliver(HttpRequestToBeSent callback){return execute(callback.annotations(),new RequestExchange(AuthTrafficGuard.Family.GLOBAL,callback.messageId()));}

        Result execute(Annotations notes,RequestExchange exchange) {
            try {
                if(released.get() || closed.get())throw unavailable();
                boolean wait=controls.requestPolicy()==RequestSettings.RequestPolicy.WAIT_FOR_LOGIN;
                var granted=processor.capacity.admitHttp(controls,keys,4L*clean.toByteArray().length()+(16L<<20),deadline,
                        ()->released.get() || closed.get() || !identities.isCurrent(selection));
                admission=granted;
                if(released.get()) {granted.close();throw unavailable();}
                var target=java.net.URI.create(clean.url());
                boolean ready=wait || identities.hasRecentAuthentication(selection,target);
                if(!ready)warm(target);
                acquisition=resolver.resolveAutomatic(clean.toByteArray().getBytes(),captures,wait);
                if(released.get()) {acquisition.close();throw unavailable();}
                var resolved=acquisition.future().get(Math.max(1,deadline-System.nanoTime()),TimeUnit.NANOSECONDS);
                if(!ready) {
                    appendNote(notes,"Journey "+selection.entry().definition().canonicalAlias()+": HTTP authentication was requested in the background; this request continues unchanged.");
                    return Result.continueWith(clean,notes);
                }
                var framed=HttpAuthenticationDirective.prepare(resolved.commit());
                byte[] request=selection.entry().definition().httpAuthenticationEnabled()?framed.request():framed.applicationAuthorizationRequest();
                var sent=delivery.deliverResolved(clean,notes,selection,request,deadline,admission,()->{
                    if(released.get() || closed.get() || !identities.isCurrent(selection) || System.nanoTime()>=deadline)throw new AuthenticationFailure(
                            AuthenticationFailure.Phase.LIFECYCLE,AuthenticationFailure.Cause.STALE,"This automatic authentication delivery is no longer current.");
                    resolved.validate();
                },()->dispatched.set(true),
                        wait?bpsh.authentication.http.HttpAuthenticationService.ChallengePolicy.CHALLENGE:bpsh.authentication.http.HttpAuthenticationService.ChallengePolicy.ESTABLISHED_ONLY);
                if(!wait && !identities.hasRecentAuthentication(selection,target))warm(target);
                var used=resolved.uses();
                if(!used.isEmpty()) {
                    recovery.recordLazy(exchange,used,clean.toByteArray().length(),()->resolved.replayTemplate(clean.toByteArray().getBytes(),selection));
                    responses.observedDirect(exchange,sent.response(),sent.annotations(),clean);
                }
                return new Result(clean,sent.annotations(),null,sent.response());
            } catch(InterruptedException error) {
                Thread.currentThread().interrupt();return failed(notes,exchange,
                        new AuthenticationFailure(AuthenticationFailure.Phase.QUEUE,AuthenticationFailure.Cause.CANCELLED,"Automatic request authentication was interrupted."));
            } catch(ExecutionException error) {
                return failed(notes,exchange,error.getCause() instanceof AuthenticationFailure safe?safe:
                        error.getCause() instanceof bpsh.authentication.http.HttpCapacityException?new AuthenticationFailure(AuthenticationFailure.Phase.QUEUE,
                                AuthenticationFailure.Cause.CAPACITY,"HTTP authentication delivery capacity is exhausted.","Retry after active requests finish."):
                        error.getCause() instanceof java.util.concurrent.TimeoutException?new AuthenticationFailure(AuthenticationFailure.Phase.QUEUE,
                                AuthenticationFailure.Cause.TIMEOUT,"Automatic HTTP authentication exceeded its request deadline."):unknown());
            } catch(java.util.concurrent.TimeoutException error) {
                return failed(notes,exchange,new AuthenticationFailure(
                        AuthenticationFailure.Phase.QUEUE,AuthenticationFailure.Cause.TIMEOUT,"Automatic request authentication exceeded its request deadline."));
            } catch(AuthenticationFailure|RuntimeException|LinkageError error) {
                return failed(notes,exchange,error instanceof AuthenticationFailure safe?safe:unknown());
            } finally {
                var marker=handle;if(marker!=null)marker.close();else close();
            }
        }
        private Result failed(Annotations notes,RequestExchange exchange,AuthenticationFailure error) {
            if(!dispatched.get() && controls.requestPolicy()==RequestSettings.RequestPolicy.WAIT_FOR_LOGIN &&
                    (error.phase()==AuthenticationFailure.Phase.QUEUE || error.reason()==AuthenticationFailure.Cause.STALE || error.reason()==AuthenticationFailure.Cause.CLOSED || !identities.isCurrent(selection)))
                return processor.unavailableResponse(clean,notes,exchange,selection.entry(),error);
            return processor.failed(clean,notes,exchange,selection.entry(),dispatched.get(),error);
        }
        private void warm(java.net.URI target) {
            var configured=selection.entry().definition().authenticationUrl();
            var probe=configured.getRawFragment()==null && bpsh.journey.JourneyOrigins.authenticationOrigin(configured).equals(bpsh.journey.JourneyOrigins.authenticationOrigin(target))?configured:target;
            identities.warm(selection,probe,System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(controls.attemptTimeoutMs()));
        }
        @Override public void close() {
            if(!released.compareAndSet(false,true))return;
            var operation=acquisition;try {if(operation!=null)operation.close();}finally {var lease=admission;if(lease!=null)lease.close();}
        }
    }
}
