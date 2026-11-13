package bpsh.burp.http;

import bpsh.authentication.AuthenticationFailure;
import bpsh.browser.AuthTrafficGuard;
import bpsh.request.RequestSettings;
import burp.api.montoya.http.handler.*;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import static bpsh.burp.http.SessionRequestProcessor.*;

/** Global delivery boundary for terminal stops, owned traffic, direct HTTP identities and non-Proxy requests. */
public final class GlobalHttpSessionAdapter implements HttpHandler {
    private final SessionRequestProcessor processor;
    private final DeferredRequestDelivery deferred;
    private final AutomaticHttpAuthentication automatic;
    private final HttpAuthenticationDelivery direct;
    private final RecoveryReplayDelivery replays;
    private final RequestControlState controls;
    private final AtomicBoolean closed;

    /** Wires shared operations; installs no independent parsers, caches or workers. */
    GlobalHttpSessionAdapter(SessionRequestProcessor processor, HttpAuthenticationDelivery direct, RecoveryReplayDelivery replays,
                            RequestControlState controls, AtomicBoolean closed, DeferredRequestDelivery deferred, AutomaticHttpAuthentication automatic) {
        this.automatic=automatic;this.deferred=deferred;this.processor=processor;this.direct=direct;this.replays=replays;this.controls=controls;this.closed=closed;
    }

    /** @param request Actual global outgoing message. @return Supported continuation, terminal drop or actual direct-delivery response. */
    @Override public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        var exchange=new RequestExchange(AuthTrafficGuard.Family.GLOBAL,request.messageId());
        var applied=controls.snapshot(); var cfg=applied.controls();
        var notes=request.annotations();
        boolean terminal=false;
        try {
            var ownership=processor.ownership(request,exchange.family(),exchange.id());
            if(ownership.classification()==AuthTrafficGuard.Classification.INVALID)
                return action(processor.stopped(request,notes,exchange,null,ownership.failure()));
            if(ownership.replayKey()!=null) {terminal=true;return action(deferred.deliver(request,ownership));}
            var bytes=request.toByteArray();
            boolean httpTagged=HttpAuthenticationDirective.present(bytes);
            if(ownership.classification()==AuthTrafficGuard.Classification.OWNED) {
                terminal=true;
                if(httpTagged||hasTags(bytes))return action(processor.stopped(request,notes,exchange,null,nested()));
                return RequestToBeSentAction.continueWith(request.withUpdatedHeader("User-Agent",ownership.userAgent()),notes);
            }
            if(httpTagged) {
                terminal=true;
                if(closed.get())return action(processor.stopped(request,notes,exchange,null,unavailable()));
                if(bytes.length()>NativeTagParser.MAX_OUTPUT_BYTES)
                    return action(processor.stopped(request,notes,exchange,null,NativeTagParser.syntax("The tagged request exceeds the 4 MiB message ceiling.")));
                try(var admitted=processor.capacity.admit(cfg,List.of(),4L*bytes.length()+(16L<<20))) {
                    var delivered=direct.deliver(request,HttpAuthenticationDirective.consume(bytes.getBytes()),cfg.requestWaitTimeoutMs(),admitted);
                    return RequestToBeSentAction.spoof(delivered.response(),delivered.annotations());
                }
            }
            var tool=tool(request);
            if(tool==RequestSettings.Tool.PROXY)return RequestToBeSentAction.continueWith(request,notes);
            var context=new RequestRuleMatcher.Context(exchange,tool,null);
            var matching=processor.matching(request,context,applied);
            var authenticated=automatic.prepare(request,notes,context,applied,matching,false);
            return action(authenticated==null?processor.process(request,notes,context,applied,matching):authenticated);
        } catch(InterruptedException error) {
            Thread.currentThread().interrupt();
            return action(processor.failed(request,notes,exchange,null,terminal,new AuthenticationFailure(AuthenticationFailure.Phase.QUEUE,
                    AuthenticationFailure.Cause.CANCELLED,"This request's authentication wait was interrupted.","Resend the request when ready.")));
        } catch(ExecutionException error) {
            return action(processor.failed(request,notes,exchange,null,terminal,error.getCause() instanceof AuthenticationFailure safe?safe:unknown()));
        } catch(AuthenticationFailure error) {return action(processor.failed(request,notes,exchange,null,terminal,error));}
        catch(RuntimeException|LinkageError error) {return action(processor.failed(request,notes,exchange,null,terminal,unknown()));}
    }

    /** @param result Shared processor outcome. @return Global action without another credential pass. */
    private static RequestToBeSentAction action(SessionRequestProcessor.Result result) {
        if(result.response()!=null)return RequestToBeSentAction.spoof(result.response(),result.annotations());
        return result.stop()==null?RequestToBeSentAction.continueWith(result.request(),result.annotations()):RequestToBeSentAction.drop(result.annotations());
    }

    /** @param request Actual origin. @return Supported tool or null without guessing. */
    private static RequestSettings.Tool tool(HttpRequestToBeSent request) {
        try{return RequestSettings.Tool.valueOf(request.toolSource().toolType().name());}
        catch(IllegalArgumentException|NullPointerException error){return null;}
    }

    /** @param response Actual global response. @return Original response, retaining any separately authorized replay. */
    @Override public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        var notes=response.annotations();
        replays.response(new RequestExchange(AuthTrafficGuard.Family.GLOBAL,response.messageId()),response,notes,response.initiatingRequest());
        return ResponseReceivedAction.continueWith(response,notes);
    }
}
