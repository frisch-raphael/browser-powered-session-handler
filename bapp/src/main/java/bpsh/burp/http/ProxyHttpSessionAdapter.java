package bpsh.burp.http;

import bpsh.browser.AuthTrafficGuard;
import bpsh.request.RequestSettings;
import burp.api.montoya.proxy.MessageReceivedAction;
import burp.api.montoya.proxy.http.*;
import static bpsh.burp.http.SessionRequestProcessor.*;

/** Final edited-request preparation using actual incoming listeners, with best-effort native Proxy drops. */
public final class ProxyHttpSessionAdapter implements ProxyRequestHandler,ProxyResponseHandler {
    private final SessionRequestProcessor processor;
    private final RecoveryReplayDelivery replays;
    private final RequestControlState controls;

    /** Shares preparation and recovery owners with the global adapter. */
    ProxyHttpSessionAdapter(SessionRequestProcessor processor,RecoveryReplayDelivery replays,RequestControlState controls) {
        this.processor=processor;this.replays=replays;this.controls=controls;
    }

    /** @param request Incoming request before interception. @return Normal interception, owned bypass or a supported early drop. */
    @Override public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest request) {
        var exchange=new RequestExchange(AuthTrafficGuard.Family.PROXY,request.messageId());
        var ownership=processor.ownership(request,exchange.family(),exchange.id());
        var error=ownership.classification()==AuthTrafficGuard.Classification.INVALID?ownership.failure():
                ownership.classification()==AuthTrafficGuard.Classification.OWNED
                        &&(hasTags(request.toByteArray())||HttpAuthenticationDirective.present(request.toByteArray()))?nested():null;
        if(error!=null) {
            var stopped=processor.stopped(request,request.annotations(),exchange,null,error);
            return ProxyRequestReceivedAction.proxyRequestReceivedAction(request,stopped.annotations(),MessageReceivedAction.DROP);
        }
        return ownership.classification()==AuthTrafficGuard.Classification.OWNED&&ownership.replayKey()==null
                ?ProxyRequestReceivedAction.doNotIntercept(request,request.annotations()):ProxyRequestReceivedAction.continueWith(request,request.annotations());
    }

    /** @param request Final request after user interception edits. @return Prepared output or a best-effort native Proxy drop. */
    @Override public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest request) {
        var exchange=new RequestExchange(AuthTrafficGuard.Family.PROXY,request.messageId());
        var ownership=processor.ownership(request,exchange.family(),exchange.id());
        SessionRequestProcessor.Result result;
        if(ownership.classification()==AuthTrafficGuard.Classification.INVALID)
            result=processor.stopped(request,request.annotations(),exchange,null,ownership.failure());
        else if(ownership.classification()==AuthTrafficGuard.Classification.OWNED)
            return ProxyRequestToBeSentAction.continueWith(request,request.annotations());
        else if(HttpAuthenticationDirective.present(request.toByteArray()))
            return ProxyRequestToBeSentAction.continueWith(request,request.annotations());
        else result=processor.process(request,request.annotations(),new RequestRuleMatcher.Context(exchange,RequestSettings.Tool.PROXY,
                    ProxyListeners.incomingPort(request.listenerInterface())),controls.snapshot());
        return result.stop()==null?ProxyRequestToBeSentAction.continueWith(result.request(),result.annotations())
                :ProxyRequestToBeSentAction.proxyRequestToBeSentAction(result.request(),result.annotations(),burp.api.montoya.proxy.MessageToBeSentAction.DROP);
    }

    /** @param response Response in the Proxy ID family. @return Original response with owned traffic retaining its interception exemption. */
    @Override public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
        var notes=response.annotations();
        boolean internal=replays.response(new RequestExchange(AuthTrafficGuard.Family.PROXY,response.messageId()),response,notes,response.initiatingRequest());
        return internal?ProxyResponseReceivedAction.doNotIntercept(response,notes):ProxyResponseReceivedAction.continueWith(response,notes);
    }

    /** @param response Final user-reviewed response. @return Original response under normal Burp policy. */
    @Override public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) {return ProxyResponseToBeSentAction.continueWith(response,response.annotations());}
}
