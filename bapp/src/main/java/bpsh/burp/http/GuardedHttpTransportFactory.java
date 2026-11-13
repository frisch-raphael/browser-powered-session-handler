package bpsh.burp.http;

import bpsh.authentication.AuthenticationFailure;
import bpsh.authentication.http.HttpTransportFactory;
import bpsh.browser.AuthTrafficGuard;
import bpsh.journey.SecretStore;
import java.util.ArrayList;

/** Owns the sole recursion marker for DIRECT/TEST scopes routed through an upstream proxy. */
public final class GuardedHttpTransportFactory implements HttpTransportFactory {
    private final HttpTransportFactory delegate;
    private final AuthTrafficGuard guard;
    /** @param delegate Shared transport factory. @param guard Extension-owned traffic provenance. */
    public GuardedHttpTransportFactory(HttpTransportFactory delegate,AuthTrafficGuard guard) {this.delegate=delegate;this.guard=guard;}
    @Override public bpsh.authentication.http.HttpMessageBody.Allocator bodies() {return delegate.bodies();}
    @Override public void close() {delegate.close();}
    @Override public java.util.concurrent.CompletableFuture<bpsh.authentication.http.HttpAuthenticationService> open(
            ScopeSpec spec,SecretStore.Values values,long deadline) {
        var opened=delegate.open(spec,values,deadline);
        boolean direct=spec.purpose()==Purpose.DIRECT || spec.purpose()==Purpose.TEST;
        if(!direct || spec.setup().browser().proxy()==null)return opened;
        AuthTrafficGuard.Lease lease;
        try {lease=guard.begin();}
        catch(AuthenticationFailure failure) {opened.thenAccept(bpsh.authentication.http.HttpAuthenticationService::close);opened.cancel(true);return java.util.concurrent.CompletableFuture.failedFuture(failure);}
        var result=new java.util.concurrent.CompletableFuture<bpsh.authentication.http.HttpAuthenticationService>();
        opened.whenComplete((service,error)->{
            if(error!=null) {lease.close();result.completeExceptionally(error);return;}
            var wrapped=new bpsh.authentication.http.HttpAuthenticationService() {
                @Override public boolean isOpen() {return service.isOpen();}
                @Override public boolean isIdle() {return service.isIdle();}
                @Override public Delivery admit(long end) throws java.io.IOException {
                    var admitted=service.admit(end);
                    return new Delivery() {
                        @Override public java.util.concurrent.CompletableFuture<Response> exchange(Request request) {
                            try {
                                if(request.headers().stream().filter(header->header.name().equalsIgnoreCase("User-Agent")).count()>1)
                                    throw SessionRequestProcessor.configuration("A routed HTTP-auth request has multiple User-Agent headers.","Use one User-Agent header.");
                                var headers=new ArrayList<Header>();String agent="";
                                for(var header:request.headers()) {if(header.name().equalsIgnoreCase("User-Agent"))agent=header.value();else headers.add(header);}
                                headers.add(new Header("User-Agent",lease.decorate(agent)));
                                return admitted.exchange(request.withHeaders(headers));
                            } catch(AuthenticationFailure failure) {admitted.close();return java.util.concurrent.CompletableFuture.failedFuture(failure);}
                        }
                        @Override public void close() {admitted.close();}
                    };
                }

                @Override public java.util.List<bpsh.authentication.http.HttpAuthenticationEvidence> observations() {return service.observations();}
                @Override public AuthenticationFailure failure() {return service.failure();}
                @Override public void close() {try {service.close();}finally {lease.close();}}
            };
            if(!result.complete(wrapped))wrapped.close();
        });
        result.whenComplete((service,error)->{if(error!=null) {opened.cancel(true);lease.close();}});
        return result;
    }

}
