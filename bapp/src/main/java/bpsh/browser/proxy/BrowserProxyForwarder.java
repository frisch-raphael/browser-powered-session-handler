package bpsh.browser.proxy;

import bpsh.authentication.AuthenticationFailure;
import bpsh.authentication.http.HttpAuthenticationEvidence;
import bpsh.authentication.http.HttpAuthenticationService;
import bpsh.journey.BrowserSetup;
import bpsh.transport.tls.JourneyTlsContexts;
import com.microsoft.playwright.options.Proxy;
import java.net.InetSocketAddress;
import java.time.Clock;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Owns browser ingress and an attempt-scoped lease from the shared HTTP runtime. */
public final class BrowserProxyForwarder implements AutoCloseable {
    private final HttpAuthenticationService transport;
    private final AtomicReference<AuthenticationFailure> failure=new AtomicReference<>();
    private final AtomicReference<HttpAuthenticationEvidence> evidence=new AtomicReference<>(new HttpAuthenticationEvidence(null,HttpAuthenticationEvidence.Status.UNCONFIRMED));
    private final AtomicBoolean closed=new AtomicBoolean();
    private final JourneyBrowserProxy browser;

    public BrowserProxyForwarder(BrowserSetup setup,HttpAuthenticationService scope,bpsh.authentication.http.HttpMessageBody.Allocator bodies,Clock clock,long deadline) throws AuthenticationFailure {
        transport=scope;
        try {
            browser=new JourneyBrowserProxy(target->{
                boolean authenticated=setup.httpAuthenticationEnabled() && setup.httpAuthentication().allows(target);
                return new HttpAuthenticationService() {
                    @Override public boolean isOpen() {return transport.isOpen();}
                    @Override public boolean isIdle() {return transport.isIdle();}
                    @Override public Delivery admit(long end) throws java.io.IOException {
                        var admitted=transport.admit(end);
                        return new Delivery() {
                            @Override public CompletableFuture<Response> exchange(Request request) {
                                var source=admitted.exchange(request);
                                var result=new CompletableFuture<Response>();
                                source.whenComplete((response,error)->{
                                    if(error!=null) {result.completeExceptionally(error);return;}
                                    Response forwarded=response;
                                    try {
                                        if(authenticated && response.authentication().status()!=HttpAuthenticationEvidence.Status.UNCONFIRMED)evidence.set(response.authentication());
                                        // Playwright also offers its local proxy credentials for origin
                                        // challenges. Authentication terminates here, never in Chromium.
                                        var headers=response.headers().stream().filter(h->!h.name().equalsIgnoreCase("WWW-Authenticate")).toList();
                                        if(headers.size()!=response.headers().size()) {
                                            forwarded=new Response(response.status(),headers,response.body().retain(),response.authentication());
                                            response.close();
                                        }
                                        if(!result.complete(forwarded))forwarded.close();
                                    } catch(Throwable failure) {
                                        forwarded.close();result.completeExceptionally(failure);
                                    }
                                });
                                result.whenComplete((response,error)->{if(result.isCancelled())source.cancel(true);});
                                return result;
                            }
                            @Override public void close() {admitted.close();}
                        };
                    }
                    
                    @Override public void close() { /* The attempt owns the delegate, not a request. */ }
                };
            },bodies,clock,deadline,error->{
                AuthenticationFailure observed=JourneyTlsContexts.destinationFailure(error,setup.mtls()!=null);
                if(observed==null)observed=setup.browser().proxy()!=null ? JourneyTlsContexts.upstreamFailure(error) :
                        new AuthenticationFailure(AuthenticationFailure.Phase.PROXY,AuthenticationFailure.Cause.UNKNOWN,"The login proxy could not complete the destination request.");
                failure.compareAndSet(null,observed);
            });
        } catch(Exception error) {
            scope.close();
            if(error instanceof AuthenticationFailure safe)throw safe;
            throw new AuthenticationFailure(AuthenticationFailure.Phase.PROXY,AuthenticationFailure.Cause.CONFIGURATION,"The login proxy could not start.");
        }
    }

    public Proxy browserProxy() {return browser.browserProxy();}
    public String spkiSha256() {return browser.spkiSha256();}
    public InetSocketAddress address() {return browser.address();}
    public java.util.List<HttpAuthenticationEvidence> observations() {return transport.observations();}
    public HttpAuthenticationEvidence authentication() {return evidence.get();}
    public AuthenticationFailure failure() {return transport.failure()!=null?transport.failure():failure.get();}
    @Override public void close() {
        if(!closed.compareAndSet(false,true))return;
        try {browser.close();} finally {transport.close();}
    }
}
