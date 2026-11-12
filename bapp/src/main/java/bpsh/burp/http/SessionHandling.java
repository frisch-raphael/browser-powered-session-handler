package bpsh.burp.http;

import bpsh.browser.AuthTrafficGuard;
import bpsh.journey.JourneyCatalog;
import java.util.concurrent.atomic.AtomicBoolean;

/** Composes shared request operations, thin callback adapters and their owned replay lifecycle. */
public final class SessionHandling implements AutoCloseable {
    private final AtomicBoolean closed=new AtomicBoolean();
    private final RecoveryReplayDelivery replays;
    private final GlobalHttpSessionAdapter global;
    private final ProxyHttpSessionAdapter proxy;

    /** Wires one request graph without registering callbacks or owning the shared authentication services. */
    public SessionHandling(JourneyCatalog registry,NativeTagResolver resolver,AuthTrafficGuard guard,SessionRecovery recovery,
                           Diagnostics diagnostics,RequestControlState controls,RecoveryReplayDelivery.ReplayTransport transport,
                           bpsh.authentication.http.HttpIdentityManager identities) {
        var processor=new SessionRequestProcessor(registry,resolver,guard,recovery,diagnostics,closed);
        var direct=new HttpAuthenticationDelivery(registry,resolver,guard,identities);
        replays=new RecoveryReplayDelivery(registry,guard,recovery,diagnostics,controls,closed,transport);
        global=new GlobalHttpSessionAdapter(processor,direct,replays,controls,closed);
        proxy=new ProxyHttpSessionAdapter(processor,replays,controls);
    }

    /** @return Global delivery adapter; register before the Proxy producer. */
    public GlobalHttpSessionAdapter global() {return global;}
    /** @return Proxy request/response adapter. */
    public ProxyHttpSessionAdapter proxy() {return proxy;}
    /** @param millis Bounded replay worker cleanup budget. */
    public void awaitClosed(long millis) {replays.awaitClosed(millis);}
    /** Cancels owned replay delivery; the lifecycle owner deregisters both adapters. */
    @Override public void close() {if(closed.compareAndSet(false,true))replays.close();}
}
