package bpsh.browser;

import bpsh.authentication.AuthenticationFailure;
import bpsh.authentication.AuthenticationStage;
import bpsh.browser.proxy.BrowserProxyForwarder;
import bpsh.browser.runtime.BrowserRuntimeManager;
import bpsh.browser.runtime.PlaywrightDriverAdapter;
import bpsh.journey.BrowserSetup;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.SecretStore;
import com.microsoft.playwright.Browser;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Request;
import com.microsoft.playwright.Route;
import com.microsoft.playwright.options.Proxy;
import java.time.Clock;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/** Launches worker-owned browser sessions shared by authentication and interactive recording. */
public final class BrowserSessionLauncher {
    /** Whether to retain configured visibility or override it for a particular consumer. */
    public enum Visibility { CONFIGURED, HEADED, HEADLESS }
    /** Safe observations of successful resource acquisition and close completion. */
    public enum ResourceEvent { BROWSER_OPEN, CONTEXT_OPEN, CONTEXT_CLOSED, BROWSER_CLOSED }
    /** Identifies owned resources without exposing handles, URLs or credentials. */
    public record Lifecycle(long resourceId, long parentId, JourneyDefinition.Identity identity, ResourceEvent event, boolean bootstrap) {}

    private final BrowserRuntimeManager runtime;
    private final bpsh.authentication.http.HttpTransportFactory httpTransport;
    private final AuthTrafficGuard traffic;
    private final Clock clock;
    private final Consumer<Lifecycle> lifecycle;
    private final AtomicLong resourceIds = new AtomicLong();

    /** Captures shared services without preparing assets, opening a device or starting a browser. */
    public BrowserSessionLauncher(BrowserRuntimeManager runtime, bpsh.authentication.http.HttpTransportFactory httpTransport, AuthTrafficGuard traffic, Clock clock) {
        this(runtime, httpTransport, traffic, clock, ignored -> {});
    }

    /** Adds a safe observation seam while keeping resource ownership inside the browser boundary. */
    public BrowserSessionLauncher(BrowserRuntimeManager runtime, bpsh.authentication.http.HttpTransportFactory httpTransport, AuthTrafficGuard traffic,
            Clock clock, Consumer<Lifecycle> lifecycle) {
        this.runtime = runtime; this.httpTransport = httpTransport; this.traffic = traffic; this.clock = clock;
        this.lifecycle = java.util.Objects.requireNonNull(lifecycle);
    }

    private void observed(Lifecycle event) {
        try { lifecycle.accept(event); } catch (RuntimeException ignored) { /* diagnostics cannot prevent cleanup */ }
    }

    private final class OwnedBrowser implements AutoCloseable {
        final Browser browser;
        final JourneyDefinition.Identity identity;
        final long id = resourceIds.incrementAndGet();
        OwnedBrowser(Browser browser, JourneyDefinition.Identity identity) {
            this.browser = browser; this.identity = identity;
            observed(new Lifecycle(id, 0, identity, ResourceEvent.BROWSER_OPEN, false));
        }
        @Override public void close() {
            try { browser.close(); }
            finally {
                // Cancellation may have already terminated the owned driver before the close reply.
                if (!browser.isConnected()) observed(new Lifecycle(id, 0, identity, ResourceEvent.BROWSER_CLOSED, false));
            }
        }
    }

    private final class OwnedContext implements AutoCloseable {
        final BrowserContext context;
        final OwnedBrowser browser;
        final boolean bootstrap;
        final long id = resourceIds.incrementAndGet();
        OwnedContext(BrowserContext context, OwnedBrowser browser, boolean bootstrap) {
            this.context = context; this.browser = browser; this.bootstrap = bootstrap;
            observed(new Lifecycle(id, browser.id, browser.identity, ResourceEvent.CONTEXT_OPEN, bootstrap));
        }
        @Override public void close() {
            context.close(); observed(new Lifecycle(id, browser.id, browser.identity, ResourceEvent.CONTEXT_CLOSED, bootstrap));
        }
    }

    /** Owns every acquired resource until the creating worker closes the session. */
    public final class Session implements AutoCloseable {
        private final Thread owner = Thread.currentThread();
        private final AtomicReference<AuthenticationFailure> routingFailure = new AtomicReference<>();
        private OwnedBrowser browser;
        private OwnedContext context;
        private PlaywrightDriverAdapter.Session driver;
        private BrowserProxyForwarder transport;
        private AuthTrafficGuard.Lease trafficLease;
        private boolean closed;

        private void owner() {
            if (Thread.currentThread() != owner) throw new IllegalStateException("Browser session belongs to another worker.");
        }

        /** Borrows the fresh context on its owning worker, without transferring cleanup ownership. */
        public BrowserContext context() {
            owner(); if (closed) throw new IllegalStateException("Browser session is closed."); return context.context;
        }

        /** Borrows the driver's private integration boundary inside the browser package only. */
        PlaywrightDriverAdapter.Session driver() {
            owner(); if (closed) throw new IllegalStateException("Browser session is closed."); return driver;
        }

        /** Rejects known routing failures before another action or result publication. */
        public void checkTraffic() throws AuthenticationFailure {
            owner(); if (routingFailure.get() != null) throw routingFailure.get();
        }

        /** Returns safe native transport evidence without replacing successful credential extraction. */
        public bpsh.authentication.http.HttpAuthenticationEvidence httpAuthentication() { owner(); return transport == null ? null : transport.authentication(); }

        public java.util.List<bpsh.authentication.http.HttpAuthenticationEvidence> httpObservations() {owner();return transport==null?java.util.List.of():transport.observations();}
        public AuthenticationFailure transportFailure() { owner(); return transport == null ? null : transport.failure(); }

        /** Closes context, browser, driver and transport before revoking ownership of their traffic. */
        @Override public void close() throws AuthenticationFailure {
            owner(); if (closed) return; closed = true;
            AuthenticationFailure failure = null;
            for (AutoCloseable resource : new AutoCloseable[]{context, browser, driver, transport, trafficLease}) {
                if (resource == null) continue;
                try { resource.close(); }
                catch (Exception | LinkageError error) {
                    AuthenticationFailure safe = error instanceof AuthenticationFailure classified ? classified
                            : new AuthenticationFailure(AuthenticationFailure.Phase.LIFECYCLE, AuthenticationFailure.Cause.UNKNOWN,
                                    "The browser session could not finish closing.");
                    if (failure == null) failure = safe; else failure.addSuppressed(safe);
                }
            }
            if (failure != null) throw failure;
        }
    }

    /**
     * Prepares a fresh session without navigating or executing login steps.
     * @param identity Journey generation used only for safe lifecycle attribution.
     * @param setup Setup already validated by the shared codec.
     * @param inputValues Borrowed snapshot; the shared factory copies setup secrets before returning.
     * @param visibility Explicit consumer override, independent of saved browser settings.
     * @param explicitRecovery Whether the user explicitly authorized recovery from PIN suppression.
     * @param deadline Original monotonic deadline, including setup and native work.
     * @param cancelled Worker cancellation predicate.
     * @param observer Fixed preparation progress, without browser output.
     * @return Session owned by this worker; close it on every completion path.
     * @throws AuthenticationFailure On safe setup, native, cancellation or startup failure.
     */
    public Session open(JourneyDefinition.Identity identity, BrowserSetup setup, SecretStore.Values inputValues,
            Visibility visibility, boolean explicitRecovery, long deadline, BooleanSupplier cancelled,
            Consumer<AuthenticationStage> observer) throws AuthenticationFailure {
        return openOwned(identity,setup,inputValues,visibility,explicitRecovery,deadline,cancelled,observer,bpsh.authentication.http.HttpTransportFactory.Purpose.BROWSER);
    }
    /** Opens recording setup with its own pinned transport scope, including unsaved recordings. */
    public Session openRecording(JourneyDefinition.Identity identity,BrowserSetup setup,SecretStore.Values inputValues,
            Visibility visibility,boolean explicitRecovery,long deadline,BooleanSupplier cancelled,Consumer<AuthenticationStage> observer) throws AuthenticationFailure {
        return openOwned(identity,setup,inputValues,visibility,explicitRecovery,deadline,cancelled,observer,bpsh.authentication.http.HttpTransportFactory.Purpose.RECORDING);
    }
    private Session openOwned(JourneyDefinition.Identity identity,BrowserSetup setup,SecretStore.Values inputValues,
            Visibility visibility,boolean explicitRecovery,long deadline,BooleanSupplier cancelled,Consumer<AuthenticationStage> observer,
            bpsh.authentication.http.HttpTransportFactory.Purpose purpose) throws AuthenticationFailure {
        var session = new Session();
        try {
            AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.SETUP, deadline, cancelled);
            BrowserRuntimeManager.Ready ready = runtime.acquire(deadline, cancelled, observer);
            if(setup.mtls()!=null || setup.httpAuthenticationEnabled()) {
                var spec=new bpsh.authentication.http.HttpTransportFactory.ScopeSpec(java.util.UUID.randomUUID(),purpose,identity,0,setup,explicitRecovery);
                var opening=httpTransport.open(spec,inputValues,deadline);
                bpsh.authentication.http.HttpAuthenticationService scope=null;
                try {
                    while(scope==null) {
                        AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.SETUP,deadline,cancelled);
                        try {scope=opening.get(Math.min(50,Math.max(1,java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(deadline-System.nanoTime()))),java.util.concurrent.TimeUnit.MILLISECONDS);}
                        catch(java.util.concurrent.TimeoutException waiting) { /* poll cancellation within the original deadline */ }
                    }
                    session.transport=new BrowserProxyForwarder(setup,scope,httpTransport.bodies(),clock,deadline);
                } catch(Exception failure) {
                    opening.thenAccept(bpsh.authentication.http.HttpAuthenticationService::close);opening.cancel(true);
                    if(failure instanceof java.util.concurrent.ExecutionException wrapper && wrapper.getCause() instanceof AuthenticationFailure safe)throw safe;
                    if(failure instanceof InterruptedException)Thread.currentThread().interrupt();
                    throw failure;
                }
            }
            boolean proxied = session.transport != null || setup.browser().proxy() != null;
            if (proxied) session.trafficLease = traffic.begin();
            BrowserRuntimeManager.observed(observer, AuthenticationStage.STARTING_DRIVER);
            session.driver = PlaywrightDriverAdapter.open(ready, deadline, cancelled);
            boolean headless = switch (visibility) { case CONFIGURED -> setup.browser().headless(); case HEADED -> false; case HEADLESS -> true; };
            var options = new BrowserType.LaunchOptions().setExecutablePath(ready.browserExecutable()).setHeadless(headless)
                    .setTimeout(AuthenticationFailure.remainingMs(setup.browser().navigationTimeoutMs(), deadline, cancelled));
            if (session.transport != null) options.setProxy(session.transport.browserProxy())
                    .setArgs(List.of("--ignore-certificate-errors-spki-list=" + session.transport.spkiSha256()));
            else if (setup.browser().proxy() != null) options.setProxy(new Proxy(setup.browser().proxy().url().toString()).setBypass("<-loopback>"));
            else options.setArgs(List.of("--no-proxy-server"));
            BrowserRuntimeManager.observed(observer, AuthenticationStage.STARTING_BROWSER);
            session.browser = new OwnedBrowser(startBrowser(session.driver, options, deadline, cancelled), identity);
            var contextOptions = new Browser.NewContextOptions().setIgnoreHTTPSErrors(setup.browser().ignoreHttpsErrors());
            String originalAgent = null;
            if (session.trafficLease != null) {
                try (var bootstrap = new OwnedContext(session.browser.browser.newContext(), session.browser, true)) {
                    originalAgent = (String) bootstrap.context.newPage().evaluate("navigator.userAgent");
                }
                contextOptions.setUserAgent(session.trafficLease.decorate(originalAgent));
            }
            session.context = new OwnedContext(session.browser.browser.newContext(contextOptions), session.browser, false);
            installRouting(session, originalAgent);
            return session;
        } catch (Exception | LinkageError error) {
            AuthenticationFailure failure;
            if (error instanceof AuthenticationFailure classified) failure = classified;
            else if (error instanceof LinkageError) failure = new AuthenticationFailure(AuthenticationFailure.Phase.SETUP,
                    AuthenticationFailure.Cause.CONFIGURATION, "The bundled browser runtime could not load.",
                    "Reload the complete universal extension JAR, then try again.");
            else {
                try { AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.SETUP, deadline, cancelled); }
                catch (AuthenticationFailure stopped) { closeAfterFailure(session, stopped); throw stopped; }
                failure = new AuthenticationFailure(AuthenticationFailure.Phase.SETUP, AuthenticationFailure.Cause.UNKNOWN,
                        "The browser session could not start.");
            }
            closeAfterFailure(session, failure); throw failure;
        }
    }

    private static void closeAfterFailure(Session session, AuthenticationFailure primary) {
        try { session.close(); } catch (AuthenticationFailure cleanup) { primary.addSuppressed(cleanup); }
    }

    private static Browser startBrowser(PlaywrightDriverAdapter.Session driver, BrowserType.LaunchOptions options,
            long deadline, BooleanSupplier cancelled) throws AuthenticationFailure {
        try { return driver.playwright().chromium().launch(options); }
        catch (RuntimeException error) {
            AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.SETUP, deadline, cancelled);
            throw new AuthenticationFailure(AuthenticationFailure.Phase.SETUP, AuthenticationFailure.Cause.UNKNOWN,
                    "Chromium could not start.", "Check the documented operating-system and browser-library prerequisites.");
        }
    }

    private static void installRouting(Session session, String defaultAgent) {
        if (session.trafficLease == null) return;
        session.context.context.route("**/*", route -> {
            try {
                Request request = route.request();
                if (AuthTrafficGuard.containsNativeTag(request.url()) || AuthTrafficGuard.containsNativeTag(request.postData())
                        || request.headers().entrySet().stream().anyMatch(entry -> AuthTrafficGuard.containsNativeTag(entry.getKey()) || AuthTrafficGuard.containsNativeTag(entry.getValue())))
                    throw new AuthenticationFailure(AuthenticationFailure.Phase.LIFECYCLE, AuthenticationFailure.Cause.CONFIGURATION,
                            "A login request contains authentication tags.", "Remove authentication tags from the requests made during login.");
                var headers = new HashMap<>(request.headers());
                headers.put("user-agent", session.trafficLease.decorate(headers.getOrDefault("user-agent", defaultAgent)));
                route.resume(new Route.ResumeOptions().setHeaders(headers));
            } catch (AuthenticationFailure failure) {
                session.routingFailure.compareAndSet(null, failure); route.abort();
            } catch (RuntimeException error) {
                session.routingFailure.compareAndSet(null, new AuthenticationFailure(AuthenticationFailure.Phase.LIFECYCLE,
                        AuthenticationFailure.Cause.UNKNOWN, "A browser request could not be routed safely."));
                try { route.abort(); } catch (RuntimeException ignored) { /* closed contexts already reject delivery */ }
            }
        });
    }
}
