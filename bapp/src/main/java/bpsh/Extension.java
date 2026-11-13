package bpsh;

import bpsh.browser.AuthTrafficGuard;
import bpsh.browser.BrowserAuthentication;
import bpsh.browser.BrowserFlowRunner;
import bpsh.browser.BrowserSessionLauncher;
import bpsh.browser.BrowserJourneyRecorder;
import bpsh.request.RequestSettings;
import bpsh.journey.persistence.ProjectStore;
import bpsh.journey.editing.JourneyWorkspace;
import bpsh.journey.persistence.UserLibraryStore;
import bpsh.burp.http.Diagnostics;
import bpsh.burp.http.SessionHandling;
import bpsh.burp.http.RequestControlState;
import bpsh.burp.http.NativeTagResolver;
import bpsh.burp.http.SessionRecovery;
import bpsh.authentication.AuthenticationFailure;
import bpsh.transport.tls.Pkcs11IdentityManager;
import bpsh.browser.runtime.BrowserRuntimeManager;
import bpsh.journey.SecretStore;
import bpsh.authentication.session.AuthenticationCoordinator;
import bpsh.burp.ui.AuthenticationTagMenu;
import bpsh.burp.ui.UiController;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.handler.RequestAction;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.*;

/** Composes one native service graph and owns the entire UI/hook/browser/storage unload sequence. */
public final class Extension implements BurpExtension {
    static final String NAME = "Browser Powered Session Handler";

    /**
     * Verifies supported host actions before registering any processing and loads only native storage.
     * @param api Current Burp host boundary.
     */
    @Override public void initialize(MontoyaApi api) {
        api.extension().setName(NAME);
        if (!supported(api)) return;
        Services services = null;
        try {
            services = new Services(api); Services owned = services;
            if (SwingUtilities.isEventDispatchThread()) owned.buildUi(); else SwingUtilities.invokeAndWait(owned::buildUi);
            owned.registrations.add(api.http().registerHttpHandler(owned.handler.global()));
            owned.registrations.add(api.proxy().registerRequestHandler(owned.handler.proxy()));
            owned.registrations.add(api.proxy().registerResponseHandler(owned.handler.proxy()));
            owned.registrations.add(api.userInterface().registerContextMenuItemsProvider(new AuthenticationTagMenu(owned.registry, api.logging()::logToError)));
            api.extension().registerUnloadingHandler(owned::close); owned.ui.start();
            api.logging().logToOutput(NAME + " loaded with native saved journeys. Configure and Test a journey before use.");
        } catch (Exception | LinkageError ex) {
            if (services != null) services.close();
            api.logging().logToError("The extension could not start.");
        }
    }

    /**
     * Creates inert host action objects to detect an old factory before any native tag hooks become active.
     * @param api Error/UI reporting boundary; capability probes never send network requests.
     * @return Whether the compiled SDK's required drop, raw-request and Proxy action factories work.
     */
    static boolean supported(MontoyaApi api) {
        try {
            if (Runtime.version().feature() < 21) throw new IllegalStateException();
            if (RequestToBeSentAction.drop(Annotations.annotations("Native drop capability check")).action() != RequestAction.DROP) throw new IllegalStateException();
            var request = HttpRequest.httpRequest("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
            ProxyRequestReceivedAction.doNotIntercept(request, Annotations.annotations());
            burp.api.montoya.proxy.http.ProxyRequestToBeSentAction.continueWith(request, Annotations.annotations());
            RequestToBeSentAction.spoof(HttpResponse.httpResponse("HTTP/1.1 204 No Content\r\n\r\n"), Annotations.annotations());
            ProxyResponseReceivedAction.doNotIntercept(HttpResponse.httpResponse("HTTP/1.1 204 No Content\r\n\r\n"), Annotations.annotations());
            return true;
        } catch (RuntimeException | LinkageError ex) {
            String message = "This extension requires Java 21+ and Burp with Montoya 2026.4 global request-drop, response spoofing and Proxy action factory support. Update Burp and load the complete universal JAR; no authentication hooks were registered.";
            api.logging().logToError(message);
            SwingUtilities.invokeLater(() -> { var text = new JTextArea(message, 6, 70); text.setEditable(false); text.setLineWrap(true); text.setWrapStyleWord(true); api.userInterface().registerSuiteTab(NAME, new JScrollPane(text)); });
            return false;
        }
    }

    /** Owns shared state once; individual browser attempts borrow services and retain no host configuration. */
    private static final class Services implements AutoCloseable {
        final MontoyaApi api;
        final AtomicBoolean closed = new AtomicBoolean();
        final List<Registration> registrations = new ArrayList<>();
        final RequestControlState controls = new RequestControlState(RequestSettings.Controls.defaults());
        final SecretStore secrets = new SecretStore();
        final JourneyWorkspace registry = new JourneyWorkspace(secrets);
        final UserLibraryStore library = new UserLibraryStore();
        final BrowserRuntimeManager runtime = new BrowserRuntimeManager();
        final bpsh.browser.runtime.BrowserExecutableSettings browserSettings = new bpsh.browser.runtime.BrowserExecutableSettings();
        final bpsh.browser.runtime.BurpBrowserResolver browserResolver = bpsh.browser.runtime.BurpBrowserResolver.current( browserSettings::executableOverride);
        final Pkcs11IdentityManager identities = new Pkcs11IdentityManager();
        final AuthTrafficGuard guard = new AuthTrafficGuard();
        final bpsh.authentication.http.HttpAuthenticationActivity httpActivity = new bpsh.authentication.http.HttpAuthenticationActivity(registry);
        final bpsh.transport.httpauth.HttpTransportRuntime httpTransport = new bpsh.transport.httpauth.HttpTransportRuntime(identities,httpActivity::observe);
        final bpsh.authentication.http.HttpIdentityManager httpIdentities;
        final AuthenticationCoordinator coordinator;
        final BrowserJourneyRecorder recorder;
        final NativeTagResolver resolver;
        final SessionRecovery recovery;
        final Diagnostics diagnostics;
        final SessionHandling handler;
        final UiController ui;

        /**
         * Composes one shared native service graph without starting browsers, PIN submission or storage loading.
         *
         * @param api Current host; construction starts no browser, native PIN submission or storage read.
         */
        Services(MontoyaApi api) {
            this.api = api; diagnostics = new Diagnostics(api.logging()::logToError);
            var httpFactory=new bpsh.burp.http.GuardedHttpTransportFactory(httpTransport,guard);
            httpIdentities = new bpsh.authentication.http.HttpIdentityManager(registry,secrets,httpFactory,httpActivity);
            var launcher = new BrowserSessionLauncher(runtime, browserResolver, httpFactory, guard, Clock.systemUTC());
            var runner = new BrowserFlowRunner(launcher, Clock.systemUTC());
            recorder = new BrowserJourneyRecorder(launcher);
            coordinator = BrowserAuthentication.coordinator(registry, secrets, runner, identities, controls.snapshot().controls()); resolver = new NativeTagResolver(registry, coordinator);
            httpActivity.events((identity,progress)->coordinator.events().append(identity.key(),progress.time(),
                    progress.stage().failure()?bpsh.authentication.session.JourneyEventLog.Level.ERROR:
                    progress.stage()==bpsh.authentication.http.HttpAuthenticationProgress.Stage.CANCELLED ||
                    progress.stage()==bpsh.authentication.http.HttpAuthenticationProgress.Stage.UNCONFIRMED?
                            bpsh.authentication.session.JourneyEventLog.Level.WARNING:bpsh.authentication.session.JourneyEventLog.Level.INFO,
                    progress.message()));
            recovery = new SessionRecovery(coordinator, (identity, message) -> {
                var entry = registry.snapshot().entries().get(identity.key());
                boolean capacity = message.startsWith("The recovery replay template");
                diagnostics.state(entry == null ? null : entry.definition().alias(), new AuthenticationFailure(
                        capacity ? AuthenticationFailure.Phase.QUEUE : AuthenticationFailure.Phase.EXTRACTION,
                        capacity ? AuthenticationFailure.Cause.CAPACITY : AuthenticationFailure.Cause.CONFIGURATION, message,
                        capacity ? "After login, resend the original request manually." : "Convert the response encoding or use status-code recovery."));
            });
            handler = new SessionHandling(registry, resolver, guard, recovery, diagnostics, controls,
                    (request, timeout) -> api.http().sendRequest(request, burp.api.montoya.http.RequestOptions.requestOptions().withResponseTimeout(timeout)), httpIdentities);
            ui = new UiController(api, new bpsh.journey.editing.JourneyStorage(new ProjectStore(api.persistence().extensionData()), library), secrets, registry, coordinator, identities, controls, diagnostics, recorder, new bpsh.burp.http.ProxyListeners(api));
            var browserInstallation = new bpsh.authentication.BrowserInstallation() {
                @Override public String executableOverride() { return browserSettings.executableOverride(); }
                @Override public void setExecutableOverride(String value) { browserSettings.setExecutableOverride(value); }
                @Override public Selection discover(long deadline, java.util.function.BooleanSupplier cancelled) throws AuthenticationFailure {
                    var selected = browserResolver.resolve(deadline, cancelled);
                    return new Selection(selected.executable(), selected.source() == bpsh.browser.runtime.BurpBrowserResolver.Source.EXPLICIT);
                }
            };
            ui.browserRuntime(browserInstallation, new bpsh.burp.ui.BrowserRuntimePreferences(api.persistence().preferences(), browserInstallation));
            ui.httpIdentities(httpIdentities);
            ui.httpActivity(httpActivity);
        }
        /** Builds and registers the suite tab on the EDT; loading native stores is queued afterward. */
        void buildUi() { var component = ui.buildUi(); api.userInterface().applyThemeToComponent(component); registrations.add(api.userInterface().registerSuiteTab(NAME, component)); }

        /** Revokes all work, stops UI/watchers, deregisters hooks and closes only extension-owned services. */
        @Override public void close() {
            if (!closed.compareAndSet(false, true)) return;
            cleanup(api.logging()::logToError, httpActivity::close, handler::close, recorder::close, ui::shutdown);
            for (Registration registration : List.copyOf(registrations)) cleanup(api.logging()::logToError, registration::deregister);
            cleanup(api.logging()::logToError, coordinator::close, recovery::close);
            Runnable finish = () -> cleanup(api.logging()::logToError, identities::close, httpIdentities::close,
                    () -> ui.awaitSaves(5000), () -> { if (!recorder.awaitClosed(5000)) throw new IllegalStateException("Recording cleanup did not finish."); }, httpTransport::close,
                    () -> coordinator.awaitWorkers(2500), () -> httpTransport.awaitClosed(5000),
                    () -> handler.awaitClosed(2500), () -> httpIdentities.awaitClosed(2500), () -> ui.awaitClosed(2500),
                    guard::close, runtime::close, secrets::close, diagnostics::close);
            if (SwingUtilities.isEventDispatchThread()) { var thread = new Thread(finish, "bpsh-unload-cleanup"); thread.setDaemon(true); thread.start(); } else finish.run();
        }
    }

    /** Attempts every owned cleanup even when an earlier service or the diagnostic sink fails. */
    static void cleanup(java.util.function.Consumer<String> errors, Runnable... actions) {
        try { bpsh.authentication.ServiceCleanup.close(actions); }
        catch (RuntimeException | LinkageError failure) {
            try { errors.accept("An extension resource did not finish cleanup; remaining resources will still be closed."); }
            catch (RuntimeException | LinkageError ignored) { /* A broken host logger cannot prevent resource cleanup. */ }
        }
    }
}
