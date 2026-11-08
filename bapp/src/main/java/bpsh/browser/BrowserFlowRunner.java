package bpsh.browser;

import bpsh.browser.runtime.BoundedTokenResponses;

import bpsh.journey.JourneySecrets;
import bpsh.journey.BrowserSetup;

import bpsh.authentication.credentials.AuthenticationResult;
import bpsh.authentication.credentials.TokenExtractor;
import bpsh.journey.AuthStep;
import bpsh.authentication.AuthenticationFailure;
import bpsh.authentication.AuthenticationStage;
import bpsh.journey.JourneyDefinition;
import bpsh.browser.mtls.Pkcs11IdentityManager;
import bpsh.browser.runtime.BrowserRuntimeManager;
import bpsh.journey.SecretStore;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.PlaywrightException;
import com.microsoft.playwright.Response;
import java.net.URI;
import java.time.Clock;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import static bpsh.browser.BrowserFailureClassifier.*;

/**
 * Executes a fresh browser/context on its calling worker, with listeners installed before navigation.
 *
 * This component does not register Burp hooks, cache tokens or perform automatic retries. The
 * coordinator owns worker/cycle admission and generation publication. Browser/process/proxy cleanup
 * is scoped to this attempt, while verified binaries and established provider login may be reused.
 */
public final class BrowserFlowRunner {



    /** Token-free observation of actual SDK resource creation and successful close completion. */
    public enum ResourceEvent { BROWSER_OPEN, CONTEXT_OPEN, CONTEXT_CLOSED, BROWSER_CLOSED }
    public record Lifecycle(long resourceId, long parentId, JourneyDefinition.Identity identity, ResourceEvent event, boolean bootstrap) {}
    private final BrowserSessionLauncher launcher;
    private final Clock clock;

    /**
     * Wires shared local services without starting a browser, loading a token or touching Burp hooks.
     * @param runtime Offline verified runtime owner.
     * @param identities Shared module/slot PIN-state owner.
     * @param traffic Active attempt-marker owner.
     * @param clock Wall time for extraction/Retry-After metadata.
     */
    public BrowserFlowRunner(BrowserRuntimeManager runtime, Pkcs11IdentityManager identities, AuthTrafficGuard traffic, Clock clock) {
        this(runtime, identities, traffic, clock, event -> {});
    }
    /** Supplies a nonsecret production lifecycle observation seam without exposing browser/context handles. */
    public BrowserFlowRunner(BrowserRuntimeManager runtime, Pkcs11IdentityManager identities, AuthTrafficGuard traffic, Clock clock,
                             java.util.function.Consumer<Lifecycle> lifecycle) {
        java.util.Objects.requireNonNull(lifecycle); this.clock = clock;
        this.launcher = new BrowserSessionLauncher(runtime, identities, traffic, clock, event -> lifecycle.accept(new Lifecycle(
                event.resourceId(), event.parentId(), event.identity(), ResourceEvent.valueOf(event.event().name()), event.bootstrap())));
    }

    /** Reuses a shared launcher when authentication and recording are wired by the composition root. */
    public BrowserFlowRunner(BrowserSessionLauncher launcher, Clock clock) {
        this.launcher = java.util.Objects.requireNonNull(launcher); this.clock = clock;
    }

    /**
     * Runs one actual attempt with fresh context/profile state and its unchanged monotonic budget.
     * @param identity Scope/UUID/generation captured by the coordinator.
     * @param journey Validated immutable definition matching that identity.
     * @param supplied Open caller-owned values; copied for this attempt and not consumed.
     * @param explicitRecovery Explicit Retry/Save and test permission to recover PIN suppression.
     * @param deadlineNanos Original attempt deadline, including setup/native/proxy time.
     * @param cancelled Cycle epoch/cancellation predicate; must also reject stale generations.
     * @return Normalized token attributed to the supplied identity.
     * @throws AuthenticationFailure On classified setup, PIN, step, extraction or lifecycle failure.
     */
    public AuthenticationResult run(JourneyDefinition.Identity identity, JourneyDefinition journey, SecretStore.Values supplied,
                       boolean explicitRecovery, long deadlineNanos, BooleanSupplier cancelled) throws AuthenticationFailure {
        return run(identity, journey, supplied, explicitRecovery, deadlineNanos, cancelled, stage -> {});
    }

    /** Executes an owned attempt while reporting fixed local preparation states.
     * @param identity Captured journey generation.
     * @param journey Immutable journey configuration.
     * @param supplied Caller-owned session values.
     * @param explicitRecovery Explicit PIN recovery permission.
     * @param deadlineNanos Original monotonic attempt deadline.
     * @param cancelled Lifecycle cancellation predicate.
     * @param observer Safe attempt-local setup observer.
     * @return Captured credentials and ownership metadata.
     * @throws AuthenticationFailure On a classified attempt failure.
     */
    public AuthenticationResult run(JourneyDefinition.Identity identity, JourneyDefinition journey, SecretStore.Values supplied,
                       boolean explicitRecovery, long deadlineNanos, BooleanSupplier cancelled,
                       java.util.function.Consumer<AuthenticationStage> observer) throws AuthenticationFailure {
        AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.SETUP, deadlineNanos, cancelled);
        if (journey.draft() != null) throw new AuthenticationFailure(AuthenticationFailure.Phase.SETUP,
                AuthenticationFailure.Cause.CONFIGURATION, "This journey has incomplete or invalid settings.", "Review the journey settings, then test login.");
        try (SecretStore.Values values = supplied.copy()) {
            validateSecrets(journey, values);
            try (var session = launcher.open(identity, BrowserSetup.from(journey), values, BrowserSessionLauncher.Visibility.CONFIGURED,
                    explicitRecovery, deadlineNanos, cancelled, observer)) {
                BrowserRuntimeManager.observed(observer, AuthenticationStage.AUTHENTICATING);
                return execute(identity, journey, values, session, deadlineNanos, cancelled);
            }
        } catch (AuthenticationFailure ex) { throw ex; }
        catch (Exception ex) {
            AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.LIFECYCLE, deadlineNanos, cancelled);
            throw new AuthenticationFailure(AuthenticationFailure.Phase.SETUP, AuthenticationFailure.Cause.UNKNOWN,
                    "The browser could not complete the login.", "");
        }
    }

    /**
     * Installs capture listeners in the shared session, executes steps and pumps the event loop until completion.
     * @param identity Captured generation to attach to success.
     * @param journey Validated flow/extraction definition.
     * @param values Attempt-owned secret copies.
     * @param session Shared launch/resource/traffic ownership on this worker.
     * @param deadline Original budget.
     * @param cancelled Epoch/cancellation predicate.
     * @return Valid token outcome after final cancellation/expiry checks.
     * @throws AuthenticationFailure If no valid result succeeds within the configured budget.
     */
    private AuthenticationResult execute(JourneyDefinition.Identity identity, JourneyDefinition journey, SecretStore.Values values,
                            BrowserSessionLauncher.Session session,
                            long deadline, BooleanSupplier cancelled) throws AuthenticationFailure {
        BrowserContext context = session.context();
        TokenExtractor extractor = new TokenExtractor(journey.extraction(), clock);
        boolean requiresAllSteps = !journey.steps().isEmpty() && capturesCookies(journey.extraction());
        context.onResponse(response -> {
            observeStatus(response, journey, extractor);

        });
        try (var responses = BoundedTokenResponses.install(context, new BoundedTokenResponses.Capture() {
            @Override public boolean matches(String url) { return extractor.matchesResponse(url); }
            @Override public boolean complete() { return extractor.hasToken(); }
            @Override public void declaredLength(String value) throws AuthenticationFailure { TokenExtractor.checkDeclaredLength(value); }
            @Override public void response(String url, byte[] body, boolean success) { extractor.considerResponse(url, body, success); }
            @Override public void failure(AuthenticationFailure error) { extractor.observe(error); }
        })) {
        context.onRequestFailed(request -> {
            if (mainFrameNavigation(request)) {
                AuthenticationFailure observed = networkFailure(request.failure(), journey.mtls() != null); if (observed != null) extractor.observe(observed);
            }
        });
        Page page = context.newPage();
        try (var executor = new BrowserStepExecutor(context, page, journey.steps())) {
            int stepsStarted = 0;
            boolean executionFailed = false;
            try {
                applyTimeouts(page, journey, deadline, cancelled); page.navigate(journey.authenticationUrl().toString()); cookies(context, journey, extractor);
                for (int i = 0; i < journey.steps().size() && (requiresAllSteps || !extractor.hasToken()); i++) {
                    var action = journey.steps().get(i); stepsStarted = i + 1;
                    try {
                        AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.STEP, deadline, cancelled);
                        session.checkTraffic();
                        executor.execute(action, values, journey.browser().navigationTimeoutMs(), deadline, cancelled);
                    }
                    catch (PlaywrightException ex) {
                        var failure = stepFailure(ex, action, i + 1);
                        if (requiresAllSteps) throw failure;
                        executionFailed = true; extractor.observe(failure); break;
                    }
                    catch (AuthenticationFailure ex) { throw ex.atStep(new AuthenticationFailure.Step(action.id(), i + 1, action.type())); }
                    cookies(context, journey, extractor);
                }
                if (requiresAllSteps) {
                    executor.finish(deadline, cancelled, () -> false);
                    cookies(context, journey, extractor);
                }
            } catch (PlaywrightException ex) {
                var failure = stepFailure(ex, null, 0);
                if (requiresAllSteps) throw failure;
                executionFailed = true; extractor.observe(failure);
            }
            catch (AuthenticationFailure ex) {
                if (requiresAllSteps || ex.reason() != AuthenticationFailure.Cause.TIMEOUT) throw ex;
                extractor.observe(ex);
            }
            long waitEnd = Math.min(deadline, System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(journey.browser().tokenWaitTimeoutMs()));
            while (!extractor.hasToken() && waitEnd - System.nanoTime() > 0) {
                try { AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.EXTRACTION, deadline, cancelled); }
                catch (AuthenticationFailure ex) {
                    if (ex.reason() != AuthenticationFailure.Cause.TIMEOUT) throw ex;
                    extractor.observe(ex); break;
                }
                session.checkTraffic();
                cookies(context, journey, extractor);
                if (!extractor.hasToken()) try { executor.pump(Math.min(50.0, Math.max(0.001, (waitEnd - System.nanoTime()) / 1_000_000.0))); }
                catch (PlaywrightException ex) {
                    extractor.observe(new AuthenticationFailure(AuthenticationFailure.Phase.LIFECYCLE, AuthenticationFailure.Cause.UNKNOWN,
                            "The browser stopped before credentials could be captured."));
                    break;
                }
            }
            if (!executionFailed && !extractor.hasToken()) executor.finish(deadline, cancelled, extractor::hasToken);
            session.checkTraffic();
            if (session.transportFailure() != null) extractor.observe(session.transportFailure());
            try { AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.EXTRACTION, deadline, cancelled); }
            catch (AuthenticationFailure ex) {
                if (ex.reason() != AuthenticationFailure.Cause.TIMEOUT || extractor.hasToken()) throw ex;
                // Preserve a positively observed PIN/trust/status/extraction cause over a generic timeout.
                extractor.observe(ex);
            }
            return new AuthenticationResult(identity, extractor.result(), clock.instant(), System.nanoTime(), extractor.cookieValues(), extractor.namedValues(), extractor.expirySeconds(), journey.steps().size() - stepsStarted);
        }
        }
    }

    /**
     * Identifies captures that can match an anonymous session cookie before login has completed.
     * @param extraction Validated single or combined capture definition.
     * @return Whether configured login steps must finish before accepting the captured credentials.
     */
    private static boolean capturesCookies(JourneyDefinition.Extraction extraction) {
        if (extraction instanceof JourneyDefinition.CookieExtraction) return true;
        return extraction instanceof JourneyDefinition.CombinedExtraction combined
                && combined.tokens().stream().anyMatch(token -> capturesCookies(token.selector()));
    }


    /**
     * Caps both page defaults by the original attempt budget before another browser operation.
     *
     * @param page Owned page.
     * @param journey Timeout defaults.
     * @param deadline Original budget.
     * @param cancelled Cancellation predicate.
     * @throws AuthenticationFailure If exhausted.
     */
    private static void applyTimeouts(Page page, JourneyDefinition journey, long deadline, BooleanSupplier cancelled) throws AuthenticationFailure {
        double timeout = AuthenticationFailure.remainingMs(journey.browser().navigationTimeoutMs(), deadline, cancelled); page.setDefaultTimeout(timeout); page.setDefaultNavigationTimeout(timeout);
    }

    /**
     * Reads cookies applicable to the configured origin URL, retaining ambiguity or normalization failures.
     *
     * @param context Owned context.
     * @param journey Extraction definition.
     * @param extractor Attempt collector.
     */
    private static void cookies(BrowserContext context, JourneyDefinition journey, TokenExtractor extractor) {
        extractor.collectCookies(url -> context.cookies(url).stream().map(c -> new bpsh.authentication.credentials.CapturedCookie(c.name, c.value, c.domain, c.path, c.expires)).toList());
    }

    /**
     * Classifies only relevant auth statuses, ignoring unrelated third-party subresource failures.
     * @param response Observed owned-context response.
     * @param journey Extraction/authentication origins governing relevance.
     * @param extractor Attempt collector; a valid token still wins over incidental statuses.
     */
    private void observeStatus(Response response, JourneyDefinition journey, TokenExtractor extractor) {
        boolean relevant = extractor.matchesResponse(response.url());
        if (mainFrameNavigation(response.request())) try {
            URI origin = TokenExtractor.origin(URI.create(response.url()));
            relevant |= origin.equals(TokenExtractor.origin(journey.authenticationUrl()))
                    || journey.extraction() instanceof JourneyDefinition.CookieExtraction cookie && origin.equals(TokenExtractor.origin(cookie.originUrl()));
        } catch (RuntimeException ignored) { /* malformed/irrelevant URL */ }
        if (!relevant) return;
        int status = response.status();
        if (status == 401 || status == 403) extractor.observe(new AuthenticationFailure(AuthenticationFailure.Phase.NAVIGATION, AuthenticationFailure.Cause.AUTH_REJECTED,
                "The login server returned HTTP " + status + ".", "", status, null));
        else if (Set.of(408, 429, 500, 502, 503, 504).contains(status)) extractor.observe(new AuthenticationFailure(AuthenticationFailure.Phase.NAVIGATION, AuthenticationFailure.Cause.TEMPORARY_SERVICE,
                "The login service returned HTTP " + status + ".", "", status,
                status == 429 || status == 503 ? retryAfter(response.headerValue("retry-after"), clock.instant()) : null));
    }

    /**
     * Classifies only established top-level navigation without interrupting the event loop.
     * Playwright can report popup navigation before its frame exists; that observation
     * cannot establish a main-frame failure. Configured extraction URLs remain relevant
     * independently of frame availability.
     * @param request Owned-context request whose navigation metadata is being inspected.
     * @return Whether an available frame establishes top-level navigation.
     */
    static boolean mainFrameNavigation(com.microsoft.playwright.Request request) {
        if (!request.isNavigationRequest()) return false;
        try {
            var frame = request.frame();
            return frame != null && frame.parentFrame() == null;
        } catch (PlaywrightException unavailable) {
            return false;
        }
    }









    /**
     * Checks required secret availability and stable step ownership before launching browser or native work.
     *
     * @param journey Validated definition.
     * @param values Open attempt snapshot.
     * @throws AuthenticationFailure If a configured runtime secret is missing or ownership invalid.
     */
    private static void validateSecrets(JourneyDefinition journey, SecretStore.Values values) throws AuthenticationFailure {
        try { JourneySecrets.validateSecretOwnership(journey, values); }
        catch (IllegalArgumentException ex) { throw new AuthenticationFailure(AuthenticationFailure.Phase.SETUP, AuthenticationFailure.Cause.CONFIGURATION, "The saved login values no longer match this journey's configuration.", "Save the journey and re-enter the required passwords or PIN."); }
        char[] pin = values.pin();
        try {
            if (journey.mtls() != null && pin == null) throw missing("mTLS PIN");
            for (int i = 0; i < journey.steps().size(); i++) if (journey.steps().get(i).type() == AuthStep.Type.SECURE_INPUT) {
                var step = journey.steps().get(i); char[] value = values.stepValue(step.id());
                if (value == null) throw new AuthenticationFailure(AuthenticationFailure.Phase.SETUP, AuthenticationFailure.Cause.MISSING_SECRET,
                        "Step " + (i + 1) + " — Enter secret: no secret value was supplied.")
                        .atStep(new AuthenticationFailure.Step(step.id(), i + 1, step.type()));
                Arrays.fill(value, '\0');
            }
        } finally { if (pin != null) Arrays.fill(pin, '\0'); }
    }
    /**
     * Explains which configured value is unavailable and how the operator can supply it.
     *
     * @param field Safe configured field description.
     * @return Terminal missing-value guidance without credentials.
     */
    private static AuthenticationFailure missing(String field) {
        var result = new AuthenticationFailure(AuthenticationFailure.Phase.SETUP, AuthenticationFailure.Cause.MISSING_SECRET, "The journey is missing its " + field + ".", "Enter the value, then run Test login.");
        return field.equals("mTLS PIN") ? result.atInput(AuthenticationFailure.Input.MTLS_PIN) : result;
    }
}
