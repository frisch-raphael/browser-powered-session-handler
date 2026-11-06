import com.microsoft.playwright.Browser;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.PlaywrightException;
import com.microsoft.playwright.Request;
import com.microsoft.playwright.Response;
import com.microsoft.playwright.TimeoutError;
import com.microsoft.playwright.options.LoadState;
import com.microsoft.playwright.options.Proxy;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

/**
 * Executes a fresh browser/context on its calling worker, with listeners installed before navigation.
 *
 * This component does not register Burp hooks, cache tokens or perform automatic retries. The future
 * coordinator owns worker/cycle admission and generation publication. Browser/process/proxy cleanup
 * is scoped to this attempt, while verified binaries and established provider login may be reused.
 */
public final class BrowserFlowRunner {
    /** Stable SDK diagnostic marker used only for classification; the raw message is never retained. */
    private static final String AMBIGUOUS_SELECTOR = "strict mode violation:";
    /**
     * Carries a deliberate token result without making diagnostic output disclose it.
     * @param identity Configuration generation used by the attempt; caller rechecks before publication.
     * @param token Normalized extracted text for explicit use by the coordinator.
     * @param acquiredAt Wall time at successful completion.
     * @param acquiredNanos Monotonic acquisition time, so cleanup cannot extend the cache's maximum age.
     * @param cookies Configured cookie values, never diagnostic output.
     * @param namedTokens All user-named credentials used by explicit request tags.
     * @param expiresAt Earliest cookie/JWT expiry across the complete result.
     * @param skippedSteps Actions not started because all configured credentials were already captured.
     */
    public record Outcome(JourneyDefinition.Identity identity, String token, Instant acquiredAt, long acquiredNanos,
                          Map<String, String> cookies, Map<String, String> namedTokens, java.util.OptionalLong expiresAt, int skippedSteps) {
        /** Defensively copies the complete credential set without exposing values in diagnostics. */
        public Outcome { cookies = Map.copyOf(cookies); namedTokens = Map.copyOf(namedTokens); }
        /** Keeps adapters without execution metadata source-compatible. */
        public Outcome(JourneyDefinition.Identity identity, String token, Instant acquiredAt, long acquiredNanos,
                       Map<String, String> cookies, Map<String, String> namedTokens, java.util.OptionalLong expiresAt) {
            this(identity, token, acquiredAt, acquiredNanos, cookies, namedTokens, expiresAt, 0);
        }
        /**
         * Retains the single-token constructor for adapters with no additional cookie result.
         * @param identity Exact journey generation.
         * @param token Primary credential.
         * @param acquiredAt Acquisition wall clock.
         * @param acquiredNanos Acquisition monotonic clock.
         */
        public Outcome(JourneyDefinition.Identity identity, String token, Instant acquiredAt, long acquiredNanos) { this(identity, token, acquiredAt, acquiredNanos, Map.of(), Map.of(), java.util.OptionalLong.empty()); }
        /**
         * Returns identity-only diagnostics; no token or browser state.
         *
         * @return Identity-only diagnostics; no token or browser state.
         */
        @Override public String toString() { return "AuthenticationOutcome[identity=" + identity + "]"; }
    }

    /** Token-free observation of actual SDK resource creation and successful close completion. */
    public enum ResourceEvent { BROWSER_OPEN, CONTEXT_OPEN, CONTEXT_CLOSED, BROWSER_CLOSED }
    public record Lifecycle(long resourceId, long parentId, JourneyDefinition.Identity identity, ResourceEvent event, boolean bootstrap) {}
    private final java.util.function.Consumer<Lifecycle> lifecycle;
    private final java.util.concurrent.atomic.AtomicLong resourceIds = new java.util.concurrent.atomic.AtomicLong();
    private void observed(Lifecycle event) { try { lifecycle.accept(event); } catch (RuntimeException ignored) { /* diagnostics cannot prevent resource cleanup */ } }
    private final class OwnedBrowser implements AutoCloseable {
        final Browser browser; final JourneyDefinition.Identity identity; final long id = resourceIds.incrementAndGet();
        OwnedBrowser(Browser browser, JourneyDefinition.Identity identity) { this.browser = browser; this.identity = identity; observed(new Lifecycle(id, 0, identity, ResourceEvent.BROWSER_OPEN, false)); }
        @Override public void close() { browser.close(); observed(new Lifecycle(id, 0, identity, ResourceEvent.BROWSER_CLOSED, false)); }
    }
    private final class OwnedContext implements AutoCloseable {
        final BrowserContext context; final OwnedBrowser owner; final boolean bootstrap; final long id = resourceIds.incrementAndGet();
        OwnedContext(BrowserContext context, OwnedBrowser owner, boolean bootstrap) { this.context = context; this.owner = owner; this.bootstrap = bootstrap; observed(new Lifecycle(id, owner.id, owner.identity, ResourceEvent.CONTEXT_OPEN, bootstrap)); }
        @Override public void close() { context.close(); observed(new Lifecycle(id, owner.id, owner.identity, ResourceEvent.CONTEXT_CLOSED, bootstrap)); }
    }

    private final BrowserRuntimeManager runtime;
    private final Pkcs11IdentityManager identities;
    private final AuthTrafficGuard traffic;
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
        this.runtime = runtime; this.identities = identities; this.traffic = traffic; this.clock = clock; this.lifecycle = java.util.Objects.requireNonNull(lifecycle);
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
    public Outcome run(JourneyDefinition.Identity identity, JourneyDefinition journey, SecretStore.Values supplied,
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
    public Outcome run(JourneyDefinition.Identity identity, JourneyDefinition journey, SecretStore.Values supplied,
                       boolean explicitRecovery, long deadlineNanos, BooleanSupplier cancelled,
                       java.util.function.Consumer<BrowserRuntimeManager.SetupStage> observer) throws AuthenticationFailure {
        AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.SETUP, deadlineNanos, cancelled);
        if (journey.draft() != null) throw new AuthenticationFailure(AuthenticationFailure.Phase.SETUP,
                AuthenticationFailure.Cause.CONFIGURATION, "This journey has incomplete or invalid settings.", "Review the journey settings, then test login.");
        try (SecretStore.Values values = supplied.copy()) {
            validateSecrets(journey, values);
            BrowserRuntimeManager.Ready ready = runtime.acquire(deadlineNanos, cancelled, observer);
            char[] pin = values.pin();
            JourneyTlsProxy local = null;
            try {
                if (journey.mtls() != null) {
                    Pkcs11IdentityManager.Selected selected = identities.select(journey.mtls(), pin, explicitRecovery, deadlineNanos, cancelled);
                    local = new JourneyTlsProxy(journey.mtls(), selected, journey.browser().proxy(), clock);
                }
                boolean proxied = local != null || journey.browser().proxy() != null;
                BrowserRuntimeManager.observed(observer, BrowserRuntimeManager.SetupStage.STARTING_DRIVER);
                try (JourneyTlsProxy transport = local;
                     AuthTrafficGuard.Lease lease = proxied ? traffic.begin() : null;
                     PlaywrightDriverAdapter.Session driver = PlaywrightDriverAdapter.open(ready, deadlineNanos, cancelled)) {
                    var options = new BrowserType.LaunchOptions().setExecutablePath(ready.browserExecutable()).setHeadless(journey.browser().headless())
                            .setTimeout(AuthenticationFailure.remainingMs(journey.browser().navigationTimeoutMs(), deadlineNanos, cancelled));
                    if (transport != null) options.setProxy(transport.browserProxy()).setArgs(List.of("--ignore-certificate-errors-spki-list=" + transport.spkiSha256()));
                    else if (journey.browser().proxy() != null) options.setProxy(browserProxy(journey.browser().proxy()));
                    else options.setArgs(List.of("--no-proxy-server"));
                    BrowserRuntimeManager.observed(observer, BrowserRuntimeManager.SetupStage.STARTING_BROWSER);
                    try (var ownedBrowser = new OwnedBrowser(startBrowser(driver, options, deadlineNanos, cancelled), identity)) {
                        Browser browser = ownedBrowser.browser;
                        Browser.NewContextOptions contextOptions = new Browser.NewContextOptions();
                        String original = null;
                        if (lease != null) {
                            try (var bootstrap = new OwnedContext(browser.newContext(), ownedBrowser, true)) { original = (String) bootstrap.context.newPage().evaluate("navigator.userAgent"); }
                            contextOptions.setUserAgent(lease.decorate(original));
                        }
                        try (var context = new OwnedContext(browser.newContext(contextOptions), ownedBrowser, false)) {
                            BrowserRuntimeManager.observed(observer, BrowserRuntimeManager.SetupStage.AUTHENTICATING);
                            return execute(identity, journey, values, context.context, transport, lease, original, deadlineNanos, cancelled);
                        }
                    }
                }
            } finally { if (pin != null) Arrays.fill(pin, '\0'); }
        } catch (AuthenticationFailure ex) { throw ex; }
        catch (Exception ex) {
            AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.LIFECYCLE, deadlineNanos, cancelled);
            throw new AuthenticationFailure(AuthenticationFailure.Phase.SETUP, AuthenticationFailure.Cause.UNKNOWN,
                    "The browser could not complete the login.", "");
        }
    }

    /** Starts Chromium with narrow safe setup attribution.
     * @param driver Attempt-owned Playwright driver.
     * @param options Exact pinned executable and bounded launch options.
     * @param deadline Original deadline.
     * @param cancelled Attempt lifecycle predicate.
     * @return Owned caller browser.
     * @throws AuthenticationFailure On startup failure or cancellation.
     */
    private static Browser startBrowser(PlaywrightDriverAdapter.Session driver, BrowserType.LaunchOptions options,
                                        long deadline, BooleanSupplier cancelled) throws AuthenticationFailure {
        try { return driver.playwright().chromium().launch(options); }
        catch (RuntimeException error) {
            AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.SETUP, deadline, cancelled);
            throw new AuthenticationFailure(AuthenticationFailure.Phase.SETUP, AuthenticationFailure.Cause.UNKNOWN,
                    "Chromium could not start.", "Check the documented operating-system and browser-library prerequisites.");
        }
    }

    /**
     * Installs per-context routing/listeners, executes steps and pumps the event loop until completion.
     * @param identity Captured generation to attach to success.
     * @param journey Validated flow/extraction definition.
     * @param values Attempt-owned secret copies.
     * @param context Fresh context owned by the current worker.
     * @param transport mTLS transport, or null for ordinary journeys.
     * @param lease Marker for proxied traffic, or null for direct traffic.
     * @param defaultAgent Actual bootstrap agent, used when worker-script routing omits the header.
     * @param deadline Original budget.
     * @param cancelled Epoch/cancellation predicate.
     * @return Valid token outcome after final cancellation/expiry checks.
     * @throws AuthenticationFailure If no valid result succeeds within the configured budget.
     */
    private Outcome execute(JourneyDefinition.Identity identity, JourneyDefinition journey, SecretStore.Values values,
                            BrowserContext context, JourneyTlsProxy transport, AuthTrafficGuard.Lease lease, String defaultAgent,
                            long deadline, BooleanSupplier cancelled) throws AuthenticationFailure {
        TokenExtractor extractor = new TokenExtractor(journey.extraction(), clock);
        AtomicReference<AuthenticationFailure> routingFailure = new AtomicReference<>();
        if (lease != null) context.route("**/*", route -> {
            try {
                Request request = route.request();
                if (AuthTrafficGuard.containsNativeTag(request.url()) || AuthTrafficGuard.containsNativeTag(request.postData())
                        || request.headers().entrySet().stream().anyMatch(e -> AuthTrafficGuard.containsNativeTag(e.getKey()) || AuthTrafficGuard.containsNativeTag(e.getValue())))
                    throw new AuthenticationFailure(AuthenticationFailure.Phase.LIFECYCLE, AuthenticationFailure.Cause.CONFIGURATION,
                            "A login request contains authentication tags.", "Remove authentication tags from the requests made during login.");
                Map<String, String> headers = new HashMap<>(request.headers());
                // Service-worker script requests can omit User-Agent in Playwright's header map.
                // Preserve the real browser agent rather than forwarding only the marker.
                headers.put("user-agent", lease.decorate(headers.getOrDefault("user-agent", defaultAgent)));
                route.resume(new com.microsoft.playwright.Route.ResumeOptions().setHeaders(headers));
            } catch (AuthenticationFailure ex) { routingFailure.compareAndSet(null, ex); route.abort(); }
        });
        context.onResponse(response -> {
            observeStatus(response, journey, extractor);
            if (extractor.matchesResponse(response.url()) && !extractor.hasToken()) {
                try { TokenExtractor.checkDeclaredLength(response.headerValue("content-length")); extractor.considerResponse(response.url(), response.body(), response.status() >= 200 && response.status() < 300); }
                catch (AuthenticationFailure ex) { extractor.observe(ex); }
                catch (PlaywrightException ex) { extractor.observe(new AuthenticationFailure(AuthenticationFailure.Phase.EXTRACTION, AuthenticationFailure.Cause.EXTRACTION,
                        "The token response could not be read.", "")); }
            }
        });
        context.onRequestFailed(request -> {
            if (mainFrameNavigation(request)) {
                AuthenticationFailure observed = networkFailure(request.failure()); if (observed != null) extractor.observe(observed);
            }
        });
        Page page = context.newPage();
        int stepsStarted = 0;
        try {
            applyTimeouts(page, journey, deadline, cancelled); page.navigate(journey.authenticationUrl().toString()); cookies(context, journey, extractor);
            for (int i = 0; i < journey.steps().size() && !extractor.hasToken(); i++) {
                var action = journey.steps().get(i); stepsStarted = i + 1;
                try {
                    AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.STEP, deadline, cancelled);
                    if (routingFailure.get() != null) throw routingFailure.get();
                    applyTimeouts(page, journey, deadline, cancelled); step(page, action, values, deadline, cancelled);
                }
                catch (PlaywrightException ex) {
                    extractor.observe(stepFailure(ex, action, i + 1)); break;
                }
                catch (AuthenticationFailure ex) { throw ex.atStep(new AuthenticationFailure.Step(action.id(), i + 1, action.type())); }
                cookies(context, journey, extractor);
            }
        } catch (PlaywrightException ex) { extractor.observe(stepFailure(ex, null, 0)); }
        catch (AuthenticationFailure ex) {
            if (ex.reason() != AuthenticationFailure.Cause.TIMEOUT) throw ex;
            extractor.observe(ex);
        }
        long waitEnd = Math.min(deadline, System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(journey.browser().tokenWaitTimeoutMs()));
        while (!extractor.hasToken() && waitEnd - System.nanoTime() > 0) {
            try { AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.EXTRACTION, deadline, cancelled); }
            catch (AuthenticationFailure ex) {
                if (ex.reason() != AuthenticationFailure.Cause.TIMEOUT) throw ex;
                extractor.observe(ex); break;
            }
            if (routingFailure.get() != null) throw routingFailure.get();
            cookies(context, journey, extractor);
            if (!extractor.hasToken()) try { page.waitForTimeout(Math.min(50.0, Math.max(0.001, (waitEnd - System.nanoTime()) / 1_000_000.0))); }
            catch (PlaywrightException ex) { break; }
        }
        if (routingFailure.get() != null) throw routingFailure.get();
        if (transport != null && transport.failure() != null) extractor.observe(transport.failure());
        try { AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.EXTRACTION, deadline, cancelled); }
        catch (AuthenticationFailure ex) {
            if (ex.reason() != AuthenticationFailure.Cause.TIMEOUT || extractor.hasToken()) throw ex;
            // Preserve a positively observed PIN/trust/status/extraction cause over a generic timeout.
            extractor.observe(ex);
        }
        return new Outcome(identity, extractor.result(), clock.instant(), System.nanoTime(), extractor.cookieValues(), extractor.namedValues(), extractor.expirySeconds(), journey.steps().size() - stepsStarted);
    }

    /**
     * Executes one retained step using only its own secret association and current remaining budget.
     * @param page Owned primary page.
     * @param step Validated immutable step.
     * @param values Attempt-owned values.
     * @param deadline Original budget.
     * @param cancelled Epoch/cancellation predicate.
     * @throws AuthenticationFailure If cancelled/expired or a required secure value is absent.
     */
    private static void step(Page page, AuthStep.Definition step, SecretStore.Values values, long deadline,
                              BooleanSupplier cancelled) throws AuthenticationFailure {
        switch (step.type()) {
            case CLICK -> page.locator(step.selector()).click();
            case INPUT -> page.locator(step.selector()).fill(step.value());
            case SECURE_INPUT -> {
                char[] value = values.stepValue(step.id());
                if (value == null) throw missing("secure-input value");
                try { page.locator(step.selector()).fill(new String(value)); } finally { Arrays.fill(value, '\0'); }
            }
            case WAIT_LOAD_STATE -> page.waitForLoadState(switch (step.state()) { case "domcontentloaded" -> LoadState.DOMCONTENTLOADED; case "networkidle" -> LoadState.NETWORKIDLE; default -> LoadState.LOAD; });
            case WAIT_URL -> { if ("exact".equals(step.state())) page.waitForURL(url -> url.equals(step.urlPattern())); else page.waitForURL(step.urlPattern()); }
            case WAIT_SELECTOR -> page.locator(step.selector()).waitFor(new com.microsoft.playwright.Locator.WaitForOptions().setState(
                    switch (step.state() == null ? "visible" : step.state()) { case "hidden" -> com.microsoft.playwright.options.WaitForSelectorState.HIDDEN; case "attached" -> com.microsoft.playwright.options.WaitForSelectorState.ATTACHED; case "detached" -> com.microsoft.playwright.options.WaitForSelectorState.DETACHED; default -> com.microsoft.playwright.options.WaitForSelectorState.VISIBLE; }));
            case WAIT_TIME -> {
                long end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(step.durationMs());
                while (end - System.nanoTime() > 0) { AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.STEP, deadline, cancelled); page.waitForTimeout(Math.min(50, Math.max(0.001, (end - System.nanoTime()) / 1_000_000.0))); }
            }
        }
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
        extractor.collectCookies(url -> context.cookies(url));
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
     * Maps browser main-frame request-failure symbols only, never selector/exception prose.
     * @param symbol Playwright Request.failure observation.
     * @return Typed positive transport/trust observation, or null for an unmapped outcome.
     */
    static AuthenticationFailure networkFailure(String symbol) {
        if (symbol == null) return null;
        String code = symbol.startsWith("net::") ? symbol.substring(5) : symbol;
        if (!code.matches("ERR_[A-Z0-9_]{1,100}")) return null;
        switch (code) {
            case "ERR_NAME_NOT_RESOLVED" -> {
                return navigationFailure(AuthenticationFailure.Cause.UNKNOWN, code,
                        "The login server's hostname could not be resolved");
            }
            case "ERR_CONNECTION_REFUSED" -> {
                return navigationFailure(AuthenticationFailure.Cause.TRANSPORT, code,
                        "The connection to the login server was refused");
            }
            case "ERR_CONNECTION_TIMED_OUT" -> {
                return navigationFailure(AuthenticationFailure.Cause.TRANSPORT, code,
                        "The connection to the login server timed out");
            }
            case "ERR_CONNECTION_RESET", "ERR_CONNECTION_CLOSED" -> {
                return navigationFailure(AuthenticationFailure.Cause.TRANSPORT, code,
                        "The connection closed before the login page loaded");
            }
            case "ERR_NETWORK_CHANGED" -> {
                return navigationFailure(AuthenticationFailure.Cause.TRANSPORT, code,
                        "The browser's network connection changed while loading the login page");
            }
            case "ERR_INTERNET_DISCONNECTED" -> {
                return navigationFailure(AuthenticationFailure.Cause.TRANSPORT, code,
                        "The browser lost its network connection");
            }
            case "ERR_PROXY_CONNECTION_FAILED" -> {
                return navigationFailure(AuthenticationFailure.Cause.UNKNOWN, code,
                        "The browser could not connect to the configured proxy");
            }
            case "ERR_TUNNEL_CONNECTION_FAILED" -> {
                return navigationFailure(AuthenticationFailure.Cause.UNKNOWN, code,
                        "The proxy could not connect to the login server");
            }
            case "ERR_CERT_AUTHORITY_INVALID" -> {
                return navigationFailure(AuthenticationFailure.Cause.TRUST, code,
                        "The browser does not trust the login server's certificate");
            }
            case "ERR_CERT_COMMON_NAME_INVALID" -> {
                return navigationFailure(AuthenticationFailure.Cause.TRUST, code,
                        "The server's certificate does not match the login hostname");
            }
            case "ERR_CERT_DATE_INVALID" -> {
                return navigationFailure(AuthenticationFailure.Cause.TRUST, code,
                        "The server's certificate is outside its validity dates");
            }
            case "ERR_CERT_REVOKED" -> {
                return navigationFailure(AuthenticationFailure.Cause.TRUST, code,
                        "The login server's certificate has been revoked");
            }
        }
        if (code.startsWith("ERR_CERT_"))
            return navigationFailure(AuthenticationFailure.Cause.TRUST, code,
                    "The browser rejected the login server's certificate");
        if (code.equals("ERR_INVALID_AUTH_CREDENTIALS") || code.equals("ERR_PROXY_AUTH_UNSUPPORTED"))
            return new AuthenticationFailure(AuthenticationFailure.Phase.PROXY, AuthenticationFailure.Cause.PROXY_AUTH,
                    code.equals("ERR_PROXY_AUTH_UNSUPPORTED")
                            ? "The browser could not use the proxy's authentication method (" + code + ")."
                            : "The browser rejected authentication (" + code + ").").atInput(AuthenticationFailure.Input.PROXY_URL);
        if (code.equals("ERR_SSL_PROTOCOL_ERROR") || code.equals("ERR_SSL_VERSION_OR_CIPHER_MISMATCH"))
            return navigationFailure(AuthenticationFailure.Cause.UNKNOWN, code,
                    "The browser could not establish an HTTPS connection to the login server");
        return navigationFailure(AuthenticationFailure.Cause.UNKNOWN, code,
                "The browser could not open the login page");
    }

    /** Reports only the observed browser failure and its safe code. */
    private static AuthenticationFailure navigationFailure(AuthenticationFailure.Cause cause, String code, String problem) {
        var result = new AuthenticationFailure(AuthenticationFailure.Phase.NAVIGATION, cause, problem + " (" + code + ").");
        if (code.contains("PROXY") || code.equals("ERR_TUNNEL_CONNECTION_FAILED")) return result.atInput(AuthenticationFailure.Input.PROXY_URL);
        if (Set.of("ERR_NETWORK_CHANGED", "ERR_INTERNET_DISCONNECTED").contains(code)) return result;
        return result.atInput(AuthenticationFailure.Input.LOGIN_URL);
    }

    /**
     * Parses server retry guidance without changing the attempt or cycle deadline.
     *
     * @param value Relevant Retry-After header.
     * @param now Observation wall time.
     * @return Parsed nonnegative delta/date, or null for invalid input.
     */
    static Instant retryAfter(String value, Instant now) {
        if (value == null) return null;
        try { return value.matches("[0-9]+") ? now.plusSeconds(Long.parseLong(value)) : ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant(); }
        catch (RuntimeException ex) { return null; }
    }

    /**
     * Reports a safe step index and timeout category without retaining raw browser exception text.
     *
     * @param error Browser operation exception, inspected only for timeout type.
     * @param index One-based step or zero for initial navigation.
     * @param step Exact configured action, or null for initial navigation.
     * @return Safe terminal operation result.
     */
    private static AuthenticationFailure stepFailure(PlaywrightException error, AuthStep.Definition step, int index) {
        boolean ambiguous = step != null && error.getMessage() != null && error.getMessage().contains(AMBIGUOUS_SELECTOR);
        String action = step == null ? "Opening the login page" : "Step " + index + " — " + step.type().label();
        var failure = new AuthenticationFailure(index == 0 ? AuthenticationFailure.Phase.NAVIGATION : AuthenticationFailure.Phase.STEP,
                error instanceof TimeoutError ? AuthenticationFailure.Cause.STEP_TIMEOUT : AuthenticationFailure.Cause.UNKNOWN,
                action + (ambiguous ? ": the selector matches several elements." : error instanceof TimeoutError ? " timed out." : " failed."));
        return step == null ? failure.atInput(AuthenticationFailure.Input.LOGIN_URL) : failure.atStep(new AuthenticationFailure.Step(step.id(), index, step.type()));
    }

    /**
     * Binds an explicit HTTP proxy to this owned browser, preventing Chromium's implicit loopback bypass.
     *
     * @param proxy Explicit validated HTTP proxy.
     * @return Owned-browser proxy binding.
     */
    private static Proxy browserProxy(JourneyDefinition.Proxy proxy) {
        return new Proxy(proxy.url().toString()).setBypass("<-loopback>");
    }

    /**
     * Checks required secret availability and stable step ownership before launching browser or native work.
     *
     * @param journey Validated definition.
     * @param values Open attempt snapshot.
     * @throws AuthenticationFailure If a configured runtime secret is missing or ownership invalid.
     */
    private static void validateSecrets(JourneyDefinition journey, SecretStore.Values values) throws AuthenticationFailure {
        try { ConfigManager.validateSecretOwnership(journey, values); }
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
