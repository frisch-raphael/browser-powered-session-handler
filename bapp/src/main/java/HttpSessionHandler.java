import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.MessageReceivedAction;
import burp.api.montoya.proxy.http.*;
import java.io.ByteArrayInputStream;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Applies one native request pipeline globally and exempts only verified owned traffic from Proxy interception. */
public final class HttpSessionHandler implements HttpHandler, ProxyRequestHandler, ProxyResponseHandler, AutoCloseable {
    private final JourneyRegistry registry;
    private final NativeTagResolver resolver;
    private final AuthTrafficGuard guard;
    private final SessionRecovery recovery;
    private final Diagnostics diagnostics;
    private final AtomicReference<Config.Controls> controls;
    private final AtomicBoolean closed = new AtomicBoolean();

    /** Host boundary for a single actual replay send; response hooks retain the normal response path. */
    @FunctionalInterface public interface ReplayTransport { void send(HttpRequest request, long responseTimeoutMs) throws Exception; }
    private final ReplayTransport transport;
    private final java.util.concurrent.ThreadPoolExecutor replayWorkers = new java.util.concurrent.ThreadPoolExecutor(2, 2, 0,
            java.util.concurrent.TimeUnit.MILLISECONDS, new java.util.concurrent.ArrayBlockingQueue<>(256), r -> { var t = new Thread(r, "bpsh-recovery-replay"); t.setDaemon(true); return t; });
    private final java.util.concurrent.ConcurrentHashMap<String, ReplayJob> replayDeliveries = new java.util.concurrent.ConcurrentHashMap<>();

    /**
     * Wires shared native services without installing hooks or changing the Proxy master switch.
     * @param registry Consistent saved alias/generation publications.
     * @param resolver Atomic explicit/ordinary replacement pipeline.
     * @param guard Active owned-attempt markers and separate hook ledgers.
     * @param recovery Used-version recovery only.
     * @param diagnostics Safe annotated/logged outcomes.
     * @param controls Current validated project policy; explicit tags remain independent.
     */
    public HttpSessionHandler(JourneyRegistry registry, NativeTagResolver resolver, AuthTrafficGuard guard,
                              SessionRecovery recovery, Diagnostics diagnostics, AtomicReference<Config.Controls> controls) { this(registry, resolver, guard, recovery, diagnostics, controls, null); }
    /** Wires actual host replay delivery without moving it into the response callback or the test adapter. */
    public HttpSessionHandler(JourneyRegistry registry, NativeTagResolver resolver, AuthTrafficGuard guard,
                              SessionRecovery recovery, Diagnostics diagnostics, AtomicReference<Config.Controls> controls, ReplayTransport transport) {
        this.registry = registry; this.resolver = resolver; this.guard = guard; this.recovery = recovery; this.diagnostics = diagnostics; this.controls = controls; this.transport = transport;
    }

    /**
     * Resolves one request atomically; only the Burp callback waits, while authentication runs on owned workers.
     * @param request Global outgoing request; its raw bytes are inspected before URL helpers.
     * @return Complete continuation, original ordinary continuation with warning, or supported annotated drop.
     */
    @Override public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        boolean tagged = false; JourneyRegistry.Entry selected = null;
        try {
            var ownership = ownership(request, AuthTrafficGuard.Family.GLOBAL, request.messageId());
            if (ownership.classification() == AuthTrafficGuard.Classification.INVALID) return stopped(request, null, ownership.failure());
            if (ownership.replayKey() != null) {
                tagged = true; // A failed replay is always stopped; never fall through to unchanged forwarding of its marker.
                var replay = replayDeliveries.get(ownership.replayKey());
                if (closed.get() || replay == null || !replay.dispatched.compareAndSet(false, true)) return stopped(request, null, unavailable());
                replay.plan.validateForDelivery();
                recovery.record(request.messageId(), replay.plan.uses(), false);
                replay.actualId = request.messageId();
                appendNote(replay.originalNotes, "BPSH replay: request " + request.messageId() + ". Original response retained.");
                return RequestToBeSentAction.continueWith(replay.clean, request.annotations().withNotes("BPSH recovery replay of request " + replay.plan.originalId() + "."));
            }
            ByteArray bytes = request.toByteArray(); tagged = hasTags(bytes);
            if (ownership.classification() == AuthTrafficGuard.Classification.OWNED) {
                if (tagged) return stopped(request, null, nested());
                return RequestToBeSentAction.continueWith(request.withUpdatedHeader("User-Agent", ownership.userAgent()), request.annotations());
            }
            if (closed.get()) {
                if (tagged) return stopped(request, null, unavailable());
                return RequestToBeSentAction.continueWith(request, request.annotations());
            }
            var cfg = controls.get();
            var matching = !tagged && cfg.enabled() && cfg.tools().contains(request.toolSource().toolType())
                    ? cfg.rules().stream().filter(r -> r.enabled() && handlesUrl(r, request)).toList() : List.<Config.AutomaticRule>of();
            boolean ordinary = !matching.isEmpty();
            if (!tagged && !ordinary) return RequestToBeSentAction.continueWith(request, request.annotations());
            if (tagged && bytes.length() > NativeTagParser.MAX_OUTPUT_BYTES) return stopped(request, null, NativeTagParser.syntax("The tagged request exceeds the 4 MiB message ceiling."));
            var automatic = new java.util.ArrayList<NativeTagResolver.Automatic>();
            if (ordinary) {
                var snapshot = registry.snapshot();
                for (var rule : matching) {
                    try { selected = snapshot.resolve(new SecretStore.Key(rule.journey().scope(), rule.journey().id())); }
                    catch (IllegalStateException ex) { selected = null; throw configuration("An enabled automatic journey is unavailable.", "Review its rule in Session handling."); }
                    automatic.add(new NativeTagResolver.Automatic(selected, rule.recovery()));
                }
            }
            try (var operation = resolver.resolveAutomatic(bytes.getBytes(), automatic)) {
                var resolved = operation.future().get();
                if (!resolved.changed()) return RequestToBeSentAction.continueWith(request, request.annotations());
                byte[] committed = resolved.commit();
                HttpRequest changed = HttpRequest.httpRequest(request.httpService(), ByteArray.byteArray(committed));
                var used = resolved.uses();
                if (tagged && cfg.enabled()) {
                    used = used.stream().map(u -> {
                        var rule = cfg.rules().stream().filter(r -> r.enabled() && r.journey().scope() == u.identity().scope()
                                && r.journey().id().equals(u.identity().journeyId()) && handlesUrl(r, changed)).reduce((a, b) -> b);
                        return rule.map(r -> new SessionRecovery.Used(u.identity(), u.version(), r.recovery())).orElse(u);
                    }).toList();
                }
                recovery.record(request.messageId(), used, false, resolved.replayTemplate(bytes.getBytes()));
                return RequestToBeSentAction.continueWith(changed, request.annotations());
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt(); return failed(request, selected, tagged, new AuthenticationFailure(AuthenticationFailure.Phase.QUEUE, AuthenticationFailure.Cause.CANCELLED,
                    "This request's authentication wait was interrupted.", "Resend the request when ready."));
        } catch (ExecutionException ex) {
            return failed(request, selected, tagged, ex.getCause() instanceof AuthenticationFailure safe ? safe : unknown());
        } catch (AuthenticationFailure ex) { return failed(request, selected, tagged, ex); }
        catch (RuntimeException | LinkageError ex) { return failed(request, selected, tagged, unknown()); }
    }

    /**
     * Runs attributed recovery independently of the current UI selection when automatic handling is enabled.
     * @param response Global correlated response; status-only recovery never materializes its body.
     * @return The original response unchanged; an authorized single replay is sent and correlated separately.
     */
    @Override public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        var notes = response.annotations();
        if (!closed.get()) {
            boolean internal = guard.consumeResponse(AuthTrafficGuard.Family.GLOBAL, response.messageId());
            var decision = recovery.receivedPlan(response.messageId(), response.statusCode(), () -> {
                int actualBytes = response.toByteArray().length() - response.bodyOffset();
                return new SessionRecovery.Response(response.statusCode(), response.headerValue("Content-Type"), response.headerValue("Content-Encoding"),
                        actualBytes, () -> new ByteArrayInputStream(response.body().getBytes()));
            }, internal, controls.get().enabled());
            if (decision.matched()) appendNote(notes, "BPSH detected session loss. Original response retained; a request can be replayed at most once.");
            if (decision.replay() != null) {
                var initiating = response.initiatingRequest(); var service = initiating == null ? null : initiating.httpService();
                decision.replay().whenComplete((plan, error) -> {
                    if (error != null) { replayFailure(notes, error); return; }
                    var job = new ReplayJob(plan, service, notes);
                    if (closed.get() || transport == null) { job.close(); replayFailure(notes, unavailable()); return; }
                    try { replayWorkers.execute(job); }
                    catch (RuntimeException failure) { job.close(); replayFailure(notes, new AuthenticationFailure(AuthenticationFailure.Phase.QUEUE,
                            AuthenticationFailure.Cause.CAPACITY, "The recovery replay queue is full. The original response was retained.")); }
                });
            }
        }
        return ResponseReceivedAction.continueWith(response, notes);
    }

    /** Retains actual replay correlation without retaining original application response bodies. */
    private final class ReplayJob implements Runnable, AutoCloseable {
        final SessionRecovery.ReplayPlan plan;
        final burp.api.montoya.http.HttpService service;
        final Annotations originalNotes;
        final AtomicBoolean dispatched = new AtomicBoolean();
        volatile HttpRequest clean;
        volatile AuthTrafficGuard.Lease lease;
        volatile long actualId = -1;
        ReplayJob(SessionRecovery.ReplayPlan plan, burp.api.montoya.http.HttpService service, Annotations originalNotes) { this.plan = plan; this.service = service; this.originalNotes = originalNotes; }
        @Override public void run() {
            try {
                if (closed.get() || !controls.get().enabled()) return;
                clean = HttpRequest.httpRequest(service, ByteArray.byteArray(plan.claim()));
                lease = guard.beginReplay(); replayDeliveries.put(lease.key(), this);
                var marked = clean.withUpdatedHeader("User-Agent", lease.decorate(clean.headerValue("User-Agent")));
                if (closed.get()) return;
                transport.send(marked, controls.get().requestWaitTimeoutMs());
            } catch (Exception | LinkageError error) { replayFailure(originalNotes, error); }
            finally { close(); }
        }
        @Override public void close() { var marker = lease; if (marker != null) { replayDeliveries.remove(marker.key(), this); marker.close(); } plan.close(); }
    }
    /** Preserves existing user notes and identifies both original and replay outcomes using safe numeric IDs. */
    private static void appendNote(Annotations notes, String message) {
        synchronized (notes) { String current = notes.notes(); notes.setNotes((current == null || current.isBlank() ? "" : current + "\n") + message); }
    }
    /** Reports a known failed replay/wait without changing its cause or inventing an application response. */
    private void replayFailure(Annotations notes, Throwable error) {
        if (closed.get()) return;
        Throwable cause = error instanceof java.util.concurrent.CompletionException && error.getCause() != null ? error.getCause() : error;
        var safe = cause instanceof AuthenticationFailure known ? known : new AuthenticationFailure(AuthenticationFailure.Phase.LIFECYCLE,
                AuthenticationFailure.Cause.UNKNOWN, "The recovery replay did not complete. The original response was retained.");
        var entry = safe.journey() == null ? null : registry.snapshot().entries().get(safe.journey().key());
        diagnostics.state(entry == null ? null : entry.definition().alias(), safe); appendNote(notes, "BPSH recovery: " + safe.getMessage());
    }

    /**
     * Bypasses request interception only for an active owned marker and retains the suffix for global stripping.
     * @param request Proxy-received request in its independent message-ID namespace.
     * @return Normal interception policy, owned doNotIntercept, or a stopped invalid/nested request.
     */
    @Override public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest request) {
        var decision = ownership(request, AuthTrafficGuard.Family.PROXY, request.messageId());
        AuthenticationFailure error = decision.classification() == AuthTrafficGuard.Classification.INVALID ? decision.failure()
                : decision.classification() == AuthTrafficGuard.Classification.OWNED && hasTags(request.toByteArray()) ? nested() : null;
        if (error != null) {
            var notice = diagnostics.request(request.messageId(), null, error, true);
            return ProxyRequestReceivedAction.proxyRequestReceivedAction(request, annotate(request.annotations(), notice), MessageReceivedAction.DROP);
        }
        return decision.classification() == AuthTrafficGuard.Classification.OWNED && decision.replayKey() == null
                ? ProxyRequestReceivedAction.doNotIntercept(request, request.annotations()) : ProxyRequestReceivedAction.continueWith(request, request.annotations());
    }

    /**
     * Leaves Proxy transmission unchanged because global handling owns resolution and marker removal.
     *
     * @param request Proxy outgoing message.
     * @return Unchanged request; global handling owns stripping/resolution.
     */
    @Override public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest request) { return ProxyRequestToBeSentAction.continueWith(request, request.annotations()); }
    /**
     * Exempts only a retained Proxy-owned response ID, independently of global recovery attribution.
     *
     * @param response Proxy response with its own correlated ID.
     * @return doNotIntercept only for retained owned provenance.
     */
    @Override public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
        return guard.consumeResponse(AuthTrafficGuard.Family.PROXY, response.messageId()) ? ProxyResponseReceivedAction.doNotIntercept(response, response.annotations())
                : ProxyResponseReceivedAction.continueWith(response, response.annotations());
    }
    /**
     * Preserves the response and the user's normal final Proxy handling.
     *
     * @param response Proxy outgoing response.
     * @return Original response under the user's normal policy.
     */
    @Override public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) { return ProxyResponseToBeSentAction.continueWith(response, response.annotations()); }

    /**
     * Handles duplicate carriers conservatively; an ambiguous reserved suffix never grants ownership.
     * @param request Actual global or Proxy request.
     * @param family Independent ledger family.
     * @param id Correlated host ID in that family.
     * @return Safe carrier disposition without logging marker values.
     */
    private AuthTrafficGuard.Decision ownership(HttpRequest request, AuthTrafficGuard.Family family, long id) {
        var agents = request.headers().stream().filter(h -> h.name().equalsIgnoreCase("User-Agent")).map(h -> h.value()).toList();
        if (agents.size() <= 1) return guard.classify(agents.isEmpty() ? null : agents.getFirst(), family, id);
        boolean reserved = agents.stream().map(a -> guard.classify(a, family, id)).anyMatch(d -> d.classification() != AuthTrafficGuard.Classification.NORMAL);
        return reserved ? new AuthTrafficGuard.Decision(AuthTrafficGuard.Classification.INVALID, null, configuration("The request has an authentication marker in more than one User-Agent header.", "Retry the journey. For a manually edited request, keep a single User-Agent header and remove the BPSHAuth marker."))
                : new AuthTrafficGuard.Decision(AuthTrafficGuard.Classification.NORMAL, null, null);
    }

    /**
     * Searches host bytes without allocating a huge untagged upload; encoded target scans use small overlapping chunks.
     * @param bytes Host-owned raw message.
     * @return Whether explicit native policy applies before any URL helper or scope test.
     */
    static boolean hasTags(ByteArray bytes) {
        if (bytes.indexOf("<@") >= 0 || bytes.indexOf("</@") >= 0) return true;
        int lineEnd = bytes.indexOf("\r\n"); if (lineEnd < 0) return false;
        for (int start = 0; start < lineEnd; start += 8192) {
            byte[] chunk = bytes.subArray(start, Math.min(lineEnd, start + 8192 + 32)).getBytes();
            if (NativeTagParser.encodedPrefix(chunk, 0, chunk.length)) return true;
        }
        return false;
    }

    /**
     * Applies ordinary injection scope only after raw explicit-tag detection has completed.
     *
     * @param cfg Ordinary controls.
     * @param request Untagged request only.
     * @return Whether its actual URL/scope is eligible.
     */
    private static boolean handlesUrl(Config.AutomaticRule cfg, HttpRequest request) {
        return switch (cfg.urlMode()) { case ALL_REQUESTS -> true; case BURP_SCOPE -> request.isInScope(); case SINGLE_URL -> request.url().startsWith(cfg.urlPrefix().toString()); };
    }
    /**
     * Maps a safe failure to whole-request tagged drop or the unchanged ordinary request with a warning.
     *
     * @param request Original request.
     * @param selected Optional selected ordinary entry.
     * @param tagged Whole-request policy.
     * @param error Typed safe error.
     * @return Drop or original continuation.
     */
    private RequestToBeSentAction failed(HttpRequestToBeSent request, JourneyRegistry.Entry selected, boolean tagged, AuthenticationFailure error) {
        if (tagged) return stopped(request, alias(error, selected), error);
        var notice = diagnostics.request(request.messageId(), alias(error, selected), error, false);
        return RequestToBeSentAction.continueWith(request, annotate(request.annotations(), notice));
    }
    /**
     * Creates a supported annotated drop without fabricating an application response.
     *
     * @param request Original request.
     * @param alias Known alias or null.
     * @param error Typed cause and guidance.
     * @return Supported annotated drop, never a synthetic target response.
     */
    private RequestToBeSentAction stopped(HttpRequestToBeSent request, String alias, AuthenticationFailure error) {
        return RequestToBeSentAction.drop(annotate(request.annotations(), diagnostics.request(request.messageId(), alias, error, true)));
    }
    /**
     * Finds the actually failed saved alias from safe generation attribution rather than guessing from UI selection.
     *
     * @param error Possibly attributed safe failure.
     * @param selected Optional ordinary selection.
     * @return Actual failed alias when still available, otherwise the selected alias or null.
     */
    private String alias(AuthenticationFailure error, JourneyRegistry.Entry selected) {
        if (error.journey() != null) { var entry = registry.snapshot().entries().get(error.journey().key()); if (entry != null) return entry.definition().alias(); }
        return selected == null ? null : selected.definition().alias();
    }
    /**
     * Preserves user notes while adding a safe outcome and highlighting a tagged stop.
     *
     * @param original Existing host notes/highlight.
     * @param notice Safe request outcome.
     * @return Notes preserving user content and highlighting tagged stops.
     */
    private static Annotations annotate(Annotations original, Diagnostics.Notice notice) {
        String notes = original.notes(); var result = original.withNotes((notes == null || notes.isBlank() ? "" : notes + "\n") + notice.text());
        return notice.requestStopped() ? result.withHighlightColor(HighlightColor.RED) : result;
    }
    /**
     * Builds a terminal lifecycle/configuration correction without attaching raw host exception text.
     *
     * @param problem Known configuration issue.
     * @param action Concrete correction.
     * @return Redacted terminal configuration failure.
     */
    private static AuthenticationFailure configuration(String problem, String action) { return new AuthenticationFailure(AuthenticationFailure.Phase.LIFECYCLE, AuthenticationFailure.Cause.CONFIGURATION, problem, action); }
    /**
     * Returns actionable rejection of recursive native tags on owned traffic.
     *
     * @return Actionable rejection of recursive native tags on owned traffic.
     */
    private static AuthenticationFailure nested() { return configuration("A login request contains authentication tags.", "Remove authentication tags from the requests made during login."); }
    /**
     * Returns safe unload failure for a still-registered explicit request.
     *
     * @return Safe unload failure for a still-registered explicit request.
     */
    private static AuthenticationFailure unavailable() { return new AuthenticationFailure(AuthenticationFailure.Phase.LIFECYCLE, AuthenticationFailure.Cause.CLOSED, "The extension is unloading.", "Reload the extension and resend the tagged request when ready."); }
    /**
     * Returns unknown stays unknown, without logging raw host/selector/credential-bearing exceptions.
     *
     * @return Unknown stays unknown, without logging raw host/selector/credential-bearing exceptions.
     */
    private static AuthenticationFailure unknown() { return new AuthenticationFailure(AuthenticationFailure.Phase.LIFECYCLE, AuthenticationFailure.Cause.UNKNOWN, "The request could not be prepared for authentication.", ""); }
    /** Stops new acquisition through these hooks; the lifecycle owner deregisters them and closes shared services. */
    @Override public void close() {
        closed.set(true);
        for (var task : replayWorkers.shutdownNow()) if (task instanceof ReplayJob job) job.close();
        replayDeliveries.values().forEach(ReplayJob::close);
    }
}
