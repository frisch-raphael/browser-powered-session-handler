import com.google.re2j.Pattern;
import com.google.re2j.PatternSyntaxException;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import java.util.function.Consumer;
import java.util.function.BiConsumer;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;

/** Coordinates attributed, single-use recovery replays with bounded retention and linear-time RE2 matching. */
public final class SessionRecovery implements AutoCloseable {
    static final int MAX_BODY = 64 << 10, MAX_RECORDS = 10_000;
    /** Explains supported body recovery settings for the future native UI and skipped-body guidance. */
    public static final String BODY_MATCH_HELP = "Body recovery checks declared text/JSON/XML/JavaScript/form MIME types in UTF-8, ASCII or ISO-8859-1, with 64 KiB encoded and decoded limits. Gzip and zlib-deflate are supported; convert other encodings/charsets or use status-code recovery.";
    static final long RETENTION = java.util.concurrent.TimeUnit.MINUTES.toNanos(5);

    /** Token-free provenance captured at successful request commit, not from the UI's current selection. */
    public record Used(JourneyDefinition.Identity identity, long version, JourneyDefinition.Recovery rule, long validationEpisode, boolean replay) {
        public Used(JourneyDefinition.Identity identity, long version, JourneyDefinition.Recovery rule) { this(identity, version, rule, 0, false); }
    }
    /**
     * Borrows a response body lazily; status-only rules never call the body supplier.
     * @param status Actual response status code.
     * @param contentType Declared MIME/charset, or null.
     * @param contentEncoding Declared content coding, or null.
     * @param bodyBytes Actual encoded body byte count from the host, not Content-Length.
     * @param body Owned stream supplier used only for bounded regex decoding.
     */
    public record Response(int status, String contentType, String contentEncoding, long bodyBytes, Supplier<InputStream> body) {}
    /** Stores only safe used-version provenance and monotonic insertion time. */
    private record Attribution(long at, List<Used> used, NativeTagResolver.ReplayTemplate template, Reservation reservation) {}

    private final AuthenticationCoordinator coordinator;
    private final LongSupplier nanos;
    private final BiConsumer<JourneyDefinition.Identity, String> guidance;
    private final LinkedHashMap<Long, Attribution> records = new LinkedHashMap<>();
    private final LinkedHashMap<String, Pattern> patterns = new LinkedHashMap<>(16, 0.75f, true);
    private long observed;
    private boolean observedOnce;
    private volatile boolean closed;
    static final long MAX_RETAINED_BYTES = 32L << 20;
    private long retainedBytes;
    private final java.util.Set<Pending> pending = new java.util.HashSet<>();
    private final java.util.Set<ReplayPlan> plans = new java.util.HashSet<>();

    /** One response decision; an absent future means no replay is authorized. */
    public record Decision(boolean matched, java.util.concurrent.CompletableFuture<ReplayPlan> replay) {}
    /** Releases the template budget once, including rejection, cancellation and shutdown paths. */
    private final class Reservation {
        final int bytes; final java.util.concurrent.atomic.AtomicBoolean released = new java.util.concurrent.atomic.AtomicBoolean();
        Reservation(int bytes) { this.bytes = bytes; retainedBytes += bytes; }
        void release() { if (released.compareAndSet(false, true)) synchronized (SessionRecovery.this) { retainedBytes -= bytes; } }
    }
    /** A single-use production replay plan with final generation/version checks immediately before sending. */
    public final class ReplayPlan implements AutoCloseable {
        private final long originalId;
        private final NativeTagResolver.Resolved resolved;
        private final List<Used> used;
        private final Reservation reservation;
        private final java.util.concurrent.atomic.AtomicBoolean claimed = new java.util.concurrent.atomic.AtomicBoolean(), released = new java.util.concurrent.atomic.AtomicBoolean();
        private ReplayPlan(long originalId, NativeTagResolver.Resolved resolved, List<Used> rules, Reservation reservation) {
            this.originalId = originalId; this.resolved = resolved; this.reservation = reservation;
            var byIdentity = new java.util.HashMap<JourneyDefinition.Identity, JourneyDefinition.Recovery>(); rules.forEach(u -> byIdentity.put(u.identity(), u.rule()));
            this.used = resolved.uses().stream().map(u -> coordinator.provenance(new Used(u.identity(), u.version(), byIdentity.getOrDefault(u.identity(), u.rule())), true)).toList();
        }
        public long originalId() { return originalId; }
        public List<Used> uses() { return used; }
        public void validateForDelivery() throws AuthenticationFailure {
            if (closed || released.get()) throw new AuthenticationFailure(AuthenticationFailure.Phase.LIFECYCLE, AuthenticationFailure.Cause.STALE, "This recovery replay is no longer available.");
            resolved.commit();
        }
        public byte[] claim() throws AuthenticationFailure {
            if (closed || released.get() || !claimed.compareAndSet(false, true)) throw new AuthenticationFailure(AuthenticationFailure.Phase.LIFECYCLE,
                    AuthenticationFailure.Cause.STALE, "This recovery replay is no longer available.");
            return resolved.commit();
        }
        @Override public void close() { if (released.compareAndSet(false, true)) { reservation.release(); synchronized (SessionRecovery.this) { plans.remove(this); } } }
        @Override public String toString() { return "RecoveryReplay[original=" + originalId + "]"; }
    }
    /** Owns only this original's waits; cancellation never cancels another original's shared reauthentication. */
    private final class Pending implements AutoCloseable {
        final long originalId; final Attribution source;
        final java.util.concurrent.CompletableFuture<ReplayPlan> future = new java.util.concurrent.CompletableFuture<>();
        volatile AuthenticationCoordinator.Ticket ticket;
        volatile NativeTagResolver.Operation operation;
        final java.util.concurrent.atomic.AtomicBoolean done = new java.util.concurrent.atomic.AtomicBoolean();
        Pending(long originalId, Attribution source) {
            this.originalId = originalId; this.source = source;
            future.whenComplete((value, error) -> { if (future.isCancelled()) close(); });
        }
        void begin(List<Used> matched) {
            if (closed || done.get()) { close(); return; }
            try {
                ticket = coordinator.recover(matched);
                ticket.future().whenComplete((tokens, error) -> {
                    if (error != null) { fail(error); return; }
                    if (closed || done.get()) { close(); return; }
                    try {
                        operation = source.template().prepare();
                        operation.future().whenComplete((resolved, failure) -> {
                            if (failure != null) { fail(failure); return; }
                            ReplayPlan plan;
                            try { plan = new ReplayPlan(originalId, resolved, source.used(), source.reservation()); }
                            catch (RuntimeException preparation) { fail(preparation); return; }
                            if (!done.compareAndSet(false, true)) { plan.close(); return; }
                            synchronized (SessionRecovery.this) { pending.remove(this); if (!closed) plans.add(plan); }
                            if (closed || !future.complete(plan)) plan.close();
                            releaseWaits();
                        });
                    } catch (AuthenticationFailure | RuntimeException failure) { fail(failure); }
                });
                if (done.get()) releaseWaits();
            } catch (RuntimeException failure) { fail(failure); }
        }
        void releaseWaits() { var t = ticket; if (t != null) t.close(); var op = operation; if (op != null) op.close(); }
        void fail(Throwable error) {
            if (!done.compareAndSet(false, true)) return;
            source.reservation().release(); synchronized (SessionRecovery.this) { pending.remove(this); }
            Throwable cause = error instanceof java.util.concurrent.CompletionException && error.getCause() != null ? error.getCause() : error;
            future.completeExceptionally(cause); releaseWaits();
        }
        @Override public void close() { fail(new AuthenticationFailure(AuthenticationFailure.Phase.LIFECYCLE, AuthenticationFailure.Cause.CANCELLED, "This request's recovery was cancelled.")); }
    }

    /**
     * Creates a request-ID ledger without installing HTTP hooks or reading a body.
     * @param coordinator Version-specific invalidation owner.
     */
    public SessionRecovery(AuthenticationCoordinator coordinator) { this(coordinator, System::nanoTime, (identity, message) -> {}); }
    /**
     * Routes skipped textual-body guidance to the host's safe, rate-limited diagnostics.
     * @param coordinator Version-specific invalidation owner.
     * @param guidance Safe identity and fixed conversion/help text, never response headers or content.
     */
    public SessionRecovery(AuthenticationCoordinator coordinator, BiConsumer<JourneyDefinition.Identity, String> guidance) { this(coordinator, System::nanoTime, guidance); }
    /**
     * Creates bounded request provenance using an injected monotonic expiry clock.
     *
     * @param coordinator Version invalidator.
     * @param nanos Monotonic retention clock for deterministic tests.
     */
    SessionRecovery(AuthenticationCoordinator coordinator, LongSupplier nanos) { this(coordinator, nanos, (identity, message) -> {}); }
    /**
     * Injects retention timing and skipped-body diagnostics without installing host callbacks.
     * @param coordinator Version-specific invalidator.
     * @param nanos Monotonic retention clock.
     * @param guidance Fixed safe text routed to the owning journey.
     */
    SessionRecovery(AuthenticationCoordinator coordinator, LongSupplier nanos, BiConsumer<JourneyDefinition.Identity, String> guidance) {
        this.coordinator = coordinator; this.nanos = nanos; this.guidance = guidance;
    }

    /**
     * Records the exact used generations and versions only after the whole request is committed.
     * @param requestId Global HTTP message ID.
     * @param used Distinct journeys actually inserted; no credential strings.
     * @param internal Whether the guard classifies this as owned authentication traffic.
     */
    public synchronized void record(long requestId, Collection<Used> used, boolean internal) { record(requestId, used, internal, null); }
    /** Retains a bounded pre-injection template only after successful request commit. */
    public synchronized void record(long requestId, Collection<Used> used, boolean internal, NativeTagResolver.ReplayTemplate template) {
        prune(); var previous = records.remove(requestId); if (previous != null) previous.reservation().release();
        if (closed || internal || used.isEmpty()) return;
        int size = template == null ? 0 : template.size();
        if (size > NativeTagParser.MAX_OUTPUT_BYTES || retainedBytes + size > MAX_RETAINED_BYTES) {
            template = null; size = 0;
            try { guidance.accept(used.iterator().next().identity(), "The recovery replay template could not be retained within the request-memory limit."); } catch (RuntimeException ignored) { /* Diagnostics cannot prevent safe provenance retention. */ }
        }
        var captured = used.stream().map(u -> coordinator.provenance(u, u.replay())).toList();
        records.put(requestId, new Attribution(observed, captured, template, new Reservation(size)));
        while (records.size() > MAX_RECORDS) records.pollFirstEntry().getValue().reservation().release();
    }

    /** Matches a response once, authorizes shared recovery, and never replays a replay. */
    public Decision receivedPlan(long requestId, int status, Supplier<Response> details, boolean internal, boolean automaticEnabled) {
        Attribution source;
        synchronized (this) { prune(); source = records.remove(requestId); }
        if (source == null) return new Decision(false, null);
        if (closed || internal) { source.reservation().release(); return new Decision(false, null); }
        var matched = matches(source, status, details);
        if (matched.isEmpty() || !automaticEnabled) { source.reservation().release(); return new Decision(false, null); }
        boolean replay = source.used().stream().anyMatch(Used::replay);
        for (var used : matched) if (used.validationEpisode() != 0 || used.replay()) coordinator.rejectedReplacement(used, status);
        if (replay || matched.stream().anyMatch(u -> u.validationEpisode() != 0)) {
            source.reservation().release(); return new Decision(true, null);
        }
        if (source.template() == null) {
            source.reservation().release();
            // Losing replay capacity must not bypass shared recovery or its persistent pause contract.
            var ticket = coordinator.recover(matched);
            ticket.future().whenComplete((tokens, error) -> ticket.close());
            return new Decision(true, null);
        }
        var work = new Pending(requestId, source);
        synchronized (this) { if (!closed) pending.add(work); }
        work.begin(matched); return new Decision(true, work.future);
    }
    /** Evaluates only captured policies and marks successful observed use separately from extraction. */
    private List<Used> matches(Attribution source, int status, Supplier<Response> details) {
        String text = null; boolean read = false;
        var result = new ArrayList<Used>();
        for (var used : source.used()) {
            var rule = used.rule(); if (!rule.enabled()) { if (status >= 200 && status < 300) coordinator.accepted(used); continue; }
            boolean matched = rule.mode() != JourneyDefinition.RecoveryMode.REGEX && rule.statusCode() == status;
            boolean assessed = rule.mode() == JourneyDefinition.RecoveryMode.STATUS_CODE || matched;
            if (!matched && rule.mode() != JourneyDefinition.RecoveryMode.STATUS_CODE) {
                if (!read) {
                    try { text = boundedText(details.get(), message -> guidance.accept(used.identity(), message)); } catch (RuntimeException ignored) { }
                    read = true;
                }
                if (text != null) try { matched = pattern(rule.pattern()).matcher(text).find(); assessed = true; } catch (AuthenticationFailure ignored) { }
            }
            if (matched) result.add(used);
            else if (assessed && status >= 200 && status < 300) coordinator.accepted(used);
        }
        return result;
    }

    /**
     * Applies each captured rule to its own used token version, leaving the response unchanged.
     * @param requestId Same global ID recorded at request commit.
     * @param response Lazy actual response metadata/body.
     * @param internal Validated internal responses never cause recovery.
     * @return Number of current versions invalidated; no replay of the application request occurs.
     */
    public int received(long requestId, Response response, boolean internal) {
        return received(requestId, response.status(), () -> response, internal);
    }

    /**
     * Defers even host body access and MIME inspection until an attributed enabled regex rule needs them.
     * @param requestId Correlated global request ID.
     * @param status Actual status available without touching body bytes.
     * @param details Lazy body metadata and byte supplier; status-only/unattributed/internal paths never invoke it.
     * @param internal Whether the traffic guard established owned authentication provenance.
     * @return Number of exact used versions invalidated, leaving the response unchanged.
     */
    public int received(long requestId, int status, Supplier<Response> details, boolean internal) {
        Attribution attribution;
        synchronized (this) { prune(); attribution = records.remove(requestId); if (closed || internal || attribution == null) { if (attribution != null) attribution.reservation().release(); return 0; } }
        int invalidated = 0;
        for (var used : matches(attribution, status, details)) if (coordinator.invalidateVersion(used.identity(), used.version())) invalidated++;
        attribution.reservation().release();
        return invalidated;
    }

    /**
     * Validates source and compiled-program bounds with safe position guidance on unsupported syntax.
     * @param source Configured expression, never included in diagnostic output.
     * @return DOTALL/find-style RE2 pattern; callers invoke matcher.find rather than matches.
     * @throws AuthenticationFailure If empty, oversized, unsupported or above 10,000 instructions.
     */
    public static Pattern compile(String source) throws AuthenticationFailure {
        if (source == null || source.isBlank() || source.getBytes(StandardCharsets.UTF_8).length > 4096)
            throw invalidPattern("The recovery expression must contain 1-4096 UTF-8 bytes.");
        try {
            Pattern compiled = Pattern.compile(source, Pattern.DOTALL);
            if (compiled.programSize() > 10_000) throw invalidPattern("The session-detection expression is too complex.");
            return compiled;
        } catch (PatternSyntaxException ex) {
            throw invalidPattern("The recovery expression uses unsupported or invalid RE2 syntax"
                    + (ex.getIndex() >= 0 ? " at position " + ex.getIndex() + "." : "."));
        }
    }

    /**
     * Keeps at most 64 compiled patterns without logging or exporting their potentially sensitive source.
     * @param source Previously validated configured source.
     * @return Compiled bounded RE2 pattern.
     * @throws AuthenticationFailure If the source is invalid despite its configuration boundary.
     */
    private synchronized Pattern pattern(String source) throws AuthenticationFailure {
        Pattern pattern = patterns.get(source); if (pattern != null) return pattern;
        pattern = compile(source); patterns.put(source, pattern); while (patterns.size() > 64) patterns.pollFirstEntry(); return pattern;
    }

    /**
     * Checks actual encoded size/MIME before opening a stream, then caps decoded size independently.
     * @param response Actual response metadata and lazy bytes.
     * @return Strictly decoded supported text, or null when size/type/encoding is unsuitable.
     */
    static String boundedText(Response response) {
        return boundedText(response, message -> {});
    }

    /**
     * Adds fixed conversion guidance for unsupported textual decoding without echoing untrusted headers.
     * @param response Actual MIME/coding/count and lazy bytes.
     * @param guidance Safe conversion/help sink; a broken logger cannot interrupt recovery.
     * @return Supported bounded text, or null after skipping unsuitable content.
     */
    private static String boundedText(Response response, Consumer<String> guidance) {
        Charset charset = charset(response.contentType());
        if (charset == null) {
            if (response.contentType() != null && textualMime(response.contentType().split(";", 2)[0].trim().toLowerCase(Locale.ROOT))) skipped(guidance);
            return null;
        }
        if (response.bodyBytes() < 0 || response.bodyBytes() > MAX_BODY) return null;
        String encoding = response.contentEncoding() == null ? "identity" : response.contentEncoding().trim().toLowerCase(Locale.ROOT);
        if (!List.of("identity", "gzip", "deflate").contains(encoding)) { skipped(guidance); return null; }
        try (InputStream input = response.body().get()) {
            byte[] encoded = input.readNBytes(MAX_BODY + 1); if (encoded.length > MAX_BODY || encoded.length != response.bodyBytes()) return null;
            try (InputStream decoded = switch (encoding) { case "gzip" -> new GZIPInputStream(new ByteArrayInputStream(encoded)); case "deflate" -> new InflaterInputStream(new ByteArrayInputStream(encoded)); default -> new ByteArrayInputStream(encoded); }) {
                byte[] bytes = decoded.readNBytes(MAX_BODY + 1); if (bytes.length > MAX_BODY) return null;
                return charset.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
            }
        } catch (Exception ex) { return null; }
    }

    /**
     * Selects only declared supported textual MIME types and explicit/default UTF-8 text encoding.
     * @param contentType Header value; missing/nontext/unsupported charsets return null.
     * @return UTF-8, ASCII or ISO-8859-1 only; no charset guessing is performed.
     */
    static Charset charset(String contentType) {
        if (contentType == null) return null;
        String[] parts = contentType.split(";"); String mime = parts[0].trim().toLowerCase(Locale.ROOT);
        if (!textualMime(mime)) return null;
        String selected = "utf-8"; boolean found = false;
        for (int i = 1; i < parts.length; i++) {
            String parameter = parts[i].trim(); int eq = parameter.indexOf('=');
            if (eq > 0 && parameter.substring(0, eq).trim().equalsIgnoreCase("charset")) {
                if (found) return null; found = true; selected = parameter.substring(eq + 1).trim();
                if (selected.length() >= 2 && selected.startsWith("\"") && selected.endsWith("\"")) selected = selected.substring(1, selected.length() - 1);
            }
        }
        return switch (selected.toLowerCase(Locale.ROOT)) { case "utf-8", "utf8" -> StandardCharsets.UTF_8; case "us-ascii", "ascii" -> StandardCharsets.US_ASCII; case "iso-8859-1", "iso8859-1" -> StandardCharsets.ISO_8859_1; default -> null; };
    }

    /**
     * Shares the declared-text MIME policy between strict decoding and skipped-charset help.
     * @param mime Lowercase trimmed media type without parameters.
     * @return Whether this is an explicitly supported textual media family.
     */
    private static boolean textualMime(String mime) {
        return mime.startsWith("text/") || mime.equals("application/json") || mime.endsWith("+json") || mime.equals("application/xml") || mime.endsWith("+xml")
                || mime.equals("application/javascript") || mime.equals("application/x-javascript") || mime.equals("application/x-www-form-urlencoded");
    }

    /**
     * Reports the observed decoding failure without guessing its remedy.
     * @param guidance Host-owned safe diagnostic sink.
     */
    private static void skipped(Consumer<String> guidance) { try { guidance.accept("Session detection could not read the response's text encoding or compression."); } catch (RuntimeException ignored) { /* preserve response processing */ } }

    /** Expires old/clock-rollback entries before insertion or response lookup; caller holds the monitor. */
    private void prune() {
        long now = nanos.getAsLong(); if (observedOnce && now - observed < 0) { records.values().forEach(a -> a.reservation().release()); records.clear(); } observed = now; observedOnce = true;
        while (!records.isEmpty() && now - records.firstEntry().getValue().at() >= RETENTION) records.pollFirstEntry().getValue().reservation().release();
    }
    /**
     * Explains a regex constraint or unsupported syntax without echoing pattern or response contents.
     *
     * @param problem Safe regex constraint/position.
     * @return Terminal correction without echoing expression or response data.
     */
    private static AuthenticationFailure invalidPattern(String problem) { return new AuthenticationFailure(AuthenticationFailure.Phase.SETUP, AuthenticationFailure.Cause.CONFIGURATION, problem,
            "Correct the session-detection expression using supported RE2 syntax."); }
    /** Releases all provenance and compiled patterns without invalidating unrelated cached tokens. */
    @Override public void close() {
        List<Pending> active; List<ReplayPlan> issued;
        synchronized (this) {
            closed = true; records.values().forEach(a -> a.reservation().release()); records.clear(); patterns.clear();
            active = List.copyOf(pending); issued = List.copyOf(plans);
        }
        active.forEach(Pending::close); issued.forEach(ReplayPlan::close);
    }
}
