package bpsh.burp.http;

import bpsh.browser.AuthTrafficGuard;
import bpsh.request.RequestSettings;
import bpsh.journey.JourneyCatalog;
import bpsh.authentication.credentials.CredentialUse;
import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.JourneyKey;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.*;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;


/** Shared atomic ordinary/tagged preparation; adapters supply actual origin and delivery policy. */
public final class SessionRequestProcessor {
    private final JourneyCatalog registry;
    private final NativeTagResolver resolver;
    private final AuthTrafficGuard guard;
    private final SessionRecovery recovery;
    private final Diagnostics diagnostics;
    private final AtomicBoolean closed;
    final RequestCapacity capacity = new RequestCapacity();

    /** @param request Complete continuation or failed original. @param annotations Safe notes. @param stop Terminal failure notice, or null for continuation. */
    public record Result(HttpRequest request, Annotations annotations, Diagnostics.Notice stop, burp.api.montoya.http.message.responses.HttpResponse response) {
        /** @param request Outgoing message. @param annotations Host notes. @return Ordinary continuation. */
        static Result continueWith(HttpRequest request, Annotations annotations) { return new Result(request, annotations, null, null); }
    }

    /** Captures matching rules once for either ordinary capture or transport preparation. */
    List<RequestSettings.AutomaticRule> matching(HttpRequest request,RequestRuleMatcher.Context context,RequestControlState.Applied applied) {
        return closed.get() || hasTags(request.toByteArray())?List.of():applied.matcher().automaticRules(request,context);
    }

    /** Wires shared policy owners without registering a host callback. */
    SessionRequestProcessor(JourneyCatalog registry, NativeTagResolver resolver, AuthTrafficGuard guard,
                            SessionRecovery recovery, Diagnostics diagnostics, AtomicBoolean closed) {
        this.registry=registry; this.resolver=resolver; this.guard=guard; this.recovery=recovery; this.diagnostics=diagnostics; this.closed=closed;
    }

    /** @param request Outgoing message. @param notes Host notes. @param context Actual origin. @param applied Captured controls and plan. @return Atomic continuation or required stop. */
    Result process(HttpRequest request, Annotations notes, RequestRuleMatcher.Context context, RequestControlState.Applied applied,List<RequestSettings.AutomaticRule> matching) {
        boolean tagged = false; JourneyCatalog.Entry selected = null;
        var cfg = applied.controls();
        try {
            ByteArray bytes = request.toByteArray(); tagged = hasTags(bytes);
            if (closed.get()) {
                if (tagged) return stopped(request, notes, context.exchange(), null, unavailable());
                return Result.continueWith(request, notes);
            }
            boolean ordinary = !matching.isEmpty();
            if (!tagged && !ordinary) return Result.continueWith(request, notes);
            if (tagged && bytes.length() > NativeTagParser.MAX_OUTPUT_BYTES) return stopped(request, notes, context.exchange(), null, NativeTagParser.syntax("The tagged request exceeds the 4 MiB message ceiling."));
            var automatic = new java.util.ArrayList<NativeTagResolver.Automatic>();
            if (ordinary) {
                var snapshot = registry.snapshot();
                for (var rule : matching) {
                    try { selected = snapshot.resolve(new JourneyKey(rule.journey().scope(), rule.journey().id())); }
                    catch (IllegalStateException ex) { selected = null; throw configuration("An enabled automatic journey is unavailable.", "Review its rule in Session handling."); }
                    automatic.add(new NativeTagResolver.Automatic(selected, rule.recovery()));
                }
                selected = null; // A shared acquisition failure must not blame the last matching rule.
            }
            try (var admitted = capacity.admit(cfg, automatic.stream().map(a -> a.entry().identity().key()).toList(), 4L * bytes.length() + (16L << 20))) {
                int headerEnd = tagged ? bytes.length() : bytes.indexOf("\r\n\r\n") + 4;
                if (!tagged && (headerEnd < 4 || headerEnd > NativeTagParser.MAX_TEXT_BYTES)) throw NativeTagParser.syntax("The request headers are incomplete or oversized.");
                byte[] input = tagged ? bytes.getBytes() : bytes.subArray(0, headerEnd).getBytes();
            try (var operation = resolver.resolveAutomatic(input, automatic, cfg.requestPolicy() == RequestSettings.RequestPolicy.WAIT_FOR_LOGIN)) {
                var resolved = operation.future().get();
                if (!resolved.changed()) return Result.continueWith(request, notes);
                byte[] committed = resolved.commit();
                ByteArray outgoing;
                if (tagged) outgoing = ByteArray.byteArray(committed);
                else {
                    outgoing = ByteArray.byteArrayOfLength(Math.addExact(committed.length, bytes.length() - headerEnd));
                    outgoing.setBytes(0, committed);
                    if (bytes.length() > headerEnd) outgoing.setBytes(committed.length, bytes.subArray(headerEnd, bytes.length()));
                }
                HttpRequest changed = HttpRequest.httpRequest(request.httpService(), outgoing);
                var used = resolved.uses();
                if (tagged && cfg.enabled()) {
                    used = used.stream().map(u -> {
                        return applied.matcher().taggedRecovery(u.identity(), changed, context)
                                .map(policy -> new CredentialUse(u.identity(), u.version(), policy)).orElse(u);
                    }).toList();
                }
                recovery.recordLazy(context.exchange(), used, bytes.length(), () -> resolved.replayTemplate(bytes.getBytes()));
                return Result.continueWith(changed, notes);
            }
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt(); return failed(request, notes, context.exchange(), selected, tagged, new AuthenticationFailure(AuthenticationFailure.Phase.QUEUE, AuthenticationFailure.Cause.CANCELLED,
                    "This request's authentication wait was interrupted.", "Resend the request when ready."));
        } catch (ExecutionException ex) {
            return failed(request, notes, context.exchange(), selected, tagged, ex.getCause() instanceof AuthenticationFailure safe ? safe : unknown());
        } catch (AuthenticationFailure ex) { return failed(request, notes, context.exchange(), selected, tagged, ex); }
        catch (RuntimeException | LinkageError ex) { return failed(request, notes, context.exchange(), selected, tagged, unknown()); }
    }

    /** @param request Original. @param notes Host notes. @param exchange Actual request reference. @param selected Optional journey. @param tagged Whole-request policy. @param error Safe failure. @return Stop or unchanged automatic continuation. */
    Result failed(HttpRequest request, Annotations notes, RequestExchange exchange, JourneyCatalog.Entry selected, boolean tagged, AuthenticationFailure error) {
        if (tagged) return stopped(request, notes, exchange, alias(error, selected), error);
        var notice=diagnostics.request(exchange, alias(error, selected), error, false);
        return Result.continueWith(request, annotate(notes, notice));
    }
    /** @param request Failed original. @param notes Host notes. @param exchange Actual request reference. @param alias Safe journey alias. @param error Safe failure. @return Required stop with diagnostic attribution. */
    Result stopped(HttpRequest request, Annotations notes, RequestExchange exchange, String alias, AuthenticationFailure error) {
        var notice=diagnostics.request(exchange,alias,error,true);
        return new Result(request,annotate(notes,notice),notice,null);
    }
    private String alias(AuthenticationFailure error, JourneyCatalog.Entry selected) {
        if (error.journey() != null) { var entry = registry.snapshot().entries().get(error.journey().key()); if (entry != null) return entry.definition().alias(); }
        return selected == null ? null : selected.definition().alias();
    }
    static Annotations annotate(Annotations original, Diagnostics.Notice notice) {
        String notes = original.notes();
        var result = notes != null && notes.lines().anyMatch(notice.text()::equals) ? original
                : original.withNotes((notes == null || notes.isBlank() ? "" : notes + "\n") + notice.text());
        return notice.dropRequested() ? result.withHighlightColor(HighlightColor.RED) : result;
    }
    AuthTrafficGuard.Decision ownership(HttpRequest request, AuthTrafficGuard.Family family, long id) {
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

    static AuthenticationFailure configuration(String problem, String action) { return new AuthenticationFailure(AuthenticationFailure.Phase.LIFECYCLE, AuthenticationFailure.Cause.CONFIGURATION, problem, action); }
    /**
     * Returns actionable rejection of recursive native tags on owned traffic.
     *
     * @return Actionable rejection of recursive native tags on owned traffic.
     */
    static AuthenticationFailure nested() { return configuration("A login request contains authentication tags.", "Remove authentication tags from the requests made during login."); }
    /**
     * Returns safe unload failure for a still-registered explicit request.
     *
     * @return Safe unload failure for a still-registered explicit request.
     */
    static AuthenticationFailure unavailable() { return new AuthenticationFailure(AuthenticationFailure.Phase.LIFECYCLE, AuthenticationFailure.Cause.CLOSED, "The extension is unloading.", "Reload the extension and resend the tagged request when ready."); }
    /**
     * Returns unknown stays unknown, without logging raw host/selector/credential-bearing exceptions.
     *
     * @return Unknown stays unknown, without logging raw host/selector/credential-bearing exceptions.
     */
    static AuthenticationFailure unknown() { return new AuthenticationFailure(AuthenticationFailure.Phase.LIFECYCLE, AuthenticationFailure.Cause.UNKNOWN, "The request could not be prepared for authentication.", ""); }
    static void appendNote(Annotations notes, String message) {
        synchronized (notes) {
            String current = notes.notes();
            if (current != null && current.lines().anyMatch(message::equals)) return;
            notes.setNotes((current == null || current.isBlank() ? "" : current + "\n") + message);
        }
    }
}
