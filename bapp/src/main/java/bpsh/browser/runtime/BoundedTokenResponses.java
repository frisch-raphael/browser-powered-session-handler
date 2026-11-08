package bpsh.browser.runtime;

import bpsh.authentication.AuthenticationFailure;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.CDPSession;
import com.microsoft.playwright.Page;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Streams matching Chromium responses with a decoded byte ceiling before extraction or Java body retrieval. */
public final class BoundedTokenResponses implements AutoCloseable {
    /** Attempt-local extraction callbacks; runtime has no credential-domain dependency. */
    public interface Capture {
        /** Selects a response URL. */
        boolean matches(String url);
        /** Reports whether all requested credentials are captured. */
        boolean complete();
        /** Validates declared encoded length before opening the stream. */
        void declaredLength(String value) throws AuthenticationFailure;
        /** Consumes bounded decoded bytes. */
        void response(String url, byte[] body, boolean success);
        /** Records safe collection failure. */
        void failure(AuthenticationFailure error);
    }

    /** Maximum decoded token-response bytes. */
    private static final int LIMIT = 1 << 20;
    private final BrowserContext context;
    private final Capture capture;
    private final java.util.List<CDPSession> sessions = new java.util.ArrayList<>();
    private final java.util.function.Consumer<Page> pageListener;
    private boolean closed;

    /** Owns the listeners and protocol sessions until extraction finishes. */
    private BoundedTokenResponses(BrowserContext context, Capture capture) { this.context = context; this.capture = capture; this.pageListener = page -> attach(context, page, capture); }

    /** Installs attempt-owned response interception on initial pages and popups. */
    public static BoundedTokenResponses install(BrowserContext context, Capture extractor) {
        var owner = new BoundedTokenResponses(context, extractor);
        try {
            context.onPage(owner.pageListener);
            context.pages().forEach(owner.pageListener);
            return owner;
        } catch (RuntimeException error) { owner.close(); throw error; }
    }

    /** Revokes callbacks before disabling interception and before the browser context starts closing. */
    @Override public void close() {
        if (closed) return;
        closed = true; context.offPage(pageListener);
        for (var session : java.util.List.copyOf(sessions)) {
            try { session.send("Fetch.disable"); } catch (RuntimeException ignored) { /* page may already be gone */ }
            try { session.send("Network.disable"); } catch (RuntimeException ignored) { /* page may already be gone */ }
            try { session.detach(); } catch (RuntimeException ignored) { /* page may already be gone */ }
        }
        sessions.clear();
    }

    /** Attaches collection to a page and its out-of-process frames. */
    private void attach(BrowserContext context, Page page, Capture extractor) {
        if (closed) return;
        CDPSession cdp = context.newCDPSession(page);
        page.onFrameNavigated(frame -> {
            if (closed || frame == page.mainFrame()) return;
            try { intercept(context.newCDPSession(frame), extractor); }
            catch (com.microsoft.playwright.PlaywrightException ignored) { /* in-process frames share the page session */ }
        });
        intercept(cdp, extractor);
    }

    /** Enables response-stage collection on one page or out-of-process frame target. */
    private void intercept(CDPSession cdp, Capture extractor) {
        sessions.add(cdp);
        serviceWorkerResponses(cdp, extractor);
        cdp.on("Fetch.requestPaused", event -> {
            if (closed) return;
            String id = event.get("requestId").getAsString();
            String url = event.getAsJsonObject("request").get("url").getAsString();
            int status = event.has("responseStatusCode") ? event.get("responseStatusCode").getAsInt() : 0;
            if (!extractor.matches(url) || extractor.complete() || status < 200 || status == 204 || status == 205 || status == 304 || status >= 300 && status < 400) {
                cdp.send("Fetch.continueRequest", params("requestId", id)); return;
            }
            String handle = null;
            try {
                JsonArray headers = event.getAsJsonArray("responseHeaders");
                for (var item : headers) {
                    var header = item.getAsJsonObject();
                    if (header.get("name").getAsString().equalsIgnoreCase("content-length"))
                        extractor.declaredLength(header.get("value").getAsString());
                }
                handle = cdp.send("Fetch.takeResponseBodyAsStream", params("requestId", id)).get("stream").getAsString();
                var bytes = new ByteArrayOutputStream();
                while (true) {
                    var read = params("handle", handle); read.addProperty("size", Math.min(32768, LIMIT + 1 - bytes.size()));
                    var chunk = cdp.send("IO.read", read);
                    byte[] data = chunk.has("base64Encoded") && chunk.get("base64Encoded").getAsBoolean()
                            ? Base64.getDecoder().decode(chunk.get("data").getAsString())
                            : chunk.get("data").getAsString().getBytes(StandardCharsets.UTF_8);
                    if (data.length > LIMIT - bytes.size()) throw oversized();
                    bytes.writeBytes(data);
                    if (chunk.has("eof") && chunk.get("eof").getAsBoolean()) break;
                }
                byte[] body = bytes.toByteArray();
                extractor.response(url, body, status >= 200 && status < 300);
                var fulfill = params("requestId", id); fulfill.addProperty("responseCode", status);
                var copiedHeaders = new JsonArray();
                for (var item : headers) {
                    String name = item.getAsJsonObject().get("name").getAsString();
                    if (!name.equalsIgnoreCase("content-length") && !name.equalsIgnoreCase("content-encoding") && !name.equalsIgnoreCase("transfer-encoding")) copiedHeaders.add(item);
                }
                fulfill.add("responseHeaders", copiedHeaders); fulfill.addProperty("body", Base64.getEncoder().encodeToString(body));
                cdp.send("Fetch.fulfillRequest", fulfill);
            } catch (AuthenticationFailure error) {
                extractor.failure(error); abort(cdp, id);
            } catch (RuntimeException error) {
                extractor.failure(new AuthenticationFailure(AuthenticationFailure.Phase.EXTRACTION, AuthenticationFailure.Cause.EXTRACTION,
                        "The token response could not be read within the extraction limit."));
                abort(cdp, id);
            } finally {
                if (handle != null) try { cdp.send("IO.close", params("handle", handle)); } catch (RuntimeException ignored) { /* context may be closed */ }
            }
        });
        var options = new JsonObject(); var patterns = new JsonArray(); var pattern = new JsonObject();
        pattern.addProperty("urlPattern", "*"); pattern.addProperty("requestStage", "Response"); patterns.add(pattern); options.add("patterns", patterns);
        cdp.send("Fetch.enable", options);
    }

    /** Streams service-worker responses, which bypass response-stage Fetch interception. */
    private void serviceWorkerResponses(CDPSession cdp, Capture capture) {
        var streams = new java.util.HashMap<String, WorkerBody>();
        var network = new JsonObject(); network.addProperty("maxResourceBufferSize", LIMIT);
        network.addProperty("maxTotalBufferSize", LIMIT * 4); cdp.send("Network.enable", network);
        cdp.on("Network.responseReceived", event -> {
            if (closed) return;
            var response = event.getAsJsonObject("response"); String url = response.get("url").getAsString();
            if (!response.has("fromServiceWorker") || !response.get("fromServiceWorker").getAsBoolean() || !capture.matches(url) || capture.complete()) return;
            String id = event.get("requestId").getAsString();
            if (streams.size() >= 4) { capture.failure(new AuthenticationFailure(AuthenticationFailure.Phase.EXTRACTION,
                    AuthenticationFailure.Cause.CAPACITY, "Too many token responses are arriving at once.")); return; }
            var body = new WorkerBody(url, response.get("status").getAsInt()); streams.put(id, body);
            try {
                var streamed = cdp.send("Network.streamResourceContent", params("requestId", id));
                byte[] buffered = Base64.getDecoder().decode(streamed.get("bufferedData").getAsString());
                byte[] pending = body.bytes.toByteArray(); body.bytes.reset(); body.append(buffered); body.append(pending);
                body.initializing = false;
                if (body.finished && streams.remove(id) != null) capture.response(body.url, body.bytes.toByteArray(), body.status >= 200 && body.status < 300);
            } catch (AuthenticationFailure | RuntimeException error) {
                streams.remove(id); capture.failure(error instanceof AuthenticationFailure safe ? safe : new AuthenticationFailure(
                        AuthenticationFailure.Phase.EXTRACTION, AuthenticationFailure.Cause.EXTRACTION,
                        "The service-worker token response could not be streamed within the extraction limit."));
            }
        });
        cdp.on("Network.dataReceived", event -> {
            if (closed) return;
            var body = streams.get(event.get("requestId").getAsString());
            if (body == null) return;
            try {
                body.observed += event.get("dataLength").getAsLong();
                if (body.observed > LIMIT) throw oversized();
                if (event.has("data")) body.append(Base64.getDecoder().decode(event.get("data").getAsString()));
            }
            catch (AuthenticationFailure error) {
                streams.clear(); capture.failure(error); cdp.send("Network.disable");
            }
        });
        cdp.on("Network.loadingFinished", event -> {
            if (closed) return;
            String id = event.get("requestId").getAsString(); var body = streams.get(id);
            if (body != null && body.initializing) { body.finished = true; return; }
            streams.remove(id);
            if (body != null) capture.response(body.url, body.bytes.toByteArray(), body.status >= 200 && body.status < 300);
        });
        cdp.on("Network.loadingFailed", event -> streams.remove(event.get("requestId").getAsString()));
    }

    /** One bounded decoded service-worker response. */
    private static final class WorkerBody {
        long observed;
        boolean initializing = true, finished;
        final String url;
        final int status;
        final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        WorkerBody(String url, int status) { this.url = url; this.status = status; }
        void append(byte[] data) throws AuthenticationFailure { if (data.length > LIMIT - bytes.size()) throw oversized(); bytes.writeBytes(data); }
    }

    /** Stops an oversized or unreadable intercepted response. */
    private static void abort(CDPSession cdp, String id) {
        try { var options = params("requestId", id); options.addProperty("errorReason", "Aborted"); cdp.send("Fetch.failRequest", options); }
        catch (RuntimeException ignored) { /* closing contexts already stop delivery */ }
    }
    /** Builds a bounded CDP command argument. */
    private static JsonObject params(String name, String value) { var result = new JsonObject(); result.addProperty(name, value); return result; }
    /** Returns redacted size-limit guidance. */
    private static AuthenticationFailure oversized() { return new AuthenticationFailure(AuthenticationFailure.Phase.EXTRACTION,
            AuthenticationFailure.Cause.EXTRACTION, "The matching response exceeds the extraction limit.", "Keep token responses within 1 MiB."); }
}
