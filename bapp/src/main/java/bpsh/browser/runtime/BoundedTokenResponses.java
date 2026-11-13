package bpsh.browser.runtime;

import bpsh.authentication.AuthenticationFailure;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.CDPSession;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Streams matching Chromium responses with a decoded byte ceiling before extraction or Java body retrieval. */
public final class BoundedTokenResponses implements AutoCloseable {
    /** Attempt-local extraction callbacks; runtime has no credential-domain dependency. */
    public interface Capture {
        /** Selects a response URL. */
        boolean matches(String url);
        /** Observes broad origin-only capture without changing the browser's ordinary response delivery. */
        default boolean passive(String url) { return false; }

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
    private final ResponseCollection<ObservedKey> observed;
    private final java.util.List<CDPSession> sessions = new java.util.ArrayList<>();
    private EarlyBrowserTargets targets;
    private boolean closed;

    /** Owns the listeners and protocol sessions until extraction finishes. */
    private BoundedTokenResponses(BrowserContext context, Capture capture) { this.context = context; this.capture = capture; this.observed = new ResponseCollection<>(capture); }

    /** Installs attempt-owned response interception on initial pages and popups. */
    public static BoundedTokenResponses install(BrowserContext context, Capture extractor) {
        var owner = new BoundedTokenResponses(context, extractor);
        try {
            owner.targets = new EarlyBrowserTargets(context, session -> owner.intercept(session, extractor));
            return owner;
        } catch (RuntimeException error) { owner.close(); throw error; }
    }

    /** Revokes callbacks before disabling interception and before the browser context starts closing. */
    @Override public void close() {
        if (closed) return;
        closed = true; observed.clear();
        for (var session : java.util.List.copyOf(sessions)) {
            try { session.send("Fetch.disable"); } catch (RuntimeException ignored) { /* page may already be gone */ }
            try { session.send("Network.disable"); } catch (RuntimeException ignored) { /* page may already be gone */ }
            try { session.detach(); } catch (RuntimeException ignored) { /* page may already be gone */ }
        }
        sessions.clear(); if (targets != null) targets.close();
    }

    /** Enables response-stage collection on one page or out-of-process frame target. */
    private void intercept(CDPSession cdp, Capture extractor) {
        sessions.add(cdp);
        observeResponses(cdp, extractor);
        cdp.on("Fetch.requestPaused", event -> {
            if (closed) return;
            String id = event.get("requestId").getAsString();
            String url = event.getAsJsonObject("request").get("url").getAsString();
            int status = event.has("responseStatusCode") ? event.get("responseStatusCode").getAsInt() : 0;
            if (!extractor.matches(url) || extractor.passive(url) || extractor.complete() || status < 200 || status == 204 || status == 205 || status == 304 || status >= 300 && status < 400) {
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

    /** Identifies one request inside its actual target session, including out-of-process frames. */
    private record ObservedKey(CDPSession session,String id) {}

    /** Streams broad selectors and service-worker responses without modifying browser delivery. */
    private void observeResponses(CDPSession cdp, Capture capture) {
        var network = new JsonObject(); network.addProperty("maxResourceBufferSize", LIMIT);
        network.addProperty("maxTotalBufferSize", LIMIT * 4); cdp.send("Network.enable", network);
        // Register broad streams before response completion; Chromium refuses streaming an already finished body.
        cdp.on("Network.requestWillBeSent",event->{
            if(closed || capture.complete())return;
            var key=new ObservedKey(cdp,event.get("requestId").getAsString());
            String url=event.getAsJsonObject("request").get("url").getAsString();
            var previous=observed.get(key);
            if(previous!=null && event.has("redirectResponse")) {observed.retire(key,previous);previous=null;}
            if(previous==null && capture.matches(url) && capture.passive(url))startObserved(key,url,0,false,capture);
        });
        cdp.on("Network.responseReceived", event -> {
            if (closed || capture.complete()) return;
            var response = event.getAsJsonObject("response"); String url = response.get("url").getAsString();
            boolean worker=response.has("fromServiceWorker") && response.get("fromServiceWorker").getAsBoolean();
            if ((!worker && !capture.passive(url)) || !capture.matches(url)) return;
            var key=new ObservedKey(cdp,event.get("requestId").getAsString());var body=observed.get(key);
            int status=response.get("status").getAsInt();
            if(status<200 || status==204 || status==205 || status==304 || status>=300 && status<400) {
                if(body!=null)observed.retire(key,body);return;
            }
            try {
                if(response.has("headers"))for(var header:response.getAsJsonObject("headers").entrySet())
                    if(header.getKey().equalsIgnoreCase("content-length"))capture.declaredLength(header.getValue().getAsString());
            } catch(AuthenticationFailure failure) {if(body!=null)observed.retire(key,body);capture.failure(failure);return;}
            boolean cached=response.has("fromDiskCache") && response.get("fromDiskCache").getAsBoolean()
                    || response.has("fromPrefetchCache") && response.get("fromPrefetchCache").getAsBoolean();
            if(body==null) {startObserved(key,url,status,cached,capture);body=observed.get(key);}
            if(body!=null) {body.status=status;body.cached|=cached;}
        });
        cdp.on("Network.dataReceived", event -> {
            if (closed || capture.complete()) {observed.clear();return;}
            var key=new ObservedKey(cdp,event.get("requestId").getAsString());var body=observed.get(key);
            if(body==null)return;
            try {
                long length=event.get("dataLength").getAsLong();
                if(length<0 || length>LIMIT-body.received)throw oversized();
                body.received+=length;
                if(event.has("data"))observed.append(key,body,decode(event.get("data").getAsString()));
            } catch(AuthenticationFailure failure) {observed.retire(key,body);capture.failure(failure);}
        });
        cdp.on("Network.loadingFinished", event -> {
            if(closed)return;
            var key=new ObservedKey(cdp,event.get("requestId").getAsString());var body=observed.get(key);
            if(body==null)return;
            body.finished=true;if(!body.initializing)publishObserved(key,body,capture);
        });
        cdp.on("Network.requestServedFromCache",event->{
            var key=new ObservedKey(cdp,event.get("requestId").getAsString());var body=observed.get(key);if(body!=null)body.cached=true;
        });
        cdp.on("Network.loadingFailed",event->{
            var key=new ObservedKey(cdp,event.get("requestId").getAsString());var body=observed.get(key);if(body!=null)observed.retire(key,body);
        });
    }
    /** Retrieves only a positively completed response with exact observed decoded byte evidence. */
    static byte[] completedWorkerBody(CDPSession session,String id,long received) throws AuthenticationFailure {
        if(received<=0 || received>LIMIT)throw workerReadFailure();
        byte[] bytes=decodeFinished(session.send("Network.getResponseBody",params("requestId",id)));
        if(bytes.length!=received)throw workerReadFailure();
        return bytes;
    }
    private static AuthenticationFailure workerReadFailure(){return new AuthenticationFailure(AuthenticationFailure.Phase.EXTRACTION,
            AuthenticationFailure.Cause.EXTRACTION,"The service-worker token response could not be streamed within the extraction limit.");}

    /** Starts one bounded stream and rejects reentrant results after its collection has been evicted. */
    private void startObserved(ObservedKey key,String url,int status,boolean cached,Capture capture) {
        var body=new ObservedBody(url,status);body.cached=cached;observed.start(key,body);
        try {
            var result=key.session().send("Network.streamResourceContent",params("requestId",key.id()));
            if(closed || observed.get(key)!=body)return;
            observed.prepend(key,body,decode(result.get("bufferedData").getAsString()));
            body.initializing=false;if(body.finished)publishObserved(key,body,capture);
        } catch(AuthenticationFailure|RuntimeException error) {
            // Owned target channels deliberately discard vendor messages. A later
            // completion with measured bytes is the independent authorization for
            // bounded retrieval; the stream error alone never authorizes a read.
            if(error instanceof RuntimeException && observed.get(key)==body) {
                body.completedFallback=true;body.initializing=false;if(body.finished)publishObserved(key,body,capture);return;
            }
            if(observed.retire(key,body)==null)return;
            if(error instanceof AuthenticationFailure safe)capture.failure(safe);
        }
    }
    /** Retires accounting before handing an independently bounded result to extraction. */
    private void publishObserved(ObservedKey key,ObservedBody body,Capture capture) {
        if(closed || observed.get(key)!=body)return;
        if(body.completedFallback) {
            try {
                // A finished, uncached, non-range response has a measured decoded size; headers alone never authorize this read.
                if(!body.finished || body.cached || body.status==206 || body.received<=0 || body.received>LIMIT)throw oversized();
                byte[] bytes=completedWorkerBody(key.session(),key.id(),body.received);
                if(closed || observed.get(key)!=body)return;
                observed.replace(key,body,bytes);
            } catch(AuthenticationFailure|RuntimeException error) {
                if(observed.retire(key,body)!=null)capture.failure(error instanceof AuthenticationFailure safe?safe:new AuthenticationFailure(
                        AuthenticationFailure.Phase.EXTRACTION,AuthenticationFailure.Cause.EXTRACTION,
                        "The completed token response could not be read within the extraction limit."));return;
            }
        }
        if(observed.retire(key,body)!=null && body.status>=200)capture.response(body.url,body.bytes.toByteArray(),body.status<300);
    }
    /** Encodes only an already size-qualified body into a fixed-capacity UTF-8 buffer. */
    static byte[] decodeFinished(JsonObject reply) throws AuthenticationFailure {
        String text=reply.get("body").getAsString();
        if(reply.has("base64Encoded") && reply.get("base64Encoded").getAsBoolean())return decode(text);
        if(text.length()>LIMIT)throw oversized();
        var output=java.nio.ByteBuffer.allocate(LIMIT);
        var encoder=StandardCharsets.UTF_8.newEncoder();var state=encoder.encode(java.nio.CharBuffer.wrap(text),output,true);
        if(state.isError() || state.isOverflow())throw oversized();
        state=encoder.flush(output);if(state.isError() || state.isOverflow())throw oversized();
        return java.util.Arrays.copyOf(output.array(),output.position());
    }
    /** Checks encoded size before allocating the decoded protocol buffer. */
    private static byte[] decode(String encoded) throws AuthenticationFailure {
        if(encoded.length()>4*((LIMIT+2)/3))throw oversized();return Base64.getDecoder().decode(encoded);
    }
    /** One bounded passive response; excess collection never interrupts browser delivery. */
    static final class ObservedBody {
        long received;boolean initializing=true,finished,completedFallback,cached;
        final String url;int status;ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        ObservedBody(String url,int status){this.url=url;this.status=status;}
    }
    /** Shares four MiB of collected payload across at most 128 active response records in one context. */
    static final class ResponseCollection<K> {
        private static final int MAX_RECORDS=128,MAX_BYTES=LIMIT*4;
        final java.util.LinkedHashMap<K,ObservedBody> streams=new java.util.LinkedHashMap<>();
        final Capture capture;int retained;
        ResponseCollection(Capture capture){this.capture=capture;}
        ObservedBody get(K key){return streams.get(key);}
        void start(K key,ObservedBody body) {
            var old=get(key);if(old!=null)retire(key,old);
            if(streams.size()==MAX_RECORDS)evict(null);
            streams.put(key,body);
        }
        ObservedBody retire(K key,ObservedBody expected) {
            if(expected==null || streams.get(key)!=expected)return null;
            streams.remove(key);retained-=expected.bytes.size();return expected;
        }
        void clear(){streams.clear();retained=0;}
        void append(K key,ObservedBody body,byte[] bytes) throws AuthenticationFailure {
            if(get(key)!=body)return;reserve(body,bytes.length);body.bytes.writeBytes(bytes);retained+=bytes.length;
        }
        void replace(K key,ObservedBody body,byte[] bytes) throws AuthenticationFailure {
            if(get(key)!=body)return;
            if(bytes.length>LIMIT)throw oversized();retained-=body.bytes.size();body.bytes=new ByteArrayOutputStream();append(key,body,bytes);
        }
        void prepend(K key,ObservedBody body,byte[] bytes) throws AuthenticationFailure {
            if(get(key)!=body)return;reserve(body,bytes.length);
            var merged=new ByteArrayOutputStream(bytes.length+body.bytes.size());merged.writeBytes(bytes);
            try{body.bytes.writeTo(merged);}catch(java.io.IOException impossible){throw new java.io.UncheckedIOException(impossible);}
            body.bytes=merged;retained+=bytes.length;
        }
        private void reserve(ObservedBody body,int bytes) throws AuthenticationFailure {
            if(bytes>LIMIT-body.bytes.size())throw oversized();
            while(retained+bytes>MAX_BYTES)evict(body);
        }
        private void evict(ObservedBody keep) {
            var victim=streams.entrySet().stream().filter(entry->entry.getValue()!=keep).findFirst().orElseThrow();
            retire(victim.getKey(),victim.getValue());victim.getValue().bytes=new ByteArrayOutputStream();
            capture.failure(new AuthenticationFailure(AuthenticationFailure.Phase.EXTRACTION,AuthenticationFailure.Cause.CAPACITY,
                    "Response capture reached its shared collection budget.","Narrow the response path if the expected credential is not captured."));
        }
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
