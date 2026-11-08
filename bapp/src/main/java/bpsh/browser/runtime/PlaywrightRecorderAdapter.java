package bpsh.browser.runtime;

import bpsh.journey.JourneyRecording;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Frame;
import com.microsoft.playwright.options.BindingCallback;
import com.microsoft.playwright.impl.Transport;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.function.IntSupplier;

/** Isolates the pinned Java 1.64.0 / driver 1.64.1 private recorder protocol on its owning worker. */
public final class PlaywrightRecorderAdapter implements AutoCloseable {
    public static final String SOURCE_BINDING = "__bpshRecordingSource";
    /** Safe completion metadata contains neither selectors nor entered values. */
    public record MetadataStatus(boolean available, boolean failed, int pending, boolean degraded, String documentId) {}

    /** Installs metadata before navigation, retaining Playwright as the sole action detector. */
    public static void installMetadata(BrowserContext context, BindingCallback source) {
        context.exposeBinding(SOURCE_BINDING, source); context.addInitScript(metadataScript());
    }

    /** @return The maintained source resource with the shared bounded recording constants applied. */
    public static String metadataScript() {
        try (var input = PlaywrightRecorderAdapter.class.getResourceAsStream("/bpsh/browser/recorder-action-metadata.js")) {
            if (input == null) throw incompatible(); byte[] bytes = input.readNBytes(64 * 1024 + 1);
            if (bytes.length > 64 * 1024) throw incompatible(); String script = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
            String marker = "__BPSH_LIMITS__";
            if (script.indexOf(marker) < 0 || script.indexOf(marker) != script.lastIndexOf(marker)) throw incompatible();
            var limits = new JsonObject(); limits.addProperty("nodes", JourneyRecording.Limits.METADATA_NODES);
            limits.addProperty("fields", JourneyRecording.Limits.METADATA_FIELDS); limits.addProperty("records", JourneyRecording.Limits.METADATA_RECORDS);
            limits.addProperty("pending", JourneyRecording.Limits.QUEUED_EVENTS); limits.addProperty("stop", JourneyRecording.Limits.STOP_MS);
            return script.replace(marker, limits.toString());
        } catch (IOException error) { throw incompatible(); }
    }

    /** Reads or drains live-document calls without an acknowledgment protocol for an old document. */
    public static MetadataStatus metadataStatus(Frame frame, boolean drain) {
        return metadataStatus(frame, drain, JourneyRecording.Limits.STOP_MS);
    }
    /** Uses only the remaining Stop budget for a live document. */
    public static MetadataStatus metadataStatus(Frame frame, boolean drain, double timeoutMs) {
        Object value = frame.evaluate(drain
                ? "async timeout => window.__bpshRecorderMetadata ? await window.__bpshRecorderMetadata.drain(timeout) : null"
                : "() => window.__bpshRecorderMetadata ? window.__bpshRecorderMetadata.status() : null", timeoutMs);
        if (!(value instanceof java.util.Map<?, ?> data)) return new MetadataStatus(false, false, 0, true, "");
        if (!(data.get("failed") instanceof Boolean failed) || !(data.get("degraded") instanceof Boolean degraded)
                || !(data.get("pending") instanceof Number pending) || pending.intValue() < 0 || pending.intValue() > JourneyRecording.Limits.QUEUED_EVENTS * 2
                || !(data.get("documentId") instanceof String document) || !document.matches("[A-Za-z0-9_-]{1,128}")) throw incompatible();
        return new MetadataStatus(true, failed, pending.intValue(), degraded, document);
    }
    /** Native action lifecycle; generated code and snapshots never enter these records. */
    public enum Kind { ADDED, UPDATED, SIGNAL }
    public enum Classification { ORDINARY, SECRET, UNKNOWN }
    /** Metadata carries identity only, never a field's value. */
    public record Metadata(String sourceKey, String documentId, String fieldId, Classification classification) {}
    /** Adopts a fill buffer, returns independent copies and wipes its owned buffer on close. */
    public record Action(String name, String selector, List<String> options, String key, int modifiers, String button,
            int clickCount, boolean position, String url, String popupPageGuid, Metadata metadata, char[] value) implements AutoCloseable {
        public Action { options = List.copyOf(options); }
        @Override public char[] value() { return value == null ? null : value.clone(); }
        @Override public void close() { if (value != null) Arrays.fill(value, '\0'); }
        @Override public String toString() { return "RecorderAction[name=" + name + "]"; }
    }
    /** One bounded event retains only supported structured fields. */
    public record Event(Kind kind, String pageGuid, Action action, int bytes) implements AutoCloseable {
        @Override public void close() { action.close(); }
        @Override public String toString() { return "RecorderEvent[kind=" + kind + ", action=" + action.name() + "]"; }
    }

    /** Preserves every ordinary response/event while intercepting only the owned recorder channel. */
    static final class Tap implements Transport {
        private final Transport pipe;
        private PlaywrightRecorderAdapter active;
        Tap(Transport pipe) { this.pipe = pipe; }
        void releaseRecorder() { if (active != null) active.close(); }
        @Override public void send(JsonObject message) { pipe.send(message); }
        @Override public JsonObject poll(Duration timeout) {
            JsonObject message = pipe.poll(timeout);
            if (message != null && message.has("method") && message.get("method").isJsonPrimitive()
                    && "recorderEvent".equals(message.get("method").getAsString())) {
                JsonObject params = message.has("params") && message.get("params").isJsonObject() ? message.getAsJsonObject("params") : null;
                if (params != null) {
                    params.remove("code");
                    if (params.has("data") && params.get("data").isJsonObject()) {
                        params.getAsJsonObject("data").remove("ariaSnapshot"); params.getAsJsonObject("data").remove("ref");
                    }
                }
                if (active != null && active.contextGuid.equals(stringOrEmpty(message, "guid"))) active.receive(params);
                // Playwright Java does not consume recorder data. Drop value-bearing private data before its dispatch/logging.
                if (params != null) params.remove("data");
            }
            return message;
        }
        @Override public void close() throws IOException { pipe.close(); }
    }

    private static final Set<String> ACTIONS = Set.of("fill", "click", "check", "uncheck", "select", "press", "openPage", "closePage", "navigate");
    private static final Set<String> FIELDS = Set.of("name", "selector", "text", "options", "key", "modifiers", "button", "clickCount", "position", "url", "popupPageGuid",
            "bpshSourceActionId", "bpshClassification", "bpshDocumentId", "bpshFieldId");
    private final Thread owner = Thread.currentThread();
    private final Object connection;
    private final Method send;
    private final Tap tap;
    private final String contextGuid;
    private final ArrayDeque<Event> events = new ArrayDeque<>();
    private IntSupplier retainedBudget = () -> JourneyRecording.Limits.RETAINED_BYTES;
    private int queuedBytes;
    private String failure;
    private boolean accepting, closed;

    PlaywrightRecorderAdapter(Object connection, Tap tap, BrowserContext context) {
        this.connection = connection; this.tap = tap;
        try {
            if (tap.active != null) throw incompatible();
            Class<?> channel = Class.forName("com.microsoft.playwright.impl.ChannelOwner", true, Page.class.getClassLoader());
            Field field = channel.getDeclaredField("connection"); field.setAccessible(true);
            if (field.get(context) != connection) throw incompatible();
            contextGuid = guid(context);
            send = connection.getClass().getMethod("sendMessage", String.class, String.class, JsonObject.class, Double.class);
            var version = new Properties();
            try (var input = Page.class.getResourceAsStream("/META-INF/maven/com.microsoft.playwright/playwright/pom.properties")) {
                if (input == null) throw incompatible(); version.load(input);
            }
            if (!"1.64.0".equals(version.getProperty("version"))) throw incompatible();
            tap.active = this;
        } catch (ReflectiveOperationException | IOException error) { throw incompatible(); }
    }

    /** Rejects an unexpected bundled driver before invoking its private recording commands. */
    static void verifyDriver(BrowserRuntimeManager.Ready ready) {
        var file = ready.driverEntryPoint().getParent().resolve("package.json");
        try {
            if (java.nio.file.Files.size(file) > 64 * 1024) throw incompatible();
            var node = com.google.gson.JsonParser.parseString(java.nio.file.Files.readString(file));
            if (!node.isJsonObject() || !"1.64.1".equals(stringOrEmpty(node.getAsJsonObject(), "version"))) throw incompatible();
        } catch (IOException | com.google.gson.JsonParseException error) { throw incompatible(); }
    }

    /** @return Driver identity for an actual owned page, never a URL or positional page index. */
    public static String pageGuid(Page page) { return guid(page); }

    private static String guid(Object channelOwner) {
        try {
            var type = Class.forName("com.microsoft.playwright.impl.ChannelOwner", true, Page.class.getClassLoader());
            Field field = type.getDeclaredField("guid"); field.setAccessible(true); return (String) field.get(channelOwner);
        } catch (ReflectiveOperationException | ClassCastException error) { throw incompatible(); }
    }

    /** Shares the retained-data cap with the compiler without crossing worker threads. */
    public void retainedBudget(IntSupplier remaining) { owner(); retainedBudget = java.util.Objects.requireNonNull(remaining); }
    public void start(double timeoutMs) { owner(); accepting = true; command("startRecording", timeoutMs); }
    /** Command response follows delivery of the recorder's buffered actions. */
    public void stop(double timeoutMs) { owner(); try { command("stopRecording", timeoutMs); } finally { accepting = false; } }
    public Event poll() { owner(); Event event = events.pollFirst(); if (event != null) queuedBytes -= event.bytes(); return event; }
    public String failure() { owner(); return failure; }

    private void command(String method, double timeoutMs) {
        try { send.invoke(connection, contextGuid, method, new JsonObject(), timeoutMs); }
        catch (ReflectiveOperationException error) { failure = "The browser recording command did not complete. Record the login again."; throw new IllegalStateException(failure); }
    }

    private void receive(JsonObject params) {
        if (!accepting || failure != null) return;
        Event event = null;
        try {
            event = decode(params);
            if (events.size() == JourneyRecording.Limits.QUEUED_EVENTS || queuedBytes + event.bytes() > retainedBudget.getAsInt())
                throw new IllegalArgumentException();
            events.addLast(event); queuedBytes += event.bytes(); event = null;
        } catch (RuntimeException error) {
            if (event != null) event.close(); failure = "The recording received unsupported or excessive browser data. Record the login again.";
            events.forEach(Event::close); events.clear(); queuedBytes = 0;
        }
    }

    /** Strict bounded decoder used by the live tap and deterministic protocol qualification. */
    static Event decode(JsonObject params) {
        if (params == null) throw incompatible();
        Kind kind = switch (required(params, "event", 32)) {
            case "actionAdded" -> Kind.ADDED; case "actionUpdated" -> Kind.UPDATED; case "signalAdded" -> Kind.SIGNAL; default -> throw incompatible();
        };
        JsonObject page = object(params.get("page")); String pageGuid = required(page, "guid", 128);
        JsonObject data = object(params.get("data")); String name = required(data, "name", 64);
        if (!name.matches("[A-Za-z][A-Za-z0-9_]{0,63}")) throw incompatible();
        var normalized = new JsonObject();
        for (var entry : data.entrySet()) {
            if (Set.of("ariaSnapshot", "ref").contains(entry.getKey())) continue;
            if (!FIELDS.contains(entry.getKey())) { if (ACTIONS.contains(name)) throw incompatible(); continue; }
            normalized.add(entry.getKey(), entry.getValue());
        }
        String selector = optional(data, "selector", JourneyRecording.Limits.SELECTOR_BYTES);
        if (Set.of("fill", "click", "check", "uncheck", "select", "press").contains(name) && (selector == null || selector.isBlank())) throw incompatible();
        List<String> options = new ArrayList<>();
        if (name.equals("select")) {
            if (!data.has("options") || !data.get("options").isJsonArray()) throw incompatible();
            for (var option : data.getAsJsonArray("options")) {
                if (options.size() == JourneyRecording.Limits.OPTIONS || !option.isJsonPrimitive() || !option.getAsJsonPrimitive().isString()) throw incompatible();
                if (utf8Length(option.getAsString()) > JourneyRecording.Limits.EVENT_BYTES) throw incompatible();
                options.add(option.getAsString());
            }
        }
        String value = name.equals("fill") ? required(data, "text", JourneyRecording.Limits.FILL_BYTES) : null;
        String key = name.equals("press") ? required(data, "key", 64) : "";
        int modifiers = integer(data, "modifiers", 0), clickCount = integer(data, "clickCount", 1);
        String button = data.has("button") ? required(data, "button", 32) : "left";
        String url = optional(data, "url", JourneyRecording.Limits.FILL_BYTES);
        String popup = optional(data, "popupPageGuid", 128);
        Classification classification = switch (stringOrEmpty(data, "bpshClassification")) {
            case "ordinary" -> Classification.ORDINARY; case "secret" -> Classification.SECRET; default -> Classification.UNKNOWN;
        };
        var metadata = new Metadata(identity(data, "bpshSourceActionId"), identity(data, "bpshDocumentId"), identity(data, "bpshFieldId"), classification);
        normalized.addProperty("bpshSourceActionId", metadata.sourceKey()); normalized.addProperty("bpshDocumentId", metadata.documentId());
        normalized.addProperty("bpshFieldId", metadata.fieldId()); normalized.addProperty("bpshClassification", classification.name());
        if (data.has("position")) normalized.addProperty("position", !data.get("position").isJsonNull());
        int bytes = utf8Length(normalized.toString()) + pageGuid.length() + 64;
        if (bytes > JourneyRecording.Limits.EVENT_BYTES) throw incompatible();
        return new Event(kind, pageGuid, new Action(name, selector, options, key, modifiers, button, clickCount,
                data.has("position") && !data.get("position").isJsonNull(), url, popup, metadata, value == null ? null : value.toCharArray()), bytes);
    }

    private static String identity(JsonObject data, String key) {
        String value = stringOrEmpty(data, key); return value.matches("[A-Za-z0-9_-]{1,128}") ? value : "";
    }
    private static JsonObject object(JsonElement node) { if (node == null || !node.isJsonObject()) throw incompatible(); return node.getAsJsonObject(); }
    private static int integer(JsonObject node, String key, int fallback) {
        if (!node.has(key)) return fallback;
        var value = node.get(key);
        if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isNumber() || !value.getAsString().matches("[0-9]{1,8}")) throw incompatible();
        return value.getAsInt();
    }
    private static String stringOrEmpty(JsonObject node, String key) {
        JsonElement value = node.get(key); return value != null && value.isJsonPrimitive() && value.getAsJsonPrimitive().isString() ? value.getAsString() : "";
    }
    private static String optional(JsonObject node, String key, int max) { return node.has(key) ? required(node, key, max) : null; }
    private static String required(JsonObject node, String key, int max) {
        JsonElement value = node.get(key);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) throw incompatible();
        String text = value.getAsString(); if (utf8Length(text) > max) throw incompatible(); return text;
    }
    /** Counts UTF-8 bytes without allocating another copy of an entered value. */
    static int utf8Length(String text) {
        return JourneyRecording.Limits.utf8Length(text);
    }
    public int queuedBytes() { owner(); return queuedBytes; }
    private void owner() { if (Thread.currentThread() != owner || closed) throw new IllegalStateException("Use the open recording's browser worker."); }
    private static IllegalArgumentException incompatible() { return new IllegalArgumentException("Browser recording is unavailable with this runtime. Reload the complete extension JAR."); }
    @Override public void close() {
        if (closed) return; owner(); closed = true; accepting = false;
        if (tap.active == this) tap.active = null; events.forEach(Event::close); events.clear(); queuedBytes = 0;
    }
}
