package bpsh.browser.runtime;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.microsoft.playwright.impl.Transport;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Structured protocol checks run without starting a browser or retaining generated source. */
class PlaywrightRecorderAdapterTest {
    @Test void metadataComesFromTheMaintainedResourceAndUsesTheSharedLimits() {
        var script = PlaywrightRecorderAdapter.metadataScript();
        assertFalse(script.contains("__BPSH_LIMITS__")); assertTrue(script.contains(PlaywrightRecorderAdapter.SOURCE_BINDING));
        assertTrue(script.contains("\"nodes\":16384")); assertTrue(script.contains("\"fields\":4096")); assertTrue(script.contains("\"stop\":5000"));
    }
    private static JsonObject event(String action) {
        return JsonParser.parseString("{\"event\":\"actionAdded\",\"page\":{\"guid\":\"page-1\"},\"data\":" + action + "}").getAsJsonObject();
    }

    @Test void dropsGeneratedSourceSnapshotAndEphemeralRefAndOwnsFillBuffers() {
        var event = event("{\"name\":\"fill\",\"selector\":\"#password\",\"text\":\"CANARY\"}");
        event.addProperty("code", "CANARY".repeat(20_000));
        event.getAsJsonObject("data").addProperty("ariaSnapshot", "CANARY".repeat(20_000));
        event.getAsJsonObject("data").addProperty("ref", "ephemeral");
        var decoded = PlaywrightRecorderAdapter.decode(event);
        assertTrue(decoded.bytes() < 1024); assertEquals(PlaywrightRecorderAdapter.Classification.UNKNOWN, decoded.action().metadata().classification());
        var copy = decoded.action().value(); assertArrayEquals("CANARY".toCharArray(), copy);
        assertFalse(decoded.toString().contains("CANARY")); assertFalse(decoded.action().toString().contains("CANARY"));
        decoded.close(); assertArrayEquals(new char[6], decoded.action().value()); assertArrayEquals("CANARY".toCharArray(), copy); Arrays.fill(copy, '\0');
    }

    @Test void preservesUpdatesAndExactOptionArraysAndMetadata() {
        var fill = event("{\"name\":\"fill\",\"selector\":\"#name\",\"text\":\"\",\"bpshClassification\":\"ordinary\",\"bpshDocumentId\":\"doc_1\",\"bpshFieldId\":\"field-2\",\"bpshSourceActionId\":\"doc_1_action_3\"}");
        fill.addProperty("event", "actionUpdated");
        try (var decoded = PlaywrightRecorderAdapter.decode(fill)) {
            assertEquals(PlaywrightRecorderAdapter.Kind.UPDATED, decoded.kind()); assertArrayEquals(new char[0], decoded.action().value());
            assertEquals(PlaywrightRecorderAdapter.Classification.ORDINARY, decoded.action().metadata().classification());
            assertEquals("doc_1_action_3", decoded.action().metadata().sourceKey());
        }
        for (String values : List.of("[]", "[\"\"]", "[\"\",\" blue,green \",\" blue,green \"]")) {
            try (var decoded = PlaywrightRecorderAdapter.decode(event("{\"name\":\"select\",\"selector\":\"#roles\",\"options\":" + values + "}"))) {
                assertEquals(JsonParser.parseString(values).getAsJsonArray().asList().stream().map(x -> x.getAsString()).toList(), decoded.action().options());
            }
        }
    }

    @Test void rejectsWrongShapesUnknownSupportedActionFieldsAndBoundsWithoutEchoingValues() {
        for (String body : List.of("{\"name\":\"fill\",\"selector\":\"#x\",\"text\":false}",
                "{\"name\":\"fill\",\"selector\":\"#x\",\"text\":\"CANARY\",\"unknown\":true}",
                "{\"name\":\"select\",\"selector\":\"#x\",\"options\":[null]}",
                "{\"name\":\"press\",\"selector\":\"#x\",\"key\":\"Enter\",\"modifiers\":\"2\"}")) {
            assertFalse(assertThrows(IllegalArgumentException.class, () -> PlaywrightRecorderAdapter.decode(event(body))).getMessage().contains("CANARY"));
        }
        var huge = event("{\"name\":\"fill\",\"selector\":\"#x\",\"text\":\"\"}"); huge.getAsJsonObject("data").addProperty("text", "a".repeat(16_385));
        assertThrows(IllegalArgumentException.class, () -> PlaywrightRecorderAdapter.decode(huge));
        huge.getAsJsonObject("data").addProperty("text", "\u0000".repeat(16_000));
        assertThrows(IllegalArgumentException.class, () -> PlaywrightRecorderAdapter.decode(huge));
        var options = event("{\"name\":\"select\",\"selector\":\"#x\",\"options\":[]}");
        for (int i = 0; i < 257; i++) options.getAsJsonObject("data").getAsJsonArray("options").add("x");
        assertThrows(IllegalArgumentException.class, () -> PlaywrightRecorderAdapter.decode(options));
    }

    @Test void transportTapPreservesOrdinaryRepliesAndEventsAndDropsPrivatePayloadsBeforeDispatch() {
        var normal = JsonParser.parseString("{\"id\":1,\"result\":{\"answer\":42}}").getAsJsonObject();
        var lifecycle = JsonParser.parseString("{\"guid\":\"context-1\",\"method\":\"page\",\"params\":{\"page\":{\"guid\":\"page-1\"}}}").getAsJsonObject();
        var privateEvent = new JsonObject(); privateEvent.addProperty("guid", "context-1"); privateEvent.addProperty("method", "recorderEvent");
        var payload = event("{\"name\":\"fill\",\"selector\":\"#x\",\"text\":\"CANARY\",\"ariaSnapshot\":\"CANARY\",\"ref\":\"temporary\"}");
        payload.addProperty("code", "CANARY"); privateEvent.add("params", payload);
        var queue = new java.util.ArrayDeque<>(List.of(normal, lifecycle, privateEvent)); var sent = new java.util.ArrayList<JsonObject>();
        var tap = new PlaywrightRecorderAdapter.Tap(new Transport() {
            @Override public void send(JsonObject message) { sent.add(message); }
            @Override public JsonObject poll(Duration timeout) { return queue.pollFirst(); }
            @Override public void close() {}
        });
        tap.send(normal); assertSame(normal, sent.getFirst()); assertSame(normal, tap.poll(Duration.ZERO)); assertSame(lifecycle, tap.poll(Duration.ZERO));
        assertSame(privateEvent, tap.poll(Duration.ZERO)); assertFalse(privateEvent.toString().contains("CANARY")); assertFalse(payload.has("code")); assertFalse(payload.has("data"));
    }

    @Test void utf8BoundsIncludeSupplementaryCharactersWithoutAllocatingASecretEncoding() {
        assertEquals(10, PlaywrightRecorderAdapter.utf8Length("aé€🔐"));
    }
}
