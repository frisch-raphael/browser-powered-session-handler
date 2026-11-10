package bpsh.journey.persistence;

import bpsh.burp.ui.JourneyRegistryTest;
import bpsh.journey.ConfigurationException;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.JourneyDraft;
import bpsh.journey.editing.BrowserSetupCompiler;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Certificate bypass is explicit, persistent, strictly typed and disabled for pre-existing journeys. */
class BrowserTlsPolicyTest {
    @Test void oldDocumentsStayStrictAndExplicitConsentRoundTrips() throws Exception {
        var json = new ObjectMapper();
        for (var kind : JourneyDocument.DocumentKind.values()) {
            var text = JourneyRegistryTest.fixture(kind, false, false);
            try (var legacy = JourneyJson.read(text, kind)) { assertFalse(legacy.journeys().getFirst().browser().ignoreHttpsErrors()); }
            var root = (ObjectNode) json.readTree(text);
            ((ObjectNode) root.at("/journeys/0/browser")).put("ignoreHttpsErrors", true);
            try (var optedIn = JourneyJson.read(root.toString(), kind);
                 var restored = JourneyJson.read(JourneyJson.write(optedIn), kind)) {
                assertTrue(restored.journeys().getFirst().browser().ignoreHttpsErrors());
            }
            ((ObjectNode) root.at("/journeys/0/browser")).put("ignoreHttpsErrors", "true");
            assertThrows(ConfigurationException.class, () -> JourneyJson.read(root.toString(), kind));
            ((ObjectNode) root.at("/journeys/0/browser")).putNull("ignoreHttpsErrors");
            assertThrows(ConfigurationException.class, () -> JourneyJson.read(root.toString(), kind));
        }
    }

    @Test void legacyDraftsDefaultToStrictAndRecordingCompilesTheSelectedPolicy() throws Exception {
        var text = Map.of("url", "https://login.example", "navTimeout", "30");
        var old = JourneyDraft.capture(text, Map.of(), JourneyDefinition.SlotKind.INDEX, "", List.of(), List.of());
        var legacyFlags = new java.util.HashMap<>(old.flags()); legacyFlags.remove("ignoreHttpsErrors");
        var legacy = new JourneyDraft(old.text(), legacyFlags, old.slotKind(), "", old.steps(), old.credentials());
        assertFalse(BrowserSetupCompiler.compile(legacy).browser().ignoreHttpsErrors());
        var chosen = JourneyDraft.capture(text, Map.of("ignoreHttpsErrors", true), JourneyDefinition.SlotKind.INDEX, "", List.of(), List.of());
        assertTrue(BrowserSetupCompiler.compile(chosen).browser().ignoreHttpsErrors());
        var draft = chosen.definition(java.util.UUID.randomUUID(), "Draft", "draft", false);
        try (var document = new JourneyDocument(JourneyDocument.DocumentKind.EXPORT, java.util.UUID.randomUUID(), List.of(draft), List.of(), null, Map.of());
             var restored = JourneyJson.read(JourneyJson.write(document), JourneyDocument.DocumentKind.EXPORT)) {
            assertTrue(restored.journeys().getFirst().draft().flags().get("ignoreHttpsErrors"));
            var encoded = (ObjectNode) new ObjectMapper().readTree(JourneyJson.write(document));
            ((ObjectNode) encoded.at("/journeys/0/draft/flags")).put("ignoreHttpsErrors", "true");
            assertThrows(ConfigurationException.class, () -> JourneyJson.read(encoded.toString(), JourneyDocument.DocumentKind.EXPORT));
        }
    }
}
