package bpsh.journey.persistence;

import bpsh.burp.ui.JourneyRegistryTest;
import bpsh.journey.ConfigurationException;
import bpsh.journey.JourneyDefinition;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class AuthenticationMethodsTest {
    @Test void legacyBrowserJourneysKeepTheirStepsAndMethod() throws Exception {
        String json = JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false);
        try (var source = JourneyJson.read(json, JourneyDocument.DocumentKind.PROJECT)) {
            var journey = source.journeys().getFirst(); assertTrue(journey.browser().formAuthentication()); assertEquals(journey.steps(), journey.loginSteps());
        }
    }
    @Test void legacyHttpOnlyJourneysInferFormAuthenticationOff() throws Exception {
        var root = JourneyRegistryTest.JSON.readTree(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false));
        ((com.fasterxml.jackson.databind.node.ObjectNode) root).put("schemaVersion", 2);
        var journey = (com.fasterxml.jackson.databind.node.ObjectNode) root.at("/journeys/0"); journey.putArray("steps"); journey.putNull("extraction");
        journey.set("injection", JourneyRegistryTest.JSON.readTree("{\"type\":\"per_token\",\"tokens\":[]}"));
        journey.set("httpAuthentication", JourneyRegistryTest.JSON.readTree("{\"protocol\":\"BASIC\",\"username\":\"fixture-user\",\"domain\":\"\",\"workstation\":\"\",\"origins\":[\"https://login.example\"]}"));
        try (var source = JourneyJson.read(root.toString(), JourneyDocument.DocumentKind.PROJECT)) {
            assertTrue(source.journeys().getFirst().httpOnly()); assertFalse(source.journeys().getFirst().browser().formAuthentication());
        }
    }
    @Test void disabledStepsSurviveTransferWithoutBecomingExecutable() throws Exception {
        var root = JourneyRegistryTest.JSON.readTree(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false));
        ((com.fasterxml.jackson.databind.node.ObjectNode) root).put("schemaVersion", 2);
        var journey = (com.fasterxml.jackson.databind.node.ObjectNode) root.at("/journeys/0");
        ((com.fasterxml.jackson.databind.node.ObjectNode) journey.get("browser")).put("formAuthentication", false);
        journey.set("httpAuthentication", JourneyRegistryTest.JSON.readTree("{\"protocol\":\"BASIC\",\"username\":\"fixture-user\",\"domain\":\"\",\"workstation\":\"\",\"origins\":[\"https://login.example\"]}"));
        try (var source = JourneyJson.read(root.toString(), JourneyDocument.DocumentKind.PROJECT);
             var copy = JourneyJson.read(JourneyJson.write(source), source.kind())) {
            var restored = copy.journeys().getFirst(); assertFalse(restored.browser().formAuthentication()); assertEquals(1, restored.steps().size()); assertTrue(restored.loginSteps().isEmpty());
        }
        journey.putNull("extraction"); journey.set("injection", JourneyRegistryTest.JSON.readTree("{\"type\":\"per_token\",\"tokens\":[]}"));
        try (var source = JourneyJson.read(root.toString(), JourneyDocument.DocumentKind.PROJECT)) { assertTrue(source.journeys().getFirst().httpOnly()); }
    }
    @Test void methodChoiceIsStrictAndAnExecutableJourneyNeedsAMethod() throws Exception {
        String source = JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false);
        for (Object value : new Object[]{false, "true", 1}) {
            String invalid = JourneyRegistryTest.edit(source, "/journeys/0/browser", "formAuthentication", value);
            assertThrows(ConfigurationException.class, () -> JourneyJson.read(invalid, JourneyDocument.DocumentKind.PROJECT));
        }
    }
}
