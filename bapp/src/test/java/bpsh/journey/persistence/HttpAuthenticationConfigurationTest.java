package bpsh.journey.persistence;

import bpsh.burp.ui.JourneyRegistryTest;
import bpsh.journey.ConfigurationException;
import bpsh.journey.HttpAuthentication;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.JourneySecrets;
import bpsh.journey.SecretStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.*;

class HttpAuthenticationConfigurationTest {
    private final ObjectMapper json=new ObjectMapper();
    private ObjectNode identity() throws Exception {
        ObjectNode root=(ObjectNode)json.readTree(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.EXPORT,false,false));
        root.put("schemaVersion",2);ObjectNode journey=(ObjectNode)root.at("/journeys/0");
        journey.putArray("steps");journey.putNull("extraction");journey.putObject("injection").put("type","per_token").putArray("tokens");
        journey.putObject("httpAuthentication").put("protocol","NTLM_V2").put("username","user-a").put("domain","LAB").put("workstation","")
                .putArray("origins").add("https://example.test");
        return root;
    }
    @Test void httpOnlyIdentityRoundTripsWithoutInventingACapturedTokenAndCopiesKeepSettings() throws Exception {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.configuration.schema-two");
        try(var document=JourneyJson.read(identity().toString(),JourneyDocument.DocumentKind.EXPORT)) {
            var original=document.journeys().getFirst();assertTrue(original.httpOnly());assertNull(original.extraction());
            assertEquals(HttpAuthentication.Protocol.NTLM_V2,original.httpAuthentication().protocol());
            assertEquals(original.httpAuthentication(),original.withIdentity(java.util.UUID.randomUUID(),original.steps(),false).httpAuthentication());
            String saved=JourneyJson.write(document);assertEquals(2,json.readTree(saved).get("schemaVersion").intValue());
            proof.put("schema",json.readTree(saved).get("schemaVersion").intValue());proof.put("httpOnly",original.httpOnly());proof.put("captureAbsent",original.extraction()==null);
            try(var loaded=JourneyJson.read(saved,JourneyDocument.DocumentKind.EXPORT)) {assertEquals(original,loaded.journeys().getFirst());}
        }
        proof.write();
    }
    @Test void passwordIsOwnedCopiedWipedAndOmittedWithoutExplicitExportConsent() throws Exception {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.configuration.secrets");
        ObjectNode root=identity();((ObjectNode)root.at("/journeys/0")).putObject("secrets").put("httpPassword","private-fixture-password");
        try(var document=JourneyJson.read(root.toString(),JourneyDocument.DocumentKind.EXPORT)) {
            var journey=document.journeys().getFirst();var secret=document.secrets().get(journey.id());
            JourneySecrets.requireCompleteSecrets(journey,secret);
            assertFalse(JourneyJson.write(document).contains("private-fixture-password"));
            proof.put("exportOmitted",!JourneyJson.write(document).contains("private-fixture-password"));
            try(var copy=secret.copy()) {assertArrayEquals("private-fixture-password".toCharArray(),copy.httpPassword());secret.close();assertArrayEquals("private-fixture-password".toCharArray(),copy.httpPassword());}
            var closed=assertThrows(IllegalStateException.class,secret::httpPassword);proof.put("closed",closed!=null);
        }
        try(var empty=new SecretStore.Values(null,Map.of(),new char[0])) {assertFalse(empty.isEmpty());assertEquals(0,empty.httpPassword().length);proof.put("emptySupplied",!empty.isEmpty());}
        proof.write();
    }
    @ParameterizedTest @CsvSource({"PROJECT,false", "PROJECT,true", "LIBRARY,false", "LIBRARY,true"})
    void ntlmPasswordPersistenceFollowsRememberSecrets(JourneyDocument.DocumentKind kind, boolean remember) throws Exception {
        ObjectNode root=identity();((ObjectNode)root.at("/journeys/0")).putObject("secrets").put("httpPassword","remembered-ntlm-fixture");
        try(var source=JourneyJson.read(root.toString(),JourneyDocument.DocumentKind.EXPORT)) {
            var base=source.journeys().getFirst();var journey=base.withIdentity(base.id(),base.steps(),remember);
            try(var document=new JourneyDocument(kind,java.util.UUID.randomUUID(),java.util.List.of(journey),java.util.List.of(),
                    kind==JourneyDocument.DocumentKind.PROJECT?bpsh.request.RequestSettings.Controls.defaults():null,
                    Map.of(journey.id(),source.secrets().get(base.id()).copy()))) {
                String stored=JourneyJson.write(document);
                assertEquals(remember,json.readTree(stored).at("/journeys/0/secrets").has("httpPassword"));
                assertArrayEquals("remembered-ntlm-fixture".toCharArray(),document.secrets().get(journey.id()).httpPassword(),"Saving must preserve the session password");
                try(var loaded=JourneyJson.read(stored,kind)) {
                    assertEquals(remember,loaded.secrets().containsKey(journey.id()));
                    if(remember)assertArrayEquals("remembered-ntlm-fixture".toCharArray(),loaded.secrets().get(journey.id()).httpPassword());
                }
            }
            assertFalse(JourneyJson.write(source).contains("remembered-ntlm-fixture"));
            assertTrue(JourneyJson.write(source,true).contains("remembered-ntlm-fixture"));
        }
    }
    @Test void rejectsSilentDowngradeInvalidOriginsAndCredentialFieldsInNonsecretSettings() throws Exception {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.configuration.invalid");
        for(String mutation:java.util.List.of("version","protocol","origin","password")) {
            ObjectNode root=identity(),http=(ObjectNode)root.at("/journeys/0/httpAuthentication");
            switch(mutation) {
                case "version" -> root.put("schemaVersion",1);
                case "protocol" -> http.put("protocol","NEGOTIATE");
                case "origin" -> http.putArray("origins").add("https://example.test/login");
                case "password" -> http.put("password","must-not-be-here");
            }
            var rejected=assertThrows(ConfigurationException.class,()->JourneyJson.read(root.toString(),JourneyDocument.DocumentKind.EXPORT),mutation);proof.put(mutation,rejected!=null);
        }
        proof.write();
    }
    @Test void schemaOneStillLoadsWithHttpAuthenticationDisabled() throws Exception {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.configuration.schema-one");
        try(var document=JourneyJson.read(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.EXPORT,false,false),JourneyDocument.DocumentKind.EXPORT)) {
            assertNull(document.journeys().getFirst().httpAuthentication());assertFalse(document.journeys().getFirst().httpOnly());
            proof.put("httpAbsent",document.journeys().getFirst().httpAuthentication()==null);proof.put("httpOnly",document.journeys().getFirst().httpOnly());
        }
        proof.write();
    }
    @Test void disabledEditorSettingsRetainTheirExplicitOriginAndRejectPartialSilentOmission() {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.configuration.disabled");
        var text=new java.util.HashMap<String,String>();text.put("url","https://example.test/login");text.put("navTimeout","30");
        text.put("httpDomain","LAB");text.put("httpOrigins","https://example.test");
        var partial=bpsh.journey.JourneyDraft.capture(text,Map.of(),bpsh.journey.JourneyDefinition.SlotKind.INDEX,"",java.util.List.of(),java.util.List.of());
        assertThrows(ConfigurationException.class,()->bpsh.journey.editing.BrowserSetupCompiler.compile(partial));
        assertEquals("LAB",partial.text().get("httpDomain"));
        text.put("httpUsername","user-a");text.put("url","https://another.test/login");
        var draft=bpsh.journey.JourneyDraft.capture(text,Map.of(),bpsh.journey.JourneyDefinition.SlotKind.INDEX,"",java.util.List.of(),java.util.List.of());
        var saved=bpsh.journey.editing.BrowserSetupCompiler.compile(draft).httpAuthentication();
        assertFalse(saved.enabled());assertTrue(saved.allows(java.net.URI.create("https://example.test")));
        assertFalse(saved.allows(java.net.URI.create("https://another.test")));
            proof.put("enabled",saved.enabled());proof.put("originalOrigin",saved.allows(java.net.URI.create("https://example.test")));proof.put("changedOrigin",saved.allows(java.net.URI.create("https://another.test")));proof.put("domainRetained",partial.text().get("httpDomain").equals("LAB"));
        proof.write();
    }
}
