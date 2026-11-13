package bpsh.journey.persistence;

import bpsh.burp.ui.JourneyRegistryTest;
import bpsh.journey.*;
import bpsh.authentication.credentials.TokenExtractor;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.nio.file.Path;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class OptionalCaptureTest {
    private static ObjectNode fixture() throws Exception {
        return (ObjectNode)JourneyRegistryTest.JSON.readTree(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.EXPORT,false,false));
    }
    @Test void responsePathFilterCanBeEmptyOrOmittedWhileOriginStillScopesCapture() throws Exception {
        for(String kind:List.of("json_path","regex"))for(boolean omitted:List.of(false,true)) {
            var root=fixture();var source=((ObjectNode)root.at("/journeys/0")).putObject("extraction");
            source.put("type",kind).put("responseOrigin","https://login.example");
            if(!omitted)source.put("pathSubstring","");
            if(kind.equals("json_path"))source.put("jsonPath","access_token");else source.put("startRegex","token=").put("endRegex",";");
            try(var loaded=JourneyJson.read(root.toString(),JourneyDocument.DocumentKind.EXPORT)) {
                var extractor=new TokenExtractor(loaded.journeys().getFirst().extraction(),Clock.systemUTC());
                assertTrue(extractor.matchesResponse("https://login.example/any/path?query=value"));
                assertTrue(extractor.matchesResponse("https://login.example"));
                assertFalse(extractor.matchesResponse("https://other.example/any/path"));
                assertFalse(extractor.matchesResponse("https://login.example:8443/any/path"));
                try(var copy=JourneyJson.read(JourneyJson.write(loaded),loaded.kind())) {assertEquals(loaded.journeys(),copy.journeys());}
            }
        }
    }
    @Test void cookieCaptureNeedsNoExactDomainOrPathFilter() throws Exception {
        var root=fixture();((ObjectNode)root.at("/journeys/0")).putObject("extraction").put("type","cookie").put("originUrl","https://login.example").put("name","session");
        ((ObjectNode)root.at("/journeys/0")).putObject("injection").put("type","per_token").putArray("tokens");
        try(var loaded=JourneyJson.read(root.toString(),JourneyDocument.DocumentKind.EXPORT)) {
            var cookie=(JourneyDefinition.CookieExtraction)loaded.journeys().getFirst().extraction();
            assertEquals(URI.create("https://login.example"),cookie.originUrl());assertNull(cookie.domain());assertNull(cookie.path());
        }
    }
    @Test void clientCertificateOnlyJourneyRoundTripsWithoutCapturedCredentials() throws Exception {
        var root=fixture();var journey=(ObjectNode)root.at("/journeys/0");
        journey.putArray("steps");((ObjectNode)journey.get("browser")).put("formAuthentication",false);journey.putNull("extraction");
        journey.putObject("injection").put("type","per_token").putArray("tokens");
        journey.putObject("mtls").put("modulePath",Path.of("build","fixture-pkcs11.dll").toAbsolutePath().toString()).put("certificateSha256","12".repeat(32)).putArray("origins");
        try(var loaded=JourneyJson.read(root.toString(),JourneyDocument.DocumentKind.EXPORT)) {
            var selected=loaded.journeys().getFirst();assertNull(selected.extraction());assertNotNull(selected.mtls());
            assertFalse(selected.httpAuthenticationEnabled());
            try(var copy=JourneyJson.read(JourneyJson.write(loaded),loaded.kind())) {assertEquals(selected,copy.journeys().getFirst());}
        }
    }
    @Test void aTokenFreeDraftDoesNotRequireCaptureWaitOrCredentialCacheSettings() {
        var draft=JourneyDraft.capture(Map.of("name","Transport","alias","transport","url","https://login.example", "navTimeout","30",
                "httpProtocol","BASIC","httpUsername","user-a","httpOrigins","https://login.example"),
                Map.of("formAuthentication",false,"httpAuthentication",true),JourneyDefinition.SlotKind.INDEX,"",List.of(),List.of());
        var compiled=bpsh.journey.editing.JourneyDraftCompiler.compile(draft,UUID.randomUUID());
        assertNull(compiled.extraction());assertTrue(compiled.transportOnly());
    }
    @Test void aTokenFreeDraftDoesNotRequireAnUnusedBrowserNavigationTimeout() {
        var draft=JourneyDraft.capture(Map.of("name","Transport","alias","transport","url","https://login.example",
                "httpProtocol","BASIC","httpUsername","user-a","httpOrigins","https://login.example"),
                Map.of("formAuthentication",false,"httpAuthentication",true),JourneyDefinition.SlotKind.INDEX,"",List.of(),List.of());
        var compiled=bpsh.journey.editing.JourneyDraftCompiler.compile(draft,UUID.randomUUID());assertTrue(compiled.transportOnly());
    }
    @Test void formJourneyStillNeedsACaptureAndNonStringPathFiltersStayInvalid() throws Exception {
        var root=fixture();((ObjectNode)root.at("/journeys/0/extraction")).put("pathSubstring",true);
        assertThrows(ConfigurationException.class,()->JourneyJson.read(root.toString(),JourneyDocument.DocumentKind.EXPORT));
        ((ObjectNode)root.at("/journeys/0")).putNull("extraction");
        assertThrows(ConfigurationException.class,()->JourneyJson.read(root.toString(),JourneyDocument.DocumentKind.EXPORT));
    }
}
