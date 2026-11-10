package lab.auth;

import com.google.gson.JsonObject;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Synthetic collector checks earn no product or host authentication coverage. */
class HttpAuthenticationEvidenceTest {
    @org.junit.jupiter.api.io.TempDir java.nio.file.Path temporary;
    private JsonObject identity() {
        return LabRun.JSON.toJsonTree(Map.of("fixtureClosed",true,"leakedDirectives",0,"handshakes",3,"posts",0,"handshakesBeforeReconnect",2,
                "observations",List.of(observation("user-a","socket-a"),observation("user-b","socket-b"),
                        observation("user-a","socket-a"),observation("user-b","socket-b"),observation("user-a","socket-a"),observation("user-a","socket-a"),observation("user-a","socket-a-new")))).getAsJsonObject();
    }
    private Map<String,Object> observation(String user,String socket) {
        return Map.of("user",user,"protocol","NTLM_V2","connection",socket,"method","GET","path","/whoami","bodyBytes",0);
    }
    @Test void identityProofRequiresIndependentAccountProtocolIsolationAndCleanup() {
        String id="HTTP.auth.ntlm-v2.identity";var valid=identity();assertTrue(LabHttpAuthenticationEvidence.valid(id,valid));
        for(String mutation:List.of("account","protocol","connection","handshakes","leak","cleanup","unexpected-secret","missing")) {
            var value=identity();var first=value.getAsJsonArray("observations").get(0).getAsJsonObject();
            switch(mutation) {
                case "account" -> first.addProperty("user","user-b");
                case "protocol" -> first.addProperty("protocol","NTLM_V1");
                case "connection" -> first.addProperty("connection","socket-b");
                case "handshakes" -> value.addProperty("handshakes",5);
                case "leak" -> value.addProperty("leakedDirectives",1);
                case "cleanup" -> value.addProperty("fixtureClosed",false);
                case "unexpected-secret" -> value.addProperty("authorization","must-not-be-retained");
                case "missing" -> value.remove("observations");
            }
            assertFalse(LabHttpAuthenticationEvidence.valid(id,value),mutation);assertTrue(LabHttpAuthenticationEvidence.facts(id,value).isEmpty());
        }
    }
    @Test void browserProofCannotPassWithoutExpectedCaptureProtocolAndActualProcessCleanup() {
        var value=identity();value.remove("handshakesBeforeReconnect");value.add("observations",LabRun.JSON.toJsonTree(List.of(observation("user-a","socket-a"))));
        value.addProperty("posts",1);value.addProperty("capturedExpectedAccount",true);value.addProperty("reportedProtocol","NTLM_V2");
        value.addProperty("drivers",1);value.addProperty("processes",4);value.addProperty("alive",0);value.addProperty("httpObservationCount",1);
        String id="HTTP.auth.ntlm-v2.browser";assertTrue(LabHttpAuthenticationEvidence.valid(id,value));
        for(String field:List.of("capturedExpectedAccount","reportedProtocol","drivers","processes","alive","httpObservationCount")) {
            var changed=value.deepCopy();
            if(field.equals("capturedExpectedAccount"))changed.addProperty(field,false);
            else if(field.equals("reportedProtocol"))changed.addProperty(field,"NTLM_V1");
            else changed.addProperty(field,field.equals("alive")?1:0);
            assertFalse(LabHttpAuthenticationEvidence.valid(id,changed),field);
        }
    }
    @Test void foregroundProfilePublishesOwnedMultiUserApplicationsAndClosesTheirListeners() throws Exception {
        List<java.net.URI> origins;
        try(var run=LabRun.start(new LabRun.RunSpec(java.util.UUID.randomUUID(),List.of("http-auth"),ScenarioCatalog.load(),temporary,List.of(),5000))) {
            var targets=LabRun.JSON.toJsonTree(run.servingTargets(run.generation())).getAsJsonObject().getAsJsonArray("httpAuthentication");
            assertEquals(3,targets.size());origins=targets.asList().stream().map(e->java.net.URI.create(e.getAsJsonObject().get("request").getAsString())).toList();
            try(var client=ControlledApplication.localClientBuilder().build()) {
                for(var origin:origins)assertEquals(401,client.send(java.net.http.HttpRequest.newBuilder(origin).GET().build(),java.net.http.HttpResponse.BodyHandlers.discarding()).statusCode());
                var basic=targets.asList().stream().map(e->e.getAsJsonObject()).filter(o->o.get("protocol").getAsString().equals("BASIC")).findFirst().orElseThrow();
                var request=java.net.http.HttpRequest.newBuilder(java.net.URI.create(basic.get("request").getAsString()))
                        .header("Authorization","Basic "+java.util.Base64.getEncoder().encodeToString("user-b:bravo-password".getBytes(java.nio.charset.StandardCharsets.UTF_8))).GET().build();
                var body=ScenarioCatalog.parseJson(client.send(request,java.net.http.HttpResponse.BodyHandlers.ofByteArray()).body()).getAsJsonObject();
                assertEquals("user-b",body.get("user").getAsString());assertEquals("BASIC",body.get("protocol").getAsString());
            }
        }
        try(var client=ControlledApplication.localClientBuilder().connectTimeout(java.time.Duration.ofSeconds(1)).build()) {
            for(var origin:origins)assertThrows(java.io.IOException.class,()->client.send(java.net.http.HttpRequest.newBuilder(origin).timeout(java.time.Duration.ofSeconds(1)).GET().build(),java.net.http.HttpResponse.BodyHandlers.discarding()));
        }
    }

    @Test void boundaryMetricsRejectContradictionsMissingFieldsAndUnreviewedData() {
        String id="HTTP.auth.resources.admission";
        var actual=LabRun.JSON.toJsonTree(Map.of("admitted",64,"bytes",0,"closed",0)).getAsJsonObject();
        assertTrue(LabHttpBoundaryEvidence.valid(id,actual));
        for(String mutation:List.of("admitted","bytes","closed","missing","extra")) {
            var changed=actual.deepCopy();
            if(mutation.equals("missing"))changed.remove("bytes");
            else changed.addProperty(mutation,1);
            assertFalse(LabHttpBoundaryEvidence.valid(id,changed),mutation);
            assertTrue(LabHttpBoundaryEvidence.facts(id,changed).isEmpty());
        }
        assertFalse(LabHttpBoundaryEvidence.valid("HTTP.auth.resources.unknown",actual));
    }

    @Test void browserPolicyProofRequiresSingleDeliveryAndActualProcessCleanup() {
        String id="HTTP.auth.browser-authorization.reused-ntlm-v2";
        var values=new java.util.LinkedHashMap<String,Object>();
        values.putAll(Map.of("status",200,"applicationHeaders",1,"unexpectedCredentials",0,"wireDelta",1,"handshakeDelta",0,
                "serverAccepted",true,"conflict",false,"observedProtocol","NTLM_V2"));
        values.putAll(Map.of("drivers",1,"processes",4,"alive",0,"fixtureClosed",true));
        var actual=LabRun.JSON.toJsonTree(values).getAsJsonObject();assertTrue(LabHttpBoundaryEvidence.valid(id,actual));
        for(String field:List.of("wireDelta","unexpectedCredentials","handshakeDelta","drivers","processes","alive","fixtureClosed","observedProtocol")) {
            var changed=actual.deepCopy();
            if(field.equals("fixtureClosed"))changed.addProperty(field,false);
            else if(field.equals("observedProtocol"))changed.addProperty(field,"BASIC");
            else changed.addProperty(field,field.equals("wireDelta")?2:field.equals("drivers")||field.equals("processes")?0:1);
            assertFalse(LabHttpBoundaryEvidence.valid(id,changed),field);
        }
    }
}
