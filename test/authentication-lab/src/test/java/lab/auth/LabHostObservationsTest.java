package lab.auth;

import java.net.http.*;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class LabHostObservationsTest {
    @TempDir Path directory;
    @Test void receiverDistinguishesAbsentInvalidAndMalformedCredentialsWithoutRetainingValues() throws Exception {
        try(var run=LabRun.start(new LabRun.RunSpec(UUID.randomUUID(),List.of("browser"),ScenarioCatalog.load(),directory,List.of(),5_000));
            var client=ControlledApplication.localClientBuilder().build();var lease=run.prepareCase("BROW.basic.json")) {
            for(int i=0;i<3;i++) {
                var request=HttpRequest.newBuilder(lease.endpoint("protected/b_c1"))
                        .header("X-AuthLab-Request","h000000000000000"+i).header("X-AuthLab-Sentinel","unchanged");
                if(i>0)request.header("Authorization",i==1?"Bearer PRIVATE_SENTINEL":"malformed PRIVATE_SENTINEL")
                        .header("Cookie","LAB_C1=PRIVATE_COOKIE");
                var response=client.send(request.GET().build(),HttpResponse.BodyHandlers.discarding());
                assertEquals(i==2?400:401,response.statusCode());assertEquals("h000000000000000"+i,response.headers().firstValue("X-AuthLab-Request").orElseThrow());
            }
            var observations=completed(lease,3);
            assertEquals(0,observations.get(0).request().authorizationHeaders());assertFalse(observations.get(0).request().c1());
            assertEquals(1,observations.get(1).request().authorizationHeaders());assertTrue(observations.get(1).request().c1());
            assertEquals(List.of(401,401,400),observations.stream().map(LabHostObservations.Received::status).toList());
            assertTrue(observations.stream().allMatch(row->row.request().sentinel()&&row.accountId()==null));
            assertTrue(observations.stream().allMatch(row->row.listenerPort()==run.applicationUri().getPort()));
            client.send(HttpRequest.newBuilder(lease.endpoint("protected/b_c1",true)).GET().build(),HttpResponse.BodyHandlers.discarding());
            assertEquals(run.alternateUri().getPort(),completed(lease,4).getLast().listenerPort());
            String safe=LabRun.JSON.toJson(lease.snapshot());
            assertFalse(safe.contains("PRIVATE_SENTINEL"));assertFalse(safe.contains("PRIVATE_COOKIE"));
            for(var nonces:List.of(List.of("PRIVATE_SENTINEL"),List.of("h0000000000000001","h0000000000000002"))) {
                var request=HttpRequest.newBuilder(lease.endpoint("protected/b_c1"));nonces.forEach(n->request.header("X-AuthLab-Request",n));
                assertTrue(client.send(request.GET().build(),HttpResponse.BodyHandlers.discarding()).headers().allValues("X-AuthLab-Request").isEmpty());
            }
        }
    }
    @Test void shapesBoundBodiesAndRejectAmbiguousCorrelationWithoutExportingInput() {
        var shape=LabHostObservations.shape(Map.of("X-AuthLab-Request",List.of("h0000000000000001","h0000000000000002"),
                "X-Private",List.of("<@unknown/>PRIVATE_SENTINEL"),"BPSP-HTTP-AUTHENT",List.of("PRIVATE_SENTINEL")),
                "POST","unexpected-private-path",new byte[LabHostObservations.BODY_LIMIT+1]);
        assertNull(shape.nonce());assertTrue(shape.invalidNonce());assertTrue(shape.nativeTag());assertTrue(shape.httpDirective());
        assertEquals("UNKNOWN",shape.route());assertTrue(shape.bodyTruncated());assertEquals(LabHostObservations.BODY_LIMIT,shape.bodyBytes());
        assertFalse(shape.toString().contains("PRIVATE_SENTINEL"));
    }
    @Test void overflowPendingAndDuplicateCompletionCannotProduceCompleteEvidence() {
        var facts=new LabHostObservations();var shape=LabHostObservations.shape(Map.of(),"GET","b",new byte[0]);
        assertThrows(IllegalArgumentException.class,()->facts.begin("BROW.basic.json",1,0,shape));
        long first=facts.begin("BROW.basic.json",1,12345,shape);assertEquals(false,facts.snapshot().get("complete"));
        facts.complete(first,401,null,null,List.of());assertEquals(true,facts.snapshot().get("complete"));
        assertThrows(IllegalStateException.class,()->facts.complete(first,200,"user","s1",List.of("B")));
        for(int i=1;i<=LabHostObservations.LIMIT;i++)facts.complete(facts.begin("BROW.basic.json",1,12345,shape),401,null,null,List.of());
        assertEquals(true,facts.snapshot().get("truncated"));assertEquals(false,facts.snapshot().get("complete"));
        assertEquals(LabHostObservations.LIMIT,((List<?>)facts.snapshot().get("received")).size());
    }
    @Test void httpReceiverSeparatesChallengeTransmissionsFromAuthenticatedOperations() throws Exception {
        try(var fixture=new HttpAuthenticationFixture(HttpAuthenticationFixture.Protocol.BASIC,Map.of("fixture-user","fixture-password"),null);
            var client=ControlledApplication.localClientBuilder().build()) {
            String nonce="h0000000000000001";
            var request=HttpRequest.newBuilder(fixture.url("/proof")).header("X-AuthLab-Request",nonce)
                    .POST(HttpRequest.BodyPublishers.ofString("synthetic-body"));
            var challenge=client.send(request.build(),HttpResponse.BodyHandlers.discarding());assertEquals(401,challenge.statusCode());
            assertEquals(nonce,challenge.headers().firstValue("X-AuthLab-Request").orElseThrow());
            request.header("Authorization","Basic "+Base64.getEncoder().encodeToString("fixture-user:fixture-password".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            var accepted=client.send(request.build(),HttpResponse.BodyHandlers.discarding());assertEquals(200,accepted.statusCode());
            assertEquals(nonce,accepted.headers().firstValue("X-AuthLab-Request").orElseThrow());
            assertEquals(List.of("NONE","BASIC"),fixture.requests.stream().map(HttpAuthenticationFixture.WireRequest::challengePhase).toList());
            assertEquals(1,fixture.observations.size());assertEquals(1,fixture.applicationPosts.get());
            assertEquals(nonce,fixture.observations.getFirst().nonce());assertEquals(1,fixture.observations.getFirst().operationId());
            assertEquals("fixture-user",fixture.observations.getFirst().user());assertFalse(fixture.observationOverflow.get());
            String safe=LabRun.JSON.toJson(fixture.requests)+LabRun.JSON.toJson(fixture.observations);
            assertFalse(safe.contains("fixture-password"));assertFalse(safe.contains("synthetic-body"));
        }
    }
    @Test void httpObservationEndpointReportsOrdinaryAuthorizationReachingTheApplication() throws Exception {
        try(var run=LabRun.start(new LabRun.RunSpec(UUID.randomUUID(),List.of("http-auth"),ScenarioCatalog.load(),directory,List.of(),5_000));
            var client=ControlledApplication.localClientBuilder().build()) {
            var targets=LabRun.JSON.toJsonTree(run.servingTargets(run.generation())).getAsJsonObject().getAsJsonArray("httpAuthentication");
            var basic=targets.asList().stream().map(com.google.gson.JsonElement::getAsJsonObject)
                    .filter(row->row.get("protocol").getAsString().equals("BASIC")).findFirst().orElseThrow();
            var endpoint=run.applicationUri().resolve("/http-auth/observations");
            var before=LabRun.JSON.fromJson(client.send(HttpRequest.newBuilder(endpoint).GET().build(),HttpResponse.BodyHandlers.ofString()).body(),com.google.gson.JsonObject.class);
            assertEquals(0,before.getAsJsonArray("applications").asList().stream().map(com.google.gson.JsonElement::getAsJsonObject)
                    .filter(row->row.get("protocol").getAsString().equals("BASIC")).findFirst().orElseThrow().get("applicationAuthorizations").getAsInt());
            assertEquals(401,client.send(HttpRequest.newBuilder(java.net.URI.create(basic.get("request").getAsString()))
                    .header("Authorization","Bearer application").GET().build(),HttpResponse.BodyHandlers.discarding()).statusCode());
            String safe=client.send(HttpRequest.newBuilder(endpoint).GET().build(),HttpResponse.BodyHandlers.ofString()).body();
            var after=LabRun.JSON.fromJson(safe,com.google.gson.JsonObject.class);
            assertEquals(1,after.getAsJsonArray("applications").asList().stream().map(com.google.gson.JsonElement::getAsJsonObject)
                    .filter(row->row.get("protocol").getAsString().equals("BASIC")).findFirst().orElseThrow().get("applicationAuthorizations").getAsInt());
            assertFalse(safe.contains("Bearer application"));assertFalse(safe.contains("alpha-password"));assertFalse(safe.contains("bravo-password"));
        }
    }
    @SuppressWarnings("unchecked")
    private static List<LabHostObservations.Received> completed(LabRun.CaseLease lease,int size) throws InterruptedException {
        long deadline=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(2);
        while(System.nanoTime()<deadline) {
            var snapshot=lease.hostObservations.snapshot();var rows=(List<LabHostObservations.Received>)snapshot.get("received");
            if(rows.size()==size&&Boolean.TRUE.equals(snapshot.get("complete")))return rows;
            Thread.sleep(10);
        }
        fail("Receiver observations did not complete");return List.of();
    }
}
