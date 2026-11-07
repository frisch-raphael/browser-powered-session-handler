package lab.federation;

import lab.auth.*;
import org.junit.jupiter.api.*;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** Our serving/control lifecycle only; this establishes no extension or IdP coverage. */
@Tag("federation-infrastructure")
class FederationContractTest {
    @Test @Timeout(120) void servingControlsCreateOneOwnedCaseAndRejectStaleWorkAfterReset() throws Exception {
        Path workspace=Path.of(System.getProperty("federation.workspace"));
        // Retain interrupted ownership records instead of letting JUnit remove them after failure.
        Path root=workspace.resolve("test/authentication-lab/build/runs");
        Path caPath=workspace.resolve("test/authentication-lab/build/prepared/federation/ca");
        var ca=LabTls.loadPrepared(caPath);
        var spec=new FederationEnvironment.Spec(workspace.resolve("test/federation-client/provider-assets.lock.json"),
                workspace.resolve("test/federation-client/src/main/resources/provider/downstream-realm.json"),ca);
        var run=LabRun.start(new LabRun.RunSpec(UUID.fromString(System.getProperty("federation.invocationId")),List.of("federation"),ScenarioCatalog.load(),root,List.of(),30000));
        Path descriptor=run.directory().resolve("run.json");var observed=new ArrayList<Map.Entry<String,String>>();
        try(run) {
            try(var provider=FederationEnvironment.startProvider(run,spec)) {
                assertTrue(provider.providerReady());
                var state=FederationApplication.JSON.readTree(Files.readAllBytes(descriptor));assertEquals("READY",state.get("state").asString());
                for(var resource:state.get("resources")) {
                    String kind=resource.get("kind").asString();
                    if(!Set.of("CONTAINER","NETWORK").contains(kind))continue;
                    assertEquals(run.runId().toString(),resource.get("ownerRunId").asString());assertTrue(resource.get("proof").get("verified").asBoolean());
                    observed.add(Map.entry(kind,resource.get("id").asString()));
                }
                assertEquals(1,observed.stream().filter(e->e.getKey().equals("CONTAINER")).count());assertEquals(1,observed.stream().filter(e->e.getKey().equals("NETWORK")).count());
                Path runtimeManifest=Path.of(System.getProperty("federation.runtimeManifest"));
                run.enableFederationServing(runtimeManifest);
                try(var http=ControlledApplication.localClientBuilder().connectTimeout(java.time.Duration.ofSeconds(2)).build()) {
                    String id="FED.negative.code-expired",base="/cases/"+id;
                    var created=control(http,run,"/cases",Map.of("caseId",id,"runGeneration",run.generation()));assertEquals(201,created.statusCode());
                    long generation=FederationApplication.JSON.readTree(created.body()).path("generation").asLong();
                    assertEquals(1,run.cases().size());assertEquals(provider.ports().clientOrigin()+"/oauth2/authorization/backend",run.cases().getFirst().startUri().toString());
                    var targets=FederationApplication.JSON.readTree(control(http,run,"/targets?generation="+run.generation(),null).body());
                    assertEquals(provider.ports().issuer().toString(),targets.path("federation").path("issuer").asString());
                    assertEquals(provider.ports().clientOrigin().toString(),targets.path("federation").path("clientOrigin").asString());
                    assertEquals(generation,targets.path("cases").get(0).path("generation").asLong());
                    var index=http.send(java.net.http.HttpRequest.newBuilder(run.applicationUri()).GET().build(),java.net.http.HttpResponse.BodyHandlers.ofString());
                    assertTrue(index.body().contains(run.cases().getFirst().startUri().toString()));
                    var arm=new LinkedHashMap<String,Object>();arm.put("generation",generation+1);arm.put("variant","code-expired");arm.put("checkpoint","before-token-exchange");
                    assertEquals(409,control(http,run,base+"/federation-control",arm).statusCode());arm.put("generation",generation);
                    assertEquals(200,control(http,run,base+"/federation-control",arm).statusCode());
                    var repeat=control(http,run,base+"/federation-control",arm);assertEquals(409,repeat.statusCode());
                    assertEquals("STATE_CONFLICT",FederationApplication.JSON.readTree(repeat.body()).path("error").path("code").asString());
                    assertEquals(409,control(http,run,base+"/gates/before-token-exchange/release",Map.of("generation",generation)).statusCode());
                    assertEquals(400,control(http,run,base+"/clock",Map.of("generation",generation,"advanceMs",1)).statusCode());
                    var snapshot=control(http,run,base+"/snapshot?generation="+generation,null);assertEquals(200,snapshot.statusCode());
                    var childState=FederationApplication.JSON.readTree(snapshot.body());assertEquals(id,childState.path("caseId").asString());
                    boolean armed=false;for(var event:childState.path("events"))if(event.path("name").asString().equals("control-armed-code-expired"))armed=true;
                    assertTrue(armed);assertTrue(childState.path("counters").path("httpIngress").isNull());
                    var old=run.cases().getFirst();
                    var reset=control(http,run,"/reset",Map.of("generation",run.generation()));assertEquals(200,reset.statusCode());assertEquals("CLOSED",old.snapshot().get("state"));
                    assertEquals(404,control(http,run,base+"/federation-control",arm).statusCode());
                    assertEquals(201,control(http,run,"/cases",Map.of("caseId",id,"runGeneration",run.generation())).statusCode());
                    assertNotEquals(generation,run.cases().getFirst().generation());
                    assertEquals(409,control(http,run,base+"/federation-control",arm).statusCode());
                }
            }
            for(var resource:observed)FederationEnvironment.confirmResourceAbsent(resource.getKey(),resource.getValue());
        }
        var terminal=FederationApplication.JSON.readTree(Files.readAllBytes(descriptor));assertEquals("CLOSED",terminal.get("state").asString());assertEquals(0,terminal.get("resources").size());
        assertTrue(Files.isRegularFile(caPath.resolve("ca.crt")));assertTrue(Files.isRegularFile(caPath.resolve("ca.p12")));
        Path proof=workspace.resolve("test/federation-client/build/p3/invocations/"+System.getProperty("federation.invocationId")+"/serving-controls.json");Files.createDirectories(proof.getParent());
        Files.write(proof,FederationApplication.JSON.writeValueAsBytes(Map.of("harnessOnly",true,"parentControlsForwarded",true,"staleMutationRejected",true,
                "resetRetiredChildren",true,"remainingResources",0,"extensionCoverageEstablished",false)));
    }
    private static java.net.http.HttpResponse<String> control(java.net.http.HttpClient http,LabRun run,String route,Map<String,Object> payload) throws Exception {
        var request=java.net.http.HttpRequest.newBuilder(java.net.URI.create(run.controlUri()+route)).timeout(java.time.Duration.ofSeconds(50)).header("Authorization","Bearer "+run.controlKey().reveal());
        if(payload==null)request.GET();else request.header("Content-Type","application/json").POST(java.net.http.HttpRequest.BodyPublishers.ofByteArray(FederationApplication.JSON.writeValueAsBytes(payload)));
        return http.send(request.build(),java.net.http.HttpResponse.BodyHandlers.ofString());
    }
}
