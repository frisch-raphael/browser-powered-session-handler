package lab.auth;

import com.google.gson.JsonParser;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static lab.auth.FixtureContractTest.*;
import static org.junit.jupiter.api.Assertions.*;

/** Host GUI routing recipes use the same receivers with an explicit owner-local lifetime. */
class HostFixtureLifetimeTest {
    @TempDir Path root;
    private LabRun.RunSpec spec() {
        return new LabRun.RunSpec(UUID.randomUUID(),List.of("browser"),ScenarioCatalog.load(),root,List.of(),5_000);
    }
    @Test void hostLifetimeDoesNotChangeStandardRunsAndRevocationStillRejectsLiveCredentials() throws Exception {
        try(var host=LabRun.startHost(spec());var normal=LabRun.start(spec());
            var hostCase=host.prepareCase("BROW.basic.json");var normalCase=normal.prepareCase("BROW.basic.json");
            var client=ControlledApplication.localClientBuilder().build()) {
            var hostLogin=login(client,hostCase,false);var normalLogin=login(client,normalCase,false);
            assertEquals(200,proof(client,hostCase,hostLogin));assertEquals(200,proof(client,normalCase,normalLogin));
            hostCase.advanceFixtureClock(Duration.ofSeconds(61));normalCase.advanceFixtureClock(Duration.ofSeconds(61));
            assertEquals(200,proof(client,hostCase,hostLogin));assertEquals(401,proof(client,normalCase,normalLogin));
            hostCase.revoke(json(hostLogin).get("issuanceId").getAsString());
            assertEquals(401,proof(client,hostCase,hostLogin));
            var replacement=login(client,hostCase,false);
            assertEquals(200,proof(client,hostCase,replacement));
            hostCase.advanceFixtureClock(Duration.ofSeconds(3601));
            assertEquals(401,proof(client,hostCase,replacement));
        }
    }
    @Test void hostSignedTokenUsesItsDeclaredHourBoundaryForServerAcceptance() throws Exception {
        try(var host=LabRun.startHost(spec());var lease=host.prepareCase("BROW.basic.json");
            var client=ControlledApplication.localClientBuilder().build()) {
            long before=lease.identities.timeMillis()/1000;
            var response=login(client,lease,true);String token=json(response).get("access_token").getAsString();
            var claims=JsonParser.parseString(new String(Base64.getUrlDecoder().decode(token.split("\\.")[1]),StandardCharsets.UTF_8)).getAsJsonObject();
            long expires=claims.get("exp").getAsLong(),after=lease.identities.timeMillis()/1000;
            assertTrue(expires>=before+3600&&expires<=after+3600);
            lease.advanceFixtureClock(Duration.ofSeconds(61));assertEquals(200,proof(client,lease,response));
            lease.advanceFixtureClock(Duration.ofMillis(expires*1000-lease.identities.timeMillis()));
            assertEquals(401,proof(client,lease,response));
        }
    }
    @Test void hostOwnerAppliesTheSameLifetimeToReplacementLeasesAndSeededCredentials() throws Exception {
        try(var host=LabRun.startHost(spec())) {
            var first=host.prepareCase("BROW.basic.json");long firstGeneration=first.generation();first.close();
            try(var next=host.prepareCase("BROW.basic.json")) {
                assertTrue(next.generation()>firstGeneration);
                var supplied=Map.of(FixtureIdentityStore.Role.B,next.seeded("s0").credential(FixtureIdentityStore.Role.B).reveal());
                next.advanceFixtureClock(Duration.ofSeconds(61));assertNotNull(next.identities.accept(supplied,false));
                next.advanceFixtureClock(Duration.ofSeconds(3540));assertNull(next.identities.accept(supplied,false));
            }
        }
    }
    @Test void lifetimeBoundsAndClockOverflowCannotChangeAnExistingOwner() {
        for(long invalid:List.of(-1L,0L,3601L,Long.MAX_VALUE))
            assertThrows(IllegalArgumentException.class,()->new FixtureIdentityStore(invalid));
        var owner=new FixtureIdentityStore(3600);
        var supplied=Map.of(FixtureIdentityStore.Role.B,owner.seeded("s0").credential(FixtureIdentityStore.Role.B).reveal());
        assertThrows(ArithmeticException.class,()->owner.advance(Duration.ofMillis(Long.MAX_VALUE)));
        assertNotNull(owner.accept(supplied,false));
        owner.advance(Duration.ofSeconds(3601));assertNull(owner.accept(supplied,false));
    }
    private static HttpResponse<String> login(HttpClient client,LabRun.CaseLease lease,boolean signed) throws Exception {
        var response=send(client,lease.endpoint(signed?"login/jwt":"login/json"),"POST","{\"username\":\"user\",\"password\":\"pass\"}","application/json");
        assertEquals(200,response.statusCode());return response;
    }
    private static int proof(HttpClient client,LabRun.CaseLease lease,HttpResponse<String> login) throws Exception {
        return client.send(HttpRequest.newBuilder(lease.endpoint("protected/b_c1"))
                .header("Authorization","Bearer "+json(login).get("access_token").getAsString())
                .header("Cookie","LAB_C1="+cookie(login,"LAB_C1")).GET().build(),HttpResponse.BodyHandlers.discarding()).statusCode();
    }
}
