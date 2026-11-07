package lab.auth;

import com.google.gson.*;
import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** Prevents a successful login or cleanup for one case from qualifying a different result. */
class BrowserEvidenceTest {
    static JsonObject actual(String id,String account,String role) {
        return LabRun.JSON.toJsonTree(Map.of("sourceCase",id,"snapshot",Map.of("runId",UUID.randomUUID().toString(),"caseId",id,"generation",1,"state","CLOSED","truncated",false,"counters",Map.of("actions",0),"events",List.of(Map.of("name","login-completed","safeIds",List.of(Map.of("kind","issuance","value","s6"))))),
                "proofs",List.of(Map.of("status",200,"account",account,"issuance","s6","roles",List.of(role))),"failures",List.of(),
                "attempts",List.of(Map.of("contextId",17,"contextsClosed",1,"browsersOpened",1,"browsersClosed",1,"drivers",1,"observedProcesses",6,"alive",0)))).getAsJsonObject();
    }
    @Test void wrongAccountOldIssuanceOrWrongOutputCannotQualifyAnOtherwiseSuccessfulLogin() {
        String id="BROW.basic.json";var original=actual(id,"admin","B");assertTrue(LabBrowserEvidence.valid(id,original));
        assertEquals(ScenarioCatalog.load().requirement(id).expected(),LabBrowserEvidence.facts(id,original));
        for(var substitution:Map.of("account","user2","issuance","older-login").entrySet()) {
            var changed=original.deepCopy();changed.getAsJsonArray("proofs").get(0).getAsJsonObject().addProperty(substitution.getKey(),substitution.getValue());assertTrue(LabBrowserEvidence.facts(id,changed).isEmpty());
        }
        var wrongRole=original.deepCopy();wrongRole.getAsJsonArray("proofs").get(0).getAsJsonObject().add("roles",LabRun.JSON.toJsonTree(List.of("C1")));assertFalse(LabBrowserEvidence.valid(id,wrongRole));
    }
    @Test void liveMissingOrRepeatedBrowserCannotQualifyCleanupAndCancellationDoesNotInventGracefulEvents() {
        String id="BROW.basic.json";var original=actual(id,"admin","B");
        for(var corruption:Map.of("alive",1,"drivers",0,"contextsClosed",0).entrySet()) {
            var changed=original.deepCopy();changed.getAsJsonArray("attempts").get(0).getAsJsonObject().addProperty(corruption.getKey(),corruption.getValue());assertFalse(LabBrowserEvidence.valid(id,changed));
        }
        var repeated=original.deepCopy();repeated.getAsJsonArray("attempts").add(repeated.getAsJsonArray("attempts").get(0).deepCopy());assertFalse(LabBrowserEvidence.valid(id,repeated));
        String cancelled="BROW.redirect-failure.cancel-before-callback";var forced=actual(cancelled,"user2","B");forced.add("proofs",new JsonArray());forced.getAsJsonObject("snapshot").add("events",new JsonArray());forced.add("failures",LabRun.JSON.toJsonTree(List.of(Map.of("cause","CANCELLED","phase","LIFECYCLE"))));
        var attempt=forced.getAsJsonArray("attempts").get(0).getAsJsonObject();for(String field:List.of("contextId","contextsClosed","browsersOpened","browsersClosed"))attempt.addProperty(field,0);
        assertTrue(LabBrowserEvidence.valid(cancelled,forced));attempt.addProperty("alive",1);assertFalse(LabBrowserEvidence.valid(cancelled,forced));
    }
    @Test void sameNameDomainAliasSharesOnlyTheExistingTwoOriginCookieProof() {
        String id="BROW.cookie-selection.same-name-domains";var actual=actual("BROW.cookie-selection.idp-client-decoy","user2","C1");assertFalse(LabBrowserEvidence.valid(id,actual),"A normal cookie login cannot qualify an unobserved competing-origin cookie.");
        actual.getAsJsonObject("snapshot").getAsJsonArray("events").add(LabRun.JSON.toJsonTree(Map.of("name","decoy-cookie-set","safeIds",List.of(Map.of("kind","origin","value","alternate")))));assertTrue(LabBrowserEvidence.valid(id,actual));
        actual.addProperty("sourceCase","BROW.basic.cookie-one");actual.getAsJsonObject("snapshot").addProperty("caseId","BROW.basic.cookie-one");assertFalse(LabBrowserEvidence.valid(id,actual));
    }
    @Test void surfaceOutputAloneCannotSubstituteForActualPageCompletion() {
        String id="BROW.surfaces.popup";var actual=actual(id,"user2","B");assertFalse(LabBrowserEvidence.valid(id,actual));
        for(String name:List.of("page-popup-parent-ready","page-popup-parent-done"))actual.getAsJsonObject("snapshot").getAsJsonArray("events").add(LabRun.JSON.toJsonTree(Map.of("name",name,"safeIds",List.of())));
        assertTrue(LabBrowserEvidence.valid(id,actual));actual.getAsJsonObject("snapshot").addProperty("truncated",true);assertFalse(LabBrowserEvidence.valid(id,actual));
    }
    @Test void recoveryRequiresSerialClosedBrowsersAndOneSharedThreeAttemptCycle() {
        var actual=new JsonObject();var counts=Map.ofEntries(Map.entry("loginRequests",4),Map.entry("issuedCredentials",2),Map.entry("protectedIngress",17),Map.entry("acceptedRequests",9),Map.entry("recoveryAttempts",3),Map.entry("originals",8),Map.entry("replays",8),Map.entry("browsersOpened",4),Map.entry("browsersClosed",4),Map.entry("contextsOpened",4),Map.entry("contextsClosed",4),Map.entry("distinctResources",8),Map.entry("drivers",4),Map.entry("processes",40),Map.entry("alive",0));
        counts.forEach(actual::addProperty);actual.addProperty("acceptedUse",true);var events=new JsonArray();
        for(int index=0;index<4;index++) {
            long browser=index*2+1,context=browser+1;
            for(var event:List.of(Map.of("event","BROWSER_OPEN","resource",browser,"parent",0L),Map.of("event","CONTEXT_OPEN","resource",context,"parent",browser),Map.of("event","CONTEXT_CLOSED","resource",context,"parent",browser),Map.of("event","BROWSER_CLOSED","resource",browser,"parent",0L)))events.add(LabRun.JSON.toJsonTree(event));
        }
        actual.add("events",events);assertTrue(LabRecoveryBrowserEvidence.valid(actual));
        var parallel=actual.deepCopy();parallel.getAsJsonArray("events").set(1,events.get(4).deepCopy());assertFalse(LabRecoveryBrowserEvidence.valid(parallel));
        actual.addProperty("recoveryAttempts",4);assertFalse(LabRecoveryBrowserEvidence.valid(actual));actual.addProperty("recoveryAttempts",3);actual.addProperty("alive",1);assertFalse(LabRecoveryBrowserEvidence.valid(actual));
    }
}
