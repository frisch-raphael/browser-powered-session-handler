package lab.auth;

import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** Guards publication claims against missing members and stale generations. */
class OutputEvidenceTest {
    @Test void partialAcquisitionCannotQualifyCompletePublication() {
        String id="CORE.outputs.missing-member";var actual=LabRun.JSON.toJsonTree(Map.of("published",false,"values",0,"sameIdentity",true,"namedValuesMatch",false,"cookiesMatch",false,"waitingRequests",0,"arrivalOrder",List.of("access","other"),"initiallyComplete",false,"finallyComplete",false,"failureCause","EXTRACTION")).getAsJsonObject();
        assertTrue(LabOutputEvidence.valid(id,actual));assertEquals(new HashSet<>(ScenarioCatalog.load().requirement(id).expected()),new HashSet<>(LabOutputEvidence.facts(id,actual)));actual.addProperty("published",true);assertTrue(LabOutputEvidence.facts(id,actual).isEmpty());actual.addProperty("published",false);actual.addProperty("values",2);assertFalse(LabOutputEvidence.valid(id,actual));
    }
    @Test void correctValuesCannotHideWrongGenerationOrEarlyPublication() {
        String id="CORE.outputs.cookie-before-token";var actual=LabRun.JSON.toJsonTree(Map.ofEntries(Map.entry("published",true),Map.entry("values",3),Map.entry("sameIdentity",true),Map.entry("namedValuesMatch",true),Map.entry("cookiesMatch",true),Map.entry("waitingRequests",0),Map.entry("arrivalOrder",List.of("session","access","other")),Map.entry("incompleteBeforeLastMember",List.of(true,true)),Map.entry("expirySeconds",2_000_000_020L),Map.entry("wholeSetExpiredAtBoundary",true),Map.entry("deletedCookieRemovesCompleteSet",true))).getAsJsonObject();
        assertTrue(LabOutputEvidence.valid(id,actual));var early=actual.deepCopy();early.add("incompleteBeforeLastMember",LabRun.JSON.toJsonTree(List.of(true,false)));assertFalse(LabOutputEvidence.valid(id,early));actual.addProperty("sameIdentity",false);assertFalse(LabOutputEvidence.valid(id,actual));
    }
    @Test void returningAfterRetirementCannotQualifyACompleteSet() {
        String id="CORE.outputs.late-retired-attempt";var actual=LabRun.JSON.toJsonTree(Map.of("retiredCause","STALE","unloadedCause","CLOSED","retiredPublished",false,"unloadedPublished",false,"waitingRequests",0,"newerPublished",true,"replacementWaitedForOldWorker",true,"lateRetiredPublished",false,"obsoleteGeneration",2,"newerGeneration",3)).getAsJsonObject();assertTrue(LabOutputEvidence.valid(id,actual));assertEquals(new HashSet<>(ScenarioCatalog.load().requirement(id).expected()),new HashSet<>(LabOutputEvidence.facts(id,actual)));actual.addProperty("retiredPublished",true);assertFalse(LabOutputEvidence.valid(id,actual));
    }
}
