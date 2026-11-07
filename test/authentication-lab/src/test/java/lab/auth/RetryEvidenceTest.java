package lab.auth;

import com.google.gson.*;
import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** Prevents unrelated acquisitions or another caller's budget from hiding extra attempts. */
class RetryEvidenceTest {
    @Test void subresourceFailureNeedsAnObservedSingleClosedBrowserAndTerminalClassification() {
        String id="CORE.retry.subresource-error";var a=LabRun.JSON.toJsonTree(Map.of("attempts",1,"assetRequests",1,"cause","EXTRACTION","retryable",false,"orderedCleanup",true,"resources",2,"drivers",1,"processes",8,"alive",0)).getAsJsonObject();
        assertTrue(LabRetryEvidence.valid(id,a));a.addProperty("retryable",true);assertFalse(LabRetryEvidence.valid(id,a));a.addProperty("retryable",false);a.addProperty("alive",1);assertTrue(LabRetryEvidence.facts(id,a).isEmpty());
    }
    static JsonObject third(){return LabRun.JSON.toJsonTree(Map.ofEntries(Map.entry("cause","TRANSPORT"),Map.entry("attempts",3),Map.entry("initialAcquisitions",1),Map.entry("totalAttempts",4),Map.entry("recoveryFlags",List.of(false,false,false)),Map.entry("waitingRequests",0),Map.entry("runningAttempts",0),Map.entry("queuedCycles",0),Map.entry("pendingWorkers",0),Map.entry("phase","READY"),Map.entry("sharedCallers",80),Map.entry("resultAvailable",true))).getAsJsonObject();}
    @Test void separateInitialAcquisitionCannotHideAFourthRecoveryAttemptOrPerCallerCycles() {
        var actual=third();String id="CORE.retry.callers-share-budget";assertTrue(LabRetryEvidence.valid(id,actual));
        for(var wrong:Map.of("attempts",4,"totalAttempts",5,"sharedCallers",1,"waitingRequests",1).entrySet()){var changed=actual.deepCopy();changed.addProperty(wrong.getKey(),wrong.getValue());assertTrue(LabRetryEvidence.facts(id,changed).isEmpty());}
    }
    @Test void automaticRetriesCannotRepeatExplicitPinRecovery() {
        String id="CORE.retry.second-succeeds";var actual=third();actual.addProperty("cause","TEMPORARY_SERVICE");actual.addProperty("attempts",2);actual.addProperty("initialAcquisitions",0);actual.addProperty("totalAttempts",2);actual.addProperty("sharedCallers",1);actual.add("recoveryFlags",LabRun.JSON.toJsonTree(List.of(true,false)));
        assertTrue(LabRetryEvidence.valid(id,actual));actual.add("recoveryFlags",LabRun.JSON.toJsonTree(List.of(true,true)));assertFalse(LabRetryEvidence.valid(id,actual));
    }
    @Test void exhaustingTheBudgetRequiresAnObservedPauseWithoutAUsableResult() {
        String id="CORE.retry.three-fail";var actual=third();actual.addProperty("initialAcquisitions",0);actual.addProperty("totalAttempts",3);actual.addProperty("sharedCallers",1);assertFalse(LabRetryEvidence.valid(id,actual));
        actual.addProperty("phase","PAUSED");actual.addProperty("resultAvailable",false);assertTrue(LabRetryEvidence.valid(id,actual));assertEquals(new HashSet<>(ScenarioCatalog.load().requirement(id).expected()),new HashSet<>(LabRetryEvidence.facts(id,actual)));
        actual.addProperty("pendingWorkers",1);assertFalse(LabRetryEvidence.valid(id,actual));
    }
}
