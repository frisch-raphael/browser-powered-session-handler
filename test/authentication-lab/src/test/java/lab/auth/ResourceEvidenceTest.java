package lab.auth;

import org.junit.jupiter.api.Test;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class ResourceEvidenceTest {
    @Test void manyCallersRequireTheCurrentFiniteDefaultsAndExplicitLargerLimits() {
        String id="CORE.resources.waiter-unlimited";
        var actual=LabRun.JSON.toJsonTree(Map.of("callers",100,"completed",100,"configuredGlobal",256,"configuredPerJourney",256,
                "defaultGlobal",64,"defaultPerJourney",16,"attempts",1,"waitingRequests",0)).getAsJsonObject();
        assertTrue(LabResourceEvidence.valid(id,actual));
        for(String key:java.util.List.of("configuredGlobal","configuredPerJourney","defaultGlobal","defaultPerJourney","completed")) {
            var changed=actual.deepCopy();changed.addProperty(key,0);assertFalse(LabResourceEvidence.valid(id,changed));
        }
        var disabled=actual.deepCopy();disabled.remove("defaultGlobal");disabled.addProperty("limitsDisabled",true);assertFalse(LabResourceEvidence.valid(id,disabled));
    }
    @Test void clearingWaitersCannotHideARunningWorkerAfterUnload() {
        String id="CORE.resources.unload-backoff";var a=LabRun.JSON.toJsonTree(Map.of("cause","CLOSED","extraAttempts",0,"timers",0,"pendingWorkers",0,"published",false,"waitingRequests",0,"runningAttempts",0,"queuedCycles",0)).getAsJsonObject();
        assertTrue(LabResourceEvidence.valid(id,a));a.addProperty("runningAttempts",1);assertTrue(LabResourceEvidence.facts(id,a).isEmpty());
    }
    @Test void oneCallersTimeoutMustPreserveTheOtherCallersActualBudgetAndSuccess() {
        String id="CORE.resources.one-caller-timeout";var a=LabRun.JSON.toJsonTree(Map.of("timedOutCause","TIMEOUT","otherCompleted",true,"thirdCancelled",true,"attempts",1,"deadlineNanos",11_000_000_000L,"waitingRequests",0)).getAsJsonObject();
        assertTrue(LabResourceEvidence.valid(id,a));a.addProperty("deadlineNanos",10_500_000_000L);assertFalse(LabResourceEvidence.valid(id,a));
    }
}
