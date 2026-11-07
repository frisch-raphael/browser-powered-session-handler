package lab.auth;

import org.junit.jupiter.api.Test;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class ResourceEvidenceTest {
    @Test void clearingWaitersCannotHideARunningWorkerAfterUnload() {
        String id="CORE.resources.unload-backoff";var a=LabRun.JSON.toJsonTree(Map.of("cause","CLOSED","extraAttempts",0,"timers",0,"pendingWorkers",0,"published",false,"waitingRequests",0,"runningAttempts",0,"queuedCycles",0)).getAsJsonObject();
        assertTrue(LabResourceEvidence.valid(id,a));a.addProperty("runningAttempts",1);assertTrue(LabResourceEvidence.facts(id,a).isEmpty());
    }
    @Test void oneCallersTimeoutMustPreserveTheOtherCallersActualBudgetAndSuccess() {
        String id="CORE.resources.one-caller-timeout";var a=LabRun.JSON.toJsonTree(Map.of("timedOutCause","TIMEOUT","otherCompleted",true,"thirdCancelled",true,"attempts",1,"deadlineNanos",11_000_000_000L,"waitingRequests",0)).getAsJsonObject();
        assertTrue(LabResourceEvidence.valid(id,a));a.addProperty("deadlineNanos",10_500_000_000L);assertFalse(LabResourceEvidence.valid(id,a));
    }
}
