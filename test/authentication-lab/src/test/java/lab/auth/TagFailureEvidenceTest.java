package lab.auth;

import org.junit.jupiter.api.Test;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class TagFailureEvidenceTest {
    @Test void unresolvedAliasMustHaveMatchingRequestAndLogFeedbackWithoutChangingAnotherJourney() {
        String id="CORE.diagnostics.unresolved-tag";var actual=new com.google.gson.JsonObject();actual.addProperty("nativePhase","STEP");actual.addProperty("nativeCause","CONFIGURATION");
        for(String flag:java.util.List.of("requestStopped","sourceUnchanged","noReplacement","correctAlias","requestMessageMatches","logMessageMatches","currentRevision","forbiddenClaimAbsent","redacted"))actual.addProperty(flag,true);
        for(String counter:java.util.List.of("waitingRequests","pendingWorkers","extraAttempts"))actual.addProperty(counter,0);
        assertTrue(LabTagFailureEvidence.valid(id,actual));actual.addProperty("logMessageMatches",false);assertTrue(LabTagFailureEvidence.facts(id,actual).isEmpty());
    }
    @Test void unchangedBytesAreInsufficientWhenTheFailedRequestWasForwarded() {
        String id="CORE.tag-failure.unknown";var actual=LabRun.JSON.toJsonTree(Map.of("cause","CONFIGURATION","drop","DROP","sourceUnchanged",true,"noReplacement",true,"extraAttemptsOnDrop",0,"waitingRequests",0,"pendingWorkers",0,"replaySends",0)).getAsJsonObject();
        assertTrue(LabTagFailureEvidence.valid(id,actual));actual.addProperty("drop","CONTINUE");assertTrue(LabTagFailureEvidence.facts(id,actual).isEmpty());
    }
    @Test void pausedRequestCannotRestartAuthenticationOrLeaveAReplayPending() {
        String id="CORE.tag-failure.paused";var actual=LabRun.JSON.toJsonTree(Map.of("cause","AUTH_REJECTED","drop","DROP","sourceUnchanged",true,"noReplacement",true,"extraAttemptsOnDrop",0,"waitingRequests",0,"pendingWorkers",0,"replaySends",0)).getAsJsonObject();
        assertTrue(LabTagFailureEvidence.valid(id,actual));actual.addProperty("extraAttemptsOnDrop",1);assertFalse(LabTagFailureEvidence.valid(id,actual));actual.addProperty("extraAttemptsOnDrop",0);actual.addProperty("replaySends",1);assertFalse(LabTagFailureEvidence.valid(id,actual));
    }
}
