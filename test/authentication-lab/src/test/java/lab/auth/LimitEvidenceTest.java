package lab.auth;

import org.junit.jupiter.api.Test;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class LimitEvidenceTest {
    @Test void anOverLimitRejectionCannotProveTheExactBoundaryWasAccepted() {
        var row=ScenarioCatalog.load().requirement("CORE.limits.dimension=output_bytes~point=at");
        var actual=LabRun.JSON.toJsonTree(Map.of("dimension","output_bytes","point","at","value",4<<20,"limit",4<<20,"accepted",true,"bytesMatch",true,"cause","NONE","attempts",2,"sourceUnchanged",true,"waitingRequests",0)).getAsJsonObject();actual.addProperty("pendingWorkers",0);
        assertTrue(LabLimitEvidence.valid(row,actual));actual.addProperty("accepted",false);assertTrue(LabLimitEvidence.facts(row,actual).isEmpty());
    }
    @Test void preflightFailureCannotLeaveAnAcquisitionQueued() {
        var row=ScenarioCatalog.load().requirement("CORE.limits.dimension=reference_count~point=above");
        var actual=LabRun.JSON.toJsonTree(Map.of("dimension","reference_count","point","above","value",17,"limit",16,"accepted",false,"bytesMatch",false,"cause","CONFIGURATION","attempts",0,"sourceUnchanged",true,"waitingRequests",0)).getAsJsonObject();actual.addProperty("pendingWorkers",0);
        assertTrue(LabLimitEvidence.valid(row,actual));actual.addProperty("pendingWorkers",1);assertFalse(LabLimitEvidence.valid(row,actual));
    }
}
