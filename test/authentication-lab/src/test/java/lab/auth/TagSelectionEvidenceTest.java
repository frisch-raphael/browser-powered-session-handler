package lab.auth;

import org.junit.jupiter.api.Test;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class TagSelectionEvidenceTest {
    @Test void correctAccountsCannotHideSubstitutedLoginIssuances() {
        String id="CORE.tag-selection.same-account-distinct-journeys";
        var proofs=new java.util.ArrayList<Map<String,Object>>();
        for(int i=0;i<4;i++)proofs.add(Map.of("alias",i%2==0?"employee":"admin","account","user2","issuance",i==0?"s6":i==2?"s8":"s7","status",200));
        var actual=LabRun.JSON.toJsonTree(Map.of("proofs",proofs,"attempts",3,"distinctIssuances",3,"unaffectedJourneyPreserved",true,"waitingRequests",0)).getAsJsonObject();
        assertTrue(LabTagSelectionEvidence.valid(id,actual));
        actual.getAsJsonArray("proofs").get(0).getAsJsonObject().addProperty("issuance","s7");assertFalse(LabTagSelectionEvidence.valid(id,actual));
    }
    @Test void namedValuesMustComeFromOneAcquisitionAndOneUnchangedSnapshot() {
        String id="CORE.tag-selection.three-outputs";
        var actual=LabRun.JSON.toJsonTree(Map.of("outputs",3,"bytesMatch",true,"namedSnapshotMatches",true,"sameVersion",true,"usedSnapshots",1,"attempts",1,"unselectedCookieAbsent",true,"disabledOutputAbsent",true,"waitingRequests",0)).getAsJsonObject();
        assertTrue(LabTagSelectionEvidence.valid(id,actual));
        actual.addProperty("attempts",3);assertTrue(LabTagSelectionEvidence.facts(id,actual).isEmpty());
        actual.addProperty("attempts",1);actual.addProperty("sameVersion",false);assertFalse(LabTagSelectionEvidence.valid(id,actual));
    }
    @Test void repeatedReferencesCannotHideAnAbsentThirdJourney() {
        String id="CORE.tag-selection.three-identities";
        var actual=LabRun.JSON.toJsonTree(Map.of("location","header","mode","raw","references",3,"plans",2,"bytesMatch",true,"snapshotVersionsMatch",true,"cachedBytesMatch",true,"extraAttemptsOnCacheUse",0,"attempts",4,"usedSnapshots",4)).getAsJsonObject();
        actual.addProperty("waitingRequests",0);assertTrue(LabTagSelectionEvidence.valid(id,actual));
        actual.addProperty("usedSnapshots",3);assertFalse(LabTagSelectionEvidence.valid(id,actual));
    }
}
