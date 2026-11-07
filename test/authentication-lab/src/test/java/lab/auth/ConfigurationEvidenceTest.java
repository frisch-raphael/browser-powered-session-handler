package lab.auth;

import org.junit.jupiter.api.Test;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class ConfigurationEvidenceTest {
    @Test void deletingOneJourneyCannotQualifyIfTheOtherJourneyIsAlsoRetired() {
        String id="CORE.registry.delete-during-login";var a=LabRun.JSON.toJsonTree(Map.of("deletedCause","STALE","deletedPublished",false,"otherIdentityUnchanged",true,"otherCompleted",true,"otherPublished",true,"waitingRequests",0,"runningAttempts",0,"queuedCycles",0)).getAsJsonObject();
        assertTrue(LabConfigurationEvidence.valid(id,a));a.addProperty("otherIdentityUnchanged",false);assertTrue(LabConfigurationEvidence.facts(id,a).isEmpty());
    }
    @Test void anUnreadableLibraryCannotQualifyBySilentlyCreatingAnEmptyReplacement() {
        String id="CORE.storage.unsupported-load-preserves";var a=LabRun.JSON.toJsonTree(Map.of("checked",3,"preserved",3,"loadRejected",3,"saveRejected",3)).getAsJsonObject();assertTrue(LabConfigurationEvidence.valid(id,a));a.addProperty("preserved",2);assertFalse(LabConfigurationEvidence.valid(id,a));
    }
}
