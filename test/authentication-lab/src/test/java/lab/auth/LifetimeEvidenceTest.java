package lab.auth;

import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** Prevents expiry, revocation and old-response observations from being substituted for one another. */
class LifetimeEvidenceTest {
    @Test void fractionalExpiryCannotBeRoundedUpToAnotherSecond() {
        String id="CORE.lifetime.exact-expiry";var actual=LabRun.JSON.toJsonTree(Map.of("expiredCause","TOKEN_EXPIRED","remainingNanos",100_000_000L,"refreshNanos",50_000_000L,"maxAgeCapNanos",86_400_000_000_000L)).getAsJsonObject();
        assertTrue(LabLifetimeEvidence.valid(id,actual));actual.addProperty("remainingNanos",1_000_000_000L);assertTrue(LabLifetimeEvidence.facts(id,actual).isEmpty());
    }
    @Test void aNewVersionMustSurviveTheOld401WhileItsOwn401StillInvalidatesIt() {
        String id="CORE.lifetime.late-old-401";var actual=LabRun.JSON.toJsonTree(Map.of("oldVersion",1,"newVersion",2,"lateInvalidated",0,"latePreservedCurrent",true,"currentInvalidated",1,"repeatedInvalidated",0,"bodyReads",0)).getAsJsonObject();assertTrue(LabLifetimeEvidence.valid(id,actual));
        for(var wrong:Map.of("newVersion",1,"lateInvalidated",1,"bodyReads",1).entrySet()){var changed=actual.deepCopy();changed.addProperty(wrong.getKey(),wrong.getValue());assertFalse(LabLifetimeEvidence.valid(id,changed));}
    }
    @Test void serverRevocationNeedsARejectedOldCredentialAndDifferentUsableReplacementForTheSameAccount() {
        String id="CORE.lifetime.server-revoked";var actual=LabRun.JSON.toJsonTree(Map.of("initialAccount","user2","initialIssuance","s6","originalStatus",401,"replacementAccount","user2","replacementIssuance","s7","replacementStatus",200,"recoveryAttempts",1,"replays",1,"waitingRequests",0)).getAsJsonObject();assertTrue(LabLifetimeEvidence.valid(id,actual));
        for(var wrong:Map.of("replacementAccount","admin","replacementIssuance","s6").entrySet()){var changed=actual.deepCopy();changed.addProperty(wrong.getKey(),wrong.getValue());assertFalse(LabLifetimeEvidence.valid(id,changed));}
        actual.addProperty("originalStatus",200);assertFalse(LabLifetimeEvidence.valid(id,actual));
    }
}
