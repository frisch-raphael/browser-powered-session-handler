package lab.auth;

import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** Rejects byte/character confusion, partial wrapper matches and unsafe-source mutation. */
class EncodingEvidenceTest {
    @Test void characterCountCannotSubstituteForTheActualUtf8BodyLength() {
        String id="CORE.encoding.body-length";var actual=LabRun.JSON.toJsonTree(Map.of("bytesMatch",true,"rebuildBytesMatch",true,"bodyBytes",8,"declaredLength",8,"characters",6,"headerCause","CONFIGURATION","attempts",1,"waitingRequests",0)).getAsJsonObject();assertTrue(LabEncodingEvidence.valid(id,actual));actual.addProperty("declaredLength",6);assertTrue(LabEncodingEvidence.facts(id,actual).isEmpty());
    }
    @Test void oneMatchingWrapperCannotHideAMissingInnerReferenceOrUnescapedNewline() {
        String id="CORE.encoding.multiple-inner-references";var actual=LabRun.JSON.toJsonTree(Map.of("wrapperBytesMatch",true,"initialAttempts",2,"multipleBytesMatch",true,"multipleSnapshots",2,"multipleAttempts",3,"newlineBytesMatch",true,"newlineExtraAttempts",0,"waitingRequests",0)).getAsJsonObject();assertTrue(LabEncodingEvidence.valid(id,actual));actual.addProperty("multipleSnapshots",1);assertFalse(LabEncodingEvidence.valid(id,actual));actual.addProperty("multipleSnapshots",2);actual.addProperty("newlineBytesMatch",false);assertFalse(LabEncodingEvidence.valid(id,actual));
    }
    @Test void rejectedTargetMustLeaveTheOriginalSourceAndReservationsIntact() {
        String id="CORE.encoding.invalid-target";var actual=LabRun.JSON.toJsonTree(Map.of("targetCause","CONFIGURATION","headerCause","CONFIGURATION","sourceUnchanged",true,"attempts",1,"waitingRequests",0,"pendingWorkers",0)).getAsJsonObject();assertTrue(LabEncodingEvidence.valid(id,actual));actual.addProperty("sourceUnchanged",false);assertFalse(LabEncodingEvidence.valid(id,actual));
    }
}
