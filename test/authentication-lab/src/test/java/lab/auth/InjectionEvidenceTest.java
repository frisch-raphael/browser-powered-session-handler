package lab.auth;

import org.junit.jupiter.api.Test;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class InjectionEvidenceTest {
    @Test void successfulBearerUseCannotProveACombinedCookieAndBearerRequest() {
        String id="CORE.injection.combined";var actual=LabRun.JSON.toJsonTree(Map.of("mode","AUTOMATIC","combined",true,"bytesMatch",true,"status",200,"account","user2","issuance","s6","expectedIssuance","s6","roles",List.of("B","C1"),"attempts",1,"waitingRequests",0)).getAsJsonObject();
        assertTrue(LabInjectionEvidence.valid(id,actual));actual.add("roles",LabRun.JSON.toJsonTree(List.of("B")));assertFalse(LabInjectionEvidence.valid(id,actual));
    }
    @Test void changingSelectionMustActuallyAuthenticateAsTheNewAccount() {
        String id="CORE.injection.selected-journey-change";
        var actual=LabRun.JSON.toJsonTree(Map.of("proofs",List.of(Map.of("account","user2","issuance","s8","status",200),Map.of("account","admin","issuance","s7","status",200)),"bytesMatch",true,"sameVersion",true,"attempts",3,"waitingRequests",0)).getAsJsonObject();
        assertTrue(LabInjectionEvidence.valid(id,actual));actual.getAsJsonArray("proofs").get(1).getAsJsonObject().addProperty("account","user2");assertTrue(LabInjectionEvidence.facts(id,actual).isEmpty());
    }
}
