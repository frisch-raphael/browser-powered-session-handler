package lab.auth;

import com.google.gson.JsonObject;
import java.util.List;
import java.util.Set;

/** Safe observations of whole-request rejection at the real component hook boundary. */
final class LabTagFailureEvidence {
    private LabTagFailureEvidence() {}
    static boolean supports(String id){return id.equals("CORE.diagnostics.unresolved-tag")||Set.of("unknown","deleted","ambiguous","paused","malformed","incomplete-selector","mixed-valid-invalid","unsupported-body","invalid-header-output").stream().anyMatch(s->id.equals("CORE.tag-failure."+s));}
    static boolean valid(String id,JsonObject actual) {
        try {
            if(id.equals("CORE.diagnostics.unresolved-tag")) {
                var flags=Set.of("requestStopped","sourceUnchanged","noReplacement","correctAlias","requestMessageMatches","logMessageMatches","currentRevision","forbiddenClaimAbsent","redacted");var fields=new java.util.HashSet<>(flags);fields.addAll(Set.of("nativePhase","nativeCause","waitingRequests","pendingWorkers","extraAttempts"));
                return actual.keySet().equals(fields)&&LabRun.text(actual,"nativePhase").equals("STEP")&&LabRun.text(actual,"nativeCause").equals("CONFIGURATION")&&flags.stream().allMatch(k->LabLifetimeEvidence.b(actual,k))&&LabLifetimeEvidence.n(actual,"waitingRequests")==0&&LabLifetimeEvidence.n(actual,"pendingWorkers")==0&&LabLifetimeEvidence.n(actual,"extraAttempts")==0;
            }
            return supports(id)&&LabLifetimeEvidence.keys(actual,"cause","drop","sourceUnchanged","noReplacement","extraAttemptsOnDrop","waitingRequests","pendingWorkers","replaySends")
                &&LabRun.text(actual,"cause").equals(id.endsWith("paused")?"AUTH_REJECTED":id.endsWith("invalid-header-output")?"EXTRACTION":"CONFIGURATION")&&LabRun.text(actual,"drop").equals("DROP")
                &&LabLifetimeEvidence.b(actual,"sourceUnchanged")&&LabLifetimeEvidence.b(actual,"noReplacement")&&LabLifetimeEvidence.n(actual,"extraAttemptsOnDrop")==0
                &&LabLifetimeEvidence.n(actual,"waitingRequests")==0&&LabLifetimeEvidence.n(actual,"pendingWorkers")==0&&LabLifetimeEvidence.n(actual,"replaySends")==0;
        }catch(RuntimeException malformed){return false;}
    }
    static List<ScenarioCatalog.Fact> facts(String id,JsonObject actual) {
        if(id.equals("CORE.diagnostics.unresolved-tag"))return valid(id,actual)?List.of(new ScenarioCatalog.Fact("stage","request"),new ScenarioCatalog.Fact("cause","unresolved-reference"),new ScenarioCatalog.Fact("requiredMessageFact","unresolved-tag-request-stopped"),new ScenarioCatalog.Fact("forbiddenMessageClaim","connection-failed"),new ScenarioCatalog.Fact("currentRevision","current-attempt-only"),new ScenarioCatalog.Fact("redaction","no-secrets-or-sensitive-urls")):List.of();
        return valid(id,actual)?List.of(new ScenarioCatalog.Fact("actions","0"),new ScenarioCatalog.Fact("publication","no-partial-plan"),new ScenarioCatalog.Fact("outcome","whole-tagged-request-stopped-with-no-partial-transformation")):List.of();
    }
}
