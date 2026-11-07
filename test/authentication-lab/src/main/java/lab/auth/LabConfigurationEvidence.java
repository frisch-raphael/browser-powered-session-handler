package lab.auth;

import com.google.gson.JsonObject;
import java.util.List;
import java.util.Set;

/** Runtime postconditions of the existing registry, editor and native-storage owners. */
final class LabConfigurationEvidence {
    private LabConfigurationEvidence() {}
    static boolean supports(String id){return id.startsWith("CORE.registry.")||id.startsWith("CORE.storage.");}
    private static boolean flags(JsonObject a,String... fields){return LabLifetimeEvidence.keys(a,fields)&&java.util.Arrays.stream(fields).allMatch(k->LabLifetimeEvidence.b(a,k));}
    static boolean valid(String id,JsonObject a) {
        try {
            if(id.equals("CORE.registry.edit-during-login"))return LabOutputEvidence.valid("CORE.outputs.late-retired-attempt",a);
            if(id.equals("CORE.registry.alias-conflict"))return LabLifetimeEvidence.keys(a,"entriesDuringConflict","oldRetired","resolutionBlocked","restoredNewGeneration")&&LabLifetimeEvidence.n(a,"entriesDuringConflict")==2&&LabLifetimeEvidence.b(a,"oldRetired")&&LabLifetimeEvidence.b(a,"resolutionBlocked")&&LabLifetimeEvidence.b(a,"restoredNewGeneration");
            if(Set.of("CORE.registry.retired-alias","CORE.registry.explicit-reassignment").contains(id))return flags(a,"oldAliasUnavailable","replacementSelected","originalAliasPreserved","collisionBlocked","deletedUnavailable","replacementHasNewId");
            if(Set.of("CORE.registry.display-rename","CORE.registry.case-only-rename").contains(id))return flags(a,"displayRetainsIdentity","caseRetainsIdentity","secretRetires","reloadRetires","deleteRetires");
            if(id.equals("CORE.registry.library-change"))return LabLifetimeEvidence.keys(a,"alias","journeys","draftRejected","epochAdvanced")&&LabRun.text(a,"alias").equals("external")&&LabLifetimeEvidence.n(a,"journeys")==1&&LabLifetimeEvidence.b(a,"draftRejected")&&LabLifetimeEvidence.b(a,"epochAdvanced");
            if(Set.of("CORE.registry.delete-during-login","CORE.registry.healthy-unrelated").contains(id))return LabLifetimeEvidence.keys(a,"deletedCause","deletedPublished","otherIdentityUnchanged","otherCompleted","otherPublished","waitingRequests","runningAttempts","queuedCycles")
                &&LabRun.text(a,"deletedCause").equals("STALE")&&!LabLifetimeEvidence.b(a,"deletedPublished")&&LabLifetimeEvidence.b(a,"otherIdentityUnchanged")&&LabLifetimeEvidence.b(a,"otherCompleted")&&LabLifetimeEvidence.b(a,"otherPublished")
                &&LabLifetimeEvidence.n(a,"waitingRequests")==0&&LabLifetimeEvidence.n(a,"runningAttempts")==0&&LabLifetimeEvidence.n(a,"queuedCycles")==0;
            if(id.equals("CORE.registry.missing-secret")) {
                var fields=Set.of("nativePhase","nativeCause","summaryMatches","detailsMatch","stateMatches","currentRevision","requestFeedbackMatches","requiredMessageMatches","forbiddenClaimAbsent","redacted","noPartialPublication","stepAttributionMatches","stepLinkCurrent","stepLinkRetired");
                return a.keySet().equals(fields)&&LabRun.text(a,"nativePhase").equals("SETUP")&&LabRun.text(a,"nativeCause").equals("MISSING_SECRET")&&fields.stream().filter(k->!k.startsWith("native")).allMatch(k->LabLifetimeEvidence.b(a,k));
            }
            if(Set.of("CORE.storage.project-roundtrip","CORE.storage.export-roundtrip").contains(id)) {
                if(!LabLifetimeEvidence.keys(a,"kinds","definitionsMatch","revisionsMatch","controlsMatch")||!LabLifetimeEvidence.b(a,"definitionsMatch")||!LabLifetimeEvidence.b(a,"revisionsMatch")||!LabLifetimeEvidence.b(a,"controlsMatch"))return false;
                var kinds=new java.util.HashSet<String>();a.getAsJsonArray("kinds").forEach(v->kinds.add(v.getAsString()));return a.getAsJsonArray("kinds").size()==3&&kinds.equals(Set.of("PROJECT","LIBRARY","EXPORT"));
            }
            if(Set.of("CORE.storage.library-roundtrip","CORE.storage.rollback").contains(id))return flags(a,"versionMatches","definitionsMatch","newRevision","shaValid","oldFilesPreserved","legacyNotImported");
            if(id.equals("CORE.storage.unsupported-load-preserves"))return LabLifetimeEvidence.keys(a,"checked","preserved","loadRejected","saveRejected")&&List.of("checked","preserved","loadRejected","saveRejected").stream().allMatch(k->LabLifetimeEvidence.n(a,k)==3);
            if(id.equals("CORE.storage.failed-write-preserves"))return flags(a,"failed","primaryPreserved","unrelatedPreserved","ownedTempsAbsent");
            return id.equals("CORE.storage.mixed-version")&&LabLifetimeEvidence.keys(a,"projectUnavailable","nativePreserved","legacyPreserved","priorNativePreserved","statusVisible","pendingWorkers")
                &&List.of("projectUnavailable","nativePreserved","legacyPreserved","priorNativePreserved","statusVisible").stream().allMatch(k->LabLifetimeEvidence.b(a,k))&&LabLifetimeEvidence.n(a,"pendingWorkers")==0;
        }catch(RuntimeException malformed){return false;}
    }
    static List<ScenarioCatalog.Fact> facts(String id,JsonObject a){return valid(id,a)?List.of(new ScenarioCatalog.Fact("outcome",id.startsWith("CORE.registry.")?"No identity switch or stale publication; correct unaffected journey behavior.":"Declared compatibility and preservation rules; no legacy importer.")):List.of();}
}
