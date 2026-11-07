package lab.auth;

import com.google.gson.*;
import java.util.*;

/** Checks observations from the existing extractor/coordinator owners, including absent publication. */
final class LabOutputEvidence {
    private LabOutputEvidence() {}
    static boolean supports(String id){return id.startsWith("CORE.outputs.");}
    private static boolean b(JsonObject value,String key){return LabLifetimeEvidence.b(value,key);}
    private static long n(JsonObject value,String key){return LabLifetimeEvidence.n(value,key);}
    static boolean valid(String id,JsonObject actual) {
        try {
            if(id.equals("CORE.outputs.late-retired-attempt"))return LabLifetimeEvidence.keys(actual,"retiredCause","unloadedCause","retiredPublished","unloadedPublished","waitingRequests","newerPublished","replacementWaitedForOldWorker","obsoleteGeneration","newerGeneration","lateRetiredPublished")&&LabRun.text(actual,"retiredCause").equals("STALE")&&LabRun.text(actual,"unloadedCause").equals("CLOSED")&&!b(actual,"retiredPublished")&&!b(actual,"unloadedPublished")&&n(actual,"waitingRequests")==0&&b(actual,"newerPublished")&&b(actual,"replacementWaitedForOldWorker")&&!b(actual,"lateRetiredPublished")&&n(actual,"newerGeneration")>n(actual,"obsoleteGeneration");
            boolean missing=id.equals("CORE.outputs.missing-member"),expired=id.equals("CORE.outputs.one-member-expired"),negative=missing||expired;
            var fields=new HashSet<>(Set.of("published","values","sameIdentity","namedValuesMatch","cookiesMatch","waitingRequests","arrivalOrder"));
            fields.addAll(negative?Set.of("initiallyComplete","finallyComplete","failureCause"):Set.of("incompleteBeforeLastMember","expirySeconds","wholeSetExpiredAtBoundary","deletedCookieRemovesCompleteSet"));
            if(!actual.keySet().equals(fields)||b(actual,"published")==negative||n(actual,"values")!=(negative?0:3)||!b(actual,"sameIdentity")||b(actual,"namedValuesMatch")==negative||b(actual,"cookiesMatch")==negative||n(actual,"waitingRequests")!=0)return false;
            var expected=id.equals("CORE.outputs.cookie-before-token")?List.of("session","access","other"):missing?List.of("access","other"):List.of("access","other","session");
            var order=actual.getAsJsonArray("arrivalOrder");if(order.size()!=expected.size())return false;for(int index=0;index<order.size();index++)if(!order.get(index).getAsString().equals(expected.get(index)))return false;
            if(negative)return b(actual,"initiallyComplete")==expired&&!b(actual,"finallyComplete")&&(missing?LabRun.text(actual,"failureCause").equals("EXTRACTION"):Set.of("EXTRACTION","TOKEN_EXPIRED").contains(LabRun.text(actual,"failureCause")));
            if(!Set.of("CORE.outputs.complete-set","CORE.outputs.token-before-cookie","CORE.outputs.cookie-before-token").contains(id))return false;
            var incomplete=actual.getAsJsonArray("incompleteBeforeLastMember");if(incomplete.size()!=2)return false;
            for(var value:incomplete)if(!value.getAsJsonPrimitive().isBoolean()||!value.getAsBoolean())return false;
            return n(actual,"expirySeconds")==2_000_000_020L&&b(actual,"wholeSetExpiredAtBoundary")&&b(actual,"deletedCookieRemovesCompleteSet");
        }catch(RuntimeException malformed){return false;}
    }
    static List<ScenarioCatalog.Fact> facts(String id,JsonObject actual){return valid(id,actual)?List.of(new ScenarioCatalog.Fact("outcome","Atomic complete publication with correct generation/issuance."),new ScenarioCatalog.Fact("publication",id.equals("CORE.outputs.late-retired-attempt")?"newer-revision-only":b(actual,"published")?"atomic-complete-same-journey-set":"no-partial-set")):List.of();}
}
