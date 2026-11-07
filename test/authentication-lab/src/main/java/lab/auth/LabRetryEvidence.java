package lab.auth;

import com.google.gson.*;
import java.util.*;

/** Reads existing coordinator owners' simulated-clock observations; contains no retry implementation. */
final class LabRetryEvidence {
    private LabRetryEvidence() {}
    static final Set<String> IDS=Set.of("CORE.retry.second-succeeds","CORE.retry.third-succeeds","CORE.retry.three-fail","CORE.retry.callers-share-budget","CORE.retry.cancel-backoff","CORE.retry.deadline-backoff","CORE.retry.nontransient","CORE.retry.PIN-rejected","CORE.retry.PIN-unknown");
    static boolean supports(String id){return IDS.contains(id)||id.equals("CORE.retry.subresource-error");}
    private static long n(JsonObject value,String key){return LabRun.number(value,key,true);}
    private static String s(JsonObject value,String key){return LabRun.text(value,key);}
    static boolean valid(String id,JsonObject actual) {
        try {
            if(id.equals("CORE.retry.subresource-error"))return LabLifetimeEvidence.keys(actual,"attempts","assetRequests","cause","retryable","orderedCleanup","resources","drivers","processes","alive")
                &&n(actual,"attempts")==1&&n(actual,"assetRequests")==1&&s(actual,"cause").equals("EXTRACTION")&&!LabLifetimeEvidence.b(actual,"retryable")&&LabLifetimeEvidence.b(actual,"orderedCleanup")&&n(actual,"resources")==2&&n(actual,"drivers")==1&&n(actual,"processes")>=2&&n(actual,"alive")==0;
            if(!supports(id)||!actual.keySet().equals(Set.of("cause","attempts","initialAcquisitions","totalAttempts","recoveryFlags","waitingRequests","runningAttempts","queuedCycles","pendingWorkers","phase","sharedCallers","resultAvailable")))return false;
            int count=id.equals("CORE.retry.second-succeeds")?2:Set.of("CORE.retry.third-succeeds","CORE.retry.three-fail","CORE.retry.callers-share-budget").contains(id)?3:1;
            boolean shared=Set.of("CORE.retry.third-succeeds","CORE.retry.callers-share-budget").contains(id),success=shared||id.equals("CORE.retry.second-succeeds");
            String cause=switch(id) {
                case "CORE.retry.second-succeeds","CORE.retry.deadline-backoff"->"TEMPORARY_SERVICE";case "CORE.retry.cancel-backoff"->"CANCELLED";
                case "CORE.retry.nontransient"->"EXTRACTION";case "CORE.retry.PIN-rejected"->"PIN_REJECTED";case "CORE.retry.PIN-unknown"->"PIN_INDETERMINATE";default->"TRANSPORT";
            };
            if(!s(actual,"cause").equals(cause)||n(actual,"attempts")!=count||n(actual,"initialAcquisitions")!=(shared?1:0)||n(actual,"totalAttempts")!=count+(shared?1:0)||n(actual,"sharedCallers")!=(shared?80:1))return false;
            for(String field:List.of("waitingRequests","runningAttempts","queuedCycles","pendingWorkers"))if(n(actual,field)!=0)return false;
            String phase=success?"READY":id.equals("CORE.retry.three-fail")?"PAUSED":Set.of("CORE.retry.cancel-backoff","CORE.retry.deadline-backoff").contains(id)?"COOLDOWN":"FAILED";
            if(!actual.get("resultAvailable").getAsJsonPrimitive().isBoolean()||actual.get("resultAvailable").getAsBoolean()!=success||!s(actual,"phase").equals(phase))return false;
            var flags=actual.getAsJsonArray("recoveryFlags");if(flags.size()!=count)return false;
            for(int index=0;index<flags.size();index++)if(!flags.get(index).getAsJsonPrimitive().isBoolean()||flags.get(index).getAsBoolean()!=(id.equals("CORE.retry.second-succeeds")&&index==0))return false;
            return true;
        }catch(RuntimeException malformed){return false;}
    }
    static List<ScenarioCatalog.Fact> facts(String id,JsonObject actual) {
        if(!valid(id,actual))return List.of();
        String count=Set.of("CORE.retry.callers-share-budget","CORE.retry.cancel-backoff","CORE.retry.deadline-backoff").contains(id)?"at-most-three-including-initial":Long.toString(n(actual,"attempts"));
        var facts=new ArrayList<ScenarioCatalog.Fact>();facts.add(new ScenarioCatalog.Fact("attempts",count));
        facts.add(new ScenarioCatalog.Fact("outcome",id.startsWith("CORE.retry.PIN-")?"PIN-outcome-preserved-no-automatic-resubmission":"At most three total attempts, no PIN resubmission or false retry classification."));
        if(id.equals("CORE.retry.three-fail"))facts.add(new ScenarioCatalog.Fact("state","PAUSED"));return List.copyOf(facts);
    }
}
