package lab.auth;

import com.google.gson.JsonObject;
import java.util.List;
import java.util.Set;

/** Observations of bounded coordinator ownership, not browser or operating-system process claims. */
final class LabResourceEvidence {
    private LabResourceEvidence() {}
    static boolean supports(String id){return Set.of("slow-form","held-token","queue-full","waiter-unlimited","waiter-finite","one-caller-timeout","cancel-queued","cancel-running","unload-backoff","late-publication").stream().anyMatch(s->id.equals("CORE.resources."+s));}
    private static long n(JsonObject a,String key){return LabLifetimeEvidence.n(a,key);}
    private static boolean b(JsonObject a,String key){return LabLifetimeEvidence.b(a,key);}
    static boolean valid(String id,JsonObject a) {
        try {
            if(id.endsWith("late-publication"))return LabOutputEvidence.valid("CORE.outputs.late-retired-attempt",a);
            if(id.endsWith("waiter-unlimited"))return LabLifetimeEvidence.keys(a,"callers","completed","limitsDisabled","attempts","waitingRequests")&&n(a,"callers")==100&&n(a,"completed")==100&&b(a,"limitsDisabled")&&n(a,"attempts")==1&&n(a,"waitingRequests")==0;
            if(Set.of("CORE.resources.one-caller-timeout","CORE.resources.slow-form","CORE.resources.held-token").contains(id))return LabLifetimeEvidence.keys(a,"timedOutCause","otherCompleted","thirdCancelled","attempts","deadlineNanos","waitingRequests")&&LabRun.text(a,"timedOutCause").equals("TIMEOUT")&&b(a,"otherCompleted")&&b(a,"thirdCancelled")&&n(a,"attempts")==1&&n(a,"deadlineNanos")==11_000_000_000L&&n(a,"waitingRequests")==0;
            if(id.endsWith("queue-full"))return LabLifetimeEvidence.keys(a,"admitted","fullWaiting","fullRunning","fullQueued","deniedCause","closedCallers","waitingRequests","runningAttempts","queuedCycles")
                &&n(a,"admitted")==34&&n(a,"fullWaiting")==34&&n(a,"fullRunning")==2&&n(a,"fullQueued")==32&&LabRun.text(a,"deniedCause").equals("CAPACITY")&&n(a,"closedCallers")==34&&released(a);
            if(id.endsWith("waiter-finite"))return LabLifetimeEvidence.keys(a,"waitingBefore","rejected","sourceUnchanged","waitingRequests","runningAttempts","queuedCycles")&&n(a,"waitingBefore")==1&&n(a,"rejected")==2&&b(a,"sourceUnchanged")&&released(a);
            if(id.endsWith("cancel-queued"))return LabLifetimeEvidence.keys(a,"cause","cancelledPublished","firstCompleted","secondCompleted","replacementCompleted","waitingRequests","runningAttempts","queuedCycles")&&LabRun.text(a,"cause").equals("CANCELLED")&&!b(a,"cancelledPublished")&&b(a,"firstCompleted")&&b(a,"secondCompleted")&&b(a,"replacementCompleted")&&released(a);
            if(id.endsWith("cancel-running"))return LabLifetimeEvidence.keys(a,"cause","testCause","cancelledPublished","unrelatedCompleted","explicitCompleted","waitingRequests","runningAttempts","queuedCycles")&&LabRun.text(a,"cause").equals("CANCELLED")&&LabRun.text(a,"testCause").equals("CANCELLED")&&!b(a,"cancelledPublished")&&b(a,"unrelatedCompleted")&&b(a,"explicitCompleted")&&released(a);
            return id.endsWith("unload-backoff")&&LabLifetimeEvidence.keys(a,"cause","extraAttempts","timers","pendingWorkers","published","waitingRequests","runningAttempts","queuedCycles")
                &&LabRun.text(a,"cause").equals("CLOSED")&&n(a,"extraAttempts")==0&&n(a,"timers")==0&&n(a,"pendingWorkers")==0&&!b(a,"published")&&released(a);
        }catch(RuntimeException malformed){return false;}
    }
    private static boolean released(JsonObject a){return n(a,"waitingRequests")==0&&n(a,"runningAttempts")==0&&n(a,"queuedCycles")==0;}
    static List<ScenarioCatalog.Fact> facts(String id,JsonObject a){return valid(id,a)?List.of(new ScenarioCatalog.Fact("outcome","Independent callers, bounded owned work and released reservations; defaults unchanged.")):List.of();}
}
