package lab.auth;

import com.google.gson.*;
import java.util.*;

/** Joins the existing real-browser recovery owner to its actual ordered lifecycle and protected responses. */
final class LabRecoveryBrowserEvidence {
    static final String ID="RUN.recovery.network-third-succeeds";
    private LabRecoveryBrowserEvidence() {}
    static boolean valid(JsonObject actual) {
        try {
            if(!actual.keySet().equals(Set.of("loginRequests","issuedCredentials","protectedIngress","acceptedRequests","recoveryAttempts","originals","replays","acceptedUse","browsersOpened","browsersClosed","contextsOpened","contextsClosed","distinctResources","events","drivers","processes","alive")))return false;
            var counts=Map.ofEntries(Map.entry("loginRequests",4),Map.entry("issuedCredentials",2),Map.entry("protectedIngress",17),Map.entry("acceptedRequests",9),Map.entry("recoveryAttempts",3),Map.entry("originals",8),Map.entry("replays",8),Map.entry("browsersOpened",4),Map.entry("browsersClosed",4),Map.entry("contextsOpened",4),Map.entry("contextsClosed",4),Map.entry("distinctResources",8),Map.entry("drivers",4),Map.entry("alive",0));
            for(var entry:counts.entrySet())if(LabRun.number(actual,entry.getKey(),true)!=entry.getValue())return false;
            if(LabRun.number(actual,"processes",true)<8||!actual.get("acceptedUse").getAsJsonPrimitive().isBoolean()||!actual.get("acceptedUse").getAsBoolean())return false;
            long browser=0,context=0;int opens=0;var seen=new HashSet<Long>();var events=actual.getAsJsonArray("events");if(events.size()!=16)return false;
            for(var value:events) {
                var event=value.getAsJsonObject();if(!event.keySet().equals(Set.of("event","resource","parent")))return false;
                long resource=LabRun.number(event,"resource",false),parent=LabRun.number(event,"parent",true);
                switch(LabRun.text(event,"event")) {
                    case "BROWSER_OPEN" -> {if(browser!=0||!seen.add(resource))return false;browser=resource;opens++;}
                    case "CONTEXT_OPEN" -> {if(browser==0||context!=0||parent!=browser||!seen.add(resource))return false;context=resource;}
                    case "CONTEXT_CLOSED" -> {if(context!=resource||context==0)return false;context=0;}
                    case "BROWSER_CLOSED" -> {if(context!=0||browser!=resource||browser==0)return false;browser=0;}
                    default -> {return false;}
                }
            }
            return browser==0&&context==0&&opens==4&&seen.size()==8;
        }catch(RuntimeException malformed){return false;}
    }
    static List<ScenarioCatalog.Fact> facts(JsonObject actual){return valid(actual)?List.of(new ScenarioCatalog.Fact("outcome","Actual attempts/contexts/processes agree with component policy; representative eight-original recipe."),new ScenarioCatalog.Fact("replays","at-most-one-per-original"),new ScenarioCatalog.Fact("attempts","at-most-three-including-initial")):List.of();}
}
