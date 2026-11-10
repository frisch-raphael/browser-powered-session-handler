package lab.auth;

import com.google.gson.JsonObject;
import java.util.List;
import java.util.Set;

/** Validates independent server identities and transport type, never implements authentication. */
public final class LabHttpAuthenticationEvidence {
    public static final String OUTCOME = "server-observed-account-and-authentication-type-with-owned-cleanup";
    private LabHttpAuthenticationEvidence() { }
    static boolean supports(String id) { return LabHttpBoundaryEvidence.supports(id) || id.matches("HTTP\\.auth\\.(basic|ntlm-v1|ntlm-v2)\\.(identity|direct|browser|recording)"); }
    static String task(String id) { return LabHttpBoundaryEvidence.supports(id)?LabHttpBoundaryEvidence.task(id):id.endsWith(".browser") || id.endsWith(".recording") ? ":authLabBrowserTest" : ":authLabComponentTest"; }
    static boolean valid(String id, JsonObject actual) {
        if(LabHttpBoundaryEvidence.supports(id))return LabHttpBoundaryEvidence.valid(id,actual);
        try {
            if (!supports(id) || !actual.get("fixtureClosed").getAsBoolean() || LabRun.number(actual,"leakedDirectives",true)!=0) return false;
            var fields = new java.util.HashSet<>(Set.of("fixtureClosed","leakedDirectives","observations","handshakes","posts"));
            if(id.endsWith(".direct"))fields.addAll(Set.of("actions","statuses","browserAttempts","handshakesBeforeRejection"));
            if(id.endsWith(".identity"))fields.add("handshakesBeforeReconnect");
            if(id.endsWith(".browser") || id.endsWith(".recording"))fields.addAll(Set.of("capturedExpectedAccount","reportedProtocol","drivers","processes","alive",
                    id.endsWith(".recording")?"candidateCount":"httpObservationCount"));
            if(!actual.keySet().equals(fields))return false;
            String protocol=id.split("\\.")[2].replace('-', '_').toUpperCase(java.util.Locale.ROOT);
            var observations=actual.getAsJsonArray("observations").asList().stream().map(e->e.getAsJsonObject()).toList();
            if(observations.isEmpty() || observations.stream().anyMatch(o -> !o.keySet().equals(Set.of("user","protocol","connection","method","path","bodyBytes")) ||
                    !LabRun.text(o,"protocol").equals(protocol) || !LabRun.text(o,"connection").matches("[a-zA-Z0-9-]{1,128}")))return false;
            var users=observations.stream().map(o->LabRun.text(o,"user")).toList();
            if(id.endsWith(".identity")) {
                return users.size()==7 && users.subList(0,3).equals(List.of("user-a","user-b","user-a")) &&
                        Set.copyOf(users.subList(3,5)).equals(Set.of("user-a","user-b")) &&
                        LabRun.text(observations.get(0),"connection").equals(LabRun.text(observations.get(2),"connection")) &&
                        !LabRun.text(observations.get(0),"connection").equals(LabRun.text(observations.get(1),"connection")) &&
                        users.subList(5,7).equals(List.of("user-a","user-a")) &&
                        !LabRun.text(observations.get(5),"connection").equals(LabRun.text(observations.get(6),"connection")) &&
                        (protocol.equals("BASIC") || LabRun.number(actual,"handshakesBeforeReconnect",true)==2 && LabRun.number(actual,"handshakes",true)==3);
            }
            if(id.endsWith(".direct"))return users.equals(List.of("user-a","user-b","user-a","user-a","user-a","user-a")) &&
                    actual.getAsJsonArray("actions").asList().stream().map(e->e.getAsString()).toList().equals(java.util.Collections.nCopies(7,"SPOOF_RESPONSE")) &&
                    actual.getAsJsonArray("statuses").asList().stream().map(e->e.getAsInt()).toList().equals(List.of(200,200,200,403,200,500,401)) &&
                    LabRun.number(actual,"browserAttempts",true)==0 && LabRun.number(actual,"posts",true)==1 && LabRun.number(observations.get(4),"bodyBytes",true)==7 &&
                    (protocol.equals("BASIC") || LabRun.number(actual,"handshakesBeforeRejection",true)==2);
            int drivers=id.endsWith(".recording")?2:1;
            return users.stream().allMatch("user-a"::equals) && actual.get("capturedExpectedAccount").getAsBoolean() &&
                    LabRun.text(actual,"reportedProtocol").equals(protocol) && LabRun.number(actual,"posts",true)==drivers &&
                    LabRun.number(actual,"drivers",true)==drivers && LabRun.number(actual,"processes",true)>0 && LabRun.number(actual,"alive",true)==0 &&
                    (drivers==2?LabRun.number(actual,"candidateCount",true)>=2:LabRun.number(actual,"httpObservationCount",true)>0);
        } catch(RuntimeException malformed) { return false; }
    }
    static List<ScenarioCatalog.Fact> facts(String id, JsonObject actual) {
        if(LabHttpBoundaryEvidence.supports(id))return LabHttpBoundaryEvidence.facts(id,actual);
        return valid(id,actual)?List.of(new ScenarioCatalog.Fact("outcome",OUTCOME)):List.of();
    }
}
