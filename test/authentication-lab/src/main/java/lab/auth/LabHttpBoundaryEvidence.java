package lab.auth;

import com.google.gson.JsonObject;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Strict safe-metric contracts for the existing owning boundary and browser tests. */
public final class LabHttpBoundaryEvidence {
    static final String OUTCOME="owned-http-boundary-observed";
    private LabHttpBoundaryEvidence() { }
    private static final Map<String,Map<String,Object>> BOUNDARIES=Map.ofEntries(
            Map.entry("HTTP.auth.lifecycle.early-epoch",Map.of("staleOpened",0,"freshOpened",1)),
            Map.entry("HTTP.auth.lifecycle.cancel-own",Map.of("deliveryCancelled",true,"scopeClosedBeforeOwner",0)),
            Map.entry("HTTP.auth.lifecycle.retire-setup",Map.of("invalidate",true,"reconcile",true,"close",true)),
            Map.entry("HTTP.auth.lifecycle.observation-remap",Map.of("currentGeneration",2,"observedGeneration",1,"epoch",4,"observedSecond",2000000000,"cleared",true,"tokenRetained",true)),
            Map.entry("HTTP.auth.lifecycle.secret-revision",Map.of("compatible",true,"changed",false)),
            Map.entry("HTTP.auth.resources.scopes",Map.of("peak",32,"closed",0)),
            Map.entry("HTTP.auth.resources.setup-snapshot",Map.of("user","user-a","closed",0)),
            Map.entry("HTTP.auth.resources.setup-shutdown",Map.of("scopes",0,"opening",0,"queued",0,"active",0)),
            Map.entry("HTTP.auth.resources.admission",Map.of("admitted",64,"bytes",0,"closed",0)),
            Map.entry("HTTP.auth.resources.running-ownership",Map.of("retainedAdmissions",1,"retainedBytes",1048576,"closedAdmissions",0,"closedBytes",0,"posts",1)),
            Map.entry("HTTP.auth.resources.pin-expiry",Map.of("pressureScopes",32,"oldestOpen",false,"remainingScopes",1,"browserOpen",true,"closedAdmissions",0)),
            Map.entry("HTTP.auth.resources.connections",Map.of("peak",16,"closed",0,"accepted",18)),
            Map.entry("HTTP.auth.configuration.schema-two",Map.of("schema",2,"httpOnly",true,"captureAbsent",true)),
            Map.entry("HTTP.auth.configuration.secrets",Map.of("exportOmitted",true,"closed",true,"emptySupplied",true)),
            Map.entry("HTTP.auth.configuration.invalid",Map.of("version",true,"protocol",true,"origin",true,"password",true)),
            Map.entry("HTTP.auth.configuration.schema-one",Map.of("httpAbsent",true,"httpOnly",false)),
            Map.entry("HTTP.auth.configuration.disabled",Map.of("enabled",false,"originalOrigin",true,"changedOrigin",false,"domainRetained",true)),
            Map.entry("HTTP.auth.fidelity.errors",Map.of("statuses",List.of(401,403,500),"cookieCounts",List.of(2,2,2),"bodyBytes",List.of(3,3,3))),
            Map.entry("HTTP.auth.fidelity.no-entity",Map.of("entityBytes",List.of(0,0,0),"lengths",List.of(true,true,false))),
            Map.entry("HTTP.auth.protocol.v1-vector",Map.of("ntBytes",24,"lmBytes",24,"sameProof",true)),
            Map.entry("HTTP.auth.protocol.protection-flags",Map.of("variants",2,"rejections",12)),
            Map.entry("HTTP.auth.protocol.variant-requirements",Map.of("v1RejectedEss",true,"v2RequiresInfo",true)),
            Map.entry("HTTP.auth.protocol.malformed",Map.of("rejected",14)),
            Map.entry("HTTP.auth.protocol.no-downgrade",Map.of("statuses",List.of(401,401,401,401,401,401),"accepted",0,"handshakes",0)),
            Map.entry("HTTP.auth.resources.response-headers-basic",Map.of("transmissions",List.of(1,2),"accepted",1,"posts",0)),
            Map.entry("HTTP.auth.resources.response-headers-ntlm-v1",Map.of("transmissions",List.of(1,3),"accepted",1,"posts",0)),
            Map.entry("HTTP.auth.resources.response-headers-ntlm-v2",Map.of("transmissions",List.of(1,3),"accepted",1,"posts",0)),
            Map.entry("HTTP.auth.resources.body-budget",Map.of("retained",67108864,"rejected",true,"released",0)));
    static boolean supports(String id) {
        return BOUNDARIES.containsKey(id) || id.matches("HTTP\\.auth\\.browser-authorization\\.(fresh|reused)-(basic|ntlm-v1|ntlm-v2)") || id.equals("HTTP.auth.browser-trust.scoped");
    }
    static String task(String id) {return id.startsWith("HTTP.auth.browser-")?":authLabBrowserTest":":authLabComponentTest";}
    static boolean valid(String id,JsonObject observed) {
        try {
            if(BOUNDARIES.containsKey(id))return observed.equals(LabRun.JSON.toJsonTree(BOUNDARIES.get(id)));
            if(!supports(id))return false;
            var actual=observed.deepCopy();
            int drivers=id.equals("HTTP.auth.browser-trust.scoped")?2:1;
            if(LabRun.number(actual,"drivers",true)!=drivers || LabRun.number(actual,"processes",true)<=0 || LabRun.number(actual,"alive",true)!=0 || !actual.get("fixtureClosed").getAsBoolean())return false;
            for(String key:Set.of("drivers","processes","alive","fixtureClosed"))actual.remove(key);
            if(id.equals("HTTP.auth.browser-trust.scoped"))return actual.equals(LabRun.JSON.toJsonTree(Map.of("statuses",List.of(200,502),"handshakes",1,"directTrustRejected",true)));
            boolean accepted=id.contains(".reused-ntlm");
            String protocol=id.substring(id.lastIndexOf("-")+1).equals("basic")?"BASIC":id.endsWith("v1")?"NTLM_V1":"NTLM_V2";
            return actual.equals(LabRun.JSON.toJsonTree(Map.of("status",accepted?200:401,"applicationHeaders",1,"unexpectedCredentials",0,
                    "wireDelta",1,"handshakeDelta",0,"serverAccepted",accepted,"conflict",!accepted,"observedProtocol",accepted?protocol:"NONE")));
        } catch(RuntimeException malformed) {return false;}
    }
    static List<ScenarioCatalog.Fact> facts(String id,JsonObject actual) {
        return valid(id,actual)?List.of(new ScenarioCatalog.Fact("outcome",OUTCOME)):List.of();
    }
}
