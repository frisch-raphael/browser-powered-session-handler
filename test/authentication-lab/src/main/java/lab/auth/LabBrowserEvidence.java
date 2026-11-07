package lab.auth;

import com.google.gson.*;
import java.util.*;

/** Projects existing controlled-browser account proofs and owned-resource observations. Executes no journey. */
public final class LabBrowserEvidence {
    private LabBrowserEvidence() {}
    public static boolean supports(String id) {
        return Set.of("BROW.basic","BROW.redirect","BROW.redirect-failure","BROW.cookie-selection","BROW.surfaces").contains(id.substring(0,id.lastIndexOf('.')));
    }
    static String input(String id){return id.equals("BROW.cookie-selection.same-name-domains")?"BROW.cookie-selection.idp-client-decoy":id;}
    static String method(String id) {
        return switch(id.substring(0,id.lastIndexOf('.'))) {
            case "BROW.basic" -> id.equals("BROW.basic.json")?"namedJsonAndSeveralCookiesAreAcquiredTogether":"controlledJavaLoginAuthenticatesExpectedAccount";
            case "BROW.redirect" -> "controlledRedirectsAuthenticateWithoutChangingMethodsOrLosingCookies";
            case "BROW.redirect-failure" -> "controlledRedirectFailuresPublishNoCredentialAndCloseTheirProcesses";
            case "BROW.cookie-selection" -> "controlledCookieSelectionUsesTheCurrentApplicableCredential";
            case "BROW.surfaces" -> "controlledResponseSurfacesProduceUsableCredentials";
            default -> throw new IllegalArgumentException("Uninspected browser input.");
        };
    }
    private static String s(JsonObject value,String key){return value.get(key).getAsString();}
    private static long n(JsonObject value,String key){return LabRun.number(value,key,true);}
    private static boolean flag(JsonObject value,String key){if(!value.get(key).getAsJsonPrimitive().isBoolean())throw new IllegalArgumentException("Expected an observed boolean.");return value.get(key).getAsBoolean();}
    private static Set<String> strings(JsonArray values) {
        var result=new HashSet<String>();for(var value:values){if(!value.isJsonPrimitive()||!value.getAsJsonPrimitive().isString()||!result.add(value.getAsString()))throw new IllegalArgumentException("Invalid observed names.");}return result;
    }
    private static boolean negative(String id){return id.equals("BROW.basic.invalid-credentials")||id.startsWith("BROW.redirect-failure.")||Set.of("BROW.cookie-selection.deleted-mid-flow","BROW.cookie-selection.ambiguous").contains(id);}
    static boolean valid(String id,JsonObject actual) {
        try {
            if(!supports(id)||!actual.keySet().equals(Set.of("sourceCase","snapshot","proofs","failures","attempts"))||!s(actual,"sourceCase").equals(input(id)))return false;
            var snapshot=actual.getAsJsonObject("snapshot");
            if(!s(snapshot,"caseId").equals(input(id))||n(snapshot,"generation")<=0||!s(snapshot,"state").equals("CLOSED")||flag(snapshot,"truncated")||n(snapshot.getAsJsonObject("counters"),"actions")!=0)return false;
            UUID.fromString(s(snapshot,"runId"));
            var attempts=actual.getAsJsonArray("attempts");if(attempts.size()!=1)return false;
            var attempt=attempts.get(0).getAsJsonObject();
            if(!attempt.keySet().equals(Set.of("contextId","contextsClosed","browsersOpened","browsersClosed","drivers","observedProcesses","alive"))||n(attempt,"drivers")!=1||n(attempt,"observedProcesses")<2||n(attempt,"alive")!=0)return false;
            boolean cancelled=id.equals("BROW.redirect-failure.cancel-before-callback");
            if(!cancelled&&(n(attempt,"contextId")<=0||n(attempt,"contextsClosed")!=1||n(attempt,"browsersOpened")!=1||n(attempt,"browsersClosed")!=1))return false;
            if(cancelled&&(n(attempt,"contextsClosed")>1||n(attempt,"browsersOpened")>1||n(attempt,"browsersClosed")>1))return false;
            var proofs=actual.getAsJsonArray("proofs");var failures=actual.getAsJsonArray("failures");
            var names=new HashSet<String>();var hops=new ArrayList<String>();var issuances=new HashSet<String>();
            for(var item:snapshot.getAsJsonArray("events")) {
                var event=item.getAsJsonObject();String name=s(event,"name");names.add(name);if(name.startsWith("hop-"))hops.add(name);
                if(name.equals("login-completed"))for(var safe:event.getAsJsonArray("safeIds"))if(s(safe.getAsJsonObject(),"kind").equals("issuance"))issuances.add(s(safe.getAsJsonObject(),"value"));
            }
            if(negative(id)) {
                if(!proofs.isEmpty()||failures.size()!=1||!id.startsWith("BROW.cookie-selection.")&&!issuances.isEmpty())return false;
                var failure=failures.get(0).getAsJsonObject();if(!failure.keySet().equals(Set.of("cause","phase"))||s(failure,"phase").isBlank())return false;
                String expected=id.equals("BROW.basic.invalid-credentials")?"AUTH_REJECTED":id.equals("BROW.redirect-failure.unreachable-hop")?"TRANSPORT":cancelled?"CANCELLED":id.startsWith("BROW.cookie-selection.")?"EXTRACTION":null;
                return expected==null?!s(failure,"cause").isBlank():s(failure,"cause").equals(expected);
            }
            if(!failures.isEmpty()||proofs.isEmpty()||issuances.size()!=1)return false;
            Set<String> roles=id.equals("BROW.basic.cookie-two")?Set.of("C1","C2"):id.equals("BROW.basic.cookie-one")||id.startsWith("BROW.cookie-selection.")?Set.of("C1"):Set.of("B");
            String account=id.equals("BROW.basic.json")?"admin":"user2";boolean selectedProof=false;
            for(var item:proofs) {
                var proof=item.getAsJsonObject();var accepted=strings(proof.getAsJsonArray("roles"));
                if(!proof.keySet().equals(Set.of("status","account","issuance","roles"))||n(proof,"status")!=200||!s(proof,"account").equals(account)||!issuances.contains(s(proof,"issuance"))||!Set.of("B","C1","C2").containsAll(accepted))return false;
                selectedProof|=accepted.equals(roles);
            }
            if(!selectedProof)return false;
            if(id.startsWith("BROW.cookie-selection.")) {
                String control=Set.of("BROW.cookie-selection.idp-client-decoy","BROW.cookie-selection.same-name-domains").contains(id)?"decoy-cookie-set":id.equals("BROW.cookie-selection.early-cookie-rotated")?"selected-cookie-rotated":"competing-path-cookie-set";
                if(!names.contains(control))return false;
            }
            if(id.startsWith("BROW.redirect.")) {
                String variant=id.substring(id.lastIndexOf('.')+1);int count=variant.equals("zero")?0:variant.equals("one")||variant.startsWith("post-")?1:3;
                if(hops.size()!=count)return false;
                for(int index=0;index<count;index++)if(!hops.get(index).equals("hop-"+index+(variant.equals("post-307")?"-POST":"-GET")))return false;
            }
            if(id.startsWith("BROW.surfaces.")) {
                var required=switch(id.substring(id.lastIndexOf('.')+1)) {
                    case "early-response" -> Set.of("page-early-ready");case "late-response" -> Set.of("page-late-ready","late-token-requested");
                    case "nested-json" -> Set.of("page-nested-ready");case "popup" -> Set.of("page-popup-parent-ready","page-popup-parent-done");
                    case "frame" -> Set.of("page-frame-parent-ready","page-frame-parent-done");case "cors-fetch" -> Set.of("page-cors-ready","page-cors-done","cors-probe-requested","page-cors-denied");
                    case "service-worker" -> Set.of("page-worker-controlled","page-worker-ready");default -> throw new IllegalArgumentException("Uninspected surface.");
                };
                if(!names.containsAll(required)||names.contains("page-cors-unexpected")||names.stream().anyMatch(name->name.endsWith("fixture-stage-failed")))return false;
            }
            return true;
        }catch(RuntimeException malformed){return false;}
    }
    static List<ScenarioCatalog.Fact> facts(String id,JsonObject actual) {
        if(!valid(id,actual))return List.of();
        String outcome;
        if(id.startsWith("BROW.redirect-failure."))return List.of(new ScenarioCatalog.Fact("outcome","finite-failure-no-publication-no-reopening"),new ScenarioCatalog.Fact("resources","owned-attempt-resources-closed"));
        if(id.equals("BROW.basic.invalid-credentials"))outcome="login-rejected-no-output";
        else if(id.equals("BROW.cookie-selection.deleted-mid-flow"))outcome="selected-cookie-missing-no-publication";
        else if(id.equals("BROW.cookie-selection.ambiguous"))outcome="ambiguous-selection-rejected";
        else if(id.startsWith("BROW.basic."))outcome="selected-output-authenticates-user";
        else if(id.startsWith("BROW.redirect."))outcome="ordered-hops-preserve-declared-method-and-cookies-then-authenticate";
        else if(id.startsWith("BROW.cookie-selection."))outcome="exact-final-applicable-cookie-authenticates-its-owner";
        else outcome="production-listener-extracts-selected-response-and-credential-authenticates";
        return List.of(new ScenarioCatalog.Fact("outcome",outcome));
    }
}
