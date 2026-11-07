package lab.auth;

import com.google.gson.JsonObject;
import java.util.List;
import java.util.Set;

/** Reads exact wire/protected-service observations from existing injection owners. */
final class LabInjectionEvidence {
    private LabInjectionEvidence() {}
    static boolean supports(String id){return id.startsWith("CORE.injection.");}
    static boolean valid(String id,JsonObject actual) {
        try {
            if(id.endsWith("tag-precedence"))return LabEncodingEvidence.valid("CORE.encoding.unrelated-bytes",actual);
            if(id.endsWith("disabled")||id.endsWith("url-filter"))return LabLifetimeEvidence.keys(actual,"checkedRequests","unchanged","action","extraAttempts","waitingRequests")
                &&LabLifetimeEvidence.n(actual,"checkedRequests")==(id.endsWith("disabled")?4:1)&&LabLifetimeEvidence.b(actual,"unchanged")
                &&LabRun.text(actual,"action").equals("CONTINUE")&&LabLifetimeEvidence.n(actual,"extraAttempts")==0&&LabLifetimeEvidence.n(actual,"waitingRequests")==0;
            if(id.endsWith("selected-journey-change")) {
                if(!LabLifetimeEvidence.keys(actual,"proofs","bytesMatch","sameVersion","attempts","waitingRequests")||!LabLifetimeEvidence.b(actual,"bytesMatch")||!LabLifetimeEvidence.b(actual,"sameVersion")||LabLifetimeEvidence.n(actual,"attempts")!=3||LabLifetimeEvidence.n(actual,"waitingRequests")!=0)return false;
                var proofs=actual.getAsJsonArray("proofs");if(proofs.size()!=2)return false;
                for(int i=0;i<2;i++){var proof=proofs.get(i).getAsJsonObject();if(!LabLifetimeEvidence.keys(proof,"account","issuance","status")||!LabRun.text(proof,"account").equals(i==0?"user2":"admin")||!LabRun.text(proof,"issuance").matches("s[0-9]+")||LabLifetimeEvidence.n(proof,"status")!=200)return false;}
                return !LabRun.text(proofs.get(0).getAsJsonObject(),"issuance").equals(LabRun.text(proofs.get(1).getAsJsonObject(),"issuance"));
            }
            if(id.endsWith("bearer")||id.endsWith("combined")) {
                boolean combined=id.endsWith("combined");
                if(!LabLifetimeEvidence.keys(actual,"mode","combined","bytesMatch","status","account","issuance","expectedIssuance","roles","attempts","waitingRequests")
                    ||!LabRun.text(actual,"mode").equals("AUTOMATIC")||LabLifetimeEvidence.b(actual,"combined")!=combined||!LabLifetimeEvidence.b(actual,"bytesMatch")||LabLifetimeEvidence.n(actual,"status")!=200
                    ||!LabRun.text(actual,"account").equals("user2")||!LabRun.text(actual,"issuance").matches("s[0-9]+")||!LabRun.text(actual,"issuance").equals(LabRun.text(actual,"expectedIssuance"))
                    ||LabLifetimeEvidence.n(actual,"attempts")!=1||LabLifetimeEvidence.n(actual,"waitingRequests")!=0)return false;
                var roles=new java.util.HashSet<String>();actual.getAsJsonArray("roles").forEach(r->roles.add(r.getAsString()));
                return roles.equals(combined?Set.of("B","C1"):Set.of("B"))&&actual.getAsJsonArray("roles").size()==roles.size();
            }
            return Set.of("cookie","replace-stale","preserve-other-cookie","duplicate-name").stream().anyMatch(s->id.equals("CORE.injection."+s))
                &&LabLifetimeEvidence.keys(actual,"bytesMatch","sourceUnchanged","attempts","usedSnapshots","waitingRequests")
                &&LabLifetimeEvidence.b(actual,"bytesMatch")&&LabLifetimeEvidence.b(actual,"sourceUnchanged")&&LabLifetimeEvidence.n(actual,"attempts")==1&&LabLifetimeEvidence.n(actual,"usedSnapshots")==1&&LabLifetimeEvidence.n(actual,"waitingRequests")==0;
        }catch(RuntimeException malformed){return false;}
    }
    static List<ScenarioCatalog.Fact> facts(String id,JsonObject actual) {
        return valid(id,actual)?List.of(new ScenarioCatalog.Fact("outcome",id.endsWith("tag-precedence")?"native-tag-result-takes-precedence":id.endsWith("disabled")||id.endsWith("url-filter")?"request-unchanged":"exact-declared-request-local-injection-and-unrelated-fields-preserved")):List.of();
    }
}
