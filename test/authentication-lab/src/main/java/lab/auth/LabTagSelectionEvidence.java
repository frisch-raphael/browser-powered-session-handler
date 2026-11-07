package lab.auth;

import com.google.gson.JsonObject;
import java.util.List;
import java.util.Set;

/** Checks observations from the existing resolver owners without acquiring credentials. */
final class LabTagSelectionEvidence {
    private LabTagSelectionEvidence() {}
    static boolean supports(String id) {
        return Set.of("repeat-one-output","two-outputs","three-outputs","two-identities","three-identities","case-only-alias","same-account-distinct-journeys","alternating-users").stream().anyMatch(s->id.equals("CORE.tag-selection."+s));
    }
    static boolean valid(String id,JsonObject actual) {
        try {
            if(id.endsWith("same-account-distinct-journeys")||id.endsWith("alternating-users")) {
                if(!LabLifetimeEvidence.keys(actual,"proofs","attempts","distinctIssuances","unaffectedJourneyPreserved","waitingRequests")
                    ||LabLifetimeEvidence.n(actual,"attempts")!=3||LabLifetimeEvidence.n(actual,"distinctIssuances")!=3
                    ||!LabLifetimeEvidence.b(actual,"unaffectedJourneyPreserved")||LabLifetimeEvidence.n(actual,"waitingRequests")!=0)return false;
                var proofs=actual.getAsJsonArray("proofs");if(proofs.size()!=4)return false;var issuances=new java.util.HashSet<String>();
                for(int i=0;i<4;i++) {
                    var proof=proofs.get(i).getAsJsonObject();String alias=i%2==0?"employee":"admin",account=i%2==1&&id.endsWith("alternating-users")?"admin":"user2";
                    if(!LabLifetimeEvidence.keys(proof,"alias","account","issuance","status")||!LabRun.text(proof,"alias").equals(alias)||!LabRun.text(proof,"account").equals(account)
                        ||LabLifetimeEvidence.n(proof,"status")!=200||!LabRun.text(proof,"issuance").matches("s[0-9]+"))return false;
                    issuances.add(LabRun.text(proof,"issuance"));
                }
                return issuances.size()==3&&!LabRun.text(proofs.get(0).getAsJsonObject(),"issuance").equals(LabRun.text(proofs.get(1).getAsJsonObject(),"issuance"))
                    &&LabRun.text(proofs.get(1).getAsJsonObject(),"issuance").equals(LabRun.text(proofs.get(3).getAsJsonObject(),"issuance"));
            }
            if(id.endsWith("case-only-alias"))return LabEncodingEvidence.valid("CORE.encoding.unrelated-bytes",actual);
            if(id.endsWith("two-outputs")||id.endsWith("three-outputs")) {
                return LabLifetimeEvidence.keys(actual,"outputs","bytesMatch","namedSnapshotMatches","sameVersion","usedSnapshots","attempts","unselectedCookieAbsent","disabledOutputAbsent","waitingRequests")
                    &&LabLifetimeEvidence.n(actual,"outputs")==(id.endsWith("two-outputs")?2:3)
                    &&LabLifetimeEvidence.n(actual,"usedSnapshots")==1&&LabLifetimeEvidence.n(actual,"attempts")==1&&LabLifetimeEvidence.n(actual,"waitingRequests")==0
                    &&List.of("bytesMatch","namedSnapshotMatches","sameVersion","unselectedCookieAbsent","disabledOutputAbsent").stream().allMatch(k->LabLifetimeEvidence.b(actual,k));
            }
            int references=id.endsWith("two-identities")?2:3;
            return supports(id)&&LabLifetimeEvidence.keys(actual,"location","mode","references","plans","bytesMatch","snapshotVersionsMatch","cachedBytesMatch","extraAttemptsOnCacheUse","attempts","usedSnapshots","waitingRequests")
                &&LabRun.text(actual,"location").equals("header")&&LabRun.text(actual,"mode").equals("raw")
                &&LabLifetimeEvidence.n(actual,"references")==references&&LabLifetimeEvidence.n(actual,"plans")==2
                &&LabLifetimeEvidence.n(actual,"attempts")==references+1&&LabLifetimeEvidence.n(actual,"usedSnapshots")==references+1
                &&LabLifetimeEvidence.n(actual,"extraAttemptsOnCacheUse")==0&&LabLifetimeEvidence.n(actual,"waitingRequests")==0
                &&List.of("bytesMatch","snapshotVersionsMatch","cachedBytesMatch").stream().allMatch(k->LabLifetimeEvidence.b(actual,k));
        } catch(RuntimeException malformed) {return false;}
    }
    static List<ScenarioCatalog.Fact> facts(String id,JsonObject actual) {
        return valid(id,actual)?List.of(new ScenarioCatalog.Fact("outcome","Correct intended output in each slot; no independent-journey automatic composition.")):List.of();
    }
}
