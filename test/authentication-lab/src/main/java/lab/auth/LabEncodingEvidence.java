package lab.auth;

import com.google.gson.*;
import java.util.*;

/** Reads the native pipeline's independent byte comparisons; does not encode any content. */
final class LabEncodingEvidence {
    private LabEncodingEvidence() {}
    static boolean supports(String id){return id.startsWith("CORE.encoding.")&&!id.equals("CORE.encoding.literal-prefix");}
    private static boolean b(JsonObject value,String key){return LabLifetimeEvidence.b(value,key);}
    private static long n(JsonObject value,String key){return LabLifetimeEvidence.n(value,key);}
    static boolean valid(String id,JsonObject actual) {
        try {
            if(id.equals("CORE.encoding.unrelated-bytes"))return LabLifetimeEvidence.keys(actual,"location","mode","references","plans","bytesMatch","snapshotVersionsMatch","cachedBytesMatch","extraAttemptsOnCacheUse","attempts","usedSnapshots","waitingRequests")&&LabRun.text(actual,"location").equals("header")&&LabRun.text(actual,"mode").equals("raw")&&n(actual,"references")==1&&n(actual,"plans")==1&&b(actual,"bytesMatch")&&b(actual,"snapshotVersionsMatch")&&b(actual,"cachedBytesMatch")&&n(actual,"extraAttemptsOnCacheUse")==0&&n(actual,"attempts")==1&&n(actual,"usedSnapshots")==1&&n(actual,"waitingRequests")==0;
            if(id.equals("CORE.encoding.invalid-target"))return LabLifetimeEvidence.keys(actual,"targetCause","headerCause","sourceUnchanged","attempts","waitingRequests","pendingWorkers")&&LabRun.text(actual,"targetCause").equals("CONFIGURATION")&&LabRun.text(actual,"headerCause").equals("CONFIGURATION")&&b(actual,"sourceUnchanged")&&n(actual,"attempts")==1&&n(actual,"waitingRequests")==0&&n(actual,"pendingWorkers")==0;
            if(Set.of("CORE.encoding.unicode","CORE.encoding.body-length").contains(id))return LabLifetimeEvidence.keys(actual,"bytesMatch","rebuildBytesMatch","bodyBytes","declaredLength","characters","headerCause","attempts","waitingRequests")&&b(actual,"bytesMatch")&&b(actual,"rebuildBytesMatch")&&n(actual,"bodyBytes")==8&&n(actual,"declaredLength")==8&&n(actual,"characters")==6&&LabRun.text(actual,"headerCause").equals("CONFIGURATION")&&n(actual,"attempts")==1&&n(actual,"waitingRequests")==0;
            return Set.of("CORE.encoding.space","CORE.encoding.reserved","CORE.encoding.quote","CORE.encoding.nested-wrappers","CORE.encoding.multiple-inner-references","CORE.encoding.newline").contains(id)&&LabLifetimeEvidence.keys(actual,"wrapperBytesMatch","initialAttempts","multipleBytesMatch","multipleSnapshots","multipleAttempts","newlineBytesMatch","newlineExtraAttempts","waitingRequests")&&b(actual,"wrapperBytesMatch")&&n(actual,"initialAttempts")==2&&b(actual,"multipleBytesMatch")&&n(actual,"multipleSnapshots")==2&&n(actual,"multipleAttempts")==3&&b(actual,"newlineBytesMatch")&&n(actual,"newlineExtraAttempts")==0&&n(actual,"waitingRequests")==0;
        }catch(RuntimeException malformed){return false;}
    }
    static List<ScenarioCatalog.Fact> facts(String id,JsonObject actual){return valid(id,actual)?List.of(new ScenarioCatalog.Fact("outcome",id.equals("CORE.encoding.invalid-target")?"unrepresentable-target-rejected":"exact-independently-calculated-encoded-bytes-and-unrelated-bytes-preserved")):List.of();}
}
