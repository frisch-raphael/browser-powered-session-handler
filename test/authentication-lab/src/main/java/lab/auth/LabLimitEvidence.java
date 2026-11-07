package lab.auth;

import com.google.gson.JsonObject;
import java.util.List;
import java.util.Map;

/** Validates actual boundary values from the existing parser/extractor owners. */
final class LabLimitEvidence {
    private LabLimitEvidence() {}
    static final Map<String,Integer> LIMITS=Map.of("wrapper_depth",8,"reference_count",16,"tagged_request_bytes",1<<20,"json_response_bytes",1<<20,"output_bytes",4<<20,"regex_source_bytes",4096);
    static boolean supports(String id){return id.startsWith("CORE.limits.");}
    static boolean valid(ScenarioCatalog.Requirement row,JsonObject actual) {
        try {
            var axes=new java.util.HashMap<String,String>();row.axes().forEach(a->axes.put(a.name(),a.value()));
            String dimension=axes.get("dimension"),point=axes.get("point");int limit=LIMITS.get(dimension),delta=point.equals("below")?-1:point.equals("above")?1:0;boolean accepted=delta<=0;
            int attempts=dimension.equals("reference_count")?(accepted?limit+delta:0):dimension.equals("output_bytes")?2:dimension.equals("tagged_request_bytes")?(accepted?1:0):0;
            return LabLifetimeEvidence.keys(actual,"dimension","point","value","limit","accepted","bytesMatch","cause","attempts","sourceUnchanged","waitingRequests","pendingWorkers")
                &&LabRun.text(actual,"dimension").equals(dimension)&&LabRun.text(actual,"point").equals(point)
                &&LabLifetimeEvidence.n(actual,"value")==limit+delta&&LabLifetimeEvidence.n(actual,"limit")==limit
                &&LabLifetimeEvidence.b(actual,"accepted")==accepted&&LabLifetimeEvidence.b(actual,"bytesMatch")==accepted
                &&LabRun.text(actual,"cause").equals(accepted?"NONE":dimension.equals("json_response_bytes")||dimension.equals("regex_source_bytes")?"EXTRACTION":"CONFIGURATION")
                &&LabLifetimeEvidence.n(actual,"attempts")==attempts&&LabLifetimeEvidence.b(actual,"sourceUnchanged")
                &&LabLifetimeEvidence.n(actual,"waitingRequests")==0&&LabLifetimeEvidence.n(actual,"pendingWorkers")==0;
        }catch(RuntimeException malformed){return false;}
    }
    static List<ScenarioCatalog.Fact> facts(ScenarioCatalog.Requirement row,JsonObject actual) {
        return valid(row,actual)?List.of(new ScenarioCatalog.Fact("outcome",LabLifetimeEvidence.b(actual,"accepted")?"within-declared-limit-accepted":"over-limit-rejected")):List.of();
    }
}
