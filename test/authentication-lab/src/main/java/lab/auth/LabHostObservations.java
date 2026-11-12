package lab.auth;

import java.nio.charset.StandardCharsets;
import java.util.*;

/** Independent receiver facts; never retains credential, header or body values. */
final class LabHostObservations {
    static final int LIMIT = 10_000, BODY_LIMIT = 1 << 20;
    record Shape(String nonce, boolean invalidNonce, String method, String route,
                 int authorizationHeaders, int cookieHeaders, boolean c1, boolean c2,
                 boolean nativeTag, boolean httpDirective, boolean sentinel,
                 int bodyBytes, boolean bodyTruncated) { }
    record Received(long sequence, String caseId, long generation, int listenerPort, Shape request,
                    int status, String accountId, String issuanceId, List<String> roles) {
        Received { roles = List.copyOf(roles); }
    }
    private final List<Received> received = new ArrayList<>();
    private long sequence;

    static Shape shape(Map<String, List<String>> headers, String method, String route, byte[] body) {
        var nonce = values(headers,"X-AuthLab-Request");
        boolean valid = nonce.size()==1 && nonce.getFirst().matches("h[0-9a-f]{16}");
        var cookies=values(headers,"Cookie");boolean c1=false,c2=false;
        for(String header:cookies)for(String item:header.split(";")) {
            String name=item.split("=",2)[0].trim();c1|=name.equals("LAB_C1");c2|=name.equals("LAB_C2");
        }
        boolean tag=headers.values().stream().flatMap(Collection::stream).anyMatch(value->value.contains("<@"))
                ||new String(body,StandardCharsets.ISO_8859_1).contains("<@");
        var sentinel=values(headers,"X-AuthLab-Sentinel");
        return new Shape(valid?nonce.getFirst():null,!nonce.isEmpty()&&!valid,method,
                Set.of("b","c1","c2","b_c1","b_c2","c1_c2","b_c1_c2","independent-cookies").contains(route)?route:"UNKNOWN",
                values(headers,"Authorization").size(),cookies.size(),c1,c2,tag,
                !values(headers,"BPSP-HTTP-AUTHENT").isEmpty(),sentinel.equals(List.of("unchanged")),
                Math.min(body.length,BODY_LIMIT),body.length>BODY_LIMIT);
    }
    private static List<String> values(Map<String,List<String>> headers,String name) {
        return headers.entrySet().stream().filter(entry->entry.getKey().equalsIgnoreCase(name))
                .flatMap(entry->entry.getValue().stream()).toList();
    }
    synchronized long begin(String caseId,long generation,int listenerPort,Shape shape) {
        if(listenerPort<1||listenerPort>65535)throw new IllegalArgumentException("HOST_RECEIVER_PORT");
        long id=++sequence;
        if(id<=LIMIT)received.add(new Received(id,caseId,generation,listenerPort,shape,0,null,null,List.of()));
        return id;
    }
    synchronized void complete(long id,int status,String account,String issuance,List<String> roles) {
        if(id<1||id>LIMIT)return;
        var original=received.get((int)id-1);
        if(original.status()!=0)throw new IllegalStateException("HOST_RECEIVER_ALREADY_COMPLETED");
        received.set((int)id-1,new Received(id,original.caseId(),original.generation(),original.listenerPort(),original.request(),status,account,issuance,roles));
    }
    synchronized Map<String,Object> snapshot() {
        return Map.of("received",List.copyOf(received),"truncated",sequence>LIMIT,
                "complete",sequence<=LIMIT&&received.stream().allMatch(row->row.status()>0&&!row.request().invalidNonce()&&!row.request().bodyTruncated()));
    }
}
