package bpsh.support;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import lab.auth.LabObservationCapture;

/** Safe boundary metrics, emitted after the owning test's resources have closed. */
public final class HttpBoundaryCapture {
    private final String id;
    private final long began=System.nanoTime();
    private final Map<String,Object> observed=new LinkedHashMap<>();
    public HttpBoundaryCapture(String id) {this.id=id;}
    public void put(String name,Object value) {observed.put(name,value);}
    public void write() {
        try {LabObservationCapture.write(id,observed,Map.of("startupMs",0L,
                "caseMs",TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-began),"cleanupMs",0L));}
        catch(Exception failure) {throw new AssertionError("Could not publish HTTP boundary observations.",failure);}
    }
}
