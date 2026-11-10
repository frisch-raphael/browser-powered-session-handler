package bpsh.support;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import lab.auth.HttpAuthenticationFixture;
import lab.auth.LabObservationCapture;
import static org.junit.jupiter.api.Assertions.*;

/** Safe fixture observations shared by native tests and their captured acceptance owners. */
public final class HttpAuthenticationCapture {
    private HttpAuthenticationCapture() { }
    public static Map<String, Object> observed(HttpAuthenticationFixture fixture) {
        var values = new LinkedHashMap<String, Object>();
        values.put("observations", fixture.observations.stream().map(o -> Map.of(
                "user", o.user(), "protocol", o.protocol().name(), "connection", o.connection(),
                "method", o.method(), "path", o.path(), "bodyBytes", o.bodyBytes())).toList());
        values.put("handshakes", fixture.handshakes.get());
        values.put("posts", fixture.applicationPosts.get());
        values.put("leakedDirectives", fixture.leakedDirectives.get());
        return values;
    }
    public static String id(String protocol, String caseName) {
        return "HTTP.auth." + protocol.toLowerCase(java.util.Locale.ROOT).replace('_', '-') + "." + caseName;
    }
    public static void record(String protocol, String caseName, HttpAuthenticationFixture fixture,
                              Map<String, Object> observed, long began) throws Exception {
        assertTrue(fixture.isClosed(), "Capture is published only after the fixture and its event loops close.");
        observed.put("fixtureClosed", fixture.isClosed());
        LabObservationCapture.write(id(protocol, caseName), observed, Map.of("startupMs", 0L,
                "caseMs", TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - began), "cleanupMs", 0L));
    }
}
