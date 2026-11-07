package lab.auth;

import org.junit.jupiter.api.Test;
import java.net.*;
import java.net.http.*;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

/** Qualifies our destination gate; adds no extension authentication coverage. */
class TransportFixtureTest {
    @Test void sharedProxyForwardsOnlyOwnedLoopbackOrigins() throws Exception {
        var visits=new AtomicInteger();
        try(var origin=ControlledApplication.Origin.http("localhost");
            var proxy=new TransportFixtures.UnauthenticatedProxy(null,uri->ControlledApplication.Origin.ownsPort(uri.getPort()))) {
            origin.route("/",exchange->{visits.incrementAndGet();ControlledApplication.Origin.reply(exchange,200,"text/plain","owned");}).start();
            try(var http=HttpClient.newBuilder().proxy(ProxySelector.of(new InetSocketAddress("127.0.0.1",proxy.url().getPort()))).connectTimeout(Duration.ofSeconds(2)).build()) {
                var accepted=http.send(HttpRequest.newBuilder(origin.url("/")).timeout(Duration.ofSeconds(3)).GET().build(),HttpResponse.BodyHandlers.ofString());
                assertEquals(200,accepted.statusCode());assertEquals("owned",accepted.body());
                var rejected=http.send(HttpRequest.newBuilder(URI.create("http://example.invalid:9/")).timeout(Duration.ofSeconds(3)).GET().build(),HttpResponse.BodyHandlers.discarding());
                assertEquals(403,rejected.statusCode());assertEquals(1,visits.get());assertEquals(1,proxy.requestCounter().get());
            }
        }
    }
}
