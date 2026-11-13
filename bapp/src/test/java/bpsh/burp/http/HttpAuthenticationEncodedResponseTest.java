package bpsh.burp.http;

import bpsh.authentication.http.HttpIdentityManager;
import bpsh.authentication.session.CoordinatorFixtures;
import bpsh.journey.HttpAuthentication;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.SecretStore;
import bpsh.support.IntegrationFixtures;
import bpsh.transport.httpauth.HttpTransportRuntime;
import lab.auth.EncodedResponseFixture;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import static org.junit.jupiter.api.Assertions.*;

/** Real authentication lab plus maintained Montoya doubles: compressed JSON must reach the originating tool decoded. */
class HttpAuthenticationEncodedResponseTest {
    @ParameterizedTest @EnumSource(HttpAuthentication.Protocol.class)
    void taggedResponsesDecodeContentWithoutRepeatingApplicationRequests(HttpAuthentication.Protocol protocol) throws Exception {
        var hooks = new NativeTagPipelineTest().new ProductionHooks();
        try (var fixture = new NativeTagPipelineTest.Fixture();
             var lab = IntegrationFixtures.httpAuthentication(protocol.name(), null);
             var runtime = new HttpTransportRuntime()) {
            var definition = new JourneyDefinition(UUID.randomUUID(), "HTTP", "http", lab.url("/whoami"), false, List.of(),
                    new JourneyDefinition.Browser(true, null, 10000, 3000), null, JourneyDefinition.Injection.perToken(List.of()),
                    new JourneyDefinition.Cache(1800, 10), null,
                    new HttpAuthentication(protocol, "user-a", "LAB", "", Set.of(lab.url("/"))), null);
            CoordinatorFixtures.load(fixture.registry, List.of(definition));
            try (var values = new SecretStore.Values(null, Map.of(), "alpha-password".toCharArray())) {
                fixture.secrets.put(new bpsh.journey.JourneyKey(JourneyDefinition.Scope.PROJECT, definition.id()), values);
            }
            try (var identities = new HttpIdentityManager(fixture.registry, fixture.secrets, runtime);
                 var host = hooks.new Host(fixture, null, identities, lab.url("/"))) {
                host.selectedTool = burp.api.montoya.core.ToolType.REPEATER;
                int id = 1;
                for (String coding : List.of("br", "gzip", "deflate")) {
                    var request = host.request("GET /encoded/" + coding + " HTTP/1.1\r\nHost: " + lab.url("/").getAuthority()
                            + "\r\nAccept-Encoding: br, gzip, deflate\r\nBPSP-HTTP-AUTHENT: <@http/>\r\n\r\n", id++, false);
                    assertEquals("SPOOF_RESPONSE", host.handler.handleHttpRequestToBeSent(request).action().name());
                    assertEquals(200, host.spoofResponse.statusCode());
                    assertEquals(EncodedResponseFixture.JSON, new String(host.spoofResponse.body().getBytes(), StandardCharsets.UTF_8));
                    assertNull(host.spoofResponse.headerValue("Content-Encoding"));
                    assertEquals(Integer.toString(EncodedResponseFixture.JSON.getBytes(StandardCharsets.UTF_8).length),
                            host.spoofResponse.headerValue("Content-Length"));
                    String wire = new String(host.spoofResponse.toByteArray().getBytes(), StandardCharsets.UTF_8);
                    assertTrue(wire.contains("Set-Cookie: first=1\r\nSet-Cookie: second=2\r\n"));
                }
                assertEquals(3, lab.observations.size());
                assertEquals(0, lab.leakedDirectives.get()); assertEquals(0, fixture.attempts);
                assertTrue(lab.observations.stream().allMatch(row -> row.user().equals("user-a")));
                if (protocol != HttpAuthentication.Protocol.BASIC) assertEquals(1, lab.handshakes.get());
            }
        }
    }
}
