package bpsh.burp.http;

import bpsh.journey.*;
import bpsh.authentication.http.*;
import bpsh.authentication.session.CoordinatorFixtures;
import bpsh.support.IntegrationFixtures;
import java.net.URI;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ClientCertificateOnlyHookTest {
    @Test void taggedCertificateOnlyRequestsUseTlsSettingsAndKeepApplicationAuthorization() throws Exception {
        var seen=new java.util.concurrent.atomic.AtomicReference<HttpAuthenticationService.Request>();var origin=URI.create("https://example.test");
        var allocator=new HttpMessageBody.Allocator(1024);
        var factory=new HttpTransportFactory() {
            public HttpMessageBody.Allocator bodies(){return allocator;}public void close(){}
            public CompletableFuture<HttpAuthenticationService> open(ScopeSpec spec,SecretStore.Values values,long deadline) {
                assertNotNull(spec.setup().mtls());assertFalse(spec.setup().httpAuthenticationEnabled());
                return CompletableFuture.completedFuture(new HttpAuthenticationService() {
                    public boolean isOpen(){return true;}public void close(){}
                    public Delivery admit(long end){return IntegrationFixtures.httpDelivery(request->{seen.set(request);
                        try(var builder=allocator.builder(0)){return CompletableFuture.completedFuture(new Response(200,List.of(),builder.finish(),
                                new HttpAuthenticationEvidence(null,HttpAuthenticationEvidence.Status.UNCONFIRMED)));}
                    });}
                });
            }
        };
        try(var fixture=new NativeTagPipelineTest.Fixture()) {
            var mtls=new JourneyDefinition.Mtls("fixture-module",new JourneyDefinition.Slot(JourneyDefinition.SlotKind.INDEX,0),"12".repeat(32),List.of(origin),null);
            var selected=new JourneyDefinition(UUID.randomUUID(),"Certificate","certificate",origin,false,List.of(),
                    new JourneyDefinition.Browser(true,null,30000,3000,false,false),null,JourneyDefinition.Injection.perToken(List.of()),new JourneyDefinition.Cache(1800,10),mtls);
            CoordinatorFixtures.load(fixture.registry,List.of(selected));
            try(var manager=new HttpIdentityManager(fixture.registry,fixture.secrets,factory);
                var host=new NativeTagPipelineTest().new ProductionHooks().new Host(fixture,null,manager,origin)) {
                var incoming=host.request("GET /protected HTTP/1.1\r\nHost: example.test\r\nBPSP-HTTP-AUTHENT: <@certificate/>\r\nAuthorization: Bearer application-token\r\n\r\n",1,false);
                var action=host.handler.handleHttpRequestToBeSent(incoming);assertEquals("SPOOF_RESPONSE",action.action().name());
                assertNotNull(seen.get());assertTrue(seen.get().headers().stream().anyMatch(h->h.name().equalsIgnoreCase("Authorization")&&h.value().equals("Bearer application-token")));
                assertTrue(seen.get().headers().stream().noneMatch(h->h.name().equalsIgnoreCase("BPSP-HTTP-AUTHENT")));assertEquals(0,fixture.attempts);
                assertTrue(action.annotations().notes().contains("client-certificate settings"));assertFalse(action.annotations().notes().contains("accepted Basic"));
            }
        }
    }
}
