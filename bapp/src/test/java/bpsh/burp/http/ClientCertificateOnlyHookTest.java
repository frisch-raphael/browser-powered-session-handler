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
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.EnumSource(bpsh.request.RequestSettings.RequestPolicy.class)
    void automaticCertificateOnlyRoutingHonorsBothPoliciesWithoutTokens(bpsh.request.RequestSettings.RequestPolicy policy) throws Exception {
        var origin=URI.create("https://example.test");var opened=new java.util.concurrent.atomic.AtomicInteger();
        var methods=new CopyOnWriteArrayList<String>();var allocator=new HttpMessageBody.Allocator(1024);
        var factory=new HttpTransportFactory(){
            public HttpMessageBody.Allocator bodies(){return allocator;}public void close(){}
            public CompletableFuture<HttpAuthenticationService> open(ScopeSpec spec,SecretStore.Values values,long deadline){
                opened.incrementAndGet();assertNotNull(spec.setup().mtls());assertFalse(spec.setup().httpAuthenticationEnabled());assertEquals(Purpose.DIRECT,spec.purpose());
                return CompletableFuture.completedFuture(new HttpAuthenticationService(){
                    public boolean isOpen(){return true;}public void close(){}
                    public Delivery admit(long end){return IntegrationFixtures.httpDelivery(request->{
                        methods.add(request.method());assertEquals(origin,JourneyOrigins.authenticationOrigin(request.uri()));
                        if(request.method().equals("HEAD"))assertTrue(request.headers().isEmpty());
                        else assertTrue(request.headers().stream().anyMatch(h->h.name().equalsIgnoreCase("Authorization")&&h.value().equals("Bearer application-token")));
                        return CompletableFuture.completedFuture(new Response(200,List.of(),IntegrationFixtures.httpBody(new byte[0]),
                                new HttpAuthenticationEvidence(null,HttpAuthenticationEvidence.Status.UNCONFIRMED)));
                    });}
                });
            }
        };
        var hooks=new NativeTagPipelineTest().new ProductionHooks();
        try(var fixture=new NativeTagPipelineTest.Fixture()) {
            var certificate=new JourneyDefinition.Mtls("fixture-module",new JourneyDefinition.Slot(JourneyDefinition.SlotKind.INDEX,0),"12".repeat(32),List.of(origin),null);
            var d=new JourneyDefinition(UUID.randomUUID(),"Certificate","certificate",origin,false,List.of(),new JourneyDefinition.Browser(true,null,30000,3000,false,false),null,
                    JourneyDefinition.Injection.perToken(List.of()),new JourneyDefinition.Cache(1800,10),certificate);
            CoordinatorFixtures.load(fixture.registry,List.of(d));
            try(var manager=new HttpIdentityManager(fixture.registry,fixture.secrets,factory)) {
                try(var host=hooks.new Host(fixture,null,manager,origin)) {
                    var entry=fixture.registry.snapshot().resolve("certificate");var defaults=bpsh.request.RequestSettings.Controls.defaults();
                    var rule=new bpsh.request.RequestSettings.AutomaticRule(true,new bpsh.request.RequestSettings.JourneySelection(entry.identity().scope(),entry.identity().journeyId()),
                            new bpsh.request.RequestSettings.AllRequests(),8081,new JourneyDefinition.Recovery(false,JourneyDefinition.RecoveryMode.STATUS_CODE,401,null));
                    host.controls.publish(host.controls.prepare(new bpsh.request.RequestSettings.Controls(true,List.of(rule),defaults.tools(),10000,30000,60000,null,null,policy)));
                    host.selectedTool=burp.api.montoya.core.ToolType.PROXY;
                    String raw="GET /protected HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer application-token\r\n\r\n";
                    for(int id=1;id<=2;id++) {
                        var proxy=host.proxy.handleRequestToBeSent((burp.api.montoya.proxy.http.InterceptedRequest)host.request(raw,id,true));
                        var action=host.handler.handleHttpRequestToBeSent(host.request(new String(proxy.request().toByteArray().getBytes(),java.nio.charset.StandardCharsets.ISO_8859_1),1000+id,true));
                        if(policy==bpsh.request.RequestSettings.RequestPolicy.DO_NOT_WAIT && id==1) {
                            assertEquals("CONTINUE",action.action().name());assertArrayEquals(raw.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1),action.request().toByteArray().getBytes());
                            manager.warm(manager.select(entry),origin.resolve("/protected"),System.nanoTime()+5_000_000_000L).get();
                        } else assertEquals("SPOOF_RESPONSE",action.action().name());
                    }
                    assertEquals(1,opened.get());assertEquals(0,fixture.attempts);assertNull(fixture.coordinator.peek(entry.identity()));
                    assertTrue(host.logs.isEmpty(), "Valid certificate-only automatic handling must not warn about missing tokens.");
                    assertTrue(fixture.coordinator.events().snapshot(entry.identity().key()).stream()
                            .noneMatch(event -> event.level() != bpsh.authentication.session.JourneyEventLog.Level.INFO));
                    assertEquals(policy==bpsh.request.RequestSettings.RequestPolicy.DO_NOT_WAIT?List.of("HEAD","GET"):List.of("GET","GET"),methods);
                }
            }
        }
    }
}
