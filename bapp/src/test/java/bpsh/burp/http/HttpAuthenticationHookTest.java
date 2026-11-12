package bpsh.burp.http;

import bpsh.authentication.http.HttpIdentityManager;
import bpsh.authentication.session.CoordinatorFixtures;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.HttpAuthentication;
import bpsh.support.IntegrationFixtures;
import bpsh.transport.httpauth.HttpTransportRuntime;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import static org.junit.jupiter.api.Assertions.*;

class HttpAuthenticationHookTest {
    @ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(booleans = {false, true})
    void uncertainOrInterruptedDeliveryWarnsBeforeResending(boolean interrupt) throws Exception {
        var entered = new java.util.concurrent.CountDownLatch(1);
        var response = new java.util.concurrent.CompletableFuture<bpsh.authentication.http.HttpAuthenticationService.Response>();
        var allocator = new bpsh.authentication.http.HttpMessageBody.Allocator(1024);
        var factory = new bpsh.authentication.http.HttpTransportFactory() {
            @Override public java.util.concurrent.CompletableFuture<bpsh.authentication.http.HttpAuthenticationService> open(ScopeSpec spec, bpsh.journey.SecretStore.Values values, long deadline) {
                return java.util.concurrent.CompletableFuture.completedFuture(new bpsh.authentication.http.HttpAuthenticationService() {
                    @Override public boolean isOpen() { return true; }
                    @Override public Delivery admit(long end) { return IntegrationFixtures.httpDelivery(request -> {
                        entered.countDown();
                        if (!interrupt) response.completeExceptionally(new java.io.IOException("CANARY_SECRET"));
                        return response;
                    }); }
                    @Override public void close() { }
                });
            }
            @Override public bpsh.authentication.http.HttpMessageBody.Allocator bodies() { return allocator; }
            @Override public void close() { }
        };
        var hooks = new NativeTagPipelineTest().new ProductionHooks(); var origin = java.net.URI.create("http://example.test");
        try (var fixture = new NativeTagPipelineTest.Fixture()) {
            var definition = new JourneyDefinition(UUID.randomUUID(), "HTTP", "http", origin, false, List.of(),
                    new JourneyDefinition.Browser(true, null, 10000, 1000), null, JourneyDefinition.Injection.perToken(List.of()),
                    new JourneyDefinition.Cache(1800, 10), null, new HttpAuthentication(HttpAuthentication.Protocol.BASIC, "user-a", "", "", Set.of(origin)), null);
            CoordinatorFixtures.load(fixture.registry, List.of(definition));
            try (var identities = new HttpIdentityManager(fixture.registry, fixture.secrets, factory); var host = hooks.new Host(fixture, null, identities, origin)) {
                var request = host.request("POST /perform HTTP/1.1\r\nHost: example.test\r\nBPSP-HTTP-AUTHENT: <@http/>\r\nContent-Length: 0\r\n\r\n", 1, false);
                var result = new java.util.concurrent.atomic.AtomicReference<burp.api.montoya.http.handler.RequestToBeSentAction>();
                var worker = new Thread(() -> result.set(host.handler.handleHttpRequestToBeSent(request)));
                try {
                    worker.start(); assertTrue(entered.await(5, java.util.concurrent.TimeUnit.SECONDS));
                    if (interrupt) worker.interrupt();
                    worker.join(5000); assertFalse(worker.isAlive());
                    assertEquals("DROP", result.get().action().name());
                    String notes = result.get().annotations().notes();
                    assertTrue(notes.contains("may have reached the server"), notes);
                    assertTrue(notes.contains("Check the server-side result"), notes);
                    assertTrue(notes.contains("Journey http:"), notes);
                    assertFalse(notes.contains("not sent"), notes); assertFalse(notes.contains("CANARY"), notes);
                    assertTrue(notes.startsWith("existing user note\n"), notes);
                } finally { worker.interrupt(); response.cancel(true); worker.join(5000); }
            }
        }
    }

    @org.junit.jupiter.api.Test void interruptedIdentitySetupDetachesAdmissionAndReleasesCallbackCapacity() throws Exception {
        var entered = new java.util.concurrent.CountDownLatch(1);
        var opening = new java.util.concurrent.CompletableFuture<bpsh.authentication.http.HttpAuthenticationService>();
        var admissions = new java.util.concurrent.atomic.AtomicInteger();
        var allocator = new bpsh.authentication.http.HttpMessageBody.Allocator(1024);
        var factory = new bpsh.authentication.http.HttpTransportFactory() {
            @Override public java.util.concurrent.CompletableFuture<bpsh.authentication.http.HttpAuthenticationService> open(ScopeSpec spec, bpsh.journey.SecretStore.Values values, long deadline) { entered.countDown(); return opening; }
            @Override public bpsh.authentication.http.HttpMessageBody.Allocator bodies() { return allocator; }
            @Override public void close() { }
        };
        var service = new bpsh.authentication.http.HttpAuthenticationService() {
            @Override public boolean isOpen() { return true; }
            @Override public Delivery admit(long deadline) {
                admissions.incrementAndGet(); return IntegrationFixtures.httpDelivery(request -> java.util.concurrent.CompletableFuture.completedFuture(
                        new Response(200, List.of(), IntegrationFixtures.httpBody(new byte[0]), new bpsh.authentication.http.HttpAuthenticationEvidence(
                                HttpAuthentication.Protocol.NTLM_V2, bpsh.authentication.http.HttpAuthenticationEvidence.Status.ACCEPTED))));
            }
            @Override public void close() { }
        };
        var outer = new NativeTagPipelineTest(); var hooks = outer.new ProductionHooks(); var origin = java.net.URI.create("http://example.test");
        try (var fixture = new NativeTagPipelineTest.Fixture()) {
            var definition = new JourneyDefinition(UUID.randomUUID(), "HTTP", "http", origin, false, List.of(),
                    new JourneyDefinition.Browser(true, null, 10000, 1000), null, JourneyDefinition.Injection.perToken(List.of()),
                    new JourneyDefinition.Cache(1800, 10), null, new HttpAuthentication(HttpAuthentication.Protocol.NTLM_V2, "user-a", "LAB", "", Set.of(origin)), null);
            CoordinatorFixtures.load(fixture.registry, List.of(definition));
            try (var identities = new HttpIdentityManager(fixture.registry, fixture.secrets, factory); var host = hooks.new Host(fixture, null, identities, origin)) {
                host.controls.publish(host.controls.prepare(new bpsh.request.RequestSettings.Controls(false, List.of(), List.of(), 60000, 60000, 300000, 1, 1)));
                var request = host.request("GET /whoami HTTP/1.1\r\nHost: example.test\r\nBPSP-HTTP-AUTHENT: <@http/>\r\n\r\n", 1, false);
                var result = new java.util.concurrent.atomic.AtomicReference<burp.api.montoya.http.handler.RequestToBeSentAction>();
                var worker = new Thread(() -> result.set(host.handler.handleHttpRequestToBeSent(request)));
                try {
                    worker.start(); assertTrue(entered.await(5, java.util.concurrent.TimeUnit.SECONDS)); worker.interrupt(); worker.join(5000);
                    assertFalse(worker.isAlive()); assertEquals("DROP", result.get().action().name());
                    opening.complete(service); assertEquals(0, admissions.get(), "Interrupted waiters must not receive a late, unowned delivery lease");
                    assertEquals("SPOOF_RESPONSE", host.handler.handleHttpRequestToBeSent(request).action().name());
                    assertEquals(1, admissions.get());
                } finally { worker.interrupt(); worker.join(5000); }
            }
        }
    }

    @org.junit.jupiter.api.Test void routedTransportRequestsCannotStartAnotherAutomaticLogin() throws Exception {
        var outer=new NativeTagPipelineTest();var hooks=outer.new ProductionHooks();var origin=java.net.URI.create("http://example.test");
        var hostRef=new java.util.concurrent.atomic.AtomicReference<NativeTagPipelineTest.ProductionHooks.Host>();
        var owned=new java.util.concurrent.atomic.AtomicBoolean();var allocator=new bpsh.authentication.http.HttpMessageBody.Allocator(1024);
        var factory=new bpsh.authentication.http.HttpTransportFactory() {
            @Override public java.util.concurrent.CompletableFuture<bpsh.authentication.http.HttpAuthenticationService> open(ScopeSpec spec,bpsh.journey.SecretStore.Values values,long deadline) {
                return java.util.concurrent.CompletableFuture.completedFuture(new bpsh.authentication.http.HttpAuthenticationService() {
                    @Override public boolean isOpen() {return true;}
                    @Override public Delivery admit(long end) {return IntegrationFixtures.httpDelivery(request->{
                        var host=hostRef.get();String agent=request.headers().stream().filter(h->h.name().equalsIgnoreCase("User-Agent")).findFirst().orElseThrow().value();
                        owned.set(host.guard.classify(agent,bpsh.browser.AuthTrafficGuard.Family.PROXY,900).classification()==bpsh.browser.AuthTrafficGuard.Classification.OWNED);
                        var inner=host.handler.handleHttpRequestToBeSent(host.request("GET /whoami HTTP/1.1\r\nHost: example.test\r\nUser-Agent: "+agent+"\r\n\r\n",901,false));
                        assertEquals("CONTINUE",inner.action().name());assertEquals("probe-agent",inner.request().headerValue("User-Agent"));
                        return java.util.concurrent.CompletableFuture.completedFuture(new Response(200,List.of(),IntegrationFixtures.httpBody(new byte[0]),
                                new bpsh.authentication.http.HttpAuthenticationEvidence(HttpAuthentication.Protocol.NTLM_V2,bpsh.authentication.http.HttpAuthenticationEvidence.Status.ACCEPTED)));
                    });}
                    @Override public void close() { }
                });
            }
            @Override public bpsh.authentication.http.HttpMessageBody.Allocator bodies() {return allocator;}
            @Override public void close() { }
        };
        try(var fixture=new NativeTagPipelineTest.Fixture()) {
            var id=UUID.randomUUID();var identity=new JourneyDefinition(id,"HTTP","http",origin,false,List.of(),
                    new JourneyDefinition.Browser(true,new JourneyDefinition.Proxy(java.net.URI.create("http://127.0.0.1:8080")),10000,1000),null,
                    JourneyDefinition.Injection.perToken(List.of()),new JourneyDefinition.Cache(1800,10),null,
                    new HttpAuthentication(HttpAuthentication.Protocol.NTLM_V2,"user-a","LAB","",Set.of(origin)),null);
            var definitions=new java.util.ArrayList<>(fixture.definitions);definitions.add(identity);CoordinatorFixtures.load(fixture.registry,definitions);
            try(var identities=new HttpIdentityManager(fixture.registry,fixture.secrets,factory);var host=hooks.new Host(fixture,null,identities,origin)) {
                hostRef.set(host);var employee=fixture.registry.snapshot().resolve("employee");var d=bpsh.request.RequestSettings.Controls.defaults();
                var rule=new bpsh.request.RequestSettings.AutomaticRule(true,new bpsh.request.RequestSettings.JourneySelection(employee.identity().scope(),employee.identity().journeyId()), new bpsh.request.RequestSettings.AllRequests(), null,new JourneyDefinition.Recovery(false,JourneyDefinition.RecoveryMode.STATUS_CODE,401,null));
                host.controls.publish(host.controls.prepare(new bpsh.request.RequestSettings.Controls(true,List.of(rule),d.tools(),60000,60000,300000,null,null,bpsh.request.RequestSettings.RequestPolicy.DO_NOT_WAIT)));
                var action=host.handler.handleHttpRequestToBeSent(host.request("GET /whoami HTTP/1.1\r\nHost: example.test\r\nUser-Agent: probe-agent\r\nBPSP-HTTP-AUTHENT: <@http/>\r\n\r\n",1,false));
                assertEquals("SPOOF_RESPONSE",action.action().name());assertTrue(owned.get());assertEquals(0,fixture.attempts);assertTrue(fixture.clock.workers.isEmpty());
            }
        }
    }
    @ParameterizedTest(name="direct-{0}") @EnumSource(HttpAuthentication.Protocol.class)
    void taggedAccountsReturnActualResponsesThroughTheProductionHook(HttpAuthentication.Protocol protocol) throws Exception {
        var outer=new NativeTagPipelineTest();var hooks=outer.new ProductionHooks();
        long began=System.nanoTime();
        var lab=IntegrationFixtures.httpAuthentication(protocol.name(),null);
        java.util.Map<String,Object> observed;
        var actions=new java.util.ArrayList<String>();var statuses=new java.util.ArrayList<Integer>();
        try(lab;
            var fixture=new NativeTagPipelineTest.Fixture();var runtime=new HttpTransportRuntime()) {
            var definitions=new java.util.ArrayList<JourneyDefinition>();
            for(String user:List.of("user-a","user-b"))definitions.add(new JourneyDefinition(UUID.randomUUID(),user,user,lab.url("/whoami"),false,List.of(),
                    new JourneyDefinition.Browser(true,null,10000,3000),null,JourneyDefinition.Injection.perToken(List.of()),
                    new JourneyDefinition.Cache(1800,10),null,new HttpAuthentication(protocol,user,"LAB","",Set.of(lab.url("/"))),null));
            CoordinatorFixtures.load(fixture.registry,definitions);
            for(var definition:definitions)try(var values=new bpsh.journey.SecretStore.Values(null,java.util.Map.of(),
                    (definition.alias().equals("user-a")?"alpha-password":"bravo-password").toCharArray())) {
                fixture.secrets.put(new bpsh.journey.JourneyKey(JourneyDefinition.Scope.PROJECT,definition.id()),values);
            }
            try(var identities=new HttpIdentityManager(fixture.registry,fixture.secrets,runtime);
                var host=hooks.new Host(fixture,null,identities,lab.url("/"))) {
                int id=1;
                for(String user:List.of("user-a","user-b","user-a")) {
                    host.selectedTool=id==2?burp.api.montoya.core.ToolType.PROXY:burp.api.montoya.core.ToolType.REPEATER;
                    var incoming=host.request("GET /whoami HTTP/1.1\r\nHost: "+lab.url("/").getAuthority()+
                            "\r\nBPSP-HTTP-AUTHENT: <@"+user+"/>\r\nAuthorization: Bearer discarded\r\n\r\n",id++,false);
                    if(host.selectedTool==burp.api.montoya.core.ToolType.PROXY) {
                        var deferred=host.proxy.handleRequestToBeSent((burp.api.montoya.proxy.http.InterceptedRequest)incoming);
                        assertSame(incoming,deferred.request());assertTrue(deferred.request().hasHeader("BPSP-HTTP-AUTHENT"));
                        incoming=host.request(new String(deferred.request().toByteArray().getBytes(),StandardCharsets.ISO_8859_1),1000+id,false);
                    }
                    var action=host.handler.handleHttpRequestToBeSent(incoming);
                    actions.add(action.action().name());assertEquals("SPOOF_RESPONSE",action.action().name());
                    String response=new String(host.spoofResponse.toByteArray().getBytes(),StandardCharsets.UTF_8);
                    statuses.add(Integer.parseInt(response.substring(9,12)));assertTrue(response.startsWith("HTTP/1.1 200"),response);assertTrue(response.contains(user),response);
                }
                var forbidden=host.handler.handleHttpRequestToBeSent(host.request("GET /forbidden HTTP/1.1\r\nHost: "+lab.url("/").getAuthority()+
                        "\r\nBPSP-HTTP-AUTHENT: <@user-a/>\r\n\r\n",id,false));
                actions.add(forbidden.action().name());assertEquals("SPOOF_RESPONSE",forbidden.action().name());
                String rejected=new String(host.spoofResponse.toByteArray().getBytes(),StandardCharsets.UTF_8);
                statuses.add(Integer.parseInt(rejected.substring(9,12)));assertTrue(rejected.startsWith("HTTP/1.1 403"));
                assertEquals(4,lab.observations.size());assertEquals(0,lab.leakedDirectives.get());assertEquals(0,fixture.attempts);
                if(protocol!=HttpAuthentication.Protocol.BASIC)assertEquals(2,lab.handshakes.get());
                int beforeRejection=lab.handshakes.get();
                for(String path:List.of("/perform","/server-error","/reject")) {
                    boolean post=path.equals("/perform");
                    String raw=(post?"POST ":"GET ")+path+" HTTP/1.1\r\nHost: "+lab.url("/").getAuthority()+
                            "\r\nBPSP-HTTP-AUTHENT: <@user-a/>\r\n"+(post?"Content-Length: 7\r\n":"")+"\r\n"+(post?"payload":"");
                    var action=host.handler.handleHttpRequestToBeSent(host.request(raw,++id,false));
                    actions.add(action.action().name());assertEquals("SPOOF_RESPONSE",action.action().name());
                    String actual=new String(host.spoofResponse.toByteArray().getBytes(),StandardCharsets.UTF_8);
                    int status=Integer.parseInt(actual.substring(9,12));statuses.add(status);
                    assertEquals(post?200:path.equals("/reject")?401:500,status);
                }
                assertEquals(1,lab.applicationPosts.get());assertEquals(6,lab.observations.size());assertEquals(7,lab.observations.get(4).bodyBytes());
                observed=bpsh.support.HttpAuthenticationCapture.observed(lab);observed.put("handshakesBeforeRejection",beforeRejection);
                observed.put("actions",List.copyOf(actions));observed.put("statuses",List.copyOf(statuses));
                observed.put("browserAttempts",fixture.attempts);
            }
        }
        bpsh.support.HttpAuthenticationCapture.record(protocol.name(),"direct",lab,observed,began);
    }
}
