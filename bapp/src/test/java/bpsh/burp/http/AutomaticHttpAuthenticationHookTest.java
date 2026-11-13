package bpsh.burp.http;

import bpsh.authentication.http.HttpIdentityManager;
import bpsh.authentication.session.CoordinatorFixtures;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.HttpAuthentication;
import bpsh.support.IntegrationFixtures;
import bpsh.transport.httpauth.HttpTransportRuntime;
import bpsh.request.RequestSettings;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import static org.junit.jupiter.api.Assertions.*;

class AutomaticHttpAuthenticationHookTest {
    @ParameterizedTest(name="automatic-warm-proxy-{0}")
    @EnumSource(value=HttpAuthentication.Protocol.class,names={"NTLM_V1","NTLM_V2"})
    void automaticProxyRuleUsesThePreviouslyAuthenticatedIdentity(HttpAuthentication.Protocol protocol) throws Exception {
        var hooks=new NativeTagPipelineTest().new ProductionHooks();
        try(var lab=IntegrationFixtures.httpAuthentication(protocol.name(),null);
            var fixture=new NativeTagPipelineTest.Fixture();var runtime=new HttpTransportRuntime()) {
            var definition=new JourneyDefinition(UUID.randomUUID(),"User A","user-a",lab.url("/whoami"),false,List.of(),
                    new JourneyDefinition.Browser(true,null,10000,3000),null,JourneyDefinition.Injection.perToken(List.of()),
                    new JourneyDefinition.Cache(1800,10),null,new HttpAuthentication(protocol,"user-a","LAB","",Set.of(lab.url("/"))),null);
            CoordinatorFixtures.load(fixture.registry,List.of(definition));
            try(var values=new bpsh.journey.SecretStore.Values(null,java.util.Map.of(),"alpha-password".toCharArray())) {
                fixture.secrets.put(new bpsh.journey.JourneyKey(JourneyDefinition.Scope.PROJECT,definition.id()),values);
            }
            try(var identities=new HttpIdentityManager(fixture.registry,fixture.secrets,runtime);
                var host=hooks.new Host(fixture,null,identities,lab.url("/"))) {
                String request="GET /whoami HTTP/1.1\r\nHost: "+lab.url("/").getAuthority()+"\r\n";
                var warm=host.handler.handleHttpRequestToBeSent(host.request(request+"BPSP-HTTP-AUTHENT: <@user-a/>\r\n\r\n",1,false));
                assertEquals("SPOOF_RESPONSE",warm.action().name());assertEquals(1,lab.handshakes.get());
                var entry=fixture.registry.snapshot().resolve("user-a");var defaults=bpsh.request.RequestSettings.Controls.defaults();
                var rule=new bpsh.request.RequestSettings.AutomaticRule(true,new bpsh.request.RequestSettings.JourneySelection(entry.identity().scope(),entry.identity().journeyId()),
                        new bpsh.request.RequestSettings.AllRequests(),8081,new JourneyDefinition.Recovery(false,JourneyDefinition.RecoveryMode.STATUS_CODE,401,null));
                host.controls.publish(host.controls.prepare(new bpsh.request.RequestSettings.Controls(true,List.of(rule),defaults.tools(),10000,30000,60000,null,null)));
                host.selectedTool=burp.api.montoya.core.ToolType.PROXY;
                var proxy=hooks.callback(fixture,()->host.proxy.handleRequestToBeSent((burp.api.montoya.proxy.http.InterceptedRequest)host.request(request+"\r\n",2,true)));
                var delivered=hooks.callback(fixture,()->host.handler.handleHttpRequestToBeSent(host.request(
                        new String(proxy.request().toByteArray().getBytes(),StandardCharsets.ISO_8859_1),1002,true)));
                assertEquals("SPOOF_RESPONSE",delivered.action().name(),"The matching automatic rule must reach the shared HTTP identity transport.");
                assertTrue(new String(host.spoofResponse.toByteArray().getBytes(),StandardCharsets.UTF_8).contains("user-a"));
                assertEquals(2,lab.observations.size());assertEquals(1,lab.handshakes.get(),"Reuse the existing authenticated connection.");
                assertEquals(0,fixture.attempts,"NTLM-only authentication must not request a browser token.");
                assertTrue(host.logs.isEmpty(), "Successful automatic NTLM must not produce request warnings.");
                assertTrue(fixture.coordinator.events().snapshot(entry.identity().key()).stream()
                        .noneMatch(event -> event.level() != bpsh.authentication.session.JourneyEventLog.Level.INFO));
            }
        }
    }
    @ParameterizedTest(name="automatic-immediate-{0}") @EnumSource(HttpAuthentication.Protocol.class)
    void immediateAutomaticRequestsWarmTheSharedPoolWithoutWaitingOrReplayingThePost(HttpAuthentication.Protocol protocol) throws Exception {
        var hooks=new NativeTagPipelineTest().new ProductionHooks();
        try(var lab=IntegrationFixtures.httpAuthentication(protocol.name(),null);
            var fixture=new NativeTagPipelineTest.Fixture();var runtime=new HttpTransportRuntime()) {
            var definition=new JourneyDefinition(UUID.randomUUID(),"User A","user-a",lab.url("/whoami"),false,List.of(),
                    new JourneyDefinition.Browser(true,null,10000,3000),null,JourneyDefinition.Injection.perToken(List.of()),
                    new JourneyDefinition.Cache(1800,10),null,new HttpAuthentication(protocol,"user-a","LAB","",Set.of(lab.url("/"))),null);
            CoordinatorFixtures.load(fixture.registry,List.of(definition));
            try(var values=new bpsh.journey.SecretStore.Values(null,java.util.Map.of(),"alpha-password".toCharArray())) {
                fixture.secrets.put(new bpsh.journey.JourneyKey(JourneyDefinition.Scope.PROJECT,definition.id()),values);
            }
            try(var identities=new HttpIdentityManager(fixture.registry,fixture.secrets,runtime);
                var host=hooks.new Host(fixture,null,identities,lab.url("/"))) {
                var entry=fixture.registry.snapshot().resolve("user-a");var defaults=bpsh.request.RequestSettings.Controls.defaults();
                var rule=new bpsh.request.RequestSettings.AutomaticRule(true,new bpsh.request.RequestSettings.JourneySelection(entry.identity().scope(),entry.identity().journeyId()),
                        new bpsh.request.RequestSettings.AllRequests(),null,new JourneyDefinition.Recovery(false,JourneyDefinition.RecoveryMode.STATUS_CODE,401,null));
                host.controls.publish(host.controls.prepare(new bpsh.request.RequestSettings.Controls(true,List.of(rule),defaults.tools(),10000,30000,60000,null,null,
                        bpsh.request.RequestSettings.RequestPolicy.DO_NOT_WAIT)));
                host.selectedTool=burp.api.montoya.core.ToolType.REPEATER;
                String raw="POST /perform HTTP/1.1\r\nHost: "+lab.url("/").getAuthority()+"\r\nContent-Length: 7\r\n\r\npayload";
                var original=host.request(raw,1,true);var first=host.handler.handleHttpRequestToBeSent(original);
                assertEquals("CONTINUE",first.action().name());assertArrayEquals(original.toByteArray().getBytes(),first.request().toByteArray().getBytes());
                identities.warm(identities.select(entry),lab.url("/perform"),System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(5)).get(5,java.util.concurrent.TimeUnit.SECONDS);
                assertEquals(0,lab.applicationPosts.get(),"The background HEAD cannot replay the original POST.");
                int handshakes=lab.handshakes.get(),before=lab.requests.size();
                var second=host.handler.handleHttpRequestToBeSent(host.request(raw,2,true));assertEquals("SPOOF_RESPONSE",second.action().name());
                assertEquals(1,lab.applicationPosts.get());assertEquals(1,lab.requests.size()-before);
                if(protocol!=HttpAuthentication.Protocol.BASIC)assertEquals(handshakes,lab.handshakes.get());
                assertEquals(0,fixture.attempts);
            }
        }
    }

    @ParameterizedTest(name="automatic-listeners-{0}") @EnumSource(HttpAuthentication.Protocol.class)
    void coldAutomaticRequestsRouteUsersByListenerAndLaterRulesWinWithoutReplayingPosts(HttpAuthentication.Protocol protocol) throws Exception {
        var hooks=new NativeTagPipelineTest().new ProductionHooks();
        try(var lab=IntegrationFixtures.httpAuthentication(protocol.name(),null);
            var fixture=new NativeTagPipelineTest.Fixture();var runtime=new HttpTransportRuntime()) {
            var a=definition(protocol,"user-a",lab.url("/"));var b=definition(protocol,"user-b",lab.url("/"));
            CoordinatorFixtures.load(fixture.registry,List.of(a,b));
            for(var d:List.of(a,b))try(var values=new bpsh.journey.SecretStore.Values(null,java.util.Map.of(),
                    (d.alias().equals("user-a")?"alpha-password":"bravo-password").toCharArray())) {
                fixture.secrets.put(new bpsh.journey.JourneyKey(JourneyDefinition.Scope.PROJECT,d.id()),values);
            }
            try(var identities=new HttpIdentityManager(fixture.registry,fixture.secrets,runtime);var host=hooks.new Host(fixture,null,identities,lab.url("/"))) {
                var first=fixture.registry.snapshot().resolve("user-a");var second=fixture.registry.snapshot().resolve("user-b");
                var defaults=RequestSettings.Controls.defaults();
                host.controls.publish(host.controls.prepare(new RequestSettings.Controls(true,List.of(rule(first,8081),rule(second,8082)),defaults.tools(),10000,30000,60000,null,null)));
                host.selectedTool=burp.api.montoya.core.ToolType.PROXY;
                String raw="POST /perform HTTP/1.1\r\nHost: "+lab.url("/").getAuthority()+"\r\nAuthorization: Bearer discarded\r\nContent-Length: 7\r\n\r\npayload";
                int id=1;
                for(int port:List.of(8081,8082,8081)) {
                    host.incomingListener="127.0.0.1:"+port;final int message=id++;
                    var proxy=host.proxy.handleRequestToBeSent((burp.api.montoya.proxy.http.InterceptedRequest)host.request(raw,message,true));
                    var global=host.request(new String(proxy.request().toByteArray().getBytes(),StandardCharsets.ISO_8859_1),1000+message,true);
                    assertEquals("SPOOF_RESPONSE",host.handler.handleHttpRequestToBeSent(global).action().name());
                    String response=new String(host.spoofResponse.toByteArray().getBytes(),StandardCharsets.UTF_8);
                    assertTrue(response.contains(port==8081?"user-a":"user-b"));
                }
                assertEquals(3,lab.applicationPosts.get());assertEquals(3,lab.observations.size());
                if(protocol!=HttpAuthentication.Protocol.BASIC)assertEquals(2,lab.handshakes.get());
                assertEquals(lab.observations.get(0).connection(),lab.observations.get(2).connection());
                host.incomingListener="127.0.0.1:8083";
                var untouched=host.request(raw,4,true);
                assertArrayEquals(untouched.toByteArray().getBytes(),host.proxy.handleRequestToBeSent((burp.api.montoya.proxy.http.InterceptedRequest)untouched).request().toByteArray().getBytes());
                host.controls.publish(host.controls.prepare(new RequestSettings.Controls(true,List.of(rule(first,null),rule(second,null)),defaults.tools(),10000,30000,60000,null,null)));
                var selected=host.proxy.handleRequestToBeSent((burp.api.montoya.proxy.http.InterceptedRequest)host.request(raw,5,true));
                assertEquals("SPOOF_RESPONSE",host.handler.handleHttpRequestToBeSent(host.request(new String(selected.request().toByteArray().getBytes(),StandardCharsets.ISO_8859_1),1005,true)).action().name());
                assertEquals("user-b",lab.observations.getLast().user());assertEquals(4,lab.applicationPosts.get());
                if(protocol!=HttpAuthentication.Protocol.BASIC)assertEquals(2,lab.handshakes.get());
                assertEquals(0,lab.leakedDirectives.get());assertEquals(0,fixture.attempts);
            }
        }
    }
    @Test void anAuthorizationOnlyCaptureIsNotAcquiredWhenHttpAuthenticationReplacesIt() throws Exception {
        var hooks=new NativeTagPipelineTest().new ProductionHooks();
        try(var lab=IntegrationFixtures.httpAuthentication("NTLM_V2",null);var fixture=new NativeTagPipelineTest.Fixture();var runtime=new HttpTransportRuntime()) {
            var d=definition(HttpAuthentication.Protocol.NTLM_V2,"user-a",lab.url("/"));
            var definitions=new java.util.ArrayList<>(fixture.definitions);definitions.add(d);CoordinatorFixtures.load(fixture.registry,definitions);
            try(var values=new bpsh.journey.SecretStore.Values(null,java.util.Map.of(),"alpha-password".toCharArray())) {fixture.secrets.put(new bpsh.journey.JourneyKey(JourneyDefinition.Scope.PROJECT,d.id()),values);}
            try(var identities=new HttpIdentityManager(fixture.registry,fixture.secrets,runtime);var host=hooks.new Host(fixture,null,identities,lab.url("/"))) {
                var defaults=RequestSettings.Controls.defaults();var employee=fixture.registry.snapshot().resolve("employee");var http=fixture.registry.snapshot().resolve("user-a");
                host.controls.publish(host.controls.prepare(new RequestSettings.Controls(true,List.of(rule(employee,null),rule(http,null)),defaults.tools(),10000,30000,60000,null,null)));
                host.selectedTool=burp.api.montoya.core.ToolType.REPEATER;
                var result=host.handler.handleHttpRequestToBeSent(host.request("GET /whoami HTTP/1.1\r\nHost: "+lab.url("/").getAuthority()+"\r\n\r\n",1,true));
                assertEquals("SPOOF_RESPONSE",result.action().name());assertEquals(0,fixture.attempts);assertNull(fixture.coordinator.peek(employee.identity()));
            }
        }
    }
    @Test void aPostDispatchLinkageFailureCannotForwardTheOriginalPostAgain() throws Exception {
        var hooks=new NativeTagPipelineTest().new ProductionHooks();var applied=new java.util.concurrent.atomic.AtomicInteger();
        var origin=java.net.URI.create("http://example.test");var allocator=new bpsh.authentication.http.HttpMessageBody.Allocator(1024);
        var factory=new bpsh.authentication.http.HttpTransportFactory(){
            public bpsh.authentication.http.HttpMessageBody.Allocator bodies(){return allocator;}public void close(){}
            public java.util.concurrent.CompletableFuture<bpsh.authentication.http.HttpAuthenticationService> open(ScopeSpec spec,bpsh.journey.SecretStore.Values values,long deadline){
                return java.util.concurrent.CompletableFuture.completedFuture(new bpsh.authentication.http.HttpAuthenticationService(){
                    public boolean isOpen(){return true;}public void close(){}
                    public Delivery admit(long end){return IntegrationFixtures.httpDelivery(request->{applied.incrementAndGet();throw new LinkageError("CANARY_PRIVATE");});}
                });
            }
        };
        try(var fixture=new NativeTagPipelineTest.Fixture()) {
            CoordinatorFixtures.load(fixture.registry,List.of(definition(HttpAuthentication.Protocol.NTLM_V2,"user-a",origin)));
            try(var identities=new HttpIdentityManager(fixture.registry,fixture.secrets,factory);var host=hooks.new Host(fixture,null,identities,origin)) {
                var defaults=RequestSettings.Controls.defaults();var selected=fixture.registry.snapshot().resolve("user-a");
                host.controls.publish(host.controls.prepare(new RequestSettings.Controls(true,List.of(rule(selected,null)),defaults.tools(),10000,30000,60000,null,null)));
                host.selectedTool=burp.api.montoya.core.ToolType.REPEATER;
                var sent=host.handler.handleHttpRequestToBeSent(host.request("POST /perform HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n",1,true));
                assertEquals(1,applied.get());assertEquals("DROP",sent.action().name());assertFalse(sent.annotations().notes().contains("CANARY"));
            }
        }
    }
    @Test void capturedSessionRecoveryUsesTheSameHttpIdentityWithoutDependingOnHostSpoofResponseCallbacks() throws Exception {
        var hooks=new NativeTagPipelineTest().new ProductionHooks();
        var delivered=new java.util.concurrent.CountDownLatch(1);var sends=new java.util.concurrent.atomic.AtomicInteger();
        var hostRef=new java.util.concurrent.atomic.AtomicReference<NativeTagPipelineTest.ProductionHooks.Host>();
        var failure=new java.util.concurrent.atomic.AtomicReference<Throwable>();
        try(var lab=IntegrationFixtures.httpAuthentication("NTLM_V2",null);var fixture=new NativeTagPipelineTest.Fixture();var runtime=new HttpTransportRuntime()) {
            var old=fixture.definitions.stream().filter(d->d.alias().equals("employee")).findFirst().orElseThrow();
            var employee=new JourneyDefinition(old.id(),old.displayName(),old.alias(),old.authenticationUrl(),old.rememberSecrets(),old.steps(),old.browser(),old.extraction(),
                    JourneyDefinition.Injection.perToken(List.of(new JourneyDefinition.TokenInjection(null,JourneyDefinition.InjectionType.HEADER,"X-Session"))),old.cache(),old.mtls(),old.httpAuthentication(),old.draft());
            var http=definition(HttpAuthentication.Protocol.NTLM_V2,"user-a",lab.url("/"));CoordinatorFixtures.load(fixture.registry,List.of(employee,http));
            try(var values=new bpsh.journey.SecretStore.Values(null,java.util.Map.of(),"alpha-password".toCharArray())) {fixture.secrets.put(new bpsh.journey.JourneyKey(JourneyDefinition.Scope.PROJECT,http.id()),values);}
            try(var identities=new HttpIdentityManager(fixture.registry,fixture.secrets,runtime);
                var host=hooks.new Host(fixture,(marked,timeout)->{
                    try {
                        sends.incrementAndGet();var h=hostRef.get();
                        var replay=h.handler.handleHttpRequestToBeSent(h.request(new String(marked.toByteArray().getBytes(),StandardCharsets.ISO_8859_1),900,true));
                        assertEquals("SPOOF_RESPONSE",replay.action().name());
                    } catch(Throwable error){failure.set(error);}finally{delivered.countDown();}
                },identities,lab.url("/"))) {
                hostRef.set(host);var defaults=RequestSettings.Controls.defaults();var selected=fixture.registry.snapshot().resolve("employee");
                var recover=new RequestSettings.AutomaticRule(true,new RequestSettings.JourneySelection(selected.identity().scope(),selected.identity().journeyId()),new RequestSettings.AllRequests(),null,
                        new JourneyDefinition.Recovery(true,JourneyDefinition.RecoveryMode.STATUS_CODE,401,null));
                host.controls.publish(host.controls.prepare(new RequestSettings.Controls(true,List.of(recover,rule(fixture.registry.snapshot().resolve("user-a"),null)),defaults.tools(),10000,30000,60000,null,null)));
                host.selectedTool=burp.api.montoya.core.ToolType.REPEATER;
                fixture.coordinator.acquire(List.of(selected));fixture.clock.runWorker();
                var first=host.handler.handleHttpRequestToBeSent(host.request("GET /reject HTTP/1.1\r\nHost: "+lab.url("/").getAuthority()+"\r\n\r\n",50,true));
                assertEquals("SPOOF_RESPONSE",first.action().name());
                assertFalse(fixture.clock.workers.isEmpty(),"The actual direct401 must trigger configured capture recovery even without a native response hook.");
                fixture.values.put("employee","replacement-token");fixture.clock.runWorker();
                assertTrue(delivered.await(5,java.util.concurrent.TimeUnit.SECONDS));assertNull(failure.get());assertEquals(1,sends.get());
                assertEquals(2,fixture.attempts);assertEquals(bpsh.authentication.session.AuthenticationCoordinator.Phase.PAUSED,fixture.coordinator.status(selected.identity()).phase());
                host.handler.handleHttpResponseReceived(host.response(50,(short)401,null,new byte[0]));assertEquals(1,sends.get());
            }
        }
    }
    @ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(booleans={false,true})
    void aDeferredRequestCannotSwitchIdentityAfterClearOrAliasReassignment(boolean replace) throws Exception {
        var hooks=new NativeTagPipelineTest().new ProductionHooks();
        try(var lab=IntegrationFixtures.httpAuthentication("NTLM_V2",null);var fixture=new NativeTagPipelineTest.Fixture();var runtime=new HttpTransportRuntime()) {
            var definition=definition(HttpAuthentication.Protocol.NTLM_V2,"user-a",lab.url("/"));CoordinatorFixtures.load(fixture.registry,List.of(definition));
            try(var values=new bpsh.journey.SecretStore.Values(null,java.util.Map.of(),"alpha-password".toCharArray())) {fixture.secrets.put(new bpsh.journey.JourneyKey(JourneyDefinition.Scope.PROJECT,definition.id()),values);}
            try(var identities=new HttpIdentityManager(fixture.registry,fixture.secrets,runtime);var host=hooks.new Host(fixture,null,identities,lab.url("/"))) {
                var selected=fixture.registry.snapshot().resolve("user-a");var defaults=RequestSettings.Controls.defaults();
                host.controls.publish(host.controls.prepare(new RequestSettings.Controls(true,List.of(rule(selected,8081)),defaults.tools(),10000,30000,60000,null,null)));
                host.selectedTool=burp.api.montoya.core.ToolType.PROXY;
                String raw="GET /whoami HTTP/1.1\r\nHost: "+lab.url("/").getAuthority()+"\r\n\r\n";
                var proxy=host.proxy.handleRequestToBeSent((burp.api.montoya.proxy.http.InterceptedRequest)host.request(raw,1,true));
                assertTrue(proxy.request().hasHeader("User-Agent"));
                if(replace) {
                    var d=definition(HttpAuthentication.Protocol.NTLM_V2,"user-a",lab.url("/"));
                    var reassigned=new JourneyDefinition(d.id(),"Different account","user-a",d.authenticationUrl(),false,d.steps(),d.browser(),null,d.injection(),d.cache(),null,
                            new HttpAuthentication(HttpAuthentication.Protocol.NTLM_V2,"user-b","LAB","",Set.of(lab.url("/"))),null);
                    CoordinatorFixtures.load(fixture.registry,List.of(reassigned));
                } else identities.invalidate(selected.identity());
                var result=host.handler.handleHttpRequestToBeSent(host.request(new String(proxy.request().toByteArray().getBytes(),StandardCharsets.ISO_8859_1),1001,true));
                assertEquals("CONTINUE",result.action().name());assertArrayEquals(raw.getBytes(StandardCharsets.ISO_8859_1),result.request().toByteArray().getBytes());
                assertEquals(0,lab.requests.size());assertEquals(0,fixture.attempts);
            }
        }
    }
    @Test void coldNonwaitingHttpAuthenticationKeepsTheWholeOriginalEvenWithAnotherCachedCapture() throws Exception {
        var hooks=new NativeTagPipelineTest().new ProductionHooks();
        try(var lab=IntegrationFixtures.httpAuthentication("NTLM_V2",null);var fixture=new NativeTagPipelineTest.Fixture();var runtime=new HttpTransportRuntime()) {
            var old=fixture.definitions.stream().filter(d->d.alias().equals("employee")).findFirst().orElseThrow();
            var employee=new JourneyDefinition(old.id(),old.displayName(),old.alias(),old.authenticationUrl(),old.rememberSecrets(),old.steps(),old.browser(),old.extraction(),
                    JourneyDefinition.Injection.perToken(List.of(new JourneyDefinition.TokenInjection(null,JourneyDefinition.InjectionType.HEADER,"X-Session"))),old.cache(),old.mtls(),old.httpAuthentication(),old.draft());
            var d=definition(HttpAuthentication.Protocol.NTLM_V2,"user-a",lab.url("/"));CoordinatorFixtures.load(fixture.registry,List.of(employee,d));
            try(var values=new bpsh.journey.SecretStore.Values(null,java.util.Map.of(),"alpha-password".toCharArray())) {fixture.secrets.put(new bpsh.journey.JourneyKey(JourneyDefinition.Scope.PROJECT,d.id()),values);}
            try(var identities=new HttpIdentityManager(fixture.registry,fixture.secrets,runtime);var host=hooks.new Host(fixture,null,identities,lab.url("/"))) {
                var selected=fixture.registry.snapshot().resolve("employee");fixture.coordinator.acquire(List.of(selected));fixture.clock.runWorker();assertNotNull(fixture.coordinator.peek(selected.identity()));
                var defaults=RequestSettings.Controls.defaults();var http=fixture.registry.snapshot().resolve("user-a");
                host.controls.publish(host.controls.prepare(new RequestSettings.Controls(true,List.of(rule(selected,null),rule(http,null)),defaults.tools(),10000,30000,60000,null,null,RequestSettings.RequestPolicy.DO_NOT_WAIT)));
                host.selectedTool=burp.api.montoya.core.ToolType.REPEATER;String raw="GET /whoami HTTP/1.1\r\nHost: "+lab.url("/").getAuthority()+"\r\n\r\n";
                var cold=host.handler.handleHttpRequestToBeSent(host.request(raw,1,true));assertEquals("CONTINUE",cold.action().name());assertArrayEquals(raw.getBytes(StandardCharsets.ISO_8859_1),cold.request().toByteArray().getBytes());
                identities.warm(identities.select(http),lab.url("/whoami"),System.nanoTime()+5_000_000_000L).get();
                assertEquals("SPOOF_RESPONSE",host.handler.handleHttpRequestToBeSent(host.request(raw,2,true)).action().name());assertEquals(1,fixture.attempts);
            }
        }
    }
    @Test void httpAuthenticationForTheLoginOriginDoesNotSuppressBearerCaptureAtAnotherOrigin() throws Exception {
        var hooks=new NativeTagPipelineTest().new ProductionHooks();
        try(var fixture=new NativeTagPipelineTest.Fixture();var runtime=new HttpTransportRuntime()) {
            var old=fixture.definitions.stream().filter(d->d.alias().equals("employee")).findFirst().orElseThrow();
            var employee=new JourneyDefinition(old.id(),old.displayName(),old.alias(),old.authenticationUrl(),old.rememberSecrets(),old.steps(),old.browser(),old.extraction(),old.injection(),old.cache(),old.mtls(),
                    new HttpAuthentication(HttpAuthentication.Protocol.NTLM_V2,"user-a","LAB","",Set.of(bpsh.journey.JourneyOrigins.authenticationOrigin(old.authenticationUrl()))),old.draft());
            CoordinatorFixtures.load(fixture.registry,List.of(employee));
            try(var identities=new HttpIdentityManager(fixture.registry,fixture.secrets,runtime);var host=hooks.new Host(fixture,null,identities,java.net.URI.create("https://api.example"))) {
                var defaults=RequestSettings.Controls.defaults();host.controls.publish(host.controls.prepare(new RequestSettings.Controls(true,List.of(rule(fixture.registry.snapshot().resolve("employee"),null)),defaults.tools(),10000,30000,60000,null,null)));
                host.selectedTool=burp.api.montoya.core.ToolType.REPEATER;
                var sent=hooks.callback(fixture,()->host.handler.handleHttpRequestToBeSent(host.request("GET /protected HTTP/1.1\r\nHost: api.example\r\nAuthorization: Bearer stale\r\n\r\n",1,true)));
                assertEquals("CONTINUE",sent.action().name());assertEquals("Bearer employee-token",sent.request().headerValue("Authorization"));assertEquals(1,fixture.attempts);
            }
        }
    }
    @Test void nonwaitingWarmupUsesTheConfiguredProtectedPageAtTheActualOrigin() throws Exception {
        var hooks=new NativeTagPipelineTest().new ProductionHooks();
        try(var lab=IntegrationFixtures.httpAuthentication("NTLM_V2",null);var fixture=new NativeTagPipelineTest.Fixture();var runtime=new HttpTransportRuntime()) {
            var d=definition(HttpAuthentication.Protocol.NTLM_V2,"user-a",lab.url("/"));CoordinatorFixtures.load(fixture.registry,List.of(d));
            try(var values=new bpsh.journey.SecretStore.Values(null,java.util.Map.of(),"alpha-password".toCharArray())) {fixture.secrets.put(new bpsh.journey.JourneyKey(JourneyDefinition.Scope.PROJECT,d.id()),values);}
            try(var identities=new HttpIdentityManager(fixture.registry,fixture.secrets,runtime);var host=hooks.new Host(fixture,null,identities,lab.url("/"))) {
                var entry=fixture.registry.snapshot().resolve("user-a");var defaults=RequestSettings.Controls.defaults();
                host.controls.publish(host.controls.prepare(new RequestSettings.Controls(true,List.of(rule(entry,null)),defaults.tools(),10000,30000,60000,null,null,RequestSettings.RequestPolicy.DO_NOT_WAIT)));
                host.selectedTool=burp.api.montoya.core.ToolType.REPEATER;
                var first=host.handler.handleHttpRequestToBeSent(host.request("GET /anonymous-page HTTP/1.1\r\nHost: "+lab.url("/").getAuthority()+"\r\n\r\n",1,true));
                assertEquals("CONTINUE",first.action().name());
                identities.warm(identities.select(entry),lab.url("/whoami"),System.nanoTime()+5_000_000_000L).get(5,java.util.concurrent.TimeUnit.SECONDS);
                assertTrue(identities.hasRecentAuthentication(identities.select(entry),lab.url("/whoami")));
                assertEquals("HEAD",lab.observations.getFirst().method());assertEquals("/whoami",lab.observations.getFirst().path());
            }
        }
    }
    @Test void aPredispatchLinkageFailureReleasesAdmissionForTheNextRequest() throws Exception {
        var hooks=new NativeTagPipelineTest().new ProductionHooks();
        try(var lab=IntegrationFixtures.httpAuthentication("NTLM_V2",null);var fixture=new NativeTagPipelineTest.Fixture();var runtime=new HttpTransportRuntime()) {
            var d=definition(HttpAuthentication.Protocol.NTLM_V2,"user-a",lab.url("/"));CoordinatorFixtures.load(fixture.registry,List.of(d));
            try(var values=new bpsh.journey.SecretStore.Values(null,java.util.Map.of(),"alpha-password".toCharArray())) {fixture.secrets.put(new bpsh.journey.JourneyKey(JourneyDefinition.Scope.PROJECT,d.id()),values);}
            try(var identities=new HttpIdentityManager(fixture.registry,fixture.secrets,runtime);var host=hooks.new Host(fixture,null,identities,lab.url("/"))) {
                var defaults=RequestSettings.Controls.defaults();host.controls.publish(host.controls.prepare(new RequestSettings.Controls(true,List.of(rule(fixture.registry.snapshot().resolve("user-a"),null)),defaults.tools(),10000,30000,60000,1,1)));
                host.selectedTool=burp.api.montoya.core.ToolType.REPEATER;var fail=new java.util.concurrent.atomic.AtomicBoolean(true);
                burp.api.montoya.internal.ObjectFactoryLocator.FACTORY=host.stub(burp.api.montoya.internal.MontoyaObjectFactory.class,(method,args)->{
                    if(method.getReturnType()==burp.api.montoya.http.message.requests.HttpRequest.class && fail.compareAndSet(true,false))throw new LinkageError("CANARY_PRIVATE");
                    return host.factory(method,args);
                });
                String raw="GET /whoami HTTP/1.1\r\nHost: "+lab.url("/").getAuthority()+"\r\n\r\n";
                assertEquals("CONTINUE",host.handler.handleHttpRequestToBeSent(host.request(raw,1,true)).action().name());assertEquals(0,lab.requests.size());
                assertEquals("SPOOF_RESPONSE",host.handler.handleHttpRequestToBeSent(host.request(raw,2,true)).action().name());
            }
        }
    }
    private static JourneyDefinition definition(HttpAuthentication.Protocol protocol,String user,java.net.URI origin) {
        return new JourneyDefinition(UUID.randomUUID(),user,user,origin.resolve("/whoami"),false,List.of(),new JourneyDefinition.Browser(true,null,10000,3000),
                null,JourneyDefinition.Injection.perToken(List.of()),new JourneyDefinition.Cache(1800,10),null,
                new HttpAuthentication(protocol,user,"LAB","",Set.of(origin)),null);
    }
    private static RequestSettings.AutomaticRule rule(bpsh.journey.JourneyCatalog.Entry entry,Integer port) {
        return new RequestSettings.AutomaticRule(true,new RequestSettings.JourneySelection(entry.identity().scope(),entry.identity().journeyId()),new RequestSettings.AllRequests(),port,
                new JourneyDefinition.Recovery(false,JourneyDefinition.RecoveryMode.STATUS_CODE,401,null));
    }
}
