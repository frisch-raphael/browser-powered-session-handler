package bpsh.transport.httpauth;

import bpsh.authentication.http.HttpAuthenticationService;
import bpsh.journey.HttpAuthentication;
import bpsh.support.IntegrationFixtures;
import org.junit.jupiter.api.Test;
import javax.net.ssl.SSLContext;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

class HttpTransportRuntimeTest {
    @Test void missingPasswordPublishesActionableSetupFailureAndBrokenObserversCannotFailDelivery() throws Exception {
        var failureEvent=new java.util.concurrent.CompletableFuture<bpsh.authentication.http.HttpAuthenticationProgress>();
        try(var lab=IntegrationFixtures.httpAuthentication("NTLM_V2",null);
            var runtime=new HttpTransportRuntime(null,spec->event->{if(event.stage().failure())failureEvent.complete(event);})) {
            var identity=new bpsh.journey.JourneyDefinition.Identity(bpsh.journey.JourneyDefinition.Scope.PROJECT,java.util.UUID.randomUUID(),1);
            var auth=new HttpAuthentication(HttpAuthentication.Protocol.NTLM_V2,"user-a","LAB","",Set.of(lab.url("/")));
            var setup=new bpsh.journey.BrowserSetup(lab.url("/whoami"),new bpsh.journey.JourneyDefinition.Browser(true,null,10000,1000),null,auth);
            var spec=new bpsh.authentication.http.HttpTransportFactory.ScopeSpec(java.util.UUID.randomUUID(),bpsh.authentication.http.HttpTransportFactory.Purpose.TEST,identity,0,setup,false);
            try(var values=new bpsh.journey.SecretStore.Values(null,java.util.Map.of())) {
                assertThrows(java.util.concurrent.ExecutionException.class,()->runtime.open(spec,values,System.nanoTime()+TimeUnit.SECONDS.toNanos(5)).get(6,TimeUnit.SECONDS));
                assertEquals("MISSING_SECRET",failureEvent.get(1,TimeUnit.SECONDS).stage().name());
            }
            try(var isolated=new HttpTransportRuntime(null,ignored->event->{throw new IllegalStateException("private-observer-text");});
                var values=new bpsh.journey.SecretStore.Values(null,java.util.Map.of(),"alpha-password".toCharArray());
                var scope=isolated.open(spec,values,System.nanoTime()+TimeUnit.SECONDS.toNanos(5)).get(6,TimeUnit.SECONDS)) {
                assertTrue(body(scope,lab.url("/whoami")).contains("user-a"));
            }
        }
    }
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.EnumSource(HttpAuthentication.Protocol.class)
    void ntlmHandshakeReuseAndRejectionAreObservableForEveryScopeWithoutLeakingSecrets(HttpAuthentication.Protocol protocol) throws Exception {
        var events=new java.util.concurrent.CopyOnWriteArrayList<bpsh.authentication.http.HttpAuthenticationProgress>();
        try(var lab=IntegrationFixtures.httpAuthentication(protocol.name(),null);
            var runtime=new HttpTransportRuntime(null,spec->events::add)) {
            var identity=new bpsh.journey.JourneyDefinition.Identity(bpsh.journey.JourneyDefinition.Scope.PROJECT,java.util.UUID.randomUUID(),1);
            var auth=new HttpAuthentication(protocol,"user-a","LAB","",Set.of(lab.url("/")));
            var setup=new bpsh.journey.BrowserSetup(lab.url("/whoami"),new bpsh.journey.JourneyDefinition.Browser(true,null,10000,1000),null,auth);
            for(var purpose:bpsh.authentication.http.HttpTransportFactory.Purpose.values()) {
                events.clear();
                var spec=new bpsh.authentication.http.HttpTransportFactory.ScopeSpec(java.util.UUID.randomUUID(),purpose,identity,0,setup,false);
                try(var secrets=new bpsh.journey.SecretStore.Values(null,java.util.Map.of(),"alpha-password".toCharArray());
                    var scope=runtime.open(spec,secrets,System.nanoTime()+TimeUnit.SECONDS.toNanos(10)).get(5,TimeUnit.SECONDS)) {
                    assertTrue(body(scope,lab.url("/whoami")).contains("user-a"));
                    var handshake=protocol==HttpAuthentication.Protocol.BASIC?List.of("STARTED","BASIC_SENT","ACCEPTED"):
                            List.of("STARTED","NEGOTIATE_SENT","CHALLENGE_RECEIVED","AUTHENTICATE_SENT","ACCEPTED");
                    assertEquals(handshake,events.stream().map(e->e.stage().name()).toList());
                    assertTrue(events.stream().allMatch(e->e.protocol()==protocol));
                    events.clear();assertTrue(body(scope,lab.url("/whoami")).contains("user-a"));
                    assertEquals(protocol==HttpAuthentication.Protocol.BASIC?handshake:List.of("CONNECTION_REUSED"),events.stream().map(e->e.stage().name()).toList());
                    events.clear();try(var denied=exchange(scope,lab.url("/forbidden"))) {assertEquals(403,denied.status());}
                    assertEquals("APPLICATION_DENIED",events.getLast().stage().name());assertTrue(events.getLast().message().contains("HTTP 403"));
                    events.clear();try(var broken=exchange(scope,lab.url("/server-error"))) {assertEquals(500,broken.status());}
                    assertEquals("SERVER_ERROR",events.getLast().stage().name());assertTrue(events.getLast().message().contains("HTTP 500"));
                }
                events.clear();
                try(var secrets=new bpsh.journey.SecretStore.Values(null,java.util.Map.of(),"wrong-secret-password".toCharArray());
                    var scope=runtime.open(spec,secrets,System.nanoTime()+TimeUnit.SECONDS.toNanos(10)).get(5,TimeUnit.SECONDS);
                    var response=exchange(scope,lab.url("/whoami"))) {
                    assertEquals(401,response.status());assertEquals("REJECTED",events.getLast().stage().name());
                    assertTrue(events.getLast().message().contains("HTTP 401"));
                    assertFalse(events.toString().contains("wrong-secret-password"));assertFalse(events.toString().contains("alpha-password"));
                    assertFalse(events.stream().map(e->e.message()).toList().toString().contains("user-a"));
                }
            }
        }
    }
    @Test void browserAndDirectScopesShareLifecycleButKeepAccountsAndCloseIndependently() throws Exception {
        try(var lab=IntegrationFixtures.httpAuthentication("NTLM_V2",null);
            var runtime=new HttpTransportRuntime()) {
            var tls=SSLContext.getDefault();
            var a=new HttpAuthentication(HttpAuthentication.Protocol.NTLM_V2,"user-a","LAB","",Set.of(lab.url("/")));
            var b=new HttpAuthentication(HttpAuthentication.Protocol.NTLM_V2,"user-b","LAB","",Set.of(lab.url("/")));
            try(var browser=runtime.openBrowser(a,"alpha-password".toCharArray(),u->tls,null);
                var direct=runtime.open(b,"bravo-password".toCharArray(),u->tls,null)) {
                assertTrue(body(browser,lab.url("/whoami")).contains("user-a"));
                assertTrue(body(direct,lab.url("/whoami")).contains("user-b"));
                assertNotEquals(lab.observations.get(0).connection(),lab.observations.get(1).connection());
                browser.close();
                assertTrue(body(direct,lab.url("/whoami")).contains("user-b"));
                assertEquals(2,lab.handshakes.get());
                runtime.close();
                assertThrows(java.util.concurrent.ExecutionException.class,()->body(direct,lab.url("/whoami")));
            }
        }
    }

    @Test void browserMayVisitAnOrdinaryOriginWhileDirectPermissionRemainsExact() throws Exception {
        try(var selected=IntegrationFixtures.httpAuthentication("BASIC",null);
            var ordinary=IntegrationFixtures.httpAuthentication("BASIC",null);
            var runtime=new HttpTransportRuntime()) {
            var tls=SSLContext.getDefault();
            var auth=new HttpAuthentication(HttpAuthentication.Protocol.BASIC,"user-a","LAB","",Set.of(selected.url("/")));
            try(var browser=runtime.openBrowser(auth,"alpha-password".toCharArray(),u->tls,null);
                var direct=runtime.open(auth,"alpha-password".toCharArray(),u->tls,null)) {
                assertEquals("anonymous",body(browser,ordinary.url("/anonymous")));
                try(var response=exchange(browser,ordinary.url("/whoami"))) {
                    assertEquals(401,response.status());assertEquals(bpsh.authentication.http.HttpAuthenticationEvidence.Status.UNCONFIRMED,response.authentication().status());
                }
                assertTrue(browser.observations().isEmpty());
                assertEquals(0,ordinary.handshakes.get());
                int before=ordinary.requests.size();
                assertThrows(java.util.concurrent.ExecutionException.class,()->body(direct,ordinary.url("/whoami")));
                assertEquals(before,ordinary.requests.size());
                assertTrue(body(browser,selected.url("/whoami")).contains("user-a"));
            }
        }
    }

    @Test void scopeCapacityIsSharedAndClosingReleasesIt() throws Exception {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.resources.scopes");
        try(var runtime=new HttpTransportRuntime()) {
            var tls=SSLContext.getDefault();
            var scopes=new ArrayList<HttpAuthenticationService>();
            try {
                for(int i=0;i<32;i++)scopes.add(runtime.openBrowser(null,null,u->tls,null));
            proof.put("peak",runtime.capacity().scopes());
                assertThrows(IllegalStateException.class,()->runtime.openBrowser(null,null,u->tls,null));
                scopes.removeFirst().close();
                scopes.add(runtime.open(null,null,u->tls,null));
            } finally {scopes.forEach(HttpAuthenticationService::close);}
            runtime.close();
            proof.put("closed",runtime.capacity().scopes());
            assertThrows(IllegalStateException.class,()->runtime.openBrowser(null,null,u->tls,null));
        }
        proof.write();
    }
    @Test void factorySnapshotsSecretsBeforeReturningAndSurvivesImmediateCallerClose() throws Exception {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.resources.setup-snapshot");
        try(var lab=IntegrationFixtures.httpAuthentication("BASIC",null);var runtime=new HttpTransportRuntime()) {
            var auth=new HttpAuthentication(HttpAuthentication.Protocol.BASIC,"user-a","LAB","",Set.of(lab.url("/")));
            var identity=new bpsh.journey.JourneyDefinition.Identity(bpsh.journey.JourneyDefinition.Scope.PROJECT,java.util.UUID.randomUUID(),1);
            var spec=new bpsh.authentication.http.HttpTransportFactory.ScopeSpec(java.util.UUID.randomUUID(),bpsh.authentication.http.HttpTransportFactory.Purpose.BROWSER,
                    identity,0,new bpsh.journey.BrowserSetup(lab.url("/"),new bpsh.journey.JourneyDefinition.Browser(true,null,10000,1000),null,auth),false);
            var secrets=new bpsh.journey.SecretStore.Values(null,java.util.Map.of(),"alpha-password".toCharArray());
            var pending=runtime.open(spec,secrets,System.nanoTime()+TimeUnit.SECONDS.toNanos(5));secrets.close();
            try(var scope=pending.get(5,TimeUnit.SECONDS)) {assertTrue(body(scope,lab.url("/whoami")).contains("user-a"));proof.put("user",lab.observations.getFirst().user());}
            assertEquals(0,runtime.capacity().scopes());
            proof.put("closed",runtime.capacity().scopes());
        }
        proof.write();
    }
    @Test void shutdownRetiresQueuedAndLateFactoryResults() throws Exception {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.resources.setup-shutdown");
        var runtime=new HttpTransportRuntime();
        var identity=new bpsh.journey.JourneyDefinition.Identity(bpsh.journey.JourneyDefinition.Scope.PROJECT,java.util.UUID.randomUUID(),1);
        var pending=new ArrayList<java.util.concurrent.CompletableFuture<HttpAuthenticationService>>();
        try(var values=bpsh.journey.SecretStore.Values.empty()) {
            for(int i=0;i<32;i++)pending.add(runtime.open(new bpsh.authentication.http.HttpTransportFactory.ScopeSpec(java.util.UUID.randomUUID(),
                    bpsh.authentication.http.HttpTransportFactory.Purpose.BROWSER,identity,0,new bpsh.journey.BrowserSetup(URI.create("http://example.test"),
                    new bpsh.journey.JourneyDefinition.Browser(true,null,10000,1000),null),false),values,System.nanoTime()+TimeUnit.SECONDS.toNanos(5)));
        }
        runtime.close();
        for(var future:pending)future.handle((scope,error)->{if(scope!=null)scope.close();return null;}).get(5,TimeUnit.SECONDS);
        long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
        while((runtime.capacity().scopes()!=0 || runtime.capacity().activeSetup()!=0) && System.nanoTime()<end)
            java.util.concurrent.locks.LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(10));
        assertEquals(0,runtime.capacity().scopes());assertEquals(0,runtime.capacity().opening());assertEquals(0,runtime.capacity().queuedSetup());
        assertEquals(0,runtime.capacity().activeSetup());
            proof.put("scopes",runtime.capacity().scopes());proof.put("opening",runtime.capacity().opening());proof.put("queued",runtime.capacity().queuedSetup());proof.put("active",runtime.capacity().activeSetup());
        proof.write();
    }

    @Test void admissionIsGlobalAndPerScopeBeforeBodyAllocation() throws Exception {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.resources.admission");
        try(var runtime=new HttpTransportRuntime()) {
            var tls=SSLContext.getDefault();var scopes=new ArrayList<HttpAuthenticationService>();
            var leases=new ArrayList<HttpAuthenticationService.Delivery>();
            try {
                for(int i=0;i<4;i++) {
                    var scope=runtime.open(null,null,u->tls,null);scopes.add(scope);
                    for(int n=0;n<16;n++)leases.add(scope.admit(System.nanoTime()+TimeUnit.SECONDS.toNanos(5)));
                    assertThrows(java.io.IOException.class,()->scope.admit(System.nanoTime()+TimeUnit.SECONDS.toNanos(5)));
                }
                assertEquals(64,runtime.capacity().admittedDeliveries());assertEquals(0,runtime.capacity().bufferedBytes());
            proof.put("admitted",runtime.capacity().admittedDeliveries());proof.put("bytes",runtime.capacity().bufferedBytes());
                var extra=runtime.open(null,null,u->tls,null);scopes.add(extra);
                assertThrows(java.io.IOException.class,()->extra.admit(System.nanoTime()+TimeUnit.SECONDS.toNanos(5)));
                leases.removeFirst().close();
                leases.add(extra.admit(System.nanoTime()+TimeUnit.SECONDS.toNanos(5)));
            } finally {leases.forEach(HttpAuthenticationService.Delivery::close);scopes.forEach(HttpAuthenticationService::close);}
            assertEquals(0,runtime.capacity().admittedDeliveries());
            proof.put("closed",runtime.capacity().admittedDeliveries());
        }
        proof.write();
    }

    @Test void completedFutureKeepsAdmissionAndRequestBytesUntilItsWorkerActuallyExits() throws Exception {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.resources.running-ownership");
        try(var lab=IntegrationFixtures.httpAuthentication("BASIC",null);var runtime=new HttpTransportRuntime()) {
            var tls=SSLContext.getDefault();
            var auth=new HttpAuthentication(HttpAuthentication.Protocol.BASIC,"user-a","LAB","",Set.of(lab.url("/")));
            try(var scope=runtime.open(auth,"alpha-password".toCharArray(),u->tls,null);
                var lease=scope.admit(System.nanoTime()+TimeUnit.SECONDS.toNanos(10));var builder=runtime.bodies().builder(1<<20)) {
                builder.append(java.nio.ByteBuffer.wrap(new byte[1<<20]));var body=builder.finish();
                var future=lease.exchange(new HttpAuthenticationService.Request(lab.url("/held"),"POST",List.of(),body));body.close();
                var published=new java.util.concurrent.CountDownLatch(1);var releaseWorker=new java.util.concurrent.CountDownLatch(1);
                future.whenComplete((response,error)->{
                    published.countDown();
                    try {releaseWorker.await(5,TimeUnit.SECONDS);}catch(InterruptedException interrupted) {Thread.currentThread().interrupt();}
                });
                try {
                    lab.releaseResponse.complete(null);assertTrue(published.await(5,TimeUnit.SECONDS));
                    try(var response=future.get(5,TimeUnit.SECONDS)) {assertEquals(200,response.status());}
                    assertTrue(future.isDone());lease.close();
                    assertEquals(1,runtime.capacity().admittedDeliveries());
                    assertEquals(1<<20,runtime.capacity().bufferedBytes());
            proof.put("retainedAdmissions",runtime.capacity().admittedDeliveries());proof.put("retainedBytes",runtime.capacity().bufferedBytes());
                } finally {releaseWorker.countDown();}
                long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
                while(runtime.capacity().admittedDeliveries()!=0 && System.nanoTime()<end)java.util.concurrent.locks.LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(5));
                assertEquals(0,runtime.capacity().admittedDeliveries());assertEquals(0,runtime.capacity().bufferedBytes());
                assertEquals(1,lab.applicationPosts.get());
            proof.put("closedAdmissions",runtime.capacity().admittedDeliveries());proof.put("closedBytes",runtime.capacity().bufferedBytes());proof.put("posts",lab.applicationPosts.get());
            }
        }
        proof.write();
    }

    @Test void idleDirectScopesExpireButLiveBrowserScopesStayPinnedAndSurvivePressure() throws Exception {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.resources.pin-expiry");
        var clock=new java.util.concurrent.atomic.AtomicLong(1);
        try(var runtime=new HttpTransportRuntime(null,clock::get,TimeUnit.SECONDS.toNanos(30))) {
            var tls=SSLContext.getDefault();var all=new ArrayList<HttpAuthenticationService>();
            try {
                var browser=runtime.openBrowser(null,null,u->tls,null);all.add(browser);clock.incrementAndGet();
                var oldest=runtime.open(null,null,u->tls,null);all.add(oldest);
                for(int i=0;i<30;i++) {clock.incrementAndGet();all.add(runtime.open(null,null,u->tls,null));}
                clock.incrementAndGet();all.add(runtime.open(null,null,u->tls,null));
                assertFalse(oldest.isOpen());assertTrue(browser.isOpen());assertEquals(32,runtime.capacity().scopes());
            proof.put("pressureScopes",runtime.capacity().scopes());proof.put("oldestOpen",oldest.isOpen());
                clock.addAndGet(TimeUnit.SECONDS.toNanos(31));runtime.maintain();
                assertTrue(browser.isOpen());assertEquals(1,runtime.capacity().scopes());
                try(var admission=browser.admit(System.nanoTime()+TimeUnit.SECONDS.toNanos(1))) {assertEquals(1,runtime.capacity().admittedDeliveries());}
                assertEquals(0,runtime.capacity().admittedDeliveries());
            proof.put("remainingScopes",runtime.capacity().scopes());proof.put("browserOpen",browser.isOpen());proof.put("closedAdmissions",runtime.capacity().admittedDeliveries());
            } finally {all.forEach(HttpAuthenticationService::close);}
        }
        proof.write();
    }
    @Test void connectionBudgetIsSharedAndReclaimsOnlyIdleSockets() throws Exception {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.resources.connections");
        try(var lab=IntegrationFixtures.httpAuthentication("NTLM_V2",null);var runtime=new HttpTransportRuntime()) {
            var tls=SSLContext.getDefault();var scopes=new ArrayList<HttpAuthenticationService>();
            try {
                for(int i=0;i<17;i++) {
                    String user=i%2==0?"user-a":"user-b",password=i%2==0?"alpha-password":"bravo-password";
                    var auth=new HttpAuthentication(HttpAuthentication.Protocol.NTLM_V2,user,"LAB","",Set.of(lab.url("/")));
                    var scope=runtime.open(auth,password.toCharArray(),u->tls,null);scopes.add(scope);
                    assertTrue(body(scope,lab.url("/whoami")).contains(user));
                    assertTrue(runtime.capacity().connections()<=16);
                }
                assertEquals(16,runtime.capacity().peakConnections());
                assertTrue(scopes.getFirst().isOpen());
                assertTrue(body(scopes.getFirst(),lab.url("/whoami")).contains("user-a"));
            } finally {scopes.forEach(HttpAuthenticationService::close);}
            assertEquals(0,runtime.capacity().connections());
            proof.put("peak",runtime.capacity().peakConnections());proof.put("closed",runtime.capacity().connections());proof.put("accepted",lab.observations.size());
        }
        proof.write();
    }

    @Test void globalBodyBudgetRejectsBeforeAllocatingAndReleasesEveryOwner() throws Exception {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.resources.body-budget");
        try(var runtime=new HttpTransportRuntime()) {
            var bodies=new ArrayList<bpsh.authentication.http.HttpMessageBody>();
            try {
                byte[] block=new byte[8192];
                for(int owner=0;owner<8;owner++)try(var builder=runtime.bodies().builder(8*1024*1024)) {
                    for(int chunk=0;chunk<1024;chunk++)builder.append(java.nio.ByteBuffer.wrap(block));
                    bodies.add(builder.finish());
                }
                proof.put("retained",runtime.capacity().bufferedBytes());assertEquals(64L*1024*1024,runtime.capacity().bufferedBytes());
                try(var extra=runtime.bodies().builder(1)) {
                    var rejection=assertThrows(java.io.IOException.class,()->extra.append(java.nio.ByteBuffer.wrap(new byte[1])));
                    proof.put("rejected",rejection!=null);
                }
            } finally {bodies.forEach(bpsh.authentication.http.HttpMessageBody::close);}
            proof.put("released",runtime.capacity().bufferedBytes());assertEquals(0,runtime.capacity().bufferedBytes());
        }
        proof.write();
    }

    @Test void httpsTunnelSeparatesProxySetupFromDestinationAuthentication(
            @org.junit.jupiter.api.io.TempDir java.nio.file.Path temporary) throws Exception {
        var ca=lab.auth.LabTls.prepare(temporary.resolve("ca"));
        var material=lab.auth.LabTls.createServer(ca,temporary.resolve("server"));
        var tls=material.clientContext();
        for(var protocol:java.util.Arrays.asList(null,HttpAuthentication.Protocol.BASIC,HttpAuthentication.Protocol.NTLM_V1,HttpAuthentication.Protocol.NTLM_V2)) {
            try(var server=IntegrationFixtures.httpAuthentication(protocol==null?"BASIC":protocol.name(),material.serverContext());
                var upstream=new lab.auth.TransportFixtures.UnauthenticatedProxy(null,u->u.getPort()==server.url("/").getPort());
                var runtime=new HttpTransportRuntime()) {
                var settings=protocol==null?null:new HttpAuthentication(protocol,"user-a","LAB","",Set.of(server.url("/")));
                try(var scope=runtime.openBrowser(settings,protocol==null?null:"alpha-password".toCharArray(),u->tls,upstream.url())) {
                    for(int repeat=0;repeat<2;repeat++)try(var response=exchange(scope,server.url(protocol==null?"/anonymous":"/whoami"))) {
                        assertEquals(200,response.status());
                        assertEquals(protocol==null?bpsh.authentication.http.HttpAuthenticationEvidence.Status.UNCONFIRMED:
                                bpsh.authentication.http.HttpAuthenticationEvidence.Status.ACCEPTED,response.authentication().status());
                        if(protocol!=null)assertEquals(protocol,response.authentication().protocol());
                    }
                    assertTrue(upstream.requestCounter().get()>0,"The configured proxy must carry the tunnel.");
                    assertEquals(0,upstream.credentialHeaders());
                    if(protocol==HttpAuthentication.Protocol.NTLM_V1 || protocol==HttpAuthentication.Protocol.NTLM_V2)assertEquals(1,server.handshakes.get());
                }
            }
        }
    }

    private static HttpAuthenticationService.Response exchange(HttpAuthenticationService scope,URI url) throws Exception {
        return bpsh.support.IntegrationFixtures.httpExchange(scope,new HttpAuthenticationService.Request(url,"GET",List.of(),bpsh.support.IntegrationFixtures.httpBody(new byte[0])),
                System.nanoTime()+TimeUnit.SECONDS.toNanos(5)).get(6,TimeUnit.SECONDS);
    }
    private static String body(HttpAuthenticationService scope,URI url) throws Exception {
        return new String(bpsh.support.IntegrationFixtures.httpBytes(exchange(scope,url)),StandardCharsets.UTF_8);
    }
}
