package bpsh.authentication.http;

import bpsh.journey.HttpAuthentication;
import bpsh.journey.JourneyCatalog;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.SecretStore;
import org.junit.jupiter.api.Test;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

class HttpIdentityManagerTest {
    @Test void activeIdentityLimitIsATypedPredispatchCapacityRefusal() throws Exception {
        var entries=java.util.stream.IntStream.range(0,33).mapToObj(i->{var base=entry();var d=base.definition();return new JourneyCatalog.Entry(base.identity(),
                new JourneyDefinition(d.id(),d.displayName(),"account-"+i,d.authenticationUrl(),false,d.steps(),d.browser(),null,d.injection(),d.cache(),null,d.httpAuthentication(),null));}).toList();
        var indexed=new java.util.HashMap<bpsh.journey.JourneyKey,JourneyCatalog.Entry>();entries.forEach(e->indexed.put(e.identity().key(),e));
        var aliases=new java.util.HashMap<String,List<bpsh.journey.JourneyKey>>();entries.forEach(e->aliases.put(e.definition().canonicalAlias(),List.of(e.identity().key())));
        var leases=new java.util.ArrayList<HttpAuthenticationService.Delivery>();
        try(var secrets=new SecretStore();var manager=new HttpIdentityManager(()->new JourneyCatalog.Snapshot(indexed,aliases,Set.of()),secrets,factory((spec,values,recovery,end)->new Fake()))) {
            try {
                for(int i=0;i<32;i++)leases.add(manager.admit(manager.select(entries.get(i)),deadline()).get(2,TimeUnit.SECONDS));
                var failure=assertThrows(java.util.concurrent.ExecutionException.class,()->manager.admit(manager.select(entries.get(32)),deadline()).get(2,TimeUnit.SECONDS));
                assertInstanceOf(HttpCapacityException.class,failure.getCause());
            } finally {leases.forEach(HttpAuthenticationService.Delivery::close);}
        }
    }
    private static final URI ORIGIN=URI.create("https://example.test");
    private static JourneyCatalog.Entry entry() {
        UUID id=UUID.randomUUID();
        return new JourneyCatalog.Entry(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT,id,1),
                new JourneyDefinition(id,"User A","user-a",ORIGIN,false,List.of(),new JourneyDefinition.Browser(true,null,30000,1000),
                        null,JourneyDefinition.Injection.perToken(List.of()),new JourneyDefinition.Cache(1800,10),null,
                        new HttpAuthentication(HttpAuthentication.Protocol.NTLM_V2,"user-a","LAB","",Set.of(ORIGIN)),null));
    }
    @Test void automaticWarmupIsSingleFlightHeadInTheDirectPoolAndClearFencesReadiness() throws Exception {
        var entry=entry();var scope=new Fake();var opened=new AtomicReference<HttpTransportFactory.ScopeSpec>();
        try(var secrets=new SecretStore();var manager=new HttpIdentityManager(()->snapshot(entry),secrets,factory((spec,values,recovery,end)->{opened.set(spec);return scope;}))) {
            var selected=manager.select(entry);var target=ORIGIN.resolve("/protected?choice=1");
            var first=manager.warm(selected,target,deadline());var second=manager.warm(selected,target,deadline());assertSame(first,second);
            assertEquals(1,scope.requests.get());assertEquals("HEAD",scope.last.method());assertEquals(target,scope.last.uri());
            assertTrue(scope.last.headers().isEmpty());assertEquals(0,scope.last.bodyLength());
            assertEquals(HttpTransportFactory.Purpose.DIRECT,opened.get().purpose());assertFalse(manager.hasRecentAuthentication(selected,target));
            scope.response.complete(new HttpAuthenticationService.Response(200,List.of(),bpsh.support.IntegrationFixtures.httpBody(new byte[0]),
                    new HttpAuthenticationEvidence(HttpAuthentication.Protocol.NTLM_V2,HttpAuthenticationEvidence.Status.ACCEPTED)));
            first.get(1,TimeUnit.SECONDS);assertTrue(manager.hasRecentAuthentication(selected,target));
            manager.invalidate(entry.identity());assertFalse(manager.hasRecentAuthentication(selected,target));
            assertTrue(manager.warm(selected,target,deadline()).isCompletedExceptionally());assertEquals(1,scope.requests.get());
        }
    }
    @Test void clearingAnIdentityCancelsItsBackgroundAuthentication() throws Exception {
        var entry=entry();var scope=new Fake();
        try(var secrets=new SecretStore();var manager=new HttpIdentityManager(()->snapshot(entry),secrets,factory((spec,values,recovery,end)->scope))) {
            var warm=manager.warm(manager.select(entry),ORIGIN.resolve("/protected"),deadline());assertFalse(warm.isDone());
            manager.invalidate(entry.identity());assertTrue(warm.isCompletedExceptionally());assertTrue(scope.response.isCancelled());
        }
    }
    private static JourneyCatalog.Entry certificateEntry() {
        var base=entry();var d=base.definition();
        var mtls=new JourneyDefinition.Mtls("fixture-module",new JourneyDefinition.Slot(JourneyDefinition.SlotKind.INDEX,0),"12".repeat(32),List.of(ORIGIN),null);
        return new JourneyCatalog.Entry(base.identity(),new JourneyDefinition(d.id(),d.displayName(),d.alias(),ORIGIN,false,List.of(),
                new JourneyDefinition.Browser(true,null,30000,3000,false,false),null,d.injection(),d.cache(),mtls,null,null));
    }
    @Test void certificateOnlyTestsUseTheSharedTransportWithoutAReusableToken() throws Exception {
        var entry=certificateEntry();var scope=new Fake();scope.response.complete(new HttpAuthenticationService.Response(200,List.of(),
                bpsh.support.IntegrationFixtures.httpBody(new byte[0]),new HttpAuthenticationEvidence(null,HttpAuthenticationEvidence.Status.UNCONFIRMED)));
        var setup=new AtomicReference<HttpTransportFactory.ScopeSpec>();
        try(var secrets=new SecretStore();var manager=new HttpIdentityManager(()->snapshot(entry),secrets,factory((spec,values,recovery,end)->{setup.set(spec);return scope;}));
            var response=manager.test(entry,deadline(),false).get(5,TimeUnit.SECONDS)) {
            assertEquals(200,response.status());assertEquals(1,scope.requests.get());assertNull(setup.get().setup().httpAuthentication());
            assertEquals(entry.definition().mtls(),setup.get().setup().mtls());assertEquals(HttpTransportFactory.Purpose.TEST,setup.get().purpose());
        }
    }
    @Test void certificateOnlyDeliveryRejectsAnUnrelatedOriginBeforeDispatch() throws Exception {
        var entry=certificateEntry();var scope=new Fake();
        try(var secrets=new SecretStore();var manager=new HttpIdentityManager(()->snapshot(entry),secrets,factory((spec,values,recovery,end)->scope))) {
            var outside=new HttpAuthenticationService.Request(URI.create("https://unrelated.test"),"GET",List.of(),bpsh.support.IntegrationFixtures.httpBody(new byte[0]));
            assertThrows(java.util.concurrent.ExecutionException.class,()->deliver(manager,entry,outside,deadline()).get(5,TimeUnit.SECONDS));
            assertEquals(0,scope.requests.get());
        }
    }
    @Test void anUnvalidatedCertificateDraftCannotOpenTransport() throws Exception {
        var original=certificateEntry();var d=original.definition();var raw=bpsh.journey.JourneyDraft.capture(Map.of("url","not a URL"),
                Map.of("mtls",true,"formAuthentication",false),JourneyDefinition.SlotKind.INDEX,"",List.of(),List.of());
        var entry=new JourneyCatalog.Entry(original.identity(),new JourneyDefinition(d.id(),d.displayName(),d.alias(),d.authenticationUrl(),false,List.of(),
                d.browser(),null,d.injection(),d.cache(),d.mtls(),null,raw));
        var opened=new AtomicInteger();var scope=new Fake();scope.response.complete(response());
        try(var secrets=new SecretStore();var manager=new HttpIdentityManager(()->snapshot(entry),secrets,factory((spec,values,recovery,end)->{opened.incrementAndGet();return scope;}))) {
            assertThrows(java.util.concurrent.ExecutionException.class,()->manager.test(entry,deadline(),false).get(5,TimeUnit.SECONDS));assertEquals(0,opened.get());
        }
    }
    private static JourneyCatalog.Snapshot snapshot(JourneyCatalog.Entry entry) {
        return new JourneyCatalog.Snapshot(Map.of(entry.identity().key(),entry),Map.of("user-a",List.of(entry.identity().key())),Set.of());
    }
    private static long deadline() {return System.nanoTime()+TimeUnit.SECONDS.toNanos(5);}
    private static HttpAuthenticationService.Request request() {return new HttpAuthenticationService.Request(ORIGIN,"GET",List.of(),bpsh.support.IntegrationFixtures.httpBody(new byte[0]));}
    private static HttpAuthenticationService.Response response() {return new HttpAuthenticationService.Response(200,List.of(),bpsh.support.IntegrationFixtures.httpBody(new byte[0]),new HttpAuthenticationEvidence(HttpAuthentication.Protocol.NTLM_V2,HttpAuthenticationEvidence.Status.ACCEPTED));}
    private static final class Fake implements HttpAuthenticationService {
        final CompletableFuture<Response> response=new CompletableFuture<>();
        final AtomicInteger requests=new AtomicInteger(),closed=new AtomicInteger();
        volatile HttpAuthenticationService.Request last;
        @Override public boolean isOpen() {return true;}
            @Override public Delivery admit(long deadline) {return bpsh.support.IntegrationFixtures.httpDelivery(request->{last=request;requests.incrementAndGet();return response;});}
        @Override public void close() {closed.incrementAndGet();}
    }
    private static CompletableFuture<HttpAuthenticationService.Response> deliver(HttpIdentityManager manager,JourneyCatalog.Entry entry,HttpAuthenticationService.Request request,long end) {
        return deliver(manager,manager.select(entry),request,end);
    }
    private static CompletableFuture<HttpAuthenticationService.Response> deliver(HttpIdentityManager manager,HttpIdentityManager.Selection selection,HttpAuthenticationService.Request request,long end) {
        var result=new CompletableFuture<HttpAuthenticationService.Response>();var admission=manager.admit(selection,end);
        result.whenComplete((value,error)->{if(error!=null)admission.cancel(true);});
        admission.whenComplete((lease,error)->{
            if(error!=null) {request.body().close();result.completeExceptionally(error);return;}
            if(result.isDone()) {lease.close();request.body().close();return;}
            var operation=lease.exchange(request);
            result.whenComplete((value,failure)->{if(failure!=null)operation.cancel(true);});
            operation.whenComplete((value,failure)->{
                request.body().close();
                if(failure!=null)result.completeExceptionally(failure);else if(!result.complete(value))value.close();
                lease.close();
            });
        });return result;
    }
    @FunctionalInterface interface FakeSetup {
        HttpAuthenticationService open(HttpTransportFactory.ScopeSpec spec,SecretStore.Values values,boolean recovery,long deadline) throws Exception;
    }
    static HttpTransportFactory factory(FakeSetup setup) {
        return new HttpTransportFactory() {
            private final HttpMessageBody.Allocator bodies=new HttpMessageBody.Allocator(64L*1024*1024);
            @Override public CompletableFuture<HttpAuthenticationService> open(ScopeSpec spec,SecretStore.Values values,long deadline) {
                try {return CompletableFuture.completedFuture(setup.open(spec,values,spec.explicitRecovery(),deadline));}
                catch(Exception failure) {return CompletableFuture.failedFuture(failure);}
            }
            @Override public HttpMessageBody.Allocator bodies() {return bodies;}
            @Override public void close() { }
        };
    }
    @Test void oneScopeServesAnIdentityButFreshTestsAndInvalidationHaveSeparateLifetimes() throws Exception {
        var entry=entry();var created=new CopyOnWriteArrayList<Fake>();
        try(var secrets=new SecretStore();var manager=new HttpIdentityManager(()->snapshot(entry),secrets,factory((selected,values,recovery,end)->{
            Fake scope=new Fake();created.add(scope);scope.response.complete(response());return scope;
        }))) {
            deliver(manager,entry,request(),deadline()).get(5,TimeUnit.SECONDS);
            deliver(manager,entry,request(),deadline()).get(5,TimeUnit.SECONDS);
            assertEquals(1,created.size());assertEquals(2,created.getFirst().requests.get());
            manager.test(entry,deadline(),false).get(5,TimeUnit.SECONDS);
            assertEquals(2,created.size());assertEquals(0,created.getFirst().closed.get());
            manager.invalidate(entry.identity());assertTrue(created.getFirst().closed.get()>0);
            deliver(manager,entry,request(),deadline()).get(5,TimeUnit.SECONDS);assertEquals(3,created.size());
        }
    }
    @Test void clearedOrEditedIdentitiesCannotDeliverLateResults() throws Exception {
        var entry=entry();var current=new AtomicReference<>(snapshot(entry));var scope=new Fake();var entered=new java.util.concurrent.CountDownLatch(1);
        try(var secrets=new SecretStore();var manager=new HttpIdentityManager(current::get,secrets,factory((selected,values,recovery,end)->{entered.countDown();return scope;}))) {
            var result=deliver(manager,entry,request(),deadline());assertTrue(entered.await(5,TimeUnit.SECONDS));
            current.set(new JourneyCatalog.Snapshot(Map.of(),Map.of(),Set.of()));manager.reconcile();
            scope.response.complete(response());
            assertThrows(java.util.concurrent.ExecutionException.class,()->result.get(5,TimeUnit.SECONDS));
            assertTrue(scope.closed.get()>0);
        }
    }
    @Test void cancellationAbortsOnlyItsOwnDelivery() throws Exception {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.lifecycle.cancel-own");
        var entry=entry();var scope=new Fake();var observed=new java.util.concurrent.CountDownLatch(1);
        try(var secrets=new SecretStore();var manager=new HttpIdentityManager(()->snapshot(entry),secrets,factory((selected,values,recovery,end)->new HttpAuthenticationService() {
            @Override public boolean isOpen() {return true;}
            @Override public Delivery admit(long budget) {return bpsh.support.IntegrationFixtures.httpDelivery(request->{observed.countDown();return scope.response;});}
            @Override public void close() {scope.close();}
        }))) {
            var delivery=deliver(manager,entry,request(),deadline());assertTrue(observed.await(5,TimeUnit.SECONDS));delivery.cancel(true);
            assertTrue(scope.response.isCancelled());assertEquals(0,scope.closed.get());
            proof.put("deliveryCancelled",scope.response.isCancelled());proof.put("scopeClosedBeforeOwner",scope.closed.get());
        }
        proof.write();
    }
    @Test void selectionMadeBeforeClearCannotOpenAScopeAfterDependentWait() throws Exception {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.lifecycle.early-epoch");
        var entry=entry();var opened=new AtomicInteger();
        try(var secrets=new SecretStore();var manager=new HttpIdentityManager(()->snapshot(entry),secrets,factory((selected,values,recovery,end)->{
            opened.incrementAndGet();var scope=new Fake();scope.response.complete(response());return scope;
        }))) {
            var beforeClear=manager.select(entry);
            manager.invalidate(entry.identity());
            assertThrows(java.util.concurrent.ExecutionException.class,()->deliver(manager,beforeClear,request(),deadline()).get(5,TimeUnit.SECONDS));
            assertEquals(0,opened.get());
            proof.put("staleOpened",opened.get());
            deliver(manager,manager.select(entry),request(),deadline()).get(5,TimeUnit.SECONDS);
            assertEquals(1,opened.get());
            proof.put("freshOpened",opened.get());
        }
        proof.write();
    }
    @Test void synchronousTransportFailureCompletesWithoutWaitingForTheDeadline() throws Exception {
        var entry=entry();
        try(var secrets=new SecretStore();var manager=new HttpIdentityManager(()->snapshot(entry),secrets,factory((selected,values,recovery,end)->new HttpAuthenticationService() {
            @Override public boolean isOpen() {return true;}
            @Override public Delivery admit(long end) {return bpsh.support.IntegrationFixtures.httpDelivery(request->{throw new IllegalStateException("fixture");});}
            @Override public void close() { }
        }))) {
            assertThrows(java.util.concurrent.ExecutionException.class,()->deliver(manager,entry,request(),deadline()).get(1,TimeUnit.SECONDS));
        }
    }

    @Test void retirementCancelsPendingSetupAndReconcileAllowsReentrantFactoryCleanup() throws Exception {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.lifecycle.retire-setup");
        for(String action:List.of("invalidate","reconcile","close")) {
            var entry=entry();var current=new AtomicReference<>(snapshot(entry));
            var opening=new CompletableFuture<HttpAuthenticationService>();
            var factory=new HttpTransportFactory() {
                final HttpMessageBody.Allocator bodies=new HttpMessageBody.Allocator(1024);
                @Override public CompletableFuture<HttpAuthenticationService> open(ScopeSpec spec,SecretStore.Values values,long deadline) {return opening;}
                @Override public HttpMessageBody.Allocator bodies() {return bodies;}
                @Override public void close() { }
            };
            try(var secrets=new SecretStore();var manager=new HttpIdentityManager(current::get,secrets,factory)) {
                var waiting=manager.admit(manager.select(entry),deadline());assertFalse(waiting.isDone());
                switch(action) {
                    case "invalidate" -> manager.invalidate(entry.identity());
                    case "reconcile" -> {current.set(new JourneyCatalog.Snapshot(Map.of(),Map.of(),Set.of()));manager.reconcile();}
                    case "close" -> manager.close();
                }
                assertTrue(opening.isCancelled(),action);
            proof.put(""+action+"",opening.isCancelled());
                assertThrows(java.util.concurrent.ExecutionException.class,()->waiting.get(1,TimeUnit.SECONDS),action);
                manager.close();assertTrue(manager.admit(manager.select(entry),deadline()).isCompletedExceptionally());
            }
        }
        proof.write();
    }

}
