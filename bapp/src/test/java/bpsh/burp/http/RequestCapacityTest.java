package bpsh.burp.http;

import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.JourneyKey;
import bpsh.request.RequestSettings;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Verifies atomic, nonblocking admission and complete release across callback stages. */
class RequestCapacityTest {
    @Test void queuedPayloadsLeaveHeadroomForOneWaiterToBecomeActive() throws Exception {
        var cfg=new RequestSettings.Controls(false,List.of(),List.of(),60000,60000,300000,3,1);
        var a=new JourneyKey(JourneyDefinition.Scope.PROJECT,UUID.randomUUID());var capacity=new RequestCapacity();
        try(var workers=java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor();var first=capacity.admit(cfg,List.of(a),1)) {
            var checked=new java.util.concurrent.CountDownLatch(2);
            var queued=workers.submit(()->capacity.admitHttp(cfg,List.of(a),272L<<20,System.nanoTime()+5_000_000_000L,()->{checked.countDown();return false;}));
            assertTrue(checked.await(2,java.util.concurrent.TimeUnit.SECONDS));
            try {
                var failure=assertThrows(AuthenticationFailure.class,()->capacity.admitHttp(cfg,List.of(a),264L<<20,System.nanoTime()+200_000_000L,()->false));
                assertEquals(AuthenticationFailure.Cause.CAPACITY,failure.reason(),"Queued payloads must not consume the headroom needed to deliver any queued request.");
            } finally {first.close();try(var granted=queued.get(2,java.util.concurrent.TimeUnit.SECONDS)){assertNotNull(granted);}}
        }
    }
    @Test void queuedPayloadBytesShareTheMemoryBoundAndTransferWithoutBlockingThemselves() throws Exception {
        var cfg=new RequestSettings.Controls(false,List.of(),List.of(),60000,60000,300000,3,1);
        var a=new JourneyKey(JourneyDefinition.Scope.PROJECT,UUID.randomUUID());var capacity=new RequestCapacity();
        try(var workers=java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor();var first=capacity.admit(cfg,List.of(a),256L<<20)) {
            var checked=new java.util.concurrent.CountDownLatch(2);
            var queued=workers.submit(()->capacity.admitHttp(cfg,List.of(a),256L<<20,System.nanoTime()+5_000_000_000L,()->{checked.countDown();return false;}));
            assertTrue(checked.await(2,java.util.concurrent.TimeUnit.SECONDS));
            assertThrows(AuthenticationFailure.class,()->capacity.admit(cfg,List.of(),17L<<20));
            first.close();
            try(var transferred=queued.get(2,java.util.concurrent.TimeUnit.SECONDS);var remainder=capacity.admit(cfg,List.of(),256L<<20)) {assertNotNull(transferred);assertNotNull(remainder);}
        }
        try(var all=capacity.admit(cfg,List.of(a),512L<<20)) {assertNotNull(all);}
    }
    @Test void queuedHttpWorkSharesTheGlobalBoundAndCancellationReleasesIt() throws Exception {
        var cfg=new RequestSettings.Controls(false,List.of(),List.of(),60000,60000,300000,2,1);
        var a=new JourneyKey(JourneyDefinition.Scope.PROJECT,UUID.randomUUID());var capacity=new RequestCapacity();
        var cancelled=new java.util.concurrent.atomic.AtomicBoolean();var checked=new java.util.concurrent.CountDownLatch(2);
        try(var workers=java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor();var first=capacity.admit(cfg,List.of(a),1)) {
            var queued=workers.submit(()->assertThrows(AuthenticationFailure.class,()->capacity.admitHttp(cfg,List.of(a),1,System.nanoTime()+5_000_000_000L,
                    ()->{checked.countDown();return cancelled.get();})));
            assertTrue(checked.await(2,java.util.concurrent.TimeUnit.SECONDS));
            assertEquals(AuthenticationFailure.Cause.CAPACITY,assertThrows(AuthenticationFailure.class,()->capacity.admit(cfg,List.of(),1)).reason());
            cancelled.set(true);assertEquals(AuthenticationFailure.Cause.CANCELLED,queued.get(2,java.util.concurrent.TimeUnit.SECONDS).reason());
            try(var second=capacity.admit(cfg,List.of(),1)) {assertNotNull(second);}
        }
        try(var all=capacity.admit(cfg,List.of(a),512L<<20)) {assertNotNull(all);}
    }

    @Test void aWaitingHttpLeaseWakesOnReleaseAndCannotExceedTheNativeScopeLimit() throws Exception {
        var cfg=new RequestSettings.Controls(false,List.of(),List.of(),60000,60000,300000,64,64);
        var a=new JourneyKey(JourneyDefinition.Scope.PROJECT,UUID.randomUUID());var capacity=new RequestCapacity();
        var leases=new java.util.ArrayList<RequestCapacity.Lease>();
        try(var workers=java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()) {
            try {
                for(int i=0;i<16;i++)leases.add(capacity.admitHttp(cfg,List.of(a),1,System.nanoTime()+5_000_000_000L,()->false));
                var checked=new java.util.concurrent.CountDownLatch(2);
                var queued=workers.submit(()->capacity.admitHttp(cfg,List.of(a),1,System.nanoTime()+5_000_000_000L,()->{checked.countDown();return false;}));
                assertTrue(checked.await(2,java.util.concurrent.TimeUnit.SECONDS));assertFalse(queued.isDone());
                leases.removeLast().close();
                try(var granted=queued.get(2,java.util.concurrent.TimeUnit.SECONDS)) {assertNotNull(granted);}
            } finally {leases.forEach(RequestCapacity.Lease::close);}
        }
        try(var all=capacity.admit(cfg,List.of(a),512L<<20)) {all.close();assertThrows(AuthenticationFailure.class,()->all.bind(List.of(a)));}
    }
    @Test void defaultsAreFiniteAndPerJourneyRefusalDoesNotLeakGlobalCapacity() throws Exception {
        assertEquals(64, RequestSettings.Controls.defaults().maxWaitingRequestsGlobal());
        assertEquals(16, RequestSettings.Controls.defaults().maxWaitingRequestsPerJourney());
        var cfg = new RequestSettings.Controls(false, List.of(), List.of(), 60000, 60000, 300000, 2, 1);
        var a = new JourneyKey(JourneyDefinition.Scope.PROJECT, UUID.randomUUID());
        var b = new JourneyKey(JourneyDefinition.Scope.PROJECT, UUID.randomUUID());
        var capacity = new RequestCapacity();
        try (var first = capacity.admit(cfg, List.of(a), 1)) {
            assertEquals(AuthenticationFailure.Cause.CAPACITY, assertThrows(AuthenticationFailure.class, () -> capacity.admit(cfg, List.of(a), 1)).reason());
            try (var second = capacity.admit(cfg, List.of(), 1)) {
                assertThrows(AuthenticationFailure.class, () -> second.bind(List.of(b, a)));
                second.bind(List.of(b)); second.bind(List.of(b));
                assertThrows(AuthenticationFailure.class, () -> capacity.admit(cfg, List.of(), 1));
            }
            try (var released = capacity.admit(cfg, List.of(b), 1)) { released.close(); }
        }
        assertThrows(AuthenticationFailure.class, () -> capacity.admit(cfg, List.of(), Long.MAX_VALUE));
        try (var allMemory = capacity.admit(cfg, List.of(a), 512L << 20)) {
            assertThrows(AuthenticationFailure.class, () -> capacity.admit(cfg, List.of(b), 1));
        }
        try (var released = capacity.admit(cfg, List.of(a), 512L << 20)) { assertNotNull(released); }
    }
}
