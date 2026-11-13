package bpsh.burp.http;

import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.JourneyKey;
import bpsh.request.RequestSettings;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Bounded callback admission and conservative request-copy reservations. */
final class RequestCapacity {
    private static final long MAX_BYTES = 512L << 20;
    private static final long DELIVERY_HEADROOM = 16L << 20;
    private static final int MAX_HTTP_WAITERS = 64;
    private final Map<JourneyKey, Integer> journeys = new HashMap<>();
    private int active;
    private int waiting;
    private long bytes;
    private long waitingBytes;

    /** Reserves before materialization; capacity exhaustion never queues another callback. */
    synchronized Lease admit(RequestSettings.Controls controls, Collection<JourneyKey> keys, long weight) throws AuthenticationFailure {
        if (weight < 0 || active + waiting >= controls.maxWaitingRequestsGlobal() || weight > MAX_BYTES - bytes - waitingBytes) throw exhausted();
        var lease = new Lease(controls, weight);
        lease.bind(keys); active++; bytes += weight; return lease;
    }

    /** Waits only at the delivery boundary; queued callbacks retain no transport/body reservation. */
    synchronized Lease admitHttp(RequestSettings.Controls controls, Collection<JourneyKey> keys, long weight,
                                 long deadline, java.util.function.BooleanSupplier cancelled) throws AuthenticationFailure, InterruptedException {
        if(weight<0 || weight>MAX_BYTES || active+waiting>=controls.maxWaitingRequestsGlobal())throw exhausted();
        boolean queued=false;
        long payloadWeight=Math.max(0,weight-DELIVERY_HEADROOM);
        try {
            while(true) {
                if(cancelled.getAsBoolean())throw new AuthenticationFailure(AuthenticationFailure.Phase.QUEUE,AuthenticationFailure.Cause.CANCELLED,
                        "Automatic HTTP authentication was cancelled before sending the request.");
                long left=deadline-System.nanoTime();
                if(left<=0)throw new AuthenticationFailure(AuthenticationFailure.Phase.QUEUE,AuthenticationFailure.Cause.TIMEOUT,
                        "The request deadline expired while waiting for HTTP authentication capacity.","Retry after active requests finish.");
                boolean available=weight<=MAX_BYTES-bytes-waitingBytes+(queued?payloadWeight:0) && keys.stream().distinct().allMatch(key->
                        journeys.getOrDefault(key,0)<Math.min(controls.maxWaitingRequestsPerJourney(),bpsh.authentication.http.HttpAuthenticationService.MAX_ADMITTED_DELIVERIES));
                if(available) {
                    var lease=new Lease(controls,weight);lease.bind(keys);active++;bytes+=weight;return lease;
                }
                if(controls.requestPolicy()!=RequestSettings.RequestPolicy.WAIT_FOR_LOGIN || !queued && waiting>=MAX_HTTP_WAITERS)throw exhausted();
                if(!queued) {
                    // Keep enough room to promote at least one queued payload into a delivery.
                    if(payloadWeight>MAX_BYTES-DELIVERY_HEADROOM-bytes-waitingBytes)throw exhausted();
                    waiting++;waitingBytes+=payloadWeight;queued=true;
                }
                java.util.concurrent.TimeUnit.NANOSECONDS.timedWait(this,Math.min(left,50_000_000L));
            }
        } finally {if(queued) {waiting--;waitingBytes-=payloadWeight;notifyAll();}}
    }

    /** One callback owns one global reservation across acquisition, identity setup and delivery. */
    final class Lease implements AutoCloseable {
        private final RequestSettings.Controls controls;
        private final long weight;
        private List<JourneyKey> keys = List.of();
        private boolean closed;
        private Lease(RequestSettings.Controls controls, long weight) { this.controls = controls; this.weight = weight; }
        /** Binds a parsed explicit identity before its potentially blocking setup. */
        void bind(Collection<JourneyKey> identities) throws AuthenticationFailure {
            synchronized (RequestCapacity.this) {
                if(closed)throw new AuthenticationFailure(AuthenticationFailure.Phase.QUEUE,AuthenticationFailure.Cause.CANCELLED,"The authentication request reservation was released.");
                var added = identities.stream().distinct().filter(key -> !keys.contains(key)).toList();
                for (var key : added) if (journeys.getOrDefault(key, 0) >= controls.maxWaitingRequestsPerJourney()) throw exhausted();
                added.forEach(key -> journeys.merge(key, 1, Integer::sum));
                var all = new java.util.ArrayList<>(keys); all.addAll(added); keys = List.copyOf(all);
            }
        }
        @Override public void close() {
            synchronized (RequestCapacity.this) {
                if (closed) return; closed = true; active--; bytes -= weight;
                keys.forEach(key -> journeys.compute(key, (ignored, count) -> count == 1 ? null : count - 1));
                RequestCapacity.this.notifyAll();
            }
        }
    }

    /** Returns fixed diagnostics without request or credential contents. */
    private static AuthenticationFailure exhausted() {
        return new AuthenticationFailure(AuthenticationFailure.Phase.QUEUE, AuthenticationFailure.Cause.CAPACITY,
                "The authentication request capacity or memory budget is exhausted.", "Reduce request size or concurrency, or resend after active requests finish.");
    }
}
