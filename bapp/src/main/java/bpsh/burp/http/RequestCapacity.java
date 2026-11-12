package bpsh.burp.http;

import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.JourneyKey;
import bpsh.request.RequestSettings;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Nonblocking admission for complete callback lifetimes and conservative request-copy reservations. */
final class RequestCapacity {
    private static final long MAX_BYTES = 512L << 20;
    private final Map<JourneyKey, Integer> journeys = new HashMap<>();
    private int active;
    private long bytes;

    /** Reserves before materialization; capacity exhaustion never queues another callback. */
    synchronized Lease admit(RequestSettings.Controls controls, Collection<JourneyKey> keys, long weight) throws AuthenticationFailure {
        if (weight < 0 || active >= controls.maxWaitingRequestsGlobal() || weight > MAX_BYTES - bytes) throw exhausted();
        var lease = new Lease(controls, weight);
        lease.bind(keys); active++; bytes += weight; return lease;
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
            }
        }
    }

    /** Returns fixed diagnostics without request or credential contents. */
    private static AuthenticationFailure exhausted() {
        return new AuthenticationFailure(AuthenticationFailure.Phase.QUEUE, AuthenticationFailure.Cause.CAPACITY,
                "The authentication request capacity or memory budget is exhausted.", "Reduce request size or concurrency, or resend after active requests finish.");
    }
}
