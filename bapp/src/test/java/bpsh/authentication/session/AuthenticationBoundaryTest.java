package bpsh.authentication.session;

import bpsh.authentication.AuthenticationPolicy;
import bpsh.authentication.credentials.AuthenticationResult;
import bpsh.journey.JourneyCatalog;
import bpsh.journey.JourneyDefinition;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises the core through its ports without a workspace, JSON document or host settings. */
class AuthenticationBoundaryTest {
    private static final AuthenticationPolicy POLICY = new AuthenticationPolicy() {
        public int requestWaitTimeoutMs() { return 1000; }
        public int attemptTimeoutMs() { return 1000; }
        public int cycleTimeoutMs() { return 2000; }
        public Integer maxWaitingRequestsGlobal() { return 1; }
        public Integer maxWaitingRequestsPerJourney() { return 1; }
    };

    @Test void acquiresAndCachesThroughReadOnlyCatalog() {
        var definition = CoordinatorFixtures.journey("employee");
        var identity = new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, definition.id(), 1);
        var entry = new JourneyCatalog.Entry(identity, definition);
        JourneyCatalog catalog = () -> new JourneyCatalog.Snapshot(Map.of(identity.key(), entry), Map.of("employee", List.of(identity.key())), Set.of());
        var clock = new CoordinatorFixtures.ManualRuntime();
        try (var coordinator = new AuthenticationCoordinator(catalog, POLICY, clock,
                (selected, recovery, deadline, cancelled) -> new AuthenticationResult(selected.identity(), "captured", clock.instant(), clock.nanos()), ignored -> null)) {
            try (var first = coordinator.acquire(List.of(entry))) {
                assertFalse(first.future().isDone()); clock.runWorker();
                assertEquals("captured", first.future().join().get(identity).value());
            }
            try (var cached = coordinator.acquire(List.of(entry))) {
                assertEquals("captured", cached.future().join().get(identity).value());
                assertTrue(clock.workers.isEmpty());
            }
        }
    }

    @Test void catalogRemovalDuringAttemptPreventsPublication() {
        var definition = CoordinatorFixtures.journey("employee");
        var identity = new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, definition.id(), 1);
        var entry = new JourneyCatalog.Entry(identity, definition);
        var publication = new AtomicReference<>(new JourneyCatalog.Snapshot(Map.of(identity.key(), entry), Map.of("employee", List.of(identity.key())), Set.of()));
        var clock = new CoordinatorFixtures.ManualRuntime();
        try (var coordinator = new AuthenticationCoordinator(publication::get, POLICY, clock,
                (selected, recovery, deadline, cancelled) -> {
                    publication.set(new JourneyCatalog.Snapshot(Map.of(), Map.of(), Set.of()));
                    return new AuthenticationResult(selected.identity(), "obsolete", clock.instant(), clock.nanos());
                }, ignored -> null);
             var ticket = coordinator.acquire(List.of(entry))) {
            clock.runWorker(); assertTrue(ticket.future().isCompletedExceptionally());
            assertNull(coordinator.peek(identity));
        }
    }
}
