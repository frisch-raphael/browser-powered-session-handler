import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

/** Supplies controlled clocks and worker queues without starting a browser or native provider. */
final class CoordinatorFixtures {
    /** Prevents instances of the test fixture namespace. */
    private CoordinatorFixtures() {}

    /** Runs timers deterministically and leaves actual worker execution under the test's control. */
    static final class ManualRuntime implements AuthenticationCoordinator.Runtime {
        long now = TimeUnit.SECONDS.toNanos(1), sequence;
        Instant wall = Instant.ofEpochSecond(2_000_000_000L);
        final ConcurrentLinkedQueue<Runnable> workers = new ConcurrentLinkedQueue<>();
        final PriorityQueue<Event> events = new PriorityQueue<>(Comparator.comparingLong((Event e) -> e.at).thenComparingLong(e -> e.order));
        boolean closed;
        /** Represents one cancellable deterministic timer. */
        final class Event implements AuthenticationCoordinator.Timer {
            final long at, order; final Runnable task; boolean cancelled;
            /** @param task Deferred callback. @param delay Delay from the controlled now. */
            Event(Runnable task, long delay) { this.task = task; at = now + Math.max(0, delay); order = sequence++; }
            /** Cancels this event without removing other timers. */
            @Override public void cancel() { synchronized (ManualRuntime.this) { cancelled = true; events.remove(this); } }
        }
        /** @return Controlled monotonic reading. */
        @Override public synchronized long nanos() { return now; }
        /** @return Independently adjustable JWT wall time. */
        @Override public synchronized Instant instant() { return wall; }
        /** @param task Deferred action. @param delay Nanoseconds from current time. @return Timer cancellation handle. */
        @Override public synchronized AuthenticationCoordinator.Timer schedule(Runnable task, long delay) { assertFalse(closed); Event event = new Event(task, delay); events.add(event); return event; }
        /** @param task Attempt admitted by the coordinator; deliberately not run inline. */
        @Override public void work(Runnable task) { assertFalse(closed); workers.add(task); }
        /** Stops pending timers; test worker jobs may still return to exercise stale publication. */
        @Override public synchronized void close() { closed = true; events.clear(); }
        /** Executes one queued worker and asserts that an actual attempt was admitted. */
        void runWorker() { Runnable task = workers.poll(); assertNotNull(task, "expected an admitted worker"); task.run(); }
        /** @param millis Monotonic/wall time to advance, executing all timers due along the way. */
        void advance(long millis) {
            long target = nanos() + TimeUnit.MILLISECONDS.toNanos(millis);
            while (true) {
                Event event;
                synchronized (this) {
                    event = events.peek();
                    if (event == null || event.at > target) { wall = wall.plusNanos(target - now); now = target; return; }
                    events.poll(); wall = wall.plusNanos(event.at - now); now = event.at;
                }
                if (!event.cancelled) event.task.run();
            }
        }
        /** @return Count of live timers, used to establish coalescing and release. */
        synchronized int timers() { return events.size(); }
    }

    /** @param alias Distinct readable alias. @return Valid immutable ordinary journey with no runtime dependencies. */
    static JourneyDefinition journey(String alias) {
        return new JourneyDefinition(UUID.randomUUID(), alias, alias, URI.create("https://login.example/login"), false, List.of(),
                new JourneyDefinition.Browser(true, null, 30_000, 3000), new JourneyDefinition.JsonExtraction(URI.create("https://login.example"), "/token", "access_token"),
                JourneyDefinition.Injection.perToken(List.of(new JourneyDefinition.TokenInjection(null, JourneyDefinition.InjectionType.BEARER, null))), new JourneyDefinition.Cache(1800, 10), null);
    }
    /** @param registry Destination managed scope. @param journeys Fresh definitions to publish atomically. */
    static void load(JourneyRegistry registry, List<JourneyDefinition> journeys) {
        try (var document = new ConfigManager.NativeDocument(ConfigManager.DocumentKind.PROJECT, UUID.randomUUID(), journeys, List.of(), Config.Controls.defaults(), Map.of())) {
            registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, document);
        }
    }
    /** @param global Optional enabled global limit. @param perJourney Optional enabled per-journey limit. @return Defaults with just admission limits changed. */
    static Config.Controls limits(Integer global, Integer perJourney) { return controls(global, perJourney, 60_000, 60_000, 300_000); }
    /** @param global Optional global limit. @param perJourney Optional per-journey limit. @param request Request budget. @param attempt Attempt budget. @param cycle Cycle budget. @return Native project controls. */
    static Config.Controls controls(Integer global, Integer perJourney, int request, int attempt, int cycle) {
        var defaults = Config.Controls.defaults();
        return new Config.Controls(false, List.of(), defaults.tools(), request, attempt, cycle, global, perJourney);
    }
    /** @param ticket Terminal failing request. @return Its typed safe cause. */
    static AuthenticationFailure error(AuthenticationCoordinator.Ticket ticket) {
        var ex = assertThrows(CompletionException.class, () -> ticket.future().join()); return assertInstanceOf(AuthenticationFailure.class, ex.getCause());
    }
    /** @param cause Symbolic failure category. @return Controlled safe attempt failure. */
    static AuthenticationFailure failure(AuthenticationFailure.Cause cause) { return new AuthenticationFailure(AuthenticationFailure.Phase.NAVIGATION, cause, "Controlled fixture failure.", "Use Test and explicitly Retry."); }
}
