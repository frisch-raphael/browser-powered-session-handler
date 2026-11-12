package bpsh.support;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

/** Actual descendant process witness shared by native browser tests and captured acceptance. */
public class BrowserProcessWitness implements AutoCloseable {
    /** Process lifetime being observed; a shared provider is not owned by one browser attempt. */
    public enum Scope { BROWSER, PROVIDER }
    private static final Object SAMPLING = new Object();
    private static final Set<BrowserProcessWitness> ACTIVE = new HashSet<>();
    private static ScheduledExecutorService observer;
    public final long began = System.nanoTime();
    private final Map<Long,Instant> observed = new ConcurrentHashMap<>();
    private final Set<Long> drivers = ConcurrentHashMap.newKeySet();
    private final Scope scope;
    private RuntimeException samplingFailure;
    private long alive;
    private boolean closed;
    public BrowserProcessWitness() { this(Scope.BROWSER); }
    public BrowserProcessWitness(Scope scope) {
        this.scope = Objects.requireNonNull(scope);
        synchronized (SAMPLING) {
            ACTIVE.add(this);
            if (observer == null) {
                observer = Executors.newSingleThreadScheduledExecutor();
                // A fixed delay lets expensive native process-table scans yield between observations.
                // Positive process counts and strict final liveness remain mandatory.
                observer.scheduleWithFixedDelay(BrowserProcessWitness::snapshot,0,100,TimeUnit.MILLISECONDS);
            }
        }
    }
    /** One native process-table scan feeds all overlapping resource scopes. */
    private static void snapshot() {
        synchronized (SAMPLING) {
            try (var children = ProcessHandle.current().descendants()) {
                children.forEach(handle -> {
                    var info = handle.info();
                    String command = info.command().orElse("").replace('\\','/').toLowerCase(Locale.ROOT);
                    boolean driver = command.endsWith("/node.exe") || command.endsWith("/node");
                    boolean browser = driver || command.endsWith("/chrome.exe") || command.endsWith("/chrome");
                    boolean provider = command.endsWith("/java.exe") || command.endsWith("/javaw.exe") || command.endsWith("/java");
                    for (var witness : ACTIVE) {
                        if (witness.scope == Scope.BROWSER ? browser : provider)
                            witness.observed.putIfAbsent(handle.pid(),info.startInstant().orElse(Instant.EPOCH));
                        if (witness.scope == Scope.BROWSER && driver) witness.drivers.add(handle.pid());
                    }
                });
            } catch (RuntimeException failure) { for (var witness : ACTIVE) witness.samplingFailure = failure; }
        }
    }
    void sample() { snapshot(); }
    public int processes() { return observed.size(); }
    public int drivers() { return drivers.size(); }
    public long alive() { return alive; }
    public void requireObserved(int expectedDrivers) {
        assertTrue(closed); assertFalse(observed.isEmpty(),"A real process witness is required.");
        assertEquals(expectedDrivers,drivers.size(),"Require exactly the owned driver count.");
    }
    @Override public void close() throws Exception {
        ScheduledExecutorService stopped = null;
        synchronized (SAMPLING) {
            if (closed) return;
            snapshot(); closed = true; ACTIVE.remove(this);
            if (ACTIVE.isEmpty()) { stopped = observer; observer = null; stopped.shutdownNow(); }
        }
        if (stopped != null) assertTrue(stopped.awaitTermination(2,TimeUnit.SECONDS));
        assertNull(samplingFailure,"Actual descendant observation must complete.");
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        do {
            alive = observed.entrySet().stream().filter(entry -> ProcessHandle.of(entry.getKey()).filter(handle -> handle.isAlive()
                    && (entry.getValue().equals(Instant.EPOCH) || handle.info().startInstant().orElse(Instant.EPOCH).equals(entry.getValue()))).isPresent()).count();
            if (alive == 0) break;
            Thread.sleep(10);
        } while (System.nanoTime() < deadline);
        assertEquals(0,alive,"Observed descendants must close after their scoped owner returns.");
    }
}
