package lab.auth.gui;

import com.sun.management.GarbageCollectionNotificationInfo;
import java.io.IOException;
import java.lang.management.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import javax.management.*;
import javax.management.openmbean.CompositeData;
import lab.auth.LabJson;

/** Optional numeric natural-GC observations; never walks objects, forces GC or retains notification text. */
final class HostHeapDiagnostics implements AutoCloseable {
    static final int MAX_EVENTS = 4096;
    static final long MAX_BYTES = 1L << 20;
    static final int MAX_LOADER_SAMPLES = 32, MAX_LOADER_BYTES = 256 * 1024;
    private static volatile HostHeapDiagnostics active;
    enum Cause { HUMONGOUS_ALLOCATION, ALLOCATION_FAILURE, METADATA_THRESHOLD, METADATA_CLEAR_SOFT,
        EVACUATION_PAUSE, CONCURRENT_CYCLE, ERGONOMICS, SYSTEM_GC, HEAP_INSPECTION, HEAP_DUMP, OTHER }
    enum Kind { MINOR, MAJOR, OTHER }
    enum Trigger { NATURAL, EXPLICIT, UNKNOWN }
    record Heap(long used, long committed, long max) {}
    record Event(long id, long startMs, long endMs, long durationMs, Cause cause, Kind kind,
                 Trigger trigger, Heap before, Heap after) {}
    private record Registration(NotificationEmitter emitter, NotificationListener listener) {}
    private final Set<String> heapPools;
    private final long heapMax;
    private final FileChannel output;
    private final int eventLimit;
    private final long byteLimit;
    private final List<Registration> registrations = new ArrayList<>();
    private long bytes;
    private int events;
    private int majorEvents;
    private boolean failed;
    private boolean overflow;
    private boolean closed;
    private Event latest;
    private FileChannel loaderOutput;
    private java.util.function.Supplier<Map<Thread, StackTraceElement[]>> loaderSource;
    private int loaderSamples, loaderBytes;
    private boolean loaderFailed, loaderOverflow;

    /** Creates one private exclusive journal; an unavailable observer never prevents normal Burp startup. */
    static HostHeapDiagnostics start(Path root) {
        HostHeapDiagnostics observer = null;
        try {
            var pools = new HashSet<String>();
            for (var pool : ManagementFactory.getMemoryPoolMXBeans())
                if (pool.getType() == MemoryType.HEAP) pools.add(pool.getName());
            long max = ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getMax();
            Path path = LabJson.owned(root, "gui/private-diagnostics/heap-gc-events.jsonl");
            Files.createDirectories(path.getParent());
            observer = new HostHeapDiagnostics(path, pools, max, MAX_EVENTS, MAX_BYTES);
            observer.enableLoaderSamples(path.resolveSibling("heap-loader-stacks.jsonl"), Thread::getAllStackTraces);
            observer.attach(ManagementFactory.getGarbageCollectorMXBeans());
        } catch (Throwable unavailable) {
            if (observer != null) observer.fail();
        }
        active = observer;
        return observer;
    }

    /** Test boundary uses the same exclusive file and production byte/event enforcement. */
    HostHeapDiagnostics(Path path, Set<String> heapPools, long heapMax, int eventLimit, long byteLimit) throws IOException {
        if (heapPools.isEmpty() || heapPools.size() > 64 || heapMax <= 0 || eventLimit < 1 || eventLimit > MAX_EVENTS
                || byteLimit < 1 || byteLimit > MAX_BYTES) throw new IllegalArgumentException("HEAP_DIAGNOSTIC_BOUNDS");
        this.heapPools = Set.copyOf(heapPools); this.heapMax = heapMax;
        this.eventLimit = eventLimit; this.byteLimit = byteLimit;
        Set<OpenOption> options = Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
        output = Files.getFileStore(path.getParent()).supportsFileAttributeView("posix")
                ? FileChannel.open(path, options, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
                : FileChannel.open(path, options);
    }

    /** Attaches only public management notifications; no poller or callback invokes product code. */
    void attach(List<? extends GarbageCollectorMXBean> collectors) {
        if (collectors.size() > 16) { fail(); return; }
        for (var collector : collectors) if (collector instanceof NotificationEmitter emitter) {
            NotificationListener listener = (notification, handback) -> notification(notification);
            try {
                emitter.addNotificationListener(listener, null, null);
                registrations.add(new Registration(emitter, listener));
            } catch (Throwable unavailable) { fail(); }
        }
        if (registrations.isEmpty()) fail();
    }

    /** Notification payloads are consumed immediately and never stored, rendered or logged. */
    void notification(Notification notification) {
        try {
            if (!GarbageCollectionNotificationInfo.GARBAGE_COLLECTION_NOTIFICATION.equals(notification.getType())) return;
            var info = GarbageCollectionNotificationInfo.from((CompositeData) notification.getUserData());
            var gc = info.getGcInfo();
            observe(gc.getId(), gc.getStartTime(), gc.getEndTime(), gc.getDuration(), info.getGcCause(), info.getGcAction(),
                    gc.getMemoryUsageBeforeGc(), gc.getMemoryUsageAfterGc());
        } catch (Throwable unavailable) { fail(); }
    }

    /** Aggregates only known HEAP pools and converts every incoming string to a closed enum. */
    void observe(long id, long start, long end, long duration, String causeText, String action,
                 Map<String, MemoryUsage> before, Map<String, MemoryUsage> after) {
        try {
            if (id < 0 || start < 0 || end < start || duration < 0 || duration != end - start)
                throw new IllegalArgumentException("HEAP_EVENT_BOUNDS");
            Cause cause = cause(causeText);
            Kind kind = "end of major GC".equals(action) ? Kind.MAJOR : "end of minor GC".equals(action) ? Kind.MINOR : Kind.OTHER;
            Trigger trigger = switch (cause) {
                case SYSTEM_GC, HEAP_INSPECTION, HEAP_DUMP -> Trigger.EXPLICIT;
                case OTHER -> Trigger.UNKNOWN;
                default -> Trigger.NATURAL;
            };
            var event = new Event(id, start, end, duration, cause, kind, trigger, aggregate(before), aggregate(after));
            append(event);
            if (event.after().used() >= (1L << 30) && trigger == Trigger.NATURAL) sampleLoaders(event);
        } catch (Throwable unavailable) { fail(); }
    }

    private Heap aggregate(Map<String, MemoryUsage> values) {
        if (values == null || values.size() > 64 || !values.keySet().containsAll(heapPools))
            throw new IllegalArgumentException("HEAP_POOLS_UNAVAILABLE");
        long used = 0, committed = 0;
        for (String pool : heapPools) {
            MemoryUsage usage = Objects.requireNonNull(values.get(pool));
            used = Math.addExact(used, usage.getUsed()); committed = Math.addExact(committed, usage.getCommitted());
        }
        if (used < 0 || committed < used || committed > heapMax) throw new IllegalArgumentException("HEAP_USAGE_BOUNDS");
        return new Heap(used, committed, heapMax);
    }

    static Cause cause(String text) {
        if (text == null) return Cause.OTHER;
        return switch (text) {
            case "G1 Humongous Allocation" -> Cause.HUMONGOUS_ALLOCATION;
            case "Allocation Failure" -> Cause.ALLOCATION_FAILURE;
            case "Metadata GC Threshold" -> Cause.METADATA_THRESHOLD;
            case "Metadata GC Clear Soft References" -> Cause.METADATA_CLEAR_SOFT;
            case "G1 Evacuation Pause" -> Cause.EVACUATION_PAUSE;
            case "G1 Compaction Pause", "G1 Preventive Collection", "G1 Periodic Collection", "Ergonomics" -> Cause.ERGONOMICS;
            case "G1 Concurrent GC", "G1 Concurrent Cycle" -> Cause.CONCURRENT_CYCLE;
            case "System.gc()", "Diagnostic Command" -> Cause.SYSTEM_GC;
            case "Heap Inspection Initiated GC" -> Cause.HEAP_INSPECTION;
            case "Heap Dump Initiated GC" -> Cause.HEAP_DUMP;
            default -> Cause.OTHER;
        };
    }

    /** Writes one bounded record immediately, keeping no growing collection under heap pressure. */
    private synchronized void append(Event event) {
        if (closed || failed || overflow) return;
        try {
            if (events >= eventLimit) { overflow = true; return; }
            byte[] line = (LabJson.JSON.toJson(event) + "\n").getBytes(StandardCharsets.US_ASCII);
            if (line.length > 1024 || bytes + line.length > byteLimit) { overflow = true; return; }
            var buffer = ByteBuffer.wrap(line);
            while (buffer.hasRemaining()) {
                if (output.write(buffer) <= 0) throw new IOException("HEAP_JOURNAL_WRITE");
            }
            bytes += line.length; events++; if (event.kind() == Kind.MAJOR) majorEvents++; latest = event;
        } catch (Throwable unavailable) { failed = true; }
    }

    private synchronized void fail() { failed = true; }

    /** Optional stack observation only at natural collections with at least 1 GiB still used. */
    void enableLoaderSamples(Path path, java.util.function.Supplier<Map<Thread, StackTraceElement[]>> source) {
        try {
            if (loaderSource != null) throw new IllegalStateException("LOADER_DIAGNOSTIC_ALREADY_CONFIGURED");
            loaderSource = Objects.requireNonNull(source);
            Set<OpenOption> options = Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
            loaderOutput = Files.getFileStore(path.getParent()).supportsFileAttributeView("posix")
                    ? FileChannel.open(path, options, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
                    : FileChannel.open(path, options);
        } catch (Throwable unavailable) { loaderFailed = true; }
    }

    /** Identifiers from the known whole-file loader or byte-array stream only; never thread names or values. */
    static Map<String, Object> loaderThreads(Map<Thread, StackTraceElement[]> snapshots) {
        if (snapshots.size() > 4096 || snapshots.values().stream().anyMatch(frames -> frames.length > 512))
            throw new IllegalArgumentException("LOADER_SNAPSHOT_BOUNDS");
        var matching = snapshots.entrySet().stream().filter(entry -> Arrays.stream(entry.getValue())
                .anyMatch(frame -> frame.getClassName().equals("burp.Z_rf") || frame.getClassName().equals("java.io.ByteArrayOutputStream")))
                .sorted(Comparator.comparingLong(entry -> entry.getKey().threadId())).toList();
        var threads = matching.stream().limit(4).map(entry -> Map.<String, Object>of("id", entry.getKey().threadId(),
                "state", entry.getKey().getState().name(), "frames", HostGuiDiagnostics.safeThreadFrames(entry.getValue()).stream()
                        .filter(frame -> frame.startsWith("java.io.") || frame.startsWith("java.util.Arrays.") || frame.startsWith("burp.Z_rf."))
                        .limit(4).toList())).toList();
        return Map.of("matchingThreads", matching.size(), "truncated", matching.size() > threads.size(), "threads", threads);
    }

    /** Bounded private journal; stack capture cannot establish object ownership or an acceptance pass. */
    private synchronized void sampleLoaders(Event event) {
        if (closed || loaderFailed || loaderOverflow || loaderOutput == null) return;
        try {
            if (loaderSamples >= MAX_LOADER_SAMPLES) { loaderOverflow = true; return; }
            var row = new LinkedHashMap<>(loaderThreads(loaderSource.get()));
            row.put("gcId", event.id()); row.put("gcEndMs", event.endMs());
            row.put("observedUptimeMs", ManagementFactory.getRuntimeMXBean().getUptime());
            byte[] line = (LabJson.JSON.toJson(row) + "\n").getBytes(StandardCharsets.US_ASCII);
            if (line.length > 4096 || (long) loaderBytes + line.length > MAX_LOADER_BYTES) { loaderOverflow = true; return; }
            var buffer = ByteBuffer.wrap(line);
            while (buffer.hasRemaining()) if (loaderOutput.write(buffer) <= 0) throw new IOException("LOADER_JOURNAL_WRITE");
            loaderSamples++; loaderBytes += line.length;
        } catch (Throwable unavailable) { loaderFailed = true; }
    }

    /** Small operation-boundary snapshot; MAJOR is not a claim of a full compacting or forced collection. */
    static Map<String, Object> snapshot() {
        HostHeapDiagnostics observer = active;
        if (observer == null) return Map.of("available", false, "failed", true, "overflow", false);
        var result = new LinkedHashMap<>(observer.state());
        try {
            var usage = ManagementFactory.getMemoryMXBean().getHeapMemoryUsage();
            result.put("current", new Heap(usage.getUsed(), usage.getCommitted(), usage.getMax()));
            result.put("currentEpochMs", System.currentTimeMillis()); result.put("currentAvailable", true);
        } catch (Throwable unavailable) { result.put("currentAvailable", false); }
        return Collections.unmodifiableMap(result);
    }

    synchronized Map<String, Object> state() {
        var result = new LinkedHashMap<String, Object>();
        result.put("available", !registrations.isEmpty()); result.put("failed", failed); result.put("overflow", overflow);
        result.put("closed", closed); result.put("events", events); result.put("majorEvents", majorEvents);
        result.put("bytes", bytes); result.put("maxEvents", eventLimit); result.put("maxBytes", byteLimit);
        result.put("heapMax", heapMax); result.put("last", latest);
        result.put("loaderAvailable", loaderOutput != null); result.put("loaderFailed", loaderFailed); result.put("loaderOverflow", loaderOverflow);
        result.put("loaderSamples", loaderSamples); result.put("loaderBytes", loaderBytes);
        return Collections.unmodifiableMap(result);
    }

    /** Unconditionally detaches every listener; cleanup exceptions never change the driver result. */
    @Override public void close() {
        synchronized (this) { if (closed) return; closed = true; }
        for (var registration : registrations) try {
            registration.emitter().removeNotificationListener(registration.listener());
        } catch (Throwable unavailable) { fail(); }
        synchronized (this) {
            try { output.close(); } catch (Throwable unavailable) { failed = true; }
            if (loaderOutput != null) try { loaderOutput.close(); } catch (Throwable unavailable) { loaderFailed = true; }
        }
    }
}
