package lab.auth.gui;

import java.lang.management.*;
import java.nio.file.*;
import java.util.*;
import javax.management.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
import static lab.auth.gui.HostHeapDiagnostics.*;

class HostHeapDiagnosticsTest {
    @TempDir Path directory;
    private final Map<String, MemoryUsage> before = Map.of("heap-a", new MemoryUsage(0, 200, 400, -1),
            "heap-b", new MemoryUsage(0, 300, 500, 1000), "PRIVATE_NON_HEAP_POOL", new MemoryUsage(0, 9000, 9000, 9000));
    private final Map<String, MemoryUsage> after = Map.of("heap-a", new MemoryUsage(0, 20, 400, -1),
            "heap-b", new MemoryUsage(0, 80, 500, 1000), "PRIVATE_NON_HEAP_POOL", new MemoryUsage(0, 9000, 9000, 9000));

    @Test void loaderStacksKeepOnlyBoundedIdentifiersFromMatchingThreads() {
        var snapshots=new LinkedHashMap<Thread,StackTraceElement[]>();
        for(int i=0;i<6;i++)snapshots.put(new Thread("PRIVATE_THREAD_"+i),new StackTraceElement[]{
                new StackTraceElement("java.util.Arrays","copyOf","PRIVATE_PATH",1),
                new StackTraceElement("java.io.ByteArrayOutputStream","toByteArray","PRIVATE_PATH",2),
                new StackTraceElement("burp.Z_rf","Za","PRIVATE_PATH",3)});
        snapshots.put(new Thread("PRIVATE_OTHER"),new StackTraceElement[]{new StackTraceElement("other.Library","PRIVATE_METHOD","PRIVATE_SOURCE",1)});
        var observed=HostHeapDiagnostics.loaderThreads(snapshots);
        assertEquals(6,observed.get("matchingThreads"));assertEquals(true,observed.get("truncated"));
        assertEquals(4,((List<?>)observed.get("threads")).size());
        String json=lab.auth.LabJson.JSON.toJson(observed);assertFalse(json.contains("PRIVATE"));assertTrue(json.contains("java.io.ByteArrayOutputStream.toByteArray"));
        var oversized=new AbstractMap<Thread,StackTraceElement[]>(){
            public Set<Map.Entry<Thread,StackTraceElement[]>> entrySet(){return Set.of();}
            @Override public int size(){return 4097;}
        };
        assertThrows(IllegalArgumentException.class,()->HostHeapDiagnostics.loaderThreads(oversized));
    }

    @Test void loaderSamplingUsesOnlyHighNaturalCollectionsAndStopsAtItsCap() throws Exception {
        var calls=new java.util.concurrent.atomic.AtomicInteger();Path stacks=directory.resolve("loaders.jsonl");
        Map<String,MemoryUsage> high=Map.of("heap",new MemoryUsage(0,1536L<<20,2L<<30,2L<<30));
        Map<String,MemoryUsage> low=Map.of("heap",new MemoryUsage(0,100L<<20,2L<<30,2L<<30));
        try(var observer=new HostHeapDiagnostics(directory.resolve("gc.jsonl"),Set.of("heap"),2L<<30,MAX_EVENTS,MAX_BYTES)) {
            observer.enableLoaderSamples(stacks,()->{calls.incrementAndGet();return Map.of();});
            observer.observe(0,0,1,1,"G1 Humongous Allocation","end of minor GC",high,low);
            observer.observe(1,1,2,1,"System.gc()","end of major GC",high,high);assertEquals(0,calls.get());
            for(int i=0;i<MAX_LOADER_SAMPLES+1;i++)observer.observe(i+2,i+2,i+3,1,"G1 Humongous Allocation","end of minor GC",high,high);
            assertEquals(MAX_LOADER_SAMPLES,calls.get());assertEquals(MAX_LOADER_SAMPLES,Files.readAllLines(stacks).size());
            assertEquals(true,observer.state().get("loaderOverflow"));assertEquals(false,observer.state().get("failed"));
            assertTrue(Files.size(stacks)<=MAX_LOADER_BYTES);
        }
    }

    @Test void optionalLoaderFailuresAreRedactedAndDoNotInvalidateTheSeparateGcJournal() throws Exception {
        Path stacks=directory.resolve("loaders.jsonl");
        Map<String,MemoryUsage> high=Map.of("heap",new MemoryUsage(0,1536L<<20,2L<<30,2L<<30));
        try(var observer=new HostHeapDiagnostics(directory.resolve("gc.jsonl"),Set.of("heap"),2L<<30,MAX_EVENTS,MAX_BYTES)) {
            observer.enableLoaderSamples(stacks,()->{throw new IllegalStateException("PRIVATE_SECRET");});
            observer.observe(1,0,1,1,"G1 Humongous Allocation","end of minor GC",high,high);
            assertEquals(true,observer.state().get("loaderFailed"));assertEquals(false,observer.state().get("failed"));
            assertEquals(1,observer.state().get("events"));assertEquals(0,Files.size(stacks));
            assertFalse(lab.auth.LabJson.JSON.toJson(observer.state()).contains("PRIVATE_SECRET"));
        }
        Files.writeString(stacks,"PRIVATE_SENTINEL");
        try(var observer=new HostHeapDiagnostics(directory.resolve("gc2.jsonl"),Set.of("heap"),2L<<30,MAX_EVENTS,MAX_BYTES)) {
            observer.enableLoaderSamples(stacks,Map::of);assertEquals(true,observer.state().get("loaderFailed"));
            assertEquals("PRIVATE_SENTINEL",Files.readString(stacks));
        }
    }

    @Test void recordsOnlyHeapAggregatesAndClosedEnumsWithoutRetainingNotificationData() throws Exception {
        Path file = directory.resolve("events.jsonl");
        try (var observer = observer(file, 4096, MAX_BYTES)) {
            observer.observe(1, 10, 12, 2, "PRIVATE_CAUSE secret/path", "PRIVATE_ACTION secret/path", before, after);
            observer.observe(2, 20, 23, 3, "G1 Humongous Allocation", "end of major GC", before, after);
            var state = observer.state(); assertEquals(2, state.get("events")); assertEquals(1, state.get("majorEvents"));
            var event = (Event) state.get("last");
            assertEquals(new Heap(500, 900, 1000), event.before()); assertEquals(new Heap(100, 900, 1000), event.after());
            assertEquals(Cause.HUMONGOUS_ALLOCATION, event.cause()); assertEquals(Trigger.NATURAL, event.trigger());
            assertEquals(Kind.MAJOR, event.kind()); assertFalse((boolean) state.get("failed"));
            String retained = Files.readString(file) + lab.auth.LabJson.JSON.toJson(state);
            assertFalse(retained.contains("PRIVATE")); assertFalse(retained.contains("secret"));
            assertFalse(retained.contains("heap-a")); assertFalse(retained.contains("9000"));
            assertTrue(retained.contains("OTHER")); assertTrue(retained.contains("UNKNOWN"));
        }
    }

    @Test void distinguishesExplicitUnknownAndNaturalCausesRatherThanClaimingFullCompaction() throws Exception {
        try (var observer = observer(directory.resolve("events.jsonl"), 4096, MAX_BYTES)) {
            for (String cause : List.of("System.gc()", "Diagnostic Command", "Heap Inspection Initiated GC", "Heap Dump Initiated GC")) {
                observer.observe(1, 1, 2, 1, cause, "end of major GC", before, after);
                assertEquals(Trigger.EXPLICIT, ((Event) observer.state().get("last")).trigger());
            }
            observer.observe(2, 2, 3, 1, null, null, before, after);
            Event event = (Event) observer.state().get("last");
            assertEquals(Trigger.UNKNOWN, event.trigger()); assertEquals(Kind.OTHER, event.kind());
            for (String cause : List.of("Allocation Failure", "Metadata GC Threshold", "Metadata GC Clear Soft References",
                    "G1 Evacuation Pause", "G1 Compaction Pause", "G1 Concurrent GC", "Ergonomics"))
                assertNotEquals(Cause.OTHER, HostHeapDiagnostics.cause(cause));
        }
    }

    @Test void enforcesEventCapAndNeverAppendsAfterOverflow() throws Exception {
        Path file = directory.resolve("events.jsonl");
        try (var observer = observer(file, 3, MAX_BYTES)) {
            for (int i = 0; i < 10; i++) observer.observe(i, 0, 1, 1, "Allocation Failure", "end of minor GC", before, after);
            assertEquals(3, observer.state().get("events")); assertEquals(true, observer.state().get("overflow"));
            assertEquals(3, Files.readAllLines(file).size()); assertTrue(Files.size(file) <= MAX_BYTES);
        }
    }

    @Test void enforcesByteCapBeforeWritingEvenFirstRecord() throws Exception {
        Path file = directory.resolve("events.jsonl");
        try (var observer = observer(file, MAX_EVENTS, 1)) {
            observer.observe(1, 0, 1, 1, "Allocation Failure", "end of minor GC", before, after);
            assertEquals(0, observer.state().get("events")); assertEquals(true, observer.state().get("overflow"));
            assertEquals(0, Files.size(file));
        }
    }

    @Test void invalidOrMissingPoolAndNumericDataFailExplicitlyWithoutLeakingOrEscaping() throws Exception {
        for (int index = 0; index < 4; index++) {
            Path file = directory.resolve("events-" + index + ".jsonl");
            try (var observer = observer(file, MAX_EVENTS, MAX_BYTES)) {
                switch (index) {
                    case 0 -> observer.observe(-1, 0, 1, 1, "PRIVATE", "PRIVATE", before, after);
                    case 1 -> observer.observe(1, 2, 1, 1, "PRIVATE", "PRIVATE", before, after);
                    case 2 -> observer.observe(1, 0, 2, 1, "PRIVATE", "PRIVATE", before, after);
                    case 3 -> observer.observe(1, 0, 1, 1, "PRIVATE", "PRIVATE", Map.of(), after);
                    default -> throw new AssertionError();
                }
                assertEquals(true, observer.state().get("failed")); assertEquals(0, observer.state().get("events"));
                assertEquals("", Files.readString(file));
            }
        }
    }

    @Test void malformedNotificationsAndListenerFailuresCannotEscapeIntoApplication() throws Exception {
        var collector = new Collector();
        try (var observer = observer(directory.resolve("events.jsonl"), MAX_EVENTS, MAX_BYTES)) {
            observer.attach(List.of(collector)); assertEquals(1, collector.listeners);
            var ignored = new Notification("PRIVATE_UNRELATED_TYPE", collector, 1); ignored.setUserData("PRIVATE_VALUE");
            collector.sendNotification(ignored); assertEquals(false, observer.state().get("failed"));
            var invalid = new Notification(com.sun.management.GarbageCollectionNotificationInfo.GARBAGE_COLLECTION_NOTIFICATION, collector, 2);
            invalid.setUserData("PRIVATE_VALUE"); assertDoesNotThrow(() -> collector.sendNotification(invalid));
            assertEquals(true, observer.state().get("failed"));
        }
        assertEquals(0, collector.listeners);
        var unavailable = new Collector(); unavailable.rejectRegistration = true;
        try (var observer = observer(directory.resolve("unavailable.jsonl"), MAX_EVENTS, MAX_BYTES)) {
            assertDoesNotThrow(() -> observer.attach(List.of(unavailable)));
            assertEquals(false, observer.state().get("available")); assertEquals(true, observer.state().get("failed"));
        }
    }

    @Test void exclusiveFileAndIdempotentClosePreserveExistingFilesAndDetachListeners() throws Exception {
        Path existing = directory.resolve("existing.jsonl"); Files.writeString(existing, "PRIVATE_SENTINEL");
        assertThrows(FileAlreadyExistsException.class, () -> observer(existing, MAX_EVENTS, MAX_BYTES));
        assertEquals("PRIVATE_SENTINEL", Files.readString(existing));
        var collector = new Collector(); Path file = directory.resolve("events.jsonl");
        var observer = observer(file, MAX_EVENTS, MAX_BYTES); observer.attach(List.of(collector));
        observer.close(); observer.close(); assertEquals(0, collector.listeners);
        observer.observe(1, 0, 1, 1, "Allocation Failure", "end of minor GC", before, after);
        assertEquals(0, Files.size(file)); assertEquals(false, observer.state().get("failed"));
        assertEquals(true, observer.state().get("closed"));
    }

    @Test void rejectsBoundsBeyondTheProductionCaps() {
        assertThrows(IllegalArgumentException.class, () -> observer(directory.resolve("events.jsonl"), MAX_EVENTS + 1, MAX_BYTES));
        assertThrows(IllegalArgumentException.class, () -> observer(directory.resolve("events.jsonl"), MAX_EVENTS, MAX_BYTES + 1));
    }

    private HostHeapDiagnostics observer(Path file, int events, long bytes) throws Exception {
        return new HostHeapDiagnostics(file, Set.of("heap-a", "heap-b"), 1000, events, bytes);
    }

    private static final class Collector extends NotificationBroadcasterSupport implements GarbageCollectorMXBean {
        int listeners; boolean rejectRegistration;
        @Override public void addNotificationListener(NotificationListener listener, NotificationFilter filter, Object handback) {
            if (rejectRegistration) throw new IllegalStateException("PRIVATE_ERROR");
            super.addNotificationListener(listener, filter, handback); listeners++;
        }
        @Override public void removeNotificationListener(NotificationListener listener) throws ListenerNotFoundException {
            super.removeNotificationListener(listener); listeners--;
        }
        @Override public String getName() { return "PRIVATE_COLLECTOR"; }
        @Override public String[] getMemoryPoolNames() { return new String[]{"PRIVATE_POOL"}; }
        @Override public boolean isValid() { return true; }
        @Override public long getCollectionCount() { return 0; }
        @Override public long getCollectionTime() { return 0; }
        @Override public ObjectName getObjectName() { return null; }
    }
}
