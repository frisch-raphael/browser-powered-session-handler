import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

class UserLibraryStoreTest {
    @TempDir Path temp;
    Path library() { return temp.resolve(".bpsh/library-v3.json"); }
    static void atomicMove(Path source, Path target) throws IOException {
        Files.move(source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }
    @Test void freshLibraryCreatesPrivateFilesAndRoundTripsWithoutRuntimeSetup() throws Exception {
        try (var store = new UserLibraryStore(library()); var absent = store.load(); var document = JourneyRegistryTest.document(ConfigManager.DocumentKind.LIBRARY)) {
            assertEquals(UserLibraryStore.Version.absent(), absent.version()); assertTrue(absent.document().journeys().isEmpty());
            try (var saved = store.save(document, absent.version()); var loaded = store.load()) {
                assertEquals(saved.version(), loaded.version()); assertEquals(document.journeys(), loaded.document().journeys());
                assertNotEquals(document.revision(), saved.version().revision()); assertEquals(64, saved.version().sha256().length());
            }
            assertFalse(Files.exists(library().resolveSibling("library-v3.json.bak")));
            if (Files.getFileAttributeView(library(), PosixFileAttributeView.class) != null) {
                assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(library()));
                assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(library().getParent()));
            } else {
                var acl = Files.getFileAttributeView(library(), AclFileAttributeView.class).getAcl();
                assertEquals(1, acl.size());
                assertTrue(acl.getFirst().principal().getName().toLowerCase().endsWith(System.getProperty("user.name").toLowerCase()));
            }
        }
    }
    @Test void twoWritersCannotOverwriteEachOtherAndSameRevisionExternalEditsConflict() throws Exception {
        try (var a = new UserLibraryStore(library()); var b = new UserLibraryStore(library());
             var document = JourneyRegistryTest.document(ConfigManager.DocumentKind.LIBRARY); var initial = a.save(document, UserLibraryStore.Version.absent());
             var stale = b.load(); var updated = a.save(document, initial.version())) {
            byte[] before = Files.readAllBytes(library());
            var ex = assertThrows(UserLibraryStore.LibraryException.class, () -> b.save(document, stale.version()));
            assertTrue(ex.getMessage().contains("reload")); assertArrayEquals(before, Files.readAllBytes(library()));
            Files.writeString(library(), Files.readString(library()).replace("Employee", "External edit"));
            assertThrows(UserLibraryStore.LibraryException.class, () -> a.save(document, updated.version()));
            assertTrue(Files.readString(library()).contains("External edit"));
        }
    }
    @Test void simultaneousFirstWritersPublishExactlyOneVersion() throws Exception {
        try (var a = new UserLibraryStore(library()); var b = new UserLibraryStore(library()); var document = JourneyRegistryTest.document(ConfigManager.DocumentKind.LIBRARY);
             var pool = Executors.newFixedThreadPool(2)) {
            CountDownLatch start = new CountDownLatch(1); AtomicInteger saved = new AtomicInteger(), conflicts = new AtomicInteger();
            var tasks = List.of(a, b).stream().map(store -> pool.submit(() -> {
                start.await();
                try (var ignored = store.save(document, UserLibraryStore.Version.absent())) { saved.incrementAndGet(); }
                catch (UserLibraryStore.LibraryException ex) { conflicts.incrementAndGet(); }
                return null;
            })).toList();
            start.countDown(); for (var task : tasks) task.get(5, TimeUnit.SECONDS);
            assertEquals(1, saved.get()); assertEquals(1, conflicts.get());
            try (var loaded = a.load()) { assertEquals(1, loaded.document().journeys().size()); }
        }
    }
    @Test void lockContentionTimesOutWithoutTouchingPrimary() throws Exception {
        try (var store = new UserLibraryStore(library(), Duration.ofMillis(150), UserLibraryStoreTest::atomicMove);
             var document = JourneyRegistryTest.document(ConfigManager.DocumentKind.LIBRARY);
             var initial = store.save(document, UserLibraryStore.Version.absent())) {
            byte[] before = Files.readAllBytes(library());
            try (var channel = FileChannel.open(library().resolveSibling("library-v1.lock"), StandardOpenOption.WRITE); var lock = channel.lock()) {
                long start = System.nanoTime();
                var ex = assertThrows(UserLibraryStore.LibraryException.class, () -> store.save(document, initial.version()));
                assertTrue(ex.getMessage().contains("lock is busy")); assertTrue(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(2));
                assertArrayEquals(before, Files.readAllBytes(library()));
            }
        }
    }
    @Test void corruptionUnknownVersionAndMalformedUtf8NeverBecomeAnEmptyLibrary() throws Exception {
        Files.createDirectories(library().getParent());
        for (byte[] data : List.of("{bad EXAMPLE_SECRET".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                JourneyRegistryTest.fixture(ConfigManager.DocumentKind.LIBRARY, false, false).replace("\"schemaVersion\":1", "\"schemaVersion\":2").getBytes(java.nio.charset.StandardCharsets.UTF_8),
                new byte[]{(byte) 0xC3, (byte) 0x28})) {
            Files.write(library(), data);
            try (var store = new UserLibraryStore(library()); var document = JourneyRegistryTest.document(ConfigManager.DocumentKind.LIBRARY)) {
                var ex = assertThrows(UserLibraryStore.LibraryException.class, store::load);
                assertTrue(ex.getMessage().contains(library().toString())); assertTrue(ex.getMessage().contains("cannot read the saved journey library"));
                assertFalse(ex.getMessage().contains("restore"));
                assertFalse(ex.getMessage().contains("EXAMPLE_SECRET")); assertNull(ex.getCause());
                assertThrows(UserLibraryStore.LibraryException.class, () -> store.save(document, UserLibraryStore.Version.absent()));
                assertArrayEquals(data, Files.readAllBytes(library()));
            }
        }
    }
    @Test void previousBackupIsRedactedAndTurningOffRememberingRemovesPrimarySecrets() throws Exception {
        try (var store = new UserLibraryStore(library());
             var remembered = ConfigManager.parseNative(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.LIBRARY, true, true), ConfigManager.DocumentKind.LIBRARY);
             var first = store.save(remembered, UserLibraryStore.Version.absent());
             var sessionOnly = ConfigManager.parseNative(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.EXPORT, false, true), ConfigManager.DocumentKind.EXPORT)) {
            assertTrue(Files.readString(library()).contains("EXAMPLE_SECRET"));
            var managed = new ConfigManager.NativeDocument(ConfigManager.DocumentKind.LIBRARY, sessionOnly.revision(), sessionOnly.journeys(), List.of(), null, sessionOnly.secrets());
            try (var saved = store.save(managed, first.version())) {
                assertFalse(Files.readString(library()).contains("EXAMPLE_SECRET"));
                assertArrayEquals("EXAMPLE_SECRET".toCharArray(), saved.document().secrets().get(JourneyRegistryTest.JOURNEY).stepValue(JourneyRegistryTest.STEP));
                try (var disk = store.load()) { assertTrue(disk.document().secrets().isEmpty()); }
                Path backup = library().resolveSibling("library-v3.json.bak"); assertFalse(Files.readString(backup).contains("EXAMPLE_SECRET"));
                try (var prior = ConfigManager.parseNative(Files.readString(backup), ConfigManager.DocumentKind.LIBRARY)) {
                    assertEquals(first.version().revision(), prior.revision()); assertTrue(prior.secrets().isEmpty());
                }
            }
        }
    }
    @Test void failedAtomicPrimaryReplacementPreservesOldFileAndCleansOnlyOwnedTemps() throws Exception {
        try (var good = new UserLibraryStore(library()); var document = JourneyRegistryTest.document(ConfigManager.DocumentKind.LIBRARY);
             var first = good.save(document, UserLibraryStore.Version.absent());
             var failing = new UserLibraryStore(library(), Duration.ofSeconds(2), (source, target) -> {
                 if (target.equals(library())) throw new java.nio.file.AtomicMoveNotSupportedException(source.toString(), target.toString(), "injected");
                 atomicMove(source, target);
             })) {
            byte[] before = Files.readAllBytes(library()); Path unrelated = library().resolveSibling("unrelated.tmp"); Files.writeString(unrelated, "keep");
            assertThrows(UserLibraryStore.LibraryException.class, () -> failing.save(document, first.version()));
            assertArrayEquals(before, Files.readAllBytes(library())); assertEquals("keep", Files.readString(unrelated));
            try (var files = Files.list(library().getParent())) { assertFalse(files.anyMatch(p -> p.getFileName().toString().startsWith(".bpsh-write-"))); }
        }
    }
    @Test void backupFailureAbortsBeforePrimaryReplacement() throws Exception {
        try (var good = new UserLibraryStore(library()); var document = JourneyRegistryTest.document(ConfigManager.DocumentKind.LIBRARY);
             var first = good.save(document, UserLibraryStore.Version.absent());
             var failing = new UserLibraryStore(library(), Duration.ofSeconds(2), (source, target) -> { throw new IOException("injected backup failure"); })) {
            byte[] before = Files.readAllBytes(library());
            assertThrows(UserLibraryStore.LibraryException.class, () -> failing.save(document, first.version()));
            assertArrayEquals(before, Files.readAllBytes(library()));
        }
    }
    @Test void deniedSaveNamesTheFailedStageAndDoesNotSuggestRestoringUncorruptedData() throws Exception {
        try (var document = JourneyRegistryTest.document(ConfigManager.DocumentKind.LIBRARY);
             var store = new UserLibraryStore(library(), Duration.ofSeconds(2), (source, target) -> { throw new java.nio.file.AccessDeniedException("EXAMPLE_SECRET"); })) {
            var error = assertThrows(UserLibraryStore.LibraryException.class, () -> store.save(document, UserLibraryStore.Version.absent()));
            assertTrue(error.getMessage().contains("replace the saved library file")); assertTrue(error.getMessage().contains("access denied"));
            assertFalse(error.getMessage().contains("EXAMPLE_SECRET")); assertFalse(error.getMessage().contains("restore")); assertNull(error.getCause());
            assertFalse(Files.exists(library()));
        }
    }
    @Test @org.junit.jupiter.api.condition.EnabledOnOs(org.junit.jupiter.api.condition.OS.WINDOWS)
    void privateCreationUsesTheWindowsAccountRatherThanMutableHostUsernameProperty() throws Exception {
        String previous = System.getProperty("user.name");
        try {
            System.setProperty("user.name", "__not_a_real_bpsh_user__");
            try (var store = new UserLibraryStore(library()); var document = JourneyRegistryTest.document(ConfigManager.DocumentKind.LIBRARY);
                 var saved = store.save(document, UserLibraryStore.Version.absent())) {
                assertTrue(Files.isRegularFile(library())); assertEquals(1, saved.document().journeys().size());
            }
            Path browserFile = temp.resolve("browser-private-file");
            Files.createFile(browserFile, BrowserRuntimeManager.privateAttributes(temp, false));
            Files.writeString(browserFile, "owned fixture"); assertEquals("owned fixture", Files.readString(browserFile));
        } finally { if (previous == null) System.clearProperty("user.name"); else System.setProperty("user.name", previous); }
    }
    @Test void watcherObservesExternalEditReportsCorruptionAndStopsOnClose() throws Exception {
        try (var writer = new UserLibraryStore(library()); var document = JourneyRegistryTest.document(ConfigManager.DocumentKind.LIBRARY);
             var first = writer.save(document, UserLibraryStore.Version.absent()); var store = new UserLibraryStore(library())) {
            CountDownLatch initial = new CountDownLatch(1), edited = new CountDownLatch(1), corrupt = new CountDownLatch(1), restored = new CountDownLatch(1);
            AtomicInteger calls = new AtomicInteger(); AtomicReference<Exception> unexpected = new AtomicReference<>();
            store.watch(loaded -> {
                try (loaded) {
                    calls.incrementAndGet();
                    String name = loaded.document().journeys().getFirst().displayName();
                    if (name.equals("Employee")) initial.countDown(); else if (name.equals("External edit")) {
                        edited.countDown(); if (corrupt.getCount() == 0) restored.countDown();
                    }
                } catch (Exception ex) { unexpected.set(ex); }
            }, ex -> corrupt.countDown());
            assertTrue(initial.await(4, TimeUnit.SECONDS));
            Files.writeString(library(), Files.readString(library()).replace("Employee", "External edit"));
            assertTrue(edited.await(4, TimeUnit.SECONDS)); assertNull(unexpected.get());
            byte[] valid = Files.readAllBytes(library());
            Files.writeString(library(), "invalid"); assertTrue(corrupt.await(4, TimeUnit.SECONDS));
            Files.write(library(), valid); assertTrue(restored.await(4, TimeUnit.SECONDS));
            store.close(); int count = calls.get(); assertThrows(IOException.class, store::load); assertEquals(count, calls.get());
        }
    }
    @Test void failingCallbacksDoNotPermanentlyStopWatcherRecovery() throws Exception {
        try (var writer = new UserLibraryStore(library()); var document = JourneyRegistryTest.document(ConfigManager.DocumentKind.LIBRARY);
             var saved = writer.save(document, UserLibraryStore.Version.absent()); var store = new UserLibraryStore(library())) {
            CountDownLatch recovered = new CountDownLatch(1); AtomicInteger changes = new AtomicInteger(), errors = new AtomicInteger();
            store.watch(loaded -> {
                try (loaded) {
                    if (changes.getAndIncrement() == 0) throw new IllegalStateException("injected callback failure");
                    recovered.countDown();
                }
            }, ex -> { errors.incrementAndGet(); throw new IllegalStateException("injected reporting failure"); });
            assertTrue(recovered.await(5, TimeUnit.SECONDS)); assertEquals(1, errors.get()); assertEquals(2, changes.get());
        }
    }
    @Test void ownSaveKeepsSessionSecretsAndWatcherEmitsOnlyExternalChanges() throws Exception {
        try (var store = new UserLibraryStore(library()); SecretStore secrets = new SecretStore();
             var source = ConfigManager.parseNative(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.EXPORT, false, true), ConfigManager.DocumentKind.EXPORT);
             var scheduler = Executors.newSingleThreadScheduledExecutor()) {
            CountDownLatch initial = new CountDownLatch(1), external = new CountDownLatch(1);
            AtomicInteger observations = new AtomicInteger(); AtomicReference<Exception> failure = new AtomicReference<>();
            store.watch(loaded -> {
                try (loaded) {
                    observations.incrementAndGet();
                    if (loaded.document().journeys().isEmpty()) initial.countDown();
                    else if (loaded.document().journeys().getFirst().displayName().equals("External edit")) external.countDown();
                }
            }, failure::set);
            assertTrue(initial.await(4, TimeUnit.SECONDS));
            var edited = new ConfigManager.NativeDocument(ConfigManager.DocumentKind.LIBRARY, source.revision(), source.journeys(), List.of(), null, source.secrets());
            JourneyRegistry registry = new JourneyRegistry(secrets);
            try (var committed = store.save(edited, UserLibraryStore.Version.absent())) {
                registry.replaceLoaded(JourneyDefinition.Scope.LIBRARY, committed.document());
                try (var values = secrets.snapshot(registry.snapshot().resolve("employee").identity().key())) {
                    assertArrayEquals("EXAMPLE_SECRET".toCharArray(), values.stepValue(JourneyRegistryTest.STEP));
                }
            }
            assertFalse(Files.readString(library()).contains("EXAMPLE_SECRET"));
            var edit = scheduler.schedule(() -> {
                try { Files.writeString(library(), Files.readString(library()).replace("Employee", "External edit")); }
                catch (IOException ex) { failure.set(ex); }
            }, 3, TimeUnit.SECONDS);
            assertTrue(external.await(6, TimeUnit.SECONDS)); edit.get();
            assertNull(failure.get()); assertEquals(2, observations.get(), "own disk echo must not replace the session snapshot");
        }
    }
}
