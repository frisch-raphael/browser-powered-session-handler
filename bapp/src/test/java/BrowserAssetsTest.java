import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises the runtime's production extractor using small, deliberately malformed ZIPs. */
class BrowserAssetsTest {
    @TempDir Path temp;
    static final ObjectMapper JSON = new ObjectMapper();
    static final String PLATFORM = "windows-x64";

    /** Stores independent manifest/archive bytes and counts archive resource reads. */
    static final class Bundle implements BrowserRuntimeManager.Resources {
        byte[] manifest, archive;
        final String platform;
        final AtomicInteger archives = new AtomicInteger();
        final Map<String, byte[]> files = new LinkedHashMap<>();

        /** Builds a minimal declared browser/driver tree; no executable is actually launched. */
        Bundle() throws Exception { this(PLATFORM); }
        /** @param platform Exact test target. */
        Bundle(String platform) throws Exception {
            this.platform = platform;
            files.put("browsers/chromium/chrome.exe", "browser".getBytes());
            files.put("driver/node.exe", "node".getBytes()); files.put("driver/package/cli.js", "driver".getBytes());
            rebuild();
        }
        /** Rebuilds the ZIP and exact digest/size declarations from the selected test files. */
        void rebuild() throws Exception {
            archive = zip(files, List.of(), false);
            ObjectNode n = JSON.createObjectNode().put("formatVersion", 1).put("platform", platform).put("playwrightJavaVersion", "1.64.0")
                    .put("browserName", "chromium").put("browserVersion", "156.0.8078.4").put("browserRevision", "1248")
                    .put("driverPackageVersion", "1.64.1").put("nodeVersion", "24.22.1").put("browserRoot", "browsers")
                    .put("browserExecutable", "browsers/chromium/chrome.exe").put("nodeExecutable", "driver/node.exe").put("driverEntryPoint", "driver/package/cli.js");
            n.putArray("helpers"); var rows = n.putArray("entries"); long total = 0;
            for (var entry : files.entrySet()) {
                rows.addObject().put("path", entry.getKey()).put("type", "file").put("bytes", entry.getValue().length)
                        .put("sha256", sha(entry.getValue())).put("executable", entry.getKey().endsWith(".exe")); total += entry.getValue().length;
            }
            n.put("unpackedBytes", total); n.putObject("archive").put("resource", BrowserRuntimeManager.platformResource(BrowserRuntimeManager.ARCHIVE_RESOURCE, platform)).put("sha256", sha(archive)).put("bytes", archive.length);
            manifest = JSON.writeValueAsBytes(n);
        }
        /** @param edit Manifest mutation for one invalid/boundary case. */
        void edit(Consumer<ObjectNode> edit) throws Exception { ObjectNode n = (ObjectNode) JSON.readTree(manifest); edit.accept(n); manifest = JSON.writeValueAsBytes(n); }
        /** Rebinds archive metadata after constructing a malformed but correctly hashed ZIP. */
        void bindArchive() throws Exception { edit(n -> ((ObjectNode) n.get("archive")).put("sha256", sha(archive)).put("bytes", archive.length)); }
        /** @param name Fixed resource name. @return Test bytes without filesystem/network fallback. */
        @Override public java.io.InputStream open(String name) throws IOException {
            if (name.equals(BrowserRuntimeManager.platformResource(BrowserRuntimeManager.MANIFEST_RESOURCE, platform))) return new ByteArrayInputStream(manifest);
            if (name.equals(BrowserRuntimeManager.platformResource(BrowserRuntimeManager.ARCHIVE_RESOURCE, platform))) { archives.incrementAndGet(); return new ByteArrayInputStream(archive); }
            throw new IOException("Unknown resource.");
        }
    }

    /** @param b In-memory bundle. @return Manager constrained to this test's temporary cache. */
    BrowserRuntimeManager manager(Bundle b) { return manager(b, BrowserRuntimeManager.Limits.standard(), BrowserAssetsTest::publish); }
    /** @param b Test bundle. @param limits Lowered or standard limits. @param publisher Atomic test boundary. @return Scoped test manager. */
    BrowserRuntimeManager manager(Bundle b, BrowserRuntimeManager.Limits limits, BrowserRuntimeManager.Publisher publisher) {
        return new BrowserRuntimeManager(b, temp.resolve("cache"), b.platform, limits, publisher);
    }
    /** @param from Owned stage. @param to New cache. @throws IOException If atomic publication fails. */
    static void publish(Path from, Path to) throws IOException { Files.move(from, to, StandardCopyOption.ATOMIC_MOVE); }
    /** @return A fresh finite monotonic setup deadline for synthetic fixtures. */
    static long deadline() { return System.nanoTime() + TimeUnit.SECONDS.toNanos(10); }
    /** @param data Exact test bytes. @return Independent SHA-256 representation. */
    static String sha(byte[] data) { try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data)); } catch (Exception ex) { throw new AssertionError(ex); } }
    /** @param files Regular members. @param extra Additional members, including duplicate names. @param symlink Whether extras use Unix-link metadata. @return Complete test ZIP. */
    static byte[] zip(Map<String, byte[]> files, List<String> extra, boolean symlink) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (var out = new ZipArchiveOutputStream(bytes)) {
            for (var entry : files.entrySet()) { var z = new ZipArchiveEntry(entry.getKey()); z.setUnixMode(0100644); out.putArchiveEntry(z); out.write(entry.getValue()); out.closeArchiveEntry(); }
            for (String name : extra) { var z = new ZipArchiveEntry(name); z.setUnixMode(symlink ? 0120777 : name.endsWith("/") ? 040755 : 0100644); out.putArchiveEntry(z); out.write(name.endsWith("/") ? new byte[0] : "driver/node.exe".getBytes()); out.closeArchiveEntry(); }
        }
        return bytes.toByteArray();
    }

    @Test void unsupportedTargetsTouchNeitherResourcesNorCache() throws Exception {
        for (String target : List.of("linux-arm64", "macos-arm64", "windows-arm64", "linux-x86", "unsupported-x64")) {
            AtomicInteger opens = new AtomicInteger(); Path root = temp.resolve(target);
            try (var runtime = new BrowserRuntimeManager(name -> { opens.incrementAndGet(); throw new IOException("unexpected"); },
                    root, target, BrowserRuntimeManager.Limits.standard(), BrowserAssetsTest::publish)) {
                assertEquals(AuthenticationFailure.Cause.UNSUPPORTED_PLATFORM,
                        assertThrows(AuthenticationFailure.class, () -> runtime.acquire(deadline(), () -> false)).reason());
                assertEquals(0, opens.get()); assertFalse(Files.exists(root));
            }
        }
    }
    @Test void eachSupportedTargetOpensOnlyItsScopedPayload() throws Exception {
        for (String platform : List.of("windows-x64", "linux-x64", "macos-x64")) {
            Bundle bundle = new Bundle(platform);
            try (var runtime = manager(bundle)) {
                assertTrue(runtime.acquire(deadline(), () -> false).root().startsWith(temp.resolve("cache").resolve(platform)));
                assertEquals(1, bundle.archives.get());
            }
            for (String resource : List.of(BrowserRuntimeManager.ARCHIVE_RESOURCE,
                    "META-INF/bpsh/foreign-x64/browser-assets.zip")) {
                bundle.edit(n -> ((ObjectNode) n.get("archive")).put("resource", resource));
                assertThrows(AuthenticationFailure.class, () -> BrowserRuntimeManager.parseManifest(bundle.manifest, platform, BrowserRuntimeManager.Limits.standard()));
            }
        }
    }
    @Test void posixExtractionPreservesExecutableFilesAndContainedLinks() throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(Files.getFileStore(temp).supportsFileAttributeView("posix"));
        Bundle bundle = new Bundle("linux-x64"); bundle.archive = zip(bundle.files, List.of("alias"), true);
        bundle.edit(n -> ((com.fasterxml.jackson.databind.node.ArrayNode) n.get("entries")).addObject()
                .put("path", "alias").put("type", "symlink").put("target", "driver/node.exe"));
        bundle.bindArchive();
        try (var runtime = manager(bundle)) {
            var ready = runtime.acquire(deadline(), () -> false);
            assertTrue(Files.isSymbolicLink(ready.root().resolve("alias")));
            assertEquals(Path.of("driver/node.exe"), Files.readSymbolicLink(ready.root().resolve("alias")));
            assertTrue(Files.isExecutable(ready.nodeExecutable()));
            assertFalse(Files.getPosixFilePermissions(ready.driverEntryPoint()).contains(java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE));
        }
    }

    @Test void extractsPublishesAndReusesOnlyVerifiedHandles() throws Exception {
        Bundle b = new Bundle(); Path root;
        try (var manager = manager(b)) {
            var first = manager.acquire(deadline(), () -> false); root = first.root();
            assertEquals("browser", Files.readString(first.browserExecutable())); assertEquals("node", Files.readString(first.nodeExecutable()));
            assertSame(first, manager.acquire(deadline(), () -> false)); assertTrue(Files.isRegularFile(root.resolve(".complete.json"))); assertEquals(1, b.archives.get());
        }
        try (var manager = manager(b)) { assertEquals(root, manager.acquire(deadline(), () -> false).root()); assertEquals(1, b.archives.get(), "cache hit verifies files without extracting another ZIP"); }
        assertTrue(Files.exists(root), "unload keeps durable cache binaries");
    }
    @Test void cacheDigestUsesDomainLfAndRawDigestsRatherThanHexText() throws Exception {
        Bundle b = new Bundle(); ByteArrayOutputStream input = new ByteArrayOutputStream(); input.write("bpsh-assets-v1\n".getBytes());
        input.write(MessageDigest.getInstance("SHA-256").digest(b.manifest)); input.write(MessageDigest.getInstance("SHA-256").digest(b.archive));
        assertEquals(sha(input.toByteArray()), BrowserRuntimeManager.bundleDigest(b.manifest, sha(b.archive)));
        assertNotEquals(BrowserRuntimeManager.bundleDigest(b.manifest, sha(b.archive)), BrowserRuntimeManager.bundleDigest((new String(b.manifest) + " ").getBytes(), sha(b.archive)));
    }
    @ParameterizedTest @ValueSource(strings = {"../escape", "/absolute", "C:/drive", "a\\backslash", "a//empty", "a/./dot", "a/../parent", ".complete.json", ".complete.json/child", "CON", "a.", "a ", "a?b"})
    void unsafeDeclaredPathsFailBeforeWriting(String name) throws Exception {
        Bundle b = new Bundle(); b.edit(n -> ((ObjectNode) n.get("entries").get(0)).put("path", name));
        try (var manager = manager(b)) { assertThrows(AuthenticationFailure.class, () -> manager.acquire(deadline(), () -> false)); }
        assertFalse(Files.exists(temp.resolve("cache")));
    }
    @Test void strictManifestVersionTypeFieldsAndSelectorsAreChecked() throws Exception {
        List<Consumer<ObjectNode>> invalid = List.of(n -> n.put("formatVersion", 2), n -> n.put("formatVersion", "1"), n -> n.put("unexpected", "value"),
                n -> n.put("nodeExecutable", "missing.exe"), n -> n.put("driverEntryPoint", "browsers"), n -> n.put("browserRoot", "driver/node.exe"),
                n -> ((ObjectNode) n.get("entries").get(1)).put("executable", false), n -> n.put("unpackedBytes", Long.MAX_VALUE),
                n -> ((ObjectNode) n.get("archive")).put("resource", "https://example.invalid/browser.zip"),
                n -> ((ObjectNode) n.get("entries").get(0)).put("bytes", 1.5), n -> ((ObjectNode) n.get("entries").get(0)).put("executable", "true"));
        for (var change : invalid) { Bundle b = new Bundle(); b.edit(change); assertThrows(AuthenticationFailure.class, () -> BrowserRuntimeManager.parseManifest(b.manifest, PLATFORM, BrowserRuntimeManager.Limits.standard())); }
        Bundle duplicate = new Bundle(); duplicate.manifest = new String(duplicate.manifest).replace("\"formatVersion\":1", "\"formatVersion\":1,\"formatVersion\":1").getBytes();
        assertThrows(AuthenticationFailure.class, () -> BrowserRuntimeManager.parseManifest(duplicate.manifest, PLATFORM, BrowserRuntimeManager.Limits.standard()));
    }
    @Test void wrongPlatformAndMissingResourcesHaveSpecificGuidance() throws Exception {
        Bundle b = new Bundle(); b.edit(n -> n.put("platform", "linux-x64"));
        try (var manager = manager(b)) { assertEquals(AuthenticationFailure.Cause.UNSUPPORTED_PLATFORM, assertThrows(AuthenticationFailure.class, () -> manager.acquire(deadline(), () -> false)).reason()); }
        try (var manager = new BrowserRuntimeManager(name -> { throw new IOException("missing"); }, temp.resolve("cache"), PLATFORM, BrowserRuntimeManager.Limits.standard(), BrowserAssetsTest::publish)) {
            assertEquals(AuthenticationFailure.Cause.ASSET_MISSING, assertThrows(AuthenticationFailure.class, () -> manager.acquire(deadline(), () -> false)).reason());
        }
    }
    @Test void fileDirectoryAndCaseCollisionsAreRejected() throws Exception {
        for (String added : List.of("driver", "DRIVER/other", "Driver/node.exe")) {
            Bundle b = new Bundle(); b.files.put(added, new byte[0]); b.rebuild();
            assertThrows(AuthenticationFailure.class, () -> BrowserRuntimeManager.parseManifest(b.manifest, PLATFORM, BrowserRuntimeManager.Limits.standard()));
        }
    }
    @Test void corruptAndIncompleteCachesArePreservedWithRecoveryPath() throws Exception {
        Bundle b = new Bundle(); Path root;
        try (var manager = manager(b)) { root = manager.acquire(deadline(), () -> false).root(); }
        Files.writeString(root.resolve("driver/node.exe"), "BAD!");
        try (var manager = manager(b)) {
            var ex = assertThrows(AuthenticationFailure.class, () -> manager.acquire(deadline(), () -> false));
            assertTrue(ex.getMessage().contains(root.toString())); assertEquals(AuthenticationFailure.Cause.ASSET_CORRUPT, ex.reason());
        }
        assertEquals("BAD!", Files.readString(root.resolve("driver/node.exe"))); assertEquals(1, b.archives.get());
        Files.delete(root.resolve(".complete.json"));
        try (var manager = manager(b)) { assertThrows(AuthenticationFailure.class, () -> manager.acquire(deadline(), () -> false)); }
        assertTrue(Files.exists(root));
    }
    @Test void markerMismatchAndUndeclaredCacheFilesAreRejected() throws Exception {
        Bundle b = new Bundle(); Path root;
        try (var manager = manager(b)) { root = manager.acquire(deadline(), () -> false).root(); }
        Path marker = root.resolve(".complete.json"); String original = Files.readString(marker);
        Files.writeString(marker, original.replace("\"formatVersion\":1", "\"formatVersion\":2"));
        try (var manager = manager(b)) { assertThrows(AuthenticationFailure.class, () -> manager.acquire(deadline(), () -> false)); }
        Files.writeString(marker, original); Files.writeString(root.resolve("foreign"), "keep");
        try (var manager = manager(b)) { assertThrows(AuthenticationFailure.class, () -> manager.acquire(deadline(), () -> false)); }
        assertEquals("keep", Files.readString(root.resolve("foreign")));
    }
    @Test void duplicateUndeclaredMissingAndWrongDigestArchiveMembersNeverPublish() throws Exception {
        for (int mode = 0; mode < 5; mode++) {
            Bundle b = new Bundle();
            if (mode == 0) b.archive = zip(b.files, List.of("driver/node.exe"), false);
            if (mode == 1) b.archive = zip(b.files, List.of("extra"), false);
            if (mode == 2) { Map<String, byte[]> missing = new LinkedHashMap<>(b.files); missing.remove("driver/node.exe"); b.archive = zip(missing, List.of(), false); }
            if (mode == 3) { Map<String, byte[]> bad = new LinkedHashMap<>(b.files); bad.put("driver/node.exe", "FAKE".getBytes()); b.archive = zip(bad, List.of(), false); }
            if (mode < 4) b.bindArchive(); else b.archive[0] ^= 1;
            try (var manager = manager(b)) { assertThrows(AuthenticationFailure.class, () -> manager.acquire(deadline(), () -> false)); }
            try (var paths = Files.list(temp.resolve("cache").resolve(PLATFORM))) { assertTrue(paths.allMatch(p -> p.getFileName().toString().endsWith(".lock"))); }
        }
    }
    @Test void declaredAndImplicitDirectoryEntriesAreCheckedAndCounted() throws Exception {
        Bundle b = new Bundle(); b.archive = zip(b.files, List.of("driver/", "driver/package/"), false); b.bindArchive();
        try (var manager = manager(b)) { assertNotNull(manager.acquire(deadline(), () -> false)); }
        Bundle bad = new Bundle(); bad.archive = zip(bad.files, List.of("undeclared/"), false); bad.bindArchive();
        try (var manager = manager(bad)) { assertThrows(AuthenticationFailure.class, () -> manager.acquire(deadline(), () -> false)); }
    }
    @Test void linkTraversalCyclesAndHopCeilingsAreValidatedBeforeExtraction() throws Exception {
        for (String target : List.of("../outside", "/absolute", "C:/drive", "bad\\target", "missing")) {
            Bundle b = new Bundle(); b.edit(n -> ((com.fasterxml.jackson.databind.node.ArrayNode) n.get("entries")).addObject().put("path", "alias").put("type", "symlink").put("target", target));
            assertThrows(AuthenticationFailure.class, () -> BrowserRuntimeManager.parseManifest(b.manifest, PLATFORM, BrowserRuntimeManager.Limits.standard()));
        }
        for (int hops : List.of(16, 17)) {
            Bundle b = new Bundle(); b.edit(n -> {
                var rows = (com.fasterxml.jackson.databind.node.ArrayNode) n.get("entries");
                for (int i = 0; i < hops; i++) rows.addObject().put("path", "link" + i).put("type", "symlink").put("target", i + 1 == hops ? "driver/node.exe" : "link" + (i + 1));
            });
            if (hops == 16) assertDoesNotThrow(() -> BrowserRuntimeManager.parseManifest(b.manifest, PLATFORM, BrowserRuntimeManager.Limits.standard()));
            else assertThrows(AuthenticationFailure.class, () -> BrowserRuntimeManager.parseManifest(b.manifest, PLATFORM, BrowserRuntimeManager.Limits.standard()));
        }
        Bundle cycle = new Bundle(); cycle.edit(n -> {
            var rows = (com.fasterxml.jackson.databind.node.ArrayNode) n.get("entries"); rows.addObject().put("path", "a").put("type", "symlink").put("target", "b"); rows.addObject().put("path", "b").put("type", "symlink").put("target", "a");
        });
        assertThrows(AuthenticationFailure.class, () -> BrowserRuntimeManager.parseManifest(cycle.manifest, PLATFORM, BrowserRuntimeManager.Limits.standard()));
    }
    @Test void loweredLimitsExerciseBoundariesWithoutLargeAllocations() throws Exception {
        Bundle b = new Bundle(); var max = BrowserRuntimeManager.Limits.standard();
        var exact = new BrowserRuntimeManager.Limits(b.manifest.length, b.archive.length, 17, 7, 3, max.pathBytes(), max.depth(), max.linkHops());
        try (var manager = manager(b, exact, BrowserAssetsTest::publish)) { assertNotNull(manager.acquire(deadline(), () -> false)); }
        List<BrowserRuntimeManager.Limits> small = List.of(
                new BrowserRuntimeManager.Limits(b.manifest.length - 1, max.zipBytes(), max.totalBytes(), max.fileBytes(), max.entries(), 4096, 32, 16),
                new BrowserRuntimeManager.Limits(max.manifestBytes(), b.archive.length - 1, 17, 7, 3, 4096, 32, 16),
                new BrowserRuntimeManager.Limits(max.manifestBytes(), max.zipBytes(), 16, 7, 3, 4096, 32, 16),
                new BrowserRuntimeManager.Limits(max.manifestBytes(), max.zipBytes(), 17, 6, 3, 4096, 32, 16),
                new BrowserRuntimeManager.Limits(max.manifestBytes(), max.zipBytes(), 17, 7, 2, 4096, 32, 16),
                new BrowserRuntimeManager.Limits(max.manifestBytes(), max.zipBytes(), 17, 7, 3, 10, 32, 16),
                new BrowserRuntimeManager.Limits(max.manifestBytes(), max.zipBytes(), 17, 7, 3, 4096, 2, 16));
        for (var limits : small) assertThrows(AuthenticationFailure.class, () -> BrowserRuntimeManager.parseManifest(b.manifest, PLATFORM, limits));
    }
    @Test void lockTimeoutAndCancellationDoNotBypassOtherOwners() throws Exception {
        Bundle b = new Bundle(); Path parent = temp.resolve("cache").resolve(PLATFORM); Files.createDirectories(parent);
        Path lock = parent.resolve(BrowserRuntimeManager.bundleDigest(b.manifest, sha(b.archive)) + ".lock");
        try (var file = FileChannel.open(lock, StandardOpenOption.CREATE, StandardOpenOption.WRITE); var held = file.lock(); var manager = manager(b)) {
            var ex = assertThrows(AuthenticationFailure.class, () -> manager.acquire(System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(100), () -> false));
            assertEquals(AuthenticationFailure.Cause.CACHE_BUSY, ex.reason());
            assertEquals(AuthenticationFailure.Cause.CANCELLED, assertThrows(AuthenticationFailure.class, () -> manager.acquire(deadline(), () -> true)).reason());
        }
        assertEquals(0, b.archives.get());
    }
    @Test void concurrentExtractorsUseOnePublishedTreeAndOneArchiveRead() throws Exception {
        Bundle b = new Bundle(); CountDownLatch start = new CountDownLatch(1);
        try (var first = manager(b); var second = manager(b); var pool = Executors.newFixedThreadPool(2)) {
            var one = pool.submit(() -> { start.await(); return first.acquire(deadline(), () -> false).root(); });
            var two = pool.submit(() -> { start.await(); return second.acquire(deadline(), () -> false).root(); }); start.countDown();
            assertEquals(one.get(5, TimeUnit.SECONDS), two.get(5, TimeUnit.SECONDS)); assertEquals(1, b.archives.get());
        }
    }
    @Test void failedAtomicPublicationAndCancelledExtractionCleanOnlyTheirOwnPaths() throws Exception {
        Bundle b = new Bundle(); Path parent = temp.resolve("cache").resolve(PLATFORM); Files.createDirectories(parent);
        Path unrelated = parent.resolve("user-profile"); Files.createDirectory(unrelated); Files.writeString(unrelated.resolve("keep"), "keep");
        try (var manager = manager(b, BrowserRuntimeManager.Limits.standard(), (from, to) -> { throw new IOException("injected atomic-move failure"); })) {
            assertThrows(AuthenticationFailure.class, () -> manager.acquire(deadline(), () -> false));
        }
        AtomicBoolean cancelled = new AtomicBoolean(); BrowserRuntimeManager.Resources source = name -> {
            if (name.equals(BrowserRuntimeManager.platformResource(BrowserRuntimeManager.ARCHIVE_RESOURCE, PLATFORM))) cancelled.set(true); return b.open(name);
        };
        try (var manager = new BrowserRuntimeManager(source, temp.resolve("cache"), PLATFORM, BrowserRuntimeManager.Limits.standard(), BrowserAssetsTest::publish)) {
            assertEquals(AuthenticationFailure.Cause.CANCELLED, assertThrows(AuthenticationFailure.class, () -> manager.acquire(deadline(), cancelled::get)).reason());
        }
        assertEquals("keep", Files.readString(unrelated.resolve("keep")));
        try (var paths = Files.list(parent)) { assertTrue(paths.noneMatch(p -> p.getFileName().toString().contains(".staging-") || p.getFileName().toString().contains(".archive-"))); }
    }

    @Test void setupObservationIsLocalAndCallbackErrorsDoNotChangePreparation() throws Exception {
        Bundle bundle = new Bundle(); var stages = new ArrayList<BrowserRuntimeManager.SetupStage>();
        try (var runtime = manager(bundle)) {
            runtime.acquire(deadline(), () -> false, stage -> { stages.add(stage); throw new IllegalStateException("fixture-secret"); });
        }
        assertEquals(List.of(BrowserRuntimeManager.SetupStage.EXTRACTING_BROWSER), stages);
        stages.clear();
        try (var runtime = manager(bundle)) { runtime.acquire(deadline(), () -> false, stages::add); }
        assertEquals(List.of(BrowserRuntimeManager.SetupStage.VERIFYING_CACHE), stages);
    }
    @Test void unrelatedIoIsNotLabeledCorruptionAndAccessErrorsStaySafe() throws Exception {
        for (boolean denied : List.of(false, true)) {
            Bundle bundle = new Bundle();
            try (var runtime = manager(bundle, BrowserRuntimeManager.Limits.standard(), (from, to) -> {
                if (denied) throw new java.nio.file.AccessDeniedException("fixture-secret");
                throw new IOException("fixture-secret");
            })) {
                var error = assertThrows(AuthenticationFailure.class, () -> runtime.acquire(deadline(), () -> false));
                assertEquals(denied ? AuthenticationFailure.Cause.CONFIGURATION : AuthenticationFailure.Cause.UNKNOWN, error.reason());
                assertFalse(error.getMessage().contains("fixture-secret")); assertNull(error.getCause());
            }
        }
    }
}
