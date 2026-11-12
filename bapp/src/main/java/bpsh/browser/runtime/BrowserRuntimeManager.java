package bpsh.browser.runtime;

import bpsh.platform.files.PrivateFiles;
import bpsh.authentication.AuthenticationFailure;
import bpsh.authentication.AuthenticationStage;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import org.apache.commons.compress.archivers.zip.ZipFile;
import static bpsh.browser.runtime.BrowserManifestCodec.*;

/**
 * Verifies and extracts only the JAR's bundled browser assets, with no network/install fallback.
 *
 * Each extension instance fully verifies its first cache acquisition, then reuses an immutable
 * ready handle. Published caches are never repaired/deleted in place. Cancellation cleans only
 * this invocation's checked staging tree; durable binaries survive manager shutdown.
 */
public final class BrowserRuntimeManager implements AutoCloseable {
    static Manifest parseManifest(byte[] raw, String expectedPlatform, Limits limits) throws AuthenticationFailure {
        return BrowserManifestCodec.parseManifest(raw, expectedPlatform, limits);
    }

    static final String MANIFEST_RESOURCE = "META-INF/bpsh/driver-assets.json";
    static final String ARCHIVE_RESOURCE = "META-INF/bpsh/driver-assets.zip.xz";
    private static final ObjectMapper JSON = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private static final LinkOption[] NOFOLLOW = { LinkOption.NOFOLLOW_LINKS };

    /** Opens classloader resources; tests supply small in-memory archives without initializing Playwright. */
    @FunctionalInterface interface Resources {
        /**
         * Opens one exact bundled classloader resource; callers own and close the returned stream.
         *
         * @param name Exact bundled resource name.
         * @return Owned stream to close.
         * @throws IOException If absent.
         */
        InputStream open(String name) throws IOException;
    }

    /** Replaces the final atomic publication primitive in failure-injection tests. */
    @FunctionalInterface interface Publisher {
        /**
         * Atomically publishes a verified staging directory without modifying an existing immutable cache.
         *
         * @param from Checked owned staging path.
         * @param to New immutable cache path.
         * @throws IOException On failure.
         */
        void publish(Path from, Path to) throws IOException;
    }

    /** Hard ceilings; tests may lower them to exercise boundaries without enormous fixture archives. */
    record Limits(long manifestBytes, long zipBytes, long totalBytes, long fileBytes, int entries,
                  int pathBytes, int depth, int linkHops) {
        /**
         * Returns the approved archive and extraction ceilings.
         *
         * @return The approved archive and extraction ceilings.
         */
        static Limits standard() { return new Limits(32L << 20, 2L << 30, 4L << 30, 1L << 30, 100_000, 4096, 32, 16); }
    }

    /** Describes a declared file or link; directories are derived only from declared parent paths. */
    record Entry(String path, boolean link, long bytes, String sha256, boolean executable, String target) {}

    /** Validated manifest metadata shared by extraction and full cache-hit validation. */
    record Manifest(String platform, String helperRoot, String nodeExecutable,
                    String driverEntryPoint, String archiveHash, long archiveBytes, long expandedBytes, long unpackedBytes,
                    Map<String, Entry> entries, Set<String> directories, List<String> helpers) {}

    /**
     * Holds verified bundled driver selectors only.
     * Bundled marker, tree, hashes and permissions are checked before construction.
     * Installed browser selection belongs to the per-attempt resolver, outside this manifest.
     */
    public static final class Ready {
        private final Path root;
        private final Manifest manifest;
        private final String digest;
        /**
         * Captures immutable verified selectors and the bundle identity after cache validation succeeds.
         *
         * @param root Verified published tree.
         * @param manifest Validated metadata.
         * @param digest Cache identity.
         */
        private Ready(Path root, Manifest manifest, String digest) {
            this.root = root; this.manifest = manifest; this.digest = digest;
        }
        /**
         * Returns immutable published bundle directory.
         *
         * @return Immutable published bundle directory.
         */
        public Path root() { return root; }
        /**
         * Returns exact verified driver-helper directory used by the owned driver environment.
         *
         * @return Exact verified driver-helper directory used by the owned driver environment.
         */
        public Path helperRoot() { return root.resolve(manifest.helperRoot()); }
        /**
         * Returns exact bundled Node executable.
         *
         * @return Exact bundled Node executable.
         */
        public Path nodeExecutable() { return root.resolve(manifest.nodeExecutable()); }
        /**
         * Returns exact bundled Playwright JS entry point.
         *
         * @return Exact bundled Playwright JS entry point.
         */
        public Path driverEntryPoint() { return root.resolve(manifest.driverEntryPoint()); }
        /**
         * Returns manifest-and-archive-derived immutable cache identity.
         *
         * @return Manifest-and-archive-derived immutable cache identity.
         */
        public String bundleDigest() { return digest; }
    }



    /** Reports fixed metadata without allowing presentation failures to change an attempt.
     * @param observer Attempt-local callback.
     * @param stage Actual setup operation.
     */
    public static void observed(Consumer<AuthenticationStage> observer, AuthenticationStage stage) {
        try { observer.accept(stage); } catch (RuntimeException ignored) { /* cleanup and policy are independent */ }
    }



    private final Resources resources;
    private final Path cacheRoot;
    private final String platform;
    private final Limits limits;
    private final Publisher publisher;
    private final ReentrantLock setup = new ReentrantLock();
    private volatile Ready ready;
    private volatile boolean closed;

    /** Creates a lazy manager; no resources, filesystem paths or browser processes are touched yet. */
    public BrowserRuntimeManager() {
        this(name -> {
            InputStream input = BrowserRuntimeManager.class.getClassLoader().getResourceAsStream(name);
            if (input == null) throw new IOException("Missing browser resource.");
            return input;
        }, Path.of(System.getProperty("user.home"), ".bpsh", "cache", "drivers-v3"), hostPlatform(), Limits.standard(),
                (from, to) -> Files.move(from, to, StandardCopyOption.ATOMIC_MOVE));
    }


    /**
     * Maps a logical asset name to the exact host's resources in the universal JAR.
     * @param name Fixed logical manifest or archive resource.
     * @param platform Normalized OS and CPU architecture.
     * @return Platform-scoped classloader resource, with no fallback to a different architecture.
     */
    static String platformResource(String name, String platform) {
        if (!Set.of("windows-x64", "linux-x64", "macos-x64").contains(platform))
            throw new IllegalArgumentException("Unsupported browser platform.");
        if (!name.equals(MANIFEST_RESOURCE) && !name.equals(ARCHIVE_RESOURCE))
            throw new IllegalArgumentException("Unexpected browser resource.");
        return "META-INF/bpsh/" + platform + "/" + name.substring(name.lastIndexOf('/') + 1);
    }



    /**
     * Configures a local test boundary without relaxing production ceilings.
     * @param resources Owned bundled-resource streams, never remote URLs.
     * @param cacheRoot Explicit cache directory owned by this runtime or test.
     * @param platform Exact normalized host target expected by the manifest.
     * @param limits Standard or lowered extraction ceilings.
     * @param publisher Atomic directory publication primitive.
     */
    BrowserRuntimeManager(Resources resources, Path cacheRoot, String platform, Limits limits, Publisher publisher) {
        this.resources = resources; this.cacheRoot = cacheRoot.toAbsolutePath().normalize(); this.platform = platform;
        this.limits = limits; this.publisher = publisher;
        Limits max = Limits.standard();
        if (limits.manifestBytes < 1 || limits.manifestBytes > max.manifestBytes || limits.zipBytes < 1 || limits.zipBytes > max.zipBytes
                || limits.totalBytes < 0 || limits.totalBytes > max.totalBytes || limits.fileBytes < 0 || limits.fileBytes > max.fileBytes
                || limits.entries < 1 || limits.entries > max.entries || limits.pathBytes < 1 || limits.pathBytes > max.pathBytes
                || limits.depth < 1 || limits.depth > max.depth || limits.linkHops < 1 || limits.linkHops > max.linkHops)
            throw new IllegalArgumentException("Asset ceilings may only be lowered.");
    }

    /**
     * Acquires an offline verified runtime within the caller's original monotonic setup budget.
     * @param deadlineNanos Absolute System.nanoTime deadline; not restarted while waiting for locks.
     * @param cancelled Cancellation predicate for the attempt/extension.
     * @return Reusable verified handle; the caller must not mutate the published tree.
     * @throws AuthenticationFailure On cancellation, unsupported assets, contention or validation/I/O failure.
     */
    public Ready acquire(long deadlineNanos, BooleanSupplier cancelled) throws AuthenticationFailure {
        return acquire(deadlineNanos, cancelled, stage -> {});
    }

    /** Acquires the exact local payload within the unchanged caller deadline.
     * @param deadlineNanos Original absolute monotonic deadline.
     * @param cancelled Attempt cancellation predicate.
     * @param observer Attempt-local safe stage observer.
     * @return Verified immutable host handle.
     * @throws AuthenticationFailure On bounded setup or validation failure.
     */
    public Ready acquire(long deadlineNanos, BooleanSupplier cancelled, Consumer<AuthenticationStage> observer) throws AuthenticationFailure {
        requireSupportedPlatform(platform);
        check(deadlineNanos, cancelled);
        if (ready != null) return ready;
        boolean held = false, waitedForSetup = false;
        try {
            // Journeys sharing this manager wait for its owned setup within their original attempt budgets.
            while (!(held = setup.tryLock())) { if (!waitedForSetup) { observed(observer, AuthenticationStage.WAITING_FOR_CACHE); waitedForSetup = true; } pause(deadlineNanos, cancelled); }
            check(deadlineNanos, cancelled);
            if (ready != null) return ready;
            byte[] raw;
            try (InputStream input = resource(platformResource(MANIFEST_RESOURCE, platform))) { raw = bounded(input, limits.manifestBytes); }
            Manifest manifest = parseManifest(raw, platform, limits);
            String manifestHash = digest(raw), bundle = bundleDigest(raw, manifest.archiveHash());
            Path parent = cacheRoot.resolve(platform), destination = parent.resolve(bundle);
            makeOwnedParents(parent);
            Path lockPath = parent.resolve(bundle + ".lock"); rejectLink(lockPath);
            createPrivateFile(lockPath, true);
            try (FileChannel channel = FileChannel.open(lockPath, StandardOpenOption.WRITE)) {
                long lockDeadline = Math.min(deadlineNanos, System.nanoTime() + TimeUnit.SECONDS.toNanos(10));
                FileLock fileLock = null; boolean waited = false;
                while (fileLock == null) {
                    if (waited && lockDeadline - System.nanoTime() <= 0) pause(lockDeadline, cancelled);
                    check(deadlineNanos, cancelled);
                    try { fileLock = channel.tryLock(); } catch (OverlappingFileLockException ignored) { /* busy in this JVM */ }
                    if (fileLock == null) { if (!waited) observed(observer, AuthenticationStage.WAITING_FOR_CACHE); waited = true; pause(lockDeadline, cancelled); }
                }
                try (FileLock ownedLock = fileLock) {
                    if (Files.exists(destination, NOFOLLOW)) {
                        observed(observer, AuthenticationStage.VERIFYING_CACHE);
                        verifyPublished(destination, manifest, bundle, manifestHash, deadlineNanos, cancelled);
                    } else {
                        observed(observer, AuthenticationStage.EXTRACTING_BROWSER);
                        extract(parent, destination, manifest, bundle, manifestHash, deadlineNanos, cancelled);
                    }
                    check(deadlineNanos, cancelled);
                    ready = new Ready(destination, manifest, bundle);
                    return ready;
                }
            }
        } catch (AuthenticationFailure ex) {
            if (ex.reason() == AuthenticationFailure.Cause.TIMEOUT)
                throw failure(ex.reason(), "Bundled browser setup timed out.", "");
            throw ex;
        } catch (Exception ex) {
            throw setupFailure(ex, "Browser setup could not finish in " + cacheRoot + ".");
        } finally { if (held) setup.unlock(); }
    }



    /**
     * Streams/verifies XZ to an owned ZIP, extracts it, then publishes only a complete validated tree.
     * @param parent Owned platform cache directory.
     * @param destination New immutable cache path; existing caches are handled by verification instead.
     * @param manifest Validated declarations and selectors.
     * @param bundle Derived directory identity.
     * @param manifestHash Exact manifest digest for the completion marker.
     * @param deadline Original attempt deadline.
     * @param cancelled Cooperative cancellation predicate.
     * @throws Exception On validation, cancellation, I/O or atomic-publication failure.
     */
    private void extract(Path parent, Path destination, Manifest manifest, String bundle, String manifestHash,
                         long deadline, BooleanSupplier cancelled) throws Exception {
        try {
            long usable = Files.getFileStore(parent).getUsableSpace();
            if (usable > 0 && usable < manifest.expandedBytes() + manifest.unpackedBytes())
                throw failure(AuthenticationFailure.Cause.CONFIGURATION, "There is not enough free space to prepare the bundled browser.",
                        "Free space for the selected archive and extracted browser, then try again.");
        } catch (IOException | UnsupportedOperationException | SecurityException ignored) { /* no positive space evidence */ }
        Path stage = parent.resolve(bundle + ".staging-" + UUID.randomUUID());
        Path archive = parent.resolve(bundle + ".archive-" + UUID.randomUUID() + ".zip");
        Files.createDirectory(stage, privateAttributes(parent, true));
        try {
            createPrivateFile(archive, false);
            try (var out = Files.newOutputStream(archive)) {
                BrowserArchiveCodec.decode(resource(platformResource(ARCHIVE_RESOURCE, platform)), out,
                        manifest.archiveBytes(), manifest.archiveHash(), manifest.expandedBytes(), () -> check(deadline, cancelled));
            }
            for (String dir : manifest.directories().stream().sorted(java.util.Comparator.comparingInt(String::length)).toList()) {
                check(deadline, cancelled); Files.createDirectory(stage.resolve(dir), privateAttributes(stage, true)); mode(stage.resolve(dir), true, true);
            }
            Set<String> seen = new HashSet<>(); int count = 0; long expanded = 0;
            try (ZipFile zip = ZipFile.builder().setFile(archive.toFile()).get()) {
                var enumeration = zip.getEntries();
                while (enumeration.hasMoreElements()) {
                    check(deadline, cancelled); var entry = enumeration.nextElement();
                    require(++count <= limits.entries, "Too many ZIP entries.");
                    String name = entry.getName(); boolean directory = entry.isDirectory();
                    if (directory) { require(name.endsWith("/"), "Invalid directory entry."); name = name.substring(0, name.length() - 1); }
                    path(name, limits); require(seen.add(name), "Duplicate ZIP path.");
                    if (directory) { require(manifest.directories().contains(name), "Undeclared ZIP directory."); continue; }
                    Entry declared = manifest.entries().get(name);
                    require(declared != null && zip.canReadEntryData(entry) && declared.link() == entry.isUnixSymlink(), "Undeclared or incompatible ZIP entry.");
                    require(entry.getSize() >= 0 && entry.getSize() <= (declared.link() ? limits.pathBytes : limits.fileBytes), "ZIP entry exceeds its ceiling.");
                    try (InputStream input = zip.getInputStream(entry)) {
                        if (declared.link()) {
                            byte[] target = bounded(input, limits.pathBytes);
                            require(Arrays.equals(target, declared.target().getBytes(StandardCharsets.UTF_8)), "Link payload mismatch.");
                        } else {
                            require(entry.getSize() == declared.bytes(), "ZIP member size mismatch.");
                            Path file = stage.resolve(name); createPrivateFile(file, false);
                            MessageDigest hash = sha(); long bytes = 0; byte[] buffer = new byte[65536];
                            try (var output = Files.newOutputStream(file)) {
                                for (int n; (n = input.read(buffer)) >= 0;) {
                                    check(deadline, cancelled); bytes += n; expanded += n;
                                    require(bytes <= declared.bytes() && expanded <= limits.totalBytes, "Expanded ZIP exceeds declarations.");
                                    hash.update(buffer, 0, n); output.write(buffer, 0, n);
                                }
                            }
                            require(bytes == declared.bytes() && hex(hash.digest()).equals(declared.sha256()), "Member digest mismatch.");
                            mode(file, declared.executable(), false);
                        }
                    }
                }
            }
            require(seen.containsAll(manifest.entries().keySet()) && expanded == manifest.unpackedBytes(), "Missing ZIP members or byte total mismatch.");
            for (Entry entry : manifest.entries().values()) if (entry.link()) {
                check(deadline, cancelled); Files.createSymbolicLink(stage.resolve(entry.path()), Path.of(entry.target()));
            }
            mode(stage, true, true);
            verifyTree(stage, manifest, false, deadline, cancelled);
            var marker = JSON.createObjectNode().put("formatVersion", 1).put("platform", platform).put("bundleDigest", bundle)
                    .put("manifestSha256", manifestHash).put("archiveSha256", manifest.archiveHash());
            Path complete = stage.resolve(".complete.json"); createPrivateFile(complete, false);
            try (FileChannel out = FileChannel.open(complete, StandardOpenOption.WRITE)) {
                ByteBuffer bytes = ByteBuffer.wrap(JSON.writeValueAsBytes(marker)); while (bytes.hasRemaining()) out.write(bytes); out.force(true);
            }
            mode(complete, false, false); check(deadline, cancelled);
            checkedStage(parent, stage, bundle); require(destination.getParent().equals(parent) && destination.getFileName().toString().equals(bundle), "Invalid publish target.");
            require(!Files.exists(destination, NOFOLLOW), "Another cache appeared during setup.");
            publishVerified(stage, destination, deadline, cancelled);
        } finally {
            Files.deleteIfExists(archive);
            if (Files.exists(stage, NOFOLLOW)) { checkedStage(parent, stage, bundle); deleteOwnedTree(stage); }
        }
    }

    /** Retries transient Windows directory-handle contention without weakening atomic publication. */
    private void publishVerified(Path stage, Path destination, long deadline, BooleanSupplier cancelled) throws Exception {
        long retryUntil = System.nanoTime() + TimeUnit.SECONDS.toNanos(1);
        while (true) {
            check(deadline, cancelled);
            try { publisher.publish(stage, destination); return; }
            catch (java.nio.file.AccessDeniedException denied) {
                if (!platform.equals("windows-x64") || System.nanoTime() >= retryUntil) throw denied;
                try { Thread.sleep(25); }
                catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); check(deadline, () -> true); }
            }
        }
    }

    /**
     * Requires a matching marker plus a complete tree on the first cache hit in this instance.
     * @param root Existing published cache; never modified by this operation.
     * @param manifest Validated bundle declarations.
     * @param bundle Expected cache identity.
     * @param manifestHash Exact manifest digest.
     * @param deadline Original attempt deadline.
     * @param cancelled Cancellation predicate.
     * @throws Exception If any published state is missing, corrupt or inaccessible.
     */
    private void verifyPublished(Path root, Manifest manifest, String bundle, String manifestHash,
                                 long deadline, BooleanSupplier cancelled) throws Exception {
        try {
            rejectLink(root); require(Files.isDirectory(root, NOFOLLOW), "Cache is not a directory.");
            Path complete = root.resolve(".complete.json"); rejectLink(complete);
            byte[] bytes; try (InputStream in = Files.newInputStream(complete)) { bytes = bounded(in, 4096); }
            JsonNode marker = JSON.readTree(utf8(bytes)); object(marker, "formatVersion", "platform", "bundleDigest", "manifestSha256", "archiveSha256");
            number(marker.get("formatVersion"), 1, 1);
            require(text(marker, "platform").equals(platform) && text(marker, "bundleDigest").equals(bundle)
                    && text(marker, "manifestSha256").equals(manifestHash) && text(marker, "archiveSha256").equals(manifest.archiveHash()), "Completion marker mismatch.");
            verifyTree(root, manifest, true, deadline, cancelled);
        } catch (AuthenticationFailure ex) { throw ex; }
        catch (Exception ex) {
            if (ex instanceof InvalidAsset || ex instanceof java.nio.file.NoSuchFileException || ex instanceof com.fasterxml.jackson.core.JsonProcessingException)
                throw failure(AuthenticationFailure.Cause.ASSET_CORRUPT, "The cached browser files are incomplete or damaged: " + root + ".",
                        "Close Burp instances using this browser bundle, delete the directory shown above, then reload the extension.");
            throw setupFailure(ex, "The cached browser files could not be verified.");
        }
    }

    /**
     * Verifies every declared file/link and rejects undeclared paths without following links in the walk.
     * @param root Owned staging or immutable published directory.
     * @param manifest Validated file/link tree.
     * @param marker Whether the root completion file must be present.
     * @param deadline Original budget deadline.
     * @param cancelled Cancellation predicate.
     * @throws Exception If paths, sizes, hashes, modes or link payloads differ.
     */
    private void verifyTree(Path root, Manifest manifest, boolean marker, long deadline, BooleanSupplier cancelled) throws Exception {
        Set<String> expected = new HashSet<>(manifest.directories()); expected.addAll(manifest.entries().keySet()); if (marker) expected.add(".complete.json");
        try (var paths = Files.walk(root)) {
            var iterator = paths.iterator();
            while (iterator.hasNext()) {
                Path file = iterator.next();
                check(deadline, cancelled); if (file.equals(root)) continue;
                String name = root.relativize(file).toString().replace('\\', '/'); require(expected.remove(name), "Undeclared cache path.");
                Entry entry = manifest.entries().get(name);
                if (entry == null) {
                    require(!Files.isSymbolicLink(file) && (name.equals(".complete.json") ? Files.isRegularFile(file, NOFOLLOW) : Files.isDirectory(file, NOFOLLOW)), "Invalid cache metadata/directory.");
                } else if (entry.link()) {
                    require(Files.isSymbolicLink(file) && Files.readSymbolicLink(file).toString().replace('\\', '/').equals(entry.target()), "Cache link mismatch.");
                    require(file.toRealPath().startsWith(root.toRealPath()), "Cache link escapes bundle.");
                } else {
                    require(Files.isRegularFile(file, NOFOLLOW) && Files.size(file) == entry.bytes(), "Cache file size/type mismatch.");
                    MessageDigest hash = sha(); byte[] buffer = new byte[65536]; long bytes = 0;
                    try (InputStream input = Files.newInputStream(file)) {
                        for (int n; (n = input.read(buffer)) >= 0;) { check(deadline, cancelled); bytes += n; require(bytes <= entry.bytes(), "Cache file grew during verification."); hash.update(buffer, 0, n); }
                    }
                    require(bytes == entry.bytes() && hex(hash.digest()).equals(entry.sha256()), "Cache file digest mismatch.");
                    if (Files.getFileAttributeView(file, PosixFileAttributeView.class) != null)
                        require(Files.getPosixFilePermissions(file).equals(PosixFilePermissions.fromString(entry.executable() ? "rwxr-xr-x" : "rw-r--r--")), "Cache executable mode mismatch.");
                }
            }
        }
        require(expected.isEmpty(), "Declared cache paths are missing.");
    }







    /**
     * Derives cache identity from exact manifest bytes and raw archive digest bytes in approved order.
     * @param manifest Original bytes, not JSON reserialization.
     * @param archiveHash Lowercase SHA-256 archive digest.
     * @return Lowercase SHA-256(domain+LF, manifest digest, archive digest).
     */
    static String bundleDigest(byte[] manifest, String archiveHash) {
        MessageDigest hash = sha(); hash.update("bpsh-assets-v1\n".getBytes(StandardCharsets.UTF_8));
        hash.update(sha().digest(manifest)); hash.update(HexFormat.of().parseHex(archiveHash)); return hex(hash.digest());
    }

    /**
     * Normalizes the actual JVM host target without choosing an approximate browser platform.
     * @return Known normalized OS/architecture or an explicit unsupported discriminator.
     */
    public static String hostPlatform() {
        String os = System.getProperty("os.name").toLowerCase(Locale.ROOT), arch = System.getProperty("os.arch").toLowerCase(Locale.ROOT);
        return (os.startsWith("windows") ? "windows" : os.contains("mac") || os.equals("darwin") ? "macos" : os.equals("linux") ? "linux" : "unsupported")
                + "-" + (Set.of("amd64", "x86_64").contains(arch) ? "x64" : Set.of("aarch64", "arm64").contains(arch) ? "arm64" : "unsupported");
    }

    /**
     * Checks shutdown, cooperative cancellation and the caller's unchanged budget.
     * @param deadline Original monotonic deadline.
     * @param cancelled Attempt cancellation predicate.
     * @throws AuthenticationFailure If shutdown, cancelled or expired.
     */
    private void check(long deadline, BooleanSupplier cancelled) throws AuthenticationFailure {
        if (closed) throw failure(AuthenticationFailure.Cause.CLOSED, "The browser service has stopped.", "Reload the extension before starting authentication.");
        AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.SETUP, deadline, cancelled);
    }

    /**
     * Opens a required local resource with missing-JAR guidance and no installer fallback.
     * @param name Exact fixed resource name.
     * @return Owned stream to close.
     * @throws AuthenticationFailure If the platform JAR omitted a required resource.
     */
    private InputStream resource(String name) throws AuthenticationFailure {
        try { return resources.open(name); }
        catch (IOException ex) { throw failure(AuthenticationFailure.Cause.ASSET_MISSING, "The extension JAR is missing its bundled browser files.", "Rebuild or download the complete universal extension JAR, then reload it."); }
    }

    /**
     * Waits at most 250 ms between lock attempts, respecting the supplied caller or external-lock deadline.
     * @param deadline Lock acquisition deadline.
     * @param cancelled Attempt cancellation predicate.
     * @throws AuthenticationFailure If busy, cancelled, closed or interrupted.
     */
    private void pause(long deadline, BooleanSupplier cancelled) throws AuthenticationFailure {
        if (deadline - System.nanoTime() <= 0)
            throw failure(AuthenticationFailure.Cause.CACHE_BUSY, "Another browser setup is still running.", "Wait for setup to finish, then try again.");
        check(deadline, cancelled);
        try { TimeUnit.NANOSECONDS.sleep(Math.min(TimeUnit.MILLISECONDS.toNanos(250), Math.max(1, deadline - System.nanoTime()))); }
        catch (InterruptedException ex) { Thread.currentThread().interrupt(); check(deadline, () -> true); }
    }

    /**
     * Creates missing owned cache parents with private permissions and rejects named symlinks.
     * @param target Platform cache directory under the configured cache root.
     * @throws IOException If a parent is non-directory, linked or cannot be created privately.
     */
    private void makeOwnedParents(Path target) throws IOException {
        List<Path> missing = new ArrayList<>(); Path parent = target;
        while (!Files.exists(parent, NOFOLLOW)) { missing.add(parent); parent = parent.getParent(); require(parent != null, "Missing cache ancestor."); }
        require(Files.isDirectory(parent, NOFOLLOW) && !Files.isSymbolicLink(parent), "Invalid cache parent.");
        for (Path dir : missing.reversed()) {
            try { Files.createDirectory(dir, privateAttributes(dir.getParent(), true)); } catch (java.nio.file.FileAlreadyExistsException ignored) { /* concurrent setup */ }
            require(Files.isDirectory(dir, NOFOLLOW) && !Files.isSymbolicLink(dir), "Invalid cache directory.");
        }
        rejectLink(cacheRoot); rejectLink(target);
    }

    /**
     * Creates a private new file, optionally tolerating the existing sibling edit lock.
     * @param file Checked owned path.
     * @param existingAllowed Whether another setup may already have created the lock file.
     * @throws IOException On unsafe/failed creation.
     */
    private static void createPrivateFile(Path file, boolean existingAllowed) throws IOException {
        try { Files.createFile(file, privateAttributes(file.getParent(), false)); }
        catch (java.nio.file.FileAlreadyExistsException ex) { if (!existingAllowed) throw ex; require(Files.isRegularFile(file, NOFOLLOW), "Invalid lock file."); }
    }

    static FileAttribute<?>[] privateAttributes(Path parent, boolean directory) throws IOException {
        return PrivateFiles.creationAttributes(parent, directory);
    }


    static java.nio.file.attribute.UserPrincipal windowsFilePrincipal(Path path) throws IOException { return PrivateFiles.windowsFilePrincipal(path); }

    /**
     * Applies the manifest's POSIX executable/data mode where POSIX permissions exist.
     * @param file Created owned file/directory.
     * @param executable Whether executable permission is required.
     * @param directory Whether to use the directory mode.
     * @throws IOException If a supported mode cannot be applied.
     */
    private static void mode(Path file, boolean executable, boolean directory) throws IOException {
        if (Files.getFileAttributeView(file, PosixFileAttributeView.class) != null)
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString(directory || executable ? "rwxr-xr-x" : "rw-r--r--"));
    }

    /**
     * Verifies the resolved staging root remains an invocation-owned sibling before recursive cleanup/move.
     * @param parent Owned platform cache parent.
     * @param stage Candidate staging directory.
     * @param bundle Validated 64-hex identity used as its prefix.
     * @throws IOException If normalized or real-path containment fails.
     */
    private static void checkedStage(Path parent, Path stage, String bundle) throws IOException {
        require(stage.toAbsolutePath().normalize().getParent().equals(parent.toAbsolutePath().normalize())
                && stage.getFileName().toString().matches(bundle + "\\.staging-[0-9a-f-]{36}") && !Files.isSymbolicLink(stage)
                && stage.toRealPath().getParent().equals(parent.toRealPath()), "Refusing cleanup/publication outside owned staging.");
    }

    /**
     * Deletes a prechecked owned staging tree without following any links.
     * @param stage Path already checked by checkedStage; never a published cache.
     * @throws IOException If owned cleanup cannot complete.
     */
    private static void deleteOwnedTree(Path stage) throws IOException {
        Files.walkFileTree(stage, new SimpleFileVisitor<>() {
            /**
             * Deletes a leaf of the checked invocation-owned tree without following symbolic links.
             *
             * @param file Owned leaf/link.
             * @param attrs No-follow metadata.
             * @return Continue.
             * @throws IOException On deletion failure.
             */
            @Override public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException { Files.delete(file); return FileVisitResult.CONTINUE; }
            /**
             * Removes an emptied invocation-owned directory, preserving traversal failures for the caller.
             *
             * @param dir Owned directory.
             * @param ex Traversal failure, if any.
             * @return Continue.
             * @throws IOException On traversal/deletion failure.
             */
            @Override public FileVisitResult postVisitDirectory(Path dir, IOException ex) throws IOException { if (ex != null) throw ex; Files.delete(dir); return FileVisitResult.CONTINUE; }
        });
    }














    /** Classifies only typed local evidence and never echoes the underlying exception.
     * @param error Local setup failure.
     * @param safe Fixed operation description.
     * @return Safe terminal setup result.
     */
    public static AuthenticationFailure setupFailure(Exception error, String safe) {
        if (error instanceof java.nio.file.AccessDeniedException)
            return failure(AuthenticationFailure.Cause.CONFIGURATION, "Burp cannot access the bundled browser files.",
                    "Allow Burp to read, write and execute files in its browser cache.");
        if (error instanceof InvalidAsset || error instanceof java.util.zip.ZipException || error instanceof java.nio.file.NoSuchFileException)
            return failure(AuthenticationFailure.Cause.ASSET_CORRUPT, safe, "Reload the complete universal extension JAR and check the selected cache.");
        return failure(AuthenticationFailure.Cause.UNKNOWN, safe, "");
    }

    /** Stops future setup without deleting published binaries or another instance's cache. */
    @Override public void close() { closed = true; ready = null; }
    /**
     * Rejects a symbolic cache target before accessing or publishing its contents.
     *
     * @param file Named target to check.
     * @throws IOException If the named path is a symbolic link.
     */
    private static void rejectLink(Path file) throws IOException { require(!Files.isSymbolicLink(file), "Linked cache target."); }
}
