import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.compress.archivers.zip.ZipFile;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashMap;
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

/**
 * Verifies and extracts only the JAR's bundled browser assets, with no network/install fallback.
 *
 * Each extension instance fully verifies its first cache acquisition, then reuses an immutable
 * ready handle. Published caches are never repaired/deleted in place. Cancellation cleans only
 * this invocation's checked staging tree; durable binaries survive manager shutdown.
 */
public final class BrowserRuntimeManager implements AutoCloseable {
    static final String MANIFEST_RESOURCE = "META-INF/bpsh/browser-assets.json";
    static final String ARCHIVE_RESOURCE = "META-INF/bpsh/browser-assets.zip";
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
         * Returns the approved v1 extraction ceilings.
         *
         * @return The approved v1 extraction ceilings.
         */
        static Limits standard() { return new Limits(32L << 20, 2L << 30, 4L << 30, 1L << 30, 100_000, 4096, 32, 16); }
    }

    /** Describes a declared file or link; directories are derived only from declared parent paths. */
    record Entry(String path, boolean link, long bytes, String sha256, boolean executable, String target) {}

    /** Validated manifest metadata shared by extraction and full cache-hit validation. */
    record Manifest(String platform, String browserRoot, String browserExecutable, String nodeExecutable,
                    String driverEntryPoint, String archiveHash, long archiveBytes, long unpackedBytes,
                    Map<String, Entry> entries, Set<String> directories, List<String> helpers) {}

    /**
     * Holds exact verified selectors; callers must use this handle rather than PATH or host browsers.
     * Constructed only after marker, tree, hashes and permissions have been checked.
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
        private Ready(Path root, Manifest manifest, String digest) { this.root = root; this.manifest = manifest; this.digest = digest; }
        /**
         * Returns immutable published bundle directory.
         *
         * @return Immutable published bundle directory.
         */
        public Path root() { return root; }
        /**
         * Returns exact verified browser-root directory used by the owned driver environment.
         *
         * @return Exact verified browser-root directory used by the owned driver environment.
         */
        public Path browserRoot() { return root.resolve(manifest.browserRoot()); }
        /**
         * Returns exact bundled Chromium executable, never a host installation.
         *
         * @return Exact bundled Chromium executable, never a host installation.
         */
        public Path browserExecutable() { return root.resolve(manifest.browserExecutable()); }
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

    /** Fixed local preparation states; none contains browser or credential output. */
    public enum SetupStage {
        WAITING_FOR_CACHE("Waiting for browser setup..."),
        VERIFYING_CACHE("Verifying bundled browser files..."),
        EXTRACTING_BROWSER("Extracting bundled browser files..."),
        STARTING_DRIVER("Starting the browser driver..."),
        STARTING_BROWSER("Starting Chromium..."),
        AUTHENTICATING("Signing in...");
        private final String description;
        /** @param description Fixed safe display/event text. */
        SetupStage(String description) { this.description = description; }
        /** @return Fixed safe display/event text. */
        public String description() { return description; }
    }

    /** Reports fixed metadata without allowing presentation failures to change an attempt.
     * @param observer Attempt-local callback.
     * @param stage Actual setup operation.
     */
    static void observed(Consumer<SetupStage> observer, SetupStage stage) {
        try { observer.accept(stage); } catch (RuntimeException ignored) { /* cleanup and policy are independent */ }
    }

    /** Distinguishes a proved asset invariant failure from unrelated filesystem I/O. */
    private static final class InvalidAsset extends IOException {
        private static final long serialVersionUID = 1L;
        /** @param message Internal invariant description, never forwarded as raw output. */
        InvalidAsset(String message) { super(message); }
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
        }, Path.of(System.getProperty("user.home"), ".bpsh", "cache"), hostPlatform(), Limits.standard(),
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

    /** Rejects unsupported JVM targets before any resource or cache access.
     * @param target Normalized JVM OS/CPU target.
     * @throws AuthenticationFailure When the target has no bundled payload.
     */
    private static void requireSupportedPlatform(String target) throws AuthenticationFailure {
        if (!Set.of("windows-x64", "linux-x64", "macos-x64").contains(target))
            throw failure(AuthenticationFailure.Cause.UNSUPPORTED_PLATFORM,
                    "Bundled Chromium does not support " + target + ".",
                    "Supported targets: Windows x64, Linux x64 and Intel macOS. Use a supported JVM and operating system.");
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
    public Ready acquire(long deadlineNanos, BooleanSupplier cancelled, Consumer<SetupStage> observer) throws AuthenticationFailure {
        requireSupportedPlatform(platform);
        check(deadlineNanos, cancelled);
        if (ready != null) return ready;
        long lockDeadline = Math.min(deadlineNanos, System.nanoTime() + TimeUnit.SECONDS.toNanos(10));
        boolean held = false, waitedForSetup = false;
        try {
            while (!(held = setup.tryLock())) { if (!waitedForSetup) { observed(observer, SetupStage.WAITING_FOR_CACHE); waitedForSetup = true; } pause(lockDeadline, cancelled); }
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
                FileLock fileLock = null; boolean waited = false;
                while (fileLock == null) {
                    if (waited && lockDeadline - System.nanoTime() <= 0) pause(lockDeadline, cancelled);
                    check(deadlineNanos, cancelled);
                    try { fileLock = channel.tryLock(); } catch (OverlappingFileLockException ignored) { /* busy in this JVM */ }
                    if (fileLock == null) { if (!waited) observed(observer, SetupStage.WAITING_FOR_CACHE); waited = true; pause(lockDeadline, cancelled); }
                }
                try (FileLock ownedLock = fileLock) {
                    if (Files.exists(destination, NOFOLLOW)) {
                        observed(observer, SetupStage.VERIFYING_CACHE);
                        verifyPublished(destination, manifest, bundle, manifestHash, deadlineNanos, cancelled);
                    } else {
                        observed(observer, SetupStage.EXTRACTING_BROWSER);
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
     * Parses a strict manifest and validates selectors, declared tree and overflow-safe size totals.
     * @param raw Exact UTF-8 bytes used to derive the bundle identity.
     * @param expectedPlatform Exact normalized current target.
     * @param limits Approved or lowered test ceilings.
     * @return Fully checked manifest; no filesystem or browser calls occur.
     * @throws AuthenticationFailure If syntax, version, platform, fields or tree semantics are invalid.
     */
    static Manifest parseManifest(byte[] raw, String expectedPlatform, Limits limits) throws AuthenticationFailure {
        try {
            requireSupportedPlatform(expectedPlatform);
            require(raw.length <= limits.manifestBytes, "Manifest exceeds its size ceiling.");
            JsonNode n = JSON.readTree(utf8(raw));
            object(n, "formatVersion", "platform", "playwrightJavaVersion", "browserName", "browserVersion", "browserRevision",
                    "driverPackageVersion", "nodeVersion", "browserRoot", "browserExecutable", "nodeExecutable", "driverEntryPoint", "helpers",
                    "archive", "unpackedBytes", "entries");
            number(n.get("formatVersion"), 1, 1);
            if (!text(n, "platform").equals(expectedPlatform))
                throw failure(AuthenticationFailure.Cause.UNSUPPORTED_PLATFORM, "This browser bundle was built for a different operating system or processor architecture.", "Reload the complete universal extension JAR.");
            require(text(n, "playwrightJavaVersion").equals("1.64.0") && text(n, "browserName").equals("chromium"), "Unsupported bundled runtime version.");
            text(n, "browserVersion"); text(n, "driverPackageVersion"); text(n, "nodeVersion");
            require(text(n, "browserRevision").matches("[0-9]+"), "Invalid browser revision.");
            String browserRoot = path(text(n, "browserRoot"), limits), browser = path(text(n, "browserExecutable"), limits);
            String node = path(text(n, "nodeExecutable"), limits), driver = path(text(n, "driverEntryPoint"), limits);
            JsonNode archive = n.get("archive"); object(archive, "resource", "sha256", "bytes");
            require(text(archive, "resource").equals(platformResource(ARCHIVE_RESOURCE, expectedPlatform)), "Unexpected archive resource.");
            String archiveHash = hashText(text(archive, "sha256")); long archiveBytes = number(archive.get("bytes"), 1, limits.zipBytes);
            long declaredTotal = number(n.get("unpackedBytes"), 0, limits.totalBytes), sum = 0;
            Map<String, Entry> entries = new HashMap<>(); Map<String, String> filesystemNames = new HashMap<>();
            Set<String> directories = new HashSet<>();
            JsonNode rows = n.get("entries"); require(rows != null && rows.isArray() && rows.size() <= limits.entries, "Invalid entry list.");
            for (JsonNode row : rows) {
                String type = text(row, "type"), name = path(text(row, "path"), limits); Entry entry;
                if (type.equals("file")) {
                    object(row, "path", "type", "bytes", "sha256", "executable");
                    require(row.get("executable").isBoolean(), "Executable mode must be boolean.");
                    long bytes = number(row.get("bytes"), 0, limits.fileBytes); sum = Math.addExact(sum, bytes);
                    require(sum <= limits.totalBytes, "Expanded size exceeds its ceiling.");
                    entry = new Entry(name, false, bytes, hashText(text(row, "sha256")), row.get("executable").booleanValue(), null);
                } else if (type.equals("symlink")) {
                    object(row, "path", "type", "target"); String target = text(row, "target");
                    relativeTarget(name, target, limits);
                    entry = new Entry(name, true, 0, null, false, target);
                } else throw new IOException("Unsupported entry type.");
                require(entries.put(name, entry) == null, "Duplicate entry.");
                String[] components = name.split("/"); String prefix = "";
                for (int i = 0; i < components.length; i++) {
                    if (expectedPlatform.startsWith("windows-"))
                        require(!components[i].matches("(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\\..*)?")
                                && !components[i].endsWith(".") && !components[i].endsWith(" ")
                                && !components[i].matches(".*[<>\"|?*].*"), "Unsafe Windows path component.");
                    prefix = prefix.isEmpty() ? components[i] : prefix + "/" + components[i];
                    String key = expectedPlatform.startsWith("windows-") || expectedPlatform.startsWith("macos-") ? prefix.toLowerCase(Locale.ROOT) : prefix;
                    String previous = filesystemNames.putIfAbsent(key, prefix);
                    require(previous == null || previous.equals(prefix), "Target-filesystem name collision.");
                    if (i < components.length - 1) directories.add(prefix);
                }
            }
            require(sum == declaredTotal, "Expanded byte sum mismatch.");
            for (String dir : directories) require(!entries.containsKey(dir), "File/link conflicts with a directory.");
            for (Entry e : entries.values()) if (e.link()) resolve(e.path(), entries, directories, limits);
            require(directories.contains(resolve(browserRoot, entries, directories, limits)), "Browser root is not a directory.");
            for (String selector : List.of(browser, node, driver)) {
                Entry e = entries.get(resolve(selector, entries, directories, limits));
                require(e != null && !e.link(), "Executable/driver selector is not a regular file.");
                if (!selector.equals(driver)) require(e.executable(), "Executable selector lacks executable mode.");
            }
            require(n.get("helpers").isArray(), "Invalid helper list.");
            List<String> helpers = new ArrayList<>(); Set<String> helperNames = new HashSet<>();
            for (JsonNode helper : n.get("helpers")) {
                object(helper, "name", "revision", "path"); require(helperNames.add(text(helper, "name")), "Duplicate helper.");
                require(text(helper, "revision").matches("[0-9]+"), "Invalid helper revision.");
                String value = path(text(helper, "path"), limits); resolve(value, entries, directories, limits); helpers.add(value);
            }
            return new Manifest(expectedPlatform, browserRoot, browser, node, driver, archiveHash, archiveBytes, sum,
                    Map.copyOf(entries), Set.copyOf(directories), List.copyOf(helpers));
        } catch (AuthenticationFailure ex) { throw ex; }
        catch (Exception ex) {
            throw failure(AuthenticationFailure.Cause.ASSET_CORRUPT, "The bundled browser configuration is invalid.",
                    "Rebuild or download the complete universal extension JAR, then reload it.");
        }
    }

    /**
     * Copies/verifies the full ZIP before extraction, then publishes only a complete validated tree.
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
            if (usable > 0 && usable < manifest.archiveBytes() + manifest.unpackedBytes())
                throw failure(AuthenticationFailure.Cause.CONFIGURATION, "There is not enough free space to prepare the bundled browser.",
                        "Free space for the selected archive and extracted browser, then try again.");
        } catch (IOException | UnsupportedOperationException | SecurityException ignored) { /* no positive space evidence */ }
        Path stage = parent.resolve(bundle + ".staging-" + UUID.randomUUID());
        Path archive = parent.resolve(bundle + ".archive-" + UUID.randomUUID() + ".zip");
        Files.createDirectory(stage, privateAttributes(parent, true));
        try {
            createPrivateFile(archive, false);
            try (InputStream input = resource(platformResource(ARCHIVE_RESOURCE, platform)); var out = Files.newOutputStream(archive)) {
                MessageDigest digest = sha(); byte[] buffer = new byte[65536]; long bytes = 0;
                for (int count; (count = input.read(buffer)) >= 0;) {
                    check(deadline, cancelled); bytes += count;
                    require(bytes <= manifest.archiveBytes(), "Archive exceeds declared size."); digest.update(buffer, 0, count); out.write(buffer, 0, count);
                }
                require(bytes == manifest.archiveBytes() && hex(digest.digest()).equals(manifest.archiveHash()), "Archive digest/size mismatch.");
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
            publisher.publish(stage, destination);
        } finally {
            Files.deleteIfExists(archive);
            if (Files.exists(stage, NOFOLLOW)) { checkedStage(parent, stage, bundle); deleteOwnedTree(stage); }
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
     * Resolves declared links, including links in selector ancestors, with bounded cycle detection.
     * @param value Declared path/selector to resolve.
     * @param entries Declared nondirectory records.
     * @param directories Implicit parent directories.
     * @param limits Link hop and path ceilings.
     * @return Existing final file or implicit-directory path within the bundle.
     * @throws IOException If dangling, cyclic, escaping or over the hop limit.
     */
    private static String resolve(String value, Map<String, Entry> entries, Set<String> directories, Limits limits) throws IOException {
        Set<String> visited = new HashSet<>(); int hops = 0;
        while (true) {
            require(visited.add(value), "Cyclic link chain."); String[] parts = value.split("/"); String prefix = ""; boolean changed = false;
            for (int i = 0; i < parts.length; i++) {
                prefix = prefix.isEmpty() ? parts[i] : prefix + "/" + parts[i]; Entry entry = entries.get(prefix);
                if (entry != null && entry.link()) {
                    require(++hops <= limits.linkHops, "Link chain exceeds its ceiling.");
                    String resolved = relativeTarget(prefix, entry.target(), limits);
                    if (i + 1 < parts.length) resolved += "/" + String.join("/", Arrays.copyOfRange(parts, i + 1, parts.length));
                    value = path(resolved, limits); changed = true; break;
                }
            }
            if (!changed) { require(entries.containsKey(value) || directories.contains(value), "Dangling selector/link."); return value; }
        }
    }

    /**
     * Resolves a relative link payload lexically, permitting dot/parent only within the bundle.
     * @param link Bundle-relative link path.
     * @param target Relative UTF-8 payload without drive/backslash/absolute forms.
     * @param limits Target-byte/path ceilings.
     * @return Normalized contained destination.
     * @throws IOException If the link escapes or its representation is invalid.
     */
    private static String relativeTarget(String link, String target, Limits limits) throws IOException {
        require(!target.isEmpty() && target.getBytes(StandardCharsets.UTF_8).length <= limits.pathBytes && !target.startsWith("/")
                && !target.contains("\\") && !target.contains(":") && !target.contains("\0"), "Invalid link target.");
        ArrayDeque<String> stack = new ArrayDeque<>(); int slash = link.lastIndexOf('/');
        if (slash >= 0) stack.addAll(List.of(link.substring(0, slash).split("/")));
        for (String component : target.split("/", -1)) {
            require(!component.isEmpty(), "Empty link component.");
            if (component.equals("..")) { require(!stack.isEmpty(), "Escaping link."); stack.removeLast(); }
            else if (!component.equals(".")) stack.addLast(component);
        }
        require(!stack.isEmpty(), "Link targets bundle root."); return path(String.join("/", stack), limits);
    }

    /**
     * Validates safe relative member/selector syntax before any path is written.
     * @param value Relative POSIX path, without trailing directory slash.
     * @param limits UTF-8 byte and component ceilings.
     * @return Unchanged validated spelling.
     * @throws IOException If absolute, reserved, traversal-shaped or too long/deep.
     */
    private static String path(String value, Limits limits) throws IOException {
        require(!value.isEmpty() && !value.startsWith("/") && !value.contains("\\") && !value.contains(":") && !value.contains("\0")
                && value.getBytes(StandardCharsets.UTF_8).length <= limits.pathBytes, "Invalid relative asset path.");
        String[] parts = value.split("/", -1); require(parts.length <= limits.depth && !parts[0].equals(".complete.json"), "Reserved/deep asset path.");
        for (String part : parts) require(!part.isEmpty() && !part.equals(".") && !part.equals(".."), "Unsafe asset path component.");
        return value;
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
    static String hostPlatform() {
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
     * Waits at most 250 ms between lock attempts, respecting the shorter ten-second/caller deadline.
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

    /**
     * Supplies creation-time user-only permissions before extracted data receives its final POSIX mode.
     * @param parent Existing owned parent determining supported attribute views.
     * @param directory Whether private directory permissions are required.
     * @return Initial POSIX mode or current-user ACL.
     * @throws IOException If restricted creation is unavailable.
     */
    static FileAttribute<?>[] privateAttributes(Path parent, boolean directory) throws IOException {
        if (Files.getFileAttributeView(parent, PosixFileAttributeView.class) != null)
            return new FileAttribute<?>[]{PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString(directory ? "rwx------" : "rw-------"))};
        if (Files.getFileAttributeView(parent, AclFileAttributeView.class) != null) {
            var user = windowsFilePrincipal(parent);
            var entry = AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(user).setPermissions(EnumSet.allOf(AclEntryPermission.class));
            if (directory) entry.setFlags(AclEntryFlag.DIRECTORY_INHERIT, AclEntryFlag.FILE_INHERIT);
            var acl = List.of(entry.build());
            return new FileAttribute<?>[]{new FileAttribute<List<AclEntry>>() {
                /**
                 * Identifies the ACL attribute applied atomically when an owned path is created.
                 *
                 * @return ACL creation attribute name.
                 */
                public String name() { return "acl:acl"; }
                /**
                 * Returns current-user-only allow entries.
                 *
                 * @return Current-user-only allow entries.
                 */
                public List<AclEntry> value() { return acl; }
            }};
        }
        throw new IOException("Private cache permissions unsupported.");
    }

    /**
     * Resolves the actual Windows account instead of the host's mutable user.name system property.
     * @param path Existing ACL-capable filesystem path.
     * @return Qualified operating-system principal used for private file creation.
     * @throws IOException If native account lookup is unavailable; never grants a broader fallback ACL.
     */
    static java.nio.file.attribute.UserPrincipal windowsFilePrincipal(Path path) throws IOException {
        try {
            var account = new com.sun.security.auth.module.NTSystem(); String name = account.getName(), domain = account.getDomain();
            if (name == null || name.isBlank()) throw new IOException("Windows account lookup returned no user.");
            String qualified = domain == null || domain.isBlank() ? name : domain + "\\" + name;
            return path.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName(qualified);
        } catch (LinkageError | SecurityException error) { throw new IOException("Windows account lookup is unavailable."); }
    }

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

    /**
     * Rejects a symbolic cache target before accessing or publishing its contents.
     *
     * @param file Named target to check.
     * @throws IOException If the named path is a symbolic link.
     */
    private static void rejectLink(Path file) throws IOException { require(!Files.isSymbolicLink(file), "Linked cache target."); }
    /**
     * Reads a small resource with an inclusive byte ceiling before allocating an unbounded byte array.
     *
     * @param input Owned input managed by the caller.
     * @param max Inclusive byte ceiling.
     * @return Bounded bytes.
     * @throws IOException On overflow/read failure.
     */
    private static byte[] bounded(InputStream input, long max) throws IOException {
        byte[] bytes = input.readNBytes((int) Math.min(Integer.MAX_VALUE, max + 1)); require(bytes.length <= max, "Resource exceeds byte ceiling."); return bytes;
    }
    /**
     * Decodes metadata strictly so malformed UTF-8 cannot silently change a manifest path or field.
     *
     * @param bytes UTF-8 representation.
     * @return Strictly decoded text.
     * @throws IOException On malformed encoding.
     */
    private static String utf8(byte[] bytes) throws IOException { return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString(); }
    /**
     * Returns required SHA-256 primitive; no global provider configuration changes occur.
     *
     * @return Required SHA-256 primitive; no global provider configuration changes occur.
     */
    private static MessageDigest sha() { try { return MessageDigest.getInstance("SHA-256"); } catch (Exception ex) { throw new IllegalStateException("SHA-256 unavailable."); } }
    /**
     * Hashes exact input bytes using SHA-256 for manifest, archive or cache identity checks.
     *
     * @param bytes Exact source bytes.
     * @return Lowercase SHA-256.
     */
    private static String digest(byte[] bytes) { return hex(sha().digest(bytes)); }
    /**
     * Formats digest bytes in the lowercase representation required by the asset contract.
     *
     * @param bytes Digest bytes.
     * @return Lowercase hex.
     */
    private static String hex(byte[] bytes) { return HexFormat.of().formatHex(bytes); }
    /**
     * Rejects noncanonical SHA-256 text before comparing integrity metadata.
     *
     * @param value Candidate lowercase SHA-256.
     * @return Unchanged valid text.
     * @throws IOException If malformed.
     */
    private static String hashText(String value) throws IOException { require(value.matches("[0-9a-f]{64}"), "Invalid SHA-256."); return value; }
    /**
     * Requires an object with the exact declared fields, rejecting omissions and unknown keys.
     *
     * @param n Candidate object.
     * @param fields Exact required field set.
     * @throws IOException On unknown/missing/type failure.
     */
    private static void object(JsonNode n, String... fields) throws IOException {
        require(n != null && n.isObject() && n.size() == fields.length, "Invalid object fields.");
        for (String field : fields) require(n.has(field), "Missing required field.");
    }
    /**
     * Reads a required nonblank string without coercing other JSON value types.
     *
     * @param n Containing object.
     * @param field Known string field.
     * @return Nonblank exact text.
     * @throws IOException On type/content failure.
     */
    private static String text(JsonNode n, String field) throws IOException { JsonNode v = n == null ? null : n.get(field); require(v != null && v.isTextual() && !v.textValue().isBlank(), "Expected string."); return v.textValue(); }
    /**
     * Reads an integral JSON number inside the declared inclusive bounds without numeric coercion.
     *
     * @param n Number node.
     * @param min Inclusive minimum.
     * @param max Inclusive maximum.
     * @return Strict long.
     * @throws IOException On invalid type/range.
     */
    private static long number(JsonNode n, long min, long max) throws IOException { require(n != null && n.isIntegralNumber() && n.canConvertToLong() && n.longValue() >= min && n.longValue() <= max, "Invalid integer."); return n.longValue(); }
    /**
     * Rejects a failed asset invariant with a safe symbolic explanation.
     *
     * @param condition Required invariant.
     * @param safe Safe symbolic detail.
     * @throws IOException If invariant fails.
     */
    private static void require(boolean condition, String safe) throws IOException { if (!condition) throw new InvalidAsset(safe); }
    /**
     * Builds a typed failure with operator recovery guidance and no raw exception cause.
     *
     * @param reason Typed setup category.
     * @param safe Safe problem text.
     * @param recovery Concrete correction.
     * @return Redacted setup exception.
     */
    private static AuthenticationFailure failure(AuthenticationFailure.Cause reason, String safe, String recovery) { return new AuthenticationFailure(AuthenticationFailure.Phase.SETUP, reason, safe, recovery); }

    /** Classifies only typed local evidence and never echoes the underlying exception.
     * @param error Local setup failure.
     * @param safe Fixed operation description.
     * @return Safe terminal setup result.
     */
    static AuthenticationFailure setupFailure(Exception error, String safe) {
        if (error instanceof java.nio.file.AccessDeniedException)
            return failure(AuthenticationFailure.Cause.CONFIGURATION, "Burp cannot access the bundled browser files.",
                    "Allow Burp to read, write and execute files in its browser cache.");
        if (error instanceof InvalidAsset || error instanceof java.util.zip.ZipException || error instanceof java.nio.file.NoSuchFileException)
            return failure(AuthenticationFailure.Cause.ASSET_CORRUPT, safe, "Reload the complete universal extension JAR and check the selected cache.");
        return failure(AuthenticationFailure.Cause.UNKNOWN, safe, "");
    }

    /** Stops future setup without deleting published binaries or another instance's cache. */
    @Override public void close() { closed = true; ready = null; }
}
