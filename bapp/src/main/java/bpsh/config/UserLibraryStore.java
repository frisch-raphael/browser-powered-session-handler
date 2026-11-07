package bpsh.config;

import bpsh.io.PrivateFiles;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Persists the native user library with locked compare-and-swap saves and atomic replacement.
 *
 * Writes compare both revision and exact-byte hash under a separate lock, force temporary files,
 * and prepare a redacted previous-version backup before replacing the primary. Corrupt data is
 * preserved for explicit repair, never silently reset. Newly created files/directories receive
 * user-restricted permissions where supported; this does not encrypt remembered secrets.
 *
 * File operations and watcher callbacks belong off Swing's EDT. Close stops observation; callers
 * must also close each Loaded result because the store does not own returned secret snapshots.
 */
public final class UserLibraryStore implements AutoCloseable {
    /**
     * Captures the disk state an editor must present when committing its changes.
     *
     * The byte hash detects manual edits even if someone kept the same JSON revision. Both fields
     * are null only for the absent-file sentinel; this value is not a token generation.
     *
     * @param revision Persisted envelope revision, or null for an absent file.
     * @param sha256 SHA-256 of exact file bytes, or null for an absent file.
     */
    public record Version(UUID revision, String sha256) {
        /**
         * Represents a library file that did not exist when the edit began.
         *
         * @return The expected version for a first save; an empty existing library still has a real version.
         */
        public static Version absent() { return new Version(null, null); }
    }
    /**
     * Pairs a caller-owned document with the disk version used for conflict checking.
     *
     * A load contains only persisted secrets. A successful save returns the committed session
     * snapshot, which may retain unremembered values that were intentionally omitted from disk.
     *
     * @param document Owned document; close this result after transferring/copying its values.
     * @param version Exact persisted state to capture for a later edit.
     */
    public record Loaded(ConfigManager.NativeDocument document, Version version) implements AutoCloseable {
        /**
         * Closes the document's owned secret snapshots; repeated closes are harmless.
         */
        @Override public void close() { document.close(); }
    }
    /**
     * Reports a library failure with its path and explicit repair/reload guidance.
     *
     * Messages must not expose raw JSON or credential-bearing parser causes.
     */
    public static final class LibraryException extends IOException {
        /**
         * Builds a recovery message from a safe reason without attaching raw exception causes.
         *
         * @param path Library path needed to locate the file and its redacted backup.
         * @param reason Safe explanation supplied by the storage layer, never raw secret-bearing text.
         */
        LibraryException(Path path, String reason) {
            this(path, reason, "");
        }
        /** @param path Library path. @param reason Classified safe problem. @param recovery Confirmed action, or empty when the remedy is unknown. */
        LibraryException(Path path, String reason, String recovery) { super("Library " + path + ": " + reason + "." + (recovery.isBlank() ? "" : " " + recovery)); }
    }
    /**
     * Provides the atomic-replacement boundary used by production saves and failure-injection tests.
     *
     * Implementations must replace the target atomically or throw; they must not fall back to a
     * non-atomic overwrite.
     */
    @FunctionalInterface interface AtomicMover {
        /**
         * Publishes a completed temporary file with atomic replacement semantics.
         *
         * @param source Completed temporary sibling owned by the save operation.
         * @param target Primary or backup destination to replace.
         * @throws IOException If replacement cannot be completed atomically.
         */
        void move(Path source, Path target) throws IOException;
    }
    /**
     * Keeps primary, owned directory and sibling lock/redacted-backup paths together after normalization.
     */
    private final Path file, directory, lockFile, backup;
    /**
     * Injects atomic replacement so tests can fail backup/primary publication without a non-atomic fallback.
     */
    private final AtomicMover mover;
    /**
     * Bounds edit-lock waiting using elapsed monotonic time, never wall-clock timestamps.
     */
    private final long lockTimeoutNanos;
    /**
     * Owns at most one daemon polling task; created by watch and stopped by close.
     */
    private ScheduledExecutorService watcher;
    /**
     * Makes shutdown visible to pending lock acquisition, polling and failure reporting.
     */
    private volatile boolean closed;
    /**
     * Identifies this instance's last successful save so observation cannot overwrite its session-only secrets.
     */
    private volatile Version writtenVersion;

    /**
     * Selects user.home/.bpsh/library-v3.json without creating files or starting a watcher.
     */
    public UserLibraryStore() {
        this(Path.of(System.getProperty("user.home"), ".bpsh", "library-v3.json"));
    }
    /**
     * Selects a library path with the production two-second lock deadline.
     *
     * @param file Primary library path, normalized to an absolute path without creating it.
     */
    public UserLibraryStore(Path file) { this(file, Duration.ofSeconds(2), UserLibraryStore::atomicMove); }
    /**
     * Configures the storage boundary for deterministic lock and replacement-failure tests.
     *
     * @param file Primary library path; its sibling lock has the fixed library-v1.lock name.
     * @param lockTimeout Positive edit-lock wait, at most two seconds.
     * @param mover Atomic replacement implementation; production uses Files.move with ATOMIC_MOVE.
     * @throws IllegalArgumentException If the requested lock timeout is outside the allowed range.
     */
    UserLibraryStore(Path file, Duration lockTimeout, AtomicMover mover) {
        this.file = file.toAbsolutePath().normalize(); this.directory = this.file.getParent();
        this.lockFile = directory.resolve("library-v1.lock"); this.backup = directory.resolve(this.file.getFileName() + ".bak");
        this.mover = Objects.requireNonNull(mover); this.lockTimeoutNanos = lockTimeout.toNanos();
        if (lockTimeoutNanos <= 0 || lockTimeoutNanos > Duration.ofSeconds(2).toNanos()) throw new IllegalArgumentException("Invalid library lock timeout.");
    }
    /**
     * Exposes the normalized primary path for configuration and recovery messages.
     *
     * @return Absolute primary library path; this call does not read the file.
     */
    public Path path() { return file; }
    /**
     * Rejects new file/watcher operations after shutdown.
     *
     * @throws IOException If close has already stopped this store.
     */
    private void checkOpen() throws IOException { if (closed) throw new IOException("Library store is closed."); }
    /**
     * Reads and validates a strict UTF-8 native library without acquiring the edit lock.
     *
     * An absent file yields an empty document plus Version.absent, not a write. Existing malformed,
     * unsupported or unreadable data raises recovery guidance and remains untouched. The hash is
     * computed from the same bytes that were parsed, rather than a reserialization.
     *
     * @return Caller-owned result containing persisted values only; close it after use.
     * @throws IOException If closed, unreadable, malformed, unsupported or a symbolic-link target.
     */
    public Loaded load() throws IOException {
        checkOpen();
        try {
            rejectLink(file);
            if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS))
                return new Loaded(ConfigManager.NativeDocument.empty(ConfigManager.DocumentKind.LIBRARY), Version.absent());
            byte[] bytes = Files.readAllBytes(file);
            String json = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
            ConfigManager.NativeDocument document = ConfigManager.parseNative(json, ConfigManager.DocumentKind.LIBRARY);
            return new Loaded(document, new Version(document.revision(), sha256(bytes)));
        } catch (IOException | IllegalArgumentException ex) {
            // Never attach raw parser/IO causes that might contain JSON or credentials.
            throw new LibraryException(file, "cannot read the saved journey library");
        }
    }

    /**
     * Commits a full library edit only if the captured disk version still matches under lock.
     *
     * The separate file lock serializes cooperating writers. The primary is reread and validated;
     * conflicts require reload/reapplication. A forced, redacted backup is replaced before the
     * primary, and failure has no unlocked/non-atomic fallback. The caller retains the edited
     * snapshot and publishes the returned session snapshot only after this method succeeds.
     *
     * The result deliberately retains session-only values in memory even when its on-disk bytes
     * omit them. Capture expected before the edit/preview, not immediately before saving.
     *
     * @param edited Validated library document; caller retains and closes it separately.
     * @param expected Revision and exact-byte hash captured when editing began, or Version.absent.
     * @return Independently owned committed document and its new disk version; caller closes it.
     * @throws IllegalArgumentException If the document has the wrong kind or fails native validation.
     * @throws IOException If closed, stale, corrupt, lock-busy, interrupted or unable to save atomically.
     */
    public Loaded save(ConfigManager.NativeDocument edited, Version expected) throws IOException {
        checkOpen();
        if (edited.kind() != ConfigManager.DocumentKind.LIBRARY) throw new IllegalArgumentException("Only library documents can be saved here.");
        Objects.requireNonNull(expected);
        ensureDirectory(); rejectLink(file); rejectLink(lockFile); rejectLink(backup);
        createPrivateIfAbsent(lockFile, false);
        try (FileChannel channel = FileChannel.open(lockFile, StandardOpenOption.WRITE)) {
            FileLock lock = acquireLock(channel);
            try (lock; Loaded current = load()) {
                checkOpen();
                if (!current.version().equals(expected)) throw new LibraryException(file, "changed since this edit; reload and reapply it");
                try (ConfigManager.NativeDocument next = edited.withRevision(UUID.randomUUID())) {
                    byte[] bytes = ConfigManager.nativeToJson(next).getBytes(StandardCharsets.UTF_8);
                    if (!current.version().equals(Version.absent())) {
                        byte[] redacted = ConfigManager.nativeToJson(current.document().redacted()).getBytes(StandardCharsets.UTF_8);
                        replace(backup, redacted); // Must succeed before primary replacement.
                    }
                    synchronized (this) {
                        replace(file, bytes);
                        writtenVersion = new Version(next.revision(), sha256(bytes));
                    }
                    return new Loaded(next.withRevision(next.revision()), new Version(next.revision(), sha256(bytes)));
                }
            }
        } catch (LibraryException ex) { throw ex; }
        catch (IOException ex) { throw writeFailure("open or close the library edit lock", ex); }
    }

    /**
     * Waits within the configured deadline for the separate edit-file lock.
     *
     * Same-JVM overlap is treated as busy. Polling sleeps for 50 ms; interruption restores the
     * thread's interrupted status and returns a safe failure instead of bypassing the lock.
     *
     * @param channel Open writable lock-file channel, owned by the calling save operation.
     * @return Acquired lock that the caller releases with its channel in a finally/resource scope.
     * @throws IOException If the deadline expires, the store closes or acquisition is interrupted/fails.
     */
    private FileLock acquireLock(FileChannel channel) throws IOException {
        long start = System.nanoTime();
        while (!closed && System.nanoTime() - start < lockTimeoutNanos) {
            try { FileLock lock = channel.tryLock(); if (lock != null) return lock; }
            catch (OverlappingFileLockException ignored) { /* another editor in this JVM */ }
            try { TimeUnit.MILLISECONDS.sleep(50); }
            catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new LibraryException(file, "save interrupted while waiting for the edit lock"); }
        }
        throw new LibraryException(file, "edit lock is busy; wait for the other writer and retry");
    }
    /**
     * Forces a private temporary sibling and atomically replaces one destination.
     *
     * Only this invocation's uniquely named temporary file is removed on exit. A failed move has no
     * in-place overwrite fallback; the caller decides whether the destination is primary or backup.
     *
     * @param destination Primary or redacted-backup path in the library directory.
     * @param bytes Complete UTF-8 representation to write; this method does not mutate the array.
     * @throws IOException If creation, forcing, link checking, replacement or temporary cleanup fails.
     */
    private void replace(Path destination, byte[] bytes) throws IOException {
        Path temp = directory.resolve(".bpsh-write-" + UUID.randomUUID() + ".tmp");
        String operation = "create the temporary library file";
        try {
            Files.createFile(temp, privateAttributes(temp, false));
            operation = "write and flush the temporary library file";
            try (FileChannel channel = FileChannel.open(temp, StandardOpenOption.WRITE)) {
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                while (buffer.hasRemaining()) channel.write(buffer);
                channel.force(true);
            }
            rejectLink(destination);
            operation = destination.equals(backup) ? "replace the library backup" : "replace the saved library file";
            mover.move(temp, destination);
        } catch (IOException error) {
            throw writeFailure(operation, error);
        } finally { Files.deleteIfExists(temp); }
    }
    /** @param operation Fixed storage-stage description. @param error OS exception whose raw text is never exposed. @return Safe guidance that preserves the primary and distinguishes write failures from corrupt data. */
    private LibraryException writeFailure(String operation, IOException error) {
        String kind = error instanceof java.nio.file.AccessDeniedException ? "access denied" : error instanceof java.nio.file.AtomicMoveNotSupportedException ? "atomic replacement unsupported" : error.getClass().getSimpleName();
        String recovery = error instanceof java.nio.file.AtomicMoveNotSupportedException
                ? "Use a local filesystem that supports atomic file replacement, then retry."
                : error instanceof java.nio.file.AccessDeniedException ? "Allow this Burp process to write to its library directory, then retry."
                : "";
        return new LibraryException(file, "could not " + operation + " (" + kind + "); the previous library is preserved", recovery);
    }
    /**
     * Replaces a destination using filesystem atomic-move support, with no copy fallback.
     *
     * @param source Completed temporary sibling to publish.
     * @param target Primary or backup destination.
     * @throws IOException If atomic replacement is unsupported or cannot complete.
     */
    private static void atomicMove(Path source, Path target) throws IOException {
        Files.move(source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }
    /**
     * Creates the single owned library directory with restricted permissions if absent.
     *
     * The parent must already exist. Existing directory permissions are not rewritten; symbolic
     * links and non-directory targets are rejected.
     *
     * @throws IOException If the parent is missing or directory creation/validation fails.
     */
    private void ensureDirectory() throws IOException {
        if (!Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
            Path parent = directory.getParent();
            if (parent == null || !Files.isDirectory(parent)) throw new LibraryException(file, "library parent directory does not exist");
            try { Files.createDirectory(directory, privateAttributes(directory, true)); }
            catch (java.nio.file.FileAlreadyExistsException ignored) { /* concurrent creator */ }
        }
        rejectLink(directory);
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) throw new LibraryException(file, "library directory is unavailable");
    }
    /**
     * Rejects a symbolic-link target before library reads or writes.
     *
     * This checks the named path itself, not every ancestor, and is not a filesystem race guarantee.
     *
     * @param path Primary, backup, lock or owned directory path to check.
     * @throws IOException If the path is currently a symbolic link.
     */
    private static void rejectLink(Path path) throws IOException {
        if (Files.isSymbolicLink(path)) throw new IOException("Library paths cannot be symbolic links.");
    }
    /**
     * Creates a restricted file without truncating an existing cooperating writer's lock.
     *
     * @param path File to create if absent.
     * @param directory Permission-mode selector passed to privateAttributes; false for the edit lock.
     * @throws IOException If file creation or permission lookup fails for a reason other than existence.
     */
    private static void createPrivateIfAbsent(Path path, boolean directory) throws IOException {
        try { Files.createFile(path, privateAttributes(path, directory)); }
        catch (java.nio.file.FileAlreadyExistsException ignored) { /* never truncate a lock file */ }
    }
    /**
     * Builds creation-time permissions for owned library files or directories.
     *
     * POSIX targets use 0600/0700. ACL targets grant the current user the permissions needed to manage
     * the created object. Unsupported filesystems fail instead of silently creating public files;
     * existing objects are not audited or changed by this helper.
     *
     * @param path New target whose existing parent determines supported attribute views.
     * @param directory Whether directory-style POSIX permissions are required.
     * @return Attributes to apply atomically during creation.
     * @throws IOException If restricted creation is unsupported or the current principal cannot be resolved.
     */
    private static FileAttribute<?>[] privateAttributes(Path path, boolean directory) throws IOException {
        Path existing = path.getParent();
        if (Files.getFileAttributeView(existing, PosixFileAttributeView.class) != null)
            return new FileAttribute<?>[] { PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString(directory ? "rwx------" : "rw-------")) };
        if (Files.getFileAttributeView(existing, AclFileAttributeView.class) != null) {
            var user = PrivateFiles.windowsFilePrincipal(existing);
            AclEntry entry = AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(user)
                    .setPermissions(EnumSet.allOf(AclEntryPermission.class)).build();
            return new FileAttribute<?>[] { new FileAttribute<List<AclEntry>>() {
                /**
                 * Selects the ACL creation attribute expected by the filesystem provider.
                 *
                 * @return The provider attribute name acl:acl.
                 */
                @Override public String name() { return "acl:acl"; }
                /**
                 * Supplies the current-user allow entry for creation-time ACL installation.
                 *
                 * @return A one-entry immutable ACL list.
                 */
                @Override public List<AclEntry> value() { return List.of(entry); }
            } };
        }
        throw new IOException("Filesystem cannot create user-restricted library files.");
    }
    /**
     * Hashes exact persisted bytes for conflict detection without parsing or normalizing them.
     *
     * @param bytes Complete library file representation.
     * @return Lowercase, 64-character SHA-256 digest.
     * @throws IllegalStateException If the JVM lacks its required SHA-256 implementation.
     */
    private static String sha256(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (java.security.NoSuchAlgorithmException ex) { throw new IllegalStateException("SHA-256 unavailable."); }
    }

    /**
     * Starts one daemon observer that polls metadata every two seconds off the EDT.
     *
     * Changed files are reread and hashed. Local-save echoes are suppressed so redacted disk values
     * cannot replace a committed session snapshot. A repaired file is emitted even when restored
     * bytes match the last valid version. Read and callback failures are retried on later ticks.
     *
     * The success callback runs under this store's publication monitor: keep it short, publish/copy
     * state only, and schedule edits separately rather than calling save from the callback. It owns
     * the supplied Loaded result and must close it; the store closes it if the callback throws.
     *
     * @param changed Consumer for an externally observed document/version, including initial observation
     *     unless it matches a local save already known to this store.
     * @param failed Consumer for read/observation failures; its own exception cannot stop future polling.
     * @throws IOException If the store is already closed.
     * @throws IllegalStateException If a watcher has already been started.
     */
    public synchronized void watch(Consumer<Loaded> changed, Consumer<IOException> failed) throws IOException {
        checkOpen(); if (watcher != null) throw new IllegalStateException("Library watcher is already active.");
        watcher = Executors.newSingleThreadScheduledExecutor(r -> { Thread t = new Thread(r, "bpsh-library-watch"); t.setDaemon(true); return t; });
        watcher.scheduleWithFixedDelay(new Runnable() {
            private Object observed;
            private Version observedVersion;
            private boolean failedObservation;
            /**
             * Observes one candidate change, guarding publication against concurrent saves and close.
             *
             * Metadata captured before reading must still match at publication. Failed observations retain
             * a retry flag; successful observations update the stamp/version even when a local echo is skipped.
             */
            @Override public void run() {
                if (closed) return;
                try {
                    Object stamp = stamp();
                    if (!failedObservation && Objects.equals(stamp, observed)) return;
                    try (Loaded loaded = load()) {
                        // Capture metadata before read: edits concurrent with read are checked on the next tick.
                        synchronized (UserLibraryStore.this) {
                            // A save may have completed between the read and this publication lock.
                            if (!Objects.equals(stamp, stamp())) return;
                            // A local save returns the session snapshot for caller publication. Its
                            // disk echo must not replace that snapshot with redacted values; external
                            // changes and repaired files still emit events.
                            if (!closed && (failedObservation || (!loaded.version().equals(observedVersion) && !loaded.version().equals(writtenVersion)))) {
                                ConfigManager.NativeDocument copy = loaded.document().withRevision(loaded.document().revision());
                                Loaded event = new Loaded(copy, loaded.version());
                                try { changed.accept(event); } catch (RuntimeException ex) { event.close(); throw ex; }
                            }
                        }
                        observedVersion = loaded.version();
                        observed = stamp;
                        failedObservation = false;
                    }
                } catch (IOException ex) { failedObservation = true; reportFailure(failed, ex); }
                catch (RuntimeException ex) {
                    failedObservation = true;
                    reportFailure(failed, new LibraryException(file, "library change callback failed; Reload to retry"));
                }
            }
        }, 0, 2, TimeUnit.SECONDS);
    }
    /**
     * Reports a watcher error without letting the error reporter terminate the polling task.
     *
     * @param failed Error consumer supplied when observation began.
     * @param error Failure to report; ignored after shutdown.
     */
    private void reportFailure(Consumer<IOException> failed, IOException error) {
        if (!closed) try { failed.accept(error); }
        catch (RuntimeException ignored) { /* A UI error reporter must not permanently kill polling/recovery. */ }
    }
    /**
     * Captures inexpensive metadata to decide whether the watcher should reread the primary.
     *
     * This is an observation hint, not write authorization: every save independently rereads bytes
     * and compares both revision and hash under the edit lock.
     *
     * @return Missing-file sentinel or modification-time/size/file-key tuple.
     * @throws IOException If metadata cannot be read.
     */
    private Object stamp() throws IOException {
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) return "absent";
        BasicFileAttributes a = Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        return List.of(a.lastModifiedTime(), a.size(), String.valueOf(a.fileKey()));
    }
    /**
     * Stops scheduled observation and rejects subsequent operations; repeated closes are harmless.
     *
     * This does not close caller-owned Loaded results or wait for an already-running save to finish.
     */
    @Override public synchronized void close() {
        closed = true; if (watcher != null) watcher.shutdownNow();
    }
}
