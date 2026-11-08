package bpsh.browser.runtime;

import bpsh.authentication.AuthenticationFailure;
import com.microsoft.playwright.Playwright;
import com.microsoft.playwright.BrowserContext;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;

/**
 * Isolates the exact Playwright 1.64.0 pipe bootstrap from browser workflow code.
 *
 * The public factory caches driver/environment state globally. Instead, this adapter launches
 * verified Node/JS selectors and constructs the pinned implementation's pipe connection. No
 * driver installer, shared Driver singleton or JVM-wide property/environment mutation occurs.
 * Reflection is limited to this library's own unnamed-module classes and checked by integration.
 */
public final class PlaywrightDriverAdapter {
    /** Prevents instantiation of the stateless owned-process bootstrap. */
    private PlaywrightDriverAdapter() {}

    /**
     * Owns one Node driver/Playwright event loop on the creating browser worker.
     *
     * The watchdog terminates only this process tree on cancellation/deadline; it never calls
     * Playwright from its thread. Normal cleanup closes the pipe then uses short bounded waits.
     * Callers borrow playwright() and close this Session rather than the library's 30-second close.
     */
    public static final class Session implements AutoCloseable {
        private final Thread owner = Thread.currentThread();
        private final Process process;
        private final Playwright playwright;
        private final Object connection;
        private final PlaywrightRecorderAdapter.Tap recordingTap;
        private final BrowserRuntimeManager.Ready runtime;
        private final Method closeConnection;
        private final ScheduledExecutorService watchdog;
        private final AtomicBoolean closed = new AtomicBoolean();
        private final Path temporary, temporaryParent;

        /**
         * Binds a fully initialized pipe to its owning worker and existing watchdog.
         * @param process Owned Node process.
         * @param playwright Initialized pinned implementation.
         * @param connection Pinned pipe connection.
         * @param closeConnection Accessible close primitive with no 30-second process wait.
         * @param watchdog Attempt deadline/cancellation monitor.
         * @param temporary Private directory used by this driver and its browser children.
         * @throws IOException If the captured temporary parent cannot be resolved.
         */
        private Session(Process process, Playwright playwright, Object connection, PlaywrightRecorderAdapter.Tap recordingTap, BrowserRuntimeManager.Ready runtime, Method closeConnection, ScheduledExecutorService watchdog, Path temporary) throws IOException {
            this.process = process; this.playwright = playwright; this.connection = connection;
            this.recordingTap = recordingTap;
            this.runtime = runtime;
            this.closeConnection = closeConnection; this.watchdog = watchdog;
            this.temporary = temporary; this.temporaryParent = temporary.getParent().toRealPath();
        }

        /**
         * Borrows the event-loop-bound API without transferring resource ownership.
         * @return Playwright instance usable only on the creating worker.
         * @throws IllegalStateException If accessed from another thread or after close.
         */
        public Playwright playwright() { owner(); if (closed.get()) throw new IllegalStateException("Driver session is closed."); return playwright; }
        /** Borrows the pinned recorder protocol for one context on this driver worker. */
        public PlaywrightRecorderAdapter recorder(BrowserContext context) {
            owner(); if (closed.get()) throw new IllegalStateException("Driver session is closed.");
            PlaywrightRecorderAdapter.verifyDriver(runtime);
            return new PlaywrightRecorderAdapter(connection, recordingTap, context);
        }

        /**
         * Returns owned Node PID for scoped cleanup/acceptance assertions; no command or credentials.
         *
         * @return Owned Node PID for scoped cleanup/acceptance assertions; no command or credentials.
         */
        long processId() { return process.pid(); }

        /**
         * Rejects cross-thread use of the Playwright event loop before touching its connection.
         *
         * @throws IllegalStateException If the caller would violate Playwright's thread confinement.
         */
        private void owner() { if (Thread.currentThread() != owner) throw new IllegalStateException("Use the owning browser worker."); }

        /** Closes the pipe and owned process tree on its worker; published browser binaries are untouched. */
        @Override public void close() throws AuthenticationFailure {
            owner(); if (!closed.compareAndSet(false, true)) return;
            recordingTap.releaseRecorder();
            watchdog.shutdownNow();
            List<ProcessHandle> children = process.descendants().toList();
            try { closeConnection.invoke(connection); } catch (Exception ignored) { /* process cleanup remains mandatory */ }
            try { if (!process.waitFor(500, TimeUnit.MILLISECONDS)) terminate(process); }
            catch (InterruptedException ex) { Thread.currentThread().interrupt(); terminate(process); }
            finally {
                children.forEach(PlaywrightDriverAdapter::terminate); if (process.isAlive()) terminate(process);
                long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
                for (ProcessHandle child : children) if (child.isAlive()) try { child.onExit().get(Math.max(1, end - System.nanoTime()), TimeUnit.NANOSECONDS); } catch (Exception ignored) { /* cleanup reports remaining file locks */ }
                cleanup(temporary, temporaryParent);
            }
        }
    }

    /**
     * Starts a driver using only a verified ready handle and per-process environment.
     * @param runtime Manager-issued immutable browser/Node/driver selectors.
     * @param deadlineNanos Original attempt deadline, also enforced during pipe initialization.
     * @param cancelled Attempt/extension cancellation predicate.
     * @return Caller-owned session on the current worker.
     * @throws AuthenticationFailure If the pinned ABI, process launch or initialization cannot complete.
     */
    public static Session open(BrowserRuntimeManager.Ready runtime, long deadlineNanos, BooleanSupplier cancelled) throws AuthenticationFailure {
        AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.SETUP, deadlineNanos, cancelled);
        // Connection's channel logger reads the parent environment, not CreateOptions.env.
        if (System.getenv("DEBUG") != null && System.getenv("DEBUG").contains("pw:channel"))
            throw setup("Playwright debug logging is enabled and could expose login values.", "Remove pw:channel from the DEBUG environment variable and restart Burp.");
        Process process = null; Path temporary = null;
        ScheduledExecutorService watchdog = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "bpsh-driver-budget"); thread.setDaemon(true); return thread;
        });
        try {
            Path temporaryParent = Path.of(System.getProperty("java.io.tmpdir")).toRealPath();
            temporary = Files.createTempDirectory(temporaryParent, "bpsh-attempt-", BrowserRuntimeManager.privateAttributes(temporaryParent, true));
            Map<String, String> environment = new HashMap<>(environment(runtime));
            for (String key : List.of("TEMP", "TMP", "TMPDIR")) environment.put(key, temporary.toString());
            ProcessBuilder builder = new ProcessBuilder(runtime.nodeExecutable().toString(), runtime.driverEntryPoint().toString(), "run-driver");
            builder.environment().clear(); builder.environment().putAll(environment);
            Files.readAttributes(runtime.nodeExecutable(), BasicFileAttributes.class);
            Files.readAttributes(runtime.driverEntryPoint(), BasicFileAttributes.class);
            if (!Files.isExecutable(runtime.nodeExecutable())) throw new java.nio.file.AccessDeniedException("Bundled Node is not executable.");
            builder.redirectError(ProcessBuilder.Redirect.DISCARD); process = builder.start();
            Process owned = process;
            watchdog.scheduleWithFixedDelay(() -> {
                try {
                    if (cancelled.getAsBoolean() || deadlineNanos - System.nanoTime() <= 0) terminate(owned);
                } catch (RuntimeException ex) {
                    // A broken lifecycle predicate must not silently disable the process budget.
                    terminate(owned);
                }
            }, 0, 50, TimeUnit.MILLISECONDS);
            ClassLoader loader = Playwright.class.getClassLoader();
            Class<?> pipeType = Class.forName("com.microsoft.playwright.impl.PipeTransport", true, loader);
            Constructor<?> pipeConstructor = pipeType.getDeclaredConstructor(InputStream.class, OutputStream.class); pipeConstructor.setAccessible(true);
            Object pipe = pipeConstructor.newInstance(process.getInputStream(), process.getOutputStream());
            var recordingTap = new PlaywrightRecorderAdapter.Tap((com.microsoft.playwright.impl.Transport) pipe);
            Class<?> connectionType = Class.forName("com.microsoft.playwright.impl.Connection", true, loader);
            Class<?> transportType = Class.forName("com.microsoft.playwright.impl.Transport", true, loader);
            Constructor<?> connectionConstructor = connectionType.getDeclaredConstructor(transportType, Map.class); connectionConstructor.setAccessible(true);
            Object connection = connectionConstructor.newInstance(recordingTap, environment);
            Method close = connectionType.getDeclaredMethod("close"); close.setAccessible(true);
            Playwright playwright = (Playwright) connectionType.getMethod("initializePlaywright").invoke(connection);
            Field driverProcess = playwright.getClass().getDeclaredField("driverProcess"); driverProcess.setAccessible(true); driverProcess.set(playwright, process);
            AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.SETUP, deadlineNanos, cancelled);
            return new Session(process, playwright, connection, recordingTap, runtime, close, watchdog, temporary);
        } catch (AuthenticationFailure ex) {
            watchdog.shutdownNow(); if (process != null) terminate(process); if (temporary != null) cleanup(temporary, temporary.getParent()); throw ex;
        } catch (Exception ex) {
            boolean exited = process != null && !process.isAlive();
            watchdog.shutdownNow(); if (process != null) terminate(process); if (temporary != null) cleanup(temporary, temporary.getParent());
            AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.SETUP, deadlineNanos, cancelled);
            throw startupFailure(ex, exited);
        }
    }

    /** Maps typed startup evidence without retaining process output or exception text.
     * @param error Driver initialization error.
     * @param exited Whether its process exited before cleanup began.
     * @return Safe setup result.
     */
    public static AuthenticationFailure startupFailure(Exception error, boolean exited) {
        var cause = error instanceof java.nio.file.AccessDeniedException ? AuthenticationFailure.Cause.CONFIGURATION
                : error instanceof java.nio.file.NoSuchFileException ? AuthenticationFailure.Cause.ASSET_MISSING : AuthenticationFailure.Cause.UNKNOWN;
        String safe = cause == AuthenticationFailure.Cause.CONFIGURATION ? "Burp cannot execute the bundled browser driver."
                : cause == AuthenticationFailure.Cause.ASSET_MISSING ? "The bundled browser driver files are missing."
                : exited ? "The browser driver exited during initialization." : "The browser driver could not start.";
        return new AuthenticationFailure(AuthenticationFailure.Phase.SETUP, cause, safe,
                cause == AuthenticationFailure.Cause.CONFIGURATION ? "Allow executable access to the browser cache."
                : cause == AuthenticationFailure.Cause.ASSET_MISSING ? "Reload the complete universal extension JAR." : "");
    }

    /**
     * Copies the host environment while removing implicit proxy, debug and driver override settings.
     * @param runtime Verified selectors used to install exact per-child overrides.
     * @return Independent child environment; never written into JVM-wide properties or System.getenv.
     */
    public static Map<String, String> environment(BrowserRuntimeManager.Ready runtime) {
        Map<String, String> result = new HashMap<>(System.getenv());
        result.keySet().removeIf(key -> {
            String k = key.toUpperCase(Locale.ROOT);
            return k.startsWith("PLAYWRIGHT_") || k.startsWith("PW_") || k.equals("DEBUG") || k.equals("NODE_OPTIONS")
                    || k.equals("NODE_PATH") || k.equals("NODE_TLS_REJECT_UNAUTHORIZED") || k.equals("NODE_EXTRA_CA_CERTS")
                    || k.equals("SELENIUM_REMOTE_URL") || k.equals("HTTP_PROXY") || k.equals("HTTPS_PROXY") || k.equals("ALL_PROXY") || k.equals("NO_PROXY");
        });
        result.put("PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD", "1"); result.put("PLAYWRIGHT_BROWSERS_PATH", runtime.browserRoot().toString());
        result.put("PLAYWRIGHT_NODEJS_PATH", runtime.nodeExecutable().toString()); result.put("PW_LANG_NAME", "java");
        result.put("PW_LANG_NAME_VERSION", "21"); result.put("PW_CLI_DISPLAY_VERSION", "1.64.0");
        return Map.copyOf(result);
    }

    /**
     * Terminates an owned Node process and captures descendants before its parent exits.
     * @param process Process launched by this adapter, never a name/PID discovered from the host.
     */
    private static void terminate(Process process) { process.descendants().toList().reversed().forEach(PlaywrightDriverAdapter::terminate); terminate(process.toHandle()); }

    /**
     * Requests forced termination of one captured owned descendant, ignoring already exited processes.
     * @param handle Node/browser descendant owned by the current session.
     */
    private static void terminate(ProcessHandle handle) { if (handle.isAlive()) handle.destroyForcibly(); }

    /**
     * Removes only a checked attempt-owned temporary tree without following links or touching user profiles.
     * @param directory Directory created for this adapter invocation.
     * @param expectedParent Captured real temporary parent.
     * @throws AuthenticationFailure If process file locks or containment checks prevent safe cleanup.
     */
    private static void cleanup(Path directory, Path expectedParent) throws AuthenticationFailure {
        try {
            if (!Files.exists(directory, java.nio.file.LinkOption.NOFOLLOW_LINKS)) return;
            if (Files.isSymbolicLink(directory) || !directory.toAbsolutePath().normalize().getParent().toRealPath().equals(expectedParent.toRealPath())
                    || !directory.getFileName().toString().startsWith("bpsh-attempt-") || !directory.toRealPath().getParent().equals(expectedParent.toRealPath()))
                throw new IOException("Unsafe owned temporary path.");
            Files.walkFileTree(directory, new SimpleFileVisitor<>() {
                /**
                 * Deletes a leaf of the checked invocation-owned tree without following symbolic links.
                 *
                 * @param file Owned leaf/link.
                 * @param attrs No-follow attributes.
                 * @return Continue.
                 * @throws IOException On delete failure.
                 */
                @Override public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException { Files.delete(file); return FileVisitResult.CONTINUE; }
                /**
                 * Removes an emptied invocation-owned directory, preserving traversal failures for the caller.
                 *
                 * @param dir Owned directory.
                 * @param error Traversal error.
                 * @return Continue.
                 * @throws IOException On traversal/delete failure.
                 */
                @Override public FileVisitResult postVisitDirectory(Path dir, IOException error) throws IOException { if (error != null) throw error; Files.delete(dir); return FileVisitResult.CONTINUE; }
            });
        } catch (IOException ex) { throw setup("The browser's temporary files could not be deleted from " + directory + ".", ""); }
    }

    /**
     * Builds a terminal setup result with concrete recovery guidance and no raw browser exception.
     *
     * @param safe Safe setup description.
     * @param recovery Concrete correction.
     * @return Terminal redacted setup error.
     */
    private static AuthenticationFailure setup(String safe, String recovery) {
        return new AuthenticationFailure(AuthenticationFailure.Phase.SETUP, AuthenticationFailure.Cause.CONFIGURATION, safe, recovery);
    }
}
