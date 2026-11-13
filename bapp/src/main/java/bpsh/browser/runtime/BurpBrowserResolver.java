package bpsh.browser.runtime;

import bpsh.authentication.AuthenticationFailure;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;
import java.util.function.*;

/** Resolves installed Burp Browser executables without reading browser profiles. */
public final class BurpBrowserResolver {
    /** Host hints are installation roots, never browser profiles or adopted processes.
     * @param platform Normalized supported target.
     * @param activeInstallations Roots identified from this Burp process.
     * @param knownInstallations Bounded conventional fallback roots.
     */
    public record Environment(String platform, List<Path> activeInstallations, List<Path> knownInstallations) {
        /** Copies caller-owned hint lists. */
        public Environment { Objects.requireNonNull(platform); activeInstallations = List.copyOf(activeInstallations); knownInstallations = List.copyOf(knownInstallations); }
    }
    /** Immutable executable choice for one attempt, outside the bundled driver manifest.
     * @param executable Canonical installed executable.
     * @param installation Canonical installation owning burpbrowser.
     * @param version Numeric directory version or unversioned.
     * @param source Selection precedence witness.
     */
    public record Selection(Path executable, Path installation, String version, Source source) {}
    /** Identifies the precedence tier without retaining process command lines. */
    public enum Source { EXPLICIT, ACTIVE_INSTALLATION, KNOWN_INSTALLATION }
    private final String platform;
    private final Supplier<Environment> environmentHints;
    private final Supplier<String> override;
    private final Predicate<Path> executable;
    private static final int MAX_ROOTS = 64, MAX_VERSIONS = 256;
    /** @param environment Bounded installation hints. @param override Current user-local raw selection. */
    public BurpBrowserResolver(Environment environment, Supplier<String> override) { this(environment, override, Files::isExecutable); }
    /** @param environment Host hints. @param override User selection. @param executable Executable-permission boundary. */
    BurpBrowserResolver(Environment environment, Supplier<String> override, Predicate<Path> executable) {
        this(environment.platform(), () -> environment, override, executable);
    }
    /** @param platform Target. @param environment Worker-resolved host hints. @param override User selection. @param executable Executability boundary. */
    BurpBrowserResolver(String platform, Supplier<Environment> environment, Supplier<String> override, Predicate<Path> executable) {
        this.platform = Objects.requireNonNull(platform); this.environmentHints = Objects.requireNonNull(environment);
        this.override = Objects.requireNonNull(override); this.executable = Objects.requireNonNull(executable);
    }
    /** Creates inert current-host discovery; filesystem inspection waits for the calling worker.
     * @param override Current user-local raw executable. @return Deferred installed-browser resolver.
     */
    public static BurpBrowserResolver current(Supplier<String> override) {
        return new BurpBrowserResolver(BrowserRuntimeManager.hostPlatform(), BurpBrowserResolver::currentEnvironment, override, Files::isExecutable);
    }
    /** Reads only current-process installation metadata and fixed platform-known roots.
     * @return Inert hints; no browser process or user profile is touched.
     */
    public static Environment currentEnvironment() {
        String platform = BrowserRuntimeManager.hostPlatform();
        Path home = Path.of(System.getProperty("user.home")); var paths = new ArrayList<Path>(); var known = new ArrayList<Path>();
        String[] arguments = ProcessHandle.current().info().arguments().orElse(new String[0]);
        for (int i = 0; i + 1 < arguments.length; i++) if (arguments[i].equals("-jar")) addPath(paths, arguments[i + 1]);
        if (paths.isEmpty()) for (String value : System.getProperty("java.class.path", "").split(java.io.File.pathSeparator))
            if (value.toLowerCase(Locale.ROOT).endsWith(".jar")) addPath(paths, value);
        ProcessHandle.current().info().command().ifPresent(value -> addPath(paths, value));
        if (platform.equals("windows-x64")) {
            var parents = new ArrayList<Path>();
            addPath(parents, System.getenv("LOCALAPPDATA") == null ? home.resolve("AppData/Local/Programs").toString() : Path.of(System.getenv("LOCALAPPDATA"), "Programs").toString());
            addPath(parents, System.getenv("ProgramFiles")); addPath(parents, System.getenv("ProgramFiles(x86)"));
            for (Path parent : parents) for (String edition : List.of("BurpSuiteDesktop", "BurpSuitePro", "BurpSuiteCommunity")) known.add(parent.resolve(edition));
        } else if (platform.equals("linux-x64")) {
            for (Path parent : List.of(home, Path.of("/opt"))) for (String edition : List.of("BurpSuiteDesktop", "BurpSuitePro", "BurpSuiteCommunity")) known.add(parent.resolve(edition));
            known.add(home.resolve(".BurpSuite"));
        } else if (platform.equals("macos-x64")) {
            for (Path parent : List.of(Path.of("/Applications"), home.resolve("Applications")))
                for (String edition : List.of("Burp Suite.app", "Burp Suite Community Edition.app", "Burp Suite Community.app", "Burp Suite Professional.app", "Burp Suite Professional Edition.app"))
                    known.add(parent.resolve(edition).resolve("Contents/Resources/app"));
        }
        return environment(platform, home, paths, known);
    }
    /** Validates bounded current-process hints; a shared Java directory never identifies Burp.
     * @param platform Target. @param home User home, never traversed. @param processPaths Current process paths only.
     * @param known Fixed conventional roots. @return Identified active roots and fixed candidates.
     */
    static Environment environment(String platform, Path home, List<Path> processPaths, List<Path> known) {
        var active = new LinkedHashSet<Path>();
        var hints = processPaths.stream().limit(MAX_ROOTS).map(Path::toAbsolutePath).toList();
        for (Path hint : hints) if (name(hint).matches("burpsuite[^/]*\\.jar") && Files.isRegularFile(hint))
            addCanonical(active, applicationRoot(platform, hint));
        // A borrowed JVM (including java.home inside another edition) is not
        // evidence of this application's installation. Actual application JARs win.
        if (active.isEmpty()) for (Path hint : hints) {
            String name = name(hint);
            if (name.startsWith("burp") && (Files.isRegularFile(hint) && !name.endsWith(".jar")
                    || name.endsWith(".app") && Files.isDirectory(hint))) addCanonical(active, applicationRoot(platform, hint));
        }
        return new Environment(platform, List.copyOf(active), known.stream().limit(MAX_ROOTS).toList());
    }
    /** @param path Metadata path. @return Lowercase basename without inspecting ancestors. */
    private static String name(Path path) { return path.getFileName() == null ? "" : path.getFileName().toString().toLowerCase(Locale.ROOT); }
    /** @param platform Target. @param application Actual application JAR or launcher. @return Its installation, never a JVM ancestor. */
    private static Path applicationRoot(String platform, Path application) {
        if (platform.equals("macos-x64")) {
            Path cursor = application;
            for (int i = 0; cursor != null && i < 6; i++, cursor = cursor.getParent())
                if (name(cursor).startsWith("burp") && name(cursor).endsWith(".app")) return cursor.resolve("Contents/Resources/app");
        }
        return application.getParent();
    }
    /** Resolves a fresh external executable within the caller's unchanged attempt budget.
     * @param deadlineNanos Original monotonic deadline. @param cancelled Attempt cancellation.
     * @return Immutable installed executable selection. @throws AuthenticationFailure On missing, ambiguous, unsafe or cancelled selection.
     */
    public Selection resolve(long deadlineNanos, BooleanSupplier cancelled) throws AuthenticationFailure {
        AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.SETUP, deadlineNanos, cancelled);
        if (!Set.of("windows-x64", "linux-x64", "macos-x64").contains(platform))
            throw failure(AuthenticationFailure.Cause.UNSUPPORTED_PLATFORM, "Burp Browser automation is unavailable on this platform.");
        try {
            String value = Objects.requireNonNull(override.get());
            if (!value.isEmpty()) {
                Path path;
                try { path = Path.of(value); } catch (InvalidPathException error) { throw failure(AuthenticationFailure.Cause.CONFIGURATION, "The selected Burp Browser path is invalid."); }
                if (!path.isAbsolute()) throw failure(AuthenticationFailure.Cause.CONFIGURATION, "Select an absolute Burp Browser executable path.");
                if (!Files.isRegularFile(path)) throw failure(AuthenticationFailure.Cause.ASSET_MISSING, "The selected Burp Browser executable is missing.");
                path = path.toRealPath(); Selection selected = identify(path, Source.EXPLICIT);
                if (selected == null || !executable.test(path)) throw failure(AuthenticationFailure.Cause.CONFIGURATION, "Select an executable in a supported Burp Browser installation.");
                AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.SETUP, deadlineNanos, cancelled); return selected;
            }
            Environment environment = environmentHints.get();
            List<Path> roots = environment.activeInstallations().isEmpty() ? environment.knownInstallations() : environment.activeInstallations();
            Source source = environment.activeInstallations().isEmpty() ? Source.KNOWN_INSTALLATION : Source.ACTIVE_INSTALLATION;
            var choices = new LinkedHashMap<Path, Selection>();
            if (roots.size() > MAX_ROOTS) throw failure(AuthenticationFailure.Cause.CONFIGURATION, "Too many Burp installations were found. Select the intended browser.");
            for (Path root : roots) {
                AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.SETUP, deadlineNanos, cancelled);
                Selection candidate = fromInstallation(root, source, deadlineNanos, cancelled);
                if (candidate != null) choices.putIfAbsent(candidate.installation(), candidate);
            }
            if (choices.size() > 1) throw failure(AuthenticationFailure.Cause.CONFIGURATION, "Several Burp installations were found. Select the intended Burp Browser executable.");
            if (choices.isEmpty()) throw failure(AuthenticationFailure.Cause.ASSET_MISSING, "Burp Browser was not found in the selected installation.");
            return choices.values().iterator().next();
        } catch (IOException | SecurityException error) {
            throw failure(AuthenticationFailure.Cause.CONFIGURATION, "The Burp Browser installation could not be read.");
        }
    }
    /** Selects the newest complete immediate numeric version, then the direct layout.
     * @param root Installation root. @param source Precedence witness. @param deadline Original deadline. @param cancelled Cancellation.
     * @return Canonical selection or null. @throws IOException On inaccessible metadata. @throws AuthenticationFailure On stopped or excessive enumeration.
     */
    private Selection fromInstallation(Path root, Source source, long deadline, BooleanSupplier cancelled) throws IOException, AuthenticationFailure {
        Path browsers = root.resolve("burpbrowser"); if (!Files.isDirectory(browsers)) return null;
        var versions = new ArrayList<Path>(); int count = 0;
        try (var children = Files.newDirectoryStream(browsers)) {
            for (Path child : children) {
                AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.SETUP, deadline, cancelled);
                if (++count > MAX_VERSIONS) throw failure(AuthenticationFailure.Cause.CONFIGURATION, "The Burp Browser installation has too many entries. Select its executable explicitly.");
                if (numeric(child.getFileName().toString()) && Files.isDirectory(child)) versions.add(child);
            }
        }
        versions.sort((a, b) -> compareVersions(b.getFileName().toString(), a.getFileName().toString())); versions.add(browsers);
        for (Path version : versions) for (String suffix : suffixes()) {
            AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.SETUP, deadline, cancelled);
            Path candidate = version.resolve(suffix);
            if (Files.isRegularFile(candidate) && executable.test(candidate)) {
                Selection selected = identify(candidate.toRealPath(), source);
                if (selected != null && selected.installation().equals(root.toRealPath())) return selected;
            }
        }
        return null;
    }
    /** Recognizes exact external layout suffixes, never just an executable basename.
     * @param path Canonical regular executable. @param source Selection witness. @return Layout-qualified selection or null.
     */
    private Selection identify(Path path, Source source) {
        for (String suffix : suffixes()) {
            Path relative = Path.of(suffix); if (!path.endsWith(relative)) continue;
            Path directory = path; for (int i = 0; i < relative.getNameCount(); i++) directory = directory.getParent();
            if (directory == null) continue;
            String version = directory.getFileName().toString();
            Path browsers = numeric(version) ? directory.getParent() : directory;
            if (browsers != null && browsers.getFileName() != null && browsers.getFileName().toString().equalsIgnoreCase("burpbrowser") && browsers.getParent() != null)
                return new Selection(path, browsers.getParent(), numeric(version) ? version : "unversioned", source);
        }
        return null;
    }
    /** @return Exact executable suffixes for this platform, in stable preferred order. */
    private List<String> suffixes() {
        return switch (platform) {
            case "windows-x64" -> List.of("chrome.exe"); case "linux-x64" -> List.of("chrome");
            case "macos-x64" -> List.of("Burp Browser.app/Contents/MacOS/Burp Browser", "Chromium.app/Contents/MacOS/Chromium");
            default -> List.of();
        };
    }
    /** @param value Candidate immediate directory name. @return Whether bounded numeric version syntax matches. */
    private static boolean numeric(String value) { return value.length() <= 64 && value.matches("[0-9]+(?:\\.[0-9]+){0,7}"); }
    /** @param a Numeric version. @param b Numeric version. @return Numeric comparison with deterministic spelling tie-break. */
    private static int compareVersions(String a, String b) {
        String[] left = a.split("\\."), right = b.split("\\.");
        for (int i = 0; i < Math.max(left.length, right.length); i++) {
            int difference = new BigInteger(i < left.length ? left[i] : "0").compareTo(new BigInteger(i < right.length ? right[i] : "0"));
            if (difference != 0) return difference;
        }
        return a.compareTo(b);
    }
    /** @param paths Current-process/known hint list. @param value Optional path spelling. */
    private static void addPath(List<Path> paths, String value) { if (value != null && !value.isEmpty()) try { paths.add(Path.of(value)); } catch (InvalidPathException ignored) { /* unavailable hint */ } }
    /** @param roots Canonical root accumulator. @param root Installation hint. */
    private static void addCanonical(Set<Path> roots, Path root) { try { if (Files.isDirectory(root)) roots.add(root.toRealPath()); } catch (IOException | SecurityException ignored) { /* unavailable hint */ } }
    /** @param cause Safe typed cause. @param message Fixed non-user-data problem. @return Sanitized prerequisite failure. */
    private static AuthenticationFailure failure(AuthenticationFailure.Cause cause, String message) {
        return new AuthenticationFailure(AuthenticationFailure.Phase.SETUP, cause, message,
                cause == AuthenticationFailure.Cause.UNSUPPORTED_PLATFORM ? "Use Windows x64, Linux x64 or Intel macOS with a matching JVM."
                        : "Open Settings and select the Burp Browser executable, or install it through Burp and use automatic detection.")
                .atInput(AuthenticationFailure.Input.BROWSER_EXECUTABLE);
    }
}
