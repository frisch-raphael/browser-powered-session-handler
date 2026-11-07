import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import org.littleshoot.proxy.HttpFilters;
import org.littleshoot.proxy.HttpFiltersAdapter;
import org.littleshoot.proxy.HttpFiltersSourceAdapter;
import org.littleshoot.proxy.HttpProxyServer;
import org.littleshoot.proxy.impl.DefaultHttpProxyServer;
import org.littleshoot.proxy.impl.ThreadPoolConfiguration;
import static org.junit.jupiter.api.Assertions.*;

/** Hosts disposable local HTTP/TLS services and validated developer fixture paths, never Burp factories. */
final class IntegrationFixtures {
    /** Prevents instantiation of test-boundary factories. */
    private IntegrationFixtures() {}

    /** Owns one ephemeral local origin and its daemon handler pool. */
    static final class Origin implements AutoCloseable {
        final HttpServer server;
        final ExecutorService executor;
        final String scheme;
        final lab.auth.ControlledApplication.Origin owner;
        /** @param server Bound HTTP/HTTPS server. @param scheme URL scheme used by this fixture. */
        Origin(HttpServer server, String scheme) {
            this(new lab.auth.ControlledApplication.Origin(server, scheme, "localhost"));
        }
        Origin(lab.auth.ControlledApplication.Origin owner) {
            this.owner = owner; this.server = owner.server(); this.scheme = owner.url("").getScheme();
            executor = owner.executor();
        }
        /** @param path Context path. @param handler Local test service. @return This origin for fluent fixture setup. */
        Origin route(String path, HttpHandler handler) { owner.route(path, handler); return this; }
        /** @return Started origin with no global/shared listener modifications. */
        Origin start() { owner.start(); return this; }
        /** @param path Absolute fixture path/query. @return Actual ephemeral localhost URL. */
        URI url(String path) { return URI.create(scheme + "://localhost:" + server.getAddress().getPort() + path); }
        /** Stops only the fixture-owned listener/handler pool. */
        @Override public void close() { owner.close(); }
    }

    /** @return Fresh unstarted loopback HTTP origin. @throws IOException If binding fails. */
    static Origin http() throws IOException { return new Origin(lab.auth.ControlledApplication.Origin.http("localhost")); }

    /**
     * Creates a strict TLS origin from the fresh SoftHSM fixture's software server key and CA.
     * @param root Owned fixture directory validated by nativeFixture().
     * @param wrongHost Whether to present its CA-signed but hostname-invalid leaf.
     * @param clientAuth Whether the origin requires a client identity.
     * @return Unstarted server; requests cannot arrive until routes have been registered.
     * @throws Exception If software fixture PEM/JDK TLS setup fails.
     */
    static Origin https(Path root, boolean wrongHost, boolean clientAuth) throws Exception {
        return new Origin(lab.auth.TransportFixtures.https(root,wrongHost,clientAuth));
    }

    /** @param exchange Owned local request. @param status Fixture status. @param type Content type. @param text UTF-8 body. @throws IOException On local connection failure. */
    static void respond(HttpExchange exchange, int status, String type, String text) throws IOException {
        lab.auth.ControlledApplication.Origin.reply(exchange,status,type,text);
    }

    /** @param origin Local server whose token endpoint is selected. @param steps Ordered native test steps. @return Validated-shape ordinary headless JSON journey. */
    static JourneyDefinition journey(Origin origin, List<AuthStep.Definition> steps) {
        return new JourneyDefinition(UUID.randomUUID(), "Fixture journey", "fixture", origin.url("/login"), false, steps,
                new JourneyDefinition.Browser(true, null, 5000, 1000),
                new JourneyDefinition.JsonExtraction(TokenExtractor.origin(origin.url("/")), "/token", "access_token"),
                JourneyDefinition.Injection.perToken(List.of(new JourneyDefinition.TokenInjection(null, JourneyDefinition.InjectionType.BEARER, null))), new JourneyDefinition.Cache(1800, 10), null);
    }

    /** @param j Base definition. @param url Initial URL. @param browser Browser settings. @param extraction Token selector. @param mtls Optional token selection. @return Modified immutable fixture definition. */
    static JourneyDefinition configured(JourneyDefinition j, URI url, JourneyDefinition.Browser browser,
            JourneyDefinition.Extraction extraction, JourneyDefinition.Mtls mtls) {
        return new JourneyDefinition(j.id(), j.displayName(), j.alias(), url, j.rememberSecrets(), j.steps(), browser,
                extraction, j.injection(), j.cache(), mtls);
    }

    /** Records only cleaned agents and path/classification, never active marker values or credentials. */
    record Seen(String path, String agent, AuthTrafficGuard.Classification classification) {}

    /** Owns an explicit HTTP/CONNECT fixture proxy; optional guard emulates global suffix stripping. */
    static final class ForwardProxy implements AutoCloseable {
        final HttpProxyServer server;
        final List<Seen> seen = new CopyOnWriteArrayList<>();
        final AtomicLong accepted;
        final lab.auth.TransportFixtures.UnauthenticatedProxy owner;
        /** @param guard Marker validator, or null for an ordinary unauthenticated upstream tunnel. */
        ForwardProxy(AuthTrafficGuard guard) {
            owner=new lab.auth.TransportFixtures.UnauthenticatedProxy((method,path,agent,id)->{
                var decision=guard==null?new AuthTrafficGuard.Decision(AuthTrafficGuard.Classification.NORMAL,agent,null):guard.classify(agent,AuthTrafficGuard.Family.GLOBAL,id);
                if(decision.classification()==AuthTrafficGuard.Classification.INVALID)return new lab.auth.TransportFixtures.ProxyDecision(false,null);
                if(!method.equals("CONNECT"))seen.add(new Seen(path,decision.userAgent(),decision.classification()));
                return new lab.auth.TransportFixtures.ProxyDecision(true,decision.userAgent());
            },uri->lab.auth.ControlledApplication.Origin.ownsPort(uri.getPort()));
            accepted=owner.requestCounter();server=owner.server();
        }
        /** @return Explicit loopback proxy URI for the fixture listener. */
        URI url() { return URI.create("http://127.0.0.1:" + server.getListenAddress().getPort()); }
        /** Stops only this fixture endpoint/pools. */
        long credentialHeaders(){return owner.credentialHeaders();}
        @Override public void close() { owner.close(); }
    }

    /**
     * Requires a fresh developer-owned SoftHSM store, failing rather than falling back to any user store.
     * @return Parsed manifest with a root matching its ownership marker and exact SOFTHSM2_CONF.
     * @throws Exception If prerequisites or ownership evidence are missing/invalid.
     */
    static JsonNode nativeFixture() throws Exception {
        String path = System.getenv("BPSH_PKCS11_FIXTURE"); assertNotNull(path, "Run test/pkcs11_fixture.py with a fresh output path and pass -Ppkcs11Fixture=<fixture.json>.");
        Path file = Path.of(path).toRealPath(), root = file.getParent(); ObjectMapper json = new ObjectMapper();
        JsonNode manifest = json.readTree(Files.readAllBytes(file)), marker = json.readTree(Files.readAllBytes(root.resolve(".fixture-owned.json")));
        assertEquals(1, manifest.path("formatVersion").intValue()); assertEquals("isolated-bpsh-tests", marker.path("purpose").textValue());
        assertEquals(manifest.path("fixtureId").textValue(), marker.path("fixtureId").textValue());
        assertEquals(root, Path.of(manifest.path("root").textValue()).toRealPath());
        assertEquals(root.resolve("softhsm2.conf").toRealPath(), Path.of(System.getenv("SOFTHSM2_CONF")).toRealPath());
        assertTrue(root.resolve("tokens").toRealPath().startsWith(root)); assertTrue(manifest.path("module").textValue().toLowerCase().contains("softhsm"));
        return manifest;
    }

    /** @return Explicit artifact chosen by the Gradle task; no loose-resource fallback.
     * @throws Exception If the supplied candidate is missing or invalid.
     */
    static Path packagedJar() throws Exception {
        String value = System.getProperty("bpsh.packagedJar");
        if (value == null || value.isBlank()) throw new IllegalArgumentException("The packaged JAR input is required.");
        Path path = Path.of(value).toRealPath();
        if (!Files.isRegularFile(path)) throw new IllegalArgumentException("The packaged JAR must be a regular file.");
        try (var jar = new java.util.jar.JarFile(path.toFile())) {
            if (jar.getEntry("BrowserRuntimeManager.class") == null) throw new IllegalArgumentException("The supplied JAR is not this extension.");
        }
        return path;
    }

    /** Streams an artifact/file hash without loading large browser archives into memory. */
    static String artifactDigest(Path path) throws Exception {
        var digest = java.security.MessageDigest.getInstance("SHA-256");
        try (var in = Files.newInputStream(path)) {
            byte[] buffer = new byte[65536];
            for (int count; (count = in.read(buffer)) >= 0;) digest.update(buffer, 0, count);
        }
        return java.util.HexFormat.of().formatHex(digest.digest());
    }

    /** Measures only ordinary bytes; filesystem allocation remains a separate OS measurement. */
    static long logicalBytes(Path root) throws Exception {
        if (!Files.exists(root)) return 0;
        try (var paths = Files.walk(root)) {
            long bytes = 0;
            for (Path path : paths.toList()) if (Files.isRegularFile(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)) bytes += Files.size(path);
            return bytes;
        }
    }

    /** Lists published identities only, never temporary or another platform's paths. */
    static java.util.Map<String, Long> cacheInventory(Path home) throws Exception {
        Path cache = home.resolve(".bpsh/cache"), selected = cache.resolve(BrowserRuntimeManager.hostPlatform());
        var inventory = new java.util.TreeMap<String, Long>();
        if (!Files.exists(cache)) return inventory;
        try (var dirs = Files.list(cache)) {
            if (dirs.anyMatch(p -> Files.isDirectory(p) && !p.equals(selected))) throw new AssertionError("A foreign platform cache was installed.");
        }
        if (Files.exists(selected)) try (var dirs = Files.list(selected)) {
            for (Path directory : dirs.toList()) if (Files.isDirectory(directory, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                    && directory.getFileName().toString().matches("[0-9a-f]{64}"))
                inventory.put(directory.getFileName().toString(), logicalBytes(directory));
        }
        return inventory;
    }

    /** Hashes earlier published files/links so an update cannot silently mutate them. */
    static java.util.Map<String, String> publishedSnapshot(Path home) throws Exception {
        var result = new java.util.TreeMap<String, String>();
        for (String identity : cacheInventory(home).keySet()) {
            Path root = home.resolve(".bpsh/cache").resolve(BrowserRuntimeManager.hostPlatform()).resolve(identity);
            try (var paths = Files.walk(root)) {
                for (Path path : paths.toList()) {
                    String key = identity + "/" + root.relativize(path);
                    if (Files.isSymbolicLink(path)) result.put(key, "link:" + Files.readSymbolicLink(path));
                    else if (Files.isRegularFile(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                        String mode = Files.getFileStore(path).supportsFileAttributeView("posix") ? Files.getPosixFilePermissions(path).toString() : "";
                        result.put(key, artifactDigest(path) + mode);
                    }
                }
            }
        }
        return result;
    }

    /** Creates a private home belonging only to this invocation's probe. */
    static Path probeHome(Path resultDirectory, String name, String runId) throws Exception {
        Path home = Files.createTempDirectory("bpsh-" + name + "-").toRealPath();
        Files.createDirectory(home.resolve("tmp")); Files.createDirectories(home.resolve(".bpsh"));
        var json = new ObjectMapper();
        Files.write(home.resolve(".bpsh-probe-owned.json"), json.writeValueAsBytes(java.util.Map.of(
                "purpose", "isolated-bpsh-runtime-probe", "runId", runId,
                "results", resultDirectory.toRealPath().toString(), "home", home.toRealPath().toString())));
        Files.writeString(home.resolve(".bpsh/library-v3.json"), "{\"probe\":\"" + runId + "\"}");
        return home;
    }

    /** Executes a normal-budget probe in a child with the exact chosen artifact. */
    static JsonNode runProbe(Path artifact, Path home, Path result, String mode, String runId) throws Exception {
        String rawClasspath = System.getProperty("bpsh.probeClasspath");
        if (rawClasspath == null) throw new AssertionError("The task must supply the explicit probe classpath.");
        Path candidate = packagedJar(); var entries = new java.util.ArrayList<String>(); int replaced = 0;
        for (String item : rawClasspath.split(java.util.regex.Pattern.quote(java.io.File.pathSeparator))) {
            if (Path.of(item).toAbsolutePath().normalize().equals(candidate)) { entries.add(artifact.toString()); replaced++; }
            else entries.add(item);
        }
        if (replaced != 1) throw new AssertionError("The candidate must occur exactly once in the probe classpath.");
        String javaName = System.getProperty("os.name").toLowerCase(java.util.Locale.ROOT).startsWith("windows") ? "java.exe" : "java";
        Path jvmExecutable = Path.of(System.getProperty("java.home"), "bin", javaName);
        Process process = new ProcessBuilder(jvmExecutable.toString(), "-Duser.home=" + home,
                "-Dbpsh.packagedJar=" + artifact, "-cp", String.join(java.io.File.pathSeparator, entries),
                "IntegrationFixtures$RuntimeProbe", mode, result.toString())
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        try {
            if (!process.waitFor(90, java.util.concurrent.TimeUnit.SECONDS)) throw new AssertionError("Runtime probe exceeded its parent wall limit.");
            if (!Files.isRegularFile(result)) throw new AssertionError("Runtime probe produced no result: " + mode);
            JsonNode evidence = new ObjectMapper().readTree(Files.readAllBytes(result));
            if (process.exitValue() != 0 || !"PASS".equals(evidence.path("status").asText()))
                throw new AssertionError("Runtime probe failed: " + mode + ", " + evidence.path("errorType").asText() + ", " + evidence.path("failureCause").asText() + ", " + evidence.path("failureProblem").asText());
            if (!runId.equals(evidence.path("runId").asText()) || !artifactDigest(artifact).equals(evidence.path("artifactSha256").asText())
                    || !mode.equals(evidence.path("mode").asText())) throw new AssertionError("Runtime probe evidence belongs to another input/run.");
            return evidence;
        } finally {
            if (process.isAlive()) {
                var children = process.descendants().toList(); children.forEach(ProcessHandle::destroyForcibly);
                process.destroyForcibly(); process.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            }
        }
    }

    /** Mandatory first-use/cache proof, plus update/rollback when a compatible old JAR is supplied. */
    static void verifyColdAndUpgrade() throws Exception {
        Path artifact = packagedJar(); String digest = artifactDigest(artifact), runId = UUID.randomUUID().toString();
        String configured = System.getProperty("bpsh.probeResultsDir");
        if (configured == null) throw new AssertionError("The probe result directory is required.");
        Path results = Path.of(configured).toAbsolutePath().resolve(BrowserRuntimeManager.hostPlatform()).resolve(digest).resolve(runId);
        Files.createDirectories(results); var json = new ObjectMapper();
        Path home = probeHome(results, "cold", runId);
        JsonNode cold = runProbe(artifact, home, results.resolve("cold.json"), "cold-probe", runId);
        JsonNode warm = runProbe(artifact, home, results.resolve("cache.json"), "cache-probe", runId);
        if (!cold.path("bundleIdentity").asText().equals(warm.path("bundleIdentity").asText())) throw new AssertionError("Cache reuse changed bundle identity.");
        Files.write(results.resolve("cold-cache.json"), json.writeValueAsBytes(java.util.Map.of("formatVersion", 1, "runId", runId, "status", "PASS", "cold", cold, "cache", warm)));
        String previous = System.getProperty("bpsh.oldPackagedJar");
        if (previous == null) {
            Files.write(results.resolve("upgrade.json"), json.writeValueAsBytes(java.util.Map.of(
                    "formatVersion", 1, "runId", runId, "status", "NOT_RUN", "reason", "OLD_ARTIFACT_NOT_SUPPLIED")));
            return;
        }
        Path old = Path.of(previous).toRealPath(); artifactDigest(old);
        Path upgradeHome = probeHome(results, "upgrade", runId);
        String library = artifactDigest(upgradeHome.resolve(".bpsh/library-v3.json"));
        JsonNode oldCold = runProbe(old, upgradeHome, results.resolve("old-cold.json"), "cold-probe", runId);
        var before = publishedSnapshot(upgradeHome);
        JsonNode upgrade = runProbe(artifact, upgradeHome, results.resolve("new-upgrade.json"), "upgrade-probe", runId);
        JsonNode reuse = runProbe(artifact, upgradeHome, results.resolve("new-cache.json"), "cache-probe", runId);
        JsonNode rollback = runProbe(old, upgradeHome, results.resolve("old-rollback.json"), "cache-probe", runId);
        var after = publishedSnapshot(upgradeHome);
        for (var entry : before.entrySet()) if (!entry.getValue().equals(after.get(entry.getKey()))) throw new AssertionError("Update modified an earlier published cache.");
        if (!library.equals(artifactDigest(upgradeHome.resolve(".bpsh/library-v3.json")))) throw new AssertionError("Update changed the user library.");
        Files.write(results.resolve("upgrade.json"), json.writeValueAsBytes(java.util.Map.of(
                "formatVersion", 1, "runId", runId, "status", "PASS", "old", oldCold, "upgrade", upgrade, "cache", reuse, "rollback", rollback)));
    }

    /** New JVM entry point; intentionally uses the retained runtime/runner signatures for old-artifact comparison. */
    public static final class RuntimeProbe {
        /** @param args Probe mode and result path; the owned-home marker supplies the run identity. */
        public static void main(String[] args) throws Exception {
            if (args.length != 2 || !List.of("cold-probe", "cache-probe", "upgrade-probe").contains(args[0]))
                throw new IllegalArgumentException("Expected a supported mode and result file.");
            Path home = Path.of(System.getProperty("user.home")).toRealPath(), result = Path.of(args[1]).toAbsolutePath();
            var json = new ObjectMapper(); JsonNode marker = json.readTree(Files.readAllBytes(home.resolve(".bpsh-probe-owned.json")));
            if (!"isolated-bpsh-runtime-probe".equals(marker.path("purpose").asText()) || !home.equals(Path.of(marker.path("home").asText()).toRealPath())
                    || !result.getParent().toRealPath().equals(Path.of(marker.path("results").asText()).toRealPath())) throw new AssertionError("Probe home ownership mismatch.");
            var evidence = json.createObjectNode().put("formatVersion", 1).put("runId", marker.path("runId").asText()).put("mode", args[0]);
            boolean success = false;
            var peak = new java.util.concurrent.atomic.AtomicLong();
            var sampler = java.util.concurrent.Executors.newSingleThreadScheduledExecutor(task -> {
                Thread thread = new Thread(task, "bpsh-probe-space"); thread.setDaemon(true); return thread;
            });
            Runnable sample = () -> {
                try { peak.accumulateAndGet(logicalBytes(home.resolve(".bpsh/cache")), Math::max); }
                catch (Exception ignored) { /* extraction can remove a file between walk and stat */ }
            };
            sampler.scheduleWithFixedDelay(sample, 0, 100, java.util.concurrent.TimeUnit.MILLISECONDS);
            try {
                Path artifact = packagedJar(); String target = BrowserRuntimeManager.hostPlatform();
                evidence.put("artifactSha256", artifactDigest(artifact)).put("platform", target);
                var before = cacheInventory(home);
                if (args[0].equals("cold-probe") && !before.isEmpty()) throw new AssertionError("Cold cache was already prepared.");
                evidence.set("beforeBundles", json.valueToTree(before));
                try (var origin = http(); var runtime = new BrowserRuntimeManager(); var identities = new Pkcs11IdentityManager();
                     var guard = new AuthTrafficGuard(); var values = SecretStore.Values.empty()) {
                    origin.route("/login", e -> respond(e, 200, "text/html", "<form method='POST' action='/token'><input id='user' name='user'><button id='submit'>Sign in</button></form>"));
                    origin.route("/token", e -> { e.getRequestBody().readAllBytes(); respond(e, 200, "application/json", "{\"access_token\":\"probe-ready\"}"); });
                    origin.start();
                    var steps = List.of(new AuthStep.Definition(UUID.randomUUID(), AuthStep.Type.INPUT, "#user", "fixture", null, null, null),
                            new AuthStep.Definition(UUID.randomUUID(), AuthStep.Type.CLICK, "#submit", null, null, null, null));
                    var journey = journey(origin, steps); var identity = new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, journey.id(), 1);
                    long started = System.nanoTime(), deadline = started + java.util.concurrent.TimeUnit.SECONDS.toNanos(60);
                    var ready = runtime.acquire(deadline, () -> false); long prepared = System.nanoTime();
                    if (args[0].equals("cache-probe") && !before.containsKey(ready.bundleDigest())) throw new AssertionError("Cache probe created a new identity.");
                    var runner = new BrowserFlowRunner(runtime, identities, guard, Clock.systemUTC());
                    var outcome = runner.run(identity, journey, values, false, deadline, () -> false);
                    long finished = System.nanoTime();
                    if (!"probe-ready".equals(outcome.token()) || finished > deadline) throw new AssertionError("Normal-budget fixture authentication failed.");
                    evidence.put("bundleIdentity", ready.bundleDigest()).put("cacheRelativePath", home.relativize(ready.root()).toString())
                            .put("preparationMillis", (prepared - started) / 1_000_000).put("loginMillis", (finished - prepared) / 1_000_000)
                            .put("totalAttemptMillis", (finished - started) / 1_000_000).put("logicalRegularBytes", logicalBytes(ready.root()));
                    try (var jar = new java.util.jar.JarFile(artifact.toFile())) {
                        var entry = jar.getJarEntry("META-INF/bpsh/" + target + "/browser-assets.json");
                        if (entry == null) entry = jar.getJarEntry("META-INF/bpsh/browser-assets.json");
                        if (entry == null) throw new AssertionError("Runtime metadata missing.");
                        JsonNode metadata;
                        try (var input = jar.getInputStream(entry)) { metadata = json.readTree(input); }
                        evidence.put("declaredArchiveBytes", metadata.path("archive").path("bytes").longValue()).put("declaredUnpackedBytes", metadata.path("unpackedBytes").longValue());
                    }
                    evidence.putNull("allocatedBytes").put("allocationMethod", "unavailable-in-portable-probe; measure separately on host");
                }
                var after = cacheInventory(home);
                if (args[0].equals("cache-probe") && !before.equals(after)) throw new AssertionError("Cache validation created another published tree.");
                evidence.set("afterBundles", json.valueToTree(after)); evidence.put("status", "PASS"); success = true;
            } catch (Exception | LinkageError error) {
                evidence.put("status", "FAIL").put("errorType", error.getClass().getSimpleName());
                if (error instanceof AuthenticationFailure failure) evidence.put("failureCause", failure.reason().name()).put("failurePhase", failure.phase().name()).put("failureProblem", failure.problem());
            } catch (AssertionError error) { evidence.put("status", "FAIL").put("errorType", "AssertionError"); }
            sample.run(); sampler.shutdownNow(); sampler.awaitTermination(2, java.util.concurrent.TimeUnit.SECONDS);
            evidence.put("sampledPeakCacheLogicalBytes", peak.get()).put("peakSamplingMethod", "100ms logical-file scan; includes cache archive/staging; not filesystem allocation");
            Files.write(result, json.writeValueAsBytes(evidence));
            if (!success) System.exit(1);
        }
    }
}
