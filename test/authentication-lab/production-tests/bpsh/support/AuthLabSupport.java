package bpsh.support;

import bpsh.journey.JourneyCatalog;

import bpsh.request.RequestSettings;
import bpsh.journey.editing.JourneyWorkspace;
import bpsh.authentication.credentials.AuthenticationResult;
import bpsh.authentication.credentials.TokenExtractor;
import bpsh.authentication.AuthenticationFailure;
import bpsh.authentication.session.CoordinatorFixtures;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

/** Owns the canonical application JVM; contains no production authentication implementation. */
public final class AuthLabSupport implements AutoCloseable {
    public static final ObjectMapper JSON = new ObjectMapper();
    /** Records actual safe assertions from an owning component execution, after its fixture closes. */
    public static void component(String id, Map<String, Object> observed) throws Exception {
        component(id, observed, null);
    }
    public static void component(String id, Map<String, Object> observed, Map<String, Long> timings) throws Exception {
        String path = System.getProperty("authlab.plan"); if (path == null) return;
        var invocation = JSON.readTree(Files.readAllBytes(Path.of(path)));
        var directory = Path.of(invocation.path("reportDirectory").asText()).resolve("component-observations"); Files.createDirectories(directory);
        String name = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(id.getBytes(StandardCharsets.UTF_8)));
        var safe = new java.util.LinkedHashMap<String, Object>();
        safe.put("version", timings == null ? 1 : 2); safe.put("invocationId", invocation.path("invocationId").asText()); safe.put("requirementId", id);
        safe.put("taskPath", ":" + invocation.path("taskName").asText()); safe.put("productionRevision", invocation.path("productionRevision").asText());
        safe.put("observed", observed); safe.put("cleanup", "COMPLETE");
        if (timings != null) { safe.put("configurationHash", invocation.path("configurationHash").asText()); safe.put("timings", timings); }
        Files.writeString(directory.resolve(name + ".json"), JSON.writeValueAsString(safe), StandardCharsets.UTF_8, java.nio.file.StandardOpenOption.CREATE_NEW);
    }
    public final JsonNode plan;
    public final Path report, environment;
    private final Process process;
    private final HttpClient http = lab.auth.ControlledApplication.localClientBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    private Path descriptor;
    private JsonNode ownership;
    private URI application, alternate, control;
    private String controlKey;
    private long runGeneration;
    private final List<Case> cases = new ArrayList<>();

    public AuthLabSupport() throws Exception { this(List.of("browser")); }
    public AuthLabSupport(List<String> profiles) throws Exception {
        plan = JSON.readTree(Files.readAllBytes(Path.of(System.getProperty("authlab.plan"))));
        report = Path.of(plan.path("reportDirectory").asText());
        environment = report.resolve("targets").resolve(UUID.randomUUID().toString()).toAbsolutePath().normalize();
        Files.createDirectories(environment);
        var command = new ArrayList<String>();
        command.add(Path.of(System.getProperty("java.home"), "bin", System.getProperty("os.name").startsWith("Windows") ? "java.exe" : "java").toString());
        command.add("-Dlab.environmentRoot=" + environment);
        command.add("-Dlab.cycleDeadlineMs=" + RequestSettings.Controls.defaults().cycleTimeoutMs());
        command.add("-Dlab.invocationId=" + plan.path("invocationId").asText());
        command.add("-classpath");
        var jars = new ArrayList<String>(); plan.path("labClasspath").forEach(p -> jars.add(p.asText()));
        command.add(String.join(File.pathSeparator, jars));
        command.addAll(List.of("lab.auth.LabMain", "serve", "--profiles", String.join(",", profiles)));
        Path console = environment.resolve("console.txt");
        process = new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(console.toFile()).start();
        try {
            long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
            while (System.nanoTime() < end) {
                if (!process.isAlive()) throw new AssertionError("Canonical target JVM stopped during startup; inspect its safe console file.");
                if (Files.isRegularFile(console)) {
                    var lines = Files.readAllLines(console, StandardCharsets.UTF_8);
                    String address = value(lines, "Controlled targets: "), second = value(lines, "Alternate origin: "), directory = value(lines, "Private run directory: ");
                    if (address != null && second != null && directory != null) {
                        application = URI.create(address);
                        alternate = URI.create(second);
                        assertEquals("127.0.0.1", application.getHost()); assertEquals("http", application.getScheme());
                        assertEquals("127.0.0.1", alternate.getHost()); assertEquals("http", alternate.getScheme()); assertNotEquals(application.getPort(), alternate.getPort());
                        descriptor = Path.of(directory).resolve("run.json").toRealPath();
                        assertTrue(descriptor.startsWith(environment.toRealPath()), "Target descriptor must remain in this invocation.");
                        ownership = JSON.readTree(Files.readAllBytes(descriptor));
                        assertEquals(1, ownership.path("descriptorVersion").asInt());
                        assertEquals(plan.path("invocationId").asText(), ownership.path("invocationId").asText());
                        assertEquals(environment.toRealPath().toString(), ownership.path("environmentRoot").asText());
                        control = URI.create(ownership.path("controlUri").asText());
                        assertEquals("127.0.0.1", control.getHost()); assertEquals("http", control.getScheme());
                        assertEquals("/control/v1/runs/" + UUID.fromString(ownership.path("runId").asText()), control.getPath());
                        controlKey = ownership.path("controlKey").asText();
                        runGeneration = ownership.path("generation").asLong();
                        runGeneration = control("POST", "/reset", Map.of("generation", runGeneration), 200).path("generation").asLong();
                        return;
                    }
                }
                Thread.sleep(10);
            }
            throw new AssertionError("Canonical target readiness deadline exceeded.");
        } catch (Throwable error) { process.destroy(); process.waitFor(5, TimeUnit.SECONDS); if (process.isAlive()) process.destroyForcibly(); http.close(); throw error; }
    }
    private static String value(List<String> lines, String prefix) { return lines.stream().filter(s -> s.startsWith(prefix)).map(s -> s.substring(prefix.length())).findFirst().orElse(null); }
    public String runId() { return ownership.path("runId").asText(); }
    private JsonNode control(String method, String path, Object body, int expectedStatus) throws Exception {
        var builder = HttpRequest.newBuilder(URI.create(control + path)).timeout(Duration.ofSeconds(8))
                .header("Authorization", "Bearer " + controlKey);
        if (body == null) builder.method(method, HttpRequest.BodyPublishers.noBody());
        else builder.header("Content-Type", "application/json").method(method, HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body)));
        var result = http.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(expectedStatus, result.statusCode(), "Canonical private control failed.");
        return JSON.readTree(result.body());
    }
    public Case prepare(String id) throws Exception {
        assertTrue(id.matches("[A-Za-z0-9._=~-]{1,200}"));
        var created = control("POST", "/cases", Map.of("caseId", id, "runGeneration", runGeneration), 201);
        var value = new Case(id, created.path("generation").asLong()); cases.add(value); return value;
    }
    public final class Case implements AutoCloseable {
        public final String id;
        public final long generation;
        private boolean closed;
        private final long began=System.nanoTime();
        private final List<Map<String,Object>> protectedResults=new ArrayList<>(),failureResults=new ArrayList<>();
        public Case(String id, long generation) { this.id = id; this.generation = generation; assertTrue(generation > 0); }
        public URI url(String route) { return url(route, false); }
        public URI url(String route, boolean other) { return (other ? alternate : application).resolve("/cases/" + id + "/" + route + (route.contains("?") ? "&" : "?") + "generation=" + generation); }
        public String cookiePath() { return "/cases/" + id; }
        public JsonNode snapshot() throws Exception { return control("GET", "/cases/" + id + "/snapshot?generation=" + generation, null, 200); }
        public void freshPhase(String phase) throws Exception {
            assertTrue(List.of("PRIME", "PROBE").contains(phase));
            var response = control("POST", "/cases/" + id + "/fresh-phase", Map.of("generation", generation, "phase", phase), 200);
            assertEquals(phase, response.path("phase").asText()); assertEquals(generation, response.path("generation").asLong());
        }
        public void freshObservation(String definitionHash, JsonNode first, JsonNode second, long primeSequence, long probeSequence, long secondLoginSequence, JsonNode state,
                              long firstContext, long secondContext) throws Exception {
            var safe = new java.util.LinkedHashMap<String, Object>();
            safe.put("invocationId", plan.path("invocationId").asText()); safe.put("fixtureRunId", runId()); safe.put("requirementId", id); safe.put("generation", generation);
            safe.put("savedDefinitionSha256", definitionHash); safe.put("configurationGeneration", 1);
            safe.put("firstAccount", first.path("accountId").asText()); safe.put("firstIssuance", first.path("issuanceId").asText());
            safe.put("secondAccount", second.path("accountId").asText()); safe.put("secondIssuance", second.path("issuanceId").asText());
            safe.put("primeSequence", primeSequence); safe.put("probeSequence", probeSequence); safe.put("secondLoginSequence", secondLoginSequence);
            var observations = new ArrayList<Map<String, Object>>();
            state.path("events").forEach(event -> {
                if (List.of("fresh-prime-observed", "fresh-probe-observed").contains(event.path("name").asText()))
                    observations.add(Map.of("name", event.path("name").asText(), "sequence", event.path("sequence").asLong(), "safeIds", event.path("safeIds")));
            });
            safe.put("stateObservations", observations);
            safe.put("firstContextId", firstContext); safe.put("secondContextId", secondContext);
            safe.put("contextIdentityObserved", true); safe.put("contextClosureObserved", true);
            Files.writeString(report.resolve("fresh-state-observations.jsonl"), JSON.writeValueAsString(safe) + "\n", StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        }
        public void surfaceObservation(JsonNode state, List<String> required, List<String> missing) throws Exception {
            var safe = Map.of("invocationId", plan.path("invocationId").asText(), "fixtureRunId", runId(), "requirementId", id, "generation", generation,
                    "requiredPageEvents", required, "missingPageEvents", missing, "truncated", state.path("truncated").asBoolean());
            Files.writeString(report.resolve("surface-observations.jsonl"), JSON.writeValueAsString(safe) + "\n", StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        }
        public String currentLoginIssuance() throws Exception {
            var state = snapshot(); assertFalse(state.path("truncated").asBoolean(), "Missing required fixture events cannot establish a pass.");
            String issuance = null;
            for (var event : state.path("events")) if (event.path("name").asText().equals("login-completed"))
                for (var safe : event.path("safeIds")) if (safe.path("kind").asText().equals("issuance")) issuance = safe.path("value").asText();
            assertNotNull(issuance, "The actual completed login must identify its issuance."); return issuance;
        }
        public void failure(AuthenticationFailure failure, String expectedCause) throws Exception {
            failureResults.add(Map.of("cause",failure.reason().name(),"phase",failure.phase().name()));
            var safe = Map.of("invocationId", plan.path("invocationId").asText(), "fixtureRunId", runId(), "requirementId", id, "generation", generation, "expectedCause", expectedCause,
                    "observedCause", failure.reason().name(), "observedPhase", failure.phase().name(), "problem", failure.problem());
            Files.writeString(report.resolve("failure-observations.jsonl"), JSON.writeValueAsString(safe) + "\n", StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        }
        public void revoke(String issuanceId) throws Exception { control("POST", "/cases/" + id + "/revoke", Map.of("generation", generation, "issuanceId", issuanceId), 200); }
        public void fault(String phase, int occurrence, String kind, Integer status, String checkpoint) throws Exception {
            var fault = new java.util.LinkedHashMap<String, Object>(); fault.put("phase", phase); fault.put("occurrence", occurrence); fault.put("kind", kind);
            fault.put("role", null); fault.put("status", status); fault.put("checkpoint", checkpoint);
            control("POST", "/cases/" + id + "/faults", Map.of("generation", generation, "fault", fault), 200);
        }
        /** Actual HTTP fixture acquisition through the production extractor, with no browser-policy claim. */
        public AuthenticationResult acquire(JourneyCatalog.Entry entry, CoordinatorFixtures.ManualRuntime clock) throws AuthenticationFailure {
            return acquire(entry,clock,"user2","pass2");
        }
        public AuthenticationResult acquire(JourneyCatalog.Entry entry, CoordinatorFixtures.ManualRuntime clock,String username,String password) throws AuthenticationFailure {
            try {
                var endpoint = url("login/json");
                var response = http.send(HttpRequest.newBuilder(endpoint).timeout(Duration.ofSeconds(3)).header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(Map.of("username",username,"password",password)))).build(), HttpResponse.BodyHandlers.ofByteArray());
                assertEquals(200, response.statusCode());
                var extractor = new TokenExtractor(entry.definition().extraction(), java.time.Clock.systemUTC());
                extractor.considerResponse(endpoint.toString(), response.body(), true);
                var cookies = new ArrayList<bpsh.authentication.credentials.CapturedCookie>();
                for (String header : response.headers().allValues("Set-Cookie")) for (var parsed : java.net.HttpCookie.parse(header))
                    cookies.add(new bpsh.authentication.credentials.CapturedCookie(parsed.getName(), parsed.getValue(), endpoint.getHost(), parsed.getPath(), null));
                extractor.collectCookies(ignored -> cookies);
                return new AuthenticationResult(entry.identity(), extractor.result(), clock.instant(), clock.nanos(), extractor.cookieValues(), extractor.namedValues(), extractor.expirySeconds());
            } catch (AuthenticationFailure known) { throw known; }
            catch (Exception failure) { throw new AssertionError("Controlled HTTP acquisition must complete.", failure); }
        }
        public record WireResponse(int status, JsonNode body, byte[] bodyBytes) {}
        /** Sends exact resolver bytes without a cookie jar or header normalization. */
        public WireResponse exchange(byte[] wire) throws Exception {
            URI endpoint = url(""); String request = new String(wire, StandardCharsets.ISO_8859_1);
            assertTrue(request.startsWith("GET /cases/" + id + "/") || request.startsWith("POST /cases/" + id + "/"));
            byte[] received;
            try (var socket = new java.net.Socket()) {
                socket.connect(new java.net.InetSocketAddress(endpoint.getHost(), endpoint.getPort()), 3000); socket.setSoTimeout(3000);
                socket.getOutputStream().write(wire); socket.getOutputStream().flush(); received = socket.getInputStream().readNBytes(65_537);
            }
            assertTrue(received.length <= 65_536); String response = new String(received, StandardCharsets.UTF_8); int split = response.indexOf("\r\n\r\n"); assertTrue(split > 0);
            byte[] body = java.util.Arrays.copyOfRange(received, split + 4, received.length);
            return new WireResponse(Integer.parseInt(response.substring(9, 12)), JSON.readTree(body), body);
        }
        /** Confirms a response is still withheld before observing the original socket timeout. */
        public void originalTimesOut(byte[] wire, int occurrence) throws Exception {
            String checkpoint = "original-timeout-" + occurrence; fault("PROTECTED", occurrence, "HOLD", null, checkpoint);
            try (var socket = new java.net.Socket()) {
                socket.connect(new java.net.InetSocketAddress(application.getHost(), application.getPort()), 3000);
                socket.getOutputStream().write(wire); socket.getOutputStream().flush(); awaitCheckpoint(checkpoint, 5000);
                socket.setSoTimeout(1); assertThrows(java.net.SocketTimeoutException.class, () -> socket.getInputStream().read());
            }
        }
        public void release(String gate) throws Exception { control("POST", "/cases/" + id + "/gates/" + gate + "/release", Map.of("generation", generation), 200); }
        public void awaitCheckpoint(String gate, long budgetMs) throws Exception {
            long end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(budgetMs);
            while (System.nanoTime() < end) {
                var state = snapshot(); assertFalse(state.path("truncated").asBoolean());
                for (var event : state.path("events")) if (event.path("name").asText().equals(gate)) return;
                Thread.sleep(10);
            }
            throw new AssertionError("Required application checkpoint was not observed: " + gate);
        }
        public JsonNode prove(String subset, Map<String, String> credentials, String account) throws Exception {
            var request = HttpRequest.newBuilder(url("protected/" + subset)).timeout(Duration.ofSeconds(3));
            if (credentials.containsKey("B")) request.header("Authorization", "Bearer " + credentials.get("B"));
            var cookies = new ArrayList<String>();
            for (String role : List.of("C1", "C2")) if (credentials.containsKey(role)) cookies.add("LAB_" + role + "=" + credentials.get(role));
            if (!cookies.isEmpty()) request.header("Cookie", String.join("; ", cookies));
            var response = http.send(request.GET().build(), HttpResponse.BodyHandlers.ofByteArray());
            assertEquals(200, response.statusCode(), "Extracted credentials must authenticate at the protected endpoint.");
            var identity = JSON.readTree(response.body()); assertEquals(account, identity.path("accountId").asText());
            assertFalse(identity.path("issuanceId").asText().isBlank());
            assertEquals(currentLoginIssuance(), identity.path("issuanceId").asText(), "An older login for the same account cannot satisfy this proof.");
            assertEquals(0, snapshot().path("counters").path("actions").asInt());
            protectedResults.add(Map.of("status",response.statusCode(),"account",identity.path("accountId").asText(),"issuance",identity.path("issuanceId").asText(),"roles",new java.util.TreeSet<>(credentials.keySet())));
            var safe = Map.of("invocationId", plan.path("invocationId").asText(), "fixtureRunId", runId(), "requirementId", id, "generation", generation,
                    "status", response.statusCode(), "accountId", identity.path("accountId").asText(), "issuanceId", identity.path("issuanceId").asText(),
                    "roles", new java.util.TreeSet<>(credentials.keySet()), "time", Instant.now().toString());
            Files.writeString(report.resolve("protected-proofs.jsonl"), JSON.writeValueAsString(safe) + "\n", StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
            return identity;
        }
        /** Sends the resolver's exact bytes so an HTTP client cannot normalize duplicated auth fields. */
        public JsonNode proveWire(byte[] wire, String subset, String account, String use) throws Exception {
            return proveWire(wire,subset,account,use,currentLoginIssuance());
        }
        /** A cached journey must retain its own completed login even after another journey logs in. */
        public JsonNode proveWire(byte[] wire, String subset, String account, String use,String expectedIssuance) throws Exception {
            URI endpoint = url("protected/" + subset);
            byte[] prefix = ("GET " + endpoint.getRawPath() + "?" + endpoint.getRawQuery() + " HTTP/1.1\r\n").getBytes(StandardCharsets.US_ASCII);
            assertTrue(wire.length >= prefix.length && java.util.Arrays.equals(prefix, java.util.Arrays.copyOf(wire, prefix.length)), "Proof must target this owned case.");
            byte[] received;
            try (var socket = new java.net.Socket()) {
                socket.connect(new java.net.InetSocketAddress(endpoint.getHost(), endpoint.getPort()), 3000); socket.setSoTimeout(3000);
                socket.getOutputStream().write(wire); socket.getOutputStream().flush();
                received = socket.getInputStream().readNBytes(65_537);
            }
            assertTrue(received.length <= 65_536, "Bounded fixture proof response required.");
            String response = new String(received, StandardCharsets.UTF_8);
            int split = response.indexOf("\r\n\r\n"); assertTrue(split > 0, "Fixture proof response must have HTTP framing.");
            int status = Integer.parseInt(response.substring(9, 12)); assertEquals(200, status, "Exact production request must authenticate.");
            var identity = JSON.readTree(response.substring(split + 4)); assertEquals(account, identity.path("accountId").asText());
            assertEquals(expectedIssuance, identity.path("issuanceId").asText(), "Exact production bytes must use this journey's login issuance.");
            assertEquals(0, snapshot().path("counters").path("actions").asInt());
            protectedResults.add(Map.of("status",status,"account",identity.path("accountId").asText(),"issuance",identity.path("issuanceId").asText(),"roles",identity.path("acceptedRoles")));
            var safe = Map.of("invocationId", plan.path("invocationId").asText(), "fixtureRunId", runId(), "requirementId", id, "generation", generation,
                    "status", status, "accountId", identity.path("accountId").asText(), "issuanceId", identity.path("issuanceId").asText(),
                    "roles", identity.path("acceptedRoles"), "use", use, "exactProductionBytes", true);
            Files.writeString(report.resolve("protected-proofs.jsonl"), JSON.writeValueAsString(safe) + "\n", StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
            return identity;
        }
        @Override public void close() throws Exception {
            if (closed) return;
            long closing=System.nanoTime();
            control("DELETE", "/cases/" + id + "?generation=" + generation, null, 200);
            var finalState=snapshot();assertEquals("CLOSED", finalState.path("state").asText()); closed = true;
            if(lab.auth.LabBrowserEvidence.supports(id)) {
                var observed=Map.<String,Object>of("sourceCase",id,"snapshot",finalState,"proofs",List.copyOf(protectedResults),"failures",List.copyOf(failureResults),"attempts",ProductionLabAdapter.resources(id));
                var timings=Map.of("startupMs",0L,"caseMs",TimeUnit.NANOSECONDS.toMillis(closing-began),"cleanupMs",TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-closing));
                component(id,observed,timings);
                if(id.equals("BROW.cookie-selection.idp-client-decoy"))component("BROW.cookie-selection.same-name-domains",observed,timings);
            }
        }
    }
    @Override public void close() throws Exception {
        Throwable failure = null;
        try {
            for (var value : cases) value.close();
            control("POST", "/stop", Map.of("generation", runGeneration), 202);
            assertTrue(process.waitFor(10, TimeUnit.SECONDS), "Owned target JVM must complete shutdown.");
            assertEquals(0, process.exitValue());
            assertEquals("CLOSED", JSON.readTree(Files.readAllBytes(descriptor)).path("state").asText());
        } catch (Throwable error) { failure = error; }
        finally {
            if (process.isAlive()) { process.destroy(); if (!process.waitFor(5, TimeUnit.SECONDS)) process.destroyForcibly(); }
            http.close(); controlKey = null;
        }
        if (failure != null) throw new AssertionError("Canonical target cleanup was incomplete.", failure);
    }
}
