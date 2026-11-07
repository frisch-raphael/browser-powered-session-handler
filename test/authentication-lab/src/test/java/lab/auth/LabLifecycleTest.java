package lab.auth;

import com.google.gson.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.net.*;
import java.net.http.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;
import static lab.auth.FixtureContractTest.*;

class LabLifecycleTest {
    @TempDir Path root;
    LabRun start() throws Exception { return LabRun.start(new LabRun.RunSpec(UUID.randomUUID(), List.of("all"), ScenarioCatalog.load(), root, List.of(), 5_000)); }
    @Test void heldLoginDoesNotBlockTheIndependentControlListener() throws Exception {
        try (var run = start(); var http = HttpClient.newHttpClient(); var lease = run.prepareCase("BROW.basic.json")) {
            lease.armFault(LabRun.FaultSpec.holdLogin("held-login"));
            var login = http.sendAsync(HttpRequest.newBuilder(lease.endpoint("login/json")).header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString("{\"username\":\"user\",\"password\":\"pass\"}")).build(), HttpResponse.BodyHandlers.ofString());
            lease.awaitCheckpoint("held-login", Duration.ofSeconds(2)); assertFalse(login.isDone());
            var snapshot = control(http, run, "/cases/" + lease.id() + "/snapshot?generation=" + lease.generation(), "GET", null);
            assertEquals(200, snapshot.statusCode()); assertEquals("RUNNING", json(snapshot).get("state").getAsString());
            var release = control(http, run, "/cases/" + lease.id() + "/gates/held-login/release", "POST", Map.of("generation", lease.generation()));
            assertEquals(200, release.statusCode()); assertEquals(200, login.get(2, TimeUnit.SECONDS).statusCode());
            assertEquals(200, control(http, run, "/cases/" + lease.id() + "/gates/held-login/release", "POST", Map.of("generation", lease.generation())).statusCode());
        }
    }
    @Test void resetRetiresHeldWorkBeforeReopeningAndRejectsOldCaseMutationsAndUrls() throws Exception {
        try (var run = start(); var http = HttpClient.newHttpClient()) {
            var old = run.prepareCase("BROW.basic.json"); URI oldUrl = old.endpoint("login/json");
            String oldCredential = old.seeded("s0").credential(FixtureIdentityStore.Role.B).reveal();
            old.armFault(LabRun.FaultSpec.holdLogin("reset-held"));
            var pending = http.sendAsync(HttpRequest.newBuilder(oldUrl).header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString("{\"username\":\"user\",\"password\":\"pass\"}")).build(), HttpResponse.BodyHandlers.ofString());
            old.awaitCheckpoint("reset-held", Duration.ofSeconds(2));
            long originalGeneration=run.generation();
            var before=json(control(http,run,"/targets?generation="+originalGeneration,"GET",null));
            assertTrue(before.get("federation").isJsonNull(),"An ordinary run must not advertise provider endpoints.");
            assertEquals(old.generation(),before.getAsJsonArray("cases").get(0).getAsJsonObject().get("generation").getAsLong());
            assertEquals(200, control(http, run, "/reset", "POST", Map.of("generation", run.generation())).statusCode());
            assertEquals(409,control(http,run,"/targets?generation="+originalGeneration,"GET",null).statusCode());
            assertTrue(json(control(http,run,"/targets?generation="+run.generation(),"GET",null)).getAsJsonArray("cases").isEmpty());
            assertEquals(410, pending.get(2, TimeUnit.SECONDS).statusCode());
            assertEquals(410, assertThrows(LabRun.ControlException.class, () -> old.advanceFixtureClock(Duration.ofSeconds(1))).status());
            try (var replacement = run.prepareCase(old.id())) {
                assertTrue(replacement.generation() > old.generation());
                assertFalse(oldCredential.equals(replacement.seeded("s0").credential(FixtureIdentityStore.Role.B).reveal()));
                assertEquals(409, send(http, oldUrl, "POST", "{\"username\":\"user\",\"password\":\"pass\"}", "application/json").statusCode());
                assertEquals(200, send(http, replacement.endpoint("login/json"), "POST", "{\"username\":\"user\",\"password\":\"pass\"}", "application/json").statusCode());
                assertEquals(0L, counters(replacement).get("actions"));
            }
        }
    }
    @Test void delayedHttpCaseCreationCannotAllocateInANewerResetGeneration() throws Exception {
        try (var run = start(); var http = HttpClient.newHttpClient()) {
            long before = run.generation(); var delayed = Map.of("caseId", "BROW.basic.json", "runGeneration", before);
            assertEquals(before + 1, run.reset(before));
            assertEquals(409, control(http, run, "/cases", "POST", delayed).statusCode()); assertEquals(0, run.cases().size());
            assertEquals(400, control(http, run, "/cases", "POST", Map.of("caseId", "BROW.basic.json")).statusCode());
            assertEquals(201, control(http, run, "/cases", "POST", Map.of("caseId", "BROW.basic.json", "runGeneration", run.generation())).statusCode()); assertEquals(1, run.cases().size());
        }
    }
    @Test void typedCreationCapturesItsVersionBeforeWaitingForTheResetLock() throws Exception {
        try (var run = start()) {
            var outcome = new AtomicReference<Throwable>(); Thread worker;
            synchronized (run) {
                worker = Thread.ofPlatform().start(() -> { try { run.prepareCase("BROW.basic.json"); } catch (Throwable ex) { outcome.set(ex); } });
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
                while (worker.getState() != Thread.State.BLOCKED && System.nanoTime() < deadline) Thread.onSpinWait();
                assertEquals(Thread.State.BLOCKED, worker.getState(), "Creation must be waiting after reading its old version.");
                run.reset(run.generation());
            }
            worker.join(2000); assertFalse(worker.isAlive());
            assertInstanceOf(LabRun.ControlException.class, outcome.get()); assertEquals("GENERATION_CONFLICT", ((LabRun.ControlException) outcome.get()).code());
            assertEquals(0, run.cases().size());
        }
    }
    @Test void controlsRequireTheirPrivateKeyStrictBodiesAndMatchingGenerations() throws Exception {
        try (var run = start(); var http = HttpClient.newHttpClient(); var lease = run.prepareCase("BROW.basic.json")) {
            var unauthorized = send(http, URI.create(run.controlUri() + "/reset"), "POST", "{\"generation\":1}", "application/json"); assertEquals(401, unauthorized.statusCode());
            assertFalse(unauthorized.body().contains(run.controlKey().reveal())); assertTrue(unauthorized.headers().firstValue("Access-Control-Allow-Origin").isEmpty());
            assertEquals(401,send(http,URI.create(run.controlUri()+"/targets?generation="+run.generation()),"GET",null,null).statusCode());
            assertEquals(409, control(http, run, "/cases/" + lease.id() + "/clock", "POST", Map.of("generation", lease.generation() + 1, "advanceMs", 1)).statusCode());
            assertEquals(400, control(http, run, "/cases/" + lease.id() + "/clock", "POST", Map.of("generation", lease.generation(), "advanceMs", -1)).statusCode());
            long clockCheckStarted = System.nanoTime();
            long before = json(control(http, run, "/cases/" + lease.id() + "/clock", "POST", Map.of("generation", lease.generation(), "advanceMs", 0))).get("fixtureTimeMs").getAsLong();
            assertEquals(400, control(http, run, "/cases/" + lease.id() + "/clock", "POST", Map.of("generation", lease.generation(), "advanceMs", Long.MAX_VALUE)).statusCode());
            long after = json(control(http, run, "/cases/" + lease.id() + "/clock", "POST", Map.of("generation", lease.generation(), "advanceMs", 0))).get("fixtureTimeMs").getAsLong();
            assertTrue(after >= before && after - before <= (System.nanoTime() - clockCheckStarted) / 1_000_000 + 1, "Rejected overflow cannot alter the clock beyond real elapsed time.");
            assertEquals(404, control(http, run, "/cases/" + lease.id() + "/clock/unreviewed", "POST", Map.of("generation", lease.generation(), "advanceMs", 1)).statusCode());
            var oversized = http.send(HttpRequest.newBuilder(URI.create(run.controlUri() + "/reset")).header("Authorization", "Bearer " + run.controlKey().reveal()).header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString("x".repeat(65_537))).build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(413, oversized.statusCode());
            var publicControl = send(http, run.applicationUri().resolve("/control/v1/runs/" + run.runId() + "/reset"), "POST", "{\"generation\":1}", "application/json"); assertEquals(404, publicControl.statusCode());
        }
    }
    @Test void freshCookiePhasesNeedPositivePrimingAndALoginBeforeTheUnchangedProbeEntry() throws Exception {
        try (var run = start(); var http = HttpClient.newHttpClient(); var lease = run.prepareCase("BROW.fresh.cookies")) {
            URI unchanged = lease.endpoint("fresh/cookies/start");
            assertEquals(409, send(http, unchanged, "GET", null, null).statusCode());
            assertThrows(LabRun.ControlException.class, () -> lease.selectFreshPhase(LabRun.FreshPhase.PROBE));
            lease.selectFreshPhase(LabRun.FreshPhase.PRIME); lease.selectFreshPhase(LabRun.FreshPhase.PRIME);
            URI primePage;
            try (var browser = browser()) {
                var entry = send(browser, unchanged, "GET", null, null); primePage = URI.create(entry.headers().firstValue("Location").orElseThrow());
                var page = send(browser, primePage, "GET", null, null); assertTrue(page.headers().allValues("Set-Cookie").stream().anyMatch(v -> v.startsWith("LAB_FRESH_MARK=")));
                assertEquals(409, send(browser, action(page), "POST", "username=user&password=pass", "application/x-www-form-urlencoded").statusCode());
                assertFalse(json(send(http, lease.endpoint("fresh/cookies/observe"), "POST", "{\"phase\":\"PRIME\",\"present\":true}", "application/json")).get("present").getAsBoolean());
                assertThrows(LabRun.ControlException.class, () -> lease.selectFreshPhase(LabRun.FreshPhase.PROBE));
                assertTrue(json(send(browser, lease.endpoint("fresh/cookies/observe"), "POST", "{\"phase\":\"PRIME\",\"present\":true}", "application/json")).get("present").getAsBoolean());
                assertThrows(LabRun.ControlException.class, () -> lease.selectFreshPhase(LabRun.FreshPhase.PROBE));
                assertEquals(200, send(browser, action(page), "POST", "username=user&password=pass", "application/x-www-form-urlencoded").statusCode());
                assertEquals(primePage, URI.create(send(browser, unchanged, "GET", null, null).headers().firstValue("Location").orElseThrow()));
            }
            // Closing this HTTP client is not claimed as a production BrowserContext witness.
            lease.selectFreshPhase(LabRun.FreshPhase.PROBE); lease.selectFreshPhase(LabRun.FreshPhase.PROBE);
            assertEquals(409, send(http, primePage, "GET", null, null).statusCode());
            var entry = send(http, unchanged, "GET", null, null); URI probe = URI.create(entry.headers().firstValue("Location").orElseThrow()); assertTrue(probe.getPath().endsWith("/probe"));
            var page = send(http, probe, "GET", null, null); assertTrue(page.headers().allValues("Set-Cookie").isEmpty());
            assertFalse(json(send(http, lease.endpoint("fresh/cookies/observe"), "POST", "{\"phase\":\"PROBE\",\"present\":false}", "application/json")).get("present").getAsBoolean());
            assertEquals(200, send(http, action(page), "POST", "username=user&password=pass", "application/x-www-form-urlencoded").statusCode());
            assertThrows(LabRun.ControlException.class, () -> lease.selectFreshPhase(LabRun.FreshPhase.PRIME));
        }
    }
    @Test void completionAndSnapshotsNeverPretendUnobservedBrowserFactsOrExposeCredentials() throws Exception {
        var run = start(); String controlKey = run.controlKey().reveal(); Path directory = run.directory();
        var secrets = new ArrayList<String>();
        try (run; var lease = run.prepareCase("BROW.basic.json")) {
            for (var role : FixtureIdentityStore.Role.values()) secrets.add(lease.seeded("s0").credential(role).reveal());
            for (int i = 0; i < 10_005; i++) lease.event(LabRun.Phase.LOGIN, "safe-event", List.of());
            var snapshot = lease.snapshot(); assertEquals(true, snapshot.get("truncated")); assertEquals(10_000, ((List<?>) snapshot.get("events")).size());
            assertNull(counters(lease).get("connections")); assertNull(counters(lease).get("applicationBytes"));
            String safe = LabRun.JSON.toJson(snapshot); assertFalse(safe.contains(controlKey)); for (String secret : secrets) assertFalse(safe.contains(secret));
            assertEquals("[redacted]", lease.seeded("s0").credential(FixtureIdentityStore.Role.B).toString());
        }
        String report = Files.readString(directory.resolve("report.jsonl")); assertFalse(report.contains(controlKey)); for (String secret : secrets) assertFalse(report.contains(secret));
        var completion = JsonParser.parseString(report.lines().reduce((a, b) -> b).orElseThrow()).getAsJsonObject(); assertEquals("RUN_COMPLETED", completion.get("type").getAsString());
        assertFalse(completion.getAsJsonObject("data").get("complete").getAsBoolean()); assertEquals(0, completion.getAsJsonObject("data").getAsJsonObject("outcomes").get("PASS").getAsInt());
        assertEquals("CLOSED", JsonParser.parseString(Files.readString(directory.resolve("run.json"))).getAsJsonObject().get("state").getAsString());
    }
    @Test void retiringTheCaseAlsoClosesItsOwnedRawListener() throws Exception {
        try (var run = start(); var lease = run.prepareCase("FIX.extra.generator-witness")) {
            var sentinel = lease.openSentinel(null); var address = sentinel.address();
            try (var socket = new java.net.Socket()) { socket.connect(address); socket.getOutputStream().write(new byte[]{1, 2}); socket.shutdownOutput(); }
            sentinel.await(s -> s.applicationBytes() == 2, Duration.ofSeconds(2)); assertEquals(2L, counters(lease).get("applicationBytes"));
            lease.close(); try (var socket = new java.net.Socket()) { assertThrows(java.io.IOException.class, () -> socket.connect(address, 1000)); }
        }
    }
    @Test void acknowledgedStopRetainsTheTerminalRecordBeforePublishingClosedState() throws Exception {
        try (var run = start(); var http = HttpClient.newHttpClient()) {
            assertEquals(202, control(http, run, "/stop", "POST", Map.of("generation", run.generation())).statusCode());
            var finished = CompletableFuture.runAsync(() -> { try { run.awaitStop(); } catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new CompletionException(ex); } });
            finished.get(8, TimeUnit.SECONDS);
            var descriptor = JsonParser.parseString(Files.readString(run.directory().resolve("run.json"))).getAsJsonObject(); assertEquals("CLOSED", descriptor.get("state").getAsString());
            var lines = Files.readAllLines(run.directory().resolve("report.jsonl")); var terminal = JsonParser.parseString(lines.getLast()).getAsJsonObject();
            assertEquals("RUN_COMPLETED", terminal.get("type").getAsString()); assertEquals("COMPLETE", terminal.getAsJsonObject("data").get("cleanupOutcome").getAsString());
        }
    }
    @TestFactory java.util.stream.Stream<DynamicTest> reportJoinRejectsIncompleteForeignSkippedDuplicatedOrContradictoryEvidence() {
        return java.util.stream.Stream.of("partial-valid", "skipped", "failed", "foreign-failed", "duplicate-xml", "missing-observation", "foreign-invocation", "wrong-case-revision", "wrong-config", "wrong-artifact", "wrong-catalog", "contradictory-status").map(mode -> DynamicTest.dynamicTest(mode, () -> {
            Path workspace = Path.of(System.getProperty("user.dir")).toAbsolutePath();
            while (workspace != null && !Files.isRegularFile(workspace.resolve("bapp/settings.gradle.kts"))) workspace = workspace.getParent();
            assertNotNull(workspace);
            var row = ScenarioCatalog.load().requirement("FIX.matrix.required=b~b=s0"); assertNotNull(row.binding());
            String invocation = UUID.randomUUID().toString(), task = ":auth-lab:test";
            Path directory = root.resolve(invocation).resolve(LabEvidence.sha256(task.getBytes(StandardCharsets.UTF_8))); Files.createDirectories(directory.resolve("junit-xml")); Files.createDirectory(directory.resolve("observations"));
            Path artifact = root.resolve(invocation).resolve("fixture-artifact.jar"); Files.writeString(artifact, "controlled unit fixture; not an executed product artifact");
            var context = new LinkedHashMap<String, Object>(); context.put("contextVersion", 1); context.put("invocationId", invocation); context.put("taskPath", task);
            context.put("configurationHash", Set.of("wrong-config", "foreign-failed").contains(mode) ? "0".repeat(64) : LabEvidence.configurationFingerprint(workspace)); context.put("productionRevision", null);
            context.put("artifactSha256", mode.equals("wrong-artifact") ? "0".repeat(64) : LabEvidence.sha256(Files.readAllBytes(artifact)));
            context.put("catalogRevision", mode.equals("wrong-catalog") ? "0".repeat(64) : LabEvidence.catalogFingerprint(workspace)); context.put("state", "COMPLETED");
            Files.writeString(directory.resolve("report-context.json"), LabRun.JSON.toJson(context));
            String test = "<testcase classname=\"lab.auth.FixtureContractTest\" name=\"" + row.binding().xmlCaseName() + "\">" + (mode.equals("skipped") ? "<skipped/>" : Set.of("failed", "foreign-failed").contains(mode) ? "<failure/>" : "") + "</testcase>";
            Files.writeString(directory.resolve("junit-xml/TEST-unit.xml"), "<testsuite>" + test + (mode.equals("duplicate-xml") ? test : "") + "</testsuite>");
            var capture = new LinkedHashMap<String, Object>(); capture.put("captureVersion", 1); capture.put("invocationId", mode.equals("foreign-invocation") ? UUID.randomUUID().toString() : invocation); capture.put("taskPath", task); capture.put("requirementId", row.id()); capture.put("caseRevision", mode.equals("wrong-case-revision") ? 2 : 1);
            capture.put("observed", List.of(new ScenarioCatalog.Fact("httpStatus", mode.equals("contradictory-status") ? "401" : "200"), new ScenarioCatalog.Fact("account", "user"), new ScenarioCatalog.Fact("issuance", "s0"), new ScenarioCatalog.Fact("actions", "0"))); capture.put("cleanup", "COMPLETE"); capture.put("startupMs", 0); capture.put("caseMs", 1); capture.put("cleanupMs", 0);
            if (!mode.equals("missing-observation")) Files.writeString(directory.resolve("observations/" + LabEvidence.sha256(row.id().getBytes(StandardCharsets.UTF_8)) + ".json"), LabRun.JSON.toJson(capture));
            assertFalse(LabEvidence.collectFixtures(directory, workspace, artifact), "One matching case cannot pass the remaining active fixture selection.");
            var records = Files.readAllLines(directory.resolve("report.jsonl")).stream().map(line -> JsonParser.parseString(line).getAsJsonObject()).toList();
            var result = records.stream().filter(r -> r.get("type").getAsString().equals("CASE_RESULT") && r.getAsJsonObject("data").getAsJsonArray("requirementIds").get(0).getAsString().equals(row.id())).findFirst().orElseThrow().getAsJsonObject("data");
            assertEquals(mode.equals("partial-valid") ? "PASS" : mode.equals("failed") ? "FAIL" : "BLOCKED", result.get("outcome").getAsString());
            assertFalse(records.getLast().getAsJsonObject("data").get("complete").getAsBoolean());
        }));
    }
    static HttpResponse<String> control(HttpClient http, LabRun run, String path, String method, Object body) throws Exception {
        var request = HttpRequest.newBuilder(URI.create(run.controlUri() + path)).timeout(Duration.ofSeconds(3)).header("Authorization", "Bearer " + run.controlKey().reveal());
        if (body != null) request.header("Content-Type", "application/json");
        return http.send(request.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(LabRun.JSON.toJson(body))).build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test void federationPortTupleStaysExclusiveAfterOneSocketIsHandedToItsChild() throws Exception {
        Path leases=root.resolve("port-leases");var runId=UUID.randomUUID();
        var first=FederationEnvironment.PortLease.reserve(leases,runId);var ports=first.ports;
        try(first;var second=FederationEnvironment.PortLease.reserve(leases,UUID.randomUUID(),true)) {
            assertTrue(second.ports.upstream()>0);
            first.handoff(ports.downstream());
            try(var third=FederationEnvironment.PortLease.reserve(leases,UUID.randomUUID())) {
                var leased=Set.of(ports.client(),ports.resource(),ports.downstream());
                for(int port:List.of(second.ports.client(),second.ports.resource(),second.ports.downstream(),second.ports.upstream(),third.ports.client(),third.ports.resource(),third.ports.downstream()))assertFalse(leased.contains(port));
            }
            try(var child=new java.net.ServerSocket()) {child.bind(new java.net.InetSocketAddress("127.0.0.1",ports.downstream()));}
        }
        for(int port:List.of(ports.client(),ports.resource(),ports.downstream())) {
            try(var listener=new java.net.ServerSocket();var channel=java.nio.channels.FileChannel.open(leases.resolve("port-"+port+".lock"),StandardOpenOption.WRITE);var lock=channel.tryLock()) {
                assertNotNull(lock);listener.bind(new java.net.InetSocketAddress("127.0.0.1",port));
            }
        }
    }

    @Test void federationSeedRendersOwnedPortsCallbacksAndSeparateClientSecrets() throws Exception {
        Path workspace=Path.of(System.getProperty("user.dir")).toAbsolutePath();while(workspace!=null&&!Files.isRegularFile(workspace.resolve("bapp/settings.gradle.kts")))workspace=workspace.getParent();assertNotNull(workspace);
        var template=ScenarioCatalog.parseJson(Files.readAllBytes(workspace.resolve("test/federation-client/src/main/resources/provider/downstream-realm.json"))).getAsJsonObject();
        var secrets=new LinkedHashMap<String,FixtureIdentityStore.Secret>();for(String id:List.of("backend-client","wrong-client-control","wrong-audience-client"))secrets.put(id,FixtureIdentityStore.randomSecret());
        var realm=FederationEnvironment.renderRealm(template,new FederationEnvironment.Ports(41001,41002,41003),secrets);
        assertEquals(3,realm.getAsJsonArray("users").size());var accounts=new HashSet<String>();for(var user:realm.getAsJsonArray("users"))assertTrue(accounts.add(user.getAsJsonObject().get("id").getAsString()));
        var clients=new HashMap<String,JsonObject>();for(var item:realm.getAsJsonArray("clients")){var client=item.getAsJsonObject();assertNull(clients.put(client.get("clientId").getAsString(),client));}
        assertEquals(Set.of("browser-client","backend-client","cookie-verifier","wrong-client-control","wrong-audience-client","authlab-api","https://app.authlab.test:41001/saml/metadata"),clients.keySet());
        for(String id:List.of("browser-client","cookie-verifier","backend-client","wrong-client-control","wrong-audience-client")) {
            var client=clients.get(id);
            assertEquals(List.of("https://app.authlab.test:41001"),client.getAsJsonArray("webOrigins").asList().stream().map(JsonElement::getAsString).toList());
            for(var callback:client.getAsJsonArray("redirectUris"))assertFalse(callback.getAsString().contains("*"));
            if(secrets.containsKey(id))assertTrue(java.security.MessageDigest.isEqual(secrets.get(id).reveal().getBytes(StandardCharsets.UTF_8),client.get("secret").getAsString().getBytes(StandardCharsets.UTF_8)),"Each confidential client retains its own private secret.");
        }
        assertEquals(List.of("https://app.authlab.test:41001/login/oauth2/code/backend","https://app.authlab.test:41001/login/oauth2/code/backend-control"),clients.get("backend-client").getAsJsonArray("redirectUris").asList().stream().map(JsonElement::getAsString).toList());
        assertEquals("https://app.authlab.test:41001/login/saml2/sso/keycloak",clients.get("https://app.authlab.test:41001/saml/metadata").getAsJsonArray("redirectUris").get(0).getAsString());
        var altered=template.deepCopy();altered.getAsJsonArray("clients").add(template.getAsJsonArray("clients").get(0).deepCopy());
        assertThrows(java.io.IOException.class,()->FederationEnvironment.renderRealm(altered,new FederationEnvironment.Ports(41001,41002,41003),secrets));
    }
}
