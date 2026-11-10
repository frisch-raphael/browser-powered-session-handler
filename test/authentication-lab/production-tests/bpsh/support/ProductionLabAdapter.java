package bpsh.support;

import bpsh.journey.persistence.JourneyDocument;
import bpsh.journey.persistence.JourneyJson;

import bpsh.browser.BrowserAuthentication;
import bpsh.browser.BrowserFlowRunner;
import bpsh.browser.BrowserJourneyIntegrationTest;
import bpsh.request.RequestSettings;
import bpsh.journey.persistence.ProjectStore;
import bpsh.journey.editing.JourneyWorkspace;
import bpsh.authentication.credentials.AuthenticationResult;
import bpsh.authentication.credentials.TokenExtractor;
import bpsh.burp.http.NativeTagResolver;
import bpsh.journey.AuthStep;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.JourneyKey;
import bpsh.journey.SecretStore;
import bpsh.authentication.session.AuthenticationCoordinator;
import bpsh.authentication.session.CoordinatorFixtures;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

/** Builds real native definitions and calls the existing runner; contains no login/recovery engine. */
public final class ProductionLabAdapter {
    public static final RequestSettings.Controls CONTROLS = RequestSettings.Controls.defaults();
    public record AttemptResources(long contextId, int contextsClosed, int browsersOpened, int browsersClosed, int drivers, int observedProcesses, long alive) {}
    private static final Map<String, List<AttemptResources>> RESOURCES = new ConcurrentHashMap<>();
    public static List<AttemptResources> resources(String id) { return List.copyOf(RESOURCES.getOrDefault(id, List.of())); }
    private ProductionLabAdapter() {}
    private static final ThreadLocal<String> PROCESS_INPUT = new ThreadLocal<>();
    public @FunctionalInterface interface ProcessInput { public void run() throws Exception; }
    public static BrowserProcesses beginProcessObservation(String input) {
        var processes=new BrowserProcesses();PROCESS_INPUT.set(input);return processes;
    }
    public static org.junit.jupiter.api.DynamicTest processCase(String input,int expectedDrivers,ProcessInput body) {
        return org.junit.jupiter.api.DynamicTest.dynamicTest("[case="+input+"]",()->{
            var processes=beginProcessObservation(input);Throwable primary=null;
            try{body.run();}catch(Exception|Error failure){primary=failure;throw failure;}
            finally{try{finishProcessObservation(input,processes,expectedDrivers);}catch(Exception|Error cleanup){if(primary!=null)primary.addSuppressed(cleanup);else throw cleanup;}}
        });
    }
    public static void finishProcessObservation(String input,BrowserProcesses processes,int expectedDrivers) throws Exception {
        long cleanupBegan=System.nanoTime();boolean cleaned=false;
        try{processes.close();cleaned=true;}
        finally {
            try {
                var capture=processEnvelope(input,Map.of("drivers",processes.drivers(),"processes",processes.processes(),"alive",processes.alive()));
                capture.put("cleanup",cleaned&&processes.alive()==0?"COMPLETE":"INCOMPLETE");
                capture.put("timings",Map.of("startupMs",0,"caseMs",TimeUnit.NANOSECONDS.toMillis(cleanupBegan-processes.began),"cleanupMs",TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-cleanupBegan)));
                writeProcessCapture("process-observations",digest(input),capture);
            }finally{PROCESS_INPUT.remove();}
        }
        if(expectedDrivers>0)processes.requireObserved(expectedDrivers);else assertEquals(0,processes.drivers(),"This setup/picker operation must not launch a browser.");
    }
    public static void retainProcessFacts(String label,Map<String,Object> facts) throws Exception {
        String input=java.util.Objects.requireNonNull(PROCESS_INPUT.get(),"Facts need their actual executing input scope.");
        var capture=processEnvelope(input,facts);capture.put("label",label);writeProcessCapture("transport-observations",label,capture);
    }
    private static java.util.LinkedHashMap<String,Object> processEnvelope(String input,Map<String,?> facts) throws Exception {
        var plan=AuthLabSupport.JSON.readTree(Files.readAllBytes(java.nio.file.Path.of(System.getProperty("authlab.plan"))));
        var capture=new java.util.LinkedHashMap<String,Object>();capture.put("version",1);capture.put("input",input);
        capture.put("invocationId",plan.path("invocationId").asText());capture.put("taskPath",":"+plan.path("taskName").asText());
        capture.put("productionRevision",plan.path("productionRevision").asText());capture.put("configurationHash",plan.path("configurationHash").asText());capture.put("observed",facts);return capture;
    }
    private static String digest(String value) throws Exception {
        return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    }
    private static void writeProcessCapture(String directory,String name,Map<String,Object> capture) throws Exception {
        var plan=AuthLabSupport.JSON.readTree(Files.readAllBytes(java.nio.file.Path.of(System.getProperty("authlab.plan"))));
        var path=java.nio.file.Path.of(plan.path("reportDirectory").asText()).resolve(directory);Files.createDirectories(path);
        Files.writeString(path.resolve(name+".json"),AuthLabSupport.JSON.writeValueAsString(capture),java.nio.file.StandardOpenOption.CREATE_NEW);
    }
    /** Shared actual-process witness for production journeys and explicit credential-verifier browsers. */
    public static final class BrowserProcesses extends BrowserProcessWitness { }
    public static final class Prepared implements AutoCloseable {
        public final JourneyDefinition definition;
        public final SecretStore.Values values;
        public Prepared(JourneyDefinition definition, SecretStore.Values values) { this.definition = definition; this.values = values; }
        @Override public void close() { values.close(); }
    }
    public record LoginTarget(String id,long generation,URI application,URI alternate) {
        public URI url(String route){return url(route,false);}
        public URI url(String route,boolean other){return (other?alternate:application).resolve("/cases/"+id+"/"+route+(route.contains("?")?"&":"?")+"generation="+generation);}
        public String cookiePath(){return "/cases/"+id;}
    }
    public record LoginDefinition(JourneyDefinition journey,UUID secureInput) {}
    public static JourneyDefinition certificateDefinition(URI start,URI issuer,JourneyDefinition.Mtls mtls,URI proxy,String alias) {
        return new JourneyDefinition(UUID.randomUUID(),"Controlled certificate login",alias,start,false,List.of(),
                new JourneyDefinition.Browser(true,proxy==null?null:new JourneyDefinition.Proxy(proxy),15_000,15_000),new JourneyDefinition.JsonExtraction(issuer,"/token","access_token"),
                JourneyDefinition.Injection.perToken(List.of(new JourneyDefinition.TokenInjection(null,JourneyDefinition.InjectionType.BEARER,null))),new JourneyDefinition.Cache(60,10),mtls);
    }
    public static Prepared login(AuthLabSupport targets, AuthLabSupport.Case target, List<String> roles, String account, String password) throws Exception {
        var input=new LoginTarget(target.id,target.generation,TokenExtractor.origin(target.url("")),TokenExtractor.origin(target.url("",true)));
        var built=loginDefinition(input,roles,account,"fixture");var journey=built.journey();
        writeExample(targets,target.id,export(journey));
        Files.writeString(targets.report.resolve("execution-settings.jsonl"), AuthLabSupport.JSON.writeValueAsString(Map.of(
                "requirementId", target.id, "generation", target.generation, "requestWaitTimeoutMs", CONTROLS.requestWaitTimeoutMs(),
                "attemptTimeoutMs", CONTROLS.attemptTimeoutMs(), "cycleTimeoutMs", CONTROLS.cycleTimeoutMs(),
                "navigationTimeoutMs", journey.browser().navigationTimeoutMs(), "tokenWaitTimeoutMs", journey.browser().tokenWaitTimeoutMs(),
                "observationBudgetMs", (long) CONTROLS.cycleTimeoutMs() + 30_000)) + "\n", StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        return new Prepared(journey,new SecretStore.Values(null,Map.of(built.secureInput(),password.toCharArray())));
    }
    /** The same native definition builder serves operational tests and live manual exports. */
    public static LoginDefinition loginDefinition(LoginTarget target,List<String> roles,String account,String alias) throws Exception {
        var steps = new ArrayList<AuthStep.Definition>();
        boolean fresh = target.id.startsWith("BROW.fresh.");
        if (fresh) steps.add(BrowserJourneyIntegrationTest.step(AuthStep.Type.WAIT_SELECTOR, "#fresh-check-complete", null));
        steps.add(BrowserJourneyIntegrationTest.step(AuthStep.Type.WAIT_SELECTOR, "#user", null));
        steps.add(BrowserJourneyIntegrationTest.step(AuthStep.Type.INPUT, "#user", account));
        if (target.id.endsWith("two-page")) {
            steps.add(BrowserJourneyIntegrationTest.step(AuthStep.Type.CLICK, "#next", null));
            steps.add(BrowserJourneyIntegrationTest.step(AuthStep.Type.WAIT_SELECTOR, "#pass", null));
        }
        var secure = BrowserJourneyIntegrationTest.step(AuthStep.Type.SECURE_INPUT, "#pass", null); steps.add(secure);
        steps.add(BrowserJourneyIntegrationTest.step(AuthStep.Type.CLICK, "#login", null));
        if (fresh) steps.add(BrowserJourneyIntegrationTest.step(AuthStep.Type.WAIT_SELECTOR, "#login-complete", null));
        if (target.id.endsWith("interstitial")) steps.add(BrowserJourneyIntegrationTest.step(AuthStep.Type.CLICK, "#consent", null));
        boolean surface = target.id.startsWith("BROW.surfaces.");
        if (surface) {
            steps.add(BrowserJourneyIntegrationTest.step(AuthStep.Type.CLICK, "#surface-entry", null));
            steps.add(BrowserJourneyIntegrationTest.step(AuthStep.Type.WAIT_SELECTOR, "#ready", null));
            if (!target.id.endsWith("early-response")) steps.add(BrowserJourneyIntegrationTest.step(AuthStep.Type.CLICK,
                    target.id.endsWith("popup") ? "#open-popup" : target.id.endsWith("frame") ? "#load-frame" : "#fetch-token", null));
            if (target.id.endsWith("popup") || target.id.endsWith("frame")) steps.add(BrowserJourneyIntegrationTest.step(AuthStep.Type.WAIT_SELECTOR, "#done", null));
            if (target.id.endsWith("cors-fetch")) {
                steps.add(BrowserJourneyIntegrationTest.step(AuthStep.Type.WAIT_SELECTOR, "#cors-done", null));
                steps.add(BrowserJourneyIntegrationTest.step(AuthStep.Type.WAIT_SELECTOR, "#cors-denied", null));
            }
        }
        var named = new ArrayList<JourneyDefinition.NamedExtraction>();
        for (String role : roles) {
            JourneyDefinition.Extraction selector = role.equals("B")
                    ? new JourneyDefinition.JsonExtraction(TokenExtractor.origin(target.url("")), "/cases/" + target.id + (target.id.endsWith("javascript") ? "/login/json" : "/outputs"), "access_token")
                    : new JourneyDefinition.CookieExtraction(target.url("protected/"), "LAB_" + role, "127.0.0.1", target.cookiePath());
            if (target.id.endsWith("deep-link")) selector = new JourneyDefinition.CookieExtraction(target.url("protected/"), "LAB_B", "127.0.0.1", target.cookiePath());
            named.add(new JourneyDefinition.NamedExtraction(name(role), selector));
        }
        if (surface) {
            String path = "/cases/" + target.id + (target.id.endsWith("service-worker") ? "/surface/sw/token" : "/surface/token");
            var selector = new JourneyDefinition.JsonExtraction(TokenExtractor.origin(target.url("", target.id.endsWith("cors-fetch"))), path,
                    target.id.endsWith("nested-json") ? "result.authentication.access_token" : "data.access_token");
            named.clear(); named.add(new JourneyDefinition.NamedExtraction(name("B"), selector));
        }
        JourneyDefinition.Extraction extraction = named.size() == 1 ? named.getFirst().selector() : new JourneyDefinition.CombinedExtraction(named);
        if (target.id.endsWith("ambiguous")) extraction = new JourneyDefinition.CookieExtraction(target.url("protected/"), "LAB_C1", null, null);
        var injection = JourneyDefinition.Injection.perToken(roles.contains("B") && !target.id.endsWith("deep-link")
                ? List.of(new JourneyDefinition.TokenInjection(roles.size() == 1 ? null : name("B"), JourneyDefinition.InjectionType.BEARER, null)) : List.of());
        URI start = fresh ? target.url("fresh/" + target.id.substring("BROW.fresh.".length()) + "/start") : target.url("start");
        var journey = new JourneyDefinition(UUID.randomUUID(), "Controlled " + target.id, alias, start, false, steps,
                new JourneyDefinition.Browser(true, null, 5_000, 1_500), extraction, injection, new JourneyDefinition.Cache(1800, 10), null);
        return new LoginDefinition(journey,secure.id());
    }
    /** Shared real-provider definition, with no provider client or authentication implementation. */
    public static LoginDefinition federationDefinition(URI clientOrigin,URI issuer,URI upstreamIssuer,String mode,String account,String completion,String alias) throws Exception {
        if(!List.of("browser","backend","saml","broker").contains(mode)||mode.equals("broker")&&upstreamIssuer==null)throw new IllegalArgumentException("Unprepared federation definition.");
        boolean backend=mode.equals("backend")||mode.equals("saml");
        var secure=BrowserJourneyIntegrationTest.step(AuthStep.Type.SECURE_INPUT,"#password",null);
        var steps=new ArrayList<AuthStep.Definition>();
        if(mode.equals("broker"))steps.add(BrowserJourneyIntegrationTest.step(AuthStep.Type.WAIT_URL,null,upstreamIssuer+"/**"));
        steps.addAll(List.of(BrowserJourneyIntegrationTest.step(AuthStep.Type.WAIT_SELECTOR,"#username",null),
                BrowserJourneyIntegrationTest.step(AuthStep.Type.INPUT,"#username",account),secure,
                BrowserJourneyIntegrationTest.step(AuthStep.Type.CLICK,"#kc-login",null),
                BrowserJourneyIntegrationTest.step(AuthStep.Type.WAIT_SELECTOR,completion,null)));
        JourneyDefinition.Extraction cookie=new JourneyDefinition.CookieExtraction(URI.create(clientOrigin+"/me"),"LAB_CLIENT","app.authlab.test","/");
        var outputs=new ArrayList<JourneyDefinition.NamedExtraction>(List.of(
                new JourneyDefinition.NamedExtraction("bearer",new JourneyDefinition.JsonExtraction(TokenExtractor.origin(issuer),"/protocol/openid-connect/token","access_token")),
                new JourneyDefinition.NamedExtraction("client",cookie)));
        if(!mode.equals("broker"))outputs.add(new JourneyDefinition.NamedExtraction("idp",new JourneyDefinition.CookieExtraction(URI.create(issuer+"/protocol/openid-connect/auth"),"KEYCLOAK_IDENTITY","idp.federation.test","/realms/authlab-downstream/")));
        if(mode.equals("broker"))outputs.add(new JourneyDefinition.NamedExtraction("upstream",new JourneyDefinition.CookieExtraction(URI.create(upstreamIssuer+"/protocol/saml"),"KEYCLOAK_IDENTITY","idp.upstream-sso.test","/realms/authlab-upstream/")));
        JourneyDefinition.Extraction extraction=backend?cookie:new JourneyDefinition.CombinedExtraction(outputs);
        String startPath=mode.equals("saml")?"/saml2/authenticate/keycloak":backend?"/oauth2/authorization/backend":mode.equals("broker")?"/spa?broker=upstream-saml":"/spa";
        var definition=new JourneyDefinition(UUID.randomUUID(),"Real federation",alias,URI.create(clientOrigin+startPath),false,
                steps,new JourneyDefinition.Browser(true,null,10000,3000),extraction,
                JourneyDefinition.Injection.perToken(backend?List.of():List.of(new JourneyDefinition.TokenInjection("bearer",JourneyDefinition.InjectionType.BEARER,null))),
                new JourneyDefinition.Cache(1800,10),null);
        return new LoginDefinition(definition,secure.id());
    }
    public static String export(JourneyDefinition journey) throws Exception {
        // Roundtrip through the actual serializer/parser before execution and omit fixture secrets from examples.
        try (var document = new JourneyDocument(JourneyDocument.DocumentKind.EXPORT, UUID.randomUUID(), List.of(journey), List.of(), null, Map.of())) {
            String serialized = JourneyJson.write(document);
            try (var parsed = JourneyJson.read(serialized, JourneyDocument.DocumentKind.EXPORT)) { assertEquals(journey, parsed.journeys().getFirst()); }
            return serialized;
        }
    }
    private static String name(String role) { return switch (role) { case "B" -> "bearer"; case "C1" -> "first"; case "C2" -> "second"; default -> throw new IllegalArgumentException(); }; }
    /** Hashes the same native saved definition/revision, with no secure-input values or runtime tokens. */
    public static String savedDefinitionHash(Prepared prepared) throws Exception {
        try (var document = new JourneyDocument(JourneyDocument.DocumentKind.EXPORT, prepared.definition.id(), List.of(prepared.definition), List.of(), null, Map.of())) {
            return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                    .digest(JourneyJson.write(document).getBytes(StandardCharsets.UTF_8)));
        }
    }
    public static Map<String, String> credentials(AuthenticationResult result, List<String> roles) {
        var selected = new java.util.LinkedHashMap<String, String>();
        for (String role : roles) {
            String value = roles.size() == 1 ? result.token() : result.namedTokens().get(name(role));
            assertNotNull(value, "Every selected credential must be present."); assertFalse(value.isEmpty()); selected.put(role, value);
        }
        return selected;
    }
    public static AuthenticationResult run(AuthLabSupport targets, AuthLabSupport.Case target, Prepared prepared) throws Exception {
        return observed(targets, target, () -> BrowserJourneyIntegrationTest.runner.run(
                new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, prepared.definition.id(), 1), prepared.definition, prepared.values, false,
                System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(CONTROLS.attemptTimeoutMs()), () -> false));
    }
    public static AuthenticationResult runAtCheckpoint(AuthLabSupport targets, AuthLabSupport.Case target, Prepared prepared, String checkpoint, boolean cancel) throws Exception {
        var cancelled = new java.util.concurrent.atomic.AtomicBoolean();
        try (var observer = Executors.newSingleThreadExecutor()) {
            var gate = observer.submit(() -> { target.awaitCheckpoint(checkpoint, (long) CONTROLS.cycleTimeoutMs() + 30_000); if (cancel) cancelled.set(true); else target.release(checkpoint); return null; });
            try {
                var result = observed(targets, target, () -> BrowserJourneyIntegrationTest.runner.run(
                        new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, prepared.definition.id(), 1), prepared.definition, prepared.values, false,
                        System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(CONTROLS.attemptTimeoutMs()), cancelled::get));
                gate.get(8, TimeUnit.SECONDS); return result;
            } finally { gate.cancel(true); observer.shutdownNow(); }
        }
    }
    public static void automaticAndTaggedProofs(AuthLabSupport targets, AuthLabSupport.Case target, Prepared prepared, String account) throws Exception {
        observed(targets, target, () -> {
            try (var secrets = new SecretStore()) {
                var registry = new JourneyWorkspace(secrets); CoordinatorFixtures.load(registry, List.of(prepared.definition));
                registry.secretChanged(new JourneyKey(JourneyDefinition.Scope.PROJECT, prepared.definition.id()), prepared.values);
                try (var coordinator = BrowserAuthentication.coordinator(registry, secrets, BrowserJourneyIntegrationTest.runner,
                        BrowserJourneyIntegrationTest.identities, CONTROLS)) {
                    var entry = registry.snapshot().resolve("fixture"); var resolver = new NativeTagResolver(registry, coordinator);
                    URI endpoint = target.url("protected/b_c1_c2");
                    String head = "GET " + endpoint.getRawPath() + "?" + endpoint.getRawQuery() + " HTTP/1.1\r\nHost: " + endpoint.getAuthority() + "\r\n";
                    String original = head + "Authorization: stale\r\nCookie: LAB_C1=old; LAB_C2=old; unrelated=keep\r\nCookie: LAB_C1=duplicate\r\n\r\n";
                    String issuance;
                    long version;
                    try (var operation = resolver.resolve(original.getBytes(StandardCharsets.US_ASCII), entry, true)) {
                        var resolved = operation.future().get((long) CONTROLS.requestWaitTimeoutMs() + 30_000, TimeUnit.MILLISECONDS);
                        assertEquals(1, resolved.uses().size()); version = resolved.uses().getFirst().version();
                        issuance = target.proveWire(resolved.commit(), "b_c1_c2", account, "automatic-combined").path("issuanceId").asText();
                    }
                    for (int count = 1; count <= 3; count++) {
                        String subset = count == 1 ? "b" : count == 2 ? "b_c1" : "b_c1_c2";
                        endpoint = target.url("protected/" + subset);
                        head = "GET " + endpoint.getRawPath() + "?" + endpoint.getRawQuery() + " HTTP/1.1\r\nHost: " + endpoint.getAuthority() + "\r\n";
                        String tagged = head + "Authorization: Bearer <@fixture token=\"bearer\"/>\r\n"
                                + (count >= 2 ? "Cookie: LAB_C1=<@fixture token=\"first\"/>" + (count == 3 ? "; LAB_C2=<@fixture token=\"second\"/>" : "") + "\r\n" : "") + "\r\n";
                        try (var operation = resolver.resolve(tagged.getBytes(StandardCharsets.US_ASCII), entry, true)) {
                            assertTrue(operation.future().isDone(), "Cached tagged uses must resolve without starting another authentication.");
                            var resolved = operation.future().join();
                            assertTrue(operation.tagsOnly()); assertEquals(1, resolved.uses().size()); assertEquals(version, resolved.uses().getFirst().version());
                            assertEquals(issuance, target.proveWire(resolved.commit(), subset, account, "tags-" + count).path("issuanceId").asText());
                        }
                    }
                    assertEquals(new AuthenticationCoordinator.Capacity(0, 0, 0), coordinator.capacity());
                }
            }
            return null;
        });
    }
    private static <T> T observed(AuthLabSupport targets, AuthLabSupport.Case target, java.util.concurrent.Callable<T> action) throws Exception {
        int resourceStart = BrowserJourneyIntegrationTest.resourceEvents.size();
        var processes = new BrowserProcesses();
        boolean returned = false;
        try { var result = action.call(); returned = true; return result; }
        finally {
            processes.close();
            if (returned || target.snapshot().path("counters").path("httpIngress").asLong() > 0) processes.requireObserved(1);
            var resources = List.copyOf(BrowserJourneyIntegrationTest.resourceEvents.subList(resourceStart, BrowserJourneyIntegrationTest.resourceEvents.size()));
            var opened = resources.stream().filter(event -> event.event() == BrowserFlowRunner.ResourceEvent.CONTEXT_OPEN && !event.bootstrap()).toList();
            boolean closed = !opened.isEmpty() && opened.stream().allMatch(context -> resources.stream().filter(event -> event.resourceId() == context.resourceId()
                    && event.event() == BrowserFlowRunner.ResourceEvent.CONTEXT_CLOSED).count() == 1);
            var actualResources = new AttemptResources(opened.size() == 1 ? opened.getFirst().resourceId() : 0,
                    (int) resources.stream().filter(event -> event.event() == BrowserFlowRunner.ResourceEvent.CONTEXT_CLOSED && !event.bootstrap()).count(),
                    (int) resources.stream().filter(event -> event.event() == BrowserFlowRunner.ResourceEvent.BROWSER_OPEN).count(),
                    (int) resources.stream().filter(event -> event.event() == BrowserFlowRunner.ResourceEvent.BROWSER_CLOSED).count(), processes.drivers(), processes.processes(), processes.alive());
            RESOURCES.computeIfAbsent(target.id, ignored -> new ArrayList<>()).add(actualResources);
            var resourceFacts = resources.stream().map(event -> Map.of("resourceId", event.resourceId(), "parentId", event.parentId(), "event", event.event().name(),
                    "bootstrap", event.bootstrap(), "journeyId", event.identity().journeyId().toString(), "generation", event.identity().generation())).toList();
            Files.writeString(targets.report.resolve("browser-lifecycle.jsonl"), AuthLabSupport.JSON.writeValueAsString(Map.of("requirementId", target.id,
                    "invocationId", targets.plan.path("invocationId").asText(), "generation", target.generation, "events", resourceFacts,
                    "contextIdentityObserved", !opened.isEmpty(), "contextClosureObserved", closed)) + "\n", StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
            var safe = Map.of("invocationId", targets.plan.path("invocationId").asText(), "fixtureRunId", targets.runId(), "requirementId", target.id, "generation", target.generation, "observedProcessCount", processes.processes(),
                    "aliveAfterReturn", processes.alive(), "outcome", returned ? "RETURNED" : "FAILED", "contextIdentityObserved", !opened.isEmpty(), "driverProcessCount", processes.drivers());
            Files.writeString(targets.report.resolve("browser-processes.jsonl"), AuthLabSupport.JSON.writeValueAsString(safe) + "\n", StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        }
    }
    private static void writeExample(AuthLabSupport targets, String id, String serialized) throws Exception {
            var directory = targets.report.resolve("native-examples"); Files.createDirectories(directory);
            Files.writeString(directory.resolve(id + ".json"), serialized, StandardCharsets.UTF_8);
            Files.writeString(directory.resolve("README.txt"), "Generated by the actual production serializer, with fixture passwords omitted. These captures contain invocation-specific URLs: the owning server stops after the checks. They are execution evidence, not persistent manual examples. A manual journey needs a live owned serve run, its current case URL/generation and the fixture password entered into its secure input. No runtime credentials or control keys are exported.\n", StandardCharsets.UTF_8);
    }
}
