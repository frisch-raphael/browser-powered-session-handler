package bpsh.browser;

import bpsh.authentication.credentials.AuthenticationResult;
import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.JourneyDefinition;
import bpsh.browser.runtime.PlaywrightDriverAdapter;
import bpsh.journey.SecretStore;
import bpsh.support.AuthLabSupport;
import bpsh.support.ProductionLabAdapter;
import java.net.*;
import java.net.http.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import lab.auth.*;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

/** Real production journeys over the maintained client and pinned Keycloak; no Burp UI is involved. */
@org.junit.jupiter.api.parallel.Execution(org.junit.jupiter.api.parallel.ExecutionMode.SAME_THREAD)
class FederationJourneyIntegrationTest {
    private static LabRun run;
    private static FederationEnvironment provider;
    private static Path runtimeManifest,report;
    private static com.fasterxml.jackson.databind.JsonNode planData;
    private static String ownerMethod;
    private static LabRun.CaseLease activeCase;
    private static FederationApplications activeApplications;
    private static long suiteBegan,suiteStartupMs,caseBegan;
    private static final Map<String,Map<String,Object>> pending=new LinkedHashMap<>();
    private static final List<Map<String,Object>> attempts=new ArrayList<>();
    private static final List<Throwable> cleanupFailures=new ArrayList<>();
    private static Map<String,Object> verifier;
    private static final Set<Long> contextsSeen=new HashSet<>();

    @BeforeAll static void prepare() throws Exception {
        suiteBegan=System.nanoTime();
        var plan=AuthLabSupport.JSON.readTree(Files.readAllBytes(Path.of(System.getProperty("authlab.plan"))));
        planData=plan;
        Path workspace=Path.of(plan.path("workspace").asText());report=Path.of(plan.path("reportDirectory").asText());
        runtimeManifest=Path.of(plan.path("federationRuntimeManifest").asText());
        assertEquals(plan.path("federationRuntimeManifestSha256").asText(),HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(runtimeManifest))));
        var ca=LabTls.loadPrepared(workspace.resolve("test/authentication-lab/build/prepared/federation/ca"));
        run=LabRun.start(new LabRun.RunSpec(UUID.fromString(plan.path("invocationId").asText()),List.of("federation"),ScenarioCatalog.load(),
                workspace.resolve("test/authentication-lab/build/runs"),List.of(),5000));
        String requested=plan.path("requestedTests").asText();boolean broker=requested.isEmpty()||requested.contains("brokeredJourney")||requested.contains("*");
        provider=FederationEnvironment.startProvider(run,new FederationEnvironment.Spec(Path.of(plan.path("federationInputs").path("test/federation-client/provider-assets.lock.json").asText()),
                Path.of(plan.path("federationInputs").path("test/federation-client/src/main/resources/provider/downstream-realm.json").asText()),ca,
                broker?Path.of(plan.path("federationInputs").path("test/federation-client/src/main/resources/provider/upstream-realm.json").asText()):null));
        BrowserJourneyIntegrationTest.setup();
        suiteStartupMs=java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-suiteBegan);
    }
    @AfterAll static void cleanup() throws Exception {
        var resources=new ArrayList<Map<String,String>>();
        if(run!=null) {
            var descriptor=AuthLabSupport.JSON.readTree(Files.readAllBytes(run.directory().resolve("run.json")));
            for(var item:descriptor.path("resources"))if(Set.of("CONTAINER","NETWORK").contains(item.path("kind").asText()))resources.add(Map.of("kind",item.path("kind").asText(),"id",item.path("id").asText()));
        }
        try { BrowserJourneyIntegrationTest.shutdown(); }
        finally { if(run!=null)run.close(); }
        if(run!=null) {
            var terminal=AuthLabSupport.JSON.readTree(Files.readAllBytes(run.directory().resolve("run.json")));assertEquals("CLOSED",terminal.path("state").asText());assertEquals(0,terminal.path("resources").size());
            for(var resource:resources)FederationEnvironment.confirmResourceAbsent(resource.get("kind"),resource.get("id"));
            Files.writeString(report.resolve("federation-run-completion.json"),AuthLabSupport.JSON.writeValueAsString(Map.of("version",1,"invocationId",planData.path("invocationId").asText(),
                    "runId",run.runId().toString(),"runtimeIdentity",AuthLabSupport.JSON.readTree(Files.readAllBytes(runtimeManifest)).path("identity").asText(),
                    "state","CLOSED","remainingResources",0,"independentlyAbsentResources",resources,"startupMs",suiteStartupMs)));
        }
    }
    @BeforeEach void resetProvider(TestInfo info) throws Exception {
        ownerMethod=info.getTestMethod().orElseThrow().getName();activeCase=null;activeApplications=null;pending.clear();attempts.clear();cleanupFailures.clear();verifier=null;
        run.reset(run.generation());caseBegan=System.nanoTime();
    }
    private static FederationApplications applications(LabRun.CaseLease target) throws Exception {
        activeCase=target;activeApplications=provider.startApplications(target,runtimeManifest);return activeApplications;
    }
    @AfterEach void captureCompletedCase() throws Exception {
        if(!cleanupFailures.isEmpty()) {
            var error=new AssertionError("Owned browser cleanup did not meet its observed lifecycle contract.");
            cleanupFailures.forEach(error::addSuppressed);throw error;
        }
        if(activeCase==null||activeApplications==null)return;
        boolean cleaned=activeApplications.closedCleanly()&&"CLOSED".equals(activeCase.snapshot().get("state"));
        long startup=activeApplications.startupMs(),cleanup=activeApplications.cleanupMs();
        var timings=Map.of("startupMs",startup,"caseMs",Math.max(0,java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-caseBegan)-startup-cleanup),"cleanupMs",cleanup);
        Path captures=report.resolve("federation-observations");Files.createDirectories(captures);
        for(var entry:pending.entrySet()) {
            var observed=new LinkedHashMap<String,Object>(entry.getValue());observed.put("ownerMethod",ownerMethod);observed.put("caseId",activeCase.id());observed.put("caseGeneration",activeCase.generation());
            observed.put("runId",run.runId().toString());observed.put("attempts",List.copyOf(attempts));observed.put("verifier",verifier);observed.put("childJvmsClosed",cleaned);
            var capture=new LinkedHashMap<String,Object>();capture.put("version",2);capture.put("invocationId",planData.path("invocationId").asText());capture.put("requirementId",entry.getKey());
            capture.put("taskPath",":authLabFederationTest");capture.put("productionRevision",planData.path("productionRevision").asText());capture.put("configurationHash",planData.path("configurationHash").asText());
            capture.put("observed",observed);capture.put("cleanup",cleaned?"COMPLETE":"INCOMPLETE");capture.put("timings",timings);
            String name=HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(entry.getKey().getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            Files.writeString(captures.resolve(name+".json"),AuthLabSupport.JSON.writeValueAsString(capture));
        }
    }

    @Test @Timeout(120) void realBrowserOutputsAuthenticateExpectedAccountsWithFreshIssuances() throws Exception {
        String id="FED.outputs.client-cookie-plus-bearer";
        try(var target=run.prepareCase(id);var applications=applications(target);var http=provider.clientBuilder().build()) {
            var first=login(applications,false,"user","pass");
            var second=login(applications,false,"user2","pass2");
            String firstCookie=first.namedTokens().get("client"),firstBearer=first.namedTokens().get("bearer");
            String secondCookie=second.namedTokens().get("client"),secondBearer=second.namedTokens().get("bearer");
            assertNotNull(firstCookie);assertNotNull(firstBearer);assertNotNull(secondCookie);assertNotNull(secondBearer);
            assertFalse(firstCookie.equals(secondCookie),"Fresh login must return a new client-cookie issuance.");
            assertFalse(firstBearer.equals(secondBearer),"Fresh login must return a new provider token.");
            var a=proof(http,applications,firstCookie,firstBearer,"11111111-1111-4111-8111-111111111111");
            var b=proof(http,applications,secondCookie,secondBearer,"22222222-2222-4222-8222-222222222222");
            assertFalse(a.path("issuanceId").asText().equals(b.path("issuanceId").asText()));
            selectedIdpCookieProof(applications,first.namedTokens().get("idp"),second.namedTokens().get("idp"),firstCookie);
            var third=login(applications,false,"user2","pass2");String thirdCookie=third.namedTokens().get("client"),thirdBearer=third.namedTokens().get("bearer");
            assertNotNull(thirdCookie);assertNotNull(thirdBearer);assertFalse(secondCookie.equals(thirdCookie));assertFalse(secondBearer.equals(thirdBearer));
            proof(http,applications,thirdCookie,thirdBearer,"22222222-2222-4222-8222-222222222222");
            record(id,Map.of("protectedProofs",3,"freshInteractiveAccounts",2,"repeatedAccountLogins",1,"freshAfterVerifier",true,"runtimeIdentity",applications.runtimeIdentity()));
        }
    }

    @Test @Timeout(60) void realSamlPostResponseProducesAUsableClientCookieWithoutInventingAnAccessToken() throws Exception {
        String id="FED.flow.saml-sp";
        try(var target=run.prepareCase(id);var applications=applications(target);var http=provider.clientBuilder().build()) {
            var result=login(applications,"saml","user2","pass2");String cookie=result.token();assertNotNull(cookie);assertFalse(cookie.isBlank());assertTrue(result.namedTokens().isEmpty());
            var me=request(http,applications.clientOrigin()+"/me",cookie,null);assertEquals(200,me.statusCode());
            var identity=AuthLabSupport.JSON.readTree(me.body());assertEquals("saml",identity.path("authenticationProtocol").asText());assertEquals("user2",identity.path("subject").asText());
            assertFalse(identity.path("providerSessionId").asText().isBlank());assertTrue(identity.path("tokenId").isNull());
            var complete=request(http,applications.clientOrigin()+"/saml-complete",cookie,null);assertEquals(200,complete.statusCode());assertTrue(complete.body().contains("id=login-complete"));
            assertFalse(me.body().contains("SAMLResponse"));assertFalse(me.body().contains("access_token"));
            record(id,Map.of("realSamlIdentityAccepted",true,"clientCookieAccepted",true,"oauthTokenInvented",false,"runtimeIdentity",applications.runtimeIdentity()));
        }
    }

    @Test @Timeout(60) void realBackendOidcPublishesOnlyACookieAfterItsHiddenTokenReachesTheApi() throws Exception {
        String id="FED.flow.backend-oidc";
        try(var target=run.prepareCase(id);var applications=applications(target);var http=provider.clientBuilder().build()) {
            var result=login(applications,true,"user2","pass2");String cookie=result.token();assertNotNull(cookie);assertFalse(cookie.isBlank());
            var me=request(http,applications.clientOrigin()+"/me",cookie,null);assertEquals(200,me.statusCode());
            var identity=AuthLabSupport.JSON.readTree(me.body());assertEquals("22222222-2222-4222-8222-222222222222",identity.path("subject").asText());
            assertFalse(identity.path("tokenId").asText().isBlank());assertFalse(identity.path("providerSessionId").asText().isBlank());
            var complete=request(http,applications.clientOrigin()+"/backend-complete",cookie,null);assertEquals(200,complete.statusCode());assertTrue(complete.body().contains("id=login-complete"));
            assertFalse(me.body().contains("access_token"));assertFalse(complete.body().contains("access_token"));assertTrue(result.namedTokens().isEmpty());
            record(id,Map.of("backendApiAcceptance",true,"clientCookieAccepted",true,"hiddenTokenReturned",false,"runtimeIdentity",applications.runtimeIdentity()));
        }
    }
    @Test @Timeout(90) void brokeredJourneyReturnsUsableCredentialsForTheExpectedAccount() throws Exception {
        String id="FED.broker.combined-outputs";
        try(var target=run.prepareCase(id);var applications=applications(target);var http=provider.clientBuilder().build()) {
            var first=login(applications,"broker","user","pass");var second=login(applications,"broker","user2","pass2");
            for(var result:List.of(first,second))for(String name:List.of("bearer","client","upstream")) {
                assertNotNull(result.namedTokens().get(name));assertFalse(result.namedTokens().get(name).isBlank());
            }
            proof(http,applications,first.namedTokens().get("client"),first.namedTokens().get("bearer"),"11111111-1111-4111-8111-111111111111");
            proof(http,applications,second.namedTokens().get("client"),second.namedTokens().get("bearer"),"22222222-2222-4222-8222-222222222222");
            for(String name:List.of("bearer","client","upstream"))assertFalse(first.namedTokens().get(name).equals(second.namedTokens().get(name)),"Captured output must belong to the current fresh login.");
            selectedCookieProof(applications,first.namedTokens().get("upstream"),second.namedTokens().get("upstream"),first.namedTokens().get("client"),true);
            record(id,Map.of("actualUpstreamPageRequired",true,"protectedAccountsVerified",2,"capturedOutputsPerJourney",3,"upstreamCookieAuthenticated",true,"providerValidationTested",false,"runtimeIdentity",applications.runtimeIdentity()));
        }
    }
    @Test @Timeout(90) void brokeredJourneyReturnsNoCredentialAfterUpstreamLoginRejection() throws Exception {
        String id="FED.broker.upstream-rejected";
        try(var target=run.prepareCase(id);var applications=applications(target);var http=provider.clientBuilder().build()) {
            var valid=login(applications,"broker","user2","pass2");
            proof(http,applications,valid.namedTokens().get("client"),valid.namedTokens().get("bearer"),"22222222-2222-4222-8222-222222222222");
            // The pinned provider's v2 theme puts the login rejection on the username field.
            var failure=assertThrows(AuthenticationFailure.class,()->login(applications,"broker","user2","deliberately-wrong-fixture-password","#input-error-username"));
            assertEquals(AuthenticationFailure.Cause.EXTRACTION,failure.reason(),failure::problem);assertFalse(failure.getMessage().toLowerCase(Locale.ROOT).contains("connection"));
            record(id,Map.of("validComparisonAccepted",true,"noCredentialReturned",true,"freshInteractiveAttempt",true,"providerValidationTested",false,"runtimeIdentity",applications.runtimeIdentity()));
        }
    }
    @Test @Timeout(60) void brokeredJourneyCancellationClosesItsBrowserBeforeReturningPartialCredentials() throws Exception {
        String id="FED.broker.cancelled",checkpoint="before-client-session";
        try(var target=run.prepareCase(id);var applications=applications(target)) {
            applications.armProtocol("client-publication-hold",checkpoint);
            var cancelled=new java.util.concurrent.atomic.AtomicBoolean();
            try(var observer=java.util.concurrent.Executors.newSingleThreadExecutor()) {
                var held=observer.submit(()->{applications.awaitProtocolCheckpoint(checkpoint,Duration.ofSeconds(25));cancelled.set(true);return true;});
                try {
                    var failure=assertThrows(AuthenticationFailure.class,()->login(applications,"broker","user2","pass2","#login-complete",cancelled::get));
                    assertEquals(AuthenticationFailure.Cause.CANCELLED,failure.reason());assertTrue(failure.getMessage().toLowerCase(Locale.ROOT).contains("cancel"));
                    assertTrue(held.get(2,java.util.concurrent.TimeUnit.SECONDS));
                }finally{held.cancel(true);observer.shutdownNow();assertTrue(observer.awaitTermination(2,java.util.concurrent.TimeUnit.SECONDS));}
            }
            var after=applications.clientSnapshot();assertFalse(after.get("truncated").getAsBoolean());
            assertEquals(1,eventCount(after,"before-client-session"));assertEquals(0,eventCount(after,"client-cookie-established"));
            retainProtocol("broker-cancelled",new com.google.gson.JsonObject(),after);
            record(id,Map.of("actualClientPublicationCheckpointObserved",true,"cancellationReturned",true,"noPartialCredentialReturned",true,
                    "ownedBrowserProcessesClosed",true,"runtimeIdentity",applications.runtimeIdentity()));
        }
    }

    @Test @Timeout(60) void backendRejectionProducesAnAccurateExtensionFailure() throws Exception {
        String variant="code-expired",id="FED.negative.code-expired";
        try(var target=run.prepareCase(id);var applications=applications(target);var http=provider.clientBuilder().build()) {
            var valid=login(applications,true,"user2","pass2");
            assertEquals(200,request(http,applications.clientOrigin()+"/backend-complete",valid.token(),null).statusCode());
            var before=applications.clientSnapshot();String checkpoint="before-token-exchange";
            ownedControl(http,"/cases/"+id+"/federation-control",Map.of("generation",target.generation(),"variant",variant,"checkpoint",checkpoint));
            try(var observer=java.util.concurrent.Executors.newSingleThreadExecutor()) {
                var released=observer.submit(()->{applications.awaitProtocolCheckpoint(checkpoint,Duration.ofSeconds(25));
                    ownedControl(http,"/cases/"+id+"/gates/"+checkpoint+"/release",Map.of("generation",target.generation()));return true;});
                try {
                    var failure=assertThrows(AuthenticationFailure.class,()->login(applications,"backend","user2","pass2",
                            "#auth-error[data-stage=token-exchange]:has-text(\"Authorization code expired (simulated test condition)\")"));
                    assertEquals(AuthenticationFailure.Phase.EXTRACTION,failure.phase());assertEquals(AuthenticationFailure.Cause.EXTRACTION,failure.reason());
                    assertNull(failure.step());assertNull(failure.httpStatus());
                    String message=failure.getMessage().toLowerCase(Locale.ROOT);assertTrue(message.contains("cookie"));
                    assertFalse(message.contains("connection"));assertFalse(message.contains("expired"),"An unobserved backend cause must not be invented.");
                    assertTrue(released.get(2,java.util.concurrent.TimeUnit.SECONDS));
                }finally{released.cancel(true);observer.shutdownNow();assertTrue(observer.awaitTermination(2,java.util.concurrent.TimeUnit.SECONDS));}
            }
            var after=applications.clientSnapshot();retainProtocol(variant,before,after);assertFalse(after.get("truncated").getAsBoolean());
            assertEquals(0,eventCount(after,"client-session-established")-eventCount(before,"client-session-established"));
            assertEquals(1,eventCount(after,"checkpoint-released"));assertEquals(1,eventCount(after,"simulated-expired-code-response"));
            record(id,Map.of("validComparisonAccepted",true,"noCredentialReturnedAfterRejection",true,"extensionMessageMatchesAvailableObservation",true,
                    "simulatedFixtureFailure",true,"providerProtocolValidationTested",false,"runtimeIdentity",applications.runtimeIdentity()));
        }
    }
    private static void retainProtocol(String variant,com.google.gson.JsonObject before,com.google.gson.JsonObject after) throws Exception {
        var evidence=new com.google.gson.JsonObject();evidence.add("before",before);evidence.add("after",after);
        Files.writeString(report.resolve("protocol-"+variant+".json"),evidence.toString());
    }
    private static long eventCount(com.google.gson.JsonObject snapshot,String name) {
        return snapshot.getAsJsonArray("events").asList().stream().filter(e->name.equals(e.getAsJsonObject().get("name").getAsString())).count();
    }
    private static void ownedControl(HttpClient http,String route,Map<String,Object> body) throws Exception {
        var request=HttpRequest.newBuilder(URI.create(run.controlUri()+route)).timeout(Duration.ofSeconds(5))
                .header("Authorization","Bearer "+run.controlKey().reveal()).header("Content-Type","application/json")
                .POST(HttpRequest.BodyPublishers.ofString(AuthLabSupport.JSON.writeValueAsString(body))).build();
        var response=http.send(request,HttpResponse.BodyHandlers.ofString());assertEquals(200,response.statusCode());
        assertEquals(body.get("generation").toString(),AuthLabSupport.JSON.readTree(response.body()).path("generation").asText());
    }

    private static AuthenticationResult login(FederationApplications applications,boolean backend,String account,String password) throws Exception {
        return login(applications,backend?"backend":"browser",account,password);
    }
    private static AuthenticationResult login(FederationApplications applications,String mode,String account,String password) throws Exception {
        return login(applications,mode,account,password,"#login-complete");
    }
    private static AuthenticationResult login(FederationApplications applications,String mode,String account,String password,String completion) throws Exception {
        return login(applications,mode,account,password,completion,()->false);
    }
    private static AuthenticationResult login(FederationApplications applications,String mode,String account,String password,String completion,java.util.function.BooleanSupplier cancelled) throws Exception {
        var built=ProductionLabAdapter.federationDefinition(applications.clientOrigin(),provider.ports().issuer(),
                provider.ports().upstream()>0?provider.ports().upstreamIssuer():null,mode,account,completion,"federation");
        var definition=built.journey();ProductionLabAdapter.export(definition);
        int start=BrowserJourneyIntegrationTest.resourceEvents.size();
        var processes=new ProductionLabAdapter.BrowserProcesses();
        Throwable primaryFailure=null;
        try(var values=new SecretStore.Values(null,Map.of(built.secureInput(),password.toCharArray()))) {
            return BrowserJourneyIntegrationTest.runner.run(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT,definition.id(),1),definition,values,false,
                    System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(25),cancelled);
        }catch(Exception|Error failure){primaryFailure=failure;throw failure;
        }finally {
            try {
                processes.close();if(primaryFailure==null||processes.processes()>0)processes.requireObserved(1);
                var events=List.copyOf(BrowserJourneyIntegrationTest.resourceEvents.subList(start,BrowserJourneyIntegrationTest.resourceEvents.size()));
                var contexts=events.stream().filter(e->e.event()==BrowserFlowRunner.ResourceEvent.CONTEXT_OPEN&&!e.bootstrap()).toList();
                long closed=events.stream().filter(e->e.event()==BrowserFlowRunner.ResourceEvent.CONTEXT_CLOSED&&!e.bootstrap()).count();
                long browsers=events.stream().filter(e->e.event()==BrowserFlowRunner.ResourceEvent.BROWSER_OPEN).count();
                long browsersClosed=events.stream().filter(e->e.event()==BrowserFlowRunner.ResourceEvent.BROWSER_CLOSED).count();
                var observed=new LinkedHashMap<String,Object>();observed.put("journeyId",definition.id().toString());observed.put("contexts",contexts.size());observed.put("closedContexts",closed);
                observed.put("contextId",contexts.size()==1?contexts.getFirst().resourceId():null);observed.put("contextIdentityObserved",!contexts.isEmpty());
                observed.put("contextClosed",contexts.size()==1&&closed==1);observed.put("browsers",browsers);observed.put("closedBrowsers",browsersClosed);
                observed.put("browserClosed",browsers==1&&browsersClosed==1);observed.put("osProcessClosureObserved",processes.processes()>0&&processes.alive()==0);
                observed.put("observedProcesses",processes.processes());observed.put("drivers",processes.drivers());observed.put("alive",processes.alive());
                if(primaryFailure instanceof AuthenticationFailure failure){
                    observed.put("failurePhase",failure.phase().name());observed.put("failureCause",failure.reason().name());
                    if(failure.step()!=null){observed.put("failedStepNumber",failure.step().number());observed.put("failedStepType",failure.step().type().name());}
                }
                attempts.add(new LinkedHashMap<>(observed));
                Files.writeString(report.resolve("federation-browser-lifecycle.jsonl"),AuthLabSupport.JSON.writeValueAsString(observed)+"\n",StandardOpenOption.CREATE,StandardOpenOption.APPEND);
                if(primaryFailure==null||!contexts.isEmpty()) {
                    assertEquals(1,contexts.size());assertTrue(contextsSeen.add(contexts.getFirst().resourceId()),"Every authentication attempt must use a distinct actual context.");
                    assertEquals(1,browsers);
                    if(primaryFailure instanceof AuthenticationFailure failure&&failure.reason()==AuthenticationFailure.Cause.CANCELLED) {
                        // The watchdog can terminate the pipe before close() emits SDK notifications.
                        // The observed owned process tree must nevertheless have fully exited above.
                        assertTrue(closed==0||closed==1);assertTrue(browsersClosed==0||browsersClosed==1);
                    }else {assertEquals(1,closed);assertEquals(1,browsersClosed);}
                }
            }catch(Exception|Error cleanupFailure){cleanupFailures.add(cleanupFailure);if(primaryFailure!=null)primaryFailure.addSuppressed(cleanupFailure);else throw cleanupFailure;}
        }
    }
    private static com.fasterxml.jackson.databind.JsonNode proof(HttpClient http,FederationApplications applications,String cookie,String bearer,String expected) throws Exception {
        var api=request(http,applications.resourceOrigin()+"/api/me",null,bearer);assertEquals(200,api.statusCode());
        var client=request(http,applications.clientOrigin()+"/me",cookie,null);assertEquals(200,client.statusCode());
        var combined=request(http,applications.clientOrigin()+"/combined",cookie,bearer);assertEquals(200,combined.statusCode());
        var a=AuthLabSupport.JSON.readTree(api.body());var c=AuthLabSupport.JSON.readTree(client.body());var pair=AuthLabSupport.JSON.readTree(combined.body());
        assertEquals(expected,a.path("subject").asText());assertEquals(expected,c.path("subject").asText());assertEquals(expected,pair.path("subject").asText());
        for(String field:List.of("tokenId","providerSessionId")){assertFalse(a.path(field).asText().isBlank());assertEquals(a.path(field),c.path(field));assertEquals(c.path(field),pair.path(field));}
        return pair;
    }

    /** Explicit output verifier only: its cookies never enter a later production authentication attempt. */
    private static void selectedIdpCookieProof(FederationApplications applications,String first,String second,String wrongService) throws Exception {
        selectedCookieProof(applications,first,second,wrongService,false);
    }
    private static void selectedCookieProof(FederationApplications applications,String first,String second,String wrongService,boolean upstream) throws Exception {
        assertNotNull(first);assertFalse(first.isBlank());assertNotNull(second);assertFalse(second.isBlank());assertFalse(first.equals(second));
        if(!upstream)try(var http=provider.clientBuilder().build()) {
            var logout=http.send(HttpRequest.newBuilder(URI.create(applications.clientOrigin()+"/logout-client")).timeout(Duration.ofSeconds(5))
                    .header("Cookie","LAB_CLIENT="+wrongService).POST(HttpRequest.BodyPublishers.noBody()).build(),HttpResponse.BodyHandlers.discarding());
            assertEquals(204,logout.statusCode());assertEquals(401,request(http,applications.clientOrigin()+"/me",wrongService,null).statusCode());
        }
        var ready=BrowserJourneyIntegrationTest.runtime.acquire(System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(15),()->false);
        var verifierProcesses=new ProductionLabAdapter.BrowserProcesses();
        try(verifierProcesses;var driver=PlaywrightDriverAdapter.open(ready,System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(20),()->false);
            var browser=driver.playwright().chromium().launch(new com.microsoft.playwright.BrowserType.LaunchOptions()
                    .setExecutablePath(ready.browserExecutable()).setHeadless(true).setArgs(List.of("--no-proxy-server")))) {
            verifySso(browser,applications,first,upstream?"aaaaaaaa-aaaa-4aaa-8aaa-111111111111":"11111111-1111-4111-8111-111111111111",upstream);
            verifySso(browser,applications,null,null,upstream);
            verifySso(browser,applications,second,upstream?"aaaaaaaa-aaaa-4aaa-8aaa-222222222222":"22222222-2222-4222-8222-222222222222",upstream);
            verifySso(browser,applications,wrongService,null,upstream);
        }
        verifierProcesses.requireObserved(1);
        verifier=Map.of("upstream",upstream,"contexts",4,"drivers",verifierProcesses.drivers(),"processes",verifierProcesses.processes(),"alive",verifierProcesses.alive(),"missingCookieRejected",true,"otherAccountIdentified",true,"wrongServiceRejected",true,"passwordSubmissions",0);
        if(!upstream)record("FED.outputs.idp-cookie",Map.of("singleSelectedCookieAccepted",true,"missingCookieRejected",true,
                "otherAccountIdentifiedSeparately",true,"clientCookieRejectedAsIdpCookie",true,"passwordSubmissions",0,
                "clientLogoutLeavesIdpSessionUsable",true,"productionBrowserSeeded",false,"runtimeIdentity",applications.runtimeIdentity()));
    }
    private static void verifySso(com.microsoft.playwright.Browser browser,FederationApplications applications,String selected,String expected,boolean upstream) throws Exception {
        String peer=upstream?"idp.upstream-sso.test":"idp.federation.test",realm=upstream?"authlab-upstream":"authlab-downstream";
        try(var context=browser.newContext()) {
            assertTrue(context.cookies().isEmpty());
            if(selected!=null)context.addCookies(List.of(new com.microsoft.playwright.options.Cookie("KEYCLOAK_IDENTITY",selected)
                    .setDomain(peer).setPath("/realms/"+realm+"/").setHttpOnly(true).setSecure(true)
                    .setSameSite(com.microsoft.playwright.options.SameSiteAttribute.NONE)));
            assertEquals(selected==null?0:1,context.cookies().size(),"No companion or client cookie may be seeded for the selected-cookie proof.");
            var page=context.newPage();page.setDefaultTimeout(10000);page.setDefaultNavigationTimeout(10000);
            var apiProofs=new ArrayList<com.fasterxml.jackson.databind.JsonNode>();var pairProofs=new ArrayList<com.fasterxml.jackson.databind.JsonNode>();
            var idpProofs=new ArrayList<com.fasterxml.jackson.databind.JsonNode>();
            var promptNone=new java.util.concurrent.atomic.AtomicInteger();var passwordSubmissions=new java.util.concurrent.atomic.AtomicInteger();
            page.onRequest(request->{var uri=URI.create(request.url());
                if(peer.equals(uri.getHost())&&uri.getPath().endsWith("/protocol/openid-connect/auth")) {
                    var parameters=Arrays.stream(Objects.toString(uri.getRawQuery(),"").split("&")).map(p->p.split("=",2))
                            .filter(p->p.length==2).collect(java.util.stream.Collectors.toMap(p->p[0],p->p[1],(a,b)->b));
                    assertEquals("none",parameters.get("prompt"));promptNone.incrementAndGet();
                }
                if(peer.equals(uri.getHost())&&request.method().equals("POST")&&uri.getPath().contains("/login-actions/"))passwordSubmissions.incrementAndGet();
            });
            page.onResponse(response->{var uri=URI.create(response.url());
                try {
                    if(uri.getPath().equals("/api/me")&&uri.getHost().equals("api.authlab.test")&&response.status()==200)apiProofs.add(AuthLabSupport.JSON.readTree(response.body()));
                    if(uri.getPath().equals("/combined")&&uri.getHost().equals("app.authlab.test")&&response.status()==200)pairProofs.add(AuthLabSupport.JSON.readTree(response.body()));
                    if(upstream&&uri.getPath().endsWith("/protocol/openid-connect/userinfo")&&peer.equals(uri.getHost())&&response.status()==200)idpProofs.add(AuthLabSupport.JSON.readTree(response.body()));
                }catch(java.io.IOException invalid){throw new java.io.UncheckedIOException(invalid);}
            });
            page.navigate(applications.clientOrigin()+"/spa?client="+(upstream?"upstream-cookie-verifier":"cookie-verifier"));
            page.locator("#login-complete,#auth-error").waitFor();
            assertEquals(1,promptNone.get());assertEquals(0,passwordSubmissions.get());assertEquals(0,page.locator("#username,#password").count());
            if(expected==null) {
                assertEquals(1,page.locator("#auth-error[data-stage=sso-session-absent]").count());assertTrue(apiProofs.isEmpty());assertTrue(pairProofs.isEmpty());assertTrue(idpProofs.isEmpty());
                assertTrue(context.cookies().stream().noneMatch(c->c.name.equals("LAB_CLIENT")));
            }else if(upstream) {
                assertEquals(1,page.locator("#login-complete").count());assertEquals(1,idpProofs.size());
                assertEquals(expected,idpProofs.getFirst().path("sub").asText());assertEquals(expected,page.locator("#login-complete").getAttribute("data-subject"));
                assertTrue(apiProofs.isEmpty());assertTrue(pairProofs.isEmpty());
            }else {
                assertEquals(1,page.locator("#login-complete").count());assertEquals(1,apiProofs.size());assertEquals(1,pairProofs.size());
                assertEquals(expected,apiProofs.getFirst().path("subject").asText());assertEquals(expected,pairProofs.getFirst().path("subject").asText());
                assertFalse(apiProofs.getFirst().path("tokenId").asText().isBlank());
                assertEquals(apiProofs.getFirst().path("tokenId"),pairProofs.getFirst().path("tokenId"));
                assertEquals(apiProofs.getFirst().path("providerSessionId"),pairProofs.getFirst().path("providerSessionId"));
            }
        }
    }
    private static HttpResponse<String> request(HttpClient http,String uri,String cookie,String bearer) throws Exception {
        var request=HttpRequest.newBuilder(URI.create(uri)).timeout(Duration.ofSeconds(5)).GET();
        if(cookie!=null)request.header("Cookie","LAB_CLIENT="+cookie);if(bearer!=null)request.header("Authorization","Bearer "+bearer);
        return http.send(request.build(),HttpResponse.BodyHandlers.ofString());
    }
    private static void record(String id,Map<String,Object> observed) throws Exception {
        Files.writeString(report.resolve("federation-observations.jsonl"),AuthLabSupport.JSON.writeValueAsString(Map.of("requirementId",id,"observed",observed,"catalogAcceptance",false))+"\n",
                StandardOpenOption.CREATE,StandardOpenOption.APPEND);
        var ids=switch(id) {
            case "FED.outputs.client-cookie-plus-bearer"->List.of(id,"FED.flow.browser-oidc","FED.outputs.api-token","FED.sso.fresh-production-attempt");
            case "FED.outputs.idp-cookie"->List.of(id,"FED.sso.missing-cookie","FED.sso.other-account-cookie","FED.sso.wrong-service","FED.sso.client-logout-idp-live");
            case "FED.flow.backend-oidc"->List.of(id,"FED.outputs.client-cookie");
            case "FED.broker.combined-outputs"->List.of(id,"FED.broker.success");
            default->List.of(id);
        };
        for(String requirement:ids)assertNull(pending.putIfAbsent(requirement,Map.copyOf(observed)),"A semantic capture must have one actual owning observation.");
    }
}
