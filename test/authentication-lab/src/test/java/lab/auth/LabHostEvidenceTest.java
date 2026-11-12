package lab.auth;

import com.google.gson.*;
import java.nio.file.*;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** Synthetic validator fixtures never grant host execution coverage. */
class LabHostEvidenceTest {
    @TempDir Path directory;
    private static JsonObject json(Object... fields) {
        var result=new JsonObject();for(int i=0;i<fields.length;i+=2)result.add((String)fields[i],LabJson.JSON.toJsonTree(fields[i+1]));return result;
    }
    private static final class Fixture {
        final LabHostGuiProtocol.Session session;
        final List<Integer> listeners=List.of(8081,8082,8083);
        final Map<Long,LabHostEvidence.Gui> receipts=new TreeMap<>();
        final JsonObject scenario;
        final UUID run=UUID.randomUUID();
        final JsonArray events=new JsonArray(),rows=new JsonArray(),callbacks=new JsonArray();
        long sequence;
        Fixture(Path root) {
            session=new LabHostGuiProtocol.Session(UUID.randomUUID(),"linux",UUID.randomUUID(),"a".repeat(64),"b".repeat(64),root);
            event("LOGIN","phase-entered",List.of());event("LOGIN","login-completed",List.of(json("kind","account","value","user"),json("kind","issuance","value","s6")));
            event("LOGIN","phase-entered",List.of());event("LOGIN","login-completed",List.of(json("kind","account","value","user2"),json("kind","issuance","value","s7")));
            receipt("READY",new JsonObject(),json("ready",true),950);
            var measures=new JsonArray();
            var first=measure("proxy-explicit-a",1000);receipt("EDIT_RULES",json("inputSha256","c".repeat(64)),json("rulesConfigured",true),1050);
            receive("h0000000000000001",true,false);original(first,"h0000000000000001","PROXY",8081,"TAGGED","user",200,200);
            callback("h0000000000000001","PROXY","received","PROXY",1,0);callback("h0000000000000001","PROXY","response_to_send","PROXY",1,200);finish(first,1100);measures.add(first);
            var second=measure("repeater-explicit-a",1200);
            receipt("SET_REPEATER_REQUEST",json("nonce","h0000000000000002","inputSha256","d".repeat(64)),json("nonce","h0000000000000002","length",200),1210);
            receipt("SEND_REPEATER",json("nonce","h0000000000000002"),json("nonce","h0000000000000002","submitted",true),1220);
            receipt("ASSERT_REPEATER_RESPONSE",json("nonce","h0000000000000002","status",200),json("nonce","h0000000000000002","status",200),1230);
            receive("h0000000000000002",true,false);original(second,"h0000000000000002","REPEATER",null,"TAGGED","user",200,200);
            callback("h0000000000000002","GLOBAL","to_send","REPEATER",2,0);callback("h0000000000000002","GLOBAL","response_received","REPEATER",2,200);finish(second,1300);measures.add(second);
            var stopped=measure("repeater-unknown",1400);
            receipt("SET_REPEATER_REQUEST",json("nonce","h0000000000000003","inputSha256","e".repeat(64)),json("nonce","h0000000000000003","length",200),1410);
            receipt("SEND_REPEATER",json("nonce","h0000000000000003"),json("nonce","h0000000000000003","submitted",true),1420);
            original(stopped,"h0000000000000003","REPEATER",null,"TAGGED_STOP",null,null,null);
            callback("h0000000000000003","GLOBAL","to_send","REPEATER",3,0);finish(stopped,1500);measures.add(stopped);
            var proxy=measure("proxy-unknown",1600);receive("h0000000000000004",false,true);
            original(proxy,"h0000000000000004","PROXY",8081,"TAGGED_PROXY_BEST_EFFORT",null,null,401);
            callback("h0000000000000004","PROXY","received","PROXY",4,0);finish(proxy,1700);measures.add(proxy);
            scenario=LabHostGuiProtocol.identity(session);scenario.addProperty("scenario","tags");scenario.addProperty("outcome","PASS");scenario.addProperty("code","HOST_SCENARIO_VERIFIED");
            scenario.addProperty("startedEpochMs",900);scenario.addProperty("endedEpochMs",1800);scenario.addProperty("runId",run.toString());scenario.addProperty("caseGeneration",1);scenario.add("measurements",measures);
            var probe=LabHostGuiProtocol.identity(session);probe.addProperty("case","host-tags");probe.addProperty("burpVersion","Burp Suite Professional 2026.10.1");
            probe.addProperty("overflow",false);probe.addProperty("complete",true);probe.add("events",callbacks);probe.addProperty("scope","Passive callback observations only; server acceptance requires independent fixture evidence.");scenario.add("probe",probe);
        }
        void event(String phase,String name,List<JsonObject> ids){events.add(json("sequence",events.size()+1,"time","2026-11-11T10:00:00Z","phase",phase,"name",name,"safeIds",ids));}
        JsonObject snapshot() {
            return json("runId",run.toString(),"caseId","BROW.basic.json","generation",1,"state","RUNNING","checkpoints",List.of(),
                    "counters",json("httpIngress",rows.size(),"routed",rows.size(),"actions",0,"connections",null,"tlsHandshakes",null,"applicationBytes",null),
                    "events",events.deepCopy(),"truncated",false,"hostObservations",json("received",rows.deepCopy(),"truncated",false,"complete",true));
        }
        JsonObject http() {
            var applications=new JsonArray();for(String protocol:List.of("BASIC","NTLM_V1","NTLM_V2"))applications.add(json("protocol",protocol,"observations",List.of(),"requests",List.of(),"truncated",false,"handshakes",0,"posts",0,"leakedDirectives",0,"applicationAuthorizations",0));
            return json("applications",applications);
        }
        JsonObject rules() {
            return json("mode","REPLACE","policy","WAIT_FOR_LOGIN","enabled",true,"tools",List.of("PROXY","REPEATER"),"rules",List.of(json("alias","host_b","enabled",true,
                    "urlMode","SINGLE_URL","url","http://127.0.0.1:41111/cases/BROW.basic.json/protected/","regex",false,"proxyPort",null,"detect",false,"detectBy","STATUS_CODE","failureStatus",401,"responsePattern","")));
        }
        JsonObject measure(String id,long began) {
            return json("subcaseId",id,"phase","WARM","guiSequenceBefore",sequence,"rules",rules(),"serverBefore",snapshot(),"httpBefore",http(),"originals",new JsonArray(),"startedEpochMs",began);
        }
        void finish(JsonObject measure,long ended) {
            measure.addProperty("guiSequenceAfter",sequence);measure.addProperty("endedEpochMs",ended);measure.add("serverAfter",snapshot());measure.add("httpAfter",http());
        }
        void receive(String nonce,boolean accepted,boolean tag) {
            event("PROTECTED","phase-entered",List.of());if(accepted)event("PROTECTED","protected-accepted",List.of(json("kind","account","value","user")));
            rows.add(json("sequence",rows.size()+1,"caseId","BROW.basic.json","generation",1,"listenerPort",41111,
                    "request",json("nonce",nonce,"invalidNonce",false,"method","GET","route","b_c1","authorizationHeaders",1,"cookieHeaders",1,"c1",true,"c2",false,"nativeTag",tag,"httpDirective",false,"sentinel",false,"bodyBytes",0,"bodyTruncated",false),
                    "status",accepted?200:401,"accountId",accepted?"user":null,"issuanceId",accepted?"s6":null,"roles",accepted?List.of("B","C1"):List.of()));
        }
        void original(JsonObject measure,String nonce,String tool,Integer listener,String kind,String account,Integer expected,Integer actual) {
            measure.getAsJsonArray("originals").add(json("nonce",nonce,"tool",tool,"listenerPort",listener,"kind",kind,"method","GET","expectedAccount",account,"expectedStatus",expected,"clientStatus",actual));
        }
        void callback(String nonce,String family,String phase,String tool,int id,int status) {
            var row=json("sequence",callbacks.size()+1,"case","host-tags","family",family,"id",id,"phase",phase,"tool",tool,"httpVersion","HTTP/1.1","status",status,
                    "nonce",nonce,"invalidNonce",false,"shapeTruncated",false,"authorizationHeaders",1,"cookieHeaders",1,"c1",true,"c2",false,"nativeTag",true,"sentinel",false,"httpAuthenticationDirective",false);
            if(family.equals("PROXY"))row.addProperty("listener","127.0.0.1:8081");callbacks.add(row);
        }
        void receipt(String operation,JsonObject intent,JsonObject observed,long began) {
            var command=new LabHostGuiProtocol.Command(++sequence,UUID.randomUUID(),LabHostGuiProtocol.Operation.valueOf(operation),began+100,intent);
            var value=LabHostGuiProtocol.receipt(session,command,began,began+1,"PASS","GUI_OPERATION_COMPLETED",observed);
            value.addProperty("deadlineEpochMs",command.deadlineEpochMs());value.add("intent",intent);receipts.put(sequence,new LabHostEvidence.Gui(value,intent));
        }
        LabHostEvidence.Platform platform() throws Exception {
            var result=new LabHostEvidence.Platform(listeners,session,receipts,"Burp Suite Professional 2026.10.1");result.primary=41111;result.alternate=42222;return result;
        }
        JsonObject measurement(int index){return scenario.getAsJsonArray("measurements").get(index).getAsJsonObject();}
        JsonObject firstReceiver(){return measurement(0).getAsJsonObject("serverAfter").getAsJsonObject("hostObservations").getAsJsonArray("received").get(0).getAsJsonObject();}
    }
    @Test void completeTagCoreJoinsRealisticRawReceiversAndCallbacksWithoutGrantingAFullVerifiedRun() throws Exception {
        var fixture=new Fixture(directory);LabHostEvidence.validateScenario(fixture.scenario,fixture.platform());
        assertFalse(Arrays.stream(LabHostEvidence.VerifiedRun.class.getDeclaredConstructors()).anyMatch(c->java.lang.reflect.Modifier.isPublic(c.getModifiers())));
        assertEquals(LabHostEvidence.RequirementProof.class,Class.forName(LabHostEvidence.OWNER).getDeclaredMethod("verifyRequirement",String.class).getReturnType());
        assertEquals(50,LabHostEvidence.subcases().values().stream().mapToInt(List::size).sum());assertEquals(LabHostScenarios.SUBCASES,LabHostEvidence.subcases());
    }
    @TestFactory Stream<DynamicTest> passingFlagsCannotReplaceIndependentOrCurrentObservations() {
        var changes=new LinkedHashMap<String,Consumer<Fixture>>();
        changes.put("missing-server",f->f.measurement(0).getAsJsonObject("serverAfter").getAsJsonObject("hostObservations").getAsJsonArray("received").remove(0));
        changes.put("wrong-user",f->{f.firstReceiver().addProperty("accountId","user2");f.firstReceiver().addProperty("issuanceId","s7");});
        changes.put("wrong-roles",f->f.firstReceiver().add("roles",LabJson.JSON.toJsonTree(List.of("B"))));
        changes.put("tag-leak",f->f.firstReceiver().getAsJsonObject("request").addProperty("nativeTag",true));
        changes.put("duplicate-execution",f->f.measurement(0).getAsJsonObject("serverAfter").getAsJsonObject("hostObservations").getAsJsonArray("received").add(f.firstReceiver().deepCopy()));
        changes.put("truncated-server",f->f.measurement(0).getAsJsonObject("serverAfter").getAsJsonObject("hostObservations").addProperty("truncated",true));
        changes.put("pending-server",f->f.measurement(0).getAsJsonObject("serverAfter").getAsJsonObject("hostObservations").addProperty("complete",false));
        changes.put("stale-generation",f->f.firstReceiver().addProperty("generation",2));
        changes.put("wrong-nonce",f->f.firstReceiver().getAsJsonObject("request").addProperty("nonce","hffffffffffffffff"));
        changes.put("foreign-identity",f->f.scenario.addProperty("runNonce",UUID.randomUUID().toString()));
        changes.put("probe-overflow",f->f.scenario.getAsJsonObject("probe").addProperty("overflow",true));
        changes.put("wrong-listener",f->f.scenario.getAsJsonObject("probe").getAsJsonArray("events").get(0).getAsJsonObject().addProperty("listener","127.0.0.1:9999"));
        changes.put("missing-response-callback",f->f.scenario.getAsJsonObject("probe").getAsJsonArray("events").get(1).getAsJsonObject().addProperty("phase","received"));
        changes.put("changed-client-status",f->f.measurement(0).getAsJsonArray("originals").get(0).getAsJsonObject().addProperty("clientStatus",401));
        changes.put("missing-case",f->f.scenario.getAsJsonArray("measurements").remove(1));
        changes.put("bad-rule",f->f.measurement(0).getAsJsonObject("rules").getAsJsonArray("rules").get(0).getAsJsonObject().addProperty("alias","host_a"));
        changes.put("deadline",f->f.scenario.addProperty("endedEpochMs",190001));
        return changes.entrySet().stream().map(change->DynamicTest.dynamicTest(change.getKey(),()->{
            var fixture=new Fixture(directory);change.getValue().accept(fixture);
            assertThrows(LabHostEvidence.Rejected.class,()->LabHostEvidence.validateScenario(fixture.scenario,fixture.platform()));
        }));
    }
    @Test void missingAndLatePublicGuiProofCannotBeSubstitutedWithAPassReceipt() throws Exception {
        var fixture=new Fixture(directory);var pass=fixture.receipts.get(4L).receipt();pass.remove("deadlineEpochMs");
        assertThrows(IllegalArgumentException.class,fixture::platform);
        fixture=new Fixture(directory);pass=fixture.receipts.get(4L).receipt();pass.addProperty("deadlineEpochMs",1);
        assertThrows(IllegalArgumentException.class,fixture::platform);
    }
    @Test void qualificationAndSinglePlatformPlansCannotCreateAcceptanceProof() throws Exception {
        Path capture=Files.createDirectory(directory.resolve("capture"));Path bytes=Files.writeString(capture.resolve("fixture.jar"),"fixture");
        var artifact=new LabHostInputs.Artifact(bytes,LabJson.sha256(bytes),Files.size(bytes),null);
        for(var mode:LabHostInputs.Mode.values()) {
            var plan=new LabHostInputs.Plan(UUID.randomUUID(),mode,List.of("windows"),mode==LabHostInputs.Mode.ACCEPTANCE?LabHostEvidence.TASK:":authLabHostQualify",
                    "a".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(40),Map.of("fixture.java","e".repeat(64)),artifact,artifact,artifact,List.of(),artifact,capture);
            var rejected=assertThrows(LabHostEvidence.Rejected.class,()->LabHostEvidence.validate(directory,directory,plan));
            assertEquals(LabHostCoordinator.Outcome.BLOCKED,rejected.outcome());assertEquals("HOST_ACCEPTANCE_IDENTITY",rejected.code());
        }
    }
    @Test void reviewedBindingMarkerIsNotMisusedAsFreshnessProof() throws Exception {
        var hashes=new LinkedHashMap<String,String>();
        for(String source:LabHostEvidence.criticalOwners()) {
            Path path=directory.resolve(source);Files.createDirectories(path.getParent());Files.writeString(path,"fixture-source:"+source);hashes.put(source,LabJson.sha256(path));
        }
        String id="H01.tool=proxy~mode=automatic-combined-injection";var witnesses=new ArrayList<ScenarioCatalog.Witness>();
        for(String scenario:LabHostEvidence.requiredScenarios(id))witnesses.add(new ScenarioCatalog.Witness(id,id+":"+scenario,LabHostEvidence.SOURCE,LabHostEvidence.sourceSymbol(scenario),scenario));
        var binding=new ScenarioCatalog.Binding("HOST:"+id,"HOST",LabHostEvidence.OWNER,LabHostEvidence.METHOD,id,witnesses,"reviewed-owner-marker",hashes,LabHostEvidence.TASK,"a".repeat(64),null);
        var original=ScenarioCatalog.load().requirement(id);
        var row=new ScenarioCatalog.Requirement(original.id(),original.group(),original.revision(),original.contract(),original.layer(),original.axes(),original.capabilities(),original.roles(),original.recipe(),original.assignments(),original.expected(),original.faults(),original.evidence(),original.budget(),binding,ScenarioCatalog.Disposition.EXTEND);
        Path bytes=Files.writeString(directory.resolve("fixture.jar"),"fixture");var artifact=new LabHostInputs.Artifact(bytes,LabJson.sha256(bytes),Files.size(bytes),null);
        var plan=new LabHostInputs.Plan(UUID.randomUUID(),LabHostInputs.Mode.ACCEPTANCE,LabHostInputs.PLATFORMS,LabHostEvidence.TASK,"a".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(40),hashes,artifact,artifact,artifact,List.of(),artifact,directory);
        assertNotEquals(binding.sourceRevision(),plan.sourceRevision());assertTrue(LabHostEvidence.bindingCurrent(row,plan,directory));
        Path changed=directory.resolve(LabHostEvidence.SOURCE);Files.writeString(changed,"changed after review");
        assertFalse(LabHostEvidence.bindingCurrent(row,plan,directory));
    }
    private static JsonObject environment() {
        return json("version",1,"burpVersion","Burp Suite Professional 2026.10.1","javaVersion","26.0.2","labJavaVersion","21.0.4","os","Linux",
                "maxBurpHeapMiB",2048,"actualMaxHeapBytes",2147483648L,"physicalMemoryMiB",6144,"listeners",List.of(8081,8082,8083),"adapter","JDK_AWT_ROBOT_V1","burpPid",200,"burpStartedEpochMs",900);
    }
    private static JsonObject memory(LabHostGuiProtocol.Session session) {
        var value=LabHostGuiProtocol.identity(session);value.addProperty("pid",200);value.addProperty("startedEpochMs",900);value.addProperty("intervalMs",200);
        value.addProperty("peakRssBytes",128L<<20);value.addProperty("samples",10);value.addProperty("overflow",false);value.addProperty("complete",true);
        value.addProperty("firstSampleEpochMs",1000);value.addProperty("lastSampleEpochMs",3000);value.addProperty("maxSampleGapMs",200);
        value.add("gc",json("complete",true,"objectObservations",2,"gcObservations",1,"maxObservedObjectBytes",64L<<20,"peakObservedHumongousBytes",96L<<20));return value;
    }
    private static JsonObject started(LabHostGuiProtocol.Session session) {
        return json("version",1,"invocationId",session.invocationId().toString(),"runNonce",session.runNonce().toString(),"pid",100,"startedEpochMs",500,"executable","/fixture/java");
    }
    private static JsonObject cleanup(LabHostGuiProtocol.Session session) {
        var value=LabHostGuiProtocol.identity(session);value.addProperty("guestPid",100);value.addProperty("guestStartedEpochMs",500);value.addProperty("durationMs",123);value.addProperty("rootRemoved",true);value.addProperty("outcome","COMPLETE");return value;
    }
    private static JsonObject terminal(LabHostGuiProtocol.Session session) {
        var value=LabHostGuiProtocol.identity(session);value.addProperty("outcome","PASS");value.addProperty("code","HOST_SCENARIOS_VERIFIED");value.addProperty("cleanup","COMPLETE");
        value.addProperty("unattended",true);value.addProperty("stage","SCENARIOS");value.addProperty("durationMs",10000);
        var scenarios=new JsonObject();LabHostInputs.SCENARIOS.forEach(id->scenarios.addProperty(id,"PASS"));value.add("scenarios",scenarios);value.add("evidence",new JsonArray());return value;
    }
    @Test void numericMetadataOwnersValidateTheirActualIdentityAndPinnedContract() throws Exception {
        var session=new Fixture(directory).session;LabHostEvidence.validateEnvironment(environment(),"linux");
        LabHostEvidence.validateMemoryNumbers(memory(session),environment(),session);LabHostEvidence.validateCleanup(cleanup(session),started(session),session);
        LabHostEvidence.validateTerminal(terminal(session),session);
    }
    @TestFactory Stream<DynamicTest> unsupportedVendorsAndRequestedHeapLabelsDoNotProveTheActualVm() {
        var changes=new LinkedHashMap<String,Consumer<JsonObject>>();
        changes.put("newer-vendor",v->v.addProperty("burpVersion","Burp Suite Professional 2026.10.10"));
        changes.put("vendor-extra-component",v->v.addProperty("burpVersion","2026.10.1.5"));
        changes.put("wrong-jvm",v->v.addProperty("javaVersion","26.0.3"));changes.put("old-lab-jvm",v->v.addProperty("labJavaVersion","20"));
        changes.put("wrong-os",v->v.addProperty("os","Windows 11"));changes.put("assisted-adapter",v->v.addProperty("adapter","OPERATOR_ASSISTED"));
        changes.put("requested-only",v->v.remove("actualMaxHeapBytes"));changes.put("large-heap",v->v.addProperty("actualMaxHeapBytes",4294967296L));
        changes.put("wrong-requested-heap",v->v.addProperty("maxBurpHeapMiB",4096));
        return changes.entrySet().stream().map(change->DynamicTest.dynamicTest(change.getKey(),()->{
            var value=environment();change.getValue().accept(value);assertThrows(LabHostEvidence.Rejected.class,()->LabHostEvidence.validateEnvironment(value,"linux"));
        }));
    }
    @TestFactory Stream<DynamicTest> incompleteRssOrGcCannotBeHiddenBehindCompleteFlags() {
        var changes=new LinkedHashMap<String,Consumer<JsonObject>>();
        changes.put("foreign-pid",v->v.addProperty("pid",201));changes.put("stale-process-start",v->v.addProperty("startedEpochMs",800));
        changes.put("slow-cadence",v->v.addProperty("intervalMs",1000));changes.put("large-gap",v->v.addProperty("maxSampleGapMs",2001));
        changes.put("zero-samples",v->v.addProperty("samples",0));changes.put("overflow",v->v.addProperty("overflow",true));
        changes.put("incomplete",v->v.addProperty("complete",false));changes.put("too-many-samples",v->v.addProperty("samples",20001));
        changes.put("zero-rss",v->v.addProperty("peakRssBytes",0));changes.put("incomplete-gc",v->v.getAsJsonObject("gc").addProperty("complete",false));
        changes.put("inconsistent-gc",v->v.getAsJsonObject("gc").addProperty("peakObservedHumongousBytes",1));
        changes.put("raw-gc-is-forbidden",v->v.getAsJsonObject("gc").addProperty("rawLog","PRIVATE_SENTINEL"));
        return changes.entrySet().stream().map(change->DynamicTest.dynamicTest(change.getKey(),()->{
            var session=new Fixture(directory).session;var value=memory(session);change.getValue().accept(value);
            assertThrows(LabHostEvidence.Rejected.class,()->LabHostEvidence.validateMemoryNumbers(value,environment(),session));
        }));
    }
    @TestFactory Stream<DynamicTest> ownedRootCleanupMustMatchTheExactGuestOwner() {
        var changes=new LinkedHashMap<String,Consumer<JsonObject>>();
        changes.put("root-remains",v->v.addProperty("rootRemoved",false));changes.put("cleanup-incomplete",v->v.addProperty("outcome","INCOMPLETE"));
        changes.put("foreign-guest",v->v.addProperty("guestPid",101));changes.put("reused-pid",v->v.addProperty("guestStartedEpochMs",501));
        changes.put("foreign-run",v->v.addProperty("runNonce",UUID.randomUUID().toString()));
        return changes.entrySet().stream().map(change->DynamicTest.dynamicTest(change.getKey(),()->{
            var session=new Fixture(directory).session;var value=cleanup(session);change.getValue().accept(value);
            assertThrows(LabHostEvidence.Rejected.class,()->LabHostEvidence.validateCleanup(value,started(session),session));
        }));
    }
    @TestFactory Stream<DynamicTest> partialAssistedOrLatePlatformFlagsCannotGrantAcceptance() {
        var changes=new LinkedHashMap<String,Consumer<JsonObject>>();
        changes.put("assisted",v->v.addProperty("unattended",false));changes.put("bad-cleanup",v->v.addProperty("cleanup","INCOMPLETE"));
        changes.put("primitive-only",v->v.addProperty("stage","PRIMITIVES"));changes.put("missing-scenario",v->v.getAsJsonObject("scenarios").remove("unload"));
        changes.put("blocked-case",v->v.getAsJsonObject("scenarios").addProperty("routing","BLOCKED"));changes.put("platform-deadline",v->v.addProperty("durationMs",45*60_000+1));
        return changes.entrySet().stream().map(change->DynamicTest.dynamicTest(change.getKey(),()->{
            var session=new Fixture(directory).session;var value=terminal(session);change.getValue().accept(value);
            var rejected=assertThrows(LabHostEvidence.Rejected.class,()->LabHostEvidence.validateTerminal(value,session));assertEquals(LabHostCoordinator.Outcome.BLOCKED,rejected.outcome());
        }));
    }
    @Test void cancellationAndObservedFailureRemainDistinctFromMissingEvidence() throws Exception {
        var session=new Fixture(directory).session;var failed=terminal(session);failed.addProperty("outcome","FAIL");
        assertEquals(LabHostCoordinator.Outcome.FAIL,assertThrows(LabHostEvidence.Rejected.class,()->LabHostEvidence.validateTerminal(failed,session)).outcome());
        var stopped=terminal(session);stopped.addProperty("outcome","INTERRUPTED");
        assertEquals(LabHostCoordinator.Outcome.INTERRUPTED,assertThrows(LabHostEvidence.Rejected.class,()->LabHostEvidence.validateTerminal(stopped,session)).outcome());
    }
    @Test void changedCapturedBytesRejectTheEntireRunBeforeSuccessReceiptsAreConsidered() throws Exception {
        UUID invocation=UUID.randomUUID();Path workspace=Files.createDirectory(directory.resolve("workspace"));
        Path report=workspace.resolve("test/authentication-lab/build/authlab").resolve(invocation.toString()).resolve(LabEvidence.sha256(LabHostEvidence.TASK.getBytes(java.nio.charset.StandardCharsets.UTF_8)));Files.createDirectories(report);
        Path capture=workspace.resolve("test/authentication-lab/build/host-runtime").resolve(invocation.toString()).resolve("capture");Files.createDirectories(capture);Path bytes=Files.writeString(capture.resolve("fixture.jar"),"captured");
        var artifact=new LabHostInputs.Artifact(bytes,LabJson.sha256(bytes),Files.size(bytes),null);
        var plan=new LabHostInputs.Plan(invocation,LabHostInputs.Mode.ACCEPTANCE,LabHostInputs.PLATFORMS,LabHostEvidence.TASK,"a".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(40),Map.of("fixture.java","e".repeat(64)),artifact,artifact,artifact,List.of(),artifact,capture);
        Files.writeString(bytes,"changed after capture");var rejected=assertThrows(LabHostEvidence.Rejected.class,()->LabHostEvidence.validate(report,workspace,plan));
        assertEquals(LabHostCoordinator.Outcome.BLOCKED,rejected.outcome());assertEquals("HOST_ARTIFACT_CHANGED",rejected.code());
    }
    @Test void aNewUnlistedJavaFileInvalidatesAnOtherwiseMatchingSourceTree() throws Exception {
        Path root=directory.resolve("bapp/src");Files.createDirectories(root);Path original=Files.writeString(root.resolve("Original.java"),"fixture");
        var hashes=Map.of("bapp/src/Original.java",LabJson.sha256(original));var audit=json("sourceTrees",List.of("bapp/src"));
        assertEquals(List.of("bapp/src"),LabHostEvidence.validateSourceInventory(directory,audit,hashes));
        Files.writeString(root.resolve("AddedAfterCapture.java"),"new unreviewed source");
        var rejected=assertThrows(LabHostEvidence.Rejected.class,()->LabHostEvidence.validateSourceInventory(directory,audit,hashes));
        assertEquals("HOST_SOURCE_INVENTORY_CHANGED",rejected.code());
    }
    @Test void sourceTreeMetadataCannotOmitItsProtocolOrEscapeTheWorkspace() throws Exception {
        Path root=directory.resolve("bapp/src");Files.createDirectories(root);Path original=Files.writeString(root.resolve("Original.java"),"fixture");
        var hashes=Map.of("bapp/src/Original.java",LabJson.sha256(original));
        for(var audit:List.of(new JsonObject(),json("sourceTrees",List.of()),json("sourceTrees",List.of("../outside")),json("sourceTrees",List.of("bapp/src","bapp/src")),json("sourceTrees",List.of("bapp","bapp/src"))))
            assertThrows(LabHostEvidence.Rejected.class,()->LabHostEvidence.validateSourceInventory(directory,audit,hashes));
        Files.delete(original);assertThrows(LabHostEvidence.Rejected.class,()->LabHostEvidence.validateSourceInventory(directory,json("sourceTrees",List.of("bapp/src")),hashes));
    }
    @Test void canonicalHostPageObservationPrecedesCredentialsAndUsesRealTimeRatherThanTheExpiryClock() throws Exception {
        try(var run=LabRun.startHost(new LabRun.RunSpec(UUID.randomUUID(),List.of("browser"),ScenarioCatalog.load(),directory,List.of(),5000));
            var lease=run.prepareCase("BROW.basic.json");var client=ControlledApplication.localClientBuilder().build()) {
            var ordinary=client.send(java.net.http.HttpRequest.newBuilder(lease.endpoint("start")).GET().build(),java.net.http.HttpResponse.BodyHandlers.discarding());
            assertEquals(200,ordinary.statusCode());assertTrue(pageEvents(lease).isEmpty());
            lease.advanceFixtureClock(java.time.Duration.ofHours(1));long before=System.currentTimeMillis();
            var page=client.send(java.net.http.HttpRequest.newBuilder(lease.endpoint("start?bpsh_host_journey=host_a")).GET().build(),java.net.http.HttpResponse.BodyHandlers.ofString());
            long after=System.currentTimeMillis();assertEquals(200,page.statusCode());assertTrue(page.body().contains("id=login-form"));
            var events=pageEvents(lease);assertEquals(1,events.size());var event=events.getFirst();
            assertEquals("LOGIN",event.get("phase").getAsString());assertEquals("host_a",event.getAsJsonArray("safeIds").get(0).getAsJsonObject().get("value").getAsString());
            long observed=java.time.Instant.parse(event.get("time").getAsString()).toEpochMilli();assertTrue(observed>=before&&observed<=after);
            assertEquals(0,lease.occurrences.getOrDefault(LabRun.Phase.LOGIN,0));
            for(String invalid:List.of("PRIVATE_SENTINEL","host_c","","host_a&bpsh_host_journey=host_b")) {
                assertEquals(400,client.send(java.net.http.HttpRequest.newBuilder(lease.endpoint("start?bpsh_host_journey="+invalid)).GET().build(),java.net.http.HttpResponse.BodyHandlers.discarding()).statusCode());
            }
            assertEquals(1,pageEvents(lease).size());assertFalse(LabRun.JSON.toJson(lease.snapshot()).contains("PRIVATE_SENTINEL"));
            assertEquals(0,lease.occurrences.getOrDefault(LabRun.Phase.LOGIN,0));
        }
    }
    private static List<JsonObject> pageEvents(LabRun.CaseLease lease) {
        return LabRun.JSON.toJsonTree(lease.snapshot()).getAsJsonObject().getAsJsonArray("events").asList().stream().map(JsonElement::getAsJsonObject)
                .filter(event->event.get("name").getAsString().equals("host-login-page-response-start")).toList();
    }
    private static JsonObject timedEvent(int sequence,long at,String name,List<JsonObject> ids) {
        return json("sequence",sequence,"time",java.time.Instant.ofEpochMilli(at).toString(),"phase","LOGIN","name",name,"safeIds",ids);
    }
    private static JsonObject admissionFixture() {
        var before=new JsonArray();var after=new JsonArray();
        after.add(timedEvent(1,1120,"host-login-page-response-start",List.of(json("kind","journey-alias","value","host_a"))));
        after.add(timedEvent(2,1140,"host-login-page-response-start",List.of(json("kind","journey-alias","value","host_b"))));
        after.add(timedEvent(3,1200,"phase-entered",List.of()));after.add(timedEvent(4,1210,"phase-entered",List.of()));
        after.add(timedEvent(5,1300,"login-completed",List.of(json("kind","account","value","user"),json("kind","issuance","value","s6"))));
        after.add(timedEvent(6,1310,"login-completed",List.of(json("kind","account","value","user2"),json("kind","issuance","value","s7"))));
        var observations=new JsonArray();
        observations.add(json("alias","host_a","nonce","h0000000000000001","dispatchEpochMs",1050,"serverEventSequence",1,"elapsedMs",70,"boundary","CLIENT_DISPATCH_TO_LOGIN_PAGE_RESPONSE_START"));
        observations.add(json("alias","host_b","nonce","h0000000000000002","dispatchEpochMs",1060,"serverEventSequence",2,"elapsedMs",80,"boundary","CLIENT_DISPATCH_TO_LOGIN_PAGE_RESPONSE_START"));
        return json("startedEpochMs",1000,"endedEpochMs",1400,"serverBefore",json("events",before),"serverAfter",json("events",after),"originals",List.of(
                json("nonce","h0000000000000001"),json("nonce","h0000000000000002"),json("nonce","h0000000000000003")),"browserAdmission",observations);
    }
    @Test void coldFirstPageDurationsAreRecomputedFromTheJoinedServerEvents() throws Exception {
        LabHostEvidence.validateColdAdmission(admissionFixture());
    }
    @TestFactory Stream<DynamicTest> firstPageTimingRejectsWarmForeignDuplicatePrematureOrInventedObservations() {
        var changes=new LinkedHashMap<String,Consumer<JsonObject>>();
        changes.put("missing-page",m->m.getAsJsonObject("serverAfter").getAsJsonArray("events").remove(0));
        changes.put("duplicate-page",m->m.getAsJsonObject("serverAfter").getAsJsonArray("events").add(m.getAsJsonObject("serverAfter").getAsJsonArray("events").get(0).deepCopy()));
        changes.put("foreign-alias",m->m.getAsJsonObject("serverAfter").getAsJsonArray("events").get(0).getAsJsonObject().getAsJsonArray("safeIds").get(0).getAsJsonObject().addProperty("value","host_failure_a"));
        changes.put("wrong-request",m->m.getAsJsonArray("browserAdmission").get(0).getAsJsonObject().addProperty("nonce","h0000000000000002"));
        changes.put("wrong-event",m->m.getAsJsonArray("browserAdmission").get(0).getAsJsonObject().addProperty("serverEventSequence",2));
        changes.put("premature-page",m->m.getAsJsonArray("browserAdmission").get(0).getAsJsonObject().addProperty("dispatchEpochMs",1121));
        changes.put("invented-duration",m->m.getAsJsonArray("browserAdmission").get(0).getAsJsonObject().addProperty("elapsedMs",71));
        changes.put("different-boundary",m->m.getAsJsonArray("browserAdmission").get(0).getAsJsonObject().addProperty("boundary","PURE_ENGINE_CPU_TIME"));
        changes.put("warm-cache",m->m.getAsJsonObject("serverBefore").getAsJsonArray("events").add(timedEvent(1,900,"login-completed",List.of())));
        changes.put("already-started",m->m.getAsJsonObject("serverBefore").getAsJsonArray("events").add(timedEvent(1,900,"host-login-page-response-start",List.of(json("kind","journey-alias","value","host_a")))));
        changes.put("missing-alias",m->m.getAsJsonArray("browserAdmission").remove(1));
        changes.put("completion-before-page",m->m.getAsJsonObject("serverAfter").getAsJsonArray("events").get(4).getAsJsonObject().addProperty("time",java.time.Instant.ofEpochMilli(1000).toString()));
        return changes.entrySet().stream().map(change->DynamicTest.dynamicTest(change.getKey(),()->{
            var measurement=admissionFixture();change.getValue().accept(measurement);assertThrows(LabHostEvidence.Rejected.class,()->LabHostEvidence.validateColdAdmission(measurement));
        }));
    }
}
