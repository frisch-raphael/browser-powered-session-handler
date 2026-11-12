package lab.auth;

import com.google.gson.*;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;
import static lab.auth.LabHostCoordinator.Outcome;

/** Joins captured host inputs, real GUI operations and independent receiving applications. */
public final class LabHostEvidence {
    private LabHostEvidence() { }
    public static final String TASK=":authLabHostTest", OWNER="lab.auth.LabHostEvidence$VerifiedRun", METHOD="verifyRequirement(java.lang.String)";
    public static final String SOURCE="test/authentication-lab/src/main/java/lab/auth/LabHostScenarios.java";
    private static final String ADAPTER="JDK_AWT_ROBOT_V1", BURP="2026.10.1", JAVA="26.0.2";
    private static final Map<String,List<String>> REQUIREMENTS=requirements();
    private static final Map<String,List<String>> SUBCASES=recipes();
    static Map<String,List<String>> subcases(){return SUBCASES;}
    private static Map<String,List<String>> recipes() {
        var result=new LinkedHashMap<String,List<String>>();
        result.put("routing",List.of("port-cold","port-warm","url-prefix","url-and-port","regex-substring","regex-case-miss","regex-case-fold","regex-anchor","regex-anchor-miss","regex-invalid-retains"));
        result.put("tags",List.of("proxy-explicit-a","repeater-explicit-a","repeater-unknown","proxy-unknown"));
        result.put("repeater",List.of("copied-ordinary","removed-port-only","url-only","explicit-tags"));
        var http=new ArrayList<String>();for(String protocol:List.of("basic","ntlm_v1","ntlm_v2"))
            for(String action:List.of("test-a","test-b","proxy-a","proxy-b","proxy-a2","repeater-a","repeater-b","repeater-a2"))http.add(protocol+"-"+action);
        result.put("http-auth",List.copyOf(http));result.put("recovery",List.of("shared-two-originals"));result.put("rejected-replay",List.of("rejected-replay","paused-subsequent"));
        result.put("intercept",List.of("matching-to-alternate","alternate-to-matching"));result.put("unload",List.of("pending-unload","post-reload-fresh"));result.put("ordinary-failure",List.of("exhausted-login-unchanged"));
        return Collections.unmodifiableMap(result);
    }
    public static Map<String,List<String>> requiredScenarios(){return REQUIREMENTS;}
    public static List<String> requiredScenarios(String id){
        var result=REQUIREMENTS.get(id);if(result==null)throw new IllegalArgumentException("HOST_REQUIREMENT");return result;
    }
    public static String protocol(String id) {
        return switch(id){case "HOST.http-auth.basic"->"BASIC";case "HOST.http-auth.ntlm-v1"->"NTLM_V1";case "HOST.http-auth.ntlm-v2"->"NTLM_V2";default->null;};
    }
    static String sourceSymbol(String scenario) {
        return switch(scenario){case "http-auth"->"httpAuth";case "rejected-replay"->"rejectedReplay";case "ordinary-failure"->"ordinaryFailure";default->scenario;};
    }
    public static String configurationFingerprint(Path workspace) throws IOException {return LabProductionEvidence.configurationFingerprint(workspace,TASK);}
    static List<String> criticalOwners() {
        var owners=new ArrayList<String>();
        for(String name:List.of("LabHostEvidence","LabHostScenarios","LabHostGuest","LabHostCoordinator","LabHostInputs","LabHostArtifactCache","LabHostVmTransport","LabHostGuiProtocol","LabHostMemory","LabHostObservations",
                "LabEvidence","LabProductionEvidence","ScenarioCatalog","RefreshBindings","LabJson","LabRun","LoginFlows","ControlledApplication","HttpAuthenticationFixture","FixtureIdentityStore"))
            owners.add("test/authentication-lab/src/main/java/lab/auth/"+name+".java");
        for(String name:List.of("HostGuiBootstrap","HostGuiDriver","HostGuiSelectors","HostGuiRules","HostGuiProbe","HostGuiAssertions","HostGuiMessages","HostGuiDiagnostics","HostGuiPreferences","HostProbeShape"))
            owners.add("test/authentication-lab/src/hostGui/java/lab/auth/gui/"+name+".java");
        owners.add("test/authentication-lab/src/hostProbe/java/lab/auth/HostProbeExtension.java");return List.copyOf(owners);
    }
    private static Map<String,List<String>> requirements() {
        var rows=new LinkedHashMap<String,List<String>>();
        rows.put("H01.tool=proxy~mode=automatic-combined-injection",List.of("routing","intercept"));
        rows.put("H01.tool=proxy~mode=native-tags",List.of("tags"));
        rows.put("H01.tool=repeater~mode=automatic-combined-injection",List.of("repeater"));
        rows.put("H01.tool=repeater~mode=native-tags",List.of("tags","repeater"));
        rows.put("H02.ordinary-unchanged",List.of("ordinary-failure"));rows.put("H02.tagged-stop",List.of("tags","repeater"));
        rows.put("H03.successful-replay",List.of("recovery"));rows.put("H03.rejected-replacement-pauses",List.of("rejected-replay"));
        rows.put("H06.unload-reload",List.of("unload"));
        for(String protocol:List.of("basic","ntlm-v1","ntlm-v2"))rows.put("HOST.http-auth."+protocol,List.of("http-auth"));
        return Collections.unmodifiableMap(rows);
    }
    public record RequirementProof(String requirementId,List<String> platforms,List<String> scenarios,String protocol,
                                   UUID invocationId,String productSha256,Map<String,String> evidenceHashes,Map<String,Long> timings) {
        public RequirementProof {platforms=List.copyOf(platforms);scenarios=List.copyOf(scenarios);evidenceHashes=Map.copyOf(evidenceHashes);timings=Map.copyOf(timings);}
    }
    /** Constructed only after every platform and every mandatory scenario has independently passed validation. */
    public static final class VerifiedRun {
        private final LabHostInputs.Plan plan;private final Map<String,String> hashes;private final Set<String> eligible;private final Map<String,Map<String,Long>> timings;
        private VerifiedRun(LabHostInputs.Plan plan,Map<String,String> hashes,Set<String> eligible,Map<String,Map<String,Long>> timings){this.plan=plan;this.hashes=Map.copyOf(hashes);this.eligible=Set.copyOf(eligible);this.timings=Map.copyOf(timings);}
        public RequirementProof verifyRequirement(String id) throws Rejected {
            requiredScenarios(id);need(eligible.contains(id),"HOST_BINDING_NOT_AUTOMATED_OR_CURRENT");
            return new RequirementProof(id,LabHostInputs.PLATFORMS,requiredScenarios(id),protocol(id),plan.invocationId(),plan.product().sha256(),hashes,timings.get(id));
        }
    }
    public static final class Rejected extends IOException {
        private final Outcome outcome;private final String code;
        private Rejected(Outcome outcome,String code){super(code);this.outcome=outcome;this.code=code;}
        public Outcome outcome(){return outcome;}public String code(){return code;}
    }
    private static void need(boolean condition,String code) throws Rejected {if(!condition)throw new Rejected(Outcome.BLOCKED,code);}
    private static void fact(boolean condition,String code) throws Rejected {if(!condition)throw new Rejected(Outcome.FAIL,code);}
    private static JsonObject object(JsonElement value){return LabJson.object(value);}
    private static JsonArray array(JsonObject value,String key){var a=value.get(key);LabJson.require(a!=null&&a.isJsonArray(),"HOST_ARRAY");return a.getAsJsonArray();}
    private static String text(JsonObject value,String key){return LabJson.string(value.get(key));}
    private static String nullable(JsonObject value,String key){var v=value.get(key);return v==null||v.isJsonNull()?null:LabJson.text(v);}
    private static long number(JsonObject value,String key) {
        var v=value.get(key);LabJson.require(v!=null&&v.isJsonPrimitive()&&v.getAsJsonPrimitive().isNumber(),"HOST_NUMBER");
        long result=new BigDecimal(v.getAsString()).longValueExact();LabJson.require(result>=0,"HOST_NUMBER");return result;
    }
    private static boolean bool(JsonObject value,String key) {
        var v=value.get(key);LabJson.require(v!=null&&v.isJsonPrimitive()&&v.getAsJsonPrimitive().isBoolean(),"HOST_BOOLEAN");return v.getAsBoolean();
    }
    private static Set<String> words(String value){return value.isEmpty()?Set.of():new HashSet<>(List.of(value.split(" ")));}
    private static void fields(JsonObject value,String required,String optional) throws Rejected {
        var keys=words(required);var allowed=new HashSet<>(keys);allowed.addAll(words(optional));
        need(value.keySet().containsAll(keys)&&allowed.containsAll(value.keySet()),"HOST_SCHEMA");
    }
    private static List<JsonObject> objects(JsonArray value){return value.asList().stream().map(LabHostEvidence::object).toList();}
    private static void identity(JsonObject value,LabHostGuiProtocol.Session session) throws Rejected {
        need(number(value,"version")==1&&text(value,"invocationId").equals(session.invocationId().toString())&&text(value,"platform").equals(session.platform())
                &&text(value,"runNonce").equals(session.runNonce().toString())&&text(value,"productSha256").equals(session.productSha256())
                &&text(value,"helperSha256").equals(session.helperSha256()),"HOST_FOREIGN_IDENTITY");
    }
    private static long duration(JsonObject value,long limit) throws Rejected {
        long began=number(value,"startedEpochMs"),ended=number(value,"endedEpochMs");need(began>0&&ended>=began&&ended-began<=limit,"HOST_DEADLINE");return ended-began;
    }
    private static Path file(Path root,String name) throws IOException {
        LabJson.relative(new JsonPrimitive(name));Path result=root.resolve(name);
        need(Files.isRegularFile(result,LinkOption.NOFOLLOW_LINKS)&&result.toRealPath().getParent().equals(root.toRealPath()),"HOST_FILE_MISSING_OR_FOREIGN");return result;
    }
    private static JsonObject read(Path root,String name,int limit,Map<String,String> hashes) throws IOException {
        Path path=file(root,name);byte[] bytes;
        try(var input=Files.newInputStream(path)){bytes=input.readNBytes(limit+1);}
        need(bytes.length<=limit,"HOST_EVIDENCE_SIZE");var value=object(LabJson.parse(bytes));hashes.put(root.getFileName()+"/"+name,LabEvidence.sha256(bytes));return value;
    }
    public static VerifiedRun validate(Path directory,Path workspace,LabHostInputs.Plan plan) throws IOException {
        try {
            directory=directory.toRealPath();workspace=workspace.toRealPath();
            need(plan.mode()==LabHostInputs.Mode.ACCEPTANCE&&plan.taskPath().equals(TASK)&&plan.platforms().equals(LabHostInputs.PLATFORMS),"HOST_ACCEPTANCE_IDENTITY");
            Path expected=workspace.resolve("test/authentication-lab/build/authlab").resolve(plan.invocationId().toString())
                    .resolve(LabEvidence.sha256(TASK.getBytes(StandardCharsets.UTF_8))).normalize();
            need(directory.equals(expected)&&directory.startsWith(workspace),"HOST_REPORT_OWNER");
            verifyInputs(workspace,plan);
            var current=ScenarioCatalog.load(workspace.resolve("test/authentication-lab/src/main/resources/catalog"));var eligible=new HashSet<String>();
            for(String id:REQUIREMENTS.keySet()) {
                var row=current.requirement(id);if(row.disposition()!=ScenarioCatalog.Disposition.MANUAL&&bindingCurrent(row,plan,workspace))eligible.add(id);
            }
            var hashes=new LinkedHashMap<String,String>();var context=read(directory,"report-context.json",1_048_576,hashes);
            fields(context,"version invocationId taskPath mode platforms sourceRevision sourceHashes configurationHash catalogRevision productSha256 helperSha256 state auditSha256 scenariosSha256 adapter runtime","");
            need(number(context,"version")==1&&text(context,"invocationId").equals(plan.invocationId().toString())&&text(context,"taskPath").equals(TASK)
                    &&text(context,"mode").equals("ACCEPTANCE")&&LabJson.strings(context.get("platforms")).equals(LabHostInputs.PLATFORMS)
                    &&text(context,"state").equals("STARTED")&&text(context,"adapter").equals(ADAPTER),"HOST_CONTEXT_IDENTITY");
            for(var entry:Map.of("sourceRevision",plan.sourceRevision(),"configurationHash",plan.configurationHash(),"catalogRevision",plan.catalogRevision(),
                    "productSha256",plan.product().sha256(),"helperSha256",plan.helper().sha256(),"auditSha256",plan.audit().sha256(),"scenariosSha256",plan.scenarios().sha256()).entrySet())
                need(text(context,entry.getKey()).equals(entry.getValue()),"HOST_CONTEXT_ARTIFACT");
            need(object(context.get("sourceHashes")).equals(LabJson.JSON.toJsonTree(plan.sourceHashes())),"HOST_CONTEXT_SOURCE");
            var runtime=new JsonArray();for(var artifact:plan.runtime()){var item=new JsonObject();item.addProperty("role",artifact.role());item.addProperty("sha256",artifact.sha256());item.addProperty("bytes",artifact.bytes());runtime.add(item);}
            need(array(context,"runtime").equals(runtime),"HOST_CONTEXT_RUNTIME");
            var inventory=LabJson.read(plan.scenarios().path(),65536);
            need(LabHostInputs.inventory(inventory).equals(REQUIREMENTS),"HOST_REQUIREMENT_MAPPING");
            for(var item:objects(array(inventory,"requirements")))need(Objects.equals(nullable(item,"protocol"),protocol(text(item,"id"))),"HOST_PROTOCOL_MAPPING");
            var nonces=new HashSet<UUID>();
            var summaries=new JsonArray();var platformProofs=new ArrayList<PlatformProof>();
            for(String platform:LabHostInputs.PLATFORMS) {var proof=validatePlatform(directory.resolve(platform),platform,plan,hashes,nonces);platformProofs.add(proof);summaries.add(proof.summary());}
            if(Files.exists(directory.resolve("completion.json"),LinkOption.NOFOLLOW_LINKS)) {
                var completion=read(directory,"completion.json",1_048_576,hashes);fields(completion,"version invocationId mode outcome code results durationMs cleanup","");
                need(number(completion,"version")==1&&text(completion,"invocationId").equals(plan.invocationId().toString())&&text(completion,"mode").equals("ACCEPTANCE")
                        &&text(completion,"cleanup").equals("COMPLETE")&&number(completion,"durationMs")>0&&array(completion,"results").equals(summaries),"HOST_TERMINAL_JOIN");checkOutcome(text(completion,"outcome"));
            }
            verifyInputs(workspace,plan);
            for(var entry:hashes.entrySet()) {
                String[] part=entry.getKey().split("/",2);Path owner=part[0].equals(directory.getFileName().toString())?directory:directory.resolve(part[0]);
                need(LabJson.sha256(file(owner,part[1])).equals(entry.getValue()),"HOST_CHANGED_EVIDENCE");
            }
            var times=new LinkedHashMap<String,Map<String,Long>>();
            for(var row:REQUIREMENTS.entrySet()) {
                long startup=0,measured=0,cleanup=0;
                for(var proof:platformProofs) {
                    long prepared=proof.initialSetup(),cases=0;
                    for(String id:row.getValue()){prepared+=proof.preparations().get(id);cases+=proof.cases().get(id);}
                    startup=Math.max(startup,prepared);measured=Math.max(measured,cases);cleanup=Math.max(cleanup,proof.cleanup());
                }
                times.put(row.getKey(),Map.of("startupMs",startup,"caseMs",measured,"cleanupMs",cleanup));
            }
            return new VerifiedRun(plan,hashes,eligible,times);
        }catch(Rejected known){throw known;}
        catch(IOException|RuntimeException unavailable){throw new Rejected(Outcome.BLOCKED,"HOST_EVIDENCE_UNAVAILABLE_OR_MALFORMED");}
    }
    private static void verifyInputs(Path workspace,LabHostInputs.Plan plan) throws IOException {
        Path capture=workspace.resolve("test/authentication-lab/build/host-runtime").resolve(plan.invocationId().toString()).resolve("capture");
        need(plan.captureDirectory().toRealPath().equals(capture)&&capture.startsWith(workspace),"HOST_CAPTURE_OWNER");
        for(var artifact:plan.artifacts()) {
            need(artifact.path().toRealPath().startsWith(capture)&&Files.isRegularFile(artifact.path(),LinkOption.NOFOLLOW_LINKS),"HOST_ARTIFACT_OWNER");
            try{artifact.verify();}catch(IOException|IllegalArgumentException changed){throw new Rejected(Outcome.BLOCKED,"HOST_ARTIFACT_CHANGED");}
        }
        var audit=LabJson.read(plan.audit().path(),1_048_576);
        need(text(audit,"head").equals(plan.head())&&text(audit,"boundaryHash").equals(plan.sourceRevision())&&object(audit.get("files")).equals(LabJson.JSON.toJsonTree(plan.sourceHashes())),"HOST_AUDIT_IDENTITY");
        var trees=validateSourceInventory(workspace,audit,plan.sourceHashes());
        need(criticalOwners().stream().allMatch(owner->trees.stream().anyMatch(tree->owner.startsWith(tree+"/"))),"HOST_AUDIT_OWNER_MISSING");
        var runtime=new HashSet<String>();var roles=new HashSet<String>();
        for(var artifact:plan.runtime()){need(Set.of("LAB","EXPORTER").contains(artifact.role())&&runtime.add(artifact.role()+":"+artifact.path()),"HOST_RUNTIME_IDENTITY");roles.add(artifact.role());}
        need(roles.equals(Set.of("LAB","EXPORTER")),"HOST_RUNTIME_IDENTITY");
        need(plan.sourceHashes().keySet().containsAll(criticalOwners()),"HOST_AUDIT_OWNER_MISSING");
        need(configurationFingerprint(workspace).equals(plan.configurationHash())&&LabEvidence.catalogFingerprint(workspace).equals(plan.catalogRevision()),"HOST_STALE_CONFIGURATION");
        for(var entry:plan.sourceHashes().entrySet()) {
            Path path=workspace.resolve(LabJson.relative(new JsonPrimitive(entry.getKey())));
            need(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)&&path.toRealPath().startsWith(workspace)&&LabJson.sha256(path).equals(entry.getValue()),"HOST_STALE_SOURCE");
        }
        need(LabJson.sha256(workspace.resolve("bapp/build/libs/browser-powered-session-handler-dev.jar")).equals(plan.product().sha256()),"HOST_DEVELOPMENT_ARTIFACT_CHANGED");
        need(LabJson.sha256(workspace.resolve("test/authentication-lab/src/main/resources/host-scenarios.json")).equals(plan.scenarios().sha256()),"HOST_INVENTORY_CHANGED");
    }
    static List<String> validateSourceInventory(Path workspace,JsonObject audit,Map<String,String> hashes) throws IOException {
        need(audit.has("sourceTrees")&&audit.get("sourceTrees").isJsonArray(),"HOST_SOURCE_TREES");
        Path owner=workspace.toRealPath();List<String> names;
        try{names=LabJson.strings(audit.get("sourceTrees"));}catch(IllegalArgumentException invalid){throw new Rejected(Outcome.BLOCKED,"HOST_SOURCE_TREES");}
        need(!names.isEmpty()&&names.size()<=32,"HOST_SOURCE_TREES");var roots=new ArrayList<Path>();int[] entries={0};
        for(String name:names) {
            Path root;
            try{root=owner.resolve(LabJson.relative(new JsonPrimitive(name)));}catch(IllegalArgumentException invalid){throw new Rejected(Outcome.BLOCKED,"HOST_SOURCE_TREES");}
            need(Files.isDirectory(root,LinkOption.NOFOLLOW_LINKS)&&root.toRealPath().equals(root)&&root.startsWith(owner)&&!root.equals(owner)
                    &&roots.stream().noneMatch(other->root.startsWith(other)||other.startsWith(root)),"HOST_SOURCE_TREES");roots.add(root);
            var actual=new HashSet<String>();
            Files.walkFileTree(root,new SimpleFileVisitor<>() {
                private void bounded(Path path,java.nio.file.attribute.BasicFileAttributes attributes) throws IOException {
                    need(++entries[0]<=100000&&!attributes.isSymbolicLink()&&path.toRealPath().equals(path),"HOST_SOURCE_TREE_UNSAFE_OR_LARGE");
                }
                @Override public FileVisitResult preVisitDirectory(Path path,java.nio.file.attribute.BasicFileAttributes attributes) throws IOException {bounded(path,attributes);return FileVisitResult.CONTINUE;}
                @Override public FileVisitResult visitFile(Path path,java.nio.file.attribute.BasicFileAttributes attributes) throws IOException {
                    bounded(path,attributes);need(attributes.isRegularFile(),"HOST_SOURCE_TREE_UNSAFE_OR_LARGE");actual.add(owner.relativize(path).toString().replace('\\','/'));return FileVisitResult.CONTINUE;
                }
            });
            var expected=hashes.keySet().stream().filter(path->path.startsWith(name+"/")).collect(java.util.stream.Collectors.toSet());
            need(actual.equals(expected),"HOST_SOURCE_INVENTORY_CHANGED");
        }
        return List.copyOf(names);
    }
    record Gui(JsonObject receipt,JsonObject intent) { }
    static final class Platform {
        final List<Integer> listeners;final LabHostGuiProtocol.Session session;final Map<Long,Gui> gui;final String vendor;
        final Set<String> nonces=new HashSet<>(),forbidden=new HashSet<>();Integer primary,alternate;Snapshot last;JsonObject lastHttp;
        Platform(List<Integer> listeners,LabHostGuiProtocol.Session session,Map<Long,Gui> gui,String vendor) throws IOException {
            this.listeners=List.copyOf(listeners);this.session=session;this.gui=Map.copyOf(gui);this.vendor=vendor;
            for(var item:gui.values())LabHostGuiProtocol.validateRetainedReceipt(item.receipt(),session);
        }
    }
    private record PlatformProof(JsonObject summary,Map<String,Long> preparations,Map<String,Long> cases,long initialSetup,long cleanup) { }
    private static PlatformProof validatePlatform(Path directory,String platform,LabHostInputs.Plan plan,Map<String,String> hashes,Set<UUID> nonces) throws IOException {
        need(Files.isDirectory(directory,LinkOption.NOFOLLOW_LINKS),"HOST_PLATFORM_MISSING");directory=directory.toRealPath();
        var terminal=read(directory,"platform.json",1_048_576,hashes);
        var session=new LabHostGuiProtocol.Session(plan.invocationId(),platform,UUID.fromString(text(terminal,"runNonce")),plan.product().sha256(),plan.helper().sha256(),directory);
        validateTerminal(terminal,session);need(nonces.add(session.runNonce()),"HOST_REUSED_RUN_NONCE");var states=object(terminal.get("scenarios"));
        var summary=read(directory,"summary.json",65536,hashes);fields(summary,"platform outcome code cleanup unattended scenarios","");
        need(text(summary,"platform").equals(platform)&&text(summary,"outcome").equals(text(terminal,"outcome"))&&text(summary,"code").equals(text(terminal,"code"))
                &&text(summary,"cleanup").equals("COMPLETE")&&bool(summary,"unattended")&&object(summary.get("scenarios")).equals(states),"HOST_PLATFORM_SUMMARY_JOIN");
        LabHostGuest.validateEvidenceIndex(array(terminal,"evidence"));var indexed=new LinkedHashMap<String,JsonObject>();
        for(var entry:objects(array(terminal,"evidence"))) {
            String name=text(entry,"path");Path artifact=file(directory,name);
            need(Files.size(artifact)==number(entry,"bytes")&&LabJson.sha256(artifact).equals(text(entry,"sha256")),"HOST_CHANGED_EVIDENCE");indexed.put(name,entry);
        }
        need(indexed.containsKey("environment.json")&&indexed.containsKey("scenario-setup.json"),"HOST_PLATFORM_PROOF_MISSING");
        var environment=read(directory,"environment.json",65536,hashes);
        validateEnvironment(environment,platform);
        var started=read(directory,"started.json",65536,hashes);
        var cleanup=read(directory,"cleanup.json",65536,hashes);
        validateCleanup(cleanup,started,session);
        var listeners=array(environment,"listeners").asList().stream().map(JsonElement::getAsInt).toList();
        need(listeners.size()==3&&new HashSet<>(listeners).size()==3&&listeners.stream().allMatch(p->p>0&&p<65536),"HOST_LISTENERS");
        var receipts=new TreeMap<Long,Gui>();var operationIds=new HashSet<UUID>();
        for(String name:indexed.keySet())if(name.matches("gui-[0-9]{3,6}\\.json")) {
            var receipt=read(directory,name,65536,hashes);LabHostGuiProtocol.validateRetainedReceipt(receipt,session);
            guiObserved(receipt);
            long budget=text(receipt,"operation").equals("READY")?180_000:30_000;
            need(number(receipt,"startedEpochMs")>=number(started,"startedEpochMs")&&number(receipt,"deadlineEpochMs")-number(receipt,"startedEpochMs")<=budget
                    &&number(receipt,"endedEpochMs")<=number(started,"startedEpochMs")+45*60_000L,"HOST_GUI_DEADLINE");
            long sequence=number(receipt,"sequence");need(sequence>0&&name.equals(String.format(Locale.ROOT,"gui-%03d.json",sequence))
                    &&operationIds.add(UUID.fromString(text(receipt,"operationId")))&&receipts.putIfAbsent(sequence,new Gui(receipt,object(receipt.get("intent"))))==null,"HOST_GUI_SEQUENCE");
            checkOutcome(text(receipt,"outcome"));
        }
        need(!receipts.isEmpty(),"HOST_GUI_MISSING");long next=1;for(long sequence:receipts.keySet())need(sequence==next++,"HOST_GUI_SEQUENCE");
        var setup=read(directory,"scenario-setup.json",1_048_576,hashes);identity(setup,session);
        fields(setup,"version invocationId platform runNonce productSha256 helperSha256 setup","");
        var preparation=object(setup.get("setup"));fields(preparation,"outcome startedEpochMs endedEpochMs scenarios serverAfter lastGuiSequence","");
        need(text(preparation,"outcome").equals("PASS"),"HOST_SETUP_INCOMPLETE");duration(preparation,8*60_000L);
        var preparations=objects(array(preparation,"scenarios"));need(preparations.size()==9,"HOST_SETUP_INCOMPLETE");
        var proof=new Platform(listeners,session,receipts,text(environment,"burpVersion"));UUID runId=null;long generation=0;
        var preparationTimes=new LinkedHashMap<String,Long>();var caseTimes=new LinkedHashMap<String,Long>();
        for(int i=0;i<LabHostInputs.SCENARIOS.size();i++) {
            String id=LabHostInputs.SCENARIOS.get(i);var prepared=preparations.get(i);
            fields(prepared,"scenario startedEpochMs endedEpochMs outcome code guiSequenceAfter","");
            need(text(prepared,"scenario").equals(id)&&text(prepared,"outcome").equals("PASS"),"HOST_SETUP_INCOMPLETE");duration(prepared,8*60_000L);
            String name="scenario-"+id+".json";need(indexed.containsKey(name),"HOST_SCENARIO_MISSING");
            var scenario=read(directory,name,16*1024*1024,hashes);identity(scenario,session);
            need(number(prepared,"endedEpochMs")<=number(scenario,"startedEpochMs")&&number(scenario,"startedEpochMs")>=number(started,"startedEpochMs")
                    &&number(scenario,"endedEpochMs")<=number(started,"startedEpochMs")+45*60_000L&&receipts.containsKey(number(prepared,"guiSequenceAfter")),"HOST_SCENARIO_TIME_JOIN");
            UUID current=UUID.fromString(text(scenario,"runId"));long currentGeneration=number(scenario,"caseGeneration");
            need((runId==null||runId.equals(current))&&currentGeneration>0&&(i==8?currentGeneration>generation:generation==0||generation==currentGeneration),"HOST_STALE_CASE");
            runId=current;generation=currentGeneration;
            validateScenario(scenario,proof);
            preparationTimes.put(id,duration(prepared,8*60_000L));caseTimes.put(id,duration(scenario,180_000));
        }
        need(indexed.containsKey("memory.json")&&!indexed.containsKey("burp-exit.json"),"HOST_MEMORY_OR_PROCESS_PROOF_MISSING");
        var memory=read(directory,"memory.json",65536,hashes);identity(memory,session);
        validateMemoryNumbers(memory,environment,session);
        var ready=receipts.get(1L);need(text(ready.receipt(),"operation").equals("READY")&&bool(object(ready.receipt().get("observed")),"ready"),"HOST_GUI_READY");
        var cold=read(directory,"scenario-routing.json",16*1024*1024,hashes);
        var reloads=receipts.values().stream().filter(item->text(item.receipt(),"operation").equals("SET_PRODUCT_LOADED")
                &&number(item.receipt(),"endedEpochMs")<=number(cold,"startedEpochMs")).toList();
        need(reloads.size()==10,"HOST_RELOAD_CYCLES");
        for(int i=0;i<10;i++)need(bool(reloads.get(i).intent(),"enabled")== (i%2==1),"HOST_RELOAD_CYCLES");
        need(number(memory,"firstSampleEpochMs")<=number(reloads.getFirst().receipt(),"startedEpochMs")
                &&number(memory,"lastSampleEpochMs")>=number(object(array(cold,"measurements").get(0)),"endedEpochMs"),"HOST_MEMORY_COVERAGE");
        var first=object(array(cold,"measurements").get(0));need(object(first.get("serverBefore")).equals(object(preparation.get("serverAfter"))),"HOST_INITIAL_SERVER_JOIN");
        var seed=objects(array(object(object(preparation.get("serverAfter")).get("hostObservations")),"received"));need(seed.size()==1,"HOST_INITIAL_SERVER_JOIN");
        String seedNonce=nullable(object(seed.getFirst().get("request")),"nonce");need(seedNonce!=null,"HOST_INITIAL_SERVER_JOIN");
        var copied=receipts.get(number(preparation,"lastGuiSequence"));need(copied!=null&&text(copied.receipt(),"operation").equals("COPY_TO_REPEATER")&&text(copied.intent(),"nonce").equals(seedNonce),"HOST_INITIAL_COPY_JOIN");
        need(number(preparation,"endedEpochMs")>=number(started,"startedEpochMs"),"HOST_STARTUP_TIME_JOIN");
        return new PlatformProof(summary,Map.copyOf(preparationTimes),Map.copyOf(caseTimes),number(preparation,"endedEpochMs")-number(started,"startedEpochMs"),number(cleanup,"durationMs"));
    }
    static void validateTerminal(JsonObject terminal,LabHostGuiProtocol.Session session) throws Rejected {
        fields(terminal,"version invocationId platform runNonce productSha256 helperSha256 outcome code cleanup unattended stage scenarios durationMs evidence","");identity(terminal,session);
        need(bool(terminal,"unattended")&&text(terminal,"stage").equals("SCENARIOS")&&text(terminal,"cleanup").equals("COMPLETE"),"HOST_ASSISTED_OR_INCOMPLETE_CLEANUP");
        need(number(terminal,"durationMs")>0&&number(terminal,"durationMs")<=45*60_000L&&text(terminal,"code").matches("[A-Z][A-Z0-9_]{0,79}"),"HOST_PLATFORM_DEADLINE");
        var states=object(terminal.get("scenarios"));need(states.keySet().equals(new HashSet<>(LabHostInputs.SCENARIOS)),"HOST_SCENARIO_MISSING");
        for(String id:LabHostInputs.SCENARIOS)checkOutcome(text(states,id));checkOutcome(text(terminal,"outcome"));
    }
    static void validateEnvironment(JsonObject environment,String platform) throws Rejected {
        fields(environment,"version burpVersion javaVersion labJavaVersion os maxBurpHeapMiB physicalMemoryMiB listeners adapter burpPid burpStartedEpochMs actualMaxHeapBytes","");
        need(number(environment,"version")==1&&text(environment,"adapter").equals(ADAPTER)&&text(environment,"javaVersion").equals(JAVA)
                &&Pattern.compile("(?:^|[^0-9.])"+Pattern.quote(BURP)+"(?:$|[^0-9.])").matcher(text(environment,"burpVersion")).find()
                &&(platform.equals("windows")?text(environment,"os").startsWith("Windows"):text(environment,"os").equals("Linux")),"HOST_VENDOR_UNSUPPORTED");
        need(number(environment,"maxBurpHeapMiB")==2048&&number(environment,"physicalMemoryMiB")>2048
                &&number(environment,"actualMaxHeapBytes")==2147483648L,"HOST_HEAP_BUDGET");
        need(number(environment,"burpPid")>0&&number(environment,"burpStartedEpochMs")>0&&Runtime.Version.parse(text(environment,"labJavaVersion")).feature()>=21,"HOST_RUNTIME_VERSION");
    }
    static void validateCleanup(JsonObject cleanup,JsonObject started,LabHostGuiProtocol.Session session) throws Rejected {
        fields(started,"version invocationId runNonce pid startedEpochMs executable","");
        need(number(started,"version")==1&&text(started,"invocationId").equals(session.invocationId().toString())&&text(started,"runNonce").equals(session.runNonce().toString())
                &&number(started,"pid")>0&&number(started,"startedEpochMs")>0,"HOST_GUEST_PROCESS_IDENTITY");
        identity(cleanup,session);fields(cleanup,"version invocationId platform runNonce productSha256 helperSha256 guestPid guestStartedEpochMs rootRemoved outcome durationMs","");
        need(number(cleanup,"guestPid")==number(started,"pid")&&number(cleanup,"guestStartedEpochMs")==number(started,"startedEpochMs")
                &&bool(cleanup,"rootRemoved")&&text(cleanup,"outcome").equals("COMPLETE")&&number(cleanup,"durationMs")<=60000,"HOST_RUNTIME_CLEANUP_INCOMPLETE");
    }
    static void validateMemoryNumbers(JsonObject memory,JsonObject environment,LabHostGuiProtocol.Session session) throws Rejected {
        identity(memory,session);
        fields(memory,"version invocationId platform runNonce productSha256 helperSha256 pid startedEpochMs intervalMs peakRssBytes samples overflow complete firstSampleEpochMs lastSampleEpochMs maxSampleGapMs gc","");
        need(number(memory,"pid")==number(environment,"burpPid")&&number(memory,"startedEpochMs")==number(environment,"burpStartedEpochMs")&&number(memory,"pid")>0
                &&number(memory,"startedEpochMs")>0&&number(memory,"intervalMs")==200&&number(memory,"samples")>0&&number(memory,"samples")<=20000
                &&number(memory,"peakRssBytes")>0&&number(memory,"peakRssBytes")<=(1L<<50)&&!bool(memory,"overflow")&&bool(memory,"complete")
                &&number(memory,"maxSampleGapMs")<=2000&&number(memory,"firstSampleEpochMs")>=number(memory,"startedEpochMs")
                &&number(memory,"lastSampleEpochMs")>=number(memory,"firstSampleEpochMs"),"HOST_MEMORY_INCOMPLETE");
        var gc=object(memory.get("gc"));fields(gc,"complete objectObservations gcObservations maxObservedObjectBytes peakObservedHumongousBytes","");
        long observations=number(gc,"objectObservations"),collections=number(gc,"gcObservations"),maximum=number(gc,"maxObservedObjectBytes"),peak=number(gc,"peakObservedHumongousBytes");
        need(bool(gc,"complete")&&observations<=100000&&collections<=4096&&collections<=observations&&maximum<=(16L<<30)&&peak>=maximum
                &&(observations==0?collections==0&&maximum==0&&peak==0:collections>0&&maximum>0),"HOST_GC_INCOMPLETE");
    }
    private static void checkOutcome(String outcome) throws Rejected {
        if(Set.of("CANCELLED","INTERRUPTED").contains(outcome))throw new Rejected(Outcome.INTERRUPTED,"HOST_CANCELLED");
        if(outcome.equals("FAIL"))throw new Rejected(Outcome.FAIL,"HOST_OBSERVED_FAILURE");
        need(outcome.equals("PASS"),"HOST_INCOMPLETE_RESULT");
    }
    private static void guiObserved(JsonObject receipt) throws Rejected {
        var observed=object(receipt.get("observed"));var intent=object(receipt.get("intent"));String operation=text(receipt,"operation");
        switch(operation) {
            case "READY"->fact(bool(observed,"ready"),"HOST_GUI_OBSERVATION");
            case "OPEN_TOOL"->fact(text(observed,"tool").equals(text(intent,"tool")),"HOST_GUI_OBSERVATION");
            case "SET_INTERCEPT","SET_PRODUCT_LOADED"->fact(bool(observed,"enabled")==bool(intent,"enabled"),"HOST_GUI_OBSERVATION");
            case "IMPORT_JOURNEY"->fact(bool(observed,"imported"),"HOST_GUI_OBSERVATION");
            case "ENTER_SECRET"->fact(bool(observed,"secretEntered"),"HOST_GUI_OBSERVATION");
            case "EDIT_RULES"->fact(observed.has("rulesConfigured")&&bool(observed,"rulesConfigured")
                    ||observed.has("validationRejected")&&bool(observed,"validationRejected"),"HOST_GUI_OBSERVATION");
            case "COPY_TO_REPEATER"->fact(bool(observed,"copied"),"HOST_GUI_OBSERVATION");
            case "SET_REPEATER_REQUEST","SET_REPEATER_NONCE"->fact(number(observed,"length")>0&&text(observed,"nonce").equals(text(intent,"nonce")),"HOST_GUI_OBSERVATION");
            case "EDIT_INTERCEPTED_REQUEST"->fact(bool(observed,"edited"),"HOST_GUI_OBSERVATION");
            case "SEND_REPEATER"->fact(bool(observed,"submitted")&&text(observed,"nonce").equals(text(intent,"nonce")),"HOST_GUI_OBSERVATION");
            case "ASSERT_REPEATER_RESPONSE"->fact(number(observed,"status")==number(intent,"status")&&text(observed,"nonce").equals(text(intent,"nonce")),"HOST_GUI_OBSERVATION");
            case "FORWARD_INTERCEPTED_REQUEST"->fact(bool(observed,"forwarded"),"HOST_GUI_OBSERVATION");
            case "CAPTURE_PROBE"->fact(bool(observed,"captureCompleted"),"HOST_GUI_OBSERVATION");
            case "ASSERT_UI"->fact(bool(observed,"assertionObserved")&&text(observed,"assertionCode").equals(text(intent,"code")),"HOST_GUI_OBSERVATION");
            case "TEST_LOGIN"->fact(text(observed,"loginResult").equals("HTTP_AUTHENTICATED"),"HOST_GUI_OBSERVATION");
            case "CLOSE"->fact(bool(observed,"closeRequested"),"HOST_GUI_OBSERVATION");
            default->throw new Rejected(Outcome.BLOCKED,"HOST_GUI_OPERATION");
        }
    }
    private record Snapshot(UUID runId,long generation,List<JsonObject> rows,List<JsonObject> events,long logins,Map<String,String> issuances) { }
    private static Snapshot snapshot(JsonObject value,UUID expectedRun,long expectedGeneration) throws Rejected {
        fields(value,"runId caseId generation state checkpoints counters events truncated hostObservations","");
        UUID run=UUID.fromString(text(value,"runId"));long generation=number(value,"generation");
        need(run.equals(expectedRun)&&generation==expectedGeneration&&text(value,"caseId").equals("BROW.basic.json")&&!bool(value,"truncated"),"HOST_STALE_OR_TRUNCATED_SERVER");
        need(Set.of("PREPARED","RUNNING","CLOSING","CLOSED").contains(text(value,"state")),"HOST_SERVER_STATE");
        for(var gate:objects(array(value,"checkpoints"))){fields(gate,"name state","");need(Set.of("WAITING","RELEASED","RETIRED").contains(text(gate,"state")),"HOST_GATE_SCHEMA");}
        var counters=object(value.get("counters"));fields(counters,"httpIngress routed actions connections tlsHandshakes applicationBytes","");
        for(String key:counters.keySet())if(!counters.get(key).isJsonNull())number(counters,key);
        var events=objects(array(value,"events"));need(events.size()<=10000,"HOST_SERVER_OVERFLOW");
        long sequence=0,logins=0;var issuances=new LinkedHashMap<String,String>();
        for(var event:events) {
            fields(event,"sequence time phase name safeIds","");need(number(event,"sequence")==++sequence,"HOST_SERVER_SEQUENCE");
            Instant.parse(text(event,"time"));LabRun.Phase.valueOf(text(event,"phase"));
            need(text(event,"name").matches("[A-Za-z0-9_-]{1,80}"),"HOST_SERVER_EVENT");
            var ids=new HashMap<String,String>();
            for(var id:objects(array(event,"safeIds"))) {
                fields(id,"kind value","");String kind=text(id,"kind"),safe=text(id,"value");
                boolean hostAlias=kind.equals("journey-alias")&&Set.of("host_a","host_b","host_failure_a","host_failure_b").contains(safe)
                        &&text(event,"name").equals("host-login-page-response-start")&&text(event,"phase").equals("LOGIN");
                need((kind.equals("account")&&Set.of("user","user2").contains(safe)||kind.equals("issuance")&&safe.matches("s[0-9]+")||hostAlias)
                        &&ids.putIfAbsent(kind,safe)==null,"HOST_SERVER_EVENT");
            }
            if(text(event,"name").equals("host-login-page-response-start"))need(ids.keySet().equals(Set.of("journey-alias")),"HOST_PAGE_EVENT");
            if(text(event,"phase").equals("LOGIN")&&text(event,"name").equals("phase-entered"))logins++;
            if(text(event,"name").equals("login-completed")) {
                need(text(event,"phase").equals("LOGIN")&&ids.keySet().equals(Set.of("account","issuance"))&&Set.of("user","user2").contains(ids.get("account"))
                        &&ids.get("issuance").matches("s[0-9]+")&&issuances.putIfAbsent(ids.get("issuance"),ids.get("account"))==null,"HOST_LOGIN_ISSUANCE");
            }
        }
        var host=object(value.get("hostObservations"));fields(host,"received truncated complete","");
        need(!bool(host,"truncated")&&bool(host,"complete"),"HOST_SERVER_INCOMPLETE");
        var rows=objects(array(host,"received"));need(rows.size()<=10000,"HOST_SERVER_OVERFLOW");sequence=0;
        for(var row:rows) {
            fields(row,"sequence caseId generation listenerPort request status accountId issuanceId roles","");
            need(number(row,"sequence")==++sequence&&number(row,"generation")==generation&&text(row,"caseId").equals("BROW.basic.json")
                    &&number(row,"listenerPort")>0&&number(row,"listenerPort")<=65535,"HOST_RECEIVER_IDENTITY");
            var shape=object(row.get("request"));fields(shape,"nonce invalidNonce method route authorizationHeaders cookieHeaders c1 c2 nativeTag httpDirective sentinel bodyBytes bodyTruncated","");
            need(!bool(shape,"invalidNonce")&&!bool(shape,"bodyTruncated")&&number(shape,"bodyBytes")<=1_048_576,"HOST_RECEIVER_TRUNCATED");
            String nonce=nullable(shape,"nonce");need(nonce==null||nonce.matches("h[0-9a-f]{16}"),"HOST_RECEIVER_NONCE");
            need(Set.of("GET","POST").contains(text(shape,"method"))&&text(shape,"route").equals("b_c1")&&number(shape,"authorizationHeaders")<=1000&&number(shape,"cookieHeaders")<=1000,"HOST_RECEIVER_SHAPE");
            for(String key:List.of("c1","c2","nativeTag","httpDirective","sentinel"))bool(shape,key);
            long status=number(row,"status");need(status>=100&&status<=599,"HOST_RECEIVER_INCOMPLETE");
            var roles=LabJson.strings(row.get("roles"));need(Set.of("B","C1","C2").containsAll(roles),"HOST_RECEIVER_ROLES");
            String account=nullable(row,"accountId"),issuance=nullable(row,"issuanceId");
            if(status==200)need(account!=null&&account.equals(issuances.get(issuance))&&!roles.isEmpty(),"HOST_UNBACKED_SERVER_SUCCESS");
            else need(account==null&&issuance==null&&roles.isEmpty(),"HOST_REJECTED_IDENTITY");
        }
        return new Snapshot(run,generation,rows,events,logins,Map.copyOf(issuances));
    }
    private static List<JsonObject> delta(Snapshot before,Snapshot after) throws Rejected {
        need(before.runId().equals(after.runId())&&before.generation()==after.generation()&&after.rows().size()>=before.rows().size()
                &&after.rows().subList(0,before.rows().size()).equals(before.rows())&&after.events().size()>=before.events().size()
                &&after.events().subList(0,before.events().size()).equals(before.events()),"HOST_SERVER_REWRITTEN");
        return after.rows().subList(before.rows().size(),after.rows().size());
    }
    private static List<JsonObject> nonceRows(List<JsonObject> rows,String nonce) {
        return rows.stream().filter(row->nonce.equals(nullable(object(row.get("request")),"nonce"))).toList();
    }
    private static void credentialShape(JsonObject row,boolean present) throws Rejected {
        var shape=object(row.get("request"));
        fact(number(shape,"authorizationHeaders")== (present?1:0)&&number(shape,"cookieHeaders")== (present?1:0)
                &&bool(shape,"c1")==present&&!bool(shape,"c2")&&!bool(shape,"nativeTag")&&!bool(shape,"httpDirective"),"HOST_RECEIVER_CREDENTIALS");
    }
    private static void accepted(JsonObject row,String account) throws Rejected {
        fact(number(row,"status")==200&&account.equals(nullable(row,"accountId"))&&new HashSet<>(LabJson.strings(row.get("roles"))).equals(Set.of("B","C1")),"HOST_SERVER_ACCOUNT");
        credentialShape(row,true);
    }
    private static void rejected(JsonObject row,boolean present) throws Rejected {
        fact(number(row,"status")==401&&nullable(row,"accountId")==null,"HOST_SERVER_REJECTION");credentialShape(row,present);
    }
    private static List<JsonObject> probe(JsonObject value,String scenario,LabHostGuiProtocol.Session session,String vendor) throws Rejected {
        fields(value,"version case burpVersion invocationId platform runNonce productSha256 helperSha256 overflow complete events scope","");identity(value,session);
        need(text(value,"case").equals("host-"+scenario)&&text(value,"burpVersion").equals(vendor)&&!bool(value,"overflow")&&bool(value,"complete"),"HOST_PROBE_INCOMPLETE");
        need(text(value,"scope").equals("Passive callback observations only; server acceptance requires independent fixture evidence."),"HOST_PROBE_SCOPE");
        var events=objects(array(value,"events"));need(!events.isEmpty()&&events.size()<=1000,"HOST_PROBE_INCOMPLETE");long next=1;
        for(var event:events) {
            fields(event,"sequence case family id phase tool httpVersion status invalidNonce shapeTruncated authorizationHeaders cookieHeaders c1 c2 nativeTag sentinel httpAuthenticationDirective","nonce listener");
            need(number(event,"sequence")==next++&&text(event,"case").equals("host-"+scenario)&&!bool(event,"invalidNonce")&&!bool(event,"shapeTruncated"),"HOST_PROBE_SEQUENCE");
            need(Set.of("GLOBAL","PROXY").contains(text(event,"family"))&&Set.of("received","to_send","response_received","response_to_send").contains(text(event,"phase")),"HOST_PROBE_CALLBACK");
            need(text(event,"tool").matches("[A-Z_]{1,80}")&&(!text(event,"family").equals("PROXY")||text(event,"tool").equals("PROXY"))
                    &&Set.of("HTTP/1.0","HTTP/1.1","HTTP/2","HTTP/2.0").contains(text(event,"httpVersion")),"HOST_PROBE_VERSION_OR_TOOL");
            need(nullable(event,"nonce")==null||nullable(event,"nonce").matches("h[0-9a-f]{16}"),"HOST_PROBE_NONCE");
            for(String key:List.of("c1","c2","nativeTag","sentinel","httpAuthenticationDirective"))bool(event,key);
            number(event,"id");number(event,"status");number(event,"authorizationHeaders");number(event,"cookieHeaders");
            need(Set.of("received","to_send").contains(text(event,"phase"))?number(event,"status")==0:number(event,"status")>=100&&number(event,"status")<=599,"HOST_PROBE_RESPONSE_STATUS");
        }
        return events;
    }
    private static List<Gui> guiRange(Map<Long,Gui> receipts,long before,long after) throws Rejected {
        need(before>0&&after>=before&&receipts.containsKey(before)&&receipts.containsKey(after),"HOST_GUI_RANGE");
        return receipts.entrySet().stream().filter(e->e.getKey()>before&&e.getKey()<=after).map(Map.Entry::getValue).toList();
    }
    private static boolean action(List<Gui> gui,String operation,String key,String value) {
        return gui.stream().anyMatch(item->text(item.receipt(),"operation").equals(operation)&&(key==null||value.equals(nullable(item.intent(),key))));
    }
    private static Gui requiredAction(List<Gui> gui,String operation,String key,String value) throws Rejected {
        var matches=gui.stream().filter(item->text(item.receipt(),"operation").equals(operation)&&(key==null||value.equals(nullable(item.intent(),key)))).toList();
        need(matches.size()==1,"HOST_GUI_ACTION_JOIN");return matches.getFirst();
    }
    private enum Delivery { ACCEPTED, ABSENT, REPLAY, REJECTED_REPLAY, STOP, PROXY_UNKNOWN, HTTP, UNLOAD }
    private record Expected(String tool,String kind,String account,Integer status,Delivery delivery,int listener) { }
    private static Expected form(String tool,String kind,String account,int listener) {
        return new Expected(tool,kind,account,account==null?401:200,account==null?Delivery.ABSENT:Delivery.ACCEPTED,listener);
    }
    private static List<Expected> expected(String scenario,String subcase) throws Rejected {
        var result=new ArrayList<Expected>();
        switch(scenario) {
            case "routing" -> {
                List<String> accounts=switch(subcase) {
                    case "port-cold"->Arrays.asList("user","user2",null);
                    case "port-warm"->Arrays.asList("user","user2",null,"user","user2",null);
                    case "url-prefix"->Arrays.asList("user","user","user",null,null,null);
                    case "url-and-port"->Arrays.asList("user","user2",null,null,null,null);
                    case "regex-substring","regex-anchor","regex-invalid-retains"->Arrays.asList("user",null);
                    case "regex-case-miss","regex-anchor-miss"->Collections.singletonList(null);
                    case "regex-case-fold"->List.of("user");default->throw new Rejected(Outcome.BLOCKED,"HOST_SUBCASE");};
                for(int i=0;i<accounts.size();i++)result.add(form("PROXY","NORMAL",accounts.get(i),subcase.startsWith("regex")?2:i%3));
            }
            case "tags" -> {
                switch(subcase) {
                    case "proxy-explicit-a"->result.add(form("PROXY","TAGGED","user",0));
                    case "repeater-explicit-a"->result.add(form("REPEATER","TAGGED","user",-1));
                    case "repeater-unknown"->result.add(new Expected("REPEATER","TAGGED_STOP",null,null,Delivery.STOP,-1));
                    case "proxy-unknown"->result.add(new Expected("PROXY","TAGGED_PROXY_BEST_EFFORT",null,null,Delivery.PROXY_UNKNOWN,0));
                    default->throw new Rejected(Outcome.BLOCKED,"HOST_SUBCASE");
                }
            }
            case "repeater" -> {
                if(subcase.equals("copied-ordinary")){result.add(form("PROXY","HISTORY_SEED","user",0));result.add(form("REPEATER","COPIED_ORDINARY","user",-1));}
                else result.add(form("REPEATER",subcase.equals("explicit-tags")?"TAGGED":"NORMAL",subcase.equals("removed-port-only")?null:"user",-1));
            }
            case "http-auth" -> {
                if(!subcase.contains("-test-")) {
                    boolean proxy=subcase.contains("-proxy-");String account=subcase.endsWith("-b")?"user-b":"user-a";
                    result.add(new Expected(proxy?"PROXY":"REPEATER",proxy?"HTTP_AUTH":"TAGGED",account,200,Delivery.HTTP,proxy?2:-1));
                }
            }
            case "recovery" -> {result.add(form("PROXY","PRIME","user",0));for(int i=0;i<2;i++)result.add(new Expected("PROXY","RECOVERY",null,401,Delivery.REPLAY,0));}
            case "rejected-replay" -> {
                if(subcase.equals("rejected-replay")){result.add(form("PROXY","PRIME","user",0));result.add(new Expected("PROXY","REJECTED_REPLAY",null,401,Delivery.REJECTED_REPLAY,0));}
                else result.add(form("PROXY","NORMAL",null,0));
            }
            case "intercept" -> result.add(form("PROXY","INTERCEPT_EDIT",subcase.equals("matching-to-alternate")?null:"user",0));
            case "unload" -> result.add(subcase.equals("pending-unload")?new Expected("PROXY","UNLOAD_PENDING",null,null,Delivery.UNLOAD,0):form("PROXY","NORMAL","user",0));
            case "ordinary-failure" -> result.add(form("PROXY","NORMAL",null,0));
            default->throw new Rejected(Outcome.BLOCKED,"HOST_SCENARIO");
        }
        return List.copyOf(result);
    }
    static void validateScenario(JsonObject value,Platform platform) throws IOException {
        fields(value,"version invocationId platform runNonce productSha256 helperSha256 scenario outcome code startedEpochMs endedEpochMs runId caseGeneration measurements probe","");
        identity(value,platform.session);String scenario=text(value,"scenario");need(LabHostInputs.SCENARIOS.contains(scenario),"HOST_SCENARIO");
        checkOutcome(text(value,"outcome"));duration(value,180_000);
        UUID run=UUID.fromString(text(value,"runId"));long generation=number(value,"caseGeneration");
        var callbacks=probe(object(value.get("probe")),scenario,platform.session,platform.vendor);
        var measures=objects(array(value,"measurements"));
        need(LabHostScenarios.SUBCASES.equals(SUBCASES)&&measures.stream().map(m->text(m,"subcaseId")).toList().equals(SUBCASES.get(scenario)),"HOST_SUBCASE_INVENTORY");
        long priorEnd=number(value,"startedEpochMs"),priorGui=0;
        for(var measure:measures) {
            String id=text(measure,"subcaseId");
            boolean cold=scenario.equals("routing")&&id.equals("port-cold")||scenario.equals("http-auth")&&id.contains("-test-")||Set.of("unload","ordinary-failure").contains(scenario);
            need(text(measure,"phase").equals(cold?"COLD":"WARM"),"HOST_MEASUREMENT_PHASE");
            String extra=scenario.equals("routing")&&id.equals("port-cold")?"browserAdmission":scenario.equals("http-auth")&&id.contains("-test-")?"uiTest":scenario.equals("repeater")&&id.equals("copied-ordinary")
                    ||scenario.equals("http-auth")&&id.endsWith("-repeater-a")?"copiedFromNonce":scenario.equals("recovery")||scenario.equals("rejected-replay")&&id.equals("rejected-replay")?"revokedIssuanceId":
                    scenario.equals("intercept")?"fromListenerPort toListenerPort":scenario.equals("unload")?id.equals("pending-unload")?"childrenBefore childrenAfter issuedBeforeReload":"priorIssuanceIds":"";
            fields(measure,"subcaseId phase guiSequenceBefore guiSequenceAfter rules serverBefore serverAfter httpBefore httpAfter originals startedEpochMs endedEpochMs"+(extra.isEmpty()?"":" "+extra),"");duration(measure,180_000);
            need(number(measure,"startedEpochMs")>=priorEnd&&number(measure,"endedEpochMs")<=number(value,"endedEpochMs"),"HOST_MEASUREMENT_TIME");priorEnd=number(measure,"endedEpochMs");
            long first=number(measure,"guiSequenceBefore"),last=number(measure,"guiSequenceAfter");need(first>=priorGui,"HOST_GUI_RANGE");priorGui=last;
            var gui=guiRange(platform.gui,first,last);
            for(var item:gui)need(number(item.receipt(),"startedEpochMs")>=number(measure,"startedEpochMs")&&number(item.receipt(),"endedEpochMs")<=number(measure,"endedEpochMs"),"HOST_GUI_TIME_JOIN");
            var before=snapshot(object(measure.get("serverBefore")),run,generation);var after=snapshot(object(measure.get("serverAfter")),run,generation);var received=delta(before,after);
            var httpBefore=object(measure.get("httpBefore"));var httpAfter=object(measure.get("httpAfter"));httpSnapshot(httpBefore);httpSnapshot(httpAfter);
            if(platform.lastHttp!=null)need(platform.lastHttp.equals(httpBefore),"HOST_UNMEASURED_HTTP_WORK");
            if(!scenario.equals("http-auth"))fact(httpBefore.equals(httpAfter),"HOST_UNDECLARED_HTTP_AUTHENTICATION");
            if(platform.last!=null&&platform.last.generation()==generation)
                need(delta(platform.last,before).isEmpty()&&platform.last.logins()==before.logins(),"HOST_UNMEASURED_SERVER_WORK");
            for(var row:after.rows())fact(!platform.forbidden.contains(nullable(object(row.get("request")),"nonce")),"HOST_STOPPED_REQUEST_DELIVERED");
            var originals=objects(array(measure,"originals"));var expectations=expected(scenario,id);need(originals.size()==expectations.size(),"HOST_ORIGINAL_INVENTORY");
            var known=new HashSet<String>();
            for(int i=0;i<originals.size();i++) {
                var original=originals.get(i);String nonce=text(original,"nonce");need(nonce.matches("h[0-9a-f]{16}")&&platform.nonces.add(nonce),"HOST_ORIGINAL_NONCE");known.add(nonce);
                original(original,expectations.get(i),nonceRows(received,nonce),callbacks,gui,platform,scenario,id,i);
            }
            fact(received.stream().allMatch(row->known.contains(nullable(object(row.get("request")),"nonce"))),"HOST_UNDECLARED_APPLICATION_EXECUTION");
            special(scenario,id,measure,before,after,received,gui,callbacks,platform);
            platform.last=after;
            platform.lastHttp=httpAfter;
        }
    }
    private static void original(JsonObject value,Expected expected,List<JsonObject> received,List<JsonObject> callbacks,List<Gui> gui,
                                 Platform platform,String scenario,String subcase,int index) throws Rejected {
        boolean needsReplayProof=expected.delivery()==Delivery.REPLAY||expected.delivery()==Delivery.REJECTED_REPLAY;
        fields(value,"nonce tool listenerPort kind method expectedAccount expectedStatus clientStatus"+(needsReplayProof?" expectedReplayAccount expectedReplayStatus":""),"");
        String nonce=text(value,"nonce");
        need(text(value,"tool").equals(expected.tool())&&text(value,"kind").equals(expected.kind())&&Objects.equals(nullable(value,"expectedAccount"),expected.account())
                &&Objects.equals(value.get("expectedStatus"),expected.status()==null?JsonNull.INSTANCE:new JsonPrimitive(expected.status()))
                &&text(value,"method").equals(expected.delivery()==Delivery.HTTP?"POST":"GET"),"HOST_ORIGINAL_INTENT");
        if(expected.listener()<0)need(value.get("listenerPort").isJsonNull(),"HOST_REPEATER_LISTENER");
        else need(number(value,"listenerPort")==platform.listeners.get(expected.listener()),"HOST_PROXY_LISTENER");
        var events=callbacks.stream().filter(event->nonce.equals(nullable(event,"nonce"))).toList();need(!events.isEmpty(),"HOST_CALLBACK_MISSING");
        JsonObject input;
        if(expected.tool().equals("PROXY")) {
            var incoming=events.stream().filter(event->text(event,"family").equals("PROXY")&&text(event,"phase").equals("received")).toList();
            need(incoming.size()==1&&text(incoming.getFirst(),"tool").equals("PROXY")
                    &&Optional.ofNullable(nullable(incoming.getFirst(),"listener")).orElse("").endsWith(":"+platform.listeners.get(expected.listener())),"HOST_PROXY_CALLBACK_IDENTITY");
            input=incoming.getFirst();
        } else {
            var outgoing=events.stream().filter(event->text(event,"family").equals("GLOBAL")&&text(event,"tool").equals("REPEATER")&&text(event,"phase").equals("to_send")).toList();
            need(outgoing.size()==1,"HOST_REPEATER_CALLBACK_IDENTITY");input=outgoing.getFirst();
            requiredAction(gui,"SEND_REPEATER","nonce",nonce);
        }
        boolean tagged=Set.of("TAGGED","TAGGED_STOP","TAGGED_PROXY_BEST_EFFORT","HTTP_AUTH").contains(expected.kind()),copied=expected.kind().equals("COPIED_ORDINARY");
        fact(bool(input,"nativeTag")==tagged&&bool(input,"httpAuthenticationDirective")== (expected.delivery()==Delivery.HTTP)
                &&number(input,"authorizationHeaders")== (tagged||copied?1:0)&&number(input,"cookieHeaders")== (expected.delivery()==Delivery.HTTP?0:tagged||copied?1:0)
                &&bool(input,"c1")== (expected.delivery()!=Delivery.HTTP&&(tagged||copied))&&!bool(input,"c2"),"HOST_ORIGINAL_CALLBACK_SHAPE");
        if(expected.status()!=null)fact(!value.get("clientStatus").isJsonNull()&&number(value,"clientStatus")==expected.status(),"HOST_CLIENT_STATUS");
        else if(!value.get("clientStatus").isJsonNull())need(number(value,"clientStatus")>=100&&number(value,"clientStatus")<=599,"HOST_CLIENT_STATUS_SCHEMA");
        if(expected.tool().equals("REPEATER")&&expected.status()!=null) {
            var proof=requiredAction(gui,"ASSERT_REPEATER_RESPONSE","nonce",nonce);
            fact(number(proof.intent(),"status")==expected.status()&&number(object(proof.receipt().get("observed")),"status")==expected.status(),"HOST_NATIVE_RESPONSE_STATUS");
        }
        if(expected.status()!=null&&Set.of(Delivery.ACCEPTED,Delivery.ABSENT).contains(expected.delivery())) {
            String family=expected.tool().equals("PROXY")?"PROXY":"GLOBAL",phase=expected.tool().equals("PROXY")?"response_to_send":"response_received";
            var responses=events.stream().filter(event->text(event,"family").equals(family)&&text(event,"phase").equals(phase)&&text(event,"tool").equals(expected.tool())).toList();
            fact(responses.size()==1&&number(responses.getFirst(),"status")==expected.status(),"HOST_CLIENT_RESPONSE_CALLBACK");
        }
        switch(expected.delivery()) {
            case ACCEPTED,ABSENT -> {
                fact(received.size()==1,"HOST_APPLICATION_EXECUTION_COUNT");
                if(expected.delivery()==Delivery.ACCEPTED)accepted(received.getFirst(),expected.account());else rejected(received.getFirst(),false);
            }
            case REPLAY,REJECTED_REPLAY -> {
                fact(received.size()==2,"HOST_REPLAY_EXECUTION_COUNT");rejected(received.getFirst(),true);
                int status=expected.delivery()==Delivery.REPLAY?200:401;
                if(status==200)accepted(received.get(1),"user");else rejected(received.get(1),true);
                need(number(value,"expectedReplayStatus")==status&&Objects.equals(nullable(value,"expectedReplayAccount"),status==200?"user":null),"HOST_REPLAY_INTENT");
                var replay=events.stream().filter(event->text(event,"family").equals("GLOBAL")&&text(event,"tool").equals("EXTENSIONS")&&text(event,"phase").equals("to_send")).toList();
                need(replay.size()==1,"HOST_REPLAY_CALLBACK_COUNT");long replayId=number(replay.getFirst(),"id");
                var originals=events.stream().filter(event->text(event,"family").equals("PROXY")&&text(event,"phase").equals("response_to_send")).toList();
                fact(originals.size()==1&&number(originals.getFirst(),"status")==401&&number(originals.getFirst(),"id")!=replayId,"HOST_ORIGINAL_REPLAY_IDENTITY");
                fact(events.stream().filter(event->text(event,"family").equals("GLOBAL")&&text(event,"tool").equals("EXTENSIONS")
                        &&text(event,"phase").equals("response_received")&&number(event,"id")==replayId&&number(event,"status")==status).count()==1,"HOST_REPLAY_RESPONSE_CALLBACK");
            }
            case STOP -> {fact(received.isEmpty(),"HOST_STOPPED_REQUEST_DELIVERED");platform.forbidden.add(nonce);}
            case PROXY_UNKNOWN -> {
                fact(received.size()<=1,"HOST_PROXY_FAILURE_DUPLICATE");
                if(!received.isEmpty()){var row=received.getFirst();var shape=object(row.get("request"));fact(nullable(row,"accountId")==null&&bool(shape,"nativeTag")
                        &&number(shape,"authorizationHeaders")==1&&number(shape,"cookieHeaders")==1,"HOST_PROXY_FAILURE_CHANGED");}
            }
            case UNLOAD -> {fact(received.size()<=1,"HOST_UNLOAD_LATE_DELIVERY");if(!received.isEmpty())rejected(received.getFirst(),false);else platform.forbidden.add(nonce);}
            case HTTP -> { /* Protocol fixture snapshots are joined separately below. */ }
        }
        for(var row:received) {
            fact(text(object(row.get("request")),"method").equals(text(value,"method")),"HOST_SERVER_METHOD");
            if(platform.primary==null){need(scenario.equals("routing")&&subcase.equals("port-cold"),"HOST_ORIGIN_WITNESS");platform.primary=(int)number(row,"listenerPort");}
            boolean alternate=scenario.equals("routing")&&((Set.of("port-warm","url-prefix","url-and-port").contains(subcase)&&index>=3)
                    ||Set.of("regex-substring","regex-anchor","regex-invalid-retains").contains(subcase)&&index==1)
                    ||scenario.equals("intercept")&&subcase.equals("matching-to-alternate");
            if(alternate&&platform.alternate==null){platform.alternate=(int)number(row,"listenerPort");fact(!platform.alternate.equals(platform.primary),"HOST_DISTINCT_ORIGINS");}
            fact(number(row,"listenerPort")== (alternate?platform.alternate:platform.primary),"HOST_FINAL_SERVER_DESTINATION");
        }
    }
    private static void uiAssertion(List<Gui> gui,String code,String nonce) throws Rejected {
        var item=requiredAction(gui,"ASSERT_UI","code",code);var observed=object(item.receipt().get("observed"));
        fact(bool(observed,"assertionObserved")&&code.equals(nullable(observed,"assertionCode"))
                &&(nonce==null||nonce.equals(nullable(item.intent(),"nonce"))&&nonce.equals(nullable(observed,"nonce"))),"HOST_VISIBLE_FEEDBACK");
    }
    private static void special(String scenario,String id,JsonObject measure,Snapshot before,Snapshot after,List<JsonObject> rows,
                                List<Gui> gui,List<JsonObject> callbacks,Platform platform) throws Rejected {
        var originals=objects(array(measure,"originals"));long logins=after.logins()-before.logins();
        if(scenario.equals("http-auth")){http(measure,id,gui);return;}
        rules(measure,scenario,id,platform,before.generation());
        switch(scenario) {
            case "routing" -> {
                fact(logins==(id.equals("port-cold")?2:0),"HOST_ROUTING_LOGIN_COUNT");
                if(id.equals("port-cold")) {
                    fact(before.logins()==0&&after.issuances().size()==2&&new HashSet<>(after.issuances().values()).equals(Set.of("user","user2"))&&before.rows().size()==1,"HOST_COLD_BROWSER_AUTHENTICATION");
                    rejected(before.rows().getFirst(),false);fact(number(before.rows().getFirst(),"listenerPort")==platform.primary,"HOST_INITIAL_ORIGIN");
                    validateColdAdmission(measure);
                }
                if(id.equals("regex-invalid-retains"))uiAssertion(gui,"URL_REGEX_INVALID",null);
            }
            case "tags" -> fact(logins==0,"HOST_TAG_UNEXPECTED_LOGIN");
            case "repeater" -> {
                fact(logins==0,"HOST_REPEATER_UNEXPECTED_LOGIN");
                if(id.equals("copied-ordinary")) {
                    String source=text(originals.getFirst(),"nonce"),copy=text(originals.get(1),"nonce");
                    need(text(measure,"copiedFromNonce").equals(source),"HOST_COPY_SOURCE");requiredAction(gui,"COPY_TO_REPEATER","nonce",source);
                    var change=requiredAction(gui,"SET_REPEATER_NONCE","nonce",copy);need(text(change.intent(),"previousNonce").equals(source),"HOST_COPY_NONCE");
                    fact(nullable(rows.getFirst(),"issuanceId").equals(nullable(rows.get(1),"issuanceId")),"HOST_COPIED_CREDENTIAL_CHANGED");
                }
            }
            case "recovery","rejected-replay" -> {
                if(id.equals("paused-subsequent")) {fact(logins==0,"HOST_PAUSED_LOGIN");uiAssertion(gui,"RECOVERY_PAUSED",null);}
                else {
                    fact(logins==1&&after.issuances().size()==before.issuances().size()+1,"HOST_SHARED_RECOVERY_LOGIN");
                    String revoked=text(measure,"revokedIssuanceId");String primeNonce=text(originals.getFirst(),"nonce");
                    fact(revoked.equals(nullable(nonceRows(rows,primeNonce).getFirst(),"issuanceId")),"HOST_REVOKED_ISSUANCE");
                    if(scenario.equals("recovery")) {
                        var replacements=new HashSet<String>();
                        for(var original:originals.subList(1,originals.size())) {
                            var replay=nonceRows(rows,text(original,"nonce")).get(1);String issuance=nullable(replay,"issuanceId");
                            fact(issuance!=null&&!issuance.equals(revoked)&&!before.issuances().containsKey(issuance),"HOST_RECOVERY_NEW_ISSUANCE");replacements.add(issuance);
                        }
                        fact(replacements.size()==1,"HOST_RECOVERY_SHARED_ISSUANCE");
                    } else uiAssertion(gui,"RECOVERY_PAUSED",null);
                }
            }
            case "intercept" -> {
                var on=gui.stream().filter(item->text(item.receipt(),"operation").equals("SET_INTERCEPT")&&bool(item.intent(),"enabled")).toList();
                var off=gui.stream().filter(item->text(item.receipt(),"operation").equals("SET_INTERCEPT")&&!bool(item.intent(),"enabled")).toList();
                need(on.size()==1&&!off.isEmpty(),"HOST_INTERCEPT_STATE");String nonce=text(originals.getFirst(),"nonce");
                var edit=requiredAction(gui,"EDIT_INTERCEPTED_REQUEST","nonce",nonce);var forward=requiredAction(gui,"FORWARD_INTERCEPTED_REQUEST","nonce",nonce);
                need(number(on.getFirst().receipt(),"sequence")<number(edit.receipt(),"sequence")&&number(edit.receipt(),"sequence")<number(forward.receipt(),"sequence")
                        &&off.stream().anyMatch(item->number(item.receipt(),"sequence")>number(forward.receipt(),"sequence")),"HOST_INTERCEPT_ACTION_ORDER");
                int from=id.equals("matching-to-alternate")?platform.primary:platform.alternate,to=id.equals("matching-to-alternate")?platform.alternate:platform.primary;
                fact(number(measure,"fromListenerPort")==from&&number(measure,"toListenerPort")==to,"HOST_INTERCEPT_ORIGIN_JOIN");
                fact(logins==(id.equals("alternate-to-matching")?1:0),"HOST_INTERCEPT_COLD_AUTHENTICATION");
            }
            case "unload" -> {
                var loading=gui.stream().filter(item->text(item.receipt(),"operation").equals("SET_PRODUCT_LOADED")).toList();
                need(loading.size()==1&&bool(loading.getFirst().intent(),"enabled")==id.equals("post-reload-fresh"),"HOST_UNLOAD_ACTION");
                fact(logins==1,"HOST_RELOAD_LOGIN_COUNT");
                if(id.equals("pending-unload")) {
                    var children=objects(array(measure,"childrenBefore"));var ended=objects(array(measure,"childrenAfter"));need(!children.isEmpty()&&children.size()==ended.size(),"HOST_CHILD_OWNERSHIP");
                    var ids=new HashSet<Long>();
                    for(var child:children) {
                        fields(child,"pid started executableSha256","");long pid=number(child,"pid"),started=number(child,"started");
                        need(pid>0&&started>0&&ids.add(pid),"HOST_CHILD_IDENTITY");LabJson.hash(child.get("executableSha256"));
                        var match=ended.stream().filter(row->number(row,"pid")==pid).toList();
                        need(match.size()==1,"HOST_CHILD_IDENTITY");fields(match.getFirst(),"pid started alive","");
                        fact(number(match.getFirst(),"started")==started&&!bool(match.getFirst(),"alive"),"HOST_CHILD_STILL_ALIVE");
                    }
                    need(new HashSet<>(LabJson.strings(measure.get("issuedBeforeReload"))).equals(after.issuances().keySet()),"HOST_RELOAD_ISSUANCE_BASELINE");
                } else {
                    var previous=new HashSet<>(LabJson.strings(measure.get("priorIssuanceIds")));
                    need(previous.equals(before.issuances().keySet()),"HOST_RELOAD_ISSUANCE_BASELINE");
                    fact(!previous.contains(nullable(rows.getFirst(),"issuanceId"))&&after.issuances().size()==before.issuances().size()+1,"HOST_RELOAD_FRESH_ISSUANCE");
                    for(String alias:List.of("host_a","host_b"))need(action(gui,"ENTER_SECRET","alias",alias),"HOST_REENTER_SECRET");
                }
            }
            case "ordinary-failure" -> {
                fact(before.logins()==0&&logins>=1&&logins<=3&&after.issuances().isEmpty(),"HOST_FAILED_LOGIN_CYCLE");
                var shape=object(rows.getFirst().get("request"));fact(bool(shape,"sentinel")&&number(shape,"bodyBytes")==0,"HOST_ORDINARY_REQUEST_CHANGED");
                uiAssertion(gui,"LOGIN_FAILED",null);uiAssertion(gui,"ORDINARY_UNCHANGED",text(originals.getFirst(),"nonce"));
            }
            default->throw new Rejected(Outcome.BLOCKED,"HOST_SCENARIO");
        }
    }
    private static void rules(JsonObject measure,String scenario,String id,Platform platform,long generation) throws Rejected {
        var settings=object(measure.get("rules"));fields(settings,"mode policy enabled tools rules","");
        need(text(settings,"mode").equals("REPLACE")&&text(settings,"policy").equals("WAIT_FOR_LOGIN")&&bool(settings,"enabled")
                &&LabJson.strings(settings.get("tools")).equals(List.of("PROXY","REPEATER")),"HOST_RULE_SETTINGS");
        var rows=objects(array(settings,"rules"));String prefix="http://127.0.0.1:"+platform.primary+"/cases/BROW.basic.json/protected/";
        String target=prefix+"b_c1?generation="+generation,anchored="^"+Pattern.quote(target)+"(?:&host_probe=h[0-9a-f]{16})?$";
        for(var row:rows) {
            fields(row,"alias enabled urlMode url regex proxyPort detect detectBy failureStatus responsePattern","");
            need(bool(row,"enabled")&&text(row,"detectBy").equals("STATUS_CODE")&&number(row,"failureStatus")==401&&text(row,"responsePattern").isEmpty(),"HOST_RULE_SCHEMA");
        }
        if(scenario.equals("routing")) {
            if(Set.of("port-cold","port-warm","url-and-port").contains(id)) {
                need(rows.size()==2,"HOST_RULE_COUNT");
                for(int i=0;i<2;i++)rule(rows.get(i),i==0?"host_a":"host_b",id.equals("url-and-port")?"SINGLE_URL":"ALL_REQUESTS",id.equals("url-and-port")?prefix:"",false,platform.listeners.get(i),false);
            } else {
                need(rows.size()==1,"HOST_RULE_COUNT");String value=switch(id){case "url-prefix"->prefix;case "regex-substring"->Pattern.quote(prefix);
                    case "regex-case-miss"->Pattern.quote(prefix.toLowerCase(Locale.ROOT));case "regex-case-fold"->"(?i)"+Pattern.quote(prefix.toLowerCase(Locale.ROOT));
                    case "regex-anchor-miss"->"^"+Pattern.quote(prefix)+"never$";default->anchored;};
                rule(rows.getFirst(),"host_a","SINGLE_URL",value,!id.equals("url-prefix"),null,false);
            }
        } else if(scenario.equals("tags")||scenario.equals("repeater")&&id.equals("explicit-tags")) {
            need(rows.size()==1,"HOST_RULE_COUNT");rule(rows.getFirst(),"host_b","SINGLE_URL",prefix,false,null,false);
        } else if(scenario.equals("repeater")&&Set.of("copied-ordinary","removed-port-only").contains(id)) {
            need(rows.size()==1,"HOST_RULE_COUNT");rule(rows.getFirst(),"host_a","ALL_REQUESTS","",false,platform.listeners.getFirst(),false);
        } else {
            need(rows.size()==1,"HOST_RULE_COUNT");rule(rows.getFirst(),scenario.equals("ordinary-failure")?"host_failure_a":"host_a","SINGLE_URL",prefix,false,null,
                    scenario.equals("recovery")||scenario.equals("rejected-replay"));
        }
    }
    private static void rule(JsonObject row,String alias,String mode,String url,boolean regex,Integer port,boolean detect) throws Rejected {
        fact(text(row,"alias").equals(alias)&&text(row,"urlMode").equals(mode)&&text(row,"url").equals(url)&&bool(row,"regex")==regex&&bool(row,"detect")==detect
                &&row.get("proxyPort").equals(port==null?JsonNull.INSTANCE:new JsonPrimitive(port)),"HOST_RULE_INTENT");
    }
    /** Cold first-page timing includes admission/initialization/navigation/rendering, not DOM readiness or pure engine CPU time. */
    static void validateColdAdmission(JsonObject measure) throws Rejected {
        var before=objects(array(object(measure.get("serverBefore")),"events"));var after=objects(array(object(measure.get("serverAfter")),"events"));
        var originals=objects(array(measure,"originals"));var timings=objects(array(measure,"browserAdmission"));
        need(originals.size()==3&&timings.size()==2,"HOST_COLD_PAGE_TIMING");
        need(before.stream().noneMatch(event->text(event,"name").equals("host-login-page-response-start")
                ||text(event,"phase").equals("LOGIN")&&Set.of("phase-entered","login-completed").contains(text(event,"name"))),"HOST_COLD_PAGE_WARM_SUBSTITUTION");
        var pages=after.stream().filter(event->text(event,"name").equals("host-login-page-response-start")).toList();
        var completed=after.stream().filter(event->text(event,"phase").equals("LOGIN")&&text(event,"name").equals("login-completed")).toList();
        need(pages.size()==2&&completed.size()==2&&after.stream().filter(event->text(event,"phase").equals("LOGIN")&&text(event,"name").equals("phase-entered")).count()==2,"HOST_COLD_PAGE_WARM_SUBSTITUTION");
        for(int i=0;i<2;i++) {
            String alias=i==0?"host_a":"host_b",account=i==0?"user":"user2";var timing=timings.get(i);
            fields(timing,"alias nonce dispatchEpochMs serverEventSequence elapsedMs boundary","");
            need(text(timing,"alias").equals(alias)&&text(timing,"nonce").equals(text(originals.get(i),"nonce"))
                    &&text(timing,"boundary").equals("CLIENT_DISPATCH_TO_LOGIN_PAGE_RESPONSE_START"),"HOST_COLD_PAGE_IDENTITY");
            long sequence=number(timing,"serverEventSequence"),dispatch=number(timing,"dispatchEpochMs");
            need(sequence>before.size()&&sequence<=after.size()&&dispatch>=number(measure,"startedEpochMs"),"HOST_COLD_PAGE_SEQUENCE");
            var page=after.get(Math.toIntExact(sequence-1));var ids=objects(array(page,"safeIds"));
            need(number(page,"sequence")==sequence&&text(page,"phase").equals("LOGIN")&&text(page,"name").equals("host-login-page-response-start")
                    &&ids.size()==1&&text(ids.getFirst(),"kind").equals("journey-alias")&&text(ids.getFirst(),"value").equals(alias),"HOST_COLD_PAGE_EVENT_JOIN");
            need(pages.stream().filter(event->objects(array(event,"safeIds")).stream().anyMatch(id->text(id,"kind").equals("journey-alias")&&text(id,"value").equals(alias))).count()==1,"HOST_COLD_PAGE_DUPLICATE");
            long observed=Instant.parse(text(page,"time")).toEpochMilli();
            fact(observed>=dispatch&&observed<=number(measure,"endedEpochMs")&&observed-dispatch<=60_000&&number(timing,"elapsedMs")==observed-dispatch,"HOST_COLD_PAGE_DURATION");
            var login=completed.stream().filter(event->objects(array(event,"safeIds")).stream().anyMatch(id->text(id,"kind").equals("account")&&text(id,"value").equals(account))).toList();
            need(login.size()==1&&number(login.getFirst(),"sequence")>sequence&&Instant.parse(text(login.getFirst(),"time")).toEpochMilli()>=observed,"HOST_COLD_PAGE_LOGIN_ORDER");
        }
    }
    private record HttpApp(String protocol,List<JsonObject> operations,List<JsonObject> requests,long handshakes,long posts) { }
    private static Map<String,HttpApp> httpSnapshot(JsonObject snapshot) throws Rejected {
        fields(snapshot,"applications","");var result=new LinkedHashMap<String,HttpApp>();
        for(var app:objects(array(snapshot,"applications"))) {
            fields(app,"protocol observations requests truncated handshakes posts leakedDirectives applicationAuthorizations","");String protocol=text(app,"protocol");
            need(Set.of("BASIC","NTLM_V1","NTLM_V2").contains(protocol)&&!result.containsKey(protocol)&&!bool(app,"truncated"),"HOST_HTTP_FIXTURE_INCOMPLETE");
            fact(number(app,"leakedDirectives")==0&&number(app,"applicationAuthorizations")==0,"HOST_HTTP_HEADER_LEAK");
            var operations=objects(array(app,"observations"));var requests=objects(array(app,"requests"));need(operations.size()<=10000&&requests.size()<=10000,"HOST_HTTP_OVERFLOW");long next=1;
            var a=new HashSet<String>();var b=new HashSet<String>();
            for(var row:operations) {
                fields(row,"user protocol connection method path bodyBytes nonce operationId","");
                need(number(row,"operationId")==next++&&text(row,"protocol").equals(protocol)&&Set.of("user-a","user-b").contains(text(row,"user"))
                        &&Set.of("GET","POST").contains(text(row,"method"))&&text(row,"path").equals("/whoami")&&number(row,"bodyBytes")<=1_048_576
                        &&text(row,"connection").matches("[A-Za-z0-9_-]{1,128}"),"HOST_HTTP_OPERATION_SCHEMA");
                String nonce=nullable(row,"nonce");need(nonce==null||nonce.matches("h[0-9a-f]{16}"),"HOST_HTTP_NONCE");
                (text(row,"user").equals("user-a")?a:b).add(text(row,"connection"));
            }
            if(!protocol.equals("BASIC"))fact(Collections.disjoint(a,b),"HOST_NTLM_IDENTITY_CONNECTION_LEAK");
            for(var row:requests) {
                fields(row,"method path connection bodyBytes nonce challengePhase httpDirective","");
                need(Set.of("GET","POST").contains(text(row,"method"))&&text(row,"path").equals("/whoami")&&text(row,"connection").matches("[A-Za-z0-9_-]{1,128}")
                        &&number(row,"bodyBytes")<=1_048_576&&Set.of("NONE","BASIC","NTLM_NEGOTIATE","NTLM_AUTHENTICATE","NTLM_SESSION").contains(text(row,"challengePhase")),"HOST_HTTP_WIRE_SCHEMA");
                String nonce=nullable(row,"nonce");need(nonce==null||nonce.matches("h[0-9a-f]{16}"),"HOST_HTTP_NONCE");fact(!bool(row,"httpDirective"),"HOST_HTTP_DIRECTIVE_LEAK");
                need(protocol.equals("BASIC")?!text(row,"challengePhase").startsWith("NTLM"):!text(row,"challengePhase").equals("BASIC"),"HOST_HTTP_PROTOCOL_DOWNGRADE");
            }
            long posts=number(app,"posts");fact(posts==operations.stream().filter(row->text(row,"method").equals("POST")).count(),"HOST_HTTP_EXECUTION_COUNTER");
            result.put(protocol,new HttpApp(protocol,operations,requests,number(app,"handshakes"),posts));
        }
        need(result.keySet().equals(Set.of("BASIC","NTLM_V1","NTLM_V2")),"HOST_HTTP_PROTOCOL_MISSING");return result;
    }
    private static void http(JsonObject measure,String id,List<Gui> gui) throws Rejected {
        var before=httpSnapshot(object(measure.get("httpBefore")));var after=httpSnapshot(object(measure.get("httpAfter")));
        String protocol=id.substring(0,id.indexOf('-')).toUpperCase(Locale.ROOT);
        for(String kind:before.keySet()) {
            var old=before.get(kind);var now=after.get(kind);
            need(now.operations().size()>=old.operations().size()&&now.operations().subList(0,old.operations().size()).equals(old.operations())
                    &&now.requests().size()>=old.requests().size()&&now.requests().subList(0,old.requests().size()).equals(old.requests())&&now.handshakes()>=old.handshakes(),"HOST_HTTP_REWRITTEN");
            if(!kind.equals(protocol))fact(now.operations().equals(old.operations())&&now.requests().equals(old.requests())&&now.posts()==old.posts(),"HOST_HTTP_WRONG_PROTOCOL_TARGET");
        }
        var old=before.get(protocol);var now=after.get(protocol);need(old!=null&&now!=null,"HOST_HTTP_SUBCASE");
        if(id.equals("basic-test-a"))fact(before.values().stream().allMatch(app->app.operations().isEmpty()&&app.requests().isEmpty()),"HOST_HTTP_COLD_BASELINE");
        if(id.equals("ntlm_v2-repeater-a2"))fact(after.values().stream().allMatch(app->app.operations().size()==8&&app.posts()==6),"HOST_HTTP_COMPLETE_RECIPE_COUNTS");
        var operations=now.operations().subList(old.operations().size(),now.operations().size());
        var transmissions=now.requests().subList(old.requests().size(),now.requests().size());
        fact(operations.size()==1&&!transmissions.isEmpty(),"HOST_HTTP_AUTHENTICATED_OPERATION_COUNT");var accepted=operations.getFirst();
        String suffix=id.endsWith("-b")?"b":"a",account="user-"+suffix;
        fact(text(accepted,"user").equals(account),"HOST_HTTP_AUTHENTICATED_USER");
        var settings=object(measure.get("rules"));fields(settings,"mode policy enabled tools rules","");
        need(!bool(settings,"enabled")&&array(settings,"rules").isEmpty(),"HOST_HTTP_AUTOMATIC_HANDLING_DISABLED");
        if(id.contains("-test-")) {
            need(array(measure,"originals").isEmpty(),"HOST_HTTP_UI_ORIGINAL");
            var proof=object(measure.get("uiTest"));fields(proof,"alias expectedProtocol expectedAccount guiSequence","");
            String alias="host_"+protocol.toLowerCase(Locale.ROOT)+"_"+suffix;
            var action=requiredAction(gui,"TEST_LOGIN","alias",alias);var visible=object(action.receipt().get("observed"));
            fact(text(visible,"loginResult").equals("HTTP_AUTHENTICATED")&&text(visible,"httpProtocol").equals(protocol),"HOST_HTTP_VISIBLE_RESULT");
            need(text(proof,"alias").equals(alias)&&text(proof,"expectedProtocol").equals(protocol)&&text(proof,"expectedAccount").equals(account)
                    &&number(proof,"guiSequence")==number(action.receipt(),"sequence"),"HOST_HTTP_UI_JOIN");
            fact(text(accepted,"method").equals("GET")&&nullable(accepted,"nonce")==null&&number(accepted,"bodyBytes")==0&&now.posts()==old.posts(),"HOST_HTTP_UI_SERVER_PROOF");
        } else {
            var original=object(array(measure,"originals").get(0));String nonce=text(original,"nonce");
            fact(nonce.equals(nullable(accepted,"nonce"))&&text(accepted,"method").equals("POST")&&number(accepted,"bodyBytes")=="authlab-action".getBytes(StandardCharsets.UTF_8).length
                    &&now.posts()==old.posts()+1&&transmissions.stream().allMatch(row->nonce.equals(nullable(row,"nonce"))&&text(row,"method").equals("POST")
                    &&number(row,"bodyBytes")==number(accepted,"bodyBytes")),"HOST_HTTP_ORIGINAL_SERVER_JOIN");
            fact(transmissions.stream().anyMatch(row->text(row,"connection").equals(text(accepted,"connection"))),"HOST_HTTP_CONNECTION_JOIN");
            if(id.contains("-repeater-a" )&&!id.endsWith("a2"))requiredAction(gui,"COPY_TO_REPEATER","nonce",text(measure,"copiedFromNonce"));
        }
    }
    static boolean bindingCurrent(ScenarioCatalog.Requirement requirement,LabHostInputs.Plan plan,Path workspace) throws IOException {
        var binding=requirement.binding();if(binding==null||!binding.executor().equals("HOST"))return false;
        if(requirement.layer()!=ScenarioCatalog.Layer.HOST||!REQUIREMENTS.containsKey(requirement.id())||!OWNER.equals(binding.className())||!METHOD.equals(binding.methodSignature())
                ||!("HOST:"+requirement.id()).equals(binding.executionId())||!requirement.id().equals(binding.parameterKey())||!TASK.equals(binding.taskPath())||binding.xmlCaseName()!=null
                ||!plan.configurationHash().equals(binding.configurationHash())||binding.sourceRevision().isBlank()
                ||!binding.sourceHashes().equals(plan.sourceHashes())||!binding.sourceHashes().keySet().containsAll(criticalOwners()))return false;
        var inputs=new HashSet<String>();String protocol=protocol(requirement.id());
        for(String id:requiredScenarios(requirement.id()))inputs.add(protocol==null?id:id+"/"+protocol);
        if(binding.witnesses().size()!=inputs.size()||!binding.witnesses().stream().map(ScenarioCatalog.Witness::inputKey).collect(java.util.stream.Collectors.toSet()).equals(inputs))return false;
        for(var witness:binding.witnesses())if(!witness.requirementId().equals(requirement.id())||!witness.sourcePath().equals(SOURCE)
                ||!witness.sourceSymbol().equals(sourceSymbol(witness.inputKey().split("/",2)[0])))return false;
        for(var source:binding.sourceHashes().entrySet())if(!source.getValue().equals(plan.sourceHashes().get(source.getKey())))return false;
        return LabEvidence.currentSources(binding,workspace);
    }
    /** Dispatcher entry; never interprets a host scenario identity as JUnit XML. */
    public static boolean collect(Path directory,Path workspace) throws IOException {
        UUID invocation;
        try{invocation=UUID.fromString(directory.toAbsolutePath().getParent().getFileName().toString());}
        catch(RuntimeException invalid){throw new Rejected(Outcome.BLOCKED,"HOST_REPORT_OWNER");}
        var plan=LabHostInputs.plan(workspace.resolve("test/authentication-lab/build/host-runtime").resolve(invocation.toString()).resolve("plan.json"));
        return collect(directory,workspace,plan);
    }
    public record CollectionResult(boolean complete,Outcome outcome,String code) {
        public CollectionResult {LabJson.require(complete==(outcome==Outcome.PASS)&&code.matches("[A-Z][A-Z0-9_]{0,79}"),"HOST_COLLECTION_RESULT");}
    }
    public static boolean collect(Path directory,Path workspace,LabHostInputs.Plan plan) throws IOException {
        return collectResult(directory,workspace,plan).complete();
    }
    public static CollectionResult collectResult(Path directory,Path workspace,LabHostInputs.Plan plan) throws IOException {
        VerifiedRun verified=null;Rejected rejected=null;
        try{verified=validate(directory,workspace,plan);}catch(Rejected failure){rejected=failure;}
        var catalog=ScenarioCatalog.load(workspace.resolve("test/authentication-lab/src/main/resources/catalog"));var counts=new LinkedHashMap<String,Integer>();
        for(String key:List.of("PASS","FAIL","BLOCKED","NOT_RUN","INTERRUPTED","EXCLUDED"))counts.put(key,0);
        boolean complete=verified!=null;String contextHash=null;
        Path context=directory.resolve("report-context.json");if(Files.isRegularFile(context,LinkOption.NOFOLLOW_LINKS))contextHash=LabJson.sha256(context);
        try(var report=new LabEvidence(directory.resolve("report-host.jsonl"),plan.invocationId(),UUID.randomUUID())) {
            report.write("RUN_STARTED",Map.of("productionRevision",plan.head()+"+working-copy:"+plan.sourceRevision(),"artifacts",List.of(new LabRun.ArtifactRecord("burp-extension","current",plan.product().sha256())),
                    "dependencyPins",List.of(),"profiles",List.of("burp-host"),"selectedRequirementIds",new ArrayList<>(REQUIREMENTS.keySet())));
            for(String id:REQUIREMENTS.keySet()) {
                var row=catalog.requirement(id);var binding=row.binding();boolean manual=binding==null||!binding.executor().equals("HOST")||row.disposition()==ScenarioCatalog.Disposition.MANUAL;
                String outcome=manual?"NOT_RUN":rejected!=null?rejected.outcome().name():"BLOCKED";
                RequirementProof proof=null;Object observedBinding=null;var observed=new ArrayList<ScenarioCatalog.Fact>();
                if(!manual&&verified!=null&&bindingCurrent(row,plan,workspace)) {
                    proof=verified.verifyRequirement(id);outcome="PASS";
                    observed.add(new ScenarioCatalog.Fact("outcome","independent-host-observations-joined"));
                    observed.add(new ScenarioCatalog.Fact("completion","all-mandatory-scenarios"));
                    observed.add(new ScenarioCatalog.Fact("hostCheckpoint","windows-and-linux"));
                    if(row.evidence().contains("resources"))observed.add(new ScenarioCatalog.Fact("resources","owned-processes-and-roots-removed"));
                    var owner=new LinkedHashMap<String,Object>();owner.put("executionId",binding.executionId());owner.put("executor","HOST");owner.put("invocationId",plan.invocationId());owner.put("taskPath",TASK);
                    owner.put("configurationHash",plan.configurationHash());owner.put("sourceRevision",plan.sourceRevision());owner.put("observedClassName",OWNER);owner.put("observedMethodSignature",METHOD);owner.put("observedParameterKey",id);
                    owner.put("bindingSha256",LabEvidence.sha256(LabJson.JSON.toJson(LabEvidence.canonical(LabJson.JSON.toJsonTree(binding))).getBytes(StandardCharsets.UTF_8)));
                    owner.put("witnessIds",binding.witnesses().stream().map(ScenarioCatalog.Witness::assertionId).toList());owner.put("contextSha256",contextHash);owner.put("outcome","PASS");observedBinding=owner;
                }
                complete &= outcome.equals("PASS");counts.merge(outcome,1,Integer::sum);
                var data=new LinkedHashMap<String,Object>();data.put("requirementIds",List.of(id));data.put("executionId",binding==null?"unbound:"+id:binding.executionId());
                data.put("observedBinding",observedBinding);data.put("caseRevision",row.revision());data.put("layer","HOST");data.put("classification",manual?"MANUAL":"SUPPORTED");data.put("outcome",outcome);
                data.put("expected",row.expected());data.put("observed",observed);data.put("missingEvidence",outcome.equals("PASS")?List.of():row.evidence());
                data.put("timings",proof==null?Map.of("startupMs",0,"caseMs",0,"cleanupMs",0):proof.timings());data.put("cleanup",verified==null?"INCOMPLETE":"COMPLETE");
                data.put("host",proof==null?Map.of("code",rejected==null?"HOST_BINDING_NOT_AUTOMATED_OR_CURRENT":rejected.code()):proof);report.write("CASE_RESULT",data);
            }
            report.write("RUN_COMPLETED",Map.of("outcomes",counts,"cleanupOutcome",verified==null?"INCOMPLETE":"COMPLETE","remainingResources",List.of(),"complete",complete));
        }
        return new CollectionResult(complete,complete?Outcome.PASS:rejected==null?Outcome.BLOCKED:rejected.outcome(),
                complete?"HOST_ACCEPTANCE_COMPLETE":rejected==null?"HOST_BINDING_NOT_AUTOMATED_OR_CURRENT":rejected.code());
    }
}
