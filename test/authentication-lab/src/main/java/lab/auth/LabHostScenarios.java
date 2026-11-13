package lab.auth;

import com.google.gson.*;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.BooleanSupplier;
import java.util.regex.Pattern;
import static lab.auth.LabHostCoordinator.Outcome;
import static lab.auth.LabHostGuiProtocol.Operation;

/** Fixed host recipes. Authentication, editing, storage and replay remain owned by the loaded extension. */
public final class LabHostScenarios implements AutoCloseable {
    @FunctionalInterface public interface Gui {
        JsonObject ask(Operation operation, JsonObject arguments, Duration timeout) throws Exception;
    }
    @FunctionalInterface public interface Export {
        void prepare(String prefix, Path output) throws Exception;
    }
    @FunctionalInterface private interface Checked { void run() throws Exception; }
    private static final String CASE = "BROW.basic.json";
    private static final long CASE_NANOS = Duration.ofSeconds(180).toNanos();
    private static final int REPORT_LIMIT = 16 * 1024 * 1024;
    public static final Map<String,List<String>> SUBCASES = subcases();
    private final LabHostGuiProtocol.Session session;
    private final LabRun run;
    private final Path root, report, inputs;
    private final List<Integer> ports;
    private final Gui gui;
    private final Export exporter;
    private final HttpClient direct;
    private final Map<Integer,HttpClient> clients = new LinkedHashMap<>();
    private final Set<String> originalNonces = new HashSet<>();
    private final List<LabRun.CaseLease> observedLeases = new ArrayList<>();
    private final List<String> forbidDelivery = new ArrayList<>();
    private final Map<String,URI> httpTargets = new LinkedHashMap<>();
    private LabRun.CaseLease lease;
    private JsonObject rules, setup = new JsonObject();
    private final JsonArray measurements = new JsonArray();
    private JsonObject measurement;
    private long deadline, lastGuiSequence;
    private String scenario;
    private long fileSequence;

    public LabHostScenarios(LabHostGuiProtocol.Session session, LabRun run, Path root, Path report,
                            List<Integer> ports, Gui gui, Export exporter) throws IOException {
        this.session = Objects.requireNonNull(session); this.run = Objects.requireNonNull(run);
        this.root = root.toRealPath(); this.report = report.toRealPath();
        if(!this.root.equals(session.root().toRealPath()) || !this.report.startsWith(this.root.resolve("report"))
                || ports.size()!=3 || new HashSet<>(ports).size()!=3 || ports.stream().anyMatch(p->p<1||p>65535))
            throw new IllegalArgumentException("HOST_SCENARIO_OWNER");
        this.ports=List.copyOf(ports);this.gui=Objects.requireNonNull(gui);this.exporter=Objects.requireNonNull(exporter);
        inputs=Files.createDirectories(this.root.resolve("scenario-inputs"));
        direct=ControlledApplication.localClientBuilder().connectTimeout(Duration.ofSeconds(5)).build();
        for(int port:ports)clients.put(port,HttpClient.newBuilder().proxy(new ProxySelector() {
            @Override public List<Proxy> select(URI uri){return List.of(new Proxy(Proxy.Type.HTTP,new InetSocketAddress("127.0.0.1",port)));}
            @Override public void connectFailed(URI uri,SocketAddress address,IOException error){}
        }).connectTimeout(Duration.ofSeconds(5)).build());
    }

    /** Setup is separately timed; no login is performed before the first measured cold dispatch. */
    public JsonObject setupEvidence(){return setup.deepCopy();}
    void prepareBrowserRuntime() throws Exception {
        deadline=System.nanoTime()+Duration.ofMinutes(12).toNanos();
        lease=run.cases().stream().filter(c->c.id().equals(CASE)).findFirst().orElseThrow(()->new Check(Outcome.BLOCKED,"HOST_CASE_MISSING"));
        observedLeases.add(lease);measurement=json("originals",new JsonArray());
        Path output=Files.createDirectory(root.resolve("scenario-native-runtime"));exporter.prepare("host",output);
        ask(Operation.IMPORT_JOURNEY,json("path",relative(output.resolve("native-examples/host_b.json")),"alias","host_b"));
    }
    JsonObject browserRuntimeLogin(boolean refill) throws Exception {
        Set<String> before=issued();
        if(refill)ask(Operation.ENTER_SECRET,json("alias","host_b","secret","FORM_B"));
        var observed=ask(Operation.TEST_BROWSER_LOGIN,json("alias","host_b"),Duration.ofSeconds(120)).getAsJsonObject("observed");
        block(observed.has("testUiConfirmed")&&observed.get("testUiConfirmed").getAsBoolean(),"HOST_RUNTIME_LOGIN_UI");
        String nonce=proxy(target(false,null),ports.getFirst(),"user2",200,formTags("host_b"));
        var row=single(nonce);String issuance=nullable(row.get("issuanceId"));
        var fresh=new HashSet<>(issued());fresh.removeAll(before);
        expect(fresh.equals(Set.of(issuance)),"HOST_RUNTIME_FRESH_LOGIN");
        return json("testUiConfirmed",true,"endedEpochMs",System.currentTimeMillis(),"proof",
                json("status",row.get("status"),"account",row.get("accountId"),"issuance",issuance,"roles",row.get("roles")));
    }
    @Override public void close(){for(var client:clients.values())client.close();direct.close();}
    JsonObject finishBrowserRuntime() throws Exception {
        Set<String> before=issued();
        var start=ask(Operation.RECORD_BROWSER_LOGIN,json("alias","host_b","secret","FORM_B"),Duration.ofSeconds(180)).getAsJsonObject("observed");
        for(String key:List.of("initialStepsCleared","nativeStart","loginTyped"))block(start.has(key)&&start.get(key).getAsBoolean(),"HOST_RUNTIME_RECORDING_UI");
        await(()->!issued().equals(before),Duration.ofSeconds(30),"HOST_RUNTIME_RECORDING_LOGIN_MISSING");
        var fresh=new HashSet<>(issued());fresh.removeAll(before);expect(fresh.size()==1,"HOST_RUNTIME_RECORDING_ISSUANCE");
        String issuance=fresh.iterator().next();
        var completed=server().getAsJsonArray("events").asList().stream().map(JsonElement::getAsJsonObject)
                .filter(event->"login-completed".equals(nullable(event.get("name")))&&event.getAsJsonArray("safeIds").asList().stream()
                        .map(JsonElement::getAsJsonObject).anyMatch(id->"issuance".equals(nullable(id.get("kind")))&&issuance.equals(nullable(id.get("value"))))).toList();
        expect(completed.size()==1,"HOST_RUNTIME_RECORDING_EVENT");
        var accounts=completed.getFirst().getAsJsonArray("safeIds").asList().stream().map(JsonElement::getAsJsonObject)
                .filter(id->"account".equals(nullable(id.get("kind")))).map(id->nullable(id.get("value"))).toList();
        expect(accounts.equals(List.of("user2")),"HOST_RUNTIME_RECORDING_ACCOUNT");
        var stop=ask(Operation.FINISH_BROWSER_RECORDING,json("alias","host_b"),Duration.ofSeconds(120)).getAsJsonObject("observed");
        for(String key:List.of("nativeStop","reviewReplaced"))block(stop.has(key)&&stop.get(key).getAsBoolean(),"HOST_RUNTIME_RECORDING_UI");
        var replay=browserRuntimeLogin(false);
        var recording=json("initialStepsCleared",start.get("initialStepsCleared"),"nativeStart",start.get("nativeStart"),"nativeStop",stop.get("nativeStop"),
                "reviewReplaced",stop.get("reviewReplaced"),"replayUiConfirmed",replay.get("testUiConfirmed"),"recordedAccount",accounts.getFirst(),"recordedIssuance",issuance,"replayProof",replay.get("proof"));
        Set<String> afterReplay=issued();var variants=new JsonArray();
        for(String theme:List.of("Light","Dark"))for(String size:List.of("compact","wide")) {
            var variant=ask(Operation.BROWSER_SETTINGS,json("alias","host_b","theme",theme,"size",size),Duration.ofSeconds(90)).getAsJsonObject("observed").deepCopy();
            expect(theme.equals(nullable(variant.get("theme")))&&size.equals(nullable(variant.get("size"))),"HOST_RUNTIME_SETTINGS_VARIANT");
            for(String key:List.of("inlineError","focused","noPopup","literalPath","controlsVisible"))block(variant.has(key)&&variant.get(key).getAsBoolean(),"HOST_RUNTIME_SETTINGS_UI");
            variants.add(variant);expect(issued().equals(afterReplay),"HOST_RUNTIME_INVALID_PATH_AUTHENTICATED");
        }
        return json("browserVersion",start.get("browserVersion"),"recording",recording,"settings",variants);
    }
    public Map<String,Outcome> run() throws IOException {
        var results=new LinkedHashMap<String,Outcome>();boolean interrupted=false, initialized=false;
        try {
            long began=System.currentTimeMillis();deadline=System.nanoTime()+Duration.ofMinutes(8).toNanos();
            try{initialize();initialized=true;setup.addProperty("outcome","PASS");}
            catch(InterruptedException stop){Thread.currentThread().interrupt();interrupted=true;setup.addProperty("outcome","INTERRUPTED");}
            catch(Exception unavailable){setup.addProperty("outcome","BLOCKED");setup.addProperty("code","HOST_SCENARIO_SETUP_UNAVAILABLE");}
            setup.addProperty("startedEpochMs",began);setup.addProperty("endedEpochMs",System.currentTimeMillis());
            setup.add("scenarios",new JsonArray());
            for(String id:LabHostInputs.SCENARIOS) {
                scenario=id;measurements.asList().clear();boolean prepared=initialized&&!interrupted;
                String preparationCode="HOST_SCENARIO_PREPARED";long preparationStarted=System.currentTimeMillis();
                if(prepared)try{deadline=System.nanoTime()+Duration.ofMinutes(8).toNanos();prepareScenario(id);}
                catch(InterruptedException stop){Thread.currentThread().interrupt();interrupted=true;prepared=false;preparationCode="HOST_CANCELLED";}
                catch(Exception unavailable){prepared=false;preparationCode="HOST_SCENARIO_PREPARATION_UNAVAILABLE";}
                setup.getAsJsonArray("scenarios").add(json("scenario",id,"startedEpochMs",preparationStarted,"endedEpochMs",System.currentTimeMillis(),
                        "outcome",prepared?"PASS":interrupted?"INTERRUPTED":"BLOCKED","code",preparationCode,"guiSequenceAfter",lastGuiSequence));
                long started=System.currentTimeMillis();
                deadline=System.nanoTime()+CASE_NANOS;Outcome outcome=Outcome.BLOCKED;String code="HOST_SCENARIO_NOT_RUN";JsonObject probe=null;
                if(prepared&&!interrupted) {
                    try {
                        resetProbe(id);dispatch(id);
                        expect(SUBCASES.get(id).equals(measurements.asList().stream().map(e->e.getAsJsonObject().get("subcaseId").getAsString()).toList()),
                                "HOST_SUBCASE_INVENTORY");
                        checkForbidden();outcome=Outcome.PASS;code="HOST_SCENARIO_VERIFIED";
                    }catch(Check failed){outcome=failed.outcome;code=failed.code;}
                    catch(InterruptedException stop){Thread.currentThread().interrupt();interrupted=true;outcome=Outcome.INTERRUPTED;code="HOST_CANCELLED";}
                    catch(Exception unavailable){outcome=Outcome.BLOCKED;code="HOST_SCENARIO_UNAVAILABLE";}
                    if(!interrupted)try{probe=exportProbe(id);validateProbe(probe,id);verifyProbeJoins(probe);}
                    catch(Check failed){outcome=failed.outcome;code=failed.code;}
                    catch(InterruptedException stop){Thread.currentThread().interrupt();interrupted=true;outcome=Outcome.INTERRUPTED;code="HOST_CANCELLED";}
                    catch(Exception unavailable){outcome=Outcome.BLOCKED;code="HOST_PROBE_UNAVAILABLE";}
                } else if(interrupted){outcome=Outcome.INTERRUPTED;code="HOST_CANCELLED";}else code=preparationCode;
                var evidence=LabHostGuiProtocol.identity(session);
                evidence.addProperty("scenario",id);evidence.addProperty("outcome",outcome.name());evidence.addProperty("code",code);
                evidence.addProperty("startedEpochMs",started);evidence.addProperty("endedEpochMs",System.currentTimeMillis());
                evidence.addProperty("runId",run.runId().toString());evidence.addProperty("caseGeneration",lease==null?0:lease.generation());
                evidence.add("measurements",measurements.deepCopy());evidence.add("probe",probe==null?JsonNull.INSTANCE:probe);
                byte[] bytes=LabJson.JSON.toJson(evidence).getBytes(StandardCharsets.UTF_8);
                if(bytes.length>REPORT_LIMIT) {
                    evidence.addProperty("outcome","BLOCKED");evidence.addProperty("code","HOST_SCENARIO_REPORT_LIMIT");
                    evidence.add("measurements",new JsonArray());evidence.add("probe",JsonNull.INSTANCE);outcome=Outcome.BLOCKED;
                }
                LabJson.writeNew(report.resolve("scenario-"+id+".json"),evidence);results.put(id,outcome);
            }
        } finally {
            close();
        }
        return Collections.unmodifiableMap(results);
    }

    private void initialize() throws Exception {
        lease=run.cases().stream().filter(c->c.id().equals(CASE)).findFirst().orElseThrow(()->new Check(Outcome.BLOCKED,"HOST_CASE_MISSING"));
        observedLeases.add(lease);
        var inventory=LabJson.JSON.toJsonTree(run.servingTargets(run.generation())).getAsJsonObject();
        for(var entry:inventory.getAsJsonArray("httpAuthentication")) {
            var item=entry.getAsJsonObject();String protocol=item.get("protocol").getAsString();
            if(!Set.of("BASIC","NTLM_V1","NTLM_V2").contains(protocol)||httpTargets.put(protocol,URI.create(item.get("request").getAsString()))!=null)
                throw new Check(Outcome.BLOCKED,"HOST_HTTP_INVENTORY");
        }
        block(httpTargets.size()==3,"HOST_HTTP_INVENTORY");
        Path output=Files.createDirectory(root.resolve("scenario-native-host"));exporter.prepare("host",output);
        for(String alias:List.of("host_a","host_b","host_basic_a","host_basic_b","host_ntlm_v1_a","host_ntlm_v1_b","host_ntlm_v2_a","host_ntlm_v2_b")) {
            ask(Operation.IMPORT_JOURNEY,json("path",relative(output.resolve("native-examples/"+alias+".json")),"alias",alias));
            ask(Operation.ENTER_SECRET,json("alias",alias,"secret",alias.equals("host_a")?"FORM_A":alias.equals("host_b")?"FORM_B":alias.endsWith("_a")?"HTTP_A":"HTTP_B"));
        }
        configure(List.of(),false);
        String nonce=nonce();URI target=target(false,nonce);
        var response=send(ports.get(2),target,nonce,Map.of(),false);
        expect(response.statusCode()==401,"HOST_REPEATER_SEED_STATUS");
        await(()->rows(nonce).size()==1,Duration.ofSeconds(3),"HOST_REPEATER_SEED_MISSING");
        ask(Operation.COPY_TO_REPEATER,json("nonce",nonce));
        setup.add("serverAfter",server());setup.addProperty("lastGuiSequence",lastGuiSequence);
    }

    private void dispatch(String id) throws Exception {
        switch(id) {
            case "routing" -> routing(); case "tags" -> tags();case "repeater" -> repeater();
            case "http-auth" -> httpAuth();case "recovery" -> recovery();case "rejected-replay" -> rejectedReplay();
            case "intercept" -> intercept();case "unload" -> unload();case "ordinary-failure" -> ordinaryFailure();
            default -> throw new Check(Outcome.BLOCKED,"HOST_SCENARIO_UNKNOWN");
        }
    }
    private void prepareScenario(String id) throws Exception {
        if(id.equals("intercept")||id.equals("unload")){reloadForm();onlyUrl(prefix(),false,false);}
        if(id.equals("ordinary-failure")) {
            configure(List.of(),false);lease.close();lease=run.prepareCase(CASE);observedLeases.add(lease);
            Path output=Files.createDirectory(root.resolve("scenario-native-failure"));exporter.prepare("host_failure",output);
            ask(Operation.IMPORT_JOURNEY,json("path",relative(output.resolve("native-examples/host_failure_a.json")),"alias","host_failure_a"));
            ask(Operation.ENTER_SECRET,json("alias","host_failure_a","secret","FORM_A"));
            configure(List.of(rule("host_failure_a","SINGLE_URL",prefix(),false,null,false)),true);
            for(int occurrence=1;occurrence<=3;occurrence++)fault(LabRun.Phase.LOGIN,occurrence,"HTTP_ERROR",503,null);
        }
    }
    private void measure(String id,String phase,Checked action) throws Exception {
        check();block(SUBCASES.get(scenario).contains(id),"HOST_SUBCASE_UNKNOWN");
        JsonObject current=json("subcaseId",id,"phase",phase,"guiSequenceBefore",lastGuiSequence);
        current.add("rules",rules==null?JsonNull.INSTANCE:rules.deepCopy());current.add("serverBefore",server());current.add("httpBefore",httpSnapshot());
        current.add("originals",new JsonArray());current.addProperty("startedEpochMs",System.currentTimeMillis());
        measurement=current;
        try{action.run();}
        finally {
            current.addProperty("endedEpochMs",System.currentTimeMillis());current.addProperty("guiSequenceAfter",lastGuiSequence);
            current.add("serverAfter",server());current.add("httpAfter",httpSnapshot());measurements.add(current);measurement=null;
        }
    }
    private JsonObject ask(Operation operation,JsonObject arguments) throws Exception {
        return ask(operation,arguments,Duration.ofSeconds(30));
    }
    private JsonObject ask(Operation operation,JsonObject arguments,Duration maximum) throws Exception {
        check();var receipt=gui.ask(operation,arguments,budget(maximum));
        block(receipt!=null&&receipt.has("sequence")&&receipt.has("observed")&&"PASS".equals(receipt.get("outcome").getAsString()),"HOST_GUI_RECEIPT_MISSING");
        long sequence=receipt.get("sequence").getAsLong();block(sequence>lastGuiSequence,"HOST_GUI_SEQUENCE");
        lastGuiSequence=sequence;return receipt;
    }
    private String nonce(){String value="h"+UUID.randomUUID().toString().replace("-","").substring(0,16);if(!originalNonces.add(value))throw new IllegalStateException("HOST_NONCE_REUSED");return value;}
    private String relative(Path file) throws IOException {return root.relativize(LabJson.owned(root,root.relativize(file).toString().replace(File.separatorChar,'/'))).toString().replace(File.separatorChar,'/');}
    private JsonObject server(){return lease==null?new JsonObject():LabJson.JSON.toJsonTree(lease.snapshot()).getAsJsonObject();}
    private JsonObject httpSnapshot() throws Exception {
        var response=direct.send(HttpRequest.newBuilder(run.applicationUri().resolve("/http-auth/observations")).timeout(budget(Duration.ofSeconds(5))).GET().build(),HttpResponse.BodyHandlers.ofByteArray());
        block(response.statusCode()==200&&response.body().length<=4*1024*1024,"HOST_HTTP_OBSERVATIONS_UNAVAILABLE");
        return LabJson.parse(response.body()).getAsJsonObject();
    }
    private URI target(boolean alternate,String nonce){URI value=lease.endpoint("protected/b_c1",alternate);return nonce==null?value:URI.create(value+"&host_probe="+nonce);}
    private HttpResponse<Void> send(int port,URI uri,String nonce,Map<String,String> headers,boolean post) throws Exception {
        check();var request=HttpRequest.newBuilder(uri).timeout(budget(Duration.ofSeconds(60))).header("X-AuthLab-Request",nonce);
        headers.forEach(request::header);
        if(post)request.POST(HttpRequest.BodyPublishers.ofString("authlab-action"));else request.GET();
        return clients.get(port).send(request.build(),HttpResponse.BodyHandlers.discarding());
    }
    private CompletableFuture<HttpResponse<Void>> sendAsync(int port,URI uri,String nonce,Map<String,String> headers) throws Exception {
        check();var request=HttpRequest.newBuilder(uri).timeout(budget(Duration.ofSeconds(60))).header("X-AuthLab-Request",nonce);
        headers.forEach(request::header);return clients.get(port).sendAsync(request.GET().build(),HttpResponse.BodyHandlers.discarding());
    }
    private JsonObject original(String nonce,String tool,Integer port,String kind,String account,Integer expected,Integer actual) {
        var row=json("nonce",nonce,"tool",tool,"listenerPort",port,"kind",kind,"method","GET","expectedAccount",account,"expectedStatus",expected,"clientStatus",actual);
        measurement.getAsJsonArray("originals").add(row);return row;
    }
    private String proxy(URI uri,int port,String account,int status,Map<String,String> headers) throws Exception {
        String nonce=nonce();URI withNonce=URI.create(uri+(uri.getRawQuery()==null?"?":"&")+"host_probe="+nonce);
        var response=send(port,withNonce,nonce,headers,false);original(nonce,"PROXY",port,tagged(headers)?"TAGGED":"NORMAL",account,status,response.statusCode());
        expect(response.statusCode()==status,"HOST_CLIENT_STATUS");if(status==200)accepted(nonce,account);else rejected(nonce,status,true);return nonce;
    }
    private String repeater(URI uri,Map<String,String> headers,String account,int status,boolean post) throws Exception {
        String nonce=nonce();Path file=requestFile(uri,nonce,headers,post);
        ask(Operation.SET_REPEATER_REQUEST,json("path",relative(file),"nonce",nonce));ask(Operation.SEND_REPEATER,json("nonce",nonce));
        var receipt=ask(Operation.ASSERT_REPEATER_RESPONSE,json("nonce",nonce,"status",status));
        Integer actual=receipt.getAsJsonObject("observed").has("status")?receipt.getAsJsonObject("observed").get("status").getAsInt():null;
        block(actual!=null,"HOST_REPEATER_RESPONSE_UNOBSERVABLE");original(nonce,"REPEATER",null,tagged(headers)?"TAGGED":"NORMAL",account,status,actual).addProperty("method",post?"POST":"GET");
        expect(actual==status,"HOST_REPEATER_STATUS");return nonce;
    }
    private Path requestFile(URI uri,String nonce,Map<String,String> headers,boolean post) throws IOException {
        String body=post?"authlab-action":"";
        var text=new StringBuilder(post?"POST ":"GET ").append(uri.getRawPath()).append(uri.getRawQuery()==null?"":"?"+uri.getRawQuery())
                .append(" HTTP/1.1\r\nHost: ").append(uri.getRawAuthority()).append("\r\nX-AuthLab-Request: ").append(nonce).append("\r\n");
        headers.forEach((name,value)->text.append(name).append(": ").append(value).append("\r\n"));
        if(post)text.append("Content-Length: ").append(body.getBytes(StandardCharsets.UTF_8).length).append("\r\nContent-Type: application/x-www-form-urlencoded\r\n");
        text.append("\r\n").append(body);Path file=inputs.resolve(String.format(Locale.ROOT,"%04d-request.txt",++fileSequence));
        Files.writeString(file,text,StandardCharsets.UTF_8,StandardOpenOption.CREATE_NEW);return file;
    }
    private List<JsonObject> rows(String nonce) {
        var snapshot=server();var host=snapshot.getAsJsonObject("hostObservations");if(host==null)return List.of();
        return host.getAsJsonArray("received").asList().stream().map(JsonElement::getAsJsonObject)
                .filter(row->nonce.equals(nullable(row.getAsJsonObject("request").get("nonce")))).toList();
    }
    private JsonObject single(String nonce) throws Exception {
        await(()->!rows(nonce).isEmpty()&&rows(nonce).stream().allMatch(row->row.get("status").getAsInt()>0),Duration.ofSeconds(5),"HOST_SERVER_OBSERVATION_MISSING");
        var found=rows(nonce);expect(found.size()==1,"HOST_DUPLICATE_APPLICATION_EXECUTION");return found.getFirst();
    }
    private void accepted(String nonce,String account) throws Exception {
        var row=single(nonce);var shape=row.getAsJsonObject("request");
        expect(row.get("status").getAsInt()==200&&account.equals(nullable(row.get("accountId"))),"HOST_SERVER_ACCOUNT");
        expect(new HashSet<>(LabJson.strings(row.get("roles"))).equals(Set.of("B","C1"))&&nullable(row.get("issuanceId"))!=null,"HOST_SERVER_ROLE_ISSUANCE");
        expect(shape.get("authorizationHeaders").getAsInt()==1&&shape.get("cookieHeaders").getAsInt()==1&&shape.get("c1").getAsBoolean()
                &&!shape.get("c2").getAsBoolean()&&!shape.get("nativeTag").getAsBoolean()&&!shape.get("httpDirective").getAsBoolean(),"HOST_SERVER_CREDENTIAL_SHAPE");
    }
    private void rejected(String nonce,int status,boolean absent) throws Exception {
        var row=single(nonce);var shape=row.getAsJsonObject("request");
        expect(row.get("status").getAsInt()==status&&row.get("accountId").isJsonNull(),"HOST_SERVER_REJECTION");
        if(absent)expect(shape.get("authorizationHeaders").getAsInt()==0&&shape.get("cookieHeaders").getAsInt()==0
                &&!shape.get("c1").getAsBoolean()&&!shape.get("c2").getAsBoolean()&&!shape.get("nativeTag").getAsBoolean()&&!shape.get("httpDirective").getAsBoolean(),"HOST_UNCHANGED_CREDENTIALS");
    }
    private JsonObject rule(String alias,String mode,String url,boolean regex,Integer port,boolean detect) {
        return json("alias",alias,"enabled",true,"urlMode",mode,"url",url,"regex",regex,"proxyPort",port,
                "detect",detect,"detectBy","STATUS_CODE","failureStatus",401,"responsePattern","");
    }
    private void configure(List<JsonObject> values,boolean enabled) throws Exception {
        var spec=json("mode","REPLACE","policy","WAIT_FOR_LOGIN","enabled",enabled);
        var tools=new JsonArray();tools.add("PROXY");tools.add("REPEATER");spec.add("tools",tools);
        var rows=new JsonArray();values.forEach(rows::add);spec.add("rules",rows);
        Path file=inputs.resolve(String.format(Locale.ROOT,"%04d-rules.json",++fileSequence));LabJson.writeNew(file,spec);
        ask(Operation.EDIT_RULES,json("path",relative(file)));rules=spec.deepCopy();
        if(measurement!=null)measurement.add("rules",rules.deepCopy());
    }
    private void resetProbe(String id) throws Exception {
        var spec=json("version",1,"case","host-"+id);var origins=new JsonArray();
        if(id.equals("http-auth"))httpTargets.values().forEach(uri->origins.add(origin(uri).toString()));
        else {origins.add(origin(run.applicationUri()).toString());origins.add(origin(run.alternateUri()).toString());}
        spec.add("origins",origins);Path input=inputs.resolve("probe-"+id+"-setup.json");LabJson.writeNew(input,spec);
        ask(Operation.CAPTURE_PROBE,json("phase","RESET","path",relative(input)));
    }
    private JsonObject exportProbe(String id) throws Exception {
        Path output=inputs.resolve("probe-"+id+"-result.json");ask(Operation.CAPTURE_PROBE,json("phase","EXPORT","path",relative(output)));
        return LabJson.read(output,1_048_576);
    }
    private void validateProbe(JsonObject value,String id) throws Check {
        try {
            expect(value.get("version").getAsInt()==1&&value.get("complete").getAsBoolean()&&!value.get("overflow").getAsBoolean(),"HOST_PROBE_INCOMPLETE");
            expect(value.get("invocationId").getAsString().equals(session.invocationId().toString())
                    &&value.get("platform").getAsString().equals(session.platform())&&value.get("runNonce").getAsString().equals(session.runNonce().toString())
                    &&value.get("productSha256").getAsString().equals(session.productSha256())&&value.get("helperSha256").getAsString().equals(session.helperSha256())
                    &&value.get("case").getAsString().equals("host-"+id),"HOST_PROBE_IDENTITY");
            long sequence=0;for(var element:value.getAsJsonArray("events")) {
                var row=element.getAsJsonObject();expect(row.get("sequence").getAsLong()==++sequence&&row.get("case").getAsString().equals("host-"+id)
                        &&!row.get("invalidNonce").getAsBoolean()&&!row.get("shapeTruncated").getAsBoolean(),"HOST_PROBE_SEQUENCE");
            }
        }catch(Check failure){throw failure;}catch(RuntimeException malformed){throw new Check(Outcome.BLOCKED,"HOST_PROBE_SCHEMA");}
    }
    private void verifyProbeJoins(JsonObject probe) throws Check {
        var events=probe.getAsJsonArray("events").asList().stream().map(JsonElement::getAsJsonObject).toList();
        for(var value:measurements)for(var original:value.getAsJsonObject().getAsJsonArray("originals")) {
            var item=original.getAsJsonObject();String nonce=item.get("nonce").getAsString(),tool=item.get("tool").getAsString();
            var observed=events.stream().filter(row->nonce.equals(nullable(row.get("nonce")))).toList();
            expect(!observed.isEmpty(),"HOST_CALLBACK_MISSING");
            if(tool.equals("PROXY"))expect(observed.stream().anyMatch(row->"PROXY".equals(nullable(row.get("family")))&&"received".equals(nullable(row.get("phase")))
                    &&listener(row,item.get("listenerPort").getAsInt())),"HOST_PROXY_LISTENER_CALLBACK");
            else expect(observed.stream().anyMatch(row->"GLOBAL".equals(nullable(row.get("family")))&&"REPEATER".equals(nullable(row.get("tool")))
                    &&"to_send".equals(nullable(row.get("phase")))),"HOST_REPEATER_CALLBACK");
            String kind=item.get("kind").getAsString();
            if(kind.equals("RECOVERY")||kind.equals("REJECTED_REPLAY")) {
                var originals=observed.stream().filter(row->"PROXY".equals(nullable(row.get("family")))&&"response_to_send".equals(nullable(row.get("phase")))).toList();
                expect(originals.size()==1&&originals.getFirst().get("status").getAsInt()==401,"HOST_RECOVERY_ORIGINAL_CALLBACK_STATUS");
                var replays=observed.stream().filter(row->"GLOBAL".equals(nullable(row.get("family")))&&"EXTENSIONS".equals(nullable(row.get("tool")))
                        &&"to_send".equals(nullable(row.get("phase")))).toList();
                expect(replays.size()==1,"HOST_REPLAY_CALLBACK_COUNT");int replayId=replays.getFirst().get("id").getAsInt();
                int originalId=originals.getFirst().get("id").getAsInt();expect(replayId!=originalId,"HOST_REPLAY_DISTINCT_IDENTITY");
                int status=kind.equals("RECOVERY")?200:401;
                expect(observed.stream().filter(row->"GLOBAL".equals(nullable(row.get("family")))&&"EXTENSIONS".equals(nullable(row.get("tool")))
                        &&"response_received".equals(nullable(row.get("phase")))&&row.get("id").getAsInt()==replayId
                        &&row.get("status").getAsInt()==status).count()==1,"HOST_REPLAY_CALLBACK_STATUS");
            }
        }
    }
    private static boolean listener(JsonObject event,int port) {
        String value=nullable(event.get("listener"));if(value==null)return false;int colon=value.lastIndexOf(':');
        return colon>0&&value.substring(colon+1).equals(Integer.toString(port));
    }
    private void checkForbidden() throws Check {
        for(String nonce:forbidDelivery)for(var owner:observedLeases) {
            var raw=LabJson.JSON.toJsonTree(owner.snapshot()).getAsJsonObject().getAsJsonObject("hostObservations").getAsJsonArray("received");
            expect(raw.asList().stream().noneMatch(row->nonce.equals(nullable(row.getAsJsonObject().getAsJsonObject("request").get("nonce")))),"HOST_STOPPED_REQUEST_DELIVERED");
        }
    }
    private int occurrences(LabRun.Phase phase) {
        return (int)server().getAsJsonArray("events").asList().stream().map(JsonElement::getAsJsonObject)
                .filter(row->phase.name().equals(nullable(row.get("phase")))&&"phase-entered".equals(nullable(row.get("name")))).count();
    }
    private void fault(LabRun.Phase phase,int occurrence,String kind,Integer status,String gate) throws Check {
        block(occurrence>0&&occurrence<=32,"HOST_FAULT_OCCURRENCE_LIMIT");
        lease.armRelativeFault(new LabRun.FaultSpec(phase,occurrence,kind,null,status,gate));
    }
    private void await(BooleanSupplier condition,Duration maximum,String code) throws Exception {
        long until=System.nanoTime()+budget(maximum).toNanos();
        while(System.nanoTime()<until){check();if(condition.getAsBoolean())return;Thread.sleep(25);}
        throw new Check(Outcome.BLOCKED,code);
    }
    private Duration budget(Duration maximum) throws Check {
        long left=deadline-System.nanoTime();block(left>0,"HOST_SCENARIO_DEADLINE");return Duration.ofNanos(Math.min(left,maximum.toNanos()));
    }
    private void check() throws Check,InterruptedException {
        if(Thread.currentThread().isInterrupted()||Files.exists(root.resolve("cancel")))throw new InterruptedException();
        block(System.nanoTime()<deadline,"HOST_SCENARIO_DEADLINE");
    }
    private static void expect(boolean value,String code) throws Check {if(!value)throw new Check(Outcome.FAIL,code);}
    private static void block(boolean value,String code) throws Check {if(!value)throw new Check(Outcome.BLOCKED,code);}
    private static String nullable(JsonElement value){return value==null||value.isJsonNull()?null:value.getAsString();}
    private static URI origin(URI uri){return URI.create(uri.getScheme()+"://"+uri.getRawAuthority());}
    private static JsonObject json(Object... fields) {
        var value=new JsonObject();for(int i=0;i<fields.length;i+=2)value.add((String)fields[i],LabJson.JSON.toJsonTree(fields[i+1]));return value;
    }
    private static final class Check extends Exception {
        final Outcome outcome;final String code;Check(Outcome outcome,String code){super(code);this.outcome=outcome;this.code=code;}
    }

    private String prefix(){return origin(run.applicationUri())+"/cases/"+CASE+"/protected/";}
    private static boolean tagged(Map<String,String> headers){return headers.values().stream().anyMatch(value->value.contains("<@"));}
    private static Map<String,String> formTags(String alias){return Map.of("Authorization","Bearer <@"+alias+" token=\"bearer\"/>","Cookie","LAB_C1=<@"+alias+" token=\"first\"/>");}
    private static Map<String,String> httpTag(String alias){return Map.of("BPSP-HTTP-AUTHENT","<@"+alias+"/>","Authorization","Bearer application");}
    private void onlyUrl(String pattern,boolean regex,boolean detect) throws Exception {
        configure(List.of(rule("host_a","SINGLE_URL",pattern,regex,null,detect)),true);
    }
    private void triple(boolean alternate,List<String> accounts) throws Exception {
        for(int i=0;i<3;i++)proxy(target(alternate,null),ports.get(i),accounts.get(i),accounts.get(i)==null?401:200,Map.of());
    }
    private void routing() throws Exception {
        measure("port-cold","COLD",()->{
            expect(occurrences(LabRun.Phase.LOGIN)==0,"HOST_COLD_PHASE_ALREADY_AUTHENTICATED");
            configure(List.of(rule("host_a","ALL_REQUESTS","",false,ports.get(0),false),
                    rule("host_b","ALL_REQUESTS","",false,ports.get(1),false)),true);
            var nonces=List.of(nonce(),nonce(),nonce());var pending=new ArrayList<CompletableFuture<HttpResponse<Void>>>();
            long[] dispatched=new long[3];
            URI same=target(false,null);
            for(int i=0;i<3;i++){dispatched[i]=System.currentTimeMillis();pending.add(sendAsync(ports.get(i),same,nonces.get(i),Map.of()));}
            for(int i=0;i<3;i++) {
                int status=pending.get(i).get(budget(Duration.ofSeconds(60)).toMillis(),TimeUnit.MILLISECONDS).statusCode();
                String account=i==0?"user":i==1?"user2":null;
                original(nonces.get(i),"PROXY",ports.get(i),"NORMAL",account,i==2?401:200,status);
                expect(status==(i==2?401:200),"HOST_ROUTING_COLD_STATUS");
                if(i==2)rejected(nonces.get(i),401,true);else accepted(nonces.get(i),account);
            }
            expect(occurrences(LabRun.Phase.LOGIN)==2,"HOST_ROUTING_COLD_LOGIN_COUNT");
            var admission=new JsonArray();var events=server().getAsJsonArray("events").asList().stream().map(JsonElement::getAsJsonObject)
                    .filter(event->"host-login-page-response-start".equals(nullable(event.get("name")))).toList();
            block(events.size()==2,"HOST_COLD_PAGE_OBSERVATION");
            for(int i=0;i<2;i++) {
                String alias=i==0?"host_a":"host_b";var matches=events.stream().filter(event->event.getAsJsonArray("safeIds").size()==1
                        &&"journey-alias".equals(nullable(event.getAsJsonArray("safeIds").get(0).getAsJsonObject().get("kind")))
                        &&alias.equals(nullable(event.getAsJsonArray("safeIds").get(0).getAsJsonObject().get("value")))).toList();
                block(matches.size()==1,"HOST_COLD_PAGE_OBSERVATION");var event=matches.getFirst();
                long observed=Instant.parse(event.get("time").getAsString()).toEpochMilli();block(observed>=dispatched[i],"HOST_COLD_PAGE_PREMATURE");
                admission.add(json("alias",alias,"nonce",nonces.get(i),"dispatchEpochMs",dispatched[i],"serverEventSequence",event.get("sequence").getAsLong(),
                        "elapsedMs",observed-dispatched[i],"boundary","CLIENT_DISPATCH_TO_LOGIN_PAGE_RESPONSE_START"));
            }
            measurement.add("browserAdmission",admission);
        });
        measure("port-warm","WARM",()->{
            triple(false,Arrays.asList("user","user2",null));triple(true,Arrays.asList("user","user2",null));
        });
        measure("url-prefix","WARM",()->{
            onlyUrl(prefix(),false,false);triple(false,List.of("user","user","user"));triple(true,Arrays.asList(null,null,null));
        });
        measure("url-and-port","WARM",()->{
            configure(List.of(rule("host_a","SINGLE_URL",prefix(),false,ports.get(0),false),
                    rule("host_b","SINGLE_URL",prefix(),false,ports.get(1),false)),true);
            triple(false,Arrays.asList("user","user2",null));triple(true,Arrays.asList(null,null,null));
        });
        measure("regex-substring","WARM",()->{
            onlyUrl(Pattern.quote(prefix()),true,false);
            proxy(target(false,null),ports.get(2),"user",200,Map.of());proxy(target(true,null),ports.get(2),null,401,Map.of());
        });
        measure("regex-case-miss","WARM",()->{
            onlyUrl(Pattern.quote(prefix().toLowerCase(Locale.ROOT)),true,false);
            proxy(target(false,null),ports.get(2),null,401,Map.of());
        });
        measure("regex-case-fold","WARM",()->{
            onlyUrl("(?i)"+Pattern.quote(prefix().toLowerCase(Locale.ROOT)),true,false);
            proxy(target(false,null),ports.get(2),"user",200,Map.of());
        });
        String anchored="^"+Pattern.quote(target(false,null).toString())+"(?:&host_probe=h[0-9a-f]{16})?$";
        measure("regex-anchor","WARM",()->{
            onlyUrl(anchored,true,false);proxy(target(false,null),ports.get(2),"user",200,Map.of());proxy(target(true,null),ports.get(2),null,401,Map.of());
        });
        measure("regex-anchor-miss","WARM",()->{
            onlyUrl("^"+Pattern.quote(prefix())+"never$",true,false);proxy(target(false,null),ports.get(2),null,401,Map.of());
        });
        measure("regex-invalid-retains","WARM",()->{
            onlyUrl(anchored,true,false);Path input=inputs.resolve("invalid-regex.json");LabJson.writeNew(input,json("mode","INVALID_REGEX","rule",1));
            ask(Operation.EDIT_RULES,json("path",relative(input)));ask(Operation.ASSERT_UI,json("alias","host_a","code","URL_REGEX_INVALID"));
            proxy(target(false,null),ports.get(2),"user",200,Map.of());proxy(target(true,null),ports.get(2),null,401,Map.of());
        });
    }
    private void tags() throws Exception {
        measure("proxy-explicit-a","WARM",()->{
            configure(List.of(rule("host_b","SINGLE_URL",prefix(),false,null,false)),true);
            proxy(target(false,null),ports.get(0),"user",200,formTags("host_a"));
        });
        measure("repeater-explicit-a","WARM",()->accepted(repeater(target(false,null),formTags("host_a"),"user",200,false),"user"));
        measure("repeater-unknown","WARM",()->{
            String nonce=nonce();Path raw=requestFile(target(false,null),nonce,formTags("host_missing"),false);
            ask(Operation.SET_REPEATER_REQUEST,json("path",relative(raw),"nonce",nonce));ask(Operation.SEND_REPEATER,json("nonce",nonce));
            original(nonce,"REPEATER",null,"TAGGED_STOP",null,null,null);quietAbsent(nonce,Duration.ofSeconds(2));forbidDelivery.add(nonce);
        });
        measure("proxy-unknown","WARM",()->{
            String nonce=nonce();Integer status=null;
            try{status=send(ports.get(0),target(false,nonce),nonce,formTags("host_missing"),false).statusCode();}
            catch(IOException closed){/* Native Proxy DROP may close the client connection; this is an observed outcome, not a retry. */}
            original(nonce,"PROXY",ports.get(0),"TAGGED_PROXY_BEST_EFFORT",null,null,status);
            quiet(Duration.ofSeconds(2));var received=rows(nonce);
            expect(received.size()<=1,"HOST_PROXY_FAILURE_DUPLICATE");
            if(!received.isEmpty()) {
                var row=received.getFirst();var shape=row.getAsJsonObject("request");
                expect(row.get("accountId").isJsonNull()&&shape.get("nativeTag").getAsBoolean()
                        &&shape.get("authorizationHeaders").getAsInt()==1&&shape.get("cookieHeaders").getAsInt()==1,
                        "HOST_PROXY_FAILURE_CHANGED_REQUEST");
            }
        });
    }
    private void repeater() throws Exception {
        measure("copied-ordinary","WARM",()->{
            configure(List.of(rule("host_a","ALL_REQUESTS","",false,ports.get(0),false)),true);
            String source=proxy(target(false,null),ports.get(0),"user",200,Map.of());
            measurement.getAsJsonArray("originals").get(0).getAsJsonObject().addProperty("kind","HISTORY_SEED");
            measurement.addProperty("copiedFromNonce",source);
            ask(Operation.COPY_TO_REPEATER,json("nonce",source));String copy=nonce();
            ask(Operation.SET_REPEATER_NONCE,json("previousNonce",source,"nonce",copy));ask(Operation.SEND_REPEATER,json("nonce",copy));
            var receipt=ask(Operation.ASSERT_REPEATER_RESPONSE,json("nonce",copy,"status",200));
            int status=receipt.getAsJsonObject("observed").get("status").getAsInt();
            original(copy,"REPEATER",null,"COPIED_ORDINARY","user",200,status);expect(status==200,"HOST_REPEATER_COPIED_STATUS");accepted(copy,"user");
        });
        measure("removed-port-only","WARM",()->rejected(repeater(target(false,null),Map.of(),null,401,false),401,true));
        measure("url-only","WARM",()->{
            onlyUrl(prefix(),false,false);accepted(repeater(target(false,null),Map.of(),"user",200,false),"user");
        });
        measure("explicit-tags","WARM",()->{
            configure(List.of(rule("host_b","SINGLE_URL",prefix(),false,null,false)),true);
            accepted(repeater(target(false,null),formTags("host_a"),"user",200,false),"user");
        });
    }
    private void httpAuth() throws Exception {
        configure(List.of(),false);
        for(String protocol:List.of("BASIC","NTLM_V1","NTLM_V2")) {
            String family=protocol.toLowerCase(Locale.ROOT),base="host_"+family;URI target=httpTargets.get(protocol);
            for(String suffix:List.of("a","b"))measure(family+"-test-"+suffix,"COLD",()->{
                JsonObject result=ask(Operation.TEST_LOGIN,json("alias",base+"_"+suffix));
                var observed=result.getAsJsonObject("observed");
                expect("HTTP_AUTHENTICATED".equals(nullable(observed.get("loginResult")))&&protocol.equals(nullable(observed.get("httpProtocol"))),"HOST_HTTP_UI_RESULT");
                measurement.add("uiTest",json("alias",base+"_"+suffix,"expectedProtocol",protocol,"expectedAccount","user-"+suffix,"guiSequence",result.get("sequence").getAsLong()));
                var delta=httpNewAccepted(protocol,measurement.getAsJsonObject("httpBefore"));
                expect(delta.size()==1&&("user-"+suffix).equals(nullable(delta.getFirst().get("user"))),"HOST_HTTP_UI_ACCOUNT");
            });
            String[] source={null};
            for(String suffix:List.of("a","b","a2"))measure(family+"-proxy-"+suffix,"WARM",()->{
                String account=suffix.equals("b")?"b":"a",nonce=nonce();URI uri=URI.create(target+"?host_probe="+nonce);
                var response=send(ports.get(2),uri,nonce,httpTag(base+"_"+account),true);
                original(nonce,"PROXY",ports.get(2),"HTTP_AUTH","user-"+account,200,response.statusCode()).addProperty("method","POST");
                expect(response.statusCode()==200,"HOST_HTTP_PROXY_STATUS");httpAccepted(protocol,nonce,"user-"+account);
                source[0]=nonce;
            });
            for(String suffix:List.of("a","b","a2"))measure(family+"-repeater-"+suffix,"WARM",()->{
                String account=suffix.equals("b")?"b":"a";
                if(suffix.equals("a")) {
                    block(source[0]!=null,"HOST_HTTP_HISTORY_SOURCE");measurement.addProperty("copiedFromNonce",source[0]);
                    ask(Operation.COPY_TO_REPEATER,json("nonce",source[0]));
                }
                String nonce=repeater(target,httpTag(base+"_"+account),"user-"+account,200,true);httpAccepted(protocol,nonce,"user-"+account);
            });
            if(!protocol.equals("BASIC")) {
                var observations=httpApplication(httpSnapshot(),protocol).getAsJsonArray("observations");
                var a=new HashSet<String>();var b=new HashSet<String>();
                for(var value:observations) {
                    var row=value.getAsJsonObject();String user=nullable(row.get("user"));
                    if("user-a".equals(user))a.add(row.get("connection").getAsString());else if("user-b".equals(user))b.add(row.get("connection").getAsString());
                }
                expect(Collections.disjoint(a,b),"HOST_HTTP_IDENTITY_CONNECTION_ISOLATION");
            }
        }
    }
    private JsonObject httpApplication(JsonObject snapshot,String protocol) throws Check {
        var matches=snapshot.getAsJsonArray("applications").asList().stream().map(JsonElement::getAsJsonObject)
                .filter(row->protocol.equals(nullable(row.get("protocol")))).toList();
        block(matches.size()==1,"HOST_HTTP_OBSERVATION_PROTOCOL");var app=matches.getFirst();
        block(!app.get("truncated").getAsBoolean(),"HOST_HTTP_OBSERVATION_OVERFLOW");return app;
    }
    private List<JsonObject> httpNewAccepted(String protocol,JsonObject before) throws Exception {
        JsonArray old=httpApplication(before,protocol).getAsJsonArray("observations");
        long previous=old.asList().stream().map(JsonElement::getAsJsonObject).mapToLong(row->row.get("operationId").getAsLong()).max().orElse(0);
        return httpApplication(httpSnapshot(),protocol).getAsJsonArray("observations").asList().stream().map(JsonElement::getAsJsonObject)
                .filter(row->row.get("operationId").getAsLong()>previous).toList();
    }
    private void httpAccepted(String protocol,String nonce,String account) throws Exception {
        final JsonObject[] observed={null};
        await(()->{
            try {observed[0]=httpApplication(httpSnapshot(),protocol);return observed[0].getAsJsonArray("observations").asList().stream()
                    .anyMatch(value->nonce.equals(nullable(value.getAsJsonObject().get("nonce"))));}
            catch(Exception unavailable){return false;}
        },Duration.ofSeconds(5),"HOST_HTTP_SERVER_OBSERVATION_MISSING");
        var app=observed[0];var accepted=app.getAsJsonArray("observations").asList().stream().map(JsonElement::getAsJsonObject)
                .filter(row->nonce.equals(nullable(row.get("nonce")))).toList();
        expect(accepted.size()==1,"HOST_HTTP_AUTHENTICATED_EXECUTION_COUNT");var row=accepted.getFirst();
        expect(account.equals(nullable(row.get("user")))&&protocol.equals(nullable(row.get("protocol")))
                &&"POST".equals(nullable(row.get("method")))&&row.get("bodyBytes").getAsInt()=="authlab-action".getBytes(StandardCharsets.UTF_8).length,
                "HOST_HTTP_AUTHENTICATED_ACCOUNT");
        var wire=app.getAsJsonArray("requests").asList().stream().map(JsonElement::getAsJsonObject).filter(item->nonce.equals(nullable(item.get("nonce")))).toList();
        expect(!wire.isEmpty()&&wire.stream().noneMatch(item->item.get("httpDirective").getAsBoolean()),"HOST_HTTP_DIRECTIVE_LEAK");
        var before=httpApplication(measurement.getAsJsonObject("httpBefore"),protocol);
        expect(app.get("posts").getAsLong()-before.get("posts").getAsLong()==1&&app.get("leakedDirectives").getAsLong()==before.get("leakedDirectives").getAsLong(),"HOST_HTTP_DUPLICATE_POST");
        block(app.has("applicationAuthorizations")&&before.has("applicationAuthorizations"),"HOST_HTTP_OVERRIDE_UNOBSERVABLE");
        expect(app.get("applicationAuthorizations").getAsLong()==before.get("applicationAuthorizations").getAsLong(),"HOST_HTTP_ORDINARY_AUTHORIZATION_FORWARDED");
    }
    private static Map<String,List<String>> subcases() {
        var result=new LinkedHashMap<String,List<String>>();
        result.put("routing",List.of("port-cold","port-warm","url-prefix","url-and-port","regex-substring","regex-case-miss",
                "regex-case-fold","regex-anchor","regex-anchor-miss","regex-invalid-retains"));
        result.put("tags",List.of("proxy-explicit-a","repeater-explicit-a","repeater-unknown","proxy-unknown"));
        result.put("repeater",List.of("copied-ordinary","removed-port-only","url-only","explicit-tags"));
        var http=new ArrayList<String>();
        for(String protocol:List.of("basic","ntlm_v1","ntlm_v2"))
            for(String action:List.of("test-a","test-b","proxy-a","proxy-b","proxy-a2","repeater-a","repeater-b","repeater-a2"))http.add(protocol+"-"+action);
        result.put("http-auth",List.copyOf(http));result.put("recovery",List.of("shared-two-originals"));
        result.put("rejected-replay",List.of("rejected-replay","paused-subsequent"));
        result.put("intercept",List.of("matching-to-alternate","alternate-to-matching"));
        result.put("unload",List.of("pending-unload","post-reload-fresh"));
        result.put("ordinary-failure",List.of("exhausted-login-unchanged"));
        return Collections.unmodifiableMap(result);
    }
    private String prime() throws Exception {
        onlyUrl(prefix(),false,true);
        String nonce=proxy(target(false,null),ports.get(0),"user",200,Map.of());
        measurement.getAsJsonArray("originals").get(measurement.getAsJsonArray("originals").size()-1).getAsJsonObject().addProperty("kind","PRIME");
        return single(nonce).get("issuanceId").getAsString();
    }
    private void hold(String gate,LabRun.Phase phase,int occurrence) throws Check {fault(phase,occurrence,"HOLD",null,gate);}
    private void reached(String gate) throws Exception {lease.awaitCheckpoint(gate,budget(Duration.ofSeconds(30)));}
    private void release(String... gates) {for(String gate:gates)try{lease.release(gate);}catch(RuntimeException unavailable){/* Owner cleanup still releases all remaining holds. */}}
    private int clientStatus(CompletableFuture<HttpResponse<Void>> pending) throws Exception {
        return pending.get(budget(Duration.ofSeconds(60)).toMillis(),TimeUnit.MILLISECONDS).statusCode();
    }
    private void replayRows(String nonce,int replayStatus,String issuance) throws Exception {
        await(()->rows(nonce).size()>=2&&rows(nonce).stream().allMatch(row->row.get("status").getAsInt()>0),Duration.ofSeconds(30),"HOST_REPLAY_MISSING");
        var received=rows(nonce);expect(received.size()==2,"HOST_REPLAY_EXECUTION_COUNT");
        var first=received.get(0);var replay=received.get(1);
        expect(first.get("sequence").getAsLong()<replay.get("sequence").getAsLong()&&first.get("status").getAsInt()==401
                &&first.get("accountId").isJsonNull()&&replay.get("status").getAsInt()==replayStatus,"HOST_REPLAY_SERVER_STATUS");
        if(replayStatus==200) {
            expect("user".equals(nullable(replay.get("accountId")))&&!issuance.equals(nullable(replay.get("issuanceId")))
                    &&nullable(replay.get("issuanceId"))!=null,"HOST_REPLAY_FRESH_ISSUANCE");
            expect(new HashSet<>(LabJson.strings(replay.get("roles"))).equals(Set.of("B","C1")),"HOST_REPLAY_ROLES");
        } else expect(replay.get("accountId").isJsonNull(),"HOST_REJECTED_REPLAY_ACCOUNT");
        for(var row:received) {
            var shape=row.getAsJsonObject("request");expect(shape.get("authorizationHeaders").getAsInt()==1&&shape.get("cookieHeaders").getAsInt()==1
                    &&shape.get("c1").getAsBoolean()&&!shape.get("c2").getAsBoolean()&&!shape.get("nativeTag").getAsBoolean()
                    &&!shape.get("httpDirective").getAsBoolean(),"HOST_REPLAY_CREDENTIAL_SHAPE");
        }
    }
    private void recovery() throws Exception {
        measure("shared-two-originals","WARM",()->{
            String issuance=prime(),login="recovery-login",first="recovery-original-one",second="recovery-original-two";
            int before=occurrences(LabRun.Phase.LOGIN);
            hold(login,LabRun.Phase.LOGIN,1);hold(first,LabRun.Phase.PROTECTED,1);hold(second,LabRun.Phase.PROTECTED,2);
            String a=nonce(),b=nonce();lease.revoke(issuance);
            var one=sendAsync(ports.get(0),target(false,a),a,Map.of());var two=sendAsync(ports.get(0),target(false,b),b,Map.of());
            try {
                reached(first);reached(second);release(first,second);
                int aStatus=clientStatus(one),bStatus=clientStatus(two);
                for(var item:List.of(original(a,"PROXY",ports.get(0),"RECOVERY",null,401,aStatus),
                        original(b,"PROXY",ports.get(0),"RECOVERY",null,401,bStatus))) {
                    item.addProperty("expectedReplayAccount","user");item.addProperty("expectedReplayStatus",200);
                }
                expect(aStatus==401&&bStatus==401,"HOST_RECOVERY_ORIGINAL_RESPONSE");
                reached(login);expect(occurrences(LabRun.Phase.LOGIN)==before+1,"HOST_RECOVERY_SHARED_LOGIN");release(login);
                replayRows(a,200,issuance);replayRows(b,200,issuance);
                expect(nullable(rows(a).get(1).get("issuanceId")).equals(nullable(rows(b).get(1).get("issuanceId"))),"HOST_RECOVERY_SHARED_ISSUANCE");
                quiet(Duration.ofSeconds(2));expect(rows(a).size()==2&&rows(b).size()==2&&occurrences(LabRun.Phase.LOGIN)==before+1,"HOST_RECOVERY_EXTRA_WORK");
            } finally {release(first,second,login);}
            measurement.addProperty("revokedIssuanceId",issuance);
        });
    }
    private void rejectedReplay() throws Exception {
        measure("rejected-replay","WARM",()->{
            String issuance=prime(),gate="rejected-login";int before=occurrences(LabRun.Phase.LOGIN);
            hold(gate,LabRun.Phase.LOGIN,1);lease.revoke(issuance);String nonce=nonce();
            try {
                int status=send(ports.get(0),target(false,nonce),nonce,Map.of(),false).statusCode();
                var original=original(nonce,"PROXY",ports.get(0),"REJECTED_REPLAY",null,401,status);
                original.add("expectedReplayAccount",JsonNull.INSTANCE);original.addProperty("expectedReplayStatus",401);
                expect(status==401,"HOST_REJECTED_ORIGINAL_STATUS");
                reached(gate);fault(LabRun.Phase.PROTECTED,1,"REJECT",null,null);release(gate);
                replayRows(nonce,401,issuance);ask(Operation.ASSERT_UI,json("alias","host_a","code","RECOVERY_PAUSED"));
                quiet(Duration.ofSeconds(2));expect(rows(nonce).size()==2&&occurrences(LabRun.Phase.LOGIN)==before+1,"HOST_REJECTED_RECURSIVE_RECOVERY");
            } finally {release(gate);}
            measurement.addProperty("revokedIssuanceId",issuance);
        });
        measure("paused-subsequent","WARM",()->{
            int before=occurrences(LabRun.Phase.LOGIN);String nonce=proxy(target(false,null),ports.get(0),null,401,Map.of());
            quiet(Duration.ofSeconds(2));expect(rows(nonce).size()==1&&occurrences(LabRun.Phase.LOGIN)==before,"HOST_PAUSED_RECOVERY_WORK");
            ask(Operation.ASSERT_UI,json("alias","host_a","code","RECOVERY_PAUSED"));
        });
    }
    private void reloadForm() throws Exception {
        ask(Operation.SET_PRODUCT_LOADED,json("enabled",false));ask(Operation.SET_PRODUCT_LOADED,json("enabled",true));
        ask(Operation.ENTER_SECRET,json("alias","host_a","secret","FORM_A"));ask(Operation.ENTER_SECRET,json("alias","host_b","secret","FORM_B"));
    }
    private void intercept() throws Exception {
        // Explicit reload resumes the journey paused by the preceding rejected-replay recipe.
        for(boolean matching:List.of(true,false))measure(matching?"matching-to-alternate":"alternate-to-matching","WARM",()->{
            String nonce=nonce();URI from=target(!matching,nonce),to=target(matching,nonce);
            ask(Operation.SET_INTERCEPT,json("enabled",true));CompletableFuture<HttpResponse<Void>> pending=null;
            try {
                pending=sendAsync(ports.get(0),from,nonce,Map.of());
                Path file=requestFile(to,nonce,Map.of(),false);
                String text=Files.readString(file,StandardCharsets.UTF_8);
                int end=text.indexOf(" HTTP/1.1");block(end>4,"HOST_INTERCEPT_REQUEST_SHAPE");
                Files.writeString(file,"GET "+to+text.substring(end),StandardCharsets.UTF_8,StandardOpenOption.TRUNCATE_EXISTING);
                ask(Operation.EDIT_INTERCEPTED_REQUEST,json("nonce",nonce,"path",relative(file)));
                ask(Operation.FORWARD_INTERCEPTED_REQUEST,json("nonce",nonce));
                // Browser login requests must also flow without requiring further human forwards.
                ask(Operation.SET_INTERCEPT,json("enabled",false));
                int status=clientStatus(pending),expected=matching?401:200;
                original(nonce,"PROXY",ports.get(0),"INTERCEPT_EDIT",matching?null:"user",expected,status);
                expect(status==expected,"HOST_INTERCEPT_CLIENT_STATUS");
                if(matching)rejected(nonce,401,true);else accepted(nonce,"user");
                expect(single(nonce).get("listenerPort").getAsInt()==to.getPort(),"HOST_INTERCEPT_FINAL_DESTINATION");
                measurement.addProperty("fromListenerPort",from.getPort());measurement.addProperty("toListenerPort",to.getPort());
            } finally {ask(Operation.SET_INTERCEPT,json("enabled",false));}
        });
    }
    private record Child(long pid,long started,String executableSha256) { }
    private ProcessHandle ownedBurp() throws Exception {
        var owner=LabJson.read(root.resolve("burp-owner.json"),4096);long pid=owner.get("pid").getAsLong(),started=owner.get("startedEpochMs").getAsLong();
        block(session.runNonce().toString().equals(owner.get("nonce").getAsString()),"HOST_CHILD_OWNER_NONCE");
        var process=ProcessHandle.of(pid).orElseThrow(()->new Check(Outcome.BLOCKED,"HOST_CHILD_OWNER_EXITED"));var info=process.info();
        block(info.startInstant().isPresent()&&info.startInstant().get().toEpochMilli()==started&&info.command().isPresent()
                &&Files.isSameFile(Path.of(info.command().get()),Path.of(owner.get("executable").getAsString())),"HOST_CHILD_OWNER_IDENTITY");
        return process;
    }
    private List<Child> productChildren() throws Exception {
        var result=new ArrayList<Child>();
        for(var process:ownedBurp().descendants().toList()) {
            var info=process.info();if(info.command().isEmpty()||info.startInstant().isEmpty())continue;
            Path executable=Path.of(info.command().get()).toRealPath();
            if(executable.startsWith(root))result.add(new Child(process.pid(),info.startInstant().get().toEpochMilli(),LabJson.sha256(executable)));
        }
        return List.copyOf(result);
    }
    private static boolean childAlive(Child child) {
        var process=ProcessHandle.of(child.pid());return process.isPresent()&&process.get().isAlive()
                &&process.get().info().startInstant().map(time->time.toEpochMilli()==child.started()).orElse(true);
    }
    private Set<String> issued() {
        var ids=new HashSet<String>();
        for(var event:server().getAsJsonArray("events"))for(var value:event.getAsJsonObject().getAsJsonArray("safeIds")) {
            var item=value.getAsJsonObject();if("issuance".equals(nullable(item.get("kind"))))ids.add(item.get("value").getAsString());
        }
        return ids;
    }
    private void unload() throws Exception {
        Set<String> before=new HashSet<>(issued());
        measure("pending-unload","COLD",()->{
            String gate="unload-login",nonce=nonce();hold(gate,LabRun.Phase.LOGIN,1);
            var pending=sendAsync(ports.get(0),target(false,nonce),nonce,Map.of());
            try {
                reached(gate);var children=productChildren();block(!children.isEmpty(),"HOST_PRODUCT_CHILD_UNOBSERVABLE");
                measurement.add("childrenBefore",LabJson.JSON.toJsonTree(children));
                ask(Operation.SET_PRODUCT_LOADED,json("enabled",false));release(gate);
                Integer status=null;try{status=clientStatus(pending);}catch(ExecutionException closed){/* Unload may close an original whose owner was cancelled. */}
                original(nonce,"PROXY",ports.get(0),"UNLOAD_PENDING",null,null,status);
                await(()->children.stream().noneMatch(LabHostScenarios::childAlive),Duration.ofSeconds(15),"HOST_PRODUCT_CHILD_STILL_RUNNING");
                measurement.add("childrenAfter",LabJson.JSON.toJsonTree(children.stream().map(child->json("pid",child.pid(),"started",child.started(),"alive",childAlive(child))).toList()));
                quiet(Duration.ofSeconds(2));var received=rows(nonce);expect(received.size()<=1,"HOST_UNLOAD_DUPLICATE_DELIVERY");
                if(!received.isEmpty())rejected(nonce,401,true);
                if(received.isEmpty())forbidDelivery.add(nonce);
                before.addAll(issued());measurement.add("issuedBeforeReload",LabJson.JSON.toJsonTree(before));
            } finally {release(gate);}
        });
        measure("post-reload-fresh","COLD",()->{
            ask(Operation.SET_PRODUCT_LOADED,json("enabled",true));
            ask(Operation.ENTER_SECRET,json("alias","host_a","secret","FORM_A"));ask(Operation.ENTER_SECRET,json("alias","host_b","secret","FORM_B"));
            onlyUrl(prefix(),false,false);int logins=occurrences(LabRun.Phase.LOGIN);
            String nonce=proxy(target(false,null),ports.get(0),"user",200,Map.of());String issuance=single(nonce).get("issuanceId").getAsString();
            expect(occurrences(LabRun.Phase.LOGIN)==logins+1&&!before.contains(issuance),"HOST_RELOAD_FRESH_LOGIN_REQUIRED");
            measurement.add("priorIssuanceIds",LabJson.JSON.toJsonTree(before));
        });
    }
    private void ordinaryFailure() throws Exception {
        try {measure("exhausted-login-unchanged","COLD",()->{
            String nonce=proxy(target(false,null),ports.get(0),null,401,Map.of("X-AuthLab-Sentinel","unchanged"));
            var row=single(nonce);var shape=row.getAsJsonObject("request");
            expect("GET".equals(nullable(shape.get("method")))&&"b_c1".equals(nullable(shape.get("route")))
                    &&shape.get("sentinel").getAsBoolean()&&shape.get("bodyBytes").getAsInt()==0,"HOST_FAILURE_ORIGINAL_CHANGED");
            int attempts=occurrences(LabRun.Phase.LOGIN);expect(attempts>=1&&attempts<=3&&issued().isEmpty(),"HOST_FAILURE_LOGIN_ATTEMPTS");
            ask(Operation.ASSERT_UI,json("alias","host_failure_a","code","LOGIN_FAILED"));quiet(Duration.ofSeconds(2));
            expect(rows(nonce).size()==1&&occurrences(LabRun.Phase.LOGIN)==attempts,"HOST_FAILURE_REPLAY_OR_RETRY");
            ask(Operation.ASSERT_UI,json("alias","host_failure_a","code","ORDINARY_UNCHANGED","nonce",nonce));
        });} finally {configure(List.of(),false);lease.close();}
    }
    private void quiet(Duration duration) throws Exception {
        long until=System.nanoTime()+budget(duration).toNanos();while(System.nanoTime()<until){check();Thread.sleep(25);}
    }
    private void quietAbsent(String nonce,Duration duration) throws Exception {
        long until=System.nanoTime()+budget(duration).toNanos();
        while(System.nanoTime()<until){check();expect(rows(nonce).isEmpty(),"HOST_STOPPED_REQUEST_DELIVERED");Thread.sleep(25);}
    }
}
