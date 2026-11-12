package lab.auth;

import com.google.gson.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.jar.JarFile;
import java.net.*;
import java.net.http.*;
import java.time.*;
import java.util.concurrent.TimeUnit;
import static lab.auth.LabJson.*;

/** Guest-local lab and Burp lifecycle. No fixture authentication is performed here. */
public final class LabHostGuest {
    private LabHostGuest() {}
    static final int COMPLETION_LIMIT=1_048_576, EVIDENCE_INDEX_LIMIT=2048;
    private static final int BURP_HEAP_MIB=2048;
    private static final String[] FIELDS = {"version","invocationId","mode","platform","runNonce","taskPath",
            "configurationHash","catalogRevision","sourceRevision","head","audit","product","helper","runtime","scenarios",
            "guestRoot","java","labJava","burpJar","approvedPreferences","display","stage"};
    /** Read-only lifecycle probe used by the coordinator when a completion receipt is missing. */
    public static void main(String[] args) {
        try {
            require(args.length==2&&args[0].equals("status"),"HOST_STATUS_ARGUMENTS");
            Path planPath=Path.of(args[1]).toRealPath();var plan=object(read(planPath,1_048_576),FIELDS);
            Path root=Path.of(text(plan,"guestRoot")).toRealPath();require(planPath.getParent().equals(root),"HOST_STATUS_ROOT");
            var owner=object(read(root.resolve("report/started.json"),4096),"version","invocationId","runNonce","pid","startedEpochMs","executable");
            require(uuid(owner.get("invocationId")).equals(uuid(plan.get("invocationId")))&&uuid(owner.get("runNonce")).equals(uuid(plan.get("runNonce"))),"HOST_STATUS_IDENTITY");
            long pid=positive(owner.get("pid"));var state=processStatus(pid,positive(owner.get("startedEpochMs")),text(owner,"executable"),"-Dlab.host.runNonce="+text(owner,"runNonce"));
            Files.writeString(root.resolve("status.json"),JSON.toJson(Map.of("version",1,"invocationId",text(owner,"invocationId"),
                    "runNonce",text(owner,"runNonce"),"pid",pid,"alive",state.alive(),"ownership",state.ownership())));
        }catch(IOException|RuntimeException failed){System.exit(3);}
    }
    record ProcessStatus(boolean alive,String ownership) {}
    static ProcessStatus processStatus(long pid,long started,String executable,String marker) {
        var process=ProcessHandle.of(pid);
        if(process.isEmpty()||!process.get().isAlive())return new ProcessStatus(false,"EXITED");
        var info=process.get().info();
        if(info.startInstant().isEmpty()||info.command().isEmpty())return new ProcessStatus(true,"UNVERIFIED");
        if(info.startInstant().get().toEpochMilli()!=started)return new ProcessStatus(true,"CHANGED");
        try {
            if(!Files.isSameFile(Path.of(executable),Path.of(info.command().get())))return new ProcessStatus(true,"CHANGED");
            return new ProcessStatus(true,markerVisible(info.arguments(),marker,()->windowsMarker(pid,marker))?"VERIFIED":"UNVERIFIED");
        }catch(IOException|RuntimeException unavailable){return new ProcessStatus(true,"UNVERIFIED");}
    }
    static boolean markerVisible(Optional<String[]> arguments,String marker,java.util.function.BooleanSupplier fallback) {
        return arguments.map(values->Arrays.asList(values).contains(marker)).orElse(false)||fallback.getAsBoolean();
    }
    static boolean owns(long pid,long started,String executable,String marker) {
        return processStatus(pid,started,executable,marker).ownership().equals("VERIFIED");
    }
    private static boolean windowsMarker(long pid,String marker) {
        if(!System.getProperty("os.name").startsWith("Windows")||!marker.matches("-Dlab\\.host\\.(?:runNonce|burpNonce)=[0-9a-f-]{36}"))return false;
        String script="$p=Get-CimInstance Win32_Process -Filter 'ProcessId="+pid+"' -ErrorAction SilentlyContinue;$pattern='(^|[\\s\"])'+[regex]::Escape('"+marker+"')+'($|[\\s\"])';if($p -and $p.CommandLine -match $pattern){[Console]::Write('OWNED')}else{[Console]::Write('OTHER')}";
        String encoded=Base64.getEncoder().encodeToString(script.getBytes(java.nio.charset.StandardCharsets.UTF_16LE));
        Process query=null;
        try {
            query=new ProcessBuilder("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","-NoProfile","-WindowStyle","Hidden","-EncodedCommand",encoded)
                    .redirectError(ProcessBuilder.Redirect.DISCARD).start();
            return query.waitFor(5,TimeUnit.SECONDS)&&query.exitValue()==0&&new String(query.getInputStream().readNBytes(64),java.nio.charset.StandardCharsets.UTF_8).equals("OWNED");
        }catch(InterruptedException stopped){Thread.currentThread().interrupt();return false;}
        catch(IOException unavailable){return false;}
        finally{if(query!=null&&query.isAlive())query.destroyForcibly();}
    }

    public static int run(Path planPath, Path report) throws IOException {
        var plan=object(read(planPath,1_048_576),FIELDS); LabHostInputs.version(plan);
        String platform=member(plan.get("platform"),"windows","linux"), nonce=uuid(plan.get("runNonce")).toString();
        UUID invocation=uuid(plan.get("invocationId"));
        member(plan.get("mode"),"ACCEPTANCE","QUALIFICATION"); member(plan.get("stage"),"PRIMITIVES","SCENARIOS");
        String expectedTask=text(plan,"mode").equals("ACCEPTANCE")?":authLabHostTest":":authLabHostQualify";
        require(text(plan,"taskPath").equals(expectedTask),"HOST_GUEST_TASK");
        hash(plan.get("configurationHash")); hash(plan.get("catalogRevision")); hash(plan.get("sourceRevision"));
        require(text(plan,"head").matches("[0-9a-f]{40}|[0-9a-f]{64}"),"HOST_HEAD");
        Path root=Path.of(text(plan,"guestRoot")).toRealPath();
        require(root.getFileName().toString().equals(invocation+"-"+nonce.substring(0,8))
                && planPath.toRealPath().getParent().equals(root) && report.toRealPath().equals(root.resolve("report")),"HOST_GUEST_OWNER");
        var owner=object(read(root.resolve("owner.json"),4096),"version","invocationId","platform","runNonce","guestRoot");
        require(positive(owner.get("version"))==1&&uuid(owner.get("invocationId")).equals(invocation)&&text(owner,"platform").equals(platform)
                &&uuid(owner.get("runNonce")).toString().equals(nonce)&&Path.of(text(owner,"guestRoot")).toRealPath().equals(root),"HOST_GUEST_OWNER");
        require(Objects.equals(System.getProperty("lab.host.runNonce"),nonce),"HOST_GUEST_PROCESS_OWNER");
        for(String key:List.of("audit","product","helper","scenarios")) verifyArtifact(plan.get(key),root,false);
        require(plan.get("runtime").isJsonArray(),"HOST_RUNTIME");
        var runtimeKeys=new HashSet<String>(); var roles=new HashSet<String>();
        for(var artifact:plan.getAsJsonArray("runtime")) {
            var value=verifyArtifact(artifact,root,true); String role=text(value,"role"); roles.add(role);
            require(runtimeKeys.add(role+":"+text(value,"path")),"HOST_DUPLICATE_RUNTIME");
        }
        require(roles.equals(Set.of("LAB","EXPORTER")),"HOST_RUNTIME_ROLES");
        for(String key:List.of("java","labJava","burpJar","approvedPreferences"))
            LabHostInputs.guestAbsolute(text(plan,key),platform);
        require(platform.equals("windows")?plan.get("display").isJsonNull():text(plan,"display").matches(":\\d{1,3}(?:\\.\\d)?"),"HOST_DISPLAY");
        String actualPlatform=System.getProperty("os.name").startsWith("Windows")?"windows":"linux";
        long began=System.currentTimeMillis();
        writeNew(report.resolve("started.json"),Map.of("version",1,"invocationId",invocation,"runNonce",nonce,
                "pid",ProcessHandle.current().pid(),"startedEpochMs",ProcessHandle.current().info().startInstant().orElseThrow().toEpochMilli(),
                "executable",ProcessHandle.current().info().command().orElseThrow()));
        LabHostCoordinator.PlatformResult result;
        if(!platform.equals(actualPlatform))result=LabHostCoordinator.PlatformResult.blocked(platform,"HOST_GUEST_OS");
        else if(Runtime.version().feature()<21)result=LabHostCoordinator.PlatformResult.blocked(platform,"HOST_GUEST_JAVA");
        else if(ModuleLayer.boot().findModule("jdk.httpserver").isEmpty())result=LabHostCoordinator.PlatformResult.blocked(platform,"HOST_LAB_JAVA_MODULE_MISSING");
        else if(!List.of("java","labJava","burpJar","approvedPreferences").stream().allMatch(key -> Files.isRegularFile(Path.of(text(plan,key)))))
            result=LabHostCoordinator.PlatformResult.blocked(platform,"HOST_GUEST_PREREQUISITE");
        else if(Files.exists(root.resolve("cancel")))result=new LabHostCoordinator.PlatformResult(platform,LabHostCoordinator.Outcome.INTERRUPTED,
                "HOST_CANCELLED",LabHostCoordinator.Cleanup.COMPLETE,true,Map.of());
        else {
            var spec=new LabRun.RunSpec(invocation,List.of("browser","http-auth"),ScenarioCatalog.load(),root.resolve("lab"),List.of(),60_000);
            try(var run=LabRun.startHost(spec)) {
                run.prepareCase("BROW.basic.json");
                Path helper=owned(root,text(object(plan.get("helper")),"path"));
                boolean backend;
                try(var jar=new JarFile(helper.toFile())) {
                    backend=jar.getManifest()!=null && "lab.auth.gui.HostGuiBootstrap".equals(jar.getManifest().getMainAttributes().getValue("Premain-Class"));
                }
                result=backend?qualifyGui(plan,root,report,run):LabHostCoordinator.PlatformResult.blocked(platform,"GUI_BACKEND_UNAVAILABLE");
            } catch(IOException|RuntimeException failure) {
                result=new LabHostCoordinator.PlatformResult(platform,LabHostCoordinator.Outcome.BLOCKED,"HOST_GUEST_LIFECYCLE_FAILED",
                        LabHostCoordinator.Cleanup.INCOMPLETE,true,Map.of());
            }
        }
        try {
            for(String key:List.of("audit","product","helper","scenarios"))verifyArtifact(plan.get(key),root,false);
            for(var artifact:plan.getAsJsonArray("runtime"))verifyArtifact(artifact,root,true);
        }catch(IOException|IllegalArgumentException changed){result=new LabHostCoordinator.PlatformResult(platform,LabHostCoordinator.Outcome.BLOCKED,
                "HOST_ARTIFACT_CHANGED",result.cleanup(),true,Map.of());}
        var terminal=new LinkedHashMap<String,Object>(); terminal.put("version",1); terminal.put("invocationId",invocation); terminal.put("platform",platform);
        terminal.put("runNonce",nonce); terminal.put("productSha256",text(object(plan.get("product")),"sha256"));
        terminal.put("helperSha256",text(object(plan.get("helper")),"sha256")); terminal.put("outcome",result.outcome()); terminal.put("code",result.code());
        terminal.put("cleanup",result.cleanup()); terminal.put("unattended",true); terminal.put("stage",text(plan,"stage"));
        terminal.put("scenarios",result.scenarios()); terminal.put("durationMs",Math.max(1,System.currentTimeMillis()-began));
        terminal.put("evidence",evidenceIndex(report));
        require(JSON.toJson(terminal).getBytes(java.nio.charset.StandardCharsets.UTF_8).length<=COMPLETION_LIMIT,"HOST_COMPLETION_SIZE");
        writeNew(report.resolve("completion.json"),terminal); return result.outcome()==LabHostCoordinator.Outcome.PASS&&result.cleanup()==LabHostCoordinator.Cleanup.COMPLETE?0:3;
    }
    private static LabHostCoordinator.PlatformResult qualifyGui(JsonObject plan,Path root,Path report,LabRun run) throws IOException {
        String platform=text(plan,"platform");Process burp=null;LabHostMemory memory=null;boolean cleaned=true;
        Map<String,LabHostCoordinator.Outcome> scenarios=Map.of();
        LabHostCoordinator.Outcome outcome=LabHostCoordinator.Outcome.BLOCKED;String code="GUI_PRIMITIVES_INCOMPLETE";
        try {
            if(!desktopReady(root,platform))return LabHostCoordinator.PlatformResult.blocked(platform,"HOST_DESKTOP_UNAVAILABLE");
            for(String part:List.of("home","tmp","data","preferences","native-exports","gui/commands","gui/receipts"))Files.createDirectories(root.resolve(part));
            writeNew(root.resolve("fixture-secrets.json"),ControlledApplication.hostFixtureSecrets());
            Files.copy(Path.of(text(plan,"approvedPreferences")),root.resolve("preferences/approved-preferences.json"));
            Path helper=owned(root,text(object(plan.get("helper")),"path")),product=owned(root,text(object(plan.get("product")),"path"));
            var session=new LabHostGuiProtocol.Session(uuid(plan.get("invocationId")),platform,uuid(plan.get("runNonce")),
                    text(object(plan.get("product")),"sha256"),text(object(plan.get("helper")),"sha256"),root);
            var identity=LabHostGuiProtocol.identity(session);identity.addProperty("root",root.toString());writeNew(root.resolve("gui-session.json"),identity);
            var listeners=new ArrayList<ServerSocket>();var ports=new ArrayList<Integer>();
            try {
                for(int i=0;i<3;i++){var listener=new ServerSocket();listener.bind(new InetSocketAddress("127.0.0.1",0));listeners.add(listener);ports.add(listener.getLocalPort());}
                var requestListeners=ports.stream().map(port->Map.of("listener_port",port,"listen_mode","loopback_only","certificate_mode","per_host","running",true)).toList();
                writeNew(root.resolve("project.json"),Map.of("proxy",Map.of("request_listeners",requestListeners)));
                var extensions=List.of(Map.of("extension_type","java","extension_file",helper.toString(),"name","Authentication lab host probe","loaded",true,"errors","ui","output","ui"),
                        Map.of("extension_type","java","extension_file",product.toString(),"name","Browser Powered Session Handler","loaded",true,"errors","ui","output","ui"));
                writeNew(root.resolve("user.json"),Map.of("user_options",Map.of("extender",Map.of("extensions",extensions,"settings",Map.of("automatically_reload_extensions_on_startup",true,"automatically_update_bapps_on_startup",false)))));
                int heapMiB=BURP_HEAP_MIB;long physicalMemoryMiB=physicalMemoryMiB(root,platform);
                var command=new ArrayList<>(List.of(text(plan,"java"),"-Xmx"+heapMiB+"m",
                        "-Xlog:gc+heap=info,gc+humongous=debug:file=gc-private.log:uptimemillis,level,tags:filecount=1,filesize=8M",
                        "-Dlab.host.gui.root="+root,"-Dlab.host.burpNonce="+session.runNonce(),
                        "-Dlab.host.preferences="+root.resolve("preferences"),"-Djava.util.prefs.PreferencesFactory=lab.auth.gui.HostGuiPreferences",
                        "-Djava.io.tmpdir="+root.resolve("tmp"),"-Duser.home="+root.resolve("home"),"-javaagent:"+helper+"="+root,"-jar",text(plan,"burpJar"),
                        "--use-defaults","--disable-auto-update","--user-config-file="+root.resolve("user.json"),"--config-file="+root.resolve("project.json"),"--data-dir="+root.resolve("data")));
                for(var listener:listeners)listener.close();
                var builder=new ProcessBuilder(command).directory(root.toFile()).redirectOutput(root.resolve("burp-private-out.txt").toFile()).redirectError(root.resolve("burp-private-error.txt").toFile());
                if(platform.equals("linux"))builder.environment().put("DISPLAY",text(plan,"display"));
                burp=builder.start();
                writeNew(root.resolve("burp-owner.json"),Map.of("pid",burp.pid(),"nonce",session.runNonce(),"executable",text(plan,"java"),
                        "startedEpochMs",burp.info().startInstant().orElseThrow().toEpochMilli()));
                memory=LabHostMemory.start(burp,root,platform);
                var peer=new GuiPeer(session,report,burp);
                peer.ask(LabHostGuiProtocol.Operation.READY,new JsonObject(),Duration.ofSeconds(180));
                Process ownedBurp=burp;
                var probe=awaitMetadata(root.resolve("probe-ready.json"),Duration.ofSeconds(30),ownedBurp::isAlive,
                        ()->Files.exists(root.resolve("cancel")));
                long actualMaxHeapBytes=verifyProbeMetadata(probe,session,burp.pid(),burp.info().startInstant().orElseThrow().toEpochMilli(),ports);
                verifyListeners(root,burp.pid(),ports,platform);
                writeNew(report.resolve("environment.json"),Map.ofEntries(Map.entry("version",1),Map.entry("burpVersion",text(probe,"burpVersion")),Map.entry("javaVersion",text(probe,"javaVersion")),Map.entry("labJavaVersion",System.getProperty("java.version")),
                        Map.entry("os",System.getProperty("os.name")),Map.entry("maxBurpHeapMiB",heapMiB),Map.entry("physicalMemoryMiB",physicalMemoryMiB),Map.entry("listeners",ports),Map.entry("adapter","JDK_AWT_ROBOT_V1"),
                        Map.entry("burpPid",burp.pid()),Map.entry("burpStartedEpochMs",burp.info().startInstant().orElseThrow().toEpochMilli()),Map.entry("actualMaxHeapBytes",actualMaxHeapBytes)));
                for(String tool:List.of("REPEATER","PROXY","EXTENSIONS"))peer.ask(LabHostGuiProtocol.Operation.OPEN_TOOL,arguments("tool",tool),Duration.ofSeconds(30));
                peer.ask(LabHostGuiProtocol.Operation.SET_INTERCEPT,arguments("enabled",false),Duration.ofSeconds(30));
                for(int cycle=0;cycle<5;cycle++) {
                    peer.ask(LabHostGuiProtocol.Operation.SET_PRODUCT_LOADED,arguments("enabled",false),Duration.ofSeconds(30));
                    peer.ask(LabHostGuiProtocol.Operation.SET_PRODUCT_LOADED,arguments("enabled",true),Duration.ofSeconds(30));
                }
                if(text(plan,"stage").equals("SCENARIOS")) {
                    var runner=new LabHostScenarios(session,run,root,report,ports,peer::ask,
                            (prefix,output)->prepareExports(plan,root,run,output,prefix));
                    scenarios=runner.run();
                    var setup=LabHostGuiProtocol.identity(session);setup.add("setup",runner.setupEvidence());
                    require(JSON.toJson(setup).getBytes(java.nio.charset.StandardCharsets.UTF_8).length<=1_048_576,"HOST_SETUP_SIZE");
                    writeNew(report.resolve("scenario-setup.json"),setup);
                    outcome=scenarioOutcome(scenarios);code=outcome==LabHostCoordinator.Outcome.PASS?"HOST_SCENARIOS_VERIFIED":"HOST_SCENARIOS_INCOMPLETE";
                } else {
                prepareExports(plan,root,run,root.resolve("native-exports"),null);
                var imported=arguments("path","native-exports/native-examples/BROW.basic.json.json");imported.addProperty("alias","lab_brow_basic_json");
                peer.ask(LabHostGuiProtocol.Operation.IMPORT_JOURNEY,imported,Duration.ofSeconds(30));
                String requestNonce="h"+UUID.randomUUID().toString().replace("-","").substring(0,16);
                URI target=URI.create(run.cases().stream().filter(c->c.id().equals("BROW.basic.json")).findFirst().orElseThrow().endpoint("protected/b_c1")+"&host_probe="+requestNonce);
                try(var client=HttpClient.newBuilder().proxy(new ProxySelector(){
                    @Override public List<Proxy> select(URI uri){return List.of(new Proxy(Proxy.Type.HTTP,new InetSocketAddress("127.0.0.1",ports.getFirst())));}
                    @Override public void connectFailed(URI uri,SocketAddress sa,IOException e){}
                }).connectTimeout(Duration.ofSeconds(5)).build()) {
                    var response=client.send(HttpRequest.newBuilder(target).timeout(Duration.ofSeconds(30)).header("X-AuthLab-Request",requestNonce).GET().build(),HttpResponse.BodyHandlers.discarding());
                    require(response.statusCode()==401,"HOST_PRIMITIVE_SEED_RESPONSE");
                    peer.ask(LabHostGuiProtocol.Operation.COPY_TO_REPEATER,arguments("nonce",requestNonce),Duration.ofSeconds(30));
                    String raw="GET "+target.getRawPath()+"?"+target.getRawQuery()+" HTTP/1.1\r\nHost: "+target.getRawAuthority()+"\r\nX-AuthLab-Request: "+requestNonce+"\r\n\r\n";
                    Files.writeString(root.resolve("repeater-request.txt"),raw);
                    var edit=arguments("nonce",requestNonce);edit.addProperty("path","repeater-request.txt");
                    peer.ask(LabHostGuiProtocol.Operation.SET_REPEATER_REQUEST,edit,Duration.ofSeconds(30));
                    peer.ask(LabHostGuiProtocol.Operation.SEND_REPEATER,arguments("nonce",requestNonce),Duration.ofSeconds(30));
                    peer.ask(LabHostGuiProtocol.Operation.SET_INTERCEPT,arguments("enabled",true),Duration.ofSeconds(30));
                    String interceptNonce="h"+UUID.randomUUID().toString().replace("-","").substring(0,16);
                    URI intercepted=URI.create(target.toString().replace(requestNonce,interceptNonce));
                    var pending=client.sendAsync(HttpRequest.newBuilder(intercepted).timeout(Duration.ofSeconds(60)).header("X-AuthLab-Request",interceptNonce).GET().build(),HttpResponse.BodyHandlers.discarding());
                    String interceptedRaw=raw.replace(requestNonce,interceptNonce);Files.writeString(root.resolve("intercept-request.txt"),interceptedRaw);
                    var interception=arguments("nonce",interceptNonce);interception.addProperty("path","intercept-request.txt");
                    peer.ask(LabHostGuiProtocol.Operation.EDIT_INTERCEPTED_REQUEST,interception,Duration.ofSeconds(30));
                    peer.ask(LabHostGuiProtocol.Operation.FORWARD_INTERCEPTED_REQUEST,arguments("nonce",interceptNonce),Duration.ofSeconds(30));
                    require(pending.get(30,TimeUnit.SECONDS).statusCode()==401,"HOST_PRIMITIVE_FORWARD_RESPONSE");
                    peer.ask(LabHostGuiProtocol.Operation.SET_INTERCEPT,arguments("enabled",false),Duration.ofSeconds(30));
                }
                outcome=LabHostCoordinator.Outcome.PASS;code="GUI_PRIMITIVES_QUALIFIED";
                }
                memory.close();
                if(!peer.broken)peer.ask(LabHostGuiProtocol.Operation.CLOSE,new JsonObject(),Duration.ofSeconds(30));
            }finally{for(var listener:listeners)try{listener.close();}catch(IOException ignored){}}
        }catch(InterruptedException stopped){Thread.currentThread().interrupt();outcome=LabHostCoordinator.Outcome.INTERRUPTED;code="HOST_CANCELLED";}
        catch(Exception failed){outcome=LabHostCoordinator.Outcome.BLOCKED;
            code=failed.getMessage()!=null&&Set.of("HOST_PROBE_NOT_READY","HOST_VENDOR_NOT_QUALIFIED","HOST_LISTENER_QUERY","HOST_LISTENER_OWNERSHIP","HOST_LISTENER_CONFIGURATION",
                    "HOST_GUI_OPERATION_FAILED","HOST_GUI_RECEIPT_DEADLINE","HOST_BURP_EXITED","HOST_NATIVE_EXPORT_FAILED","HOST_PROBE_IDENTITY","HOST_HEAP_BUDGET",
                    "HOST_PRIMITIVE_SEED_RESPONSE","HOST_PRIMITIVE_FORWARD_RESPONSE").contains(failed.getMessage())
                    ?failed.getMessage():"GUI_PRIMITIVES_INCOMPLETE";}
        finally {
            try{Files.writeString(root.resolve("cancel"),"");}catch(IOException unavailable){cleaned=false;}
            JsonObject memoryProof=null;
            if(memory!=null)try {
                memory.close();cleaned&=memory.stopped();var summary=memory.summary();
                var proof=LabHostGuiProtocol.identity(new LabHostGuiProtocol.Session(uuid(plan.get("invocationId")),platform,uuid(plan.get("runNonce")),
                        text(object(plan.get("product")),"sha256"),text(object(plan.get("helper")),"sha256"),root));
                summary.entrySet().forEach(entry->proof.add(entry.getKey(),entry.getValue()));memoryProof=proof;
                if(!summary.get("complete").getAsBoolean()&&outcome==LabHostCoordinator.Outcome.PASS){outcome=LabHostCoordinator.Outcome.BLOCKED;code="HOST_MEMORY_OBSERVATION_INCOMPLETE";}
            }catch(RuntimeException unavailable){cleaned=false;outcome=LabHostCoordinator.Outcome.BLOCKED;code="HOST_MEMORY_OBSERVATION_INCOMPLETE";}
            if(burp!=null){boolean stopped=stopOwned(burp);cleaned&=stopped;}
            if(memoryProof!=null)try {
                var gc=LabHostMemory.gcSummary(root);memoryProof.add("gc",gc);writeNew(report.resolve("memory.json"),memoryProof);
                if(!gc.get("complete").getAsBoolean()&&outcome==LabHostCoordinator.Outcome.PASS){outcome=LabHostCoordinator.Outcome.BLOCKED;code="HOST_MEMORY_OBSERVATION_INCOMPLETE";}
            }catch(IOException|RuntimeException unavailable){cleaned=false;outcome=LabHostCoordinator.Outcome.BLOCKED;code="HOST_MEMORY_OBSERVATION_INCOMPLETE";}
        }
        return new LabHostCoordinator.PlatformResult(platform,outcome,code,cleaned?LabHostCoordinator.Cleanup.COMPLETE:LabHostCoordinator.Cleanup.INCOMPLETE,true,scenarios);
    }
    static long verifyProbeMetadata(JsonObject probe,LabHostGuiProtocol.Session session,long pid,long started,List<Integer> ports) {
        object(probe,"version","invocationId","platform","runNonce","productSha256","helperSha256","burpVersion","javaVersion","os","listenerPorts","pid","startedEpochMs","maxHeapBytes");
        for(var entry:LabHostGuiProtocol.identity(session).entrySet())require(entry.getValue().equals(probe.get(entry.getKey())),"HOST_PROBE_IDENTITY");
        require(positive(probe.get("pid"))==pid&&positive(probe.get("startedEpochMs"))==started,"HOST_PROBE_IDENTITY");
        require(java.util.regex.Pattern.compile("(?<![0-9.])2026\\.10\\.1(?![A-Za-z0-9.])").matcher(text(probe,"burpVersion")).find()
                &&text(probe,"javaVersion").equals("26.0.2"),"HOST_VENDOR_NOT_QUALIFIED");
        require(text(probe,"os").matches(session.platform().equals("windows")?"Windows.*":"Linux"),"HOST_PROBE_IDENTITY");
        require(probe.get("listenerPorts").isJsonArray(),"HOST_LISTENER_CONFIGURATION");
        var observed=probe.getAsJsonArray("listenerPorts").asList().stream().map(value->Math.toIntExact(positive(value))).toList();
        require(observed.size()==ports.size()&&new HashSet<>(observed).equals(new HashSet<>(ports)),"HOST_LISTENER_CONFIGURATION");
        long heap=positive(probe.get("maxHeapBytes"));require(heap==((long)BURP_HEAP_MIB<<20),"HOST_HEAP_BUDGET");return heap;
    }
    /** A visible suite frame can precede asynchronous extension loading and its receipt publication. */
    static JsonObject awaitMetadata(Path path,Duration timeout,java.util.function.BooleanSupplier alive,
                                    java.util.function.BooleanSupplier cancelled) throws InterruptedException {
        long deadline=System.nanoTime()+timeout.toNanos();
        while(System.nanoTime()<deadline) {
            if(cancelled.getAsBoolean()||Thread.currentThread().isInterrupted())throw new InterruptedException();
            require(alive.getAsBoolean(),"HOST_PROBE_NOT_READY");
            if(Files.isRegularFile(path))try{return read(path,65536);}
            catch(IOException|IllegalArgumentException notPublished){/* A writer may still be closing its bounded receipt. */}
            Thread.sleep(50);
        }
        throw invalid("HOST_PROBE_NOT_READY");
    }
    private static JsonObject arguments(String key,Object value){var json=new JsonObject();if(value instanceof Boolean b)json.addProperty(key,b);else json.addProperty(key,value.toString());return json;}
    static LabHostCoordinator.Outcome scenarioOutcome(Map<String,LabHostCoordinator.Outcome> scenarios) {
        if(!scenarios.keySet().equals(new HashSet<>(LabHostInputs.SCENARIOS))||scenarios.values().stream().anyMatch(Objects::isNull))return LabHostCoordinator.Outcome.BLOCKED;
        for(var outcome:List.of(LabHostCoordinator.Outcome.INTERRUPTED,LabHostCoordinator.Outcome.FAIL,LabHostCoordinator.Outcome.BLOCKED))
            if(scenarios.containsValue(outcome))return outcome;
        return LabHostCoordinator.Outcome.PASS;
    }
    static int evidenceSizeLimit(String name) {
        if(name.matches("gui-[0-9]{3,6}\\.json|environment\\.json|memory\\.json|started\\.json|burp-exit\\.json"))return 65536;
        if(name.equals("scenario-setup.json"))return 1_048_576;
        for(String scenario:LabHostInputs.SCENARIOS)if(name.equals("scenario-"+scenario+".json"))return 16*1024*1024;
        return -1;
    }
    static JsonArray evidenceIndex(Path report) throws IOException {
        Path owner=report.toRealPath();var evidence=new JsonArray();
        try(var entries=Files.list(report)) {
            var files=entries.filter(path->evidenceSizeLimit(path.getFileName().toString())>0).sorted().limit(EVIDENCE_INDEX_LIMIT+1).toList();
            require(files.size()<=EVIDENCE_INDEX_LIMIT,"HOST_EVIDENCE_INDEX");
            for(Path file:files) {
                String name=file.getFileName().toString();long bytes=Files.size(file);
                require(Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)&&file.toRealPath().getParent().equals(owner),"HOST_EVIDENCE_OWNER");
                require(bytes>0&&bytes<=evidenceSizeLimit(name),"HOST_EVIDENCE_SIZE");
                var entry=new JsonObject();entry.addProperty("path",name);entry.addProperty("sha256",sha256(file));entry.addProperty("bytes",bytes);evidence.add(entry);
            }
        }
        return evidence;
    }
    static void validateEvidenceIndex(JsonArray evidence) {
        require(evidence.size()<=EVIDENCE_INDEX_LIMIT,"HOST_EVIDENCE_INDEX");var paths=new HashSet<String>();
        for(var entry:evidence) {
            var file=object(entry,"path","sha256","bytes");String path=relative(file.get("path"));int limit=evidenceSizeLimit(path);
            require(limit>0&&paths.add(path)&&positive(file.get("bytes"))<=limit,"HOST_EVIDENCE_FILE");hash(file.get("sha256"));
        }
        require(paths.contains("started.json"),"HOST_EVIDENCE_START");
    }
    private static void prepareExports(JsonObject plan,Path root,LabRun run,Path output,String prefix) throws Exception {
        require(prefix==null||Set.of("host","host_failure").contains(prefix),"HOST_EXPORT_PREFIX");
        require(Files.isDirectory(output,LinkOption.NOFOLLOW_LINKS)&&output.toRealPath().getParent().equals(root),"HOST_EXPORT_DIRECTORY");
        String classpath=plan.getAsJsonArray("runtime").asList().stream().map(JsonElement::getAsJsonObject).filter(a->text(a,"role").equals("EXPORTER"))
                .map(a->root.resolve(text(a,"path")).toString()).collect(java.util.stream.Collectors.joining(File.pathSeparator));
        var specification=new LinkedHashMap<String,Object>();specification.put("liveRunId",run.runId());
        specification.put("liveRunsRoot",root.resolve("lab").toString());specification.put("reportDirectory",output.toRealPath().toString());
        if(prefix!=null){specification.put("mode","HOST");specification.put("hostAliasPrefix",prefix);}
        Path exportPlan=root.resolve("export-"+(prefix==null?"primitives":prefix)+".json");writeNew(exportPlan,specification);
        var process=new ProcessBuilder(text(plan,"labJava"),"-Xmx256m","-XX:ActiveProcessorCount=2","-Dauthlab.plan="+exportPlan,"-classpath",classpath,"bpsh.support.ProductionLabExamples")
                .redirectOutput(output.resolve("export-private-out.txt").toFile()).redirectError(output.resolve("export-private-error.txt").toFile()).start();
        try{
            require(process.waitFor(30,TimeUnit.SECONDS)&&process.exitValue()==0,"HOST_NATIVE_EXPORT_FAILED");
            var completion=object(read(output.resolve("native-examples-completion.json"),65536),"runId","generation","files","authenticationExecuted");
            require(uuid(completion.get("runId")).equals(run.runId())&&positive(completion.get("generation"))==run.generation()
                    &&completion.get("authenticationExecuted").isJsonPrimitive()&&completion.get("authenticationExecuted").getAsJsonPrimitive().isBoolean()
                    &&!completion.get("authenticationExecuted").getAsBoolean(),"HOST_NATIVE_EXPORT_IDENTITY");
        }
        finally{if(process.isAlive())stopOwned(process);}
    }
    private static boolean stopOwned(Process process) {
        boolean interrupted=Thread.interrupted();
        try {
            var children=process.descendants().map(p->Map.entry(p,p.info().startInstant())).toList();
            process.destroy();
            try{process.waitFor(5,TimeUnit.SECONDS);}catch(InterruptedException stopped){interrupted=true;}
            for(var child:children)if(child.getValue().isPresent()&&child.getKey().info().startInstant().equals(child.getValue()))child.getKey().destroyForcibly();
            if(process.isAlive())process.destroyForcibly();
            try{return process.waitFor(5,TimeUnit.SECONDS)&&children.stream().noneMatch(p->p.getKey().isAlive());}
            catch(InterruptedException stopped){interrupted=true;return false;}
        }finally{if(interrupted)Thread.currentThread().interrupt();}
    }
    private static void verifyListeners(Path root,long pid,List<Integer> ports,String platform) throws Exception {
        if(platform.equals("windows")) {
            String script="$rows=@(Get-NetTCPConnection -State Listen -OwningProcess "+pid+" -ErrorAction SilentlyContinue|Where-Object {$_.LocalAddress -in @('127.0.0.1','::1','::ffff:127.0.0.1')}|Select-Object -ExpandProperty LocalPort);ConvertTo-Json -InputObject $rows";
            String encoded=Base64.getEncoder().encodeToString(script.getBytes(java.nio.charset.StandardCharsets.UTF_16LE));
            var process=new ProcessBuilder("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","-NoProfile","-WindowStyle","Hidden","-EncodedCommand",encoded)
                    .redirectOutput(root.resolve("listener-ports.json").toFile()).redirectError(ProcessBuilder.Redirect.DISCARD).start();
            try{require(process.waitFor(10,TimeUnit.SECONDS)&&process.exitValue()==0,"HOST_LISTENER_QUERY");}finally{if(process.isAlive())stopOwned(process);}
            var values=LabJson.parse(Files.readAllBytes(root.resolve("listener-ports.json"))).getAsJsonArray().asList().stream().map(JsonElement::getAsInt).toList();
            require(values.containsAll(ports),"HOST_LISTENER_OWNERSHIP");
        }else {
            var sockets=new HashSet<String>();
            try(var entries=Files.list(Path.of("/proc",Long.toString(pid),"fd"))){for(Path entry:entries.toList())try{String link=Files.readSymbolicLink(entry).toString();if(link.startsWith("socket:["))sockets.add(link.substring(8,link.length()-1));}catch(IOException ignored){}}
            var bound=new HashSet<Integer>();
            for(String table:List.of("/proc/net/tcp","/proc/net/tcp6"))for(String line:Files.readAllLines(Path.of(table))) {
                String[] parts=line.trim().split("\\s+");if(parts.length>9&&parts[3].equals("0A")&&sockets.contains(parts[9])) {
                    String[] address=parts[1].split(":");if(Set.of("0100007F","0000000000000000FFFF00000100007F","00000000000000000000000001000000").contains(address[0]))bound.add(Integer.parseInt(address[1],16));
                }
            }
            require(bound.containsAll(ports),"HOST_LISTENER_OWNERSHIP");
        }
    }
    private static boolean desktopReady(Path root,String platform) throws Exception {
        if(platform.equals("windows")) {
            String script="Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class AuthLabDesktop{[DllImport(\"user32.dll\")]public static extern IntPtr OpenInputDesktop(uint a,bool b,uint c);[DllImport(\"user32.dll\")]public static extern bool CloseDesktop(IntPtr h);}';$h=[AuthLabDesktop]::OpenInputDesktop(0,$false,257);if($h -eq [IntPtr]::Zero){Write-Output 'LOCKED'}else{[AuthLabDesktop]::CloseDesktop($h)|Out-Null;Write-Output 'READY'}";
            String encoded=Base64.getEncoder().encodeToString(script.getBytes(java.nio.charset.StandardCharsets.UTF_16LE));
            String status=probe(root,"desktop-status.txt",List.of("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","-NoProfile","-WindowStyle","Hidden","-EncodedCommand",encoded));
            return status.equals("READY");
        }
        String seat=probe(root,"desktop-session.txt",List.of("/usr/bin/loginctl","show-seat","seat0","-p","ActiveSession","--value"));
        if(seat.isEmpty()) {
            // This provisioned VM runs Openbox on its real Xorg console without a logind seat session.
            String check=probe(root,"desktop-wm-check.txt",List.of("/usr/bin/xprop","-root","_NET_SUPPORTING_WM_CHECK"));
            var window=openboxWindowId(check);if(window.isEmpty())return false;
            String name=probe(root,"desktop-wm-name.txt",List.of("/usr/bin/xprop","-id",window.get(),"_NET_WM_NAME"));
            return name.equals("_NET_WM_NAME(UTF8_STRING) = \"Openbox\"");
        }
        if(!seat.matches("[A-Za-z0-9_.:-]{1,40}"))return false;
        return probe(root,"desktop-status.txt",List.of("/usr/bin/loginctl","show-session",seat,"-p","LockedHint","--value")).equals("no");
    }
    static Optional<String> openboxWindowId(String check) {
        var match=java.util.regex.Pattern.compile("_NET_SUPPORTING_WM_CHECK\\(WINDOW\\): window id # (0x[0-9a-fA-F]{1,16})").matcher(check);
        return match.matches()&&!match.group(1).matches("0x0+")?Optional.of(match.group(1)):Optional.empty();
    }
    private static String probe(Path root,String name,List<String> arguments) throws Exception {
        Path output=root.resolve(name);var process=new ProcessBuilder(arguments).redirectOutput(output.toFile()).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        try{require(process.waitFor(10,TimeUnit.SECONDS)&&process.exitValue()==0,"HOST_DESKTOP_QUERY");require(Files.size(output)<=4096,"HOST_DESKTOP_QUERY_SIZE");return Files.readString(output).trim();}
        finally{if(process.isAlive())stopOwned(process);}
    }
    private static long physicalMemoryMiB(Path root,String platform) throws Exception {
        String kib;
        if(platform.equals("linux")) {
            kib=Files.readAllLines(Path.of("/proc/meminfo")).stream().filter(line->line.startsWith("MemTotal:"))
                    .map(line->line.substring("MemTotal:".length()).trim().replaceFirst("\\s+kB$","")).findFirst().orElseThrow();
        }else {
            String script="[Console]::Write((Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize)";
            String encoded=Base64.getEncoder().encodeToString(script.getBytes(java.nio.charset.StandardCharsets.UTF_16LE));
            kib=probe(root,"physical-memory.txt",List.of("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","-NoProfile","-WindowStyle","Hidden","-EncodedCommand",encoded));
        }
        require(kib.matches("[0-9]{1,12}"),"HOST_MEMORY_QUERY");long mib=Long.parseLong(kib)/1024;
        require(mib>BURP_HEAP_MIB,"HOST_MEMORY_BUDGET");return mib;
    }
    static final class GuiPeer {
        final LabHostGuiProtocol.Session session;final Path report;final Process burp;long sequence;private boolean broken;
        GuiPeer(LabHostGuiProtocol.Session session,Path report,Process burp){this.session=session;this.report=report;this.burp=burp;}
        JsonObject ask(LabHostGuiProtocol.Operation operation,JsonObject arguments,Duration timeout) throws Exception {
            require(!broken,"HOST_GUI_CHANNEL_BROKEN");
            try {
            var command=new LabHostGuiProtocol.Command(++sequence,UUID.randomUUID(),operation,System.currentTimeMillis()+timeout.toMillis(),arguments);
            Path temporary=session.root().resolve("gui/commands/"+sequence+".tmp");writeNew(temporary,LabHostGuiProtocol.encode(session,command));
            Files.move(temporary,session.root().resolve(String.format(Locale.ROOT,"gui/commands/%06d.json",sequence)),StandardCopyOption.ATOMIC_MOVE);
            Path receipt=session.root().resolve("gui/receipts/"+command.operationId()+".json");
            // Input still expires at the command deadline. Allow only failure diagnostics to finish publishing.
            while(System.currentTimeMillis()<command.deadlineEpochMs()+2_000) {
                if(Files.exists(session.root().resolve("cancel"))||Thread.currentThread().isInterrupted())throw new InterruptedException();
                if(Files.isRegularFile(receipt)) {
                    var value=LabHostGuiProtocol.validateReceipt(read(receipt,65536),session,command);
                    writeNew(report.resolve(String.format(Locale.ROOT,"gui-%03d.json",sequence)),LabHostGuiProtocol.retainedReceipt(value,session,command));
                    if(!text(value,"outcome").equals("PASS")) {
                        Path done=receipt.resolveSibling(command.operationId()+".diagnostics");
                        long grace=Math.min(command.deadlineEpochMs()+2_000,System.currentTimeMillis()+2_000);
                        while(!Files.exists(done)&&System.currentTimeMillis()<grace) {
                            if(Files.exists(session.root().resolve("cancel"))||Thread.currentThread().isInterrupted())throw new InterruptedException();
                            Thread.sleep(25);
                        }
                    }
                    require(text(value,"outcome").equals("PASS"),"HOST_GUI_OPERATION_FAILED");return value;
                }
                if(!burp.isAlive()) {
                    var exit=LabHostGuiProtocol.identity(session);exit.addProperty("sequence",command.sequence());
                    exit.addProperty("operationId",command.operationId().toString());exit.addProperty("operation",operation.name());
                    exit.addProperty("observedEpochMs",System.currentTimeMillis());exit.addProperty("exitCode",burp.exitValue());
                    writeNew(report.resolve("burp-exit.json"),exit);
                    throw invalid("HOST_BURP_EXITED");
                }
                Thread.sleep(100);
            }
            throw invalid("HOST_GUI_RECEIPT_DEADLINE");
            }catch(Exception failure){broken=true;throw failure;}
        }
    }
    private static JsonObject verifyArtifact(JsonElement element, Path root, boolean runtime) throws IOException {
        var artifact=runtime?object(element,"path","sha256","bytes","role"):object(element,"path","sha256","bytes");
        if(runtime)member(artifact.get("role"),"LAB","EXPORTER");
        Path path=owned(root,relative(artifact.get("path")));
        require(Files.isRegularFile(path)&&Files.size(path)==positive(artifact.get("bytes"))&&sha256(path).equals(hash(artifact.get("sha256"))),"HOST_GUEST_ARTIFACT");
        return artifact;
    }
    static LabHostCoordinator.PlatformResult result(JsonObject json, LabHostInputs.Plan plan, String platform, String nonce, String stage) {
        object(json,"version","invocationId","platform","runNonce","productSha256","helperSha256","outcome","code","cleanup","unattended","stage","scenarios","durationMs","evidence");
        LabHostInputs.version(json);
        require(uuid(json.get("invocationId")).equals(plan.invocationId())&&text(json,"platform").equals(platform)
                &&uuid(json.get("runNonce")).toString().equals(nonce)&&hash(json.get("productSha256")).equals(plan.product().sha256())
                &&hash(json.get("helperSha256")).equals(plan.helper().sha256())&&text(json,"stage").equals(stage.toUpperCase(Locale.ROOT)),"HOST_FOREIGN_GUEST_RESULT");
        require(json.get("unattended").isJsonPrimitive()&&json.get("unattended").getAsJsonPrimitive().isBoolean(),"HOST_UNATTENDED_TYPE");
        positive(json.get("durationMs"));
        require(json.get("evidence").isJsonArray(),"HOST_EVIDENCE_INDEX");validateEvidenceIndex(json.getAsJsonArray("evidence"));
        var scenarios=new LinkedHashMap<String,LabHostCoordinator.Outcome>();
        object(json.get("scenarios")).entrySet().forEach(e -> {
            require(LabHostInputs.SCENARIOS.contains(e.getKey()),"HOST_SCENARIO");
            scenarios.put(e.getKey(),LabHostCoordinator.Outcome.valueOf(member(e.getValue(),"PASS","FAIL","BLOCKED","INTERRUPTED")));
        });
        return new LabHostCoordinator.PlatformResult(platform,LabHostCoordinator.Outcome.valueOf(member(json.get("outcome"),"PASS","FAIL","BLOCKED","INTERRUPTED")),
                text(json,"code"),LabHostCoordinator.Cleanup.valueOf(member(json.get("cleanup"),"COMPLETE","INCOMPLETE")),json.get("unattended").getAsBoolean(),scenarios);
    }
}
