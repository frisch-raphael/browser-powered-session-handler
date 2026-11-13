package lab.auth;

import com.google.gson.*;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** The client/API pair belongs to one case, using frozen artifacts and private per-process settings. */
public final class FederationApplications implements AutoCloseable {
    private final LabRun owner;
    private final LabRun.CaseLease target;
    private final FederationEnvironment environment;
    private final AtomicBoolean retired = new AtomicBoolean();
    private final List<Child> children = new CopyOnWriteArrayList<>();
    private final Object launch = new Object();
    private volatile boolean cleanupComplete;
    private volatile long startupMs,cleanupMs;
    private boolean starting;
    private Thread starter;
    private final String classpath, runtimeIdentity;
    private record Child(String role, Process process, Instant osStarted, String executable, Path directory,
                         FixtureIdentityStore.Secret key, URI origin) {}

    FederationApplications(LabRun owner, LabRun.CaseLease target, FederationEnvironment environment, Path manifest) throws Exception {
        this.owner=owner;this.target=target;this.environment=environment;
        if(!Files.isRegularFile(manifest,LinkOption.NOFOLLOW_LINKS)||Files.size(manifest)>131_072)throw new IOException("Prepared federation runtime absent.");
        var input=ScenarioCatalog.parseJson(Files.readAllBytes(manifest)).getAsJsonObject();
        if(!input.keySet().equals(Set.of("runtimeVersion","identity","directory","artifacts"))||input.get("runtimeVersion").getAsInt()!=1)
            throw new IOException("Unrecognized federation runtime manifest.");
        runtimeIdentity=LabRun.text(input,"identity");
        if(!runtimeIdentity.matches("[a-f0-9]{64}")||!runtimeIdentity.equals(LabRun.text(input,"directory")))throw new IOException("Invalid federation runtime identity.");
        Path root=manifest.toRealPath().getParent().resolve(runtimeIdentity);
        if(!Files.isDirectory(root,LinkOption.NOFOLLOW_LINKS)||!root.toRealPath().startsWith(manifest.toRealPath().getParent()))throw new IOException("Runtime directory escaped preparation.");
        var paths=new ArrayList<String>();var entries=new ArrayList<String>();var names=new HashSet<String>();
        for(var item:input.getAsJsonArray("artifacts")) {
            var artifact=item.getAsJsonObject();String file=LabRun.text(artifact,"file"),hash=LabRun.text(artifact,"sha256");
            if(!artifact.keySet().equals(Set.of("file","bytes","sha256"))||!file.matches("[0-9]{3}-[A-Za-z0-9._-]+\\.jar")||!names.add(file)||!hash.matches("[a-f0-9]{64}"))
                throw new IOException("Invalid prepared runtime artifact.");
            Path path=root.resolve(file);
            if(!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)||!path.toRealPath().startsWith(root.toRealPath())||Files.size(path)!=artifact.get("bytes").getAsLong())throw new IOException("Prepared runtime artifact differs.");
            var digest=MessageDigest.getInstance("SHA-256");try(var stream=Files.newInputStream(path)){byte[] buffer=new byte[65_536];for(int count;(count=stream.read(buffer))>=0;)digest.update(buffer,0,count);}
            if(!HexFormat.of().formatHex(digest.digest()).equals(hash))throw new IOException("Prepared runtime artifact hash differs.");
            paths.add(path.toRealPath().toString());entries.add(file+":"+hash);
        }
        if(paths.isEmpty()||!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(String.join("\n",entries).getBytes(StandardCharsets.UTF_8))).equals(runtimeIdentity))
            throw new IOException("Prepared runtime identity differs.");
        classpath=String.join(File.pathSeparator,paths);
    }

    void start() throws Exception {
        long began=System.nanoTime();
        synchronized(launch){if(retired.get())throw new IOException("Federation startup retired.");starting=true;starter=Thread.currentThread();}
        try { start("resource");start("client"); }
        catch(Exception error){try{close();}catch(Exception cleanup){error.addSuppressed(cleanup);}throw error;}
        finally {startupMs=TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-began);synchronized(launch){starting=false;launch.notifyAll();}}
    }
    public URI clientOrigin() { return environment.ports().clientOrigin(); }
    public URI resourceOrigin() { return environment.ports().resourceOrigin(); }
    public String runtimeIdentity() { return runtimeIdentity; }
    public boolean closed() { synchronized(launch){return cleanupComplete&&!starting;} }
    public boolean closedCleanly() {
        if(!closed()||children.size()!=2)return false;
        for(var child:children)try{if(child.process().isAlive()||child.process().exitValue()!=0)return false;validateReadiness(child,"CLOSED");}catch(Exception incomplete){return false;}
        return true;
    }
    public long startupMs(){return startupMs;}public long cleanupMs(){return cleanupMs;}
    public JsonObject clientSnapshot() throws Exception {return control("snapshot?generation="+target.generation(),null);}
    public void armProtocol(String variant,String checkpoint) throws Exception {
        control("federation-control",Map.of("generation",target.generation(),"variant",variant,"checkpoint",checkpoint));
    }
    public void releaseProtocol(String checkpoint) throws Exception {
        if(!Set.of("before-token-exchange","before-client-session").contains(checkpoint))throw LabRun.error(400,"BAD_INPUT");
        control("gates/"+checkpoint+"/release",Map.of("generation",target.generation()));
    }
    /** Polls actual checkpoint state; it never substitutes a delay for a protocol observation. */
    public void awaitProtocolCheckpoint(String checkpoint,Duration timeout) throws Exception {
        long deadline=System.nanoTime()+timeout.toNanos();
        while(System.nanoTime()<deadline) {
            var snapshot=clientSnapshot();if(snapshot.get("truncated").getAsBoolean())throw new IOException("Protocol observation stream truncated.");
            for(var item:snapshot.getAsJsonArray("checkpoints")) {
                var entry=item.getAsJsonObject();if(checkpoint.equals(LabRun.text(entry,"name"))&&"WAITING".equals(LabRun.text(entry,"state")))return;
            }
            Thread.sleep(20);
        }
        throw new IOException("Protocol checkpoint was not observed within the caller's deadline.");
    }
    private JsonObject control(String route,Map<String,Object> body) throws Exception {
        if(retired.get())throw new IOException("Federation case retired.");
        var child=children.stream().filter(c->c.role().equals("client")).findFirst().orElseThrow(()->new IOException("Client role is not prepared."));
        var ready=validateReadiness(child,"READY");String base=LabRun.text(ready,"controlUri")+"/cases/"+target.id()+"/";
        var request=HttpRequest.newBuilder(URI.create(base+route)).timeout(Duration.ofSeconds(3)).header("Authorization","Bearer "+child.key().reveal());
        if(body==null)request.GET();else request.header("Content-Type","application/json").POST(HttpRequest.BodyPublishers.ofString(LabRun.JSON.toJson(body)));
        try(var client=ControlledApplication.localClientBuilder().connectTimeout(Duration.ofSeconds(1)).build()) {
            var response=client.send(request.build(),HttpResponse.BodyHandlers.ofInputStream());byte[] bytes;
            try(var input=response.body()){bytes=input.readNBytes(1_048_577);}
            if(bytes.length>1_048_576)throw new IOException("Owned federation control response exceeded its limit.");
            var result=ScenarioCatalog.parseJson(bytes).getAsJsonObject();
            if(response.statusCode()!=200) {
                if(result.keySet().equals(Set.of("error"))) {
                    var error=result.getAsJsonObject("error");
                    if(error.keySet().equals(Set.of("code","message","runId","caseId","generation"))&&owner.runId().toString().equals(LabRun.text(error,"runId"))
                            &&target.id().equals(LabRun.text(error,"caseId"))&&target.generation()==LabRun.number(error,"generation",false)) {
                        String code=LabRun.text(error,"code");Integer expected=Map.of("BAD_INPUT",400,"STATE_CONFLICT",409,"GENERATION_CONFLICT",409,"NOT_FOUND",404,"RETIRED",410,"DEADLINE",504).get(code);
                        if(expected!=null&&expected==response.statusCode())throw LabRun.error(expected,code);
                    }
                }
                throw new IOException("Owned federation control did not complete: HTTP "+response.statusCode()+".");
            }
            if(body==null&&(!result.keySet().equals(Set.of("runId","caseId","generation","state","checkpoints","counters","events","truncated"))
                    ||!owner.runId().toString().equals(LabRun.text(result,"runId"))||!target.id().equals(LabRun.text(result,"caseId"))||target.generation()!=LabRun.number(result,"generation",false)))
                throw new IOException("Owned federation snapshot identity differs.");
            if(body!=null) {
                String acknowledgement=route.equals("federation-control")?"armed":"released";
                if(!result.keySet().equals(Set.of("generation",acknowledgement))||target.generation()!=LabRun.number(result,"generation",false)
                        ||!result.get(acknowledgement).isJsonPrimitive()||!result.get(acknowledgement).getAsJsonPrimitive().isBoolean()||!result.get(acknowledgement).getAsBoolean())
                    throw new IOException("Owned federation control acknowledgement differs.");
            }
            return result;
        }
    }

    private void start(String role) throws Exception {
        if(retired.get())throw new IOException("Federation case retired before child launch.");
        Path directory=environment.directory().resolve((role.equals("client")?"c-":"r-")+UUID.randomUUID().toString().substring(0,8));
        var tls=LabTls.createServer(environment.ca(),directory,List.of(role.equals("client")?"app.authlab.test":"api.authlab.test"));
        Path certificate=directory.resolve("ca.crt");Files.copy(tls.caCertificate(),certificate);
        var key=FixtureIdentityStore.randomSecret();var ports=environment.ports();URI origin=role.equals("client")?ports.clientOrigin():ports.resourceOrigin();
        var settings=new LinkedHashMap<String,Object>();settings.put("settingsVersion",2);settings.put("invocationId",owner.spec().invocationId());settings.put("runId",owner.runId());
        settings.put("caseId",target.id());settings.put("generation",target.generation());settings.put("role",role);settings.put("clientOrigin",ports.clientOrigin().toString());
        settings.put("resourceOrigin",ports.resourceOrigin().toString());settings.put("issuer",ports.issuer().toString());settings.put("keyStore","server.p12");settings.put("keyStorePassword",tls.password().reveal());
        settings.put("caCertificate","ca.crt");settings.put("controlKey",key.reveal());
        settings.put("backendClientSecret",role.equals("client")?environment.clientSecret("backend-client").reveal():null);
        settings.put("upstreamIssuer",ports.upstream()==0?null:ports.upstreamIssuer().toString());
        Path privateSettings=directory.resolve("settings.json"),log=directory.resolve("child.log");
        Files.createFile(privateSettings);LabRun.restrict(privateSettings);Files.writeString(privateSettings,LabRun.JSON.toJson(settings));Files.createFile(log);LabRun.restrict(log);
        Path executable=Path.of(System.getProperty("java.home"),"bin",System.getProperty("os.name").startsWith("Windows")?"java.exe":"java").toRealPath();
        Path arguments=directory.resolve("launch.args");Files.createFile(arguments);LabRun.restrict(arguments);
        Files.writeString(arguments,"-cp\n"+argument(classpath)+"\nlab.federation.FederationApplication\n--settings\n"+argument(privateSettings.toString())+"\n");
        Child child;
        synchronized(launch) {
            if(retired.get())throw new IOException("Federation case retired before child launch.");
            environment.handoff(origin.getPort());
            var process=new ProcessBuilder(executable.toString(),javaArgumentFile(arguments))
                    .redirectErrorStream(true).redirectOutput(log.toFile()).start();
            // Retain the actual Process before any fallible OS identity query, so cleanup still owns it.
            child=new Child(role,process,process.info().startInstant().orElse(null),process.info().command().orElse(null),directory,key,origin);children.add(child);
            if(child.osStarted()==null||child.executable()==null||!Path.of(child.executable()).toRealPath().equals(executable)
                    ||process.toHandle().parent().map(ProcessHandle::pid).orElse(-1L)!=ProcessHandle.current().pid())throw new IOException("Child OS ownership proof unavailable.");
            Files.writeString(directory.resolve("launch.json"),LabRun.JSON.toJson(Map.of("pid",process.pid(),"osStartedAt",child.osStarted().toString(),"executable",child.executable(),
                    "parentPid",ProcessHandle.current().pid(),"runId",owner.runId(),"caseId",target.id(),"generation",target.generation(),"runtimeIdentity",runtimeIdentity)));
        }
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(20);Path ready=directory.resolve("ready-"+role+".json");
        try(var watcher=FileSystems.getDefault().newWatchService()) {
            directory.register(watcher,StandardWatchEventKinds.ENTRY_CREATE,StandardWatchEventKinds.ENTRY_MODIFY);
            while(!Files.exists(ready)) {
                if(retired.get())throw new IOException("Federation child startup retired.");
                if(!child.process().isAlive())throw new IOException("Federation "+role+" child exited before readiness.");
                long left=deadline-System.nanoTime();if(left<=0)throw new IOException("Federation "+role+" child readiness deadline.");
                var event=watcher.poll(Math.min(left,TimeUnit.MILLISECONDS.toNanos(100)),TimeUnit.NANOSECONDS);if(event!=null)event.reset();
            }
        }
        validateReadiness(child,"READY");
        if(retired.get())throw new IOException("Federation child readiness arrived after retirement.");
    }

    /** The JDK launcher's native argument-file reader needs Windows extended paths in deep worktrees. */
    static String javaArgumentFile(Path arguments) {
        String path=arguments.toAbsolutePath().normalize().toString();
        if(System.getProperty("os.name").startsWith("Windows")&&!path.startsWith("\\\\?\\"))
            path=path.startsWith("\\\\")?"\\\\?\\UNC\\"+path.substring(2):"\\\\?\\"+path;
        return "@"+path;
    }

    private JsonObject validateReadiness(Child child,String state) throws Exception {
        Path path=child.directory().resolve("ready-"+child.role()+".json");
        if(!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)||Files.size(path)>65_536)throw new IOException("Child readiness record absent or oversized.");
        var ready=ScenarioCatalog.parseJson(Files.readAllBytes(path)).getAsJsonObject();
        if(!ready.keySet().equals(Set.of("readinessVersion","invocationId","runId","caseId","role","generation","pid","startedAt","state","origin","controlUri","controlKey"))
                ||ready.get("readinessVersion").getAsInt()!=1||!owner.spec().invocationId().toString().equals(LabRun.text(ready,"invocationId"))||!owner.runId().toString().equals(LabRun.text(ready,"runId"))||!target.id().equals(LabRun.text(ready,"caseId"))
                ||!child.role().equals(LabRun.text(ready,"role"))||target.generation()!=ready.get("generation").getAsLong()||child.process().pid()!=ready.get("pid").getAsLong()
                ||!state.equals(LabRun.text(ready,"state"))||!child.origin().toString().equals(LabRun.text(ready,"origin"))
                ||!MessageDigest.isEqual(child.key().reveal().getBytes(StandardCharsets.UTF_8),LabRun.text(ready,"controlKey").getBytes(StandardCharsets.UTF_8)))throw new IOException("Child readiness identity differs.");
        Instant started=Instant.parse(LabRun.text(ready,"startedAt"));
        if(child.osStarted()==null||started.isBefore(child.osStarted())||started.isAfter(Instant.now()))throw new IOException("Child readiness start proof differs.");
        URI control=URI.create(LabRun.text(ready,"controlUri"));
        if(!"http".equals(control.getScheme())||!"127.0.0.1".equals(control.getHost())||control.getPort()<1||control.getRawUserInfo()!=null||control.getRawQuery()!=null||control.getRawFragment()!=null
                ||!control.getPath().equals("/control/v1/runs/"+owner.runId()))throw new IOException("Child control identity differs.");
        return ready;
    }

    List<Map<String,Object>> resources() {
        return children.stream().filter(c->c.process().isAlive()).map(c->Map.<String,Object>of("kind","PROCESS","id",Long.toString(c.process().pid()),"ownerRunId",owner.runId().toString(),
                "createdAt",c.osStarted()==null?"unobserved":c.osStarted().toString(),"proof",Map.of("parentPid",ProcessHandle.current().pid(),"runtimeIdentity",runtimeIdentity,
                        "executable",c.executable()==null?"unobserved":c.executable(),"role",c.role(),"caseId",target.id(),"generation",target.generation(),"verified",c.osStarted()!=null&&c.executable()!=null))).toList();
    }
    private static String argument(String value) {
        if(value.indexOf('\n')>=0||value.indexOf('\r')>=0)throw new IllegalArgumentException("Invalid JVM argument path.");
        return "\""+value.replace("\\","\\\\").replace("\"","\\\"")+"\"";
    }

    /** Never acquires a parent/case monitor: case reset can retire startup and close this pair safely. */
    @Override public void close() throws Exception {
        close(System.nanoTime()+TimeUnit.SECONDS.toNanos(5));
    }
    void close(long deadline) throws Exception {
        if(cleanupComplete)return;long began=System.nanoTime();
        retired.set(true);List<Child> owned;synchronized(launch){owned=List.copyOf(children).reversed();}
        Exception failure=null;
        for(var child:owned) {
            try {
                if(child.process().isAlive()) {
                    var info=child.process().info();
                    if(child.osStarted()==null||child.executable()==null||!info.startInstant().filter(child.osStarted()::equals).isPresent()
                            ||!info.command().filter(child.executable()::equals).isPresent())throw new IOException("Child OS ownership changed; no process signal sent.");
                    boolean acknowledged=false;
                    if(Files.exists(child.directory().resolve("ready-"+child.role()+".json"))&&System.nanoTime()<deadline) {
                        var ready=validateReadiness(child,"READY");
                        try(var client=ControlledApplication.localClientBuilder().connectTimeout(Duration.ofSeconds(1)).build()) {
                            var response=client.send(HttpRequest.newBuilder(URI.create(LabRun.text(ready,"controlUri")+"/stop")).timeout(Duration.ofNanos(Math.max(1,Math.min(TimeUnit.SECONDS.toNanos(1),deadline-System.nanoTime()))))
                                    .header("Authorization","Bearer "+child.key().reveal()).header("Content-Type","application/json")
                                    .POST(HttpRequest.BodyPublishers.ofString("{\"generation\":"+target.generation()+"}")).build(),HttpResponse.BodyHandlers.discarding());
                            acknowledged=response.statusCode()==202;
                        }
                    }
                    if(!acknowledged)child.process().destroy();
                    if(!child.process().waitFor(Math.max(0,Math.min(TimeUnit.SECONDS.toNanos(2),deadline-System.nanoTime())),TimeUnit.NANOSECONDS)) {
                        child.process().destroyForcibly();
                        if(!child.process().waitFor(Math.max(0,deadline-System.nanoTime()),TimeUnit.NANOSECONDS))throw new IOException("Owned child did not exit within the case deadline.");
                        throw new IOException("Owned child required forced termination.");
                    }
                    if(acknowledged){if(child.process().exitValue()!=0)throw new IOException("Owned child reported incomplete cleanup.");validateReadiness(child,"CLOSED");}
                }
            }catch(Exception error){
                // A malformed/unreachable control must not leave a verified owned JVM running.
                if(child.process().isAlive()&&child.osStarted()!=null&&child.executable()!=null
                        &&child.process().info().startInstant().filter(child.osStarted()::equals).isPresent()
                        &&child.process().info().command().filter(child.executable()::equals).isPresent()) {
                    child.process().destroy();
                    if(!child.process().waitFor(Math.max(0,Math.min(TimeUnit.SECONDS.toNanos(1),deadline-System.nanoTime())),TimeUnit.NANOSECONDS)) {
                        child.process().destroyForcibly();child.process().waitFor(Math.max(0,deadline-System.nanoTime()),TimeUnit.NANOSECONDS);
                    }
                }
                if(failure==null)failure=error;else failure.addSuppressed(error);
            }
        }
        synchronized(launch) {
            while(starting&&starter!=Thread.currentThread()) {
                long left=deadline-System.nanoTime();if(left<=0){var unsettled=new IOException("Retired federation startup did not settle within the case deadline.");if(failure==null)failure=unsettled;else failure.addSuppressed(unsettled);break;}
                TimeUnit.NANOSECONDS.timedWait(launch,left);
            }
        }
        if(failure!=null)throw failure;
        cleanupMs=TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-began);cleanupComplete=true;
    }
}
