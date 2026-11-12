package lab.auth;

import com.google.gson.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import static lab.auth.LabJson.*;

/** One explicit invocation owns both platform attempts and always retains their outcomes. */
public final class LabHostCoordinator {
    public enum Outcome { PASS, FAIL, BLOCKED, INTERRUPTED }
    public enum Cleanup { COMPLETE, INCOMPLETE }
    public record PlatformResult(String platform, Outcome outcome, String code, Cleanup cleanup,
                                 boolean unattended, Map<String,Outcome> scenarios) {
        public PlatformResult {
            require(LabHostInputs.PLATFORMS.contains(platform),"HOST_RESULT_PLATFORM");
            require(code.matches("[A-Z][A-Z0-9_]{0,79}"),"HOST_RESULT_CODE"); scenarios = Map.copyOf(scenarios);
        }
        static PlatformResult blocked(String platform, String code) {
            return new PlatformResult(platform,Outcome.BLOCKED,code,Cleanup.COMPLETE,true,Map.of());
        }
    }
    @FunctionalInterface interface GuestExecution {
        PlatformResult execute(LabHostInputs.Vm vm, LabHostInputs.Plan plan, Path report, String stage,
                               AtomicBoolean cancelled) throws IOException, InterruptedException;
        default void cancel() throws IOException,InterruptedException {}
    }
    @FunctionalInterface interface Cancellation { void cancel() throws IOException,InterruptedException; }
    @FunctionalInterface interface CompletionAttempt<T> { T fetch() throws IOException,InterruptedException; }
    /** Completion can become durable between the last fetch and an observed process exit. */
    static <T> T finalCompletion(CompletionAttempt<T> attempt) throws IOException,InterruptedException {
        try{return attempt.fetch();}
        catch(LabHostVmTransport.Failure missing){throw new LabHostVmTransport.Failure("HOST_GUEST_EXITED_WITHOUT_RESULT");}
    }
    /** A failed or interrupted marker must not prevent attempting cancellation of the other VM. */
    static void cancelAll(List<Cancellation> actions) throws IOException,InterruptedException {
        IOException failure=null;boolean interrupted=Thread.interrupted();
        for(var action:actions)try{action.cancel();}
        catch(IOException unavailable){failure=new LabHostVmTransport.Failure("HOST_CANCEL_UNAVAILABLE");}
        catch(InterruptedException stopped){interrupted=true;Thread.interrupted();}
        if(interrupted){Thread.currentThread().interrupt();throw new InterruptedException();}
        if(failure!=null)throw failure;
    }
    private final GuestExecution execution;
    public LabHostCoordinator() { this(new RemoteExecution(new LabHostVmTransport())); }
    LabHostCoordinator(GuestExecution execution) { this.execution = Objects.requireNonNull(execution); }

    public static int runCommand(String[] args, PrintStream out, PrintStream err) {
        try {
            var options = LabHostInputs.options(args);
            if (options.command().equals("host-guest")) return LabHostGuest.run(options.path("--plan"),options.path("--report-directory"));
            var plan = LabHostInputs.plan(options.path("--plan"));
            require(plan.mode() == (options.command().equals("host-test") ? LabHostInputs.Mode.ACCEPTANCE : LabHostInputs.Mode.QUALIFICATION),"HOST_MODE");
            var requested = options.platform().equals("both") ? LabHostInputs.PLATFORMS : List.of(options.platform());
            require(plan.platforms().equals(requested),"HOST_PLATFORM_SELECTION");
            Path workspace = options.path("--workspace").toRealPath();
            Path artifact = options.path("--artifact").toRealPath();
            require(artifact.equals(workspace.resolve("bapp/build/libs/browser-powered-session-handler-dev.jar").toRealPath())
                    && sha256(artifact).equals(plan.product().sha256()),"HOST_DEVELOPMENT_ARTIFACT");
            Path report = options.path("--report-directory"); Files.createDirectories(report);
            require(report.toRealPath().startsWith(workspace.resolve("test/authentication-lab/build/authlab").toRealPath()),"HOST_REPORT_OWNER");
            var vms = LabHostInputs.vmConfig(options.path("--vm-config"));
            int code = new LabHostCoordinator().execute(plan,vms,report,options.stage(),new AtomicBoolean(),workspace);
            out.println(code == 0 ? plan.mode()==LabHostInputs.Mode.ACCEPTANCE?"Host acceptance completed with independently joined evidence.":"Host qualification completed; no catalog acceptance inferred." : "Host execution failed, blocked or incomplete; retain its report.");
            return code;
        } catch (IllegalArgumentException invalid) { err.println("Invalid host command or plan."); return 2; }
        catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); err.println("Host execution interrupted."); return 3; }
        catch (IOException | RuntimeException failed) { err.println("Host execution unavailable; private arguments and output suppressed."); return 3; }
    }

    int execute(LabHostInputs.Plan plan, Map<String,LabHostInputs.Vm> vms, Path report, String stage,
                AtomicBoolean cancelled) throws IOException, InterruptedException {
        return execute(plan,vms,report,stage,cancelled,null);
    }
    int execute(LabHostInputs.Plan plan, Map<String,LabHostInputs.Vm> vms, Path report, String stage,
                AtomicBoolean cancelled,Path workspace) throws IOException, InterruptedException {
        Files.createDirectories(report);
        long began = System.currentTimeMillis();
        var context = new LinkedHashMap<String,Object>(); context.put("version",1); context.put("invocationId",plan.invocationId());
        context.put("taskPath",plan.taskPath()); context.put("mode",plan.mode()); context.put("platforms",plan.platforms());
        context.put("sourceRevision",plan.sourceRevision()); context.put("sourceHashes",plan.sourceHashes());
        context.put("configurationHash",plan.configurationHash()); context.put("catalogRevision",plan.catalogRevision());
        context.put("productSha256",plan.product().sha256()); context.put("helperSha256",plan.helper().sha256());
        context.put("auditSha256",plan.audit().sha256());context.put("scenariosSha256",plan.scenarios().sha256());
        context.put("adapter","JDK_AWT_ROBOT_V1");
        context.put("runtime",plan.runtime().stream().map(artifact->Map.of("role",artifact.role(),"sha256",artifact.sha256(),"bytes",artifact.bytes())).toList());
        context.put("state","STARTED"); writeNew(report.resolve("report-context.json"),context);
        var results = new ArrayList<PlatformResult>();
        var completed=new java.util.concurrent.ConcurrentHashMap<String,PlatformResult>();
        var workers=java.util.concurrent.Executors.newFixedThreadPool(plan.platforms().size(),task->{
            var thread=new Thread(task,"authlab-host-platform");thread.setDaemon(true);return thread;});
        var futures=new ArrayList<java.util.concurrent.Future<?>>();
        var interruptedWorker=new AtomicBoolean();
        Thread hook = new Thread(() -> {cancelled.set(true);try{execution.cancel();}catch(IOException|InterruptedException unavailable){}},"authlab-host-cancel"); Runtime.getRuntime().addShutdownHook(hook);
        boolean interrupted = false,accepted=false;
        try {
            for (String platform : plan.platforms()) futures.add(workers.submit(()->{
                PlatformResult result;
                if (cancelled.get()) result = new PlatformResult(platform,Outcome.INTERRUPTED,"HOST_CANCELLED",Cleanup.COMPLETE,true,Map.of());
                else if (!vms.containsKey(platform)) result = PlatformResult.blocked(platform,"HOST_VM_MISSING");
                else {
                    try {
                        Path platformReport = Files.createDirectory(report.resolve(platform));
                        for (var artifact : plan.artifacts()) artifact.verify();
                        result = execution.execute(vms.get(platform),plan,platformReport,stage,cancelled);
                        require(result.platform().equals(platform),"HOST_FOREIGN_PLATFORM_RESULT");
                    } catch (InterruptedException stop) {
                        interruptedWorker.set(true); cancelled.set(true);
                        result = new PlatformResult(platform,Outcome.INTERRUPTED,"HOST_CANCELLED",Cleanup.INCOMPLETE,true,Map.of());
                    } catch (IOException | RuntimeException failure) {
                        result = new PlatformResult(platform,Outcome.BLOCKED,failure instanceof LabHostVmTransport.Failure fixed?fixed.code():"HOST_GUEST_FAILED",Cleanup.INCOMPLETE,true,Map.of());
                    }
                }
                try {
                    Path retained=report.resolve(platform);Files.createDirectories(retained);writeNew(retained.resolve("summary.json"),result);
                    completed.put(platform,result);
                }catch(IOException|RuntimeException unavailable) {
                    completed.put(platform,new PlatformResult(platform,Outcome.BLOCKED,"HOST_REPORT_UNAVAILABLE",Cleanup.INCOMPLETE,true,Map.of()));
                }
            }));
            for(var future:futures) {
                try {future.get();}
                catch(java.util.concurrent.ExecutionException failed){/* Missing worker result remains incomplete below. */}
                if(cancelled.get()) {
                    futures.forEach(pending->pending.cancel(true));
                    try{execution.cancel();}catch(IOException|InterruptedException unavailable){/* Private helper errors stay private. */}
                    break;
                }
            }
        } catch(InterruptedException stop) {
            interrupted=true;cancelled.set(true);futures.forEach(future->future.cancel(true));
            try{execution.cancel();}catch(IOException|InterruptedException unavailable){/* Never echo private helper failures. */}
        } finally {
            workers.shutdownNow();
            try{if(!workers.awaitTermination(60,java.util.concurrent.TimeUnit.SECONDS))cancelled.set(true);}
            catch(InterruptedException stop){interrupted=true;cancelled.set(true);}
            for(String platform:plan.platforms())results.add(completed.getOrDefault(platform,
                    new PlatformResult(platform,cancelled.get()?Outcome.INTERRUPTED:Outcome.BLOCKED,
                            cancelled.get()?"HOST_CANCELLED":"HOST_WORKER_FAILED",Cleanup.INCOMPLETE,true,Map.of())));
            try { Runtime.getRuntime().removeShutdownHook(hook); } catch (IllegalStateException shuttingDown) { cancelled.set(true); }
            boolean passed = complete(plan.platforms(),results,stage);
            String code=passed?"QUALIFICATION_COMPLETE":"HOST_INCOMPLETE";Outcome evidenceOutcome=null;
            if(plan.mode()==LabHostInputs.Mode.QUALIFICATION)accepted=passed;
            else {
                code="HOST_EVIDENCE_COLLECTOR_UNAVAILABLE";
                if(workspace!=null)try {
                    var evidence=LabHostEvidence.collectResult(report,workspace,plan);accepted=evidence.complete()&&passed;
                    evidenceOutcome=evidence.outcome();code=evidence.code();
                }catch(IOException|RuntimeException unavailable){code="HOST_EVIDENCE_UNAVAILABLE";}
            }
            Outcome retained=accepted?Outcome.PASS:aggregateOutcome(results);
            if(!accepted&&retained!=Outcome.INTERRUPTED&&evidenceOutcome==Outcome.FAIL)retained=Outcome.FAIL;
            if(!accepted&&retained==Outcome.PASS)retained=Outcome.BLOCKED;
            writeNew(report.resolve("completion.json"),Map.of("version",1,"invocationId",plan.invocationId(),"mode",plan.mode(),
                    "outcome",retained.name(),"code",code,"results",results,"durationMs",System.currentTimeMillis()-began,
                    "cleanup",results.size()==plan.platforms().size()&&results.stream().allMatch(r -> r.cleanup()==Cleanup.COMPLETE)?"COMPLETE":"INCOMPLETE"));
            if (interrupted||interruptedWorker.get()) Thread.currentThread().interrupt();
        }
        return accepted?0:3;
    }
    static Outcome aggregateOutcome(List<PlatformResult> results) {
        for(Outcome outcome:List.of(Outcome.INTERRUPTED,Outcome.FAIL,Outcome.BLOCKED))
            if(results.stream().anyMatch(result->result.outcome()==outcome))return outcome;
        return results.isEmpty()||results.stream().anyMatch(result->result.cleanup()!=Cleanup.COMPLETE||!result.unattended())?Outcome.BLOCKED:Outcome.PASS;
    }
    static boolean complete(List<String> intended, List<PlatformResult> results, String stage) {
        if (results.size()!=intended.size() || !results.stream().map(PlatformResult::platform).toList().equals(intended)) return false;
        return results.stream().allMatch(r -> r.outcome()==Outcome.PASS && r.cleanup()==Cleanup.COMPLETE && r.unattended()
                && (stage.equals("primitives") || r.scenarios().keySet().equals(new HashSet<>(LabHostInputs.SCENARIOS))
                && r.scenarios().values().stream().allMatch(v -> v==Outcome.PASS)));
    }

    /** Verifies exact native ownership and absence of the guest process before removing its private root. */
    static String ownedRootCleanupScript(LabHostInputs.Vm vm,String root,UUID invocation,String nonce,long pid,long started) {
        require(UUID.fromString(nonce).toString().equals(nonce)&&pid>0&&started>0,"HOST_CLEANUP_IDENTITY");
        String leaf=invocation+"-"+nonce.substring(0,8);
        require(root.equals(LabHostVmTransport.joinGuest(vm.guestRoot(),leaf,vm.platform())),"HOST_CLEANUP_ROOT");
        if(vm.platform().equals("windows"))return """
                $ErrorActionPreference='Stop'
                $r=[IO.Path]::GetFullPath(%s).TrimEnd('\\')
                $base=[IO.Path]::GetFullPath(%s).TrimEnd('\\')
                if(-not [string]::Equals([IO.Path]::GetDirectoryName($r),$base,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($r) -cne %s){throw 'ROOT'}
                $of=Join-Path $r 'owner.json';$sf=Join-Path $r 'report/started.json'
                if((Get-Item -LiteralPath $of).Length -gt 4096 -or (Get-Item -LiteralPath $sf).Length -gt 4096){throw 'SIZE'}
                $o=Get-Content -LiteralPath $of -Raw|ConvertFrom-Json;$s=Get-Content -LiteralPath $sf -Raw|ConvertFrom-Json
                if($o.version -ne 1 -or $o.invocationId -cne %s -or $o.platform -cne 'windows' -or $o.runNonce -cne %s -or -not [string]::Equals([IO.Path]::GetFullPath($o.guestRoot),$r,[StringComparison]::OrdinalIgnoreCase)){throw 'OWNER'}
                if($s.version -ne 1 -or $s.invocationId -cne %s -or $s.runNonce -cne %s -or [long]$s.pid -ne %d -or [long]$s.startedEpochMs -ne %d){throw 'PROCESS'}
                for($i=0;$i -lt 50 -and (Get-Process -Id %d -ErrorAction SilentlyContinue);$i++){Start-Sleep -Milliseconds 100}
                if(Get-Process -Id %d -ErrorAction SilentlyContinue){throw 'ALIVE'}
                $queue=New-Object 'System.Collections.Generic.Queue[System.IO.FileSystemInfo]';$queue.Enqueue((Get-Item -LiteralPath $r -Force));$count=0
                while($queue.Count -gt 0){$entry=$queue.Dequeue();$count++;if($count -gt 100000 -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'TREE'};if($entry -is [IO.DirectoryInfo]){foreach($child in $entry.EnumerateFileSystemInfos()){$queue.Enqueue($child)}}}
                Remove-Item -LiteralPath $r -Recurse -Force
                if(Test-Path -LiteralPath $r){throw 'REMAINS'}
                """.formatted(LabHostVmTransport.powershellQuote(root),LabHostVmTransport.powershellQuote(vm.guestRoot()),LabHostVmTransport.powershellQuote(leaf),
                        LabHostVmTransport.powershellQuote(invocation.toString()),LabHostVmTransport.powershellQuote(nonce),
                        LabHostVmTransport.powershellQuote(invocation.toString()),LabHostVmTransport.powershellQuote(nonce),pid,started,pid,pid);
        String values=JSON.toJson(List.of(root,vm.guestRoot(),invocation.toString(),nonce,Long.toString(pid),Long.toString(started)));
        return """
                /usr/bin/python3 - <<'BPSH_CLEANUP'
                import json,os,pathlib,shutil,stat,time
                root,base,invocation,nonce,pid,started=%s
                r=pathlib.Path(root);b=pathlib.Path(base);pid=int(pid);started=int(started)
                assert r.is_absolute() and r.resolve(strict=True)==r and b.resolve(strict=True)==b
                assert r.parent==b and r.name==invocation+'-'+nonce[:8]
                def read(name):
                    raw=(r/name).read_bytes();assert len(raw)<=4096
                    return json.loads(raw)
                o=read('owner.json');s=read('report/started.json')
                assert o['version']==1 and o['invocationId']==invocation and o['platform']=='linux' and o['runNonce']==nonce and o['guestRoot']==root
                assert s['version']==1 and s['invocationId']==invocation and s['runNonce']==nonce and s['pid']==pid and s['startedEpochMs']==started
                def alive():
                    try:os.kill(pid,0);return True
                    except ProcessLookupError:return False
                for _ in range(50):
                    if not alive():break
                    time.sleep(.1)
                assert not alive()
                count=0;device=r.stat().st_dev
                for directory,dirs,files in os.walk(r,followlinks=False):
                    for p in [pathlib.Path(directory),*(pathlib.Path(directory)/n for n in dirs+files)]:
                        count+=1;mode=p.lstat();assert count<=100000 and mode.st_dev==device and not stat.S_ISLNK(mode.st_mode) and (stat.S_ISREG(mode.st_mode) or stat.S_ISDIR(mode.st_mode))
                shutil.rmtree(r);assert not r.exists()
                BPSH_CLEANUP
                """.formatted(values);
    }

    private static final class RemoteExecution implements GuestExecution {
        private final LabHostVmTransport transport;
        private final LabHostArtifactCache artifactCache;
        private final java.util.concurrent.ConcurrentMap<String,Map.Entry<LabHostInputs.Vm,String>> active=new java.util.concurrent.ConcurrentHashMap<>();
        RemoteExecution(LabHostVmTransport transport) { this.transport=transport;this.artifactCache=new LabHostArtifactCache(transport); }
        @Override public void cancel() throws IOException,InterruptedException {
            cancelAll(List.copyOf(active.values()).stream().<Cancellation>map(current->()->cancel(current.getKey(),current.getValue())).toList());
        }
        private void cancel(LabHostInputs.Vm vm,String root) throws IOException,InterruptedException {
            transport.script(vm,vm.platform().equals("windows")?"New-Item -ItemType File -Path "+LabHostVmTransport.powershellQuote(root+"\\cancel")+" -Force|Out-Null":
                    "touch "+LabHostVmTransport.shellQuote(root+"/cancel"),Duration.ofSeconds(30));
        }
        @Override public PlatformResult execute(LabHostInputs.Vm vm, LabHostInputs.Plan plan, Path report, String stage,
                                                 AtomicBoolean cancelled) throws IOException, InterruptedException {
            long platformDeadline=System.nanoTime()+Duration.ofMinutes(45).toNanos();
            String nonce=UUID.randomUUID().toString();
            String root=LabHostVmTransport.joinGuest(vm.guestRoot(),plan.invocationId()+"-"+nonce.substring(0,8),vm.platform());
            Path privateDirectory=Files.createDirectory(plan.captureDirectory().getParent().resolve("guest-"+vm.platform()));
            var owner=Map.of("version",1,"invocationId",plan.invocationId().toString(),"platform",vm.platform(),"runNonce",nonce,"guestRoot",root);
            writeNew(privateDirectory.resolve("owner.json"),owner);
            String quote=vm.platform().equals("windows")?LabHostVmTransport.powershellQuote(root):LabHostVmTransport.shellQuote(root);
            transport.script(vm,vm.platform().equals("windows")?
                    "$ErrorActionPreference='Stop';$r="+quote+";if(Test-Path -LiteralPath $r){throw 'Owned directory already exists'};New-Item -ItemType Directory -Path "+LabHostVmTransport.powershellQuote(vm.guestRoot())+" -Force|Out-Null;New-Item -ItemType Directory -Path $r|Out-Null;New-Item -ItemType Directory -Path ($r+'\\assets'),($r+'\\report')|Out-Null":
                    "umask 077; mkdir -p "+LabHostVmTransport.shellQuote(vm.guestRoot())+" && mkdir "+quote+" && mkdir "+quote+"/assets "+quote+"/report",Duration.ofSeconds(30));
            transport.put(vm,privateDirectory.resolve("owner.json"),LabHostVmTransport.joinGuest(root,"owner.json",vm.platform()),Duration.ofSeconds(30));
            var guest=new JsonObject(); guest.addProperty("version",1); guest.addProperty("invocationId",plan.invocationId().toString());
            guest.addProperty("mode",plan.mode().name()); guest.addProperty("platform",vm.platform()); guest.addProperty("runNonce",nonce);
            guest.addProperty("taskPath",plan.taskPath()); guest.addProperty("configurationHash",plan.configurationHash());
            guest.addProperty("catalogRevision",plan.catalogRevision()); guest.addProperty("sourceRevision",plan.sourceRevision()); guest.addProperty("head",plan.head());
            guest.addProperty("guestRoot",root); guest.addProperty("java",vm.java());guest.addProperty("labJava",vm.labJava()); guest.addProperty("burpJar",vm.burpJar());
            guest.addProperty("approvedPreferences",vm.approvedPreferences()); guest.addProperty("display",vm.display()); guest.addProperty("stage",stage.toUpperCase(Locale.ROOT));
            var destinations=new HashMap<Path,String>();
            for (var artifact:plan.artifacts()) {
                if(destinations.containsKey(artifact.path()))continue;
                String name="assets/"+artifact.sha256()+(artifact.path().getFileName().toString().endsWith(".jar")?".jar":".json");
                if(!destinations.containsValue(name)) {
                    String destination=LabHostVmTransport.joinGuest(root,name,vm.platform());
                    String slot=artifact.path().equals(plan.product().path())?"product.jar":artifact.bytes()>32L*1024*1024?"large-runtime.jar":null;
                    if(slot==null)transport.put(vm,artifact.path(),destination,remaining(platformDeadline,600));
                    else artifactCache.place(vm,artifact,root,destination,privateDirectory,slot,remaining(platformDeadline,600));
                }
                destinations.put(artifact.path(),name);
            }
            guest.add("audit",plan.audit().json(destinations.get(plan.audit().path()))); guest.add("product",plan.product().json(destinations.get(plan.product().path())));
            guest.add("helper",plan.helper().json(destinations.get(plan.helper().path()))); guest.add("scenarios",plan.scenarios().json(destinations.get(plan.scenarios().path())));
            var runtime=new JsonArray(); plan.runtime().forEach(a -> runtime.add(a.json(destinations.get(a.path())))); guest.add("runtime",runtime);
            Path guestPlan=privateDirectory.resolve("plan.json"); writeNew(guestPlan,guest);
            transport.put(vm,guestPlan,LabHostVmTransport.joinGuest(root,"plan.json",vm.platform()),Duration.ofSeconds(30));
            String cp=plan.runtime().stream().filter(a -> a.role().equals("LAB")).map(a -> LabHostVmTransport.joinGuest(root,destinations.get(a.path()),vm.platform()))
                    .collect(java.util.stream.Collectors.joining(vm.platform().equals("windows")?";":":"));
            List<String> arguments=List.of("-Xmx256m","-XX:ActiveProcessorCount=2","-classpath",cp,"lab.auth.LabMain","host-guest","--plan",
                    LabHostVmTransport.joinGuest(root,"plan.json",vm.platform()),"--report-directory",LabHostVmTransport.joinGuest(root,"report",vm.platform()));
            Path argumentFile=privateDirectory.resolve("launch.args");
            Files.writeString(argumentFile,arguments.stream().map(RemoteExecution::javaArgument).collect(java.util.stream.Collectors.joining("\n")),StandardCharsets.UTF_8,StandardOpenOption.CREATE_NEW);
            String remoteArgs=LabHostVmTransport.joinGuest(root,"launch.args",vm.platform());
            transport.put(vm,argumentFile,remoteArgs,Duration.ofSeconds(30));
            String command=vm.platform().equals("windows")?
                    "$ErrorActionPreference='Stop';Start-Process -FilePath "+LabHostVmTransport.powershellQuote(vm.labJava())+" -ArgumentList "+
                            LabHostVmTransport.powershellQuote("-Dlab.host.runNonce="+nonce+" \"@"+remoteArgs+"\"")+" -WindowStyle Hidden -RedirectStandardOutput "+LabHostVmTransport.powershellQuote(root+"\\private-out.txt")+
                            " -RedirectStandardError "+LabHostVmTransport.powershellQuote(root+"\\private-error.txt")+"|Out-Null":
                    "DISPLAY="+LabHostVmTransport.shellQuote(vm.display())+" nohup "+LabHostVmTransport.shellQuote(vm.labJava())+" "+LabHostVmTransport.shellQuote("-Dlab.host.runNonce="+nonce)+" "+LabHostVmTransport.shellQuote("@"+remoteArgs)+
                            " >"+LabHostVmTransport.shellQuote(root+"/private-out.txt")+" 2>"+LabHostVmTransport.shellQuote(root+"/private-error.txt")+" < /dev/null &";
            boolean complete=false;
            try {
                active.put(vm.platform(),Map.entry(vm,root));
                transport.interactiveScript(vm,command,Duration.ofSeconds(30));
                long deadline=platformDeadline;
                long startupDeadline=System.nanoTime()+Duration.ofSeconds(60).toNanos();boolean started=false;
                long nextStatus=0,ownerPid=0;
                Path terminal=privateDirectory.resolve("completion.json");
                while(!cancelled.get()&&System.nanoTime()<deadline) {
                    try {
                        var result=fetchCompletion(vm,plan,root,report,terminal,nonce,stage);
                        complete=result.cleanup()==Cleanup.COMPLETE;return result;
                    }catch(LabHostVmTransport.Failure notReady){
                        if(!started)try {
                            Path start=privateDirectory.resolve("started.json");transport.get(vm,LabHostVmTransport.joinGuest(root,"report/started.json",vm.platform()),start,Duration.ofSeconds(10));
                            var value=object(read(start,4096),"version","invocationId","runNonce","pid","startedEpochMs","executable");
                            require(uuid(value.get("invocationId")).equals(plan.invocationId())&&uuid(value.get("runNonce")).toString().equals(nonce),"HOST_GUEST_START_IDENTITY");ownerPid=positive(value.get("pid"));started=true;
                        }catch(LabHostVmTransport.Failure unavailable){if(System.nanoTime()>=startupDeadline)throw new LabHostVmTransport.Failure("HOST_GUEST_START_DEADLINE");}
                        if(started&&System.nanoTime()>=nextStatus) {
                            nextStatus=System.nanoTime()+Duration.ofSeconds(5).toNanos();
                            String statusCommand=vm.platform().equals("windows")?
                                    "& "+LabHostVmTransport.powershellQuote(vm.labJava())+" -Xmx64m -XX:ActiveProcessorCount=1 -classpath "+LabHostVmTransport.powershellQuote(cp)+
                                            " lab.auth.LabHostGuest status "+LabHostVmTransport.powershellQuote(LabHostVmTransport.joinGuest(root,"plan.json",vm.platform())):
                                    LabHostVmTransport.shellQuote(vm.labJava())+" -Xmx64m -XX:ActiveProcessorCount=1 -classpath "+LabHostVmTransport.shellQuote(cp)+
                                            " lab.auth.LabHostGuest status "+LabHostVmTransport.shellQuote(LabHostVmTransport.joinGuest(root,"plan.json",vm.platform()));
                            transport.script(vm,statusCommand,Duration.ofSeconds(15));
                            Path status=privateDirectory.resolve("status.json");transport.get(vm,LabHostVmTransport.joinGuest(root,"status.json",vm.platform()),status,Duration.ofSeconds(15));
                            var value=object(read(status,4096),"version","invocationId","runNonce","pid","alive","ownership");
                            require(positive(value.get("version"))==1&&uuid(value.get("invocationId")).equals(plan.invocationId())&&uuid(value.get("runNonce")).toString().equals(nonce)
                                    &&positive(value.get("pid"))==ownerPid&&value.get("alive").isJsonPrimitive()&&value.get("alive").getAsJsonPrimitive().isBoolean(),"HOST_STATUS_IDENTITY");
                            String ownership=member(value.get("ownership"),"VERIFIED","UNVERIFIED","CHANGED","EXITED");
                            require(value.get("alive").getAsBoolean()!=ownership.equals("EXITED"),"HOST_STATUS_LIVENESS");
                            if(ownership.equals("CHANGED"))throw new LabHostVmTransport.Failure("HOST_GUEST_IDENTITY_CHANGED");
                            if(!value.get("alive").getAsBoolean()) {
                                var result=finalCompletion(()->fetchCompletion(vm,plan,root,report,terminal,nonce,stage));
                                complete=result.cleanup()==Cleanup.COMPLETE;return result;
                            }
                        }
                        Thread.sleep(250);
                    }
                }
                return new PlatformResult(vm.platform(),cancelled.get()?Outcome.INTERRUPTED:Outcome.BLOCKED,"HOST_GUEST_DEADLINE",Cleanup.INCOMPLETE,true,Map.of());
            }finally {
                if(!complete) {
                    boolean wasInterrupted=Thread.interrupted();
                    try {
                        cancel(vm,root);
                    }catch(IOException|InterruptedException cleanupUnavailable){ /* Outcome remains incomplete. Never echo the helper error. */ }
                    finally {if(wasInterrupted)Thread.currentThread().interrupt();}
                }
                active.remove(vm.platform(),Map.entry(vm,root));
            }
        }
        private PlatformResult fetchCompletion(LabHostInputs.Vm vm,LabHostInputs.Plan plan,String root,Path report,
                                               Path terminal,String nonce,String stage) throws IOException,InterruptedException {
            transport.get(vm,LabHostVmTransport.joinGuest(root,"report/completion.json",vm.platform()),terminal,Duration.ofSeconds(30));
            var completion=read(terminal,1_048_576);var result=LabHostGuest.result(completion,plan,vm.platform(),nonce,stage);
            for(var file:completion.getAsJsonArray("evidence")) {
                var entry=file.getAsJsonObject();String name=text(entry,"path");Path local=report.resolve(name);
                transport.get(vm,LabHostVmTransport.joinGuest(root,"report/"+name,vm.platform()),local,Duration.ofSeconds(30));
                require(Files.size(local)==positive(entry.get("bytes"))&&sha256(local).equals(hash(entry.get("sha256"))),"HOST_EVIDENCE_CHANGED");
            }
            writeNew(report.resolve("platform.json"),completion);
            retainFailureDiagnostics(vm,root,report,terminal.getParent());
            return cleanupRoot(vm,plan,root,report,nonce,result);
        }
        private void retainFailureDiagnostics(LabHostInputs.Vm vm,String root,Path report,Path privateDirectory) {
            try(var files=Files.list(report)) {
                var failures=files.filter(p->p.getFileName().toString().matches("gui-[0-9]{3,6}\\.json")).sorted().toList();
                for(Path file:failures) {
                    var receipt=read(file,65536);if(text(receipt,"outcome").equals("PASS"))continue;
                    String operation=uuid(receipt.get("operationId")).toString();Path directory=Files.createDirectories(privateDirectory.resolve("diagnostics"));
                    for(String suffix:List.of(".png",".controls.json",".loading-frames.json",".threads.json"))try {
                        transport.get(vm,LabHostVmTransport.joinGuest(root,"gui/private-diagnostics/"+operation+suffix,vm.platform()),directory.resolve(operation+suffix),Duration.ofSeconds(10));
                    }catch(IOException unavailable){/* Optional private diagnostics never change the public result. */}
                    break;
                }
            }catch(InterruptedException stopped){Thread.currentThread().interrupt();}
            catch(IOException|RuntimeException unavailable){/* Never print private diagnostic data. */}
        }
        private PlatformResult cleanupRoot(LabHostInputs.Vm vm,LabHostInputs.Plan plan,String root,Path report,String nonce,PlatformResult result) throws IOException {
            long began=System.nanoTime();
            var session=new LabHostGuiProtocol.Session(plan.invocationId(),vm.platform(),UUID.fromString(nonce),plan.product().sha256(),plan.helper().sha256(),report);
            var proof=LabHostGuiProtocol.identity(session);boolean removed=false;long pid=0,started=0;
            try {
                var owner=object(read(report.resolve("started.json"),4096),"version","invocationId","runNonce","pid","startedEpochMs","executable");
                require(uuid(owner.get("invocationId")).equals(plan.invocationId())&&uuid(owner.get("runNonce")).toString().equals(nonce),"HOST_CLEANUP_IDENTITY");
                pid=positive(owner.get("pid"));started=positive(owner.get("startedEpochMs"));
                if(result.cleanup()==Cleanup.COMPLETE) {
                    transport.script(vm,ownedRootCleanupScript(vm,root,plan.invocationId(),nonce,pid,started),Duration.ofSeconds(45));removed=true;
                }
            }catch(InterruptedException stopped){Thread.currentThread().interrupt();}
            catch(IOException|RuntimeException unavailable){/* Preserve fixed cleanup failure; never echo paths or private outputs. */}
            proof.addProperty("guestPid",pid);proof.addProperty("guestStartedEpochMs",started);proof.addProperty("rootRemoved",removed);
            proof.addProperty("durationMs",Duration.ofNanos(System.nanoTime()-began).toMillis());
            proof.addProperty("outcome",removed?"COMPLETE":"INCOMPLETE");writeNew(report.resolve("cleanup.json"),proof);
            return removed?result:new PlatformResult(result.platform(),result.outcome(),"HOST_RUNTIME_CLEANUP_FAILED",Cleanup.INCOMPLETE,result.unattended(),result.scenarios());
        }
        private static String javaArgument(String value) {
            require(value.chars().noneMatch(c -> c<32),"HOST_JAVA_ARGUMENT");
            return "\""+value.replace("\\","\\\\").replace("\"","\\\"")+"\"";
        }
        private static Duration remaining(long deadline,long maximumSeconds) throws LabHostVmTransport.Failure {
            long left=deadline-System.nanoTime();if(left<=0)throw new LabHostVmTransport.Failure("HOST_PLATFORM_DEADLINE");
            return Duration.ofNanos(Math.min(left,Duration.ofSeconds(maximumSeconds).toNanos()));
        }
    }
}
