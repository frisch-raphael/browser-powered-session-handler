package lab.auth;

import com.google.gson.JsonObject;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Private, bounded RSS observations of one launched Burp process; this does not establish test coverage. */
public final class LabHostMemory implements AutoCloseable {
    static final int INTERVAL_MS=200,MAX_SAMPLES=20_000,MAX_BYTES=2*1024*1024;
    // A scheduling-jitter ceiling, not a claim of hard real-time sampling.
    static final long MAX_GAP_MS=2_000;
    static final long MAX_RSS=1L<<50;
    static final String SAMPLES="memory-private.samples",STOP="memory-private.stop";
    private static final Duration STOP_BUDGET=Duration.ofSeconds(2);
    record Identity(long pid,long startedEpochMs) {
        Identity {if(pid<=0||startedEpochMs<=0)throw new IllegalArgumentException("HOST_MEMORY_IDENTITY");}
    }
    record Measurement(Identity identity,long rssBytes,long sampledEpochMs) {
        Measurement(Identity identity,long rssBytes){this(identity,rssBytes,System.currentTimeMillis());}
    }
    record Parsed(long peak,int samples,boolean overflow,boolean complete,long firstEpochMs,long lastEpochMs,long maxGapMs) {}
    @FunctionalInterface interface Sampler {Measurement sample() throws IOException;}
    @FunctionalInterface interface Pause {void pause() throws InterruptedException;}
    @FunctionalInterface interface ProcessFactory {Process start(List<String> arguments) throws IOException;}

    private final Identity identity;
    private final Path samples,stop;
    private final AtomicBoolean stopping=new AtomicBoolean();
    private final CountDownLatch finished=new CountDownLatch(1);
    private volatile boolean closed,failed,cleanStop;
    private Thread worker;
    private Process observer;
    private Process target;

    private LabHostMemory(Identity identity,Path ownedRoot) throws IOException {
        this.identity=Objects.requireNonNull(identity);
        Path absolute=ownedRoot.toAbsolutePath().normalize();
        if(Files.isSymbolicLink(absolute)||!Files.isDirectory(absolute,LinkOption.NOFOLLOW_LINKS))throw new IOException("HOST_MEMORY_ROOT");
        Path root=absolute.toRealPath();samples=root.resolve(SAMPLES);stop=root.resolve(STOP);
        if(Files.exists(stop,LinkOption.NOFOLLOW_LINKS))throw new IOException("HOST_MEMORY_EXISTS");
        Files.createFile(samples);
    }

    /** Caller supplies the Process it launched in its already validated owned run directory. */
    public static LabHostMemory start(Process burp,Path ownedRoot,String platform) throws IOException {
        Objects.requireNonNull(burp);Identity identity=identity(burp);
        LabHostMemory memory;
        if(platform.equals("linux"))memory=startSampler(identity,ownedRoot,()->{
            Identity before=identity(burp);
            if(!identity.equals(before))throw new IOException("HOST_MEMORY_IDENTITY");
            Path status=Path.of("/proc",Long.toString(identity.pid()),"status");
            long bytes=Files.size(status);if(bytes>65_536)throw new IOException("HOST_MEMORY_STATUS");
            byte[] content;
            try(var input=Files.newInputStream(status)){content=input.readNBytes(65_537);}
            if(content.length>65_536)throw new IOException("HOST_MEMORY_STATUS");
            long rss;
            try {rss=linuxRss(new String(content,StandardCharsets.US_ASCII));}
            catch(IllegalArgumentException invalid){throw new IOException("HOST_MEMORY_STATUS");}
            if(!identity.equals(identity(burp)))throw new IOException("HOST_MEMORY_IDENTITY");
            return new Measurement(identity,rss);
        },cadence(),MAX_SAMPLES);
        else if(platform.equals("windows"))memory=startWindows(identity,ownedRoot,args->new ProcessBuilder(args)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start());
        else throw new IllegalArgumentException("HOST_MEMORY_PLATFORM");
        memory.target=burp;return memory;
    }

    private static Identity identity(Process process) throws IOException {
        try {
            if(!process.isAlive())throw new IOException("HOST_MEMORY_PROCESS");
            var handle=ProcessHandle.of(process.pid()).orElseThrow(()->new IOException("HOST_MEMORY_PROCESS"));
            if(!handle.isAlive())throw new IOException("HOST_MEMORY_PROCESS");
            long started=handle.info().startInstant().orElseThrow(()->new IOException("HOST_MEMORY_IDENTITY")).toEpochMilli();
            return new Identity(process.pid(),started);
        }catch(RuntimeException unavailable){throw new IOException("HOST_MEMORY_IDENTITY");}
    }

    static LabHostMemory startSampler(Identity identity,Path root,Sampler sampler,Pause pause,int limit) throws IOException {
        if(limit<1||limit>MAX_SAMPLES)throw new IllegalArgumentException("HOST_MEMORY_LIMIT");
        var memory=new LabHostMemory(identity,root);
        memory.worker=Thread.ofPlatform().daemon().name("bpsh-host-memory").unstarted(()->memory.collect(sampler,pause,limit));
        memory.worker.start();return memory;
    }

    private void collect(Sampler sampler,Pause pause,int limit) {
        int count=0;
        try(var output=Files.newBufferedWriter(samples,StandardCharsets.US_ASCII,StandardOpenOption.WRITE)) {
            output.write(header(identity));output.flush();
            while(!stopping.get()) {
                if(count==limit){output.write("OVERFLOW "+count+"\n");failed=true;return;}
                Measurement next=sampler.sample();
                if(!identity.equals(next.identity())||!validRss(next.rssBytes())||next.sampledEpochMs()<identity.startedEpochMs())throw new IOException("HOST_MEMORY_SAMPLE");
                output.write("S "+(++count)+" "+identity.pid()+" "+identity.startedEpochMs()+" "+next.sampledEpochMs()+" "+next.rssBytes()+"\n");output.flush();
                try {pause.pause();}catch(InterruptedException stopped){if(!stopping.get())throw stopped;}
            }
            output.write("END "+count+"\n");
        }catch(IOException|RuntimeException|InterruptedException unavailable){failed=true;}
        finally {finished.countDown();}
    }

    static LabHostMemory startWindows(Identity identity,Path root,ProcessFactory factory) throws IOException {
        var memory=new LabHostMemory(identity,root);
        String encoded=Base64.getEncoder().encodeToString(windowsScript(identity,memory.samples,memory.stop).getBytes(StandardCharsets.UTF_16LE));
        try {
            memory.observer=factory.start(List.of("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "-NoProfile","-NonInteractive","-WindowStyle","Hidden","-EncodedCommand",encoded));
            memory.observer.getOutputStream().close();return memory;
        }catch(IOException|RuntimeException unavailable){
            if(memory.observer!=null&&memory.observer.isAlive()) {
                memory.observer.destroyForcibly();
                try {memory.observer.waitFor(STOP_BUDGET.toMillis(),TimeUnit.MILLISECONDS);}
                catch(InterruptedException cancelled){Thread.currentThread().interrupt();}
            }
            throw new IOException("HOST_MEMORY_OBSERVER");
        }
    }

    private static String quote(String text){return "'"+text.replace("'","''")+"'";}
    private static Pause cadence() {
        long[] next={System.nanoTime()};
        return ()->{next[0]+=TimeUnit.MILLISECONDS.toNanos(INTERVAL_MS);long remaining=next[0]-System.nanoTime();if(remaining>0)TimeUnit.NANOSECONDS.sleep(remaining);};
    }
    static String windowsScript(Identity identity,Path samples,Path stop) {
        // Exactly one observer process, and one target lookup per sample. No target command line or credentials are read.
        return "$ErrorActionPreference='Stop';$writer=$null;$count=0;$pidOwned="+identity.pid()+";$startOwned="+identity.startedEpochMs()+";"+
                "$stop="+quote(stop.toString())+";try{"+
                "$stream=[IO.File]::Open("+quote(samples.toString())+",[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::Read);"+
                "$writer=[IO.StreamWriter]::new($stream,[Text.Encoding]::ASCII);$writer.NewLine=\"`n\";$writer.Write("+quote(header(identity))+");$writer.Flush();$clock=[Diagnostics.Stopwatch]::StartNew();$next=0L;"+
                "while($true){"+
                "if(Test-Path -LiteralPath $stop){if((Get-Item -LiteralPath $stop).Length -ne 5 -or [IO.File]::ReadAllText($stop) -ne \"STOP`n\"){throw 'INVALID'};$writer.WriteLine('END '+$count);break};"+
                "if($count -ge "+MAX_SAMPLES+"){$writer.WriteLine('OVERFLOW '+$count);break};"+
                "$p=Get-Process -Id $pidOwned -ErrorAction Stop;$p.Refresh();"+
                "$actual=([DateTimeOffset]$p.StartTime.ToUniversalTime()).ToUnixTimeMilliseconds();"+
                "if($p.Id -ne $pidOwned -or $actual -ne $startOwned -or $p.HasExited){throw 'INVALID'};"+
                "$rss=[long]$p.WorkingSet64;if($rss -le 0 -or $rss -gt "+MAX_RSS+"){throw 'INVALID'};"+
                "$now=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();if($now -lt $startOwned){throw 'INVALID'};"+
                "$count++;$line='S '+$count+' '+$pidOwned+' '+$startOwned+' '+$now+' '+$rss;"+
                "if($stream.Position+$line.Length+128 -gt "+MAX_BYTES+"){$writer.WriteLine('OVERFLOW '+($count-1));break};"+
                "$writer.WriteLine($line);$writer.Flush();$next+="+INTERVAL_MS+";$remaining=$next-$clock.ElapsedMilliseconds;if($remaining -gt 0){Start-Sleep -Milliseconds $remaining}}"+
                "}catch{if($writer){$writer.WriteLine('INVALID')}}finally{if($writer){$writer.Dispose()}}";
    }

    private static String header(Identity identity){return "BPSH_MEMORY_V1 "+identity.pid()+" "+identity.startedEpochMs()+" "+INTERVAL_MS+"\n";}
    private static boolean validRss(long rss){return rss>0&&rss<=MAX_RSS;}
    static long linuxRss(String text) {
        if(text.length()>65_536)throw new IllegalArgumentException("HOST_MEMORY_STATUS");
        if(java.util.regex.Pattern.compile("(?m)^VmRSS:").matcher(text).results().count()!=1)throw new IllegalArgumentException("HOST_MEMORY_STATUS");
        var matches=java.util.regex.Pattern.compile("(?m)^VmRSS:[ \\t]+([0-9]+)[ \\t]+kB$").matcher(text);
        if(!matches.find())throw new IllegalArgumentException("HOST_MEMORY_STATUS");
        long value;
        try {value=Math.multiplyExact(Long.parseLong(matches.group(1)),1024);}
        catch(ArithmeticException|NumberFormatException invalid){throw new IllegalArgumentException("HOST_MEMORY_STATUS");}
        if(matches.find()||!validRss(value))throw new IllegalArgumentException("HOST_MEMORY_STATUS");return value;
    }

    static Parsed parse(Path samples,Identity identity) {
        long peak=0,first=0,last=0,gap=0;int count=0;boolean overflow=false;
        try {
            if(Files.isSymbolicLink(samples)||!Files.isRegularFile(samples,LinkOption.NOFOLLOW_LINKS))return new Parsed(0,0,false,false,0,0,0);
            if(Files.size(samples)>MAX_BYTES)return new Parsed(0,0,true,false,0,0,0);
            byte[] bytes;
            try(var input=Files.newInputStream(samples)){bytes=input.readNBytes(MAX_BYTES+1);}
            if(bytes.length>MAX_BYTES)return new Parsed(0,0,true,false,0,0,0);
            String text=new String(bytes,StandardCharsets.US_ASCII);
            if(!text.endsWith("\n"))return new Parsed(0,0,false,false,0,0,0);
            String[] lines=text.split("\n",-1);if(lines.length<3||!lines[0].equals(header(identity).stripTrailing()))return new Parsed(0,0,false,false,0,0,0);
            boolean terminal=false,complete=false;
            for(int i=1;i<lines.length-1;i++) {
                String line=lines[i];if(line.length()>128||terminal)return new Parsed(peak,count,overflow,false,first,last,gap);
                if(line.matches("(?:END|OVERFLOW) [0-9]+")) {
                    String[] fields=line.split(" ");long expected=Long.parseLong(fields[1]);
                    overflow=fields[0].equals("OVERFLOW");terminal=true;complete=!overflow&&expected==count&&count>0;
                    if(expected!=count)return new Parsed(peak,count,overflow,false,first,last,gap);
                }else {
                    if(!line.matches("S [0-9]+ [0-9]+ [0-9]+ [0-9]+ [0-9]+"))return new Parsed(peak,count,overflow,false,first,last,gap);
                    String[] fields=line.split(" ");long sequence=Long.parseLong(fields[1]),pid=Long.parseLong(fields[2]),started=Long.parseLong(fields[3]),sampled=Long.parseLong(fields[4]),rss=Long.parseLong(fields[5]);
                    if(sequence!=count+1||pid!=identity.pid()||started!=identity.startedEpochMs()||sampled<started||sampled<last||!validRss(rss))return new Parsed(peak,count,overflow,false,first,last,gap);
                    gap=Math.max(gap,count>0?sampled-last:0);
                    if(count==MAX_SAMPLES)return new Parsed(peak,count,true,false,first,last,gap);count++;peak=Math.max(peak,rss);if(count==1)first=sampled;last=sampled;
                }
            }
            return new Parsed(peak,count,overflow,terminal&&complete&&gap<=MAX_GAP_MS,first,last,gap);
        }catch(IOException|RuntimeException unavailable){return new Parsed(peak,count,overflow,false,first,last,gap);}
    }

    /** False complete is deliberately unusable as successful memory evidence, including before close. */
    public JsonObject summary() {
        Parsed parsed=parse(samples,identity);var result=new JsonObject();result.addProperty("version",1);
        result.addProperty("pid",identity.pid());result.addProperty("startedEpochMs",identity.startedEpochMs());result.addProperty("intervalMs",INTERVAL_MS);
        result.addProperty("peakRssBytes",parsed.peak());result.addProperty("samples",parsed.samples());result.addProperty("overflow",parsed.overflow());
        result.addProperty("firstSampleEpochMs",parsed.firstEpochMs());result.addProperty("lastSampleEpochMs",parsed.lastEpochMs());result.addProperty("maxSampleGapMs",parsed.maxGapMs());
        result.addProperty("complete",closed&&cleanStop&&!failed&&parsed.complete());return result;
    }

    /** Numeric observations only; GC log text, classes and addresses stay private. */
    public static JsonObject gcSummary(Path root) {
        try {
            Path log=root.resolve("gc-private.log");
            if(Files.exists(root.resolve("gc-private.log.0"))||!Files.isRegularFile(log,LinkOption.NOFOLLOW_LINKS)||Files.size(log)>8L*1024*1024)
                return gcNumbers("",false);
            try(var input=Files.newInputStream(log)) {
                byte[] bytes=input.readNBytes(8*1024*1024+1);
                return gcNumbers(new String(bytes,StandardCharsets.US_ASCII),bytes.length<=8*1024*1024);
            }
        }catch(IOException|RuntimeException unavailable){return gcNumbers("",false);}
    }
    static JsonObject gcNumbers(String text,boolean complete) {
        text=text.replace("\r\n","\n");
        long maximum=0,peak=0;int observations=0;var collections=new HashMap<Long,Map<Long,Long>>();
        var pattern=java.util.regex.Pattern.compile("GC\\(([0-9]{1,10})\\).*?Humongous region ([0-9]{1,10}).*?object size ([0-9]{1,12})");
        var prefix=java.util.regex.Pattern.compile("^\\[[0-9]+ms\\]\\[(?:debug|info|trace|warning|error)\\s*\\]\\[gc(?:,[a-z]+)*\\s*\\] .*");
        if(text.isEmpty()||text.length()>8*1024*1024||!text.endsWith("\n"))complete=false;
        try {
            for(String line:text.split("\n")) {
                if(line.length()>4096||!prefix.matcher(line).matches())throw new IllegalArgumentException();
                var match=pattern.matcher(line);
                if(!match.find()){if(line.contains("Humongous region "))throw new IllegalArgumentException();continue;}
                long gc=Long.parseLong(match.group(1)),region=Long.parseLong(match.group(2)),size=Long.parseLong(match.group(3));
                if(size<=0||size>(16L<<30)||++observations>100000)throw new IllegalArgumentException();
                var objects=collections.computeIfAbsent(gc,ignored->new HashMap<>());
                Long old=objects.putIfAbsent(region,size);if(old!=null&&old.longValue()!=size)throw new IllegalArgumentException();
                if(collections.size()>4096)throw new IllegalArgumentException();maximum=Math.max(maximum,size);
            }
            for(var objects:collections.values()){long total=0;for(long size:objects.values())total=Math.addExact(total,size);peak=Math.max(peak,total);}
        }catch(RuntimeException malformed){complete=false;}
        var result=new JsonObject();result.addProperty("complete",complete);result.addProperty("objectObservations",observations);
        result.addProperty("gcObservations",collections.size());result.addProperty("maxObservedObjectBytes",maximum);result.addProperty("peakObservedHumongousBytes",peak);return result;
    }

    boolean awaitFinished(Duration timeout) throws InterruptedException {return finished.await(timeout.toMillis(),TimeUnit.MILLISECONDS);}
    /** Cleanup state only; stopped observers can still have incomplete or invalid evidence. */
    public boolean stopped(){return closed&&(worker==null||!worker.isAlive())&&(observer==null||!observer.isAlive());}

    @Override public synchronized void close() {
        if(closed)return;boolean interrupted=Thread.interrupted();if(interrupted)failed=true;
        if(target!=null)try {if(!identity.equals(identity(target)))failed=true;}catch(IOException unavailable){failed=true;}
        stopping.set(true);
        try {
            if(worker!=null) {
                worker.join(STOP_BUDGET.toMillis());cleanStop=!worker.isAlive();
            }else if(observer!=null) {
                if(!observer.isAlive())failed=true;
                try {Files.writeString(stop,"STOP\n",StandardCharsets.US_ASCII,StandardOpenOption.CREATE_NEW);}
                catch(IOException|RuntimeException unavailable){failed=true;}
                cleanStop=observer.waitFor(STOP_BUDGET.toMillis(),TimeUnit.MILLISECONDS);
                if(cleanStop&&observer.exitValue()!=0)failed=true;
            }
        }catch(InterruptedException cancelled){interrupted=true;failed=true;}
        finally {
            if(observer!=null&&observer.isAlive()) {
                failed=true;observer.destroyForcibly();
                try {if(!observer.waitFor(STOP_BUDGET.toMillis(),TimeUnit.MILLISECONDS))cleanStop=false;}
                catch(InterruptedException cancelled){interrupted=true;cleanStop=false;}
            }
            if(worker!=null&&worker.isAlive()){failed=true;worker.interrupt();}
            if(observer!=null)finished.countDown();closed=true;if(interrupted)Thread.currentThread().interrupt();
        }
    }
}
