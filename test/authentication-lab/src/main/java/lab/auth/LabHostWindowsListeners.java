package lab.auth;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.BooleanSupplier;
import java.util.regex.Pattern;
import static lab.auth.LabJson.*;

/** Bounded, memory-only observation of numeric Windows listener ownership. */
final class LabHostWindowsListeners {
    private LabHostWindowsListeners() {}
    static final int OUTPUT_LIMIT=1_048_576, LINE_LIMIT=512;
    static final long QUERY_TIMEOUT_MILLIS=10_000;
    private static final Pattern ROW=Pattern.compile("TCP[ \\t]+(\\S+)[ \\t]+(\\S+)[ \\t]+([A-Z_]+)[ \\t]+([0-9]{1,10})");
    private static final Pattern ENDPOINT=Pattern.compile("(?:([0-9]{1,3}(?:\\.[0-9]{1,3}){3})|\\[([0-9a-fA-F:.%]+)\\]):([0-9]{1,5})");

    static void verify(Process burp,long startedEpochMs,List<Integer> requiredPorts) throws Exception {
        BooleanSupplier identity=()->burp.isAlive()&&burp.info().startInstant()
                .map(value->value.toEpochMilli()==startedEpochMs).orElse(false);
        require(identity.getAsBoolean(),"HOST_LISTENER_IDENTITY");
        Process query;
        try {
            query=new ProcessBuilder("C:\\Windows\\System32\\netstat.exe","-ano","-p","tcp")
                    .redirectError(ProcessBuilder.Redirect.DISCARD).start();
        }catch(IOException unavailable){throw invalid("HOST_LISTENER_QUERY_START");}
        byte[] output=collect(query,QUERY_TIMEOUT_MILLIS,identity);
        Set<Integer> listeners=parse(output,burp.pid());
        require(identity.getAsBoolean(),"HOST_LISTENER_IDENTITY");
        require(listeners.containsAll(requiredPorts),"HOST_LISTENER_OWNERSHIP");
    }

    /** The deadline includes bounded output collection; no numeric table is written to disk. */
    static byte[] collect(Process query,long timeoutMillis,BooleanSupplier ownerIdentity) throws Exception {
        long deadline=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
        var reader=Executors.newSingleThreadExecutor(Thread.ofVirtual().factory());
        Future<byte[]> output=reader.submit(()->query.getInputStream().readNBytes(OUTPUT_LIMIT+1));
        try {
            while(true) {
                require(ownerIdentity.getAsBoolean(),"HOST_LISTENER_IDENTITY");
                if(output.isDone())require(result(output).length<=OUTPUT_LIMIT,"HOST_LISTENER_QUERY_OVERSIZE");
                long remaining=deadline-System.nanoTime();
                require(remaining>0,"HOST_LISTENER_QUERY_TIMEOUT");
                if(query.waitFor(Math.min(remaining,TimeUnit.MILLISECONDS.toNanos(100)),TimeUnit.NANOSECONDS))break;
            }
            require(query.exitValue()==0,"HOST_LISTENER_QUERY_EXIT");
            long remaining=deadline-System.nanoTime();
            require(remaining>0,"HOST_LISTENER_QUERY_TIMEOUT");
            byte[] bytes;
            try{bytes=output.get(remaining,TimeUnit.NANOSECONDS);}
            catch(TimeoutException expired){throw invalid("HOST_LISTENER_QUERY_TIMEOUT");}
            catch(ExecutionException unreadable){throw invalid("HOST_LISTENER_QUERY_READ");}
            require(bytes.length<=OUTPUT_LIMIT,"HOST_LISTENER_QUERY_OVERSIZE");
            require(ownerIdentity.getAsBoolean(),"HOST_LISTENER_IDENTITY");
            return bytes;
        }finally {
            // Only this directly launched numeric query is stopped; no unrelated PID is targeted.
            boolean interrupted=Thread.interrupted();
            try {
                if(query.isAlive())query.destroyForcibly();
                try{require(query.waitFor(2,TimeUnit.SECONDS),"HOST_LISTENER_QUERY_CLEANUP");}
                catch(InterruptedException stopped){interrupted=true;throw stopped;}
            }finally{
                try{query.getInputStream().close();}catch(IOException ignored){}
                output.cancel(true);reader.shutdownNow();
                try{require(reader.awaitTermination(2,TimeUnit.SECONDS),"HOST_LISTENER_QUERY_CLEANUP");}
                catch(InterruptedException stopped){interrupted=true;throw stopped;}
                finally{if(interrupted)Thread.currentThread().interrupt();}
            }
        }
    }

    private static byte[] result(Future<byte[]> output) throws InterruptedException {
        try{return output.get();}catch(ExecutionException unreadable){throw invalid("HOST_LISTENER_QUERY_READ");}
    }

    static Set<Integer> parse(byte[] output,long expectedPid) {
        require(expectedPid>0,"HOST_LISTENER_IDENTITY");
        require(output.length<=OUTPUT_LIMIT,"HOST_LISTENER_QUERY_OVERSIZE");
        var listeners=new HashSet<Integer>();var seen=new HashSet<String>();
        // Numeric rows are ASCII even when the introductory headings use the local OEM encoding.
        String table=new String(output,StandardCharsets.ISO_8859_1);
        for(String raw:table.split("\\n",-1)) {
            require(raw.length()<=LINE_LIMIT,"HOST_LISTENER_QUERY_MALFORMED");
            String line=raw.strip();
            if(!line.startsWith("TCP"))continue;
            var row=ROW.matcher(line);require(row.matches(),"HOST_LISTENER_QUERY_MALFORMED");
            var local=endpoint(row.group(1));var remote=endpoint(row.group(2));
            long pid=number(row.group(4),0,0xffff_ffffL);
            boolean listening=row.group(3).equals("LISTENING");
            if(!listening||pid!=expectedPid)continue;
            require(local.port()>0&&remote.port()==0&&Set.of("0.0.0.0","::","::ffff:0.0.0.0").contains(remote.address()),"HOST_LISTENER_QUERY_MALFORMED");
            require(seen.add(local.address()+":"+local.port()),"HOST_LISTENER_QUERY_MALFORMED");
            if(Set.of("127.0.0.1","::1","::ffff:127.0.0.1").contains(local.address()))listeners.add(local.port());
        }
        return Set.copyOf(listeners);
    }

    private record Endpoint(String address,int port) {}
    private static Endpoint endpoint(String value) {
        var match=ENDPOINT.matcher(value);require(match.matches(),"HOST_LISTENER_QUERY_MALFORMED");
        String ipv4=match.group(1),address=ipv4!=null?ipv4:match.group(2).toLowerCase(Locale.ROOT);
        if(ipv4!=null)for(String octet:ipv4.split("\\."))number(octet,0,255);
        else {
            // A colon and the closed numeric grammar prevent hostname/DNS resolution.
            require(address.contains(":")&&address.matches("[0-9a-f:.]+(?:%[0-9]+)?"),"HOST_LISTENER_QUERY_MALFORMED");
            String numeric=address.split("%",2)[0];
            try{java.net.InetAddress.getByName(numeric);}catch(java.net.UnknownHostException malformed){throw invalid("HOST_LISTENER_QUERY_MALFORMED");}
        }
        return new Endpoint(address,(int)number(match.group(3),0,65535));
    }
    private static long number(String value,long minimum,long maximum) {
        try {long number=Long.parseLong(value);require(number>=minimum&&number<=maximum,"HOST_LISTENER_QUERY_MALFORMED");return number;}
        catch(NumberFormatException malformed){throw invalid("HOST_LISTENER_QUERY_MALFORMED");}
    }
}
