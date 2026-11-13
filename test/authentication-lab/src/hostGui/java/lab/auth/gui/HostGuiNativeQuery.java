package lab.auth.gui;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.*;
import static lab.auth.gui.HostGuiSelectors.*;

/** Bounded request/reply channel to one owned native foreground metadata monitor. */
final class HostGuiNativeQuery implements AutoCloseable {
    private final Process process;
    private final long timeoutMs;
    private final ExecutorService reader=Executors.newVirtualThreadPerTaskExecutor();
    private boolean closed;
    HostGuiNativeQuery(Process process,long timeoutMs) {
        this.process=process;this.timeoutMs=timeoutMs;
        if(timeoutMs<1||timeoutMs>5000)throw new IllegalArgumentException("GUI_BROWSER_QUERY_BUDGET");
    }
    synchronized String ask(String command) {
        if(closed||!Set.of("Q","A","V").contains(command))throw new Failure("GUI_BROWSER_NATIVE_QUERY");
        try {
            process.getOutputStream().write((command+"\n").getBytes(StandardCharsets.US_ASCII));process.getOutputStream().flush();
            return reader.submit(()->line(process.getInputStream())).get(timeoutMs,TimeUnit.MILLISECONDS);
        }catch(InterruptedException stopped) {
            Thread.currentThread().interrupt();close();throw new Failure("GUI_CANCELLED");
        }catch(IOException|ExecutionException|TimeoutException failed) {close();throw new Failure("GUI_BROWSER_NATIVE_QUERY");}
    }
    private static String line(InputStream input) throws IOException {
        var bytes=new ByteArrayOutputStream(64);
        while(true) {
            int value=input.read();if(value<0)throw new EOFException();
            if(value=='\n')break;
            if(value=='\r'){if(input.read()!='\n')throw new IOException("Invalid native reply.");break;}
            if(value<32||value>126||bytes.size()==64)throw new IOException("Invalid native reply.");
            bytes.write(value);
        }
        if(bytes.size()==0)throw new IOException("Missing native reply.");
        return bytes.toString(StandardCharsets.US_ASCII);
    }
    @Override public synchronized void close() {
        if(closed)return;closed=true;boolean interrupted=Thread.interrupted(),stopped=false;
        try {
            try{process.getOutputStream().close();}catch(IOException ignored){}
            try{stopped=process.waitFor(200,TimeUnit.MILLISECONDS);}catch(InterruptedException cancelled){interrupted=true;}
            if(!stopped)process.destroyForcibly();
            try{stopped=process.waitFor(2,TimeUnit.SECONDS);}catch(InterruptedException cancelled){interrupted=true;}
            try{process.getInputStream().close();}catch(IOException ignored){}
            reader.shutdownNow();
            try{stopped&=reader.awaitTermination(2,TimeUnit.SECONDS);}catch(InterruptedException cancelled){interrupted=true;}
            if(!stopped)throw new Failure("GUI_BROWSER_QUERY_CLEANUP");
        }finally{if(interrupted)Thread.currentThread().interrupt();}
    }
}
