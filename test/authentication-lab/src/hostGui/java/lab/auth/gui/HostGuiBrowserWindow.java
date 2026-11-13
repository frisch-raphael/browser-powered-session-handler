package lab.auth.gui;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;
import static lab.auth.gui.HostGuiSelectors.*;

/** Native keyboard gate for one newly observed descendant Burp Browser window. */
final class HostGuiBrowserWindow implements AutoCloseable {
    record Identity(long pid,Instant started) {}
    private final Identity expected;
    private final Supplier<Identity> current;
    private final LongSupplier foreground;
    private final Runnable activate;
    private final Supplier<String> version;
    private final AutoCloseable resource;
    HostGuiBrowserWindow(Identity expected,Supplier<Identity> current,LongSupplier foreground,Runnable activate) {
        this(expected,current,foreground,activate,()->"0.0.0",()->{});
    }
    private HostGuiBrowserWindow(Identity expected,Supplier<Identity> current,LongSupplier foreground,Runnable activate,Supplier<String> version,AutoCloseable resource) {
        this.expected=expected;this.current=current;this.foreground=foreground;this.activate=activate;this.version=version;this.resource=resource;
    }
    static HostGuiBrowserWindow owned(ProcessHandle browser,Path temporary) {
        Identity identity=identity(browser);boolean descendant;
        try(var children=ProcessHandle.current().descendants()){descendant=children.anyMatch(child->child.pid()==identity.pid());}
        if(!descendant)throw new Failure("GUI_BROWSER_NOT_OWNED");
        String executable=browser.info().command().orElseThrow(()->new Failure("GUI_BROWSER_METADATA"));
        if(!executable.replace('\\','/').toLowerCase(Locale.ROOT).matches(".*/burpbrowser/[0-9]+(?:\\.[0-9]+){2,3}/chrome(?:\\.exe)?"))throw new Failure("GUI_BROWSER_METADATA");
        if(System.getProperty("os.name").startsWith("Windows")) {
            var query=windows(identity.pid(),executable,temporary);
            return new HostGuiBrowserWindow(identity,()->identity(browser),()->pid(query.ask("Q")),()->{
                if(!query.ask("A").equals("OK"))throw new Failure("GUI_BROWSER_ACTIVATE");
            },()->query.ask("V"),query);
        }
        return new HostGuiBrowserWindow(identity,()->identity(browser),()->pid(run(List.of("xdotool","getactivewindow","getwindowpid"))),()->{
            String window=run(List.of("xdotool","search","--onlyvisible","--pid",Long.toString(identity.pid())));
            if(!window.matches("[1-9][0-9]{0,18}"))throw new Failure("GUI_BROWSER_WINDOW_AMBIGUOUS");
            run(List.of("xdotool","windowactivate","--sync",window));
        },()->{
            var matched=java.util.regex.Pattern.compile("(?<![0-9.])([0-9]+(?:\\.[0-9]+){3})(?![0-9.])").matcher(run(List.of(executable,"--version")));
            if(!matched.find())throw new Failure("GUI_BROWSER_VERSION");return matched.group(1);
        },()->{});
    }
    private static Identity identity(ProcessHandle process) {
        if(!process.isAlive())throw new Failure("GUI_BROWSER_EXITED");
        return new Identity(process.pid(),process.info().startInstant().orElseThrow(()->new Failure("GUI_BROWSER_METADATA")));
    }
    void focus(){requireIdentity();activate.run();requireForeground();}
    void requireForeground(){requireIdentity();if(foreground.getAsLong()!=expected.pid())throw new Failure("GUI_BROWSER_FOCUS");requireIdentity();}
    String version(){requireIdentity();String value=version.get();if(!value.matches("[0-9]{1,9}(?:\\.[0-9]{1,9}){2,3}"))throw new Failure("GUI_BROWSER_VERSION");return value;}
    private void requireIdentity(){if(!expected.equals(current.get()))throw new Failure("GUI_BROWSER_IDENTITY");}
    private static long pid(String text) {
        if(!text.matches("0|[1-9][0-9]{0,18}"))throw new Failure("GUI_BROWSER_FOCUS");
        try{return Long.parseLong(text);}catch(NumberFormatException invalid){throw new Failure("GUI_BROWSER_FOCUS");}
    }
    private static HostGuiNativeQuery windows(long pid,String executable,Path temporary) {
        String script="""
                $ErrorActionPreference='Stop';
                Add-Type 'using System;using System.Runtime.InteropServices;public static class OwnedForeground{[DllImport("user32.dll")]public static extern IntPtr GetForegroundWindow();[DllImport("user32.dll")]public static extern uint GetWindowThreadProcessId(IntPtr window,out uint pid);}';
                $browserProcessId=%d;$browserExecutable='%s';$nativeShell=New-Object -ComObject WScript.Shell;
                while($null -ne ($request=[Console]::ReadLine())) {
                    switch($request) {
                        'Q' {[uint32]$foregroundProcessId=0;[void][OwnedForeground]::GetWindowThreadProcessId([OwnedForeground]::GetForegroundWindow(),[ref]$foregroundProcessId);[Console]::WriteLine($foregroundProcessId)}
                        'A' {if($nativeShell.AppActivate($browserProcessId)){[Console]::WriteLine('OK')}else{[Console]::WriteLine('NO')}}
                        'V' {$info=[Diagnostics.FileVersionInfo]::GetVersionInfo($browserExecutable);[Console]::WriteLine(('{0}.{1}.{2}.{3}' -f $info.FileMajorPart,$info.FileMinorPart,$info.FileBuildPart,$info.FilePrivatePart))}
                        default {exit 3}
                    }
                    [Console]::Out.Flush()
                }
                """.formatted(pid,executable.replace("'","''"));
        try {
            Path owned=temporary.toRealPath();
            var builder=new ProcessBuilder("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","-NoProfile","-NonInteractive","-WindowStyle","Hidden","-EncodedCommand",Base64.getEncoder().encodeToString(script.getBytes(StandardCharsets.UTF_16LE))).redirectError(ProcessBuilder.Redirect.DISCARD);
            builder.environment().put("TEMP",owned.toString());builder.environment().put("TMP",owned.toString());
            return new HostGuiNativeQuery(builder.start(),5000);
        }catch(IOException unavailable){throw new Failure("GUI_BROWSER_NATIVE_QUERY");}
    }
    private static String run(List<String> arguments) {
        try(var readers=Executors.newVirtualThreadPerTaskExecutor()) {
            Process process=null;
            try {
                process=new ProcessBuilder(arguments).redirectError(ProcessBuilder.Redirect.DISCARD).start();var input=process.getInputStream();
                var output=readers.submit(()->input.readNBytes(257));
                if(!process.waitFor(5,TimeUnit.SECONDS)||process.exitValue()!=0)throw new Failure("GUI_BROWSER_NATIVE_QUERY");
                byte[] bytes=output.get(1,TimeUnit.SECONDS);if(bytes.length>256)throw new Failure("GUI_BROWSER_NATIVE_QUERY");return new String(bytes,StandardCharsets.UTF_8).trim();
            }finally{if(process!=null&&process.isAlive())process.destroyForcibly();}
        }catch(IOException|ExecutionException|TimeoutException failed){throw new Failure("GUI_BROWSER_NATIVE_QUERY");}
        catch(InterruptedException stopped){Thread.currentThread().interrupt();throw new Failure("GUI_CANCELLED");}
    }
    @Override public void close(){try{resource.close();}catch(RuntimeException failed){throw failed;}catch(Exception failed){throw new Failure("GUI_BROWSER_QUERY_CLEANUP");}}
}
