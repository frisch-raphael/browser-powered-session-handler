package lab.auth;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

class LabHostVmTransportTest {
    private static final String SECRET="SENSITIVE_VM_SENTINEL_$()`";
    @TempDir Path directory;
    private LabHostInputs.Vm vm(String platform) {
        return new LabHostInputs.Vm(platform,directory.resolve("helper.py"),"C:/bpsh/host-tests","java","lab-java","burp.jar","preferences.json",":0");
    }
    @Test void exceptionsNeverRetainSecretArgumentsOrCauses() {
        var transport=new LabHostVmTransport((args,budget)->{throw new IOException(SECRET+args);});
        var error=assertThrows(LabHostVmTransport.Failure.class,()->transport.script(vm("linux"),SECRET,Duration.ofSeconds(1)));
        var output=new StringWriter();error.printStackTrace(new PrintWriter(output));
        assertEquals("VM_OPERATION_FAILED",error.code());assertNull(error.getCause());assertFalse(output.toString().contains(SECRET));
    }
    @Test void windowsUsesHiddenEncodedScriptAndLinuxUsesExistingHelper() throws Exception {
        var arguments=new AtomicReference<List<String>>();var transport=new LabHostVmTransport((args,budget)->arguments.set(args));
        transport.script(vm("windows"),SECRET,Duration.ofSeconds(1));var windows=arguments.get();
        assertTrue(windows.contains("Hidden"));assertTrue(windows.contains("-EncodedCommand"));
        assertFalse(windows.contains("-interactive"));
        assertEquals(SECRET,new String(Base64.getDecoder().decode(windows.getLast()),StandardCharsets.UTF_16LE));
        transport.interactiveScript(vm("windows"),SECRET,Duration.ofSeconds(1));assertTrue(arguments.get().contains("-interactive"));
        transport.script(vm("linux"),"true",Duration.ofSeconds(1));assertEquals(List.of("python",directory.resolve("helper.py").toString(),"run","printf %s dHJ1ZQ== | base64 --decode | /bin/bash"),arguments.get());
    }
    @Test void linuxScriptQuotesAndMetacharactersSurviveWindowsArgumentDeliveryAsData() throws Exception {
        String script="printf '%s' '{\"version\":1,\"private\":\"$()`\\\\\"}'\nprintf '%s' 'PRIVATE_SENTINEL'";
        var arguments=new AtomicReference<List<String>>();var transport=new LabHostVmTransport((args,budget)->arguments.set(args));
        transport.script(vm("linux"),script,Duration.ofSeconds(1));String command=arguments.get().getLast();
        assertFalse(command.contains("\""));assertFalse(command.contains("'"));assertFalse(command.contains("PRIVATE_SENTINEL"));
        assertEquals(script,new String(Base64.getDecoder().decode(command.split(" ")[2]),StandardCharsets.UTF_8));
    }
    @Test void largeArtifactTransferHasItsOwnFiniteBudget() throws Exception {
        var budget=new AtomicReference<Duration>();var transport=new LabHostVmTransport((args,timeout)->budget.set(timeout));
        transport.put(vm("windows"),directory.resolve("artifact.jar"),"C:/owned/artifact.jar",Duration.ofMinutes(10));
        assertEquals(Duration.ofMinutes(10),budget.get());
        assertThrows(IllegalArgumentException.class,()->transport.script(vm("windows"),"true",Duration.ofMinutes(10)));
        assertThrows(IllegalArgumentException.class,()->transport.put(vm("windows"),directory.resolve("artifact.jar"),"C:/owned/artifact.jar",Duration.ofMinutes(11)));
    }
    @Test void processStatusRejectsReusedIdentityWithoutTouchingTheProcess() throws Exception {
        String java=Path.of(System.getProperty("java.home"),"bin",System.getProperty("os.name").startsWith("Windows")?"java.exe":"java").toString();
        String classes=Path.of(Child.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        String marker="-Dlab.host.runNonce="+UUID.randomUUID();
        Path ready=directory.resolve("child-ready");
        var child=new ProcessBuilder(java,marker,"-cp",classes,Child.class.getName(),"hold","--ready="+ready).redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        long started=child.info().startInstant().orElseThrow().toEpochMilli();
        try {
            long deadline=System.nanoTime()+Duration.ofSeconds(5).toNanos();while(!Files.exists(ready)&&System.nanoTime()<deadline)Thread.sleep(10);
            assertTrue(Files.exists(ready),"The owned child must finish startup before querying its identity.");
            assertTrue(LabHostGuest.owns(child.pid(),started,java,marker));
            assertFalse(LabHostGuest.owns(child.pid(),started+1,java,marker));
            assertFalse(LabHostGuest.owns(child.pid(),started,java,"-Dlab.host.runNonce="+UUID.randomUUID()));
            assertFalse(LabHostGuest.owns(child.pid(),started,directory.resolve("other-java").toString(),marker));
            assertTrue(child.isAlive());
        }finally{child.destroyForcibly();child.waitFor(5,TimeUnit.SECONDS);}
        assertFalse(LabHostGuest.owns(child.pid(),started,java,marker));
    }
    @Test void realChildFailureAndTimeoutCannotExposeItsOutputOrArgumentList() throws Exception {
        String java=Path.of(System.getProperty("java.home"),"bin",System.getProperty("os.name").startsWith("Windows")?"java.exe":"java").toString();
        String classes=Path.of(Child.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        var failure=assertThrows(LabHostVmTransport.Failure.class,()->LabHostVmTransport.runPrivate(List.of(java,"-cp",classes,Child.class.getName(),SECRET),Duration.ofSeconds(5)));
        assertEquals("VM_OPERATION_FAILED",failure.code());assertFalse(failure.toString().contains(SECRET));assertNull(failure.getCause());
        var timeout=assertThrows(LabHostVmTransport.Failure.class,()->LabHostVmTransport.runPrivate(List.of(java,"-cp",classes,Child.class.getName(),"hold",SECRET),Duration.ofMillis(200)));
        assertEquals("VM_OPERATION_TIMEOUT",timeout.code());assertFalse(timeout.toString().contains(SECRET));assertNull(timeout.getCause());
    }
    public static class Child {
        public static void main(String[] args) throws Exception {
            System.out.println(SECRET);System.err.println(SECRET);
            if(args.length>1&&args[1].startsWith("--ready="))Files.writeString(Path.of(args[1].substring(8)),"ready");
            if(args[0].equals("hold"))Thread.sleep(args.length>1&&args[1].startsWith("--ready=")?30_000:10_000);System.exit(6);
        }
    }
}
