package lab.auth;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.*;
import static lab.auth.LabHostCoordinator.*;
import static org.junit.jupiter.api.Assertions.*;

class LabHostCoordinatorTest {
    @TempDir Path directory;
    @Test void aggregatePreservesAssertionFailuresCancellationAndIncompleteCleanup() {
        var failed=new PlatformResult("windows",Outcome.FAIL,"ASSERTION_FAILED",Cleanup.COMPLETE,true,Map.of());
        var cancelled=new PlatformResult("linux",Outcome.INTERRUPTED,"HOST_CANCELLED",Cleanup.COMPLETE,true,Map.of());
        assertEquals(Outcome.FAIL,aggregateOutcome(List.of(failed,passed("linux"))));
        assertEquals(Outcome.INTERRUPTED,aggregateOutcome(List.of(failed,cancelled)));
        assertEquals(Outcome.BLOCKED,aggregateOutcome(List.of(new PlatformResult("windows",Outcome.PASS,"VERIFIED",Cleanup.INCOMPLETE,true,Map.of()))));
        assertEquals(Outcome.BLOCKED,aggregateOutcome(List.of()));
        assertEquals(Outcome.PASS,aggregateOutcome(List.of(passed("windows"),passed("linux"))));
    }
    @Test void cleanupRejectsAnyRootOutsideTheExactOwnedInvocationBeforeExecution() {
        var id=UUID.randomUUID();String nonce=UUID.randomUUID().toString();var vm=vms().get("windows");
        assertThrows(IllegalArgumentException.class,()->ownedRootCleanupScript(vm,"C:\\other",id,nonce,99999999,1000));
        assertThrows(IllegalArgumentException.class,()->ownedRootCleanupScript(vm,vm.guestRoot(),id,nonce,99999999,1000));
    }
    @Test @org.junit.jupiter.api.condition.EnabledOnOs(org.junit.jupiter.api.condition.OS.WINDOWS)
    void nativeCleanupRemovesOnlyADeadOwnersExactTreeAndRejectsForeignOwnership() throws Exception {
        var id=UUID.randomUUID();String nonce=UUID.randomUUID().toString();Path base=Files.createDirectory(directory.resolve("roots"));
        var vm=new LabHostInputs.Vm("windows",directory.resolve("helper"),base.toString(),"java","java","burp","prefs",null);
        Path root=Path.of(LabHostVmTransport.joinGuest(vm.guestRoot(),id+"-"+nonce.substring(0,8),"windows"));
        Files.createDirectories(root.resolve("report"));Path unrelated=Files.writeString(base.resolve("unrelated"),"PRIVATE_SENTINEL");
        var owner=new LinkedHashMap<String,Object>();owner.put("version",1);owner.put("invocationId",id.toString());owner.put("platform","windows");owner.put("runNonce",UUID.randomUUID().toString());owner.put("guestRoot",root.toString());
        Files.writeString(root.resolve("owner.json"),LabRun.JSON.toJson(owner));
        LabJson.writeNew(root.resolve("report/started.json"),Map.of("version",1,"invocationId",id.toString(),"runNonce",nonce,"pid",99999999,"startedEpochMs",1000,"executable","java"));
        String script=ownedRootCleanupScript(vm,root.toString(),id,nonce,99999999,1000);
        assertNotEquals(0,executeCleanup(script));assertTrue(Files.isDirectory(root));assertTrue(Files.exists(unrelated));
        owner.put("runNonce",nonce);Files.writeString(root.resolve("owner.json"),LabRun.JSON.toJson(owner));
        Path longDirectory=root;
        while(longDirectory.toString().length()<300)longDirectory=longDirectory.resolve("long-component-"+"x".repeat(45));
        Files.createDirectories(longDirectory);Path longFile=Files.writeString(longDirectory.resolve("payload.txt"),"PRIVATE_LONG_PATH_CONTENT");
        assertTrue(longDirectory.toString().length()>259);assertTrue(longFile.toString().length()>259);
        assertEquals(0,executeCleanup(script));assertFalse(Files.exists(root));assertEquals("PRIVATE_SENTINEL",Files.readString(unrelated));
    }
    private int executeCleanup(String script) throws Exception {
        String encoded=Base64.getEncoder().encodeToString(script.getBytes(java.nio.charset.StandardCharsets.UTF_16LE));
        var process=new ProcessBuilder("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","-NoProfile","-WindowStyle","Hidden","-EncodedCommand",encoded)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        try{assertTrue(process.waitFor(15,java.util.concurrent.TimeUnit.SECONDS));return process.exitValue();}
        finally{if(process.isAlive())process.destroyForcibly();}
    }
    @Test void unavailableOwnershipMetadataDoesNotMeanTheProcessExited() throws Exception {
        var process=ProcessHandle.current();var info=process.info();long started=info.startInstant().orElseThrow().toEpochMilli();
        var unavailable=LabHostGuest.processStatus(process.pid(),started,directory.resolve("missing-java").toString(),"-Dlab.host.runNonce="+UUID.randomUUID());
        assertTrue(unavailable.alive());assertEquals("UNVERIFIED",unavailable.ownership());
        var changed=LabHostGuest.processStatus(process.pid(),started+1,info.command().orElseThrow(),"missing-marker");
        assertTrue(changed.alive());assertEquals("CHANGED",changed.ownership());
    }
    @Test void partialArgumentsStillAllowPositiveOsMarkerProofButNeverInventIt() {
        var calls=new AtomicInteger();
        assertTrue(LabHostGuest.markerVisible(Optional.of(new String[]{"partial"}),"expected",()->{calls.incrementAndGet();return true;}));
        assertEquals(1,calls.get());
        assertFalse(LabHostGuest.markerVisible(Optional.of(new String[0]),"expected",()->false));
        assertTrue(LabHostGuest.markerVisible(Optional.of(new String[]{"expected"}),"expected",()->{fail("Direct proof should avoid a second query");return false;}));
    }
    @Test void finalCompletionFetchAfterExitCanRecoverTheAlreadyWrittenResult() throws Exception {
        var calls=new AtomicInteger();var expected=passed("windows");
        assertSame(expected,finalCompletion(()->{calls.incrementAndGet();return expected;}));assertEquals(1,calls.get());
        var failed=assertThrows(LabHostVmTransport.Failure.class,()->finalCompletion(()->{throw new LabHostVmTransport.Failure("PRIVATE_SENTINEL");}));
        assertEquals("HOST_GUEST_EXITED_WITHOUT_RESULT",failed.code());assertNull(failed.getCause());
    }
    private Map<String,LabHostInputs.Vm> vms() {
        var result=new HashMap<String,LabHostInputs.Vm>();
        for(String platform:LabHostInputs.PLATFORMS)result.put(platform,new LabHostInputs.Vm(platform,directory.resolve("fake.py"),"owned","java","lab-java","burp","prefs",":0"));
        return result;
    }
    private static PlatformResult passed(String platform) {
        var scenarios=new LinkedHashMap<String,Outcome>();LabHostInputs.SCENARIOS.forEach(id->scenarios.put(id,Outcome.PASS));
        return new PlatformResult(platform,Outcome.PASS,"VERIFIED",Cleanup.COMPLETE,true,scenarios);
    }
    @Test void bothPlatformResultsRetainTheirOrderAndMissingOrIncompleteProofCannotPass() throws Exception {
        var plan=LabHostInputs.plan(LabHostInputsTest.fixture(directory,LabHostInputs.Mode.QUALIFICATION));var order=new java.util.concurrent.ConcurrentLinkedQueue<String>();
        var coordinator=new LabHostCoordinator((vm,p,report,stage,cancel)->{order.add(vm.platform());return passed(vm.platform());});
        assertEquals(0,coordinator.execute(plan,vms(),directory.resolve("reports"),"scenarios",new AtomicBoolean()));
        assertEquals("PASS",LabJson.read(directory.resolve("reports/completion.json"),65536).get("outcome").getAsString());
        assertEquals(new HashSet<>(LabHostInputs.PLATFORMS),new HashSet<>(order));
        assertFalse(complete(LabHostInputs.PLATFORMS,List.of(passed("windows")),"scenarios"));
        assertFalse(complete(LabHostInputs.PLATFORMS,List.of(passed("linux"),passed("windows")),"scenarios"));
        assertFalse(complete(List.of("windows"),List.of(new PlatformResult("windows",Outcome.PASS,"OK",Cleanup.COMPLETE,false,passed("windows").scenarios())),"scenarios"));
        assertFalse(complete(List.of("windows"),List.of(new PlatformResult("windows",Outcome.PASS,"OK",Cleanup.INCOMPLETE,true,passed("windows").scenarios())),"scenarios"));
        assertFalse(complete(List.of("windows"),List.of(new PlatformResult("windows",Outcome.PASS,"OK",Cleanup.COMPLETE,true,Map.of())),"scenarios"));
    }
    @Test void privateFailureRetainsTruthfulOutcomeAndStillAttemptsOtherPlatform() throws Exception {
        var plan=LabHostInputs.plan(LabHostInputsTest.fixture(directory,LabHostInputs.Mode.QUALIFICATION));var order=new java.util.concurrent.ConcurrentLinkedQueue<String>();
        var coordinator=new LabHostCoordinator((vm,p,report,stage,cancel)->{order.add(vm.platform());if(vm.platform().equals("windows"))throw new IOException("SECRET_SENTINEL");return passed(vm.platform());});
        Path reports=directory.resolve("reports");assertEquals(3,coordinator.execute(plan,vms(),reports,"scenarios",new AtomicBoolean()));
        assertEquals(new HashSet<>(LabHostInputs.PLATFORMS),new HashSet<>(order));String terminal=Files.readString(reports.resolve("completion.json"));
        assertFalse(terminal.contains("SECRET_SENTINEL"));assertTrue(terminal.contains("INCOMPLETE"));assertTrue(terminal.contains("HOST_GUEST_FAILED"));
    }
    @Test void cancellationBeforeStartStopsDispatchAndWritesTerminalEvidence() throws Exception {
        var plan=LabHostInputs.plan(LabHostInputsTest.fixture(directory,LabHostInputs.Mode.QUALIFICATION));var dispatches=new AtomicInteger();
        var coordinator=new LabHostCoordinator((vm,p,report,stage,cancel)->{dispatches.incrementAndGet();cancel.set(true);return new PlatformResult(vm.platform(),Outcome.INTERRUPTED,"CANCELLED",Cleanup.COMPLETE,true,Map.of());});
        Path reports=directory.resolve("reports");assertEquals(3,coordinator.execute(plan,vms(),reports,"scenarios",new AtomicBoolean(true)));
        assertEquals(0,dispatches.get());assertTrue(Files.readString(reports.resolve("completion.json")).contains("INTERRUPTED"));
    }
    @Test void platformsOverlapAndRetainEachSummaryBeforeTheOtherFinishes() throws Exception {
        var plan=LabHostInputs.plan(LabHostInputsTest.fixture(directory,LabHostInputs.Mode.QUALIFICATION));
        var together=new java.util.concurrent.CountDownLatch(2);Path reports=directory.resolve("reports");
        var coordinator=new LabHostCoordinator((vm,p,report,stage,cancel)->{
            together.countDown();assertTrue(together.await(3,java.util.concurrent.TimeUnit.SECONDS),"Both platform jobs must overlap");
            if(vm.platform().equals("linux")) {
                long deadline=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(3);
                while(!Files.isRegularFile(reports.resolve("windows/summary.json"))&&System.nanoTime()<deadline)Thread.sleep(10);
                assertTrue(Files.isRegularFile(reports.resolve("windows/summary.json")),"A completed platform must retain its report immediately");
            }
            return passed(vm.platform());
        });
        assertEquals(0,coordinator.execute(plan,vms(),reports,"scenarios",new AtomicBoolean()));
        var rows=LabJson.read(reports.resolve("completion.json"),65536).getAsJsonArray("results");
        assertEquals("windows",rows.get(0).getAsJsonObject().get("platform").getAsString());
        assertEquals("linux",rows.get(1).getAsJsonObject().get("platform").getAsString());
    }
    @Test void syntheticSuccessNeverGrantsAcceptanceBeforeTheEvidenceCollectorExists() throws Exception {
        var plan=LabHostInputs.plan(LabHostInputsTest.fixture(directory,LabHostInputs.Mode.ACCEPTANCE));
        var coordinator=new LabHostCoordinator((vm,p,report,stage,cancel)->passed(vm.platform()));
        Path reports=directory.resolve("reports");assertEquals(3,coordinator.execute(plan,vms(),reports,"scenarios",new AtomicBoolean()));
        assertTrue(Files.readString(reports.resolve("completion.json")).contains("HOST_EVIDENCE_COLLECTOR_UNAVAILABLE"));
        assertTrue(ScenarioCatalog.load().requirements().stream().filter(r->r.layer()==ScenarioCatalog.Layer.HOST).allMatch(r->r.disposition()==ScenarioCatalog.Disposition.MANUAL));
    }
    @Test void visibleFrameDoesNotRequireAnImmediatelyPublishedExtensionReceipt() throws Exception {
        Path receipt=directory.resolve("probe.json");var publisher=java.util.concurrent.Executors.newSingleThreadScheduledExecutor();
        try {
            publisher.schedule(()->{try{Files.writeString(receipt,"{");}catch(IOException failed){throw new UncheckedIOException(failed);}},50,java.util.concurrent.TimeUnit.MILLISECONDS);
            publisher.schedule(()->{try{Files.writeString(receipt,"{\"ready\":true}");}catch(IOException failed){throw new UncheckedIOException(failed);}},200,java.util.concurrent.TimeUnit.MILLISECONDS);
            assertTrue(LabHostGuest.awaitMetadata(receipt,java.time.Duration.ofSeconds(3),()->true,()->false).get("ready").getAsBoolean());
        }finally{publisher.shutdownNow();}
    }
    @Test void missingProbeStopsAtDeadlineCancellationOrOwnedProcessExit() {
        Path receipt=directory.resolve("probe.json");
        assertEquals("HOST_PROBE_NOT_READY",assertThrows(IllegalArgumentException.class,()->LabHostGuest.awaitMetadata(receipt,
                java.time.Duration.ofMillis(100),()->true,()->false)).getMessage());
        assertEquals("HOST_PROBE_NOT_READY",assertThrows(IllegalArgumentException.class,()->LabHostGuest.awaitMetadata(receipt,
                java.time.Duration.ofSeconds(3),()->false,()->false)).getMessage());
        assertThrows(InterruptedException.class,()->LabHostGuest.awaitMetadata(receipt,java.time.Duration.ofSeconds(3),()->true,()->true));
    }
    @Test void ownedBurpExitFailsImmediatelyAndRetainsJoinedExitEvidence() throws Exception {
        Path root=directory.resolve("guest"),report=root.resolve("report");Files.createDirectories(report);
        Files.createDirectories(root.resolve("gui/commands"));Files.createDirectories(root.resolve("gui/receipts"));
        var session=new LabHostGuiProtocol.Session(UUID.randomUUID(),"linux",UUID.randomUUID(),"a".repeat(64),"b".repeat(64),root);
        String executable=System.getProperty("os.name").startsWith("Windows")?"java.exe":"java";
        var process=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin",executable).toString(),"-version")
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        assertTrue(process.waitFor(10,java.util.concurrent.TimeUnit.SECONDS));
        var peer=new LabHostGuest.GuiPeer(session,report,process);
        assertTimeoutPreemptively(java.time.Duration.ofSeconds(2),()->assertEquals("HOST_BURP_EXITED",
                assertThrows(IllegalArgumentException.class,()->peer.ask(LabHostGuiProtocol.Operation.READY,new com.google.gson.JsonObject(),java.time.Duration.ofSeconds(30))).getMessage()));
        var exit=LabJson.read(report.resolve("burp-exit.json"),4096);
        var command=LabHostGuiProtocol.command(LabJson.read(root.resolve("gui/commands/000001.json"),4096),session);
        assertEquals(session.invocationId().toString(),exit.get("invocationId").getAsString());
        assertEquals(session.runNonce().toString(),exit.get("runNonce").getAsString());
        assertEquals(command.operationId().toString(),exit.get("operationId").getAsString());
        assertEquals(1,exit.get("sequence").getAsLong());assertEquals("READY",exit.get("operation").getAsString());
        assertEquals(process.exitValue(),exit.get("exitCode").getAsInt());assertFalse(Files.exists(report.resolve("gui-001.json")));
    }
    @Test void openboxPreflightRequiresExactlyThePublicNonzeroWindowManagerProperty() {
        assertEquals(Optional.of("0x20011f"),LabHostGuest.openboxWindowId("_NET_SUPPORTING_WM_CHECK(WINDOW): window id # 0x20011f"));
        for(String invalid:List.of("","0x20011f","_NET_SUPPORTING_WM_CHECK(WINDOW): window id # 0x0",
                "_NET_SUPPORTING_WM_CHECK(WINDOW): window id # 0x20011f\nPRIVATE_SENTINEL"))
            assertTrue(LabHostGuest.openboxWindowId(invalid).isEmpty());
    }
    @Test void cancellationAttemptsBothPlatformsAfterAnInterruptAndRestoresTheFlag() {
        var attempted=new ArrayList<String>();boolean original=Thread.interrupted();
        try {
            assertThrows(InterruptedException.class,()->LabHostCoordinator.cancelAll(List.of(
                    ()->{attempted.add("windows");throw new InterruptedException();},()->attempted.add("linux"))));
            assertEquals(List.of("windows","linux"),attempted);assertTrue(Thread.currentThread().isInterrupted());
        }finally{Thread.interrupted();if(original)Thread.currentThread().interrupt();}
    }
    @Test void cancellationAttemptsBothPlatformsAfterAPrivateTransportFailure() {
        var attempted=new ArrayList<String>();
        var failure=assertThrows(IOException.class,()->LabHostCoordinator.cancelAll(List.of(
                ()->{attempted.add("windows");throw new IOException("PRIVATE_SENTINEL");},()->attempted.add("linux"))));
        assertEquals(List.of("windows","linux"),attempted);assertEquals("HOST_CANCEL_UNAVAILABLE",failure.getMessage());
        assertNull(failure.getCause());
    }
}
