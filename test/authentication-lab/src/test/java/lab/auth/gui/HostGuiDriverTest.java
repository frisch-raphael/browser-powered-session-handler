package lab.auth.gui;

import com.google.gson.*;
import java.awt.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import lab.auth.*;
import static org.junit.jupiter.api.Assertions.*;

class HostGuiDriverTest {
    @Test void boundedThreadDiagnosticsKeepUiAndNewLoaderWorkInsteadOfOnlyOldThreads() {
        var snapshots=new LinkedHashMap<Thread,StackTraceElement[]>();
        var ui=new Thread("PRIVATE_UI_NAME");snapshots.put(ui,new StackTraceElement[]{
                new StackTraceElement("java.awt.EventDispatchThread","run","PRIVATE_SOURCE",1),
                new StackTraceElement("burp.Frame","dispatch","PRIVATE_SOURCE",1)});
        for(int i=0;i<60;i++)snapshots.put(new Thread("PRIVATE_WORKER_NAME"),new StackTraceElement[]{
                new StackTraceElement("burp.Worker","run","PRIVATE_SOURCE",1)});
        var loader=new Thread("PRIVATE_LOADER_NAME");snapshots.put(loader,new StackTraceElement[]{
                new StackTraceElement("bpsh.browser.runtime.BrowserArchiveCodec","decode","PRIVATE_SOURCE",1)});
        var archive=new Thread("PRIVATE_ARCHIVE_NAME");snapshots.put(archive,new StackTraceElement[]{
                new StackTraceElement("java.io.FileInputStream","read","PRIVATE_SOURCE",1),
                new StackTraceElement("burp.Loader","load","PRIVATE_SOURCE",1)});
        var result=HostGuiDiagnostics.threadSnapshots(snapshots);assertEquals(48,result.size());
        assertEquals(ui.threadId(),result.get(0).get("id"));assertEquals(loader.threadId(),result.get(1).get("id"));
        assertEquals(archive.threadId(),result.get(2).get("id"));assertFalse(result.toString().contains("PRIVATE_"));
    }
    @Test void privateThreadDiagnosticsKeepOnlyBoundedIdentifiersWithoutSourceOrArgumentData() {
        var frames=new StackTraceElement[]{new StackTraceElement("burp.Loader","load","PRIVATE_SOURCE_PATH",123),
                new StackTraceElement("java.io.FileInputStream","read","PRIVATE_SECRET",1),
                new StackTraceElement("PRIVATE_SECRET","method","PRIVATE_PATH",1)};
        var safe=HostGuiDiagnostics.safeThreadFrames(frames);assertEquals(java.util.List.of("burp.Loader.load","java.io.FileInputStream.read"),safe);
        assertFalse(safe.toString().contains("PRIVATE_"));
    }
    @Test void nativeLoadingDiagnosticsRetainOnlyStackFrameIdentifiers() {
        String text="PRIVATE_SECRET\n at burp.Z_rf.Za(Unknown Source)\n at burp.Za3r.ZU(PrivatePath.java:9)\n at other.Library.method(Unknown Source)\n";
        var frames=HostGuiDiagnostics.loadingFrames(text);assertEquals(java.util.List.of("burp.Z_rf.Za","burp.Za3r.ZU"),frames);
        assertFalse(frames.toString().contains("PRIVATE_SECRET"));assertFalse(frames.toString().contains("PrivatePath"));
        assertTrue(HostGuiDiagnostics.loadingFrames("x".repeat(32769)).isEmpty());
    }
    @TempDir Path directory;
    private HostGuiDriver driver(AtomicInteger inputs) throws Exception {
        return driver(inputs,Clock.fixed(Instant.ofEpochMilli(1000),ZoneOffset.UTC));
    }
    private HostGuiDriver driver(AtomicInteger inputs,Clock clock) throws Exception {
        var session=new LabHostGuiProtocol.Session(UUID.randomUUID(),"linux",UUID.randomUUID(),"a".repeat(64),"b".repeat(64),directory.toRealPath());
        return new HostGuiDriver(session,new HostGuiDriver.Input(){public void click(Component c,Point p){inputs.incrementAndGet();}
            public void keys(int... keys){inputs.incrementAndGet();}public void text(String value){inputs.incrementAndGet();}},clock);
    }
    private LabHostGuiProtocol.Command command(long deadline) {
        return new LabHostGuiProtocol.Command(1,UUID.randomUUID(),LabHostGuiProtocol.Operation.CLOSE,deadline,new JsonObject());
    }
    @Test void cancelledExpiredAndUnreadyOperationsNeverGenerateInput() throws Exception {
        var inputs=new AtomicInteger();var driver=driver(inputs);
        assertEquals("GUI_DEADLINE",assertThrows(HostGuiSelectors.Failure.class,()->driver.perform(command(1000))).getMessage());
        assertEquals("GUI_NOT_READY",assertThrows(HostGuiSelectors.Failure.class,()->driver.perform(command(2000))).getMessage());
        Files.writeString(directory.resolve("cancel"),"");
        assertEquals("GUI_CANCELLED",assertThrows(HostGuiSelectors.Failure.class,()->driver.perform(command(2000))).getMessage());
        assertEquals(0,inputs.get());
    }
    @Test void diagnosticsNeverReturnEditorOrPasswordContents() {
        HostGuiSelectors.edt(()->{
            var panel=new javax.swing.JPanel();panel.add(new javax.swing.JTextField("SECRET_SENTINEL"){@Override public boolean isShowing(){return true;}});
            panel.add(new javax.swing.JPasswordField("SECRET_SENTINEL"){@Override public boolean isShowing(){return true;}});
            panel.add(new javax.swing.JLabel("SECRET_SENTINEL"){@Override public boolean isShowing(){return true;}});
            panel.add(new javax.swing.JButton("SECRET_SENTINEL"){@Override public boolean isShowing(){return true;}});
            var result=HostGuiDiagnostics.capture(panel);assertEquals(1,result.getAsJsonObject("counts").get("text").getAsInt());
            assertEquals(1,result.getAsJsonObject("counts").get("password").getAsInt());assertFalse(result.toString().contains("SECRET_SENTINEL"));return true;
        });
    }
    @Test void stateWaitDeadlineProducesNoInput() throws Exception {
        var inputs=new AtomicInteger();var driver=driver(inputs,Clock.systemUTC());
        var command=new LabHostGuiProtocol.Command(1,UUID.randomUUID(),LabHostGuiProtocol.Operation.READY,System.currentTimeMillis()+150,new JsonObject());
        assertEquals("GUI_DEADLINE",assertThrows(HostGuiSelectors.Failure.class,()->driver.perform(command)).getMessage());assertEquals(0,inputs.get());
    }
    @Test void cancellationDuringAStateWaitProducesNoInput() throws Exception {
        var inputs=new AtomicInteger();var driver=driver(inputs,Clock.systemUTC());var scheduler=java.util.concurrent.Executors.newSingleThreadScheduledExecutor();
        try {
            scheduler.schedule(()->{try{Files.writeString(directory.resolve("cancel"),"");}catch(java.io.IOException failed){throw new AssertionError(failed);}},100,java.util.concurrent.TimeUnit.MILLISECONDS);
            var command=new LabHostGuiProtocol.Command(1,UUID.randomUUID(),LabHostGuiProtocol.Operation.READY,System.currentTimeMillis()+3000,new JsonObject());
            assertEquals("GUI_CANCELLED",assertThrows(HostGuiSelectors.Failure.class,()->driver.perform(command)).getMessage());assertEquals(0,inputs.get());
        }finally{scheduler.shutdownNow();}
    }
}
