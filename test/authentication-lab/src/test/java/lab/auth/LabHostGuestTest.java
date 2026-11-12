package lab.auth;

import com.google.gson.*;
import java.io.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static lab.auth.LabHostCoordinator.Outcome;
import static org.junit.jupiter.api.Assertions.*;

class LabHostGuestTest {
    @org.junit.jupiter.api.Test void probeEvidenceRequiresTheActualOwnedJvmHeapIdentityAndExactVendorToken() throws Exception {
        var session=new LabHostGuiProtocol.Session(UUID.randomUUID(),"linux",UUID.randomUUID(),"a".repeat(64),"b".repeat(64),directory);
        var probe=LabHostGuiProtocol.identity(session);probe.addProperty("burpVersion","Burp Suite Community Edition v2026.10.1");
        probe.addProperty("javaVersion","26.0.2");probe.addProperty("os","Linux");probe.addProperty("pid",123);probe.addProperty("startedEpochMs",1000);
        probe.addProperty("maxHeapBytes",2147483648L);var ports=new com.google.gson.JsonArray();for(int port:List.of(8081,8082,8083))ports.add(port);probe.add("listenerPorts",ports);
        assertEquals(2147483648L,LabHostGuest.verifyProbeMetadata(probe,session,123,1000,List.of(8081,8082,8083)));
        for(String version:List.of("2026.10.10","2026.10.11","2026.10.1.1","2026.10.1beta")) {
            var bad=probe.deepCopy();bad.addProperty("burpVersion",version);
            assertThrows(IllegalArgumentException.class,()->LabHostGuest.verifyProbeMetadata(bad,session,123,1000,List.of(8081,8082,8083)));
        }
        for(String field:List.of("pid","startedEpochMs","maxHeapBytes")) {
            var bad=probe.deepCopy();bad.addProperty(field,1);
            assertThrows(IllegalArgumentException.class,()->LabHostGuest.verifyProbeMetadata(bad,session,123,1000,List.of(8081,8082,8083)));
        }
        var foreign=probe.deepCopy();foreign.addProperty("runNonce",UUID.randomUUID().toString());
        assertThrows(IllegalArgumentException.class,()->LabHostGuest.verifyProbeMetadata(foreign,session,123,1000,List.of(8081,8082,8083)));
    }
    @TempDir Path directory;
    private static JsonObject entry(String name,long bytes) {
        var value=new JsonObject();value.addProperty("path",name);value.addProperty("bytes",bytes);value.addProperty("sha256","a".repeat(64));return value;
    }
    private static JsonArray index() {var index=new JsonArray();index.add(entry("started.json",2));return index;}
    @Test void scenarioOutcomeRequiresEveryCaseAndPreservesFailuresOrInterruption() {
        var values=new LinkedHashMap<String,Outcome>();LabHostInputs.SCENARIOS.forEach(id->values.put(id,Outcome.PASS));
        assertEquals(Outcome.PASS,LabHostGuest.scenarioOutcome(values));
        values.put("ordinary-failure",Outcome.BLOCKED);assertEquals(Outcome.BLOCKED,LabHostGuest.scenarioOutcome(values));
        values.put("routing",Outcome.FAIL);assertEquals(Outcome.FAIL,LabHostGuest.scenarioOutcome(values));
        values.put("tags",Outcome.INTERRUPTED);assertEquals(Outcome.INTERRUPTED,LabHostGuest.scenarioOutcome(values));
        values.remove("routing");assertEquals(Outcome.BLOCKED,LabHostGuest.scenarioOutcome(values));
        assertEquals(Outcome.BLOCKED,LabHostGuest.scenarioOutcome(Map.of()));
    }
    @Test void evidenceNamesAndSizeBoundsAreClosedAndAllowLargeScenarioFacts() {
        for(var boundary:Map.of("gui-001.json",65536,"scenario-setup.json",1_048_576,"scenario-routing.json",16*1024*1024).entrySet()) {
            var valid=index();valid.add(entry(boundary.getKey(),boundary.getValue()));assertDoesNotThrow(()->LabHostGuest.validateEvidenceIndex(valid));
            valid.get(1).getAsJsonObject().addProperty("bytes",boundary.getValue()+1);
            assertThrows(IllegalArgumentException.class,()->LabHostGuest.validateEvidenceIndex(valid));
        }
        for(String invalid:List.of("private.json","scenario-unknown.json","gui-0000001.json","../started.json","scenario-routing.json/private")) {
            var values=index();values.add(entry(invalid,2));assertThrows(IllegalArgumentException.class,()->LabHostGuest.validateEvidenceIndex(values));
        }
        var duplicate=index();duplicate.add(entry("started.json",2));assertThrows(IllegalArgumentException.class,()->LabHostGuest.validateEvidenceIndex(duplicate));
        var empty=index();empty.get(0).getAsJsonObject().addProperty("bytes",0);assertThrows(IllegalArgumentException.class,()->LabHostGuest.validateEvidenceIndex(empty));
    }
    @Test void evidenceIndexSupports2048EntriesAndOneMiBReadWithoutRelaxingItsCount() throws Exception {
        var values=index();for(int i=1;i<2048;i++)values.add(entry(String.format(Locale.ROOT,"gui-%03d.json",i),2));
        assertDoesNotThrow(()->LabHostGuest.validateEvidenceIndex(values));
        var completion=new JsonObject();completion.add("evidence",values);
        Path receipt=directory.resolve("completion.json");LabJson.writeNew(receipt,completion);
        assertTrue(Files.size(receipt)>65536);assertTrue(Files.size(receipt)<LabHostGuest.COMPLETION_LIMIT);
        assertThrows(IllegalArgumentException.class,()->LabJson.read(receipt,65536));
        assertEquals(2048,LabJson.read(receipt,LabHostGuest.COMPLETION_LIMIT).getAsJsonArray("evidence").size());
        values.add(entry("gui-2048.json",2));assertThrows(IllegalArgumentException.class,()->LabHostGuest.validateEvidenceIndex(values));
    }
    @Test void evidenceProducerHashesOnlyOwnedAllowedFilesAndRejectsNonfiles() throws Exception {
        Files.writeString(directory.resolve("started.json"),"{}");Files.writeString(directory.resolve("private.json"),"PRIVATE_SENTINEL");
        Files.writeString(directory.resolve("scenario-routing.json"),"{}"+" ".repeat(65536));
        var values=LabHostGuest.evidenceIndex(directory);assertEquals(2,values.size());LabHostGuest.validateEvidenceIndex(values);
        assertFalse(values.toString().contains("PRIVATE_SENTINEL"));assertFalse(values.toString().contains("private.json"));
        var scenario=values.asList().stream().map(JsonElement::getAsJsonObject).filter(row->row.get("path").getAsString().equals("scenario-routing.json")).findFirst().orElseThrow();
        assertEquals(Files.size(directory.resolve("scenario-routing.json")),scenario.get("bytes").getAsLong());
        assertEquals(LabJson.sha256(directory.resolve("scenario-routing.json")),scenario.get("sha256").getAsString());
        Files.createDirectory(directory.resolve("gui-002.json"));assertThrows(IllegalArgumentException.class,()->LabHostGuest.evidenceIndex(directory));
    }
    @Test void evidenceProducerRejectsSymlinkedPublicFiles() throws Exception {
        Path target=Files.writeString(directory.resolve("private.json"),"PRIVATE_SENTINEL");
        try{Files.createSymbolicLink(directory.resolve("started.json"),target);}
        catch(IOException|UnsupportedOperationException unsupported){org.junit.jupiter.api.Assumptions.abort("Symbolic links unavailable on this test host");}
        assertThrows(IllegalArgumentException.class,()->LabHostGuest.evidenceIndex(directory));
    }
    private LabHostGuest.GuiPeer peer(Process process) throws Exception {
        Path root=directory.resolve("guest");Files.createDirectories(root.resolve("report"));Files.createDirectories(root.resolve("gui/commands"));Files.createDirectories(root.resolve("gui/receipts"));
        return new LabHostGuest.GuiPeer(new LabHostGuiProtocol.Session(UUID.randomUUID(),"linux",UUID.randomUUID(),"a".repeat(64),"b".repeat(64),root.toRealPath()),root.resolve("report"),process);
    }
    private static void cannotQueueAgain(LabHostGuest.GuiPeer peer) throws Exception {
        assertEquals("HOST_GUI_CHANNEL_BROKEN",assertThrows(IllegalArgumentException.class,()->peer.ask(LabHostGuiProtocol.Operation.READY,new JsonObject(),Duration.ofSeconds(5))).getMessage());
        assertEquals(1,peer.sequence);
        try(var commands=Files.list(peer.session.root().resolve("gui/commands"))){assertEquals(1,commands.filter(p->p.getFileName().toString().endsWith(".json")).count());}
    }
    @Test void failedGuiReceiptStopsLaterCasesFromQueuingUnconsumedCommands() throws Exception {
        var peer=peer(new StaticProcess(true));var publisher=Executors.newSingleThreadExecutor();
        try {
            var published=publisher.submit(()->{
                try {
                    Path path=peer.session.root().resolve("gui/commands/000001.json");long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
                    while(!Files.isRegularFile(path)&&System.nanoTime()<deadline)Thread.sleep(10);
                    var command=LabHostGuiProtocol.command(LabJson.read(path,4096),peer.session);long now=System.currentTimeMillis();
                    Path temporary=peer.session.root().resolve("gui/receipts/"+command.operationId()+".tmp");
                    LabJson.writeNew(temporary,LabHostGuiProtocol.receipt(peer.session,command,now,now,"FAIL","GUI_CONTROL_MISSING",new JsonObject()));
                    Files.move(temporary,temporary.resolveSibling(command.operationId()+".json"),StandardCopyOption.ATOMIC_MOVE);
                    Files.writeString(peer.session.root().resolve("gui/receipts/"+command.operationId()+".diagnostics"),"");
                }catch(Exception failure){throw new CompletionException(failure);}
            });
            assertEquals("HOST_GUI_OPERATION_FAILED",assertThrows(IllegalArgumentException.class,()->peer.ask(LabHostGuiProtocol.Operation.READY,new JsonObject(),Duration.ofSeconds(5))).getMessage());
            published.get(5,TimeUnit.SECONDS);cannotQueueAgain(peer);
        }finally{publisher.shutdownNow();}
    }
    @Test void exitedGuiOwnerStopsLaterCasesFromQueuingCommands() throws Exception {
        var peer=peer(new StaticProcess(false));
        assertEquals("HOST_BURP_EXITED",assertThrows(IllegalArgumentException.class,()->peer.ask(LabHostGuiProtocol.Operation.READY,new JsonObject(),Duration.ofSeconds(5))).getMessage());
        cannotQueueAgain(peer);
    }
    @Test void expiredGuiOperationStopsLaterCasesFromQueuingCommands() throws Exception {
        var peer=peer(new StaticProcess(true));
        assertEquals("HOST_GUI_RECEIPT_DEADLINE",assertThrows(IllegalArgumentException.class,()->peer.ask(LabHostGuiProtocol.Operation.READY,new JsonObject(),Duration.ofMillis(10))).getMessage());
        cannotQueueAgain(peer);
    }
    private static final class StaticProcess extends Process {
        private final boolean alive;StaticProcess(boolean alive){this.alive=alive;}
        @Override public OutputStream getOutputStream(){return OutputStream.nullOutputStream();}
        @Override public InputStream getInputStream(){return InputStream.nullInputStream();}
        @Override public InputStream getErrorStream(){return InputStream.nullInputStream();}
        @Override public int waitFor(){return exitValue();}
        @Override public int exitValue(){if(alive)throw new IllegalThreadStateException();return 9;}
        @Override public void destroy(){}
        @Override public boolean isAlive(){return alive;}
    }
}
