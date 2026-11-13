package lab.auth;
import com.google.gson.JsonObject;
import java.io.IOException;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class LabHostBrowserRuntimeBindingTest {
 @org.junit.jupiter.api.io.TempDir java.nio.file.Path directory;
 @Test void runtimeReceiptMustBelongToTheCurrentCoordinatorInvocation() throws Exception {
  var current=LabHostBrowserRuntimeTest.receipt();
  UUID invocation=UUID.fromString(current.get("invocationId").getAsString()),nonce=UUID.fromString(current.get("runNonce").getAsString());
  assertDoesNotThrow(()->bind(current,invocation,nonce));
  assertThrows(IOException.class,()->bind(current,UUID.randomUUID(),nonce));
  assertThrows(IOException.class,()->bind(current,invocation,UUID.randomUUID()));
 }
 private static void bind(JsonObject receipt,UUID invocation,UUID nonce) throws IOException {
  LabHostCoordinator.validateRuntimeReceipt(receipt,LabHostBrowserRuntimeTest.SHA,LabHostBrowserRuntimeTest.PATH,invocation,"windows",nonce,"b".repeat(64));
 }
 @Test void scopedSuccessNeedsItsDedicatedRuntimeResultAndCannotGrantCatalogAcceptance() {
  var current=new LabHostCoordinator.PlatformResult("windows",LabHostCoordinator.Outcome.PASS,"BROWSER_RUNTIME_QUALIFIED",LabHostCoordinator.Cleanup.COMPLETE,true,Map.of());
  assertTrue(LabHostCoordinator.complete(List.of("windows"),List.of(current),"browser-runtime"));
  assertFalse(LabHostCoordinator.complete(List.of("windows"),List.of(current),"scenarios"));
  var generic=new LabHostCoordinator.PlatformResult("windows",LabHostCoordinator.Outcome.PASS,"GUI_PRIMITIVES_QUALIFIED",LabHostCoordinator.Cleanup.COMPLETE,true,Map.of());
  assertFalse(LabHostCoordinator.complete(List.of("windows"),List.of(generic),"browser-runtime"));
 }
 @Test void runtimeCompletionRequiresItsIndexedReceiptAndQualificationScope() {
  var receipt=LabHostBrowserRuntimeTest.receipt();
  var artifact=new LabHostInputs.Artifact(java.nio.file.Path.of("artifact"),LabHostBrowserRuntimeTest.SHA,1,null);
  var plan=new LabHostInputs.Plan(UUID.fromString(receipt.get("invocationId").getAsString()),LabHostInputs.Mode.QUALIFICATION,List.of("windows"),":authLabHostQualify",
    "a".repeat(64),"a".repeat(64),"a".repeat(64),"a".repeat(40),Map.of(),artifact,artifact,
    new LabHostInputs.Artifact(java.nio.file.Path.of("helper"),"b".repeat(64),1,null),List.of(),artifact,java.nio.file.Path.of("capture"));
  var terminal=new JsonObject();
  for(String key:List.of("version","invocationId","platform","runNonce","productSha256","helperSha256","stage"))terminal.add(key,receipt.get(key));
  terminal.addProperty("outcome","PASS");terminal.addProperty("code","BROWSER_RUNTIME_QUALIFIED");terminal.addProperty("cleanup","COMPLETE");
  terminal.addProperty("unattended",true);terminal.addProperty("durationMs",1000);terminal.add("scenarios",new JsonObject());
  var index=new com.google.gson.JsonArray();
  for(String path:List.of("started.json","browser-runtime.json")) {
   var entry=new JsonObject();entry.addProperty("path",path);entry.addProperty("sha256","a".repeat(64));entry.addProperty("bytes",100);index.add(entry);
  }
  terminal.add("evidence",index);String nonce=receipt.get("runNonce").getAsString();
  assertEquals("BROWSER_RUNTIME_QUALIFIED",LabHostGuest.result(terminal,plan,"windows",nonce,"browser-runtime").code());
  index.remove(1);assertThrows(IllegalArgumentException.class,()->LabHostGuest.result(terminal,plan,"windows",nonce,"browser-runtime"));
  terminal.addProperty("stage","BROWSER-RUNTIME");assertThrows(IllegalArgumentException.class,()->LabHostGuest.result(terminal,plan,"windows",nonce,"browser-runtime"));
 }
 @Test void nativeCycleJournalAndActualJvmMetadataCannotBeOmittedOrContradicted() throws Exception {
  var current=LabHostBrowserRuntimeTest.receipt();
  assertThrows(IOException.class,()->LabHostBrowserRuntime.validateNativeEvidence(current,directory));
  var environment=new JsonObject();environment.add("burpPid",current.get("burpPid"));environment.add("burpStartedEpochMs",current.get("burpStartedEpochMs"));environment.add("actualMaxHeapBytes",current.get("heapBytes"));
  LabJson.writeNew(directory.resolve("environment.json"),environment);LabJson.writeNew(directory.resolve("memory.json"),current.get("memory"));
  var session=new LabHostGuiProtocol.Session(UUID.fromString(current.get("invocationId").getAsString()),"windows",UUID.fromString(current.get("runNonce").getAsString()),LabHostBrowserRuntimeTest.SHA,"b".repeat(64),directory);
  for(int i=0;i<5;i++) {
   var cycle=current.getAsJsonArray("cycles").get(i).getAsJsonObject();
   cycle.addProperty("unloadSequence",i*10+1);cycle.addProperty("loadSequence",i*10+2);
   for(boolean enabled:List.of(false,true)) {
    long sequence=cycle.get(enabled?"loadSequence":"unloadSequence").getAsLong();var args=new JsonObject();args.addProperty("enabled",enabled);
    var observed=args.deepCopy();if(enabled)observed.addProperty("productSourceMatched",true);
    nativeReceipt(session,sequence,LabHostGuiProtocol.Operation.SET_PRODUCT_LOADED,args,observed,cycle.get("beganEpochMs").getAsLong(),cycle.get("endedEpochMs").getAsLong());
   }
  }
  var alias=new JsonObject();alias.addProperty("alias","host_b");var tested=new JsonObject();tested.addProperty("testUiConfirmed",true);
  nativeReceipt(session,34,LabHostGuiProtocol.Operation.TEST_BROWSER_LOGIN,alias,tested,1350,1355);
  nativeReceipt(session,44,LabHostGuiProtocol.Operation.TEST_BROWSER_LOGIN,alias,tested,1450,1455);
  var record=alias.deepCopy();record.addProperty("secret","FORM_B");var started=new JsonObject();
  for(String key:List.of("nativeStart","initialStepsCleared","loginTyped"))started.addProperty(key,true);started.add("browserVersion",current.get("browserVersion"));
  nativeReceipt(session,45,LabHostGuiProtocol.Operation.RECORD_BROWSER_LOGIN,record,started,1460,1465);
  var stopped=new JsonObject();stopped.addProperty("nativeStop",true);stopped.addProperty("reviewReplaced",true);
  nativeReceipt(session,46,LabHostGuiProtocol.Operation.FINISH_BROWSER_RECORDING,alias,stopped,1470,1475);
  nativeReceipt(session,47,LabHostGuiProtocol.Operation.TEST_BROWSER_LOGIN,alias,tested,1480,1485);
  long sequence=48;
  for(var item:current.getAsJsonArray("settings")) {
   var observed=item.getAsJsonObject();var intent=alias.deepCopy();intent.add("theme",observed.get("theme"));intent.add("size",observed.get("size"));
   nativeReceipt(session,sequence++,LabHostGuiProtocol.Operation.BROWSER_SETTINGS,intent,observed,1500,1505);
  }
  assertDoesNotThrow(()->LabHostBrowserRuntime.validateNativeEvidence(current,directory));
  var recordFile=directory.resolve("gui-045.json");String recordJson=java.nio.file.Files.readString(recordFile);java.nio.file.Files.delete(recordFile);
  assertThrows(IOException.class,()->LabHostBrowserRuntime.validateNativeEvidence(current,directory));java.nio.file.Files.writeString(recordFile,recordJson);
  var file=directory.resolve("gui-042.json");var nativeLoad=LabJson.read(file,65536);nativeLoad.getAsJsonObject("observed").addProperty("productSourceMatched",false);java.nio.file.Files.writeString(file,LabJson.JSON.toJson(nativeLoad));
  assertThrows(IOException.class,()->LabHostBrowserRuntime.validateNativeEvidence(current,directory));
  java.nio.file.Files.delete(file);assertThrows(IOException.class,()->LabHostBrowserRuntime.validateNativeEvidence(current,directory));
 }
 private void nativeReceipt(LabHostGuiProtocol.Session session,long sequence,LabHostGuiProtocol.Operation operation,JsonObject args,JsonObject observed,long start,long end) throws Exception {
  var command=new LabHostGuiProtocol.Command(sequence,UUID.randomUUID(),operation,end+1000,args);
  var receipt=LabHostGuiProtocol.receipt(session,command,start,end,"PASS","GUI_VERIFIED",observed);
  LabJson.writeNew(directory.resolve(String.format(java.util.Locale.ROOT,"gui-%03d.json",sequence)),LabHostGuiProtocol.retainedReceipt(receipt,session,command));
 }
}
