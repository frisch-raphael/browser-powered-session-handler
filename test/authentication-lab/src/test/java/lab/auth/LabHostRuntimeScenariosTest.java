package lab.auth;
import com.google.gson.*;
import com.sun.net.httpserver.HttpServer;
import java.net.*;
import java.net.http.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
class LabHostRuntimeScenariosTest {
 @TempDir Path root;
 private final List<LabHostGuiProtocol.Operation> operations=new ArrayList<>();
 private final List<JsonObject> arguments=new ArrayList<>();
 private final AtomicLong sequence=new AtomicLong();
 @FunctionalInterface interface NativeAction {JsonObject run(LabHostGuiProtocol.Operation operation,JsonObject args) throws Exception;}
 private NativeAction nativeAction=(operation,args)->{var value=new JsonObject();value.addProperty("testUiConfirmed",true);return value;};
 private LabHostScenarios runner(LabRun run,List<Integer> ports) throws Exception {
  var session=new LabHostGuiProtocol.Session(UUID.randomUUID(),"windows",UUID.randomUUID(),"a".repeat(64),"b".repeat(64),root);
  return new LabHostScenarios(session,run,root,Files.createDirectory(root.resolve("report")),ports,(operation,args,timeout)->{
   operations.add(operation);arguments.add(args.deepCopy());var result=new JsonObject();result.addProperty("sequence",sequence.incrementAndGet());result.addProperty("outcome","PASS");
   result.add("observed",nativeAction.run(operation,args));return result;
  },(prefix,output)->{
   assertEquals("host",prefix);Files.createDirectory(output.resolve("native-examples"));Files.writeString(output.resolve("native-examples/host_b.json"),"{}");
  });
 }
 private LabRun start() throws Exception {return LabRun.startHost(new LabRun.RunSpec(UUID.randomUUID(),List.of("browser"),ScenarioCatalog.load(),root.resolve("lab"),List.of(),5000));}
 @Test void runtimeSetupImportsOnlyTheControlledJourneyAndDoesNotAuthenticate() throws Exception {
  try(var run=start();var lease=run.prepareCase("BROW.basic.json");var runner=runner(run,List.of(18081,18082,18083))) {
   runner.prepareBrowserRuntime();assertEquals(List.of(LabHostGuiProtocol.Operation.IMPORT_JOURNEY),operations);
   assertEquals("host_b",arguments.getFirst().get("alias").getAsString());
   assertTrue(lease.snapshot().get("events").toString().indexOf("login-completed")<0);
  }
 }
 @Test void successfulNativeDialogCannotReplaceIndependentServerAuthentication() throws Exception {
  try(var run=start();var lease=run.prepareCase("BROW.basic.json");var client=ControlledApplication.localClientBuilder().build()) {
   var proxy=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
   proxy.createContext("/",exchange->{
    try {
     var request=HttpRequest.newBuilder(exchange.getRequestURI()).header("X-AuthLab-Request",exchange.getRequestHeaders().getFirst("X-AuthLab-Request")).GET().build();
     var response=client.send(request,HttpResponse.BodyHandlers.discarding());exchange.sendResponseHeaders(response.statusCode(),-1);
    }catch(Exception failure){exchange.sendResponseHeaders(502,-1);}finally{exchange.close();}
   });proxy.start();
   int port=proxy.getAddress().getPort();
   try(var runner=runner(run,List.of(port,port==18082?18084:18082,port==18083?18085:18083))) {
    runner.prepareBrowserRuntime();var rejected=assertThrows(Exception.class,()->runner.browserRuntimeLogin(true));
    assertEquals("HOST_CLIENT_STATUS",rejected.getMessage());
    assertEquals(List.of(LabHostGuiProtocol.Operation.IMPORT_JOURNEY,LabHostGuiProtocol.Operation.ENTER_SECRET,LabHostGuiProtocol.Operation.TEST_BROWSER_LOGIN),operations);
   }finally{proxy.stop(0);}
  }
 }
 @Test void recordingAndReplayRequireNewServerIssuancesWithoutRefillingRecordedSecrets() throws Exception {
  try(var run=start();var lease=run.prepareCase("BROW.basic.json");var client=ControlledApplication.localClientBuilder().build()) {
   var login=new java.util.concurrent.atomic.AtomicReference<HttpResponse<String>>();
   nativeAction=(operation,args)->{
    if(operation==LabHostGuiProtocol.Operation.TEST_BROWSER_LOGIN||operation==LabHostGuiProtocol.Operation.RECORD_BROWSER_LOGIN) {
     var response=FixtureContractTest.send(client,lease.endpoint("login/json"),"POST","{\"username\":\"user2\",\"password\":\"pass2\"}","application/json");
     assertEquals(200,response.statusCode());login.set(response);
    }
    var value=new JsonObject();
    for(String key:List.of("testUiConfirmed","nativeStart","initialStepsCleared","loginTyped","nativeStop","reviewReplaced","inlineError","focused","noPopup","literalPath","controlsVisible"))value.addProperty(key,true);
    value.addProperty("browserVersion","156.0.8078.48");
    if(operation==LabHostGuiProtocol.Operation.BROWSER_SETTINGS) {
     value.add("theme",args.get("theme"));value.add("size",args.get("size"));value.addProperty("width",args.get("size").getAsString().equals("compact")?960:1240);
    }
    return value;
   };
   var proxy=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
   proxy.createContext("/",exchange->{
    try {
     var request=HttpRequest.newBuilder(exchange.getRequestURI()).header("X-AuthLab-Request",exchange.getRequestHeaders().getFirst("X-AuthLab-Request"))
       .header("Authorization","Bearer "+FixtureContractTest.json(login.get()).get("access_token").getAsString())
       .header("Cookie","LAB_C1="+FixtureContractTest.cookie(login.get(),"LAB_C1")).GET().build();
     var response=client.send(request,HttpResponse.BodyHandlers.discarding());exchange.sendResponseHeaders(response.statusCode(),-1);
    }catch(Exception failure){exchange.sendResponseHeaders(502,-1);}finally{exchange.close();}
   });proxy.start();int port=proxy.getAddress().getPort();
   try(var runner=runner(run,List.of(port,port==18082?18084:18082,port==18083?18085:18083))) {
    runner.prepareBrowserRuntime();var first=runner.browserRuntimeLogin(true);var finished=runner.finishBrowserRuntime();
    assertEquals(4,finished.getAsJsonArray("settings").size());
    var recording=finished.getAsJsonObject("recording");
    assertNotEquals(first.getAsJsonObject("proof").get("issuance"),recording.get("recordedIssuance"));
    assertNotEquals(recording.get("recordedIssuance"),recording.getAsJsonObject("replayProof").get("issuance"));
    assertEquals(1,operations.stream().filter(op->op==LabHostGuiProtocol.Operation.ENTER_SECRET).count());
    assertTrue(operations.indexOf(LabHostGuiProtocol.Operation.FINISH_BROWSER_RECORDING)>operations.indexOf(LabHostGuiProtocol.Operation.RECORD_BROWSER_LOGIN));
   }finally{proxy.stop(0);}
  }
 }
}
