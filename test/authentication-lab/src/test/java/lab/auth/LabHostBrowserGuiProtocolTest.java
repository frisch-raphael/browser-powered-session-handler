package lab.auth;
import com.google.gson.*;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import static org.junit.jupiter.api.Assertions.*;
class LabHostBrowserGuiProtocolTest {
 @TempDir Path root;
 LabHostGuiProtocol.Session session() throws Exception {return new LabHostGuiProtocol.Session(UUID.randomUUID(),"windows",UUID.randomUUID(),"a".repeat(64),"b".repeat(64),root.toRealPath());}
 static JsonObject args(LabHostGuiProtocol.Operation operation) {
  var args=new JsonObject();args.addProperty("alias","host_b");
  if(operation==LabHostGuiProtocol.Operation.RECORD_BROWSER_LOGIN)args.addProperty("secret","FORM_B");
  if(operation==LabHostGuiProtocol.Operation.BROWSER_SETTINGS){args.addProperty("theme","Light");args.addProperty("size","compact");}
  return args;
 }
 @ParameterizedTest @EnumSource(value=LabHostGuiProtocol.Operation.class,names={"TEST_BROWSER_LOGIN","RECORD_BROWSER_LOGIN","FINISH_BROWSER_RECORDING","BROWSER_SETTINGS"})
 void runtimeActionsRejectArbitraryPrivateArguments(LabHostGuiProtocol.Operation operation) throws Exception {
  var session=session();var args=args(operation);
  var command=new LabHostGuiProtocol.Command(1,UUID.randomUUID(),operation,2000,args);
  assertEquals(operation,LabHostGuiProtocol.command(LabHostGuiProtocol.encode(session,command),session).operation());
  args.addProperty("password","PRIVATE_SENTINEL");var bad=new LabHostGuiProtocol.Command(1,UUID.randomUUID(),operation,2000,args);
  assertThrows(IllegalArgumentException.class,()->LabHostGuiProtocol.command(LabHostGuiProtocol.encode(session,bad),session));
 }
 @Test void recordingRetainsOnlyTheFixedSyntheticSecretReference() throws Exception {
  var session=session();var command=new LabHostGuiProtocol.Command(1,UUID.randomUUID(),LabHostGuiProtocol.Operation.RECORD_BROWSER_LOGIN,2000,args(LabHostGuiProtocol.Operation.RECORD_BROWSER_LOGIN));
  var observed=new JsonObject();observed.addProperty("nativeStart",true);observed.addProperty("initialStepsCleared",true);observed.addProperty("browserVersion","156.0.8078.48");
  var value=LabHostGuiProtocol.retainedReceipt(LabHostGuiProtocol.receipt(session,command,1000,1500,"PASS","COMPLETED",observed),session,command);
  assertEquals("FORM_B",value.getAsJsonObject("intent").get("secretRef").getAsString());assertFalse(value.getAsJsonObject("intent").has("secret"));
  value.getAsJsonObject("intent").addProperty("secretRef","PRIVATE_SENTINEL");assertThrows(IllegalArgumentException.class,()->LabHostGuiProtocol.validateRetainedReceipt(value,session));
 }
 @Test void themesSizesAndSecretReferencesAreClosed() throws Exception {
  var session=session();
  for(String field:List.of("theme","size")) {
   var args=args(LabHostGuiProtocol.Operation.BROWSER_SETTINGS);args.addProperty(field,"PRIVATE_SENTINEL");
   var command=new LabHostGuiProtocol.Command(1,UUID.randomUUID(),LabHostGuiProtocol.Operation.BROWSER_SETTINGS,2000,args);
   assertThrows(IllegalArgumentException.class,()->LabHostGuiProtocol.command(LabHostGuiProtocol.encode(session,command),session));
  }
  var args=args(LabHostGuiProtocol.Operation.RECORD_BROWSER_LOGIN);args.addProperty("secret","HTTP_B");
  var command=new LabHostGuiProtocol.Command(1,UUID.randomUUID(),LabHostGuiProtocol.Operation.RECORD_BROWSER_LOGIN,2000,args);
  assertThrows(IllegalArgumentException.class,()->LabHostGuiProtocol.command(LabHostGuiProtocol.encode(session,command),session));
 }
}
