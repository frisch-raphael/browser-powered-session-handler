package lab.auth.gui;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
/** Protocol tests use only a controlled child; they make no GUI qualification claim. */
class HostGuiNativeQueryTest {
 static Process child(String mode) throws Exception {
  String executable=System.getProperty("os.name").startsWith("Windows")?"javaw.exe":"java";
  String classes=Path.of(Reply.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
  return new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin",executable).toString(),"-cp",classes,Reply.class.getName(),mode).start();
 }
 @Test void boundedResponsesCanShareOneOwnedNativeMonitor() throws Exception {
  var child=child("normal");try(var query=new HostGuiNativeQuery(child,5000)) {assertEquals("1234",query.ask("Q"));assertEquals("OK",query.ask("A"));assertEquals("156.0.8078.48",query.ask("V"));}
  assertFalse(child.isAlive());
 }
 @Test void oversizedResponseCannotLeaveTheMonitorRunning() throws Exception {
  var child=child("long");try(var query=new HostGuiNativeQuery(child,5000)){assertThrows(HostGuiSelectors.Failure.class,()->query.ask("Q"));}
  assertFalse(child.isAlive());
 }
 @Test void aMissingResponseCannotBlockTheRecordingWorker() throws Exception {
  var child=child("hang");try(var query=new HostGuiNativeQuery(child,300)){assertThrows(HostGuiSelectors.Failure.class,()->query.ask("Q"));}
  assertFalse(child.isAlive());
 }
 public static class Reply {
  public static void main(String[] args) throws Exception {
   var input=new java.io.BufferedReader(new java.io.InputStreamReader(System.in));String command;
   while((command=input.readLine())!=null) {
    if(args[0].equals("hang")){Thread.sleep(10000);continue;}
    if(args[0].equals("long")){System.out.println("x".repeat(100));System.out.flush();continue;}
    System.out.println(command.equals("Q")?"1234":command.equals("A")?"OK":"156.0.8078.48");System.out.flush();
   }
  }
 }
}
