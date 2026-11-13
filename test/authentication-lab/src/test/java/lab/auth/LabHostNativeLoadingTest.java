package lab.auth;
import java.io.IOException;
import java.nio.file.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
class LabHostNativeLoadingTest {
 @TempDir Path root;
 @Test void nativeLoadingErrorSignaturesAreDetectedWithoutPublishingPrivateText() throws Exception {
  Files.writeString(root.resolve("burp-private-out.txt"),"Normal startup\n");Files.writeString(root.resolve("burp-private-error.txt"),"");
  assertEquals(0,LabHostBrowserRuntime.loadingErrors(root));
  Files.writeString(root.resolve("burp-private-error.txt"),"java.lang.UnsatisfiedLinkError: Native library already loaded in another classloader\n");
  assertEquals(1,LabHostBrowserRuntime.loadingErrors(root));
 }
 @Test void missingOrOversizeLogsCannotEstablishZeroLoadingErrors() throws Exception {
  Files.writeString(root.resolve("burp-private-out.txt"),"");assertThrows(IOException.class,()->LabHostBrowserRuntime.loadingErrors(root));
  try(var out=java.nio.channels.FileChannel.open(root.resolve("burp-private-error.txt"),StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE)) {
   out.position(8L*1024*1024);out.write(java.nio.ByteBuffer.wrap(new byte[]{1}));
  }
  assertThrows(IOException.class,()->LabHostBrowserRuntime.loadingErrors(root));
 }
}
