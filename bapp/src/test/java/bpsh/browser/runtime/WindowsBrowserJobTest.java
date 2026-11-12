package bpsh.browser.runtime;

import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** Uses real OS-held files to verify process-group ownership after the original parent exits. */
@EnabledOnOs(OS.WINDOWS)
class WindowsBrowserJobTest {
    @TempDir Path temporary;

    @Test void closesAReparentedFileHolderWithoutTerminatingAnUnrelatedProcess() throws Exception {
        String classes = Path.of(WindowsBrowserJobTest.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        Path ownedFile = temporary.resolve("owned"), ownedReady = temporary.resolve("owned-ready");
        Path foreignFile = temporary.resolve("foreign"), foreignReady = temporary.resolve("foreign-ready");
        Process owner = helper(classes, "owner", ownedFile, ownedReady);
        Process foreign = helper(classes, "holder", foreignFile, foreignReady);
        WindowsBrowserJob job = null;
        try {
            job = WindowsBrowserJob.attach(owner);
            assertNotNull(job);
            owner.getOutputStream().write(1); owner.getOutputStream().flush();
            await(ownedReady); await(foreignReady);
            assertTrue(owner.waitFor(10, TimeUnit.SECONDS), "The parent must exit before group cleanup");
            assertThrows(java.nio.file.FileSystemException.class, () -> Files.delete(ownedFile), "The reparented child must still hold its file");
            job.close(System.nanoTime() + TimeUnit.SECONDS.toNanos(2));
            Files.delete(ownedFile);
            assertTrue(foreign.isAlive(), "An unrelated process must not be in the owned job");
            assertThrows(java.nio.file.FileSystemException.class, () -> Files.delete(foreignFile));
        } finally {
            if (job != null) job.close(System.nanoTime() + TimeUnit.SECONDS.toNanos(2));
            owner.destroyForcibly(); foreign.destroyForcibly();
            assertTrue(owner.waitFor(5, TimeUnit.SECONDS)); assertTrue(foreign.waitFor(5, TimeUnit.SECONDS));
        }
    }

    /** @param classes Test-only class directory. @param role Owned parent or file holder. @param file Owned fixture file. @param ready Readiness marker. @return Owned fixture process. */
    private static Process helper(String classes, String role, Path file, Path ready) throws Exception {
        return new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java.exe").toString(),
                "-cp", classes, ResourceProcess.class.getName(), role, classes, file.toString(), ready.toString())
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
    }

    /** @param marker Fixture readiness marker. @throws Exception If the fixture does not become ready. */
    private static void await(Path marker) throws Exception {
        long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (!Files.exists(marker) && System.nanoTime() < end) Thread.sleep(10);
        assertTrue(Files.exists(marker), "The owned resource fixture must become ready");
    }

    /** Test-only process fixture; it has no authentication, browser or application behavior. */
    public static final class ResourceProcess {
        /** @param args Fixture role, class directory, owned file and readiness marker. @throws Exception On fixture failure. */
        public static void main(String[] args) throws Exception {
            if (args[0].equals("owner")) {
                System.in.read();
                helper(args[1], "holder", Path.of(args[2]), Path.of(args[3]));
            } else {
                try (var held = FileChannel.open(Path.of(args[2]), StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                        com.sun.nio.file.ExtendedOpenOption.NOSHARE_DELETE)) {
                    Files.writeString(Path.of(args[3]), "ready"); Thread.sleep(60000);
                }
            }
        }
    }
}
