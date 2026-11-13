package lab.auth;

import java.nio.file.*;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises the real JDK launcher used by the federation fixture, without authentication. */
class FederationApplicationsLaunchTest {
    @TempDir Path temporary;

    @Test void javaArgumentFilesWorkBeyondTheWindowsLegacyPathLimit() throws Exception {
        Path directory=temporary.toAbsolutePath();
        while(directory.toString().length()<280)directory=directory.resolve("owned-argument-directory");
        Files.createDirectories(directory);
        Path arguments=directory.resolve("launch.args");Files.writeString(arguments,"-version\n");
        Path executable=Path.of(System.getProperty("java.home"),"bin",System.getProperty("os.name").startsWith("Windows")?"java.exe":"java");
        var process=new ProcessBuilder(executable.toString(),FederationApplications.javaArgumentFile(arguments)).redirectErrorStream(true).start();
        try {
            assertTrue(process.waitFor(10,TimeUnit.SECONDS),"The fixture's JDK launcher must finish.");
            assertEquals(0,process.exitValue(),"The JDK must open the argument file in a deep worktree path.");
            assertTrue(new String(process.getInputStream().readNBytes(4096),java.nio.charset.StandardCharsets.UTF_8).contains("version"));
        }finally{if(process.isAlive())process.destroyForcibly();}
    }
}
