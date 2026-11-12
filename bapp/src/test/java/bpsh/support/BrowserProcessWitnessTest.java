package bpsh.support;

import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Verifies actual descendant lifetimes without launching a browser or native provider. */
class BrowserProcessWitnessTest {
    @Test void browserAttemptDoesNotOwnTheSuiteProviderJvm() throws Exception {
        try (var helper = new Helper(); var witness = new BrowserProcessWitness()) {
            witness.sample();
            witness.close();
            assertEquals(0, witness.processes());
            assertTrue(helper.child.isAlive(), "Closing an attempt must not close the shared provider.");
        }
    }
    @Test void providerWitnessRetainsHelpersUntilTheirSuiteOwnerCloses() throws Exception {
        try (var witness = new BrowserProcessWitness(BrowserProcessWitness.Scope.PROVIDER)) {
            try (var helper = new Helper()) {
                witness.sample(); assertEquals(1, witness.processes()); assertTrue(helper.child.isAlive());
            }
            witness.close(); assertEquals(0, witness.alive());
        }
    }
    @Test void providerWitnessRejectsALiveHelper() throws Exception {
        try (var helper = new Helper()) {
            var witness = new BrowserProcessWitness(BrowserProcessWitness.Scope.PROVIDER);
            witness.sample();
            assertThrows(AssertionError.class, witness::close);
            assertEquals(1, witness.processes()); assertEquals(1, witness.alive());
        }
    }
    @Test void closingABrowserScopeKeepsTheSharedProviderSamplerRunning() throws Exception {
        try (var providers = new BrowserProcessWitness(BrowserProcessWitness.Scope.PROVIDER)) {
            try (var first = new Helper()) {
                try (var browser = new BrowserProcessWitness()) {
                    awaitProcesses(providers,1); browser.close(); assertTrue(first.child.isAlive());
                }
                try (var second = new Helper()) { awaitProcesses(providers,2); }
            }
            providers.close(); assertEquals(0,providers.alive());
        }
    }
    private static void awaitProcesses(BrowserProcessWitness witness,int count) throws Exception {
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
        while(witness.processes()<count&&System.nanoTime()<deadline)Thread.sleep(10);
        assertEquals(count,witness.processes());
    }
    static final class Helper implements AutoCloseable {
        final Process child;
        Helper() throws Exception {
            String executable = System.getProperty("os.name").startsWith("Windows") ? "javaw.exe" : "java";
            String classes = Path.of(Sleeper.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
            child = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", executable).toString(),
                    "-cp", classes, Sleeper.class.getName()).start();
            assertEquals(1, child.getInputStream().read());
        }
        @Override public void close() throws Exception {
            child.getOutputStream().close();
            if (!child.waitFor(5, TimeUnit.SECONDS)) child.destroyForcibly().waitFor(5, TimeUnit.SECONDS);
        }
    }
    public static final class Sleeper {
        public static void main(String[] args) throws Exception {
            System.out.write(1); System.out.flush(); System.in.read();
        }
    }
}
