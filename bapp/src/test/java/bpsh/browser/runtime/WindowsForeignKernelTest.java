package bpsh.browser.runtime;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.JRE;
import org.junit.jupiter.api.condition.OS;
import static org.junit.jupiter.api.Assertions.*;

/** Checks the real x64 ABI and captured Windows errors independently of the job algorithm doubles. */
@EnabledOnOs(OS.WINDOWS) @EnabledForJreRange(min = JRE.JAVA_22)
class WindowsForeignKernelTest {
    @Test void createsQueriesAndReleasesARealJobWithExactWindowsStructLayouts() {
        var kernel = new WindowsForeignKernel();
        long job = kernel.CreateJobObjectW(0, 0);
        assertNotEquals(0, job);
        try {
            var limits = ByteBuffer.allocate(144).order(ByteOrder.LITTLE_ENDIAN); limits.putInt(16, 0x2000);
            assertTrue(kernel.SetInformationJobObject(job, 9, limits, limits.capacity()));
            var accounting = ByteBuffer.allocate(48).order(ByteOrder.LITTLE_ENDIAN);
            assertTrue(kernel.QueryInformationJobObject(job, 1, accounting, accounting.capacity(), 0));
            assertEquals(0, accounting.getInt(40));
        } finally { assertTrue(kernel.CloseHandle(job)); }
    }

    @Test void capturesActualErrorsBeforeReturningAndKeepsThemSeparateAcrossWorkers() throws Exception {
        var kernel = new WindowsForeignKernel(); var barrier = new CyclicBarrier(2);
        try (var workers = Executors.newFixedThreadPool(2)) {
            var missing = workers.submit(() -> {
                assertEquals(0, kernel.OpenProcess(0x1000, false, 0));
                barrier.await(5, TimeUnit.SECONDS);
                assertEquals(87, kernel.GetLastError()); return true;
            });
            var invalid = workers.submit(() -> {
                assertFalse(kernel.CloseHandle(0));
                barrier.await(5, TimeUnit.SECONDS);
                assertEquals(6, kernel.GetLastError()); return true;
            });
            assertTrue(missing.get(10, TimeUnit.SECONDS)); assertTrue(invalid.get(10, TimeUnit.SECONDS));
        }
    }
}
