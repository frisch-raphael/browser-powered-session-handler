package bpsh;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** A failed owner or host diagnostic must not prevent later mandatory cleanup. */
class ExtensionCleanupTest {
    @Test void everyCleanupRunsEvenWhenBothAnOwnerAndTheLoggerFail() {
        var closed = new ArrayList<Integer>();
        Extension.cleanup(message -> { throw new IllegalStateException("Logger unavailable"); },
                () -> closed.add(1), () -> { throw new IllegalStateException("Controlled close failure"); },
                () -> closed.add(2), () -> { throw new LinkageError("Controlled unloaded dependency"); }, () -> closed.add(3));
        assertEquals(List.of(1, 2, 3), closed);
    }
}
