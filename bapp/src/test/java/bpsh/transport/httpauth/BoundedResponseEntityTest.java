package bpsh.transport.httpauth;

import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.InputStreamEntity;
import org.junit.jupiter.api.Test;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

class BoundedResponseEntityTest {
    private static final int LIMIT = HttpClientAuthenticationTransport.MAX_RESPONSE_BYTES;

    @Test void rejectsOversizedDeclaredLengthWithoutReading() {
        AtomicInteger aborts = new AtomicInteger();
        var input = new ByteArrayInputStream(new byte[]{1});
        assertThrows(IOException.class, () -> new BoundedResponseEntity(
                new InputStreamEntity(input, LIMIT + 1L, ContentType.APPLICATION_OCTET_STREAM), aborts::incrementAndGet));
        assertEquals(1, input.available());
        assertEquals(1, aborts.get());
    }

    @Test void internalChallengeDrainAcceptsExactlyTheLimit() throws Exception {
        AtomicInteger aborts = new AtomicInteger();
        var input = new ByteArrayInputStream(new byte[LIMIT]);
        var entity = new BoundedResponseEntity(new InputStreamEntity(input, -1, ContentType.APPLICATION_OCTET_STREAM), aborts::incrementAndGet);
        entity.getContent().close();
        entity.close();
        assertEquals(0, input.available());
        assertEquals(0, aborts.get());
    }

    @Test void internalChallengeDrainStopsAfterOneExcessByteAndAbortsOnce() throws Exception {
        AtomicInteger aborts = new AtomicInteger();
        var input = new ByteArrayInputStream(new byte[LIMIT + 100]);
        var entity = new BoundedResponseEntity(new InputStreamEntity(input, -1, ContentType.APPLICATION_OCTET_STREAM), aborts::incrementAndGet);
        assertThrows(IOException.class, () -> entity.getContent().close());
        entity.close();
        assertEquals(99, input.available());
        assertEquals(1, aborts.get());
    }

    @Test void failureDuringReadCannotStartAnUnboundedDrainOnClose() throws Exception {
        AtomicInteger aborts = new AtomicInteger();
        var input = new ByteArrayInputStream(new byte[LIMIT + 100]);
        var entity = new BoundedResponseEntity(new InputStreamEntity(input, -1, ContentType.APPLICATION_OCTET_STREAM), aborts::incrementAndGet);
        assertThrows(IOException.class, () -> entity.getContent().transferTo(java.io.OutputStream.nullOutputStream()));
        assertThrows(IOException.class, entity::close);
        entity.close();
        assertEquals(99, input.available());
        assertEquals(1, aborts.get());
    }
}
