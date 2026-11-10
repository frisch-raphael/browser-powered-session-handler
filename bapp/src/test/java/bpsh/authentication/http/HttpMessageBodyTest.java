package bpsh.authentication.http;

import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class HttpMessageBodyTest {
    @Test void reservesBeforeCopyAndKeepsBytesUntilTheLastHandleCloses() throws Exception {
        var allocator=new HttpMessageBody.Allocator(3);
        try(var builder=allocator.builder(3)) {
            byte[] source={1,2,3};builder.append(ByteBuffer.wrap(source));source[0]=9;
            var body=builder.finish();var retained=body.retain();
            assertEquals(3,allocator.usedBytes());assertEquals(1,body.buffers().getFirst().get(0));
            assertThrows(ReadOnlyBufferException.class,()->body.buffers().getFirst().put(0,(byte)8));
            body.close();body.close();assertEquals(3,allocator.usedBytes());
            assertThrows(IllegalStateException.class,body::retain);
            assertEquals(3,retained.length());retained.close();assertEquals(0,allocator.usedBytes());
        }
    }
    @Test void capacityAndBodyLimitFailuresDoNotLeakReservations() throws Exception {
        var allocator=new HttpMessageBody.Allocator(5);
        try(var builder=allocator.builder(8)) {
            builder.append(ByteBuffer.wrap(new byte[3]));
            assertThrows(IOException.class,()->builder.append(ByteBuffer.wrap(new byte[3])));
            assertEquals(3,allocator.usedBytes());
        }
        assertEquals(0,allocator.usedBytes());
        try(var builder=allocator.builder(2)) {
            assertThrows(IOException.class,()->builder.append(ByteBuffer.wrap(new byte[3])));
            assertEquals(0,allocator.usedBytes());
        }
    }
    @Test void unfinishedMultiChunkBuilderAndEmptyBodiesReleaseExactlyOnce() throws Exception {
        var allocator=new HttpMessageBody.Allocator(20000);
        var builder=allocator.builder(20000);builder.append(ByteBuffer.wrap(new byte[19000]));
        assertEquals(19000,allocator.usedBytes());builder.close();builder.close();assertEquals(0,allocator.usedBytes());
        try(var emptyBuilder=allocator.builder(0);var empty=emptyBuilder.finish()) {assertEquals(0,empty.length());assertTrue(empty.buffers().isEmpty());}
        assertEquals(0,allocator.usedBytes());
    }
}
