package bpsh.transport.httpauth;

import bpsh.authentication.http.HttpMessageBody;
import org.apache.hc.core5.http.io.entity.AbstractHttpEntity;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Iterator;

/** Repeatable entity borrowing the delivery's immutable request-body handle. */
final class HttpBodyEntity extends AbstractHttpEntity {
    private final HttpMessageBody body;
    HttpBodyEntity(HttpMessageBody body) {super((String)null,null,false);this.body=body;}
    @Override public long getContentLength() {return body.length();}
    @Override public boolean isRepeatable() {return true;}
    @Override public boolean isStreaming() {return false;}
    @Override public void close() { /* The worker owns the body through its actual exit. */ }
    @Override public void writeTo(OutputStream output) throws IOException {body.writeTo(output);}
    @Override public InputStream getContent() {
        return new InputStream() {
            final Iterator<ByteBuffer> chunks=body.buffers().iterator();
            ByteBuffer current=ByteBuffer.allocate(0);
            private boolean availableChunk() {
                while(!current.hasRemaining() && chunks.hasNext())current=chunks.next();
                return current.hasRemaining();
            }
            @Override public int read() {return availableChunk()?Byte.toUnsignedInt(current.get()):-1;}
            @Override public int read(byte[] bytes,int offset,int length) {
                java.util.Objects.checkFromIndexSize(offset,length,bytes.length);
                if(length==0)return 0;
                if(!availableChunk())return -1;
                int count=Math.min(length,current.remaining());current.get(bytes,offset,count);return count;
            }
        };
    }
}
