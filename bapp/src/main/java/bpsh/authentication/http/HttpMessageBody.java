package bpsh.authentication.http;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/** Immutable owned chunks. Every handle must close; borrowed views expire with that handle. */
public final class HttpMessageBody implements AutoCloseable {
    /** One shared accounting owner for all transport payloads and owned wire copies. */
    public static final class Allocator {
        private final long maximum;
        private long used;
        public Allocator(long maximum) {
            if(maximum<0)throw new IllegalArgumentException("Invalid HTTP buffer capacity.");
            this.maximum=maximum;
        }
        private synchronized void reserve(long count) throws IOException {
            if(count>maximum-used)throw new IOException("HTTP authentication buffering capacity is exhausted.");
            used+=count;
        }
        private synchronized void release(long count) {used-=count;}
        public synchronized long usedBytes() {return used;}
        public Builder builder(int maximumBytes) {return new Builder(this,maximumBytes);}
        /** Reserves a single unavoidable host-boundary materialization before allocation. */
        public OwnedBytes bytes(int count) throws IOException {
            if(count<0)throw new IllegalArgumentException("Invalid HTTP copy size.");
            reserve(count);
            try {return new OwnedBytes(this,new byte[count]);}
            catch(RuntimeException|Error failure) {release(count);throw failure;}
        }
    }
    /** Caller-owned host copy; borrowing the array does not transfer its reservation. */
    public static final class OwnedBytes implements AutoCloseable {
        private final Allocator allocator;
        private final byte[] bytes;
        private boolean closed;
        private OwnedBytes(Allocator allocator,byte[] bytes) {this.allocator=allocator;this.bytes=bytes;}
        public synchronized byte[] borrowed() {if(closed)throw new IllegalStateException("HTTP copy is closed.");return bytes;}
        @Override public synchronized void close() {if(!closed) {closed=true;allocator.release(bytes.length);}}
    }

    /** Reserves exact chunk capacity before allocating or copying application bytes. */
    public static final class Builder implements AutoCloseable {
        private final Allocator allocator;
        private final int maximum;
        private final ArrayList<byte[]> chunks=new ArrayList<>();
        private int length;
        private boolean closed;
        private Builder(Allocator allocator,int maximum) {
            if(maximum<0)throw new IllegalArgumentException("Invalid HTTP body limit.");
            this.allocator=allocator;this.maximum=maximum;
        }
        public void append(ByteBuffer source) throws IOException {
            if(closed)throw new IllegalStateException("HTTP body builder is closed.");
            if(source.remaining()>maximum-length)throw new IOException("The HTTP body exceeds its configured limit.");
            while(source.hasRemaining()) {
                int count=Math.min(8192,source.remaining());
                allocator.reserve(count);
                byte[] chunk;
                try {chunk=new byte[count];source.get(chunk);chunks.add(chunk);}
                catch(RuntimeException|Error failure) {allocator.release(count);throw failure;}
                length+=count;
            }
        }
        public HttpMessageBody finish() {
            if(closed)throw new IllegalStateException("HTTP body builder is closed.");
            var body=new HttpMessageBody(new Shared(allocator,List.copyOf(chunks),length));
            closed=true;chunks.clear();return body;
        }
        @Override public void close() {
            if(closed)return;closed=true;chunks.clear();allocator.release(length);length=0;
        }
    }

    private static final class Shared {
        final Allocator allocator;
        final List<byte[]> chunks;
        final int length;
        int handles=1;
        Shared(Allocator allocator,List<byte[]> chunks,int length) {this.allocator=allocator;this.chunks=chunks;this.length=length;}
        synchronized void retain() {if(handles==0)throw new IllegalStateException("HTTP body is closed.");handles++;}
        synchronized void release() {if(--handles==0)allocator.release(length);}
    }
    private final Shared shared;
    private boolean closed;
    private HttpMessageBody(Shared shared) {this.shared=shared;}
    private void check() {if(closed)throw new IllegalStateException("HTTP body is closed.");}
    public synchronized int length() {check();return shared.length;}
    public synchronized List<ByteBuffer> buffers() {
        check();return shared.chunks.stream().map(bytes->ByteBuffer.wrap(bytes).asReadOnlyBuffer()).toList();
    }
    public synchronized HttpMessageBody retain() {check();shared.retain();return new HttpMessageBody(shared);}
    public synchronized void writeTo(OutputStream destination) throws IOException {
        check();for(byte[] chunk:shared.chunks)destination.write(chunk);
    }
    @Override public synchronized void close() {if(!closed) {closed=true;shared.release();}}
    @Override public String toString() {return "HttpMessageBody[redacted]";}
}
