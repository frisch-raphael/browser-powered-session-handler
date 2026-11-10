package bpsh.transport.httpauth;

import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.HttpEntityWrapper;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/** Bounds every upstream entity, including challenge bodies drained internally by HttpClient. */
final class BoundedResponseEntity extends HttpEntityWrapper {
    private final Runnable abort;
    private InputStream content;
    private boolean aborted;

    BoundedResponseEntity(HttpEntity entity, Runnable abort) throws IOException {
        super(entity);
        this.abort = abort;
        if (entity.getContentLength() > HttpClientAuthenticationTransport.MAX_RESPONSE_BYTES) throw oversized();
    }

    @Override public InputStream getContent() throws IOException {
        if (content == null) content = new BoundedStream(super.getContent());
        return content;
    }

    @Override public void writeTo(OutputStream destination) throws IOException {
        getContent().transferTo(destination);
    }

    @Override public void close() throws IOException {
        getContent().close();
    }

    private IOException oversized() {
        abortOnce();
        return new IOException("The HTTP response exceeds the 16 MiB limit.");
    }

    private void abortOnce() {
        if (!aborted) { aborted = true; abort.run(); }
    }

    private final class BoundedStream extends InputStream {
        private final InputStream input;
        private int consumed;
        private boolean closed;

        BoundedStream(InputStream input) { this.input = input; }

        @Override public int read() throws IOException {
            if (closed) throw new IOException("Response stream is closed.");
            if (consumed > HttpClientAuthenticationTransport.MAX_RESPONSE_BYTES) throw oversized();
            int value = input.read();
            if (value >= 0 && ++consumed > HttpClientAuthenticationTransport.MAX_RESPONSE_BYTES) throw oversized();
            return value;
        }

        @Override public int read(byte[] buffer, int offset, int length) throws IOException {
            java.util.Objects.checkFromIndexSize(offset, length, buffer.length);
            if (closed) throw new IOException("Response stream is closed.");
            if (consumed > HttpClientAuthenticationTransport.MAX_RESPONSE_BYTES) throw oversized();
            int allowed = Math.min(length, HttpClientAuthenticationTransport.MAX_RESPONSE_BYTES - consumed + 1);
            int count = input.read(buffer, offset, allowed);
            if (count > 0) {
                consumed += count;
                if (consumed > HttpClientAuthenticationTransport.MAX_RESPONSE_BYTES) throw oversized();
            }
            return count;
        }

        @Override public void close() throws IOException {
            if (closed) return;
            try {
                // EntityUtils.consume closes rather than reads. Drain through the limit
                // before allowing the underlying HTTP stream to close and reuse its socket.
                byte[] discard = new byte[8192];
                while (read(discard) != -1) { }
                input.close();
            } catch (IOException | RuntimeException failure) {
                abortOnce();
                throw failure;
            } finally {
                closed = true;
            }
        }
    }
}
