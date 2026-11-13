package bpsh.burp.http;

import bpsh.authentication.http.HttpAuthenticationService;
import bpsh.authentication.http.HttpMessageBody;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;
import org.brotli.dec.BrotliInputStream;

/** Bounded content decoding for spoofed Burp responses, whose bodies bypass normal network unpacking. */
final class HttpResponseContent {
    /** Same representation ceiling as native HTTP delivery, applied independently to every coding layer. */
    private static final int MAX_BYTES = 16 * 1024 * 1024;
    private HttpResponseContent() { }

    /** Returns an independently owned response; the caller retains ownership of the original encoded response. */
    static HttpAuthenticationService.Response decode(HttpMessageBody.Allocator allocator, String method,
                                                      HttpAuthenticationService.Response original) throws IOException {
        var codings = new ArrayList<String>();
        if (method.equalsIgnoreCase("HEAD") || original.status() == 204 || original.status() == 304
                || original.status() == 206 || original.body().length() == 0
                || original.headers().stream().anyMatch(h -> h.name().equalsIgnoreCase("Content-Range"))) return retain(original);
        for (var header : original.headers()) if (header.name().equalsIgnoreCase("Content-Encoding")) {
            for (String coding : header.value().split(",", -1)) {
                String normalized = coding.trim().toLowerCase(Locale.ROOT);
                if (!List.of("br", "gzip", "x-gzip", "deflate", "identity").contains(normalized)
                        || codings.size() == 4) return retain(original);
                codings.add(normalized);
            }
        }
        if (codings.isEmpty() || codings.stream().allMatch("identity"::equals)) return retain(original);
        HttpMessageBody current = original.body().retain();
        try {
            for (int index = codings.size() - 1; index >= 0; index--) {
                String coding = codings.get(index);
                if (coding.equals("identity")) continue;
                InputStream decoded;
                try {
                    InputStream source = stream(current);
                    decoded = switch (coding) {
                        case "br" -> new BrotliInputStream(source);
                        case "gzip", "x-gzip" -> new GZIPInputStream(source);
                        default -> new InflaterInputStream(source);
                    };
                } catch (IOException malformed) { return retain(original); }
                try (decoded; var builder = allocator.builder(MAX_BYTES)) {
                    byte[] bytes = new byte[8192];
                    while (true) {
                        int count;
                        // Malformed content is kept intact, never returned as a partial decoded success.
                        try { count = decoded.read(bytes); }
                        catch (IOException malformed) { return retain(original); }
                        if (count == -1) break;
                        // Capacity failures propagate separately from decoder errors and release all reservations.
                        builder.append(ByteBuffer.wrap(bytes, 0, count));
                    }
                    var next = builder.finish(); current.close(); current = next;
                }
            }
            var headers = original.headers().stream().filter(h -> !h.name().equalsIgnoreCase("Content-Encoding")
                    && !h.name().equalsIgnoreCase("Content-Length")).toList();
            return new HttpAuthenticationService.Response(original.status(), headers, current.retain(), original.authentication());
        } finally { current.close(); }
    }

    /** Keeps encoded bytes and encoding metadata together when decoding is inapplicable or unsuccessful. */
    private static HttpAuthenticationService.Response retain(HttpAuthenticationService.Response response) {
        return new HttpAuthenticationService.Response(response.status(), response.headers(), response.body().retain(), response.authentication());
    }

    /** Reads borrowed chunks without allocating an unaccounted whole-body copy. */
    private static InputStream stream(HttpMessageBody body) {
        return new InputStream() {
            private final java.util.Iterator<ByteBuffer> chunks = body.buffers().iterator();
            private ByteBuffer current = ByteBuffer.allocate(0);
            private boolean availableChunk() {
                while (!current.hasRemaining() && chunks.hasNext()) current = chunks.next();
                return current.hasRemaining();
            }
            @Override public int read() { return availableChunk() ? Byte.toUnsignedInt(current.get()) : -1; }
            @Override public int read(byte[] target, int offset, int length) {
                java.util.Objects.checkFromIndexSize(offset, length, target.length);
                if (length == 0) return 0;
                if (!availableChunk()) return -1;
                int count = Math.min(length, current.remaining()); current.get(target, offset, count); return count;
            }
        };
    }
}
