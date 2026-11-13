package lab.auth;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Independently encoded, authenticated JSON responses shared by native transport and Burp hook tests. */
public final class EncodedResponseFixture {
    public static final String JSON = "{\"message\":\"Bonjour \u00e9t\u00e9\",\"ok\":true,"
            + "\"description\":\"This authenticated response contains ordinary JSON with readable names, repeated values, and international text.\","
            + "\"items\":[\"authentication\",\"authentication\",\"response\",\"response\"]}";
    // Node zlib.brotliCompressSync(Buffer.from(JSON, 'utf8')); no production decoder is used by the fixture.
    public static final String BROTLI_BASE64 = "G+cAQCwObBvKdYxXHpOXMTdDPd3m9cruT1LIggliR0QpspWab2HDySL0ljosXTY7YL+qeVuUYJYVJfj+4r/XGz6Ol4Mhcknxh/mAcOUp+aYM3pCHTV2APLw7PZ0dQ9ttOtEWXZUFta6ccgPkwEcHS/CvowiXFNzgGTYWBmJyQgxfIolECqYx9gc=";
    private EncodedResponseFixture() { }

    /** @return Independently compressed UTF-8 JSON with the requested content coding. */
    public static byte[] encoded(String coding) throws java.io.IOException {
        if (coding.equals("br")) return Base64.getDecoder().decode(BROTLI_BASE64);
        var output = new java.io.ByteArrayOutputStream();
        try (java.io.OutputStream compressor = coding.equals("gzip")
                ? new java.util.zip.GZIPOutputStream(output) : new java.util.zip.DeflaterOutputStream(output)) {
            compressor.write(JSON.getBytes(StandardCharsets.UTF_8));
        }
        return output.toByteArray();
    }

    /** Sends a real compressed representation only after the owning application's authentication gate. */
    static void reply(ChannelHandlerContext context, String coding, String nonce) throws java.io.IOException {
        byte[] body = encoded(coding);
        var response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK,
                io.netty.buffer.Unpooled.wrappedBuffer(body));
        response.headers().set("Content-Encoding", coding).set("Content-Type", "application/json; charset=utf-8")
                .set("Content-Length", body.length).add("Set-Cookie", "first=1").add("Set-Cookie", "second=2");
        if (nonce != null) response.headers().set("X-AuthLab-Request", nonce);
        context.writeAndFlush(response);
    }
}
