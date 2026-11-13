package bpsh.burp.http;

import bpsh.authentication.http.HttpAuthenticationService;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/** Converts a complete transport response into the originating tool's HTTP/1.1 response. */
final class HttpAuthenticationResponse {
    private HttpAuthenticationResponse() { }
    static bpsh.authentication.http.HttpMessageBody.OwnedBytes wire(bpsh.authentication.http.HttpMessageBody.Allocator allocator,String method, HttpAuthenticationService.Response response) throws java.io.IOException {
        try (var readable = HttpResponseContent.decode(allocator, method, response)) {
            return materialize(allocator, method, readable);
        }
    }
    /** Serializes an owned representation with its actual byte length and unchanged binary bytes. */
    private static bpsh.authentication.http.HttpMessageBody.OwnedBytes materialize(bpsh.authentication.http.HttpMessageBody.Allocator allocator,String method, HttpAuthenticationService.Response response) throws java.io.IOException {
        boolean metadataLength = method.equalsIgnoreCase("HEAD") || response.status() == 304;
        boolean noBody = metadataLength || response.status() == 204;
        var head = new StringBuilder("HTTP/1.1 ").append(response.status()).append(" Response\r\n");
        for (var header : response.headers()) {
            if (header.name().equalsIgnoreCase("Content-Length") && !metadataLength) continue;
            head.append(header.name()).append(": ").append(header.value()).append("\r\n");
        }
        int bodyLength=noBody?0:response.body().length();
        if (!noBody) head.append("Content-Length: ").append(bodyLength).append("\r\n");
        head.append("\r\n");
        byte[] prefix=head.toString().getBytes(StandardCharsets.ISO_8859_1);
        var owned=allocator.bytes(Math.addExact(prefix.length,bodyLength));
        try {
            byte[] target=owned.borrowed();System.arraycopy(prefix,0,target,0,prefix.length);
            int offset=prefix.length;
            if(!noBody)for(var chunk:response.body().buffers()) {int count=chunk.remaining();chunk.get(target,offset,count);offset+=count;}
            return owned;
        } catch(RuntimeException|Error failure) {owned.close();throw failure;}

    }
}
