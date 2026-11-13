package bpsh.burp.http;

import bpsh.authentication.http.HttpAuthenticationService;
import bpsh.authentication.http.HttpAuthenticationEvidence;
import bpsh.authentication.http.HttpMessageBody;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Verifies decoded bytes, exact encoding metadata, fallback fidelity and bounded memory ownership. */
class HttpResponseContentTest {
    @Test void compressedJsonIsReadableAndHasConsistentHeaders() throws Exception {
        for (String coding : List.of("br", "gzip", "deflate")) {
            byte[] encoded = lab.auth.EncodedResponseFixture.encoded(coding);
            var response = new HttpAuthenticationService.Response(200, List.of(
                    new HttpAuthenticationService.Header("Content-Type", "application/json; charset=utf-8"),
                    new HttpAuthenticationService.Header("Content-Encoding", coding),
                    new HttpAuthenticationService.Header("Content-Length", Integer.toString(encoded.length)),
                    new HttpAuthenticationService.Header("Set-Cookie", "a=1"), new HttpAuthenticationService.Header("Set-Cookie", "b=2")),
                    bpsh.support.IntegrationFixtures.httpBody(encoded), new HttpAuthenticationEvidence(null, HttpAuthenticationEvidence.Status.UNCONFIRMED));
            byte[] actual = wire("GET", response);
            String text = new String(actual, StandardCharsets.UTF_8);
            int offset = text.indexOf("\r\n\r\n") + 4;
            assertEquals(lab.auth.EncodedResponseFixture.JSON, text.substring(offset), coding);
            assertFalse(text.substring(0, offset).toLowerCase(java.util.Locale.ROOT).contains("content-encoding:"));
            assertTrue(text.contains("Content-Length: " + lab.auth.EncodedResponseFixture.JSON.getBytes(StandardCharsets.UTF_8).length + "\r\n"));
            assertTrue(text.contains("Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n"));
        }
    }

    @Test void stackedCodingsDecodeInReverseOrderAcrossDuplicateHeaders() throws Exception {
        var output = new java.io.ByteArrayOutputStream();
        try (var gzip = new java.util.zip.GZIPOutputStream(output)) { gzip.write(lab.auth.EncodedResponseFixture.encoded("br")); }
        for (var headers : List.of(List.of(header("br, gzip")), List.of(header("br"), header("gzip")))) {
            try (var response = response(200, headers, output.toByteArray())) {
                var allocator = new HttpMessageBody.Allocator(1024 * 1024);
                try (var decoded = HttpResponseContent.decode(allocator, "GET", response)) {
                    assertEquals(lab.auth.EncodedResponseFixture.JSON, text(decoded.body()));
                    assertTrue(decoded.headers().isEmpty());
                }
                assertEquals(0, allocator.usedBytes());
                assertArrayEquals(output.toByteArray(), bytes(response.body()));
            }
        }
    }

    @Test void unknownMalformedAndExcessiveCodingsKeepOriginalBytesAndAllHeaders() throws Exception {
        byte[] body = "not a compressed stream".getBytes(StandardCharsets.UTF_8);
        for (String coding : List.of("br", "gzip", "deflate", "br, zstd", "br,", "br,br,br,br,br")) {
            var headers = List.of(header(coding), new HttpAuthenticationService.Header("Content-Length", Integer.toString(body.length)));
            try (var response = response(200, headers, body)) {
                var allocator = new HttpMessageBody.Allocator(1024);
                try (var decoded = HttpResponseContent.decode(allocator, "GET", response)) {
                    assertArrayEquals(body, bytes(decoded.body()), coding);
                    assertEquals(headers, decoded.headers(), coding);
                }
                assertEquals(0, allocator.usedBytes());
            }
        }
    }

    @Test void headNoEntityAndPartialResponsesDoNotDecodeTheirRepresentationMetadata() throws Exception {
        for (var test : List.of(new String[]{"HEAD", "200"}, new String[]{"GET", "204"}, new String[]{"GET", "304"}, new String[]{"GET", "206"})) {
            byte[] body = lab.auth.EncodedResponseFixture.encoded("br");
            try (var response = response(Integer.parseInt(test[1]), List.of(header("br")), body)) {
                try (var decoded = HttpResponseContent.decode(new HttpMessageBody.Allocator(1024), test[0], response)) {
                    assertArrayEquals(body, bytes(decoded.body())); assertEquals(response.headers(), decoded.headers());
                }
            }
        }
    }

    @Test void expandedBodyLimitAndSharedBudgetFailuresReleaseDecodedReservations() throws Exception {
        // Independently generated with Node zlib.brotliCompressSync(Buffer.alloc(16 * 1024 * 1024 + 1, 65)).
        byte[] bomb = java.util.Base64.getDecoder().decode("y///P/glguKxQCD3/o///3/wSwDEYRGA7v0fAAACQQM=");
        try (var response = response(200, List.of(header("br")), bomb)) {
            var allocator = new HttpMessageBody.Allocator(64L * 1024 * 1024);
            assertThrows(java.io.IOException.class, () -> HttpResponseContent.decode(allocator, "GET", response));
            assertEquals(0, allocator.usedBytes());
        }
        try (var response = response(200, List.of(header("br")), lab.auth.EncodedResponseFixture.encoded("br"))) {
            var allocator = new HttpMessageBody.Allocator(8);
            assertThrows(java.io.IOException.class, () -> HttpResponseContent.decode(allocator, "GET", response));
            assertEquals(0, allocator.usedBytes());
        }
    }

    private static HttpAuthenticationService.Header header(String coding) { return new HttpAuthenticationService.Header("Content-Encoding", coding); }
    private static HttpAuthenticationService.Response response(int status, List<HttpAuthenticationService.Header> headers, byte[] bytes) {
        return new HttpAuthenticationService.Response(status, headers, bpsh.support.IntegrationFixtures.httpBody(bytes),
                new HttpAuthenticationEvidence(null, HttpAuthenticationEvidence.Status.UNCONFIRMED));
    }
    private static byte[] bytes(HttpMessageBody body) throws Exception {
        var output = new java.io.ByteArrayOutputStream(); body.writeTo(output); return output.toByteArray();
    }
    private static String text(HttpMessageBody body) throws Exception { return new String(bytes(body), StandardCharsets.UTF_8); }
    private static byte[] wire(String method, HttpAuthenticationService.Response response) throws Exception {
        var allocator = new HttpMessageBody.Allocator(32L * 1024 * 1024);
        try (response; var result = HttpAuthenticationResponse.wire(allocator, method, response)) { return result.borrowed().clone(); }
        finally { assertEquals(0, allocator.usedBytes()); }
    }
}
