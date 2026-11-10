package bpsh.burp.http;

import bpsh.authentication.AuthenticationFailure;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class HttpAuthenticationDirectiveTest {
    @Test void consumesTheDirectiveAndAllAuthorizationBeforeTokenResolutionWhilePreservingOtherBytes() throws Exception {
        String original="POST /x HTTP/1.1\r\nHost: example.test\r\nBPSP-HTTP-AUTHENT: <@user-a/>\r\nAuthorization: <@discarded/>\r\naUtHoRiZaTiOn: Basic discarded\r\nCookie: session=<@browser/>\r\nContent-Length: 3\r\n\r\n\u0000\u00ffx";
        var selected=HttpAuthenticationDirective.consume(original.getBytes(StandardCharsets.ISO_8859_1));
        assertEquals("user-a",selected.alias());
        assertEquals("POST /x HTTP/1.1\r\nHost: example.test\r\nCookie: session=<@browser/>\r\nContent-Length: 3\r\n\r\n\u0000\u00ffx",new String(selected.request(),StandardCharsets.ISO_8859_1));
    }
    @Test void rejectsAmbiguousOrUnsupportedDirectivesInsteadOfSendingThemUpstream() {
        for(String headers:java.util.List.of("BPSP-HTTP-AUTHENT: <@a/>\r\nBPSP-HTTP-AUTHENT: <@b/>",
                "BPSP-HTTP-AUTHENT: <@a/><@b/>","BPSP-HTTP-AUTHENT: <@a token=\"x\"/>",
                "BPSP-HTTP-AUTHENT: user-a","BPSP-HTTP-AUTHENT: <@a/>\r\n Authorization: folded",
                "BPSP-HTTP-AUTHENT: <@a/>\r\nTransfer-Encoding: chunked")) {
            assertThrows(AuthenticationFailure.class,()->HttpAuthenticationDirective.consume(("GET / HTTP/1.1\r\nHost: example.test\r\n"+headers+"\r\n\r\n").getBytes(StandardCharsets.US_ASCII)));
        }
    }
    @Test void ordinaryRequestsRemainOutsideThisPolicy() throws Exception {
        assertNull(HttpAuthenticationDirective.consume("GET / HTTP/1.1\r\nHost: example.test\r\nAuthorization: Basic original\r\n\r\n".getBytes(StandardCharsets.US_ASCII)));
    }
    @Test void traceDirectiveIsRejectedBeforeCredentialResolution() {
        var failure=assertThrows(AuthenticationFailure.class,()->HttpAuthenticationDirective.consume(
                "TRACE / HTTP/1.1\r\nHost: example.test\r\nBPSP-HTTP-AUTHENT: <@a/>\r\n\r\n".getBytes(StandardCharsets.US_ASCII)));
        assertTrue(failure.getMessage().contains("TRACE"));
    }
}
