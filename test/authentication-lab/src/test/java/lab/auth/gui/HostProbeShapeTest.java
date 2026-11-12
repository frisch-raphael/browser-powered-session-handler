package lab.auth.gui;

import java.util.*;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

class HostProbeShapeTest {
    private static HostProbeShape.Header h(String name,String value){return new HostProbeShape.Header(name,value);}
    @Test void retainsOnlySyntheticCorrelationAndCredentialShape() {
        var shape=HostProbeShape.inspect(List.of(h("X-AuthLab-Request","h0123456789abcdef"),h("authorization","SECRET_SENTINEL"),
                h("Cookie","LAB_C1=SECRET_SENTINEL; other=ignored"),h("BPSP-HTTP-AUTHENT","private-alias"),h("X-AuthLab-Sentinel","unchanged")),"/protected",new byte[0],false);
        assertEquals("h0123456789abcdef",shape.nonce());assertFalse(shape.invalidNonce());assertEquals(1,shape.authorizationHeaders());
        assertEquals(1,shape.cookieHeaders());assertTrue(shape.c1());assertFalse(shape.c2());assertTrue(shape.httpDirective());assertTrue(shape.sentinel());
        assertFalse(shape.toString().contains("SECRET_SENTINEL"));assertFalse(shape.toString().contains("private-alias"));
    }
    @Test void duplicateOrArbitraryCorrelationCannotBecomePublishedText() {
        for(var headers:List.of(List.of(h("X-AuthLab-Request","SECRET_SENTINEL")),List.of(h("X-AuthLab-Request","h0123456789abcdef"),h("x-authlab-request","h0123456789abcdef")))) {
            var shape=HostProbeShape.inspect(headers,"/",new byte[0],false);assertNull(shape.nonce());assertTrue(shape.invalidNonce());assertFalse(shape.toString().contains("SECRET_SENTINEL"));
        }
    }
    @Test void boundedInspectionMarksEveryTruncationIncomplete() {
        assertTrue(HostProbeShape.inspect(List.of(h("Cookie","x".repeat(HostProbeShape.LIMIT+1))),"/",new byte[0],false).truncated());
        assertTrue(HostProbeShape.inspect(List.of(),"x".repeat(HostProbeShape.LIMIT+1),new byte[0],false).truncated());
        assertTrue(HostProbeShape.inspect(List.of(),"/",new byte[HostProbeShape.LIMIT+1],false).truncated());
        assertTrue(HostProbeShape.inspect(List.of(),"/",new byte[0],true).truncated());
        assertTrue(HostProbeShape.inspect(List.of(),"/",new byte[0],false).nonce()==null);
    }
    @Test void tagsInHeadersPathAndBodyAreObservedWithoutTheirContents() {
        assertTrue(HostProbeShape.inspect(List.of(h("X-Test","<@secret>")),"/",new byte[0],false).nativeTag());
        assertTrue(HostProbeShape.inspect(List.of(),"/<@secret>",new byte[0],false).nativeTag());
        assertTrue(HostProbeShape.inspect(List.of(),"/","<@secret>".getBytes(java.nio.charset.StandardCharsets.US_ASCII),false).nativeTag());
    }
}
