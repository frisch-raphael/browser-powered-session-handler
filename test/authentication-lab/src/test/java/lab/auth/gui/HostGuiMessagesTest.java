package lab.auth.gui;

import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

class HostGuiMessagesTest {
    private static final String BEFORE="h0123456789abcdef",AFTER="hfedcba9876543210";
    @Test void preservesCopiedCredentialsAndBodyWhileChangingOnlySyntheticHeaderAndQuery() {
        String request="POST /protected?host_probe="+BEFORE+" HTTP/1.1\r\nHost: localhost:12345\r\nAuthorization: PRIVATE_SENTINEL\r\nCookie: LAB_C1=PRIVATE_COOKIE\r\nX-Test: host_probe="+BEFORE+"\r\nX-AuthLab-Request: "+BEFORE+"\r\n\r\nbody="+BEFORE;
        String changed=HostGuiMessages.nonce(request,BEFORE,AFTER);
        assertEquals(request.replace("/protected?host_probe="+BEFORE,"/protected?host_probe="+AFTER).replace("X-AuthLab-Request: "+BEFORE,"X-AuthLab-Request: "+AFTER),changed);
        assertTrue(changed.endsWith("body="+BEFORE));
    }
    @Test void duplicateMissingOrAlreadyReusedRequestCorrelationFailsClosed() {
        String request="GET / HTTP/1.1\nHost: localhost\nX-AuthLab-Request: "+BEFORE+"\n\n";
        assertThrows(HostGuiSelectors.Failure.class,()->HostGuiMessages.nonce(request,BEFORE,BEFORE));
        assertThrows(HostGuiSelectors.Failure.class,()->HostGuiMessages.nonce(request.replace("\n\n","\nX-AuthLab-Request: "+BEFORE+"\n\n"),BEFORE,AFTER));
        assertThrows(HostGuiSelectors.Failure.class,()->HostGuiMessages.nonce("GET / HTTP/1.1\nHost: localhost\n\n",BEFORE,AFTER));
    }
    @Test void visibleResponseMustContainExactlyTheCurrentSyntheticNonceAndARealStatus() {
        String response="HTTP/1.1 401 Unauthorized\r\nX-AuthLab-Request: "+AFTER+"\r\n\r\nbody";
        assertEquals(401,HostGuiMessages.response(response,AFTER));assertNull(HostGuiMessages.response(response,BEFORE));
        assertNull(HostGuiMessages.response(response.replace("\r\n\r\n","\r\nX-AuthLab-Request: "+AFTER+"\r\n\r\n"),AFTER));
        assertNull(HostGuiMessages.response("POST / HTTP/1.1\r\nX-AuthLab-Request: "+AFTER+"\r\n\r\n",AFTER));
    }
}
