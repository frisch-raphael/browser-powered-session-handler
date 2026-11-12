package bpsh.browser.runtime;

import bpsh.authentication.AuthenticationFailure;
import com.google.gson.JsonObject;
import com.microsoft.playwright.CDPSession;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class BoundedTokenResponsesTest {
    private static final int LIMIT=1<<20;
    @Test void completedWorkerReadsRequirePositiveBoundedObservedBytes() {
        var calls=new AtomicInteger();var session=response("unread",false,calls);
        for(long size:new long[]{Long.MIN_VALUE,-1,0,LIMIT+1L,Long.MAX_VALUE})
            assertThrows(AuthenticationFailure.class,()->BoundedTokenResponses.completedWorkerBody(session,"owned",size));
        assertEquals(0,calls.get(),"Invalid/missing size evidence must never retrieve a body");
    }
    @Test void completedWorkerCannotReturnMoreOrFewerBytesThanObserved() {
        var session=response("abc",false,new AtomicInteger());
        for(long size:new long[]{1,2,4,LIMIT})assertThrows(AuthenticationFailure.class,()->BoundedTokenResponses.completedWorkerBody(session,"owned",size));
    }
    @Test void completionRaceKeepsExactLimitForBase64AndUtf8() throws Exception {
        byte[] expected="x".repeat(LIMIT).getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(expected,BoundedTokenResponses.completedWorkerBody(response(new String(expected,StandardCharsets.UTF_8),false,new AtomicInteger()),"owned",LIMIT));
        assertArrayEquals(expected,BoundedTokenResponses.completedWorkerBody(response(Base64.getEncoder().encodeToString(expected),true,new AtomicInteger()),"owned",LIMIT));
        String nonAscii="\u20ac";byte[] unicode=nonAscii.getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(unicode,BoundedTokenResponses.completedWorkerBody(response(nonAscii,false,new AtomicInteger()),"owned",unicode.length));
        assertThrows(AuthenticationFailure.class,()->BoundedTokenResponses.completedWorkerBody(response("x".repeat(LIMIT+1),false,new AtomicInteger()),"owned",LIMIT));
        assertThrows(AuthenticationFailure.class,()->BoundedTokenResponses.completedWorkerBody(response(Base64.getEncoder().encodeToString(new byte[LIMIT+1]),true,new AtomicInteger()),"owned",LIMIT));
    }
    private static CDPSession response(String body,boolean base64,AtomicInteger calls) {
        return (CDPSession)Proxy.newProxyInstance(CDPSession.class.getClassLoader(),new Class<?>[]{CDPSession.class},(proxy,method,args)->{
            assertEquals("send",method.getName());assertEquals("Network.getResponseBody",args[0]);
            assertEquals("owned",((JsonObject)args[1]).get("requestId").getAsString());calls.incrementAndGet();
            var result=new JsonObject();result.addProperty("body",body);result.addProperty("base64Encoded",base64);return result;
        });
    }
}
