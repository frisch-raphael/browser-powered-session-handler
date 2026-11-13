package bpsh.browser.runtime;

import bpsh.authentication.AuthenticationFailure;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.CDPSession;
import com.microsoft.playwright.Page;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class BoundedTokenResponseEventsTest {
    @Test void completedResponseCanFinishAfterTheStreamRpcFails() {
        var protocol=new Protocol();protocol.duringStream=()->{
            protocol.response(false);protocol.data();
        };
        try(var owner=protocol.open()) {
            protocol.request();protocol.finish();
            assertEquals(1,protocol.bodyReads);assertEquals(List.of("token"),protocol.captured);assertTrue(protocol.failures.isEmpty());
        }
    }
    @Test void memoryCacheFlagSurvivesAResponseWithFalseDiskAndPrefetchFlags() {
        var protocol=new Protocol();protocol.duringStream=()->{
            protocol.emit("Network.requestServedFromCache","{\"requestId\":\"one\"}");
            protocol.response(false);protocol.data();protocol.finish();
        };
        try(var owner=protocol.open()) {
            protocol.request();
            assertEquals(0,protocol.bodyReads);assertTrue(protocol.captured.isEmpty());assertEquals(1,protocol.failures.size());
        }
    }
    @Test void responseCacheEligibilityIsAppliedBeforeAReentrantStreamRpc() {
        var protocol=new Protocol();protocol.duringStream=()->{protocol.data();protocol.finish();};
        try(var owner=protocol.open()) {
            protocol.response(true);
            assertEquals(0,protocol.bodyReads);assertTrue(protocol.captured.isEmpty());assertEquals(1,protocol.failures.size());
        }
    }
    @Test void completedSizeEvidenceSurvivesTheOwnedTargetsSanitizedStreamFailure() {
        var protocol=new Protocol();protocol.streamFailure="The owned Chromium target protocol failed.";
        protocol.duringStream=()->{protocol.response(false);protocol.data();};
        try(var owner=protocol.open()) {
            protocol.request();assertEquals(0,protocol.bodyReads,"A failed stream alone never authorizes retrieval");
            protocol.finish();
            assertEquals(1,protocol.bodyReads);assertEquals(List.of("token"),protocol.captured);assertTrue(protocol.failures.isEmpty());
        }
    }
    /** Models the external protocol's synchronous event dispatch while a command is in flight. */
    private static final class Protocol {
        final Map<String,Consumer<JsonObject>> listeners=new HashMap<>();
        final List<String> captured=new ArrayList<>();final List<AuthenticationFailure> failures=new ArrayList<>();
        int bodyReads;Runnable duringStream;
        String streamFailure="Request with the provided ID has already finished loading";
        /** Exercise response callbacks directly; real-browser tests own target startup and attachment. */
        BoundedTokenResponses open() {
            try {
                var constructor=BoundedTokenResponses.class.getDeclaredConstructor(BrowserContext.class,BoundedTokenResponses.Capture.class);
                constructor.setAccessible(true);var owner=constructor.newInstance(context,capture);
                var intercept=BoundedTokenResponses.class.getDeclaredMethod("intercept",CDPSession.class,BoundedTokenResponses.Capture.class);
                intercept.setAccessible(true);intercept.invoke(owner,session,capture);return owner;
            } catch(ReflectiveOperationException failure) {throw new AssertionError(failure);}
        }
        final BoundedTokenResponses.Capture capture=new BoundedTokenResponses.Capture(){
            public boolean matches(String url){return true;}public boolean passive(String url){return true;}
            public boolean complete(){return !captured.isEmpty();}public void declaredLength(String length){}
            public void response(String url,byte[] body,boolean success){captured.add(new String(body,java.nio.charset.StandardCharsets.UTF_8));}
            public void failure(AuthenticationFailure error){failures.add(error);}
        };
        @SuppressWarnings("unchecked")
        final CDPSession session=proxy(CDPSession.class,(method,args)->{
            if(method.equals("on")){listeners.put((String)args[0],(Consumer<JsonObject>)args[1]);return null;}
            if(method.equals("send")) {
                if(args[0].equals("Network.streamResourceContent")) {
                    duringStream.run();throw new RuntimeException(streamFailure);
                }
                if(args[0].equals("Network.getResponseBody")){bodyReads++;return json("{\"body\":\"token\",\"base64Encoded\":false}");}
                return new JsonObject();
            }
            return null;
        });
        final Page page=proxy(Page.class,(method,args)->null);
        final BrowserContext context=proxy(BrowserContext.class,(method,args)->switch(method){
            case "pages"->List.of(page);case "newCDPSession"->session;default->null;
        });
        void request(){emit("Network.requestWillBeSent","{\"requestId\":\"one\",\"request\":{\"url\":\"https://example.test/token\"}}");}
        void response(boolean cached){emit("Network.responseReceived","{\"requestId\":\"one\",\"response\":{\"url\":\"https://example.test/token\",\"status\":200,\"fromDiskCache\":"+cached+",\"fromPrefetchCache\":false}}");}
        void data(){emit("Network.dataReceived","{\"requestId\":\"one\",\"dataLength\":5}");}
        void finish(){emit("Network.loadingFinished","{\"requestId\":\"one\"}");}
        void emit(String event,String body){listeners.get(event).accept(json(body));}
        static JsonObject json(String text){return JsonParser.parseString(text).getAsJsonObject();}
        interface Call {Object invoke(String method,Object[] args);}
        @SuppressWarnings("unchecked") static <T>T proxy(Class<T> type,Call call){
            return (T)Proxy.newProxyInstance(type.getClassLoader(),new Class<?>[]{type},(proxy,method,args)->{
                if(method.getDeclaringClass()==Object.class)return switch(method.getName()){
                    case "hashCode"->System.identityHashCode(proxy);case "equals"->proxy==args[0];default->type.getSimpleName();};
                return call.invoke(method.getName(),args);
            });
        }
    }
}
