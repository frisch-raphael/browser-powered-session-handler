package bpsh.burp.http;

import bpsh.authentication.AuthenticationFailure;
import bpsh.browser.AuthTrafficGuard;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.message.requests.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class DeferredRequestDeliveryTest {
    @Test void onlyTheExactMarkedProxyRequestCanClaimThePinnedPlanOnce() throws Exception {
        var hooks=new NativeTagPipelineTest().new ProductionHooks();
        try(var fixture=new NativeTagPipelineTest.Fixture();var host=hooks.new Host(fixture,null,null,java.net.URI.create("http://example.test"));
            var bridge=new DeferredRequestDelivery(host.guard,new AtomicBoolean())) {
            host.selectedTool=ToolType.PROXY;var calls=new AtomicInteger();var closes=new AtomicInteger();
            var clean=host.request("POST /perform HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\n\r\nabc",1,false);
            var plan=plan(clean,calls,closes);
            try(var handle=bridge.publish(plan,System.nanoTime()+10_000_000_000L)) {
                String marked=new String(handle.marked().toByteArray().getBytes(),StandardCharsets.ISO_8859_1);
                var received=host.request(marked,902,false);var ownership=host.guard.classify(received.headerValue("User-Agent"),AuthTrafficGuard.Family.GLOBAL,902);
                assertThrows(AuthenticationFailure.class,()->bridge.deliver(host.request(marked.replace("abc","abd"),903,false),ownership));
                assertEquals(0,calls.get());
                var delivered=bridge.deliver(received,ownership);assertSame(clean,delivered.request());assertEquals(1,calls.get());
                assertThrows(AuthenticationFailure.class,()->bridge.deliver(received,ownership));
            }
            assertEquals(1,closes.get());assertEquals(0,bridge.pendingCount());
        }
    }
    @Test void expiryCancellationAndWrongToolCannotGrantAnotherRequestTheIdentity() throws Exception {
        var hooks=new NativeTagPipelineTest().new ProductionHooks();var clock=new AtomicLong(100);
        try(var fixture=new NativeTagPipelineTest.Fixture();var host=hooks.new Host(fixture,null,null,java.net.URI.create("http://example.test"));
            var bridge=new DeferredRequestDelivery(host.guard,new AtomicBoolean(),clock::get,1,4096)) {
            host.selectedTool=ToolType.PROXY;var calls=new AtomicInteger();var closes=new AtomicInteger();
            var clean=host.request("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",1,false);
            try(var handle=bridge.publish(plan(clean,calls,closes),10_000_000_100L)) {
                assertThrows(AuthenticationFailure.class,()->bridge.publish(plan(clean,calls,new AtomicInteger()),10_000_000_100L));
                var received=host.request(new String(handle.marked().toByteArray().getBytes(),StandardCharsets.ISO_8859_1),900,false);
                var ownership=host.guard.classify(received.headerValue("User-Agent"),AuthTrafficGuard.Family.GLOBAL,900);
                host.selectedTool=ToolType.REPEATER;assertThrows(AuthenticationFailure.class,()->bridge.deliver(received,ownership));
                host.selectedTool=ToolType.PROXY;clock.set(10_000_000_101L);
                assertThrows(AuthenticationFailure.class,()->bridge.deliver(received,ownership));
            }
            assertEquals(0,calls.get());assertEquals(1,closes.get());assertEquals(0,bridge.pendingCount());
        }
    }
    @Test void shutdownAttemptsEveryPlanAndStopsExpiryEvenWhenOneCleanupThrows() throws Exception {
        var hooks=new NativeTagPipelineTest().new ProductionHooks();var closes=new AtomicInteger();
        try(var fixture=new NativeTagPipelineTest.Fixture();var host=hooks.new Host(fixture,null,null,java.net.URI.create("http://example.test"));
            var bridge=new DeferredRequestDelivery(host.guard,new AtomicBoolean())) {
            var clean=host.request("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",1,false);
            bridge.publish(new DeferredRequestDelivery.Plan(){
                public HttpRequest clean(){return clean;}
                public SessionRequestProcessor.Result deliver(HttpRequestToBeSent callback){throw new AssertionError();}
                public void close(){closes.incrementAndGet();throw new LinkageError("CANARY_PRIVATE");}
            },System.nanoTime()+10_000_000_000L);
            bridge.publish(plan(clean,new AtomicInteger(),closes),System.nanoTime()+10_000_000_000L);
            assertThrows(IllegalStateException.class,bridge::close);assertEquals(2,closes.get());
            assertEquals(0,bridge.pendingCount());assertDoesNotThrow(()->bridge.awaitClosed(1000));
        }
    }
    private static DeferredRequestDelivery.Plan plan(HttpRequest request,AtomicInteger calls,AtomicInteger closes) {
        return new DeferredRequestDelivery.Plan(){
            public HttpRequest clean(){return request;}public ToolType tool(){return ToolType.PROXY;}
            public SessionRequestProcessor.Result deliver(HttpRequestToBeSent host){calls.incrementAndGet();return SessionRequestProcessor.Result.continueWith(request,host.annotations());}
            public void close(){closes.incrementAndGet();}
        };
    }
}
