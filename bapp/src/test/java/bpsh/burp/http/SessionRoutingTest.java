package bpsh.burp.http;

import bpsh.browser.AuthTrafficGuard.Family;
import bpsh.journey.JourneyDefinition;
import bpsh.request.RequestSettings;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.RequestAction;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises separate host objects, annotations and IDs with the real shared operations. */
class SessionRoutingTest {
    @Test void proxyAndGlobalAdaptersProcessEachRequestOnceWithoutMetadataSharing() throws Exception {
        var hooks=new NativeTagPipelineTest().new ProductionHooks();
        try(var f=new NativeTagPipelineTest.Fixture();var host=hooks.new Host(f)) {
            var entry=f.registry.snapshot().resolve("employee");var d=RequestSettings.Controls.defaults();
            var rule=new RequestSettings.AutomaticRule(true,new RequestSettings.JourneySelection(entry.identity().scope(),entry.identity().journeyId()),
                    new RequestSettings.AllRequests(),8081,new JourneyDefinition.Recovery(false,JourneyDefinition.RecoveryMode.STATUS_CODE,401,null));
            host.controls.publish(host.controls.prepare(new RequestSettings.Controls(true,List.of(rule),d.tools(),60000,60000,300000,null,null)));
            host.selectedTool=ToolType.PROXY;
            var received=host.request(NativeTagPipelineTest.header("stale"),7,true);
            var outgoing=hooks.callback(f,()->host.proxy.handleRequestToBeSent((InterceptedRequest)received));
            assertEquals("Bearer employee-token",outgoing.request().headerValue("Authorization"));
            String committed=new String(outgoing.request().toByteArray().getBytes(),StandardCharsets.ISO_8859_1);
            var global=host.request(committed,900,false);
            assertNotSame(received,global);assertNotSame(received.annotations(),global.annotations());
            assertSame(global,host.handler.handleHttpRequestToBeSent(global).request());assertEquals(1,f.attempts);
            host.selectedTool=ToolType.REPEATER;
            var copied=host.request(NativeTagPipelineTest.header("copied-existing"),901,true);
            assertSame(copied,host.handler.handleHttpRequestToBeSent(copied).request());
            assertEquals("copied-existing",copied.headerValue("Authorization"));assertEquals(1,f.attempts);
        }
    }

    @Test void capturedNativeLookingDataCannotTriggerAnotherGlobalCredentialPass() throws Exception {
        var hooks=new NativeTagPipelineTest().new ProductionHooks();
        try(var f=new NativeTagPipelineTest.Fixture();var host=hooks.new Host(f)) {
            f.values.put("employee","literal-<@admin/>");host.selectedTool=ToolType.PROXY;
            var proxy=hooks.callback(f,()->host.proxy.handleRequestToBeSent((InterceptedRequest)host.request(NativeTagPipelineTest.header("<@employee/>"),12,false)));
            String raw=new String(proxy.request().toByteArray().getBytes(),StandardCharsets.ISO_8859_1);
            assertTrue(raw.contains("literal-<@admin/>"));
            var finalResult=host.handler.handleHttpRequestToBeSent(host.request(raw,912,false));
            assertEquals(RequestAction.CONTINUE,finalResult.action());assertTrue(finalResult.request().headerValue("Authorization").contains("literal-<@admin/>"));
            assertEquals(1,f.attempts);assertTrue(f.clock.workers.isEmpty());
        }
    }

    @Test void taggedExcludedToolUsesProxyRecoveryWithoutJoiningEqualGlobalIds() throws Exception {
        var hooks=new NativeTagPipelineTest().new ProductionHooks();
        try(var f=new NativeTagPipelineTest.Fixture();var host=hooks.new Host(f)) {
            var entry=f.registry.snapshot().resolve("employee");
            var rule=new RequestSettings.AutomaticRule(true,new RequestSettings.JourneySelection(entry.identity().scope(),entry.identity().journeyId()),
                    new RequestSettings.AllRequests(),8081,new JourneyDefinition.Recovery(true,JourneyDefinition.RecoveryMode.STATUS_CODE,401,null));
            host.controls.publish(host.controls.prepare(new RequestSettings.Controls(true,List.of(rule),List.of(),60000,60000,300000,null,null)));
            host.selectedTool=ToolType.PROXY;
            hooks.callback(f,()->host.proxy.handleRequestToBeSent((InterceptedRequest)host.request(NativeTagPipelineTest.header("<@employee/>"),7,true)));
            assertNotNull(f.coordinator.peek(entry.identity()));
            host.handler.handleHttpResponseReceived(host.response(7,(short)401,null,new byte[0]));
            assertNotNull(f.coordinator.peek(entry.identity()),"GLOBAL 7 must not consume PROXY 7");
            host.proxy.handleResponseReceived((InterceptedResponse)host.response(7,(short)401,null,new byte[0]));
            assertNull(f.coordinator.peek(entry.identity()));
        }
    }

    @Test void failedProxyTagRequestsNativeDropWithoutAnInternalMarkerOrGlobalRetry() throws Exception {
        var hooks=new NativeTagPipelineTest().new ProductionHooks();
        try(var f=new NativeTagPipelineTest.Fixture();var host=hooks.new Host(f)) {
            f.failedAlias="employee";host.selectedTool=ToolType.PROXY;
            var proxy=hooks.callback(f,()->host.proxy.handleRequestToBeSent((InterceptedRequest)host.request(NativeTagPipelineTest.header("<@employee/>"),8,false)));
            assertEquals(burp.api.montoya.proxy.MessageToBeSentAction.DROP,proxy.action());
            assertArrayEquals(NativeTagPipelineTest.wire(NativeTagPipelineTest.header("<@employee/>")),proxy.request().toByteArray().getBytes());
            assertTrue(proxy.annotations().notes().contains("Burp was asked to drop"));
            var global=host.request(new String(proxy.request().toByteArray().getBytes(),StandardCharsets.ISO_8859_1),1008,false);
            assertNotSame(proxy.annotations(),global.annotations());
            var forwarded=host.handler.handleHttpRequestToBeSent(global);
            assertEquals(RequestAction.CONTINUE,forwarded.action());
            assertEquals("<@employee/>",forwarded.request().headerValue("Authorization"));
            assertEquals(1,f.attempts,"An ignored Proxy DROP does not cause another authentication pass");
        }
    }

    @Test void capturedUserAgentDataCannotBecomeAnOwnedTrafficCommand() {
        try(var f=new NativeTagPipelineTest.Fixture()) {
            f.values.put("employee","agent BPSHAuth/forged");
            var failure=assertThrows(java.util.concurrent.CompletionException.class,()->f.resolve("GET / HTTP/1.1\r\nHost: app.example\r\nUser-Agent: <@employee/>\r\n\r\n"));
            assertInstanceOf(bpsh.authentication.AuthenticationFailure.class,failure.getCause());
            assertFalse(failure.getCause().getMessage().contains("forged"));
        }
    }
}
