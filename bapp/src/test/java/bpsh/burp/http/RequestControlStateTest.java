package bpsh.burp.http;

import bpsh.request.RequestSettings;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class RequestControlStateTest {
    @Test void concurrentRequestsObserveOneCompleteAppliedSnapshot() throws Exception {
        var a=RequestRuleMatcherTest.controls(new RequestSettings.Prefix(java.net.URI.create("https://a.test/")),8081,true,List.of(RequestSettings.Tool.PROXY));
        var b=RequestRuleMatcherTest.controls(new RequestSettings.Prefix(java.net.URI.create("https://b.test/")),8082,true,List.of(RequestSettings.Tool.PROXY));
        var state=new RequestControlState(a);var first=state.prepare(a);var second=state.prepare(b);
        var start=new java.util.concurrent.CountDownLatch(1);var workers=java.util.concurrent.Executors.newFixedThreadPool(2);
        try {
            var writer=workers.submit(()->{start.await();for(int i=0;i<5000;i++)state.publish((i&1)==0?first:second);return null;});
            var reader=workers.submit(()->{
                start.await();
                for(int i=0;i<5000;i++) {
                    var snapshot=state.snapshot();boolean isA=snapshot.controls().equals(a);
                    assertEquals(isA,!snapshot.matcher().automaticRules(RequestRuleMatcherTest.request("https://a.test/path",false),
                            RequestRuleMatcherTest.context(bpsh.browser.AuthTrafficGuard.Family.PROXY,RequestSettings.Tool.PROXY,8081)).isEmpty());
                    assertEquals(!isA,!snapshot.matcher().automaticRules(RequestRuleMatcherTest.request("https://b.test/path",false),
                            RequestRuleMatcherTest.context(bpsh.browser.AuthTrafficGuard.Family.PROXY,RequestSettings.Tool.PROXY,8082)).isEmpty());
                }return null;
            });
            start.countDown();writer.get(5,java.util.concurrent.TimeUnit.SECONDS);reader.get(5,java.util.concurrent.TimeUnit.SECONDS);
        } finally {workers.shutdownNow();}
    }
    @Test void preparingInvalidOrUnpublishedControlsKeepsTheAppliedPlan() {
        var initial=RequestSettings.Controls.defaults();var state=new RequestControlState(initial);var original=state.snapshot();
        var good=RequestRuleMatcherTest.controls(new RequestSettings.Regex("/login"),8081,true,List.of(RequestSettings.Tool.PROXY));
        var prepared=state.prepare(good);assertSame(original,state.snapshot());
        var invalid=RequestRuleMatcherTest.controls(new RequestSettings.Regex("private-secret(?=x)"),8081,true,List.of(RequestSettings.Tool.PROXY));
        var failure=assertThrows(IllegalArgumentException.class,()->state.prepare(invalid));
        assertFalse(failure.getMessage().contains("private-secret"));assertSame(original,state.snapshot());
        assertThrows(IllegalArgumentException.class,()->new RequestControlState.Applied(initial,prepared.matcher()));
        var lower=RequestRuleMatcherTest.controls(new RequestSettings.Prefix(java.net.URI.create("https://app.test/")),8081,true,List.of(RequestSettings.Tool.PROXY));
        var upper=RequestRuleMatcherTest.controls(new RequestSettings.Prefix(java.net.URI.create("https://APP.test/")),8081,true,List.of(RequestSettings.Tool.PROXY));
        assertEquals(lower,upper,"URI equality ignores host case, while literal prefix matching preserves its spelling");
        assertThrows(IllegalArgumentException.class,()->new RequestControlState.Applied(upper,RequestRuleMatcher.compile(lower)));
        state.publish(prepared);assertSame(prepared,state.snapshot());assertEquals(good,state.snapshot().matcher().controls());
    }
}
