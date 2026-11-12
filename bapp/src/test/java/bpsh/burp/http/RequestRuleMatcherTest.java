package bpsh.burp.http;

import bpsh.browser.AuthTrafficGuard.Family;
import bpsh.journey.JourneyDefinition;
import bpsh.request.RequestSettings;
import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises actual URL/port matching without assuming callback ID or annotation propagation. */
class RequestRuleMatcherTest {
    static final RequestSettings.JourneySelection ID = new RequestSettings.JourneySelection(JourneyDefinition.Scope.PROJECT, UUID.randomUUID());
    static final JourneyDefinition.Recovery RECOVERY = new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null);

    static RequestSettings.Controls controls(RequestSettings.UrlCondition url, Integer port, boolean master, List<RequestSettings.Tool> tools) {
        return new RequestSettings.Controls(master,List.of(new RequestSettings.AutomaticRule(true,ID,url,port,RECOVERY)),tools,60000,60000,300000,null,null);
    }
    static HttpRequest request(String url, boolean scope) {
        return (HttpRequest)java.lang.reflect.Proxy.newProxyInstance(HttpRequest.class.getClassLoader(),new Class<?>[]{HttpRequest.class},(p,m,a)->switch(m.getName()) {
            case "url" -> url; case "isInScope" -> scope; default -> throw new AssertionError("Unnecessary request read: "+m.getName());
        });
    }
    static RequestRuleMatcher.Context context(Family family,RequestSettings.Tool tool,Integer port) {
        return new RequestRuleMatcher.Context(new RequestExchange(family,7),tool,port);
    }

    @Test void urlAndIncomingPortConditionsMatchIndependentlyAndTogether() {
        var matcher=RequestRuleMatcher.compile(controls(new RequestSettings.Prefix(java.net.URI.create("https://app.test/api/")),8081,true,List.of(RequestSettings.Tool.values())));
        for(var family:Family.values())for(var tool:RequestSettings.Tool.values())for(Integer port:new Integer[]{null,8081,8082}) {
            var ctx=context(family,tool,port);
            assertEquals(family==Family.PROXY&&tool==RequestSettings.Tool.PROXY&&Integer.valueOf(8081).equals(port),
                    !matcher.automaticRules(request("https://app.test/api/x",false),ctx).isEmpty());
            assertTrue(matcher.automaticRules(request("https://app.test/other",true),ctx).isEmpty());
        }
        var any=RequestRuleMatcher.compile(controls(new RequestSettings.AllRequests(),null,true,List.of(RequestSettings.Tool.values())));
        assertEquals(1,any.automaticRules(request(null,false),context(Family.GLOBAL,RequestSettings.Tool.REPEATER,null)).size());
        assertTrue(any.automaticRules(request(null,false),context(Family.GLOBAL,null,null)).isEmpty());
    }

    @Test void regexFindUsesDefaultCaseAndExplicitAnchorsAndFlags() {
        var ctx=context(Family.GLOBAL,RequestSettings.Tool.REPEATER,null);
        for(String source:List.of("api/", "^https://app\\.test/api/", "(?i)APP\\.TEST")) {
            var matcher=RequestRuleMatcher.compile(controls(new RequestSettings.Regex(source),null,true,List.of(RequestSettings.Tool.REPEATER)));
            assertEquals(1,matcher.automaticRules(request("https://app.test/api/item",false),ctx).size());
        }
        var matcher=RequestRuleMatcher.compile(controls(new RequestSettings.Regex("APP\\.TEST"),null,true,List.of(RequestSettings.Tool.REPEATER)));
        assertTrue(matcher.automaticRules(request("https://app.test/api/item",true),ctx).isEmpty());
    }

    @Test void taggedRecoveryUsesCommittedUrlAndMasterButIgnoresToolSelection() {
        var identity=new JourneyDefinition.Identity(ID.scope(),ID.id(),1);
        var matcher=RequestRuleMatcher.compile(controls(new RequestSettings.Regex("/committed$"),8081,true,List.of()));
        var ctx=context(Family.PROXY,RequestSettings.Tool.PROXY,8081);
        assertTrue(matcher.automaticRules(request("https://app.test/committed",true),ctx).isEmpty());
        assertEquals(RECOVERY,matcher.taggedRecovery(identity,request("https://app.test/committed",false),ctx).orElseThrow());
        assertTrue(matcher.taggedRecovery(identity,request("https://app.test/original",true),ctx).isEmpty());
        assertTrue(matcher.taggedRecovery(identity,request("https://app.test/committed",true),context(Family.GLOBAL,RequestSettings.Tool.REPEATER,null)).isEmpty());
        var disabled=RequestRuleMatcher.compile(controls(new RequestSettings.AllRequests(),null,false,List.of()));
        assertTrue(disabled.taggedRecovery(identity,request(null,false),ctx).isEmpty());
    }
}
