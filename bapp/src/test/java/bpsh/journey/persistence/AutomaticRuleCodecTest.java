package bpsh.journey.persistence;

import bpsh.burp.ui.JourneyRegistryTest;
import bpsh.journey.ConfigurationException;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Checks the actual strict codec rather than treating legacy shapes as regex-validation evidence. */
class AutomaticRuleCodecTest {
    private static ObjectNode project() throws Exception {
        var root=(ObjectNode)JourneyRegistryTest.JSON.readTree(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT,false,false));
        var controls=(ObjectNode)root.get("controls");controls.put("rulesVersion",1);
        controls.putArray("rules").add(JourneyRegistryTest.JSON.readTree("""
                {"enabled":true,"journey":{"scope":"project","id":"22222222-2222-4222-8222-222222222222"},
                 "url":{"type":"all_requests"},"proxyPort":null,"recovery":{"enabled":true,"mode":"status_code","statusCode":401}}
                """));return root;
    }
    private static ObjectNode rule(ObjectNode root) {return (ObjectNode)root.at("/controls/rules/0");}
    private static JourneyDocument read(ObjectNode root) {return JourneyJson.read(root.toString(),JourneyDocument.DocumentKind.PROJECT);}

    @Test void currentTypedRulesRoundTripAndUnsupportedLayoutsAreRejected() throws Exception {
        missingMembersInvalidPortTypesAndConflictingUrlMembersAreRejected();
        unsupportedOrUnversionedRulesRequireExplicitResetWithoutSilentReinterpretation();
        for(String type:List.of("all_requests","burp_scope","prefix","regex"))for(Integer port:new Integer[]{null,8081}) {
            var root=project();var url=rule(root).putObject("url");url.put("type",type);
            if(type.equals("prefix"))url.put("value","https://app.example/api/");
            if(type.equals("regex"))url.put("value","(?i)app\\.example/api");
            if(port==null)rule(root).putNull("proxyPort");else rule(root).put("proxyPort",port);
            try(var parsed=read(root)) {
                String serialized=JourneyJson.write(parsed);var tree=JourneyRegistryTest.JSON.readTree(serialized);
                assertEquals(1,tree.at("/controls/rulesVersion").intValue());
                assertEquals(type,tree.at("/controls/rules/0/url/type").textValue());
                assertTrue(tree.at("/controls/rules/0").has("proxyPort"));
                assertFalse(serialized.contains("urlMode"));assertFalse(serialized.contains("urlPrefix"));
                try(var again=JourneyJson.read(serialized,JourneyDocument.DocumentKind.PROJECT)) {assertEquals(parsed.controls(),again.controls());}
            }
        }
    }

    private void missingMembersInvalidPortTypesAndConflictingUrlMembersAreRejected() throws Exception {
        for(String field:List.of("enabled","journey","url","proxyPort","recovery")) {
            var root=project();rule(root).remove(field);assertThrows(ConfigurationException.class,()->read(root));
        }
        for(String value:List.of("\"8081\"","8081.5","true","0","-1","65536","999999999999")) {
            var root=project();rule(root).set("proxyPort",JourneyRegistryTest.JSON.readTree(value));assertThrows(ConfigurationException.class,()->read(root));
        }
        for(String type:List.of("all_requests","burp_scope")) {
            var root=project();rule(root).putObject("url").put("type",type).put("value","ignored");assertThrows(ConfigurationException.class,()->read(root));
        }
        for(String source:List.of("private-secret(?=x)"," ","x".repeat(4097),"(a{100}){100}")) {
            var root=project();rule(root).putObject("url").put("type","regex").put("value",source);
            var error=assertThrows(ConfigurationException.class,()->read(root));assertFalse(error.getMessage().contains("private-secret"));assertNull(error.getCause());
        }
    }

    private void unsupportedOrUnversionedRulesRequireExplicitResetWithoutSilentReinterpretation() throws Exception {
        for(String version:List.of("null","\"1\"","1.5","2","-1")) {
            var root=project();((ObjectNode)root.get("controls")).set("rulesVersion",JourneyRegistryTest.JSON.readTree(version));
            var error=assertThrows(ConfigurationException.class,()->read(root));assertTrue(error.getMessage().contains("Reset project storage"));
        }
        var unversioned=project();((ObjectNode)unversioned.get("controls")).remove("rulesVersion");
        assertTrue(assertThrows(ConfigurationException.class,()->read(unversioned)).getMessage().contains("Unsupported Session handling storage format"));
        var missingArray=project();((ObjectNode)missingArray.get("controls")).remove("rules");assertThrows(ConfigurationException.class,()->read(missingArray));
        var empty=project();((ObjectNode)empty.get("controls")).remove(List.of("rules","rulesVersion"));
        try(var parsed=read(empty)){assertTrue(parsed.controls().rules().isEmpty());}
    }
}
