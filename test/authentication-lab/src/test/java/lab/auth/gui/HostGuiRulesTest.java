package lab.auth.gui;

import com.google.gson.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class HostGuiRulesTest {
    private JsonObject spec() {
        return JsonParser.parseString("""
            {"mode":"REPLACE","policy":"WAIT_FOR_LOGIN","enabled":true,"tools":["PROXY","REPEATER"],"rules":[
              {"alias":"host_a","enabled":true,"urlMode":"ALL_REQUESTS","url":"","regex":false,
               "proxyPort":43123,"detect":false,"detectBy":"STATUS_CODE","failureStatus":401,"responsePattern":""}]}
            """).getAsJsonObject();
    }
    @Test void emptyUnusedFieldsAndTypedPolicyPortAndAliasAreRetained() {
        var parsed=HostGuiRules.parse(spec());assertEquals("WAIT_FOR_LOGIN",parsed.policy());assertEquals(1,parsed.rules().size());
        var rule=parsed.rules().getFirst();assertEquals("host_a",rule.alias());assertEquals(43123,rule.port());
        assertEquals("",rule.url());assertEquals("",rule.pattern());assertFalse(rule.regex());
    }
    @Test void unknownFieldsPrivateValuesAndInvalidNumericTypesCannotReachGuiActions() {
        var unknown=spec();unknown.addProperty("password","PRIVATE_SENTINEL");assertThrows(IllegalArgumentException.class,()->HostGuiRules.parse(unknown));
        var typed=spec();typed.getAsJsonArray("rules").get(0).getAsJsonObject().addProperty("proxyPort","43123");
        assertThrows(IllegalArgumentException.class,()->HostGuiRules.parse(typed));
        var duplicate=spec();duplicate.getAsJsonArray("rules").add(duplicate.getAsJsonArray("rules").get(0).deepCopy());
        assertThrows(IllegalArgumentException.class,()->HostGuiRules.parse(duplicate));
    }
    @Test void invalidRegexCommandEditsOneExistingRuleWithoutReplacingItsAppliedAccount() {
        var json=JsonParser.parseString("{\"mode\":\"INVALID_REGEX\",\"rule\":1}").getAsJsonObject();
        var parsed=HostGuiRules.parse(json);assertEquals(0,parsed.row());assertTrue(parsed.rules().isEmpty());
        json.addProperty("rule",0);assertThrows(IllegalArgumentException.class,()->HostGuiRules.parse(json));
    }
}
