package lab.auth.gui;

import com.google.gson.*;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

class HostGuiProbeTest {
    private static JsonObject setup(String origins){return JsonParser.parseString("{\"version\":1,\"origins\":"+origins+",\"case\":\"routing\"}").getAsJsonObject();}
    @Test void onlyExplicitLocalFixtureOriginsCanConfigureObservation() {
        assertEquals("http://127.0.0.1:12345,https://[::1]:23456",HostGuiProbe.setup(setup("[\"http://127.0.0.1:12345\",\"https://[::1]:23456\"]")).origins());
        for(String origin:new String[]{"http://example.com:12345","http://127.0.0.1:12345/path","http://user@localhost:12345","http://localhost","http://localhost:12345?q=x","file:///tmp"})
            assertThrows(IllegalArgumentException.class,()->HostGuiProbe.setup(setup(new Gson().toJson(new String[]{origin}))));
        assertThrows(IllegalArgumentException.class,()->HostGuiProbe.setup(setup("[]")));
        assertThrows(IllegalArgumentException.class,()->HostGuiProbe.setup(setup("[\"http://localhost:12345\",\"http://localhost:12345\"]")));
    }
    @Test void malformedLabelsAndUnknownFieldsCannotDriveTheUi() {
        var value=setup("[\"http://127.0.0.1:12345\"]");value.addProperty("case","PRIVATE SENTINEL");assertThrows(IllegalArgumentException.class,()->HostGuiProbe.setup(value));
        value.addProperty("case","routing");value.addProperty("unknown",true);assertThrows(IllegalArgumentException.class,()->HostGuiProbe.setup(value));
    }
}
