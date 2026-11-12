package bpsh.burp.http;

import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ProxyListenersTest {
    @Test void configuredChoicesAndCallbackPortsAreParsedWithoutFallback() {
        var choices=ProxyListeners.parse("""
                {"proxy":{"request_listeners":[
                  {"listener_port":8082,"running":false,"listen_mode":"loopback_only","future_setting":true},
                  {"listener_port":8081,"running":true},
                  {"listener_port":8082,"running":true,"listen_specific_address":"::1"}
                ]}}
                """);
        assertEquals(List.of(8081,8082),choices.stream().map(ProxyListeners.Choice::port).toList());
        assertTrue(choices.get(1).running());assertEquals(2,choices.get(1).bindings().size());
        for(String value:List.of("127.0.0.1:8081","[::1]:8081","*:8081","0.0.0.0:8081"))assertEquals(8081,ProxyListeners.incomingPort(value));
        for(String value:List.of("",":8081"," :8081","8081","host:0","host:65536","host:abc","host:80 trailing","host:+80"))assertNull(ProxyListeners.incomingPort(value));
        assertNull(ProxyListeners.incomingPort(null));
        assertThrows(IllegalStateException.class,()->ProxyListeners.parse("{\"proxy\":{\"request_listeners\":[{\"listener_port\":8081}]}}"));
        assertThrows(IllegalStateException.class,()->ProxyListeners.parse("{\"proxy\":{\"request_listeners\":[{\"listener_port\":8081.5,\"running\":true}]}}"));
        assertThrows(IllegalStateException.class,()->ProxyListeners.parse("private host data"));
    }
}
