package bpsh.burp.http;

import burp.api.montoya.MontoyaApi;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;

/** Read-only export of configured listeners and strict parsing of actual callback ports. */
public final class ProxyListeners {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final MontoyaApi api;

    /** @param mode Advisory bind mode, or null. @param address Advisory bind address, or null. @param running Configured running state. */
    public record Binding(String mode, String address, boolean running) {}
    /** @param port Valid configured port. @param running Whether any binding on this port is running. @param bindings Advisory immutable binding details. */
    public record Choice(int port, boolean running, List<Binding> bindings) {
        /** Copies advisory metadata without resolving or opening a binding address. */
        public Choice { bindings = List.copyOf(bindings); }
    }

    /** @param api Host boundary used only for the specific settings export. */
    public ProxyListeners(MontoyaApi api) { this.api = api; }

    /** @return Sorted deduplicated configured ports; invoke off the EDT. */
    public List<Choice> read() { return parse(api.burpSuite().exportProjectOptionsAsJson("proxy.request_listeners")); }

    /** @param json Export containing only proxy.request_listeners. @return Immutable configured choices. */
    public static List<Choice> parse(String json) {
        try {
            JsonNode root = JSON.readTree(json), listeners = root.path("proxy").path("request_listeners");
            if (!listeners.isArray()) throw new IllegalArgumentException();
            var grouped = new TreeMap<Integer, List<Binding>>();
            for (var entry : listeners) {
                var port = entry.path("listener_port"); var running = entry.path("running");
                if (!entry.isObject() || !port.isIntegralNumber() || !port.canConvertToInt() || port.intValue() < 1
                        || port.intValue() > 65535 || !running.isBoolean()) throw new IllegalArgumentException();
                grouped.computeIfAbsent(port.intValue(), ignored -> new ArrayList<>()).add(new Binding(
                        advisory(entry.get("listen_mode")), advisory(entry.get("listen_specific_address")), running.booleanValue()));
            }
            return grouped.entrySet().stream().map(e -> new Choice(e.getKey(), e.getValue().stream().anyMatch(Binding::running), e.getValue())).toList();
        } catch (Exception ex) {
            throw new IllegalStateException("Could not refresh proxy ports. Check Burp's Proxy listener settings.");
        }
    }

    /** @param value Optional host metadata. @return Text as advisory data only, or null. */
    private static String advisory(JsonNode value) { return value != null && value.isTextual() ? value.textValue() : null; }

    /** @param listenerInterface Actual callback binding text. @return Valid terminal port or null for missing/malformed metadata. */
    public static Integer incomingPort(String listenerInterface) {
        if (listenerInterface == null) return null;
        int colon = listenerInterface.lastIndexOf(':');
        if (colon <= 0 || listenerInterface.substring(0, colon).isBlank()) return null;
        String suffix = listenerInterface.substring(colon + 1);
        if (!suffix.matches("[0-9]{1,5}")) return null;
        int port = Integer.parseInt(suffix);
        return port >= 1 && port <= 65535 ? port : null;
    }
}
