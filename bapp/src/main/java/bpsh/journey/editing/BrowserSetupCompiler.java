package bpsh.journey.editing;

import bpsh.journey.BrowserSetup;
import bpsh.journey.ConfigurationException;
import bpsh.journey.JourneyDraft;
import bpsh.journey.persistence.JourneyJson;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.math.BigDecimal;
import java.util.Locale;
import java.util.Map;

/** Compiles browser setup without requiring valid names, steps, capture rules or cache settings. */
public final class BrowserSetupCompiler {
    private static final ObjectMapper JSON = new ObjectMapper();
    private BrowserSetupCompiler() {}

    /** Uses the same strict setup parser as executable journeys, without storage or network access. */
    public static BrowserSetup compile(JourneyDraft draft) { return JourneyJson.readSetup(node(draft)); }

    /** Builds shared setup fields for both full-journey and recording compilation. */
    static ObjectNode node(JourneyDraft draft) {
        var text = draft.text(); var flags = draft.flags();
        var node = JSON.createObjectNode().put("authenticationUrl", text.get("url").trim());
        var browser = node.putObject("browser").put("headless", flags.get("headless"))
                .put("navigationTimeoutMs", seconds(text, "navTimeout"));
        if (!text.get("proxy").isBlank()) browser.putObject("proxy").put("url", text.get("proxy").trim());
        if (flags.get("mtls")) {
            var mtls = node.putObject("mtls").put("modulePath", text.get("module").trim())
                    .put("certificateSha256", draft.certificateSha256());
            long slot;
            try { slot = Long.parseLong(text.get("slot").trim()); }
            catch (RuntimeException invalid) { throw new ConfigurationException("slot: enter a whole number."); }
            mtls.putObject("slot").put("kind", draft.slotKind().name().toLowerCase(Locale.ROOT)).put("value", slot);
            var origins = mtls.putArray("origins");
            for (String origin : text.get("origins").split(",")) if (!origin.isBlank()) origins.add(origin.trim());
            if (!text.get("ca").isBlank()) mtls.put("trustedCaBundlePath", text.get("ca").trim());
        }
        return node;
    }

    /** Converts exact user-entered seconds once for shared setup and capture compilation. */
    static int seconds(Map<String, String> values, String key) {
        try { return new BigDecimal(values.get(key).trim()).multiply(BigDecimal.valueOf(1000)).intValueExact(); }
        catch (RuntimeException invalid) { throw new ConfigurationException(key + ": enter a valid duration in seconds."); }
    }
}
