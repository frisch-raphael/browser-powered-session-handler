package bpsh.burp.ui;

import bpsh.journey.AuthStep;
import bpsh.journey.SecretStore;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import javax.swing.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** A target-controlled dropdown value must remain literal even on the first renderer use. */
class RecordedOptionRenderingTest {
    @Test void firstAndSubsequentOptionRendersNeverFetchAnHtmlImageAndPreserveTheValue() throws Exception {
        var requests = new AtomicInteger();
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/image", exchange -> { requests.incrementAndGet(); exchange.sendResponseHeaders(204, -1); exchange.close(); });
        server.start();
        try {
            String value = "<html><img src='http://127.0.0.1:" + server.getAddress().getPort() + "/image'></html>";
            SwingUtilities.invokeAndWait(() -> {
                for (int instance = 0; instance < 2; instance++) {
                    var panel = new StepsPanel();
                    try (var secrets = new SecretStore.Values(null, Map.of())) {
                        var id = UUID.randomUUID();
                        panel.setSteps(List.of(new AuthStep.Definition(id, AuthStep.Type.SELECT_OPTIONS, "select", null, null, null, null, new AuthStep.Options(List.of(value)))), secrets);
                        var rowsField = StepsPanel.class.getDeclaredField("rows"); rowsField.setAccessible(true);
                        Object row = ((List<?>) rowsField.get(panel)).getFirst();
                        var optionsField = row.getClass().getDeclaredField("options"); optionsField.setAccessible(true);
                        var table = (JTable) optionsField.get(row);
                        for (int render = 0; render < 2; render++) {
                            assertEquals(value, ((JLabel) table.prepareRenderer(table.getCellRenderer(0, 0), 0, 0)).getText());
                            assertEquals(0, requests.get());
                        }
                        try (var snapshot = panel.snapshot()) { assertEquals(List.of(value), ((bpsh.journey.JourneyDraft.Options) snapshot.inputs.getFirst().operation()).values()); }
                    } catch (Exception failure) { throw new AssertionError(failure); }
                    finally { panel.clear(); }
                }
            });
            assertEquals(0, requests.get());
        } finally { server.stop(0); }
    }
}
