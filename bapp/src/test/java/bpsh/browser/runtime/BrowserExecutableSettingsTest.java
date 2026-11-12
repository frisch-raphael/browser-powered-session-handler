package bpsh.browser.runtime;

import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class BrowserExecutableSettingsTest {
    @Test void invalidOverrideIsPreservedUntilTheUserChoosesAutomatic() {
        var settings = new BrowserExecutableSettings(); assertEquals("", settings.executableOverride());
        settings.setExecutableOverride(" invalid literal <path> "); assertEquals(" invalid literal <path> ", settings.executableOverride());
        settings.setExecutableOverride(""); assertEquals("", settings.executableOverride());
    }
    @Test void concurrentReadersSeeCompleteSelections() throws Exception {
        var settings = new BrowserExecutableSettings(); String path = "custom/".repeat(100) + "chrome.exe";
        try (var executor = Executors.newFixedThreadPool(2)) {
            var writer = executor.submit(() -> { for (int i = 0; i < 10000; i++) { settings.setExecutableOverride(path); settings.setExecutableOverride(""); } });
            var reader = executor.submit(() -> { for (int i = 0; i < 10000; i++) { String value = settings.executableOverride(); assertTrue(value.isEmpty() || value.equals(path)); } });
            writer.get(5, TimeUnit.SECONDS); reader.get(5, TimeUnit.SECONDS);
        }
    }
}
