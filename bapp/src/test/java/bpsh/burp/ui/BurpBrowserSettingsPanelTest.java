package bpsh.burp.ui;

import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import javax.swing.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class BurpBrowserSettingsPanelTest {
    @Test void pathRemainsLiteralAndDetectedSelectionDoesNotTurnAutomaticIntoAnOverride() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var changed = new ArrayList<String>(); var browse = new AtomicInteger(); var automatic = new AtomicInteger();
            var panel = new BurpBrowserSettingsPanel(changed::add, browse::incrementAndGet, automatic::incrementAndGet);
            panel.setOverride("<html><img src='file:///not-loaded'>");
            var input = (JTextField) panel.focusTarget(); assertEquals("<html><img src='file:///not-loaded'>", input.getText());
            var caption = (JLabel) input.getClientProperty("rowLabel");
            assertEquals(input.getToolTipText(), caption.getToolTipText());
            assertEquals(input.getAccessibleContext().getAccessibleDescription(), caption.getAccessibleContext().getAccessibleDescription());
            assertTrue(changed.isEmpty(), "Populating the UI must not persist values");
            panel.setOverride(""); Path executable = Path.of("custom/Burpsuite/burpbrowser/chrome").toAbsolutePath();
            panel.showSelection(new bpsh.authentication.BrowserInstallation.Selection(executable, false));
            assertEquals("", input.getText()); assertTrue(changed.isEmpty());
            input.setText("invalid selection"); assertEquals("invalid selection", changed.getLast());
            panel.showFailure("Select the installed Burp Browser executable.");
            var error = (JTextArea) input.getClientProperty("validationMessage"); assertTrue(error.isVisible());
            assertEquals("Select the installed Burp Browser executable.", input.getAccessibleContext().getAccessibleDescription());
            assertNotNull(input.createToolTip());
        });
    }
}
