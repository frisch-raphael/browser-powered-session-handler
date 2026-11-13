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
            assertEquals(executable.toString(), input.getText()); assertTrue(changed.isEmpty());
            input.setText("invalid selection"); assertEquals("invalid selection", changed.getLast());
            panel.showFailure("Select the installed Burp Browser executable.");
            var error = (JTextArea) input.getClientProperty("validationMessage"); assertTrue(error.isVisible());
            assertEquals("Select the installed Burp Browser executable.", input.getAccessibleContext().getAccessibleDescription());
            assertNotNull(input.createToolTip());
        });
    }

    @Test void automaticSelectionShowsItsPathWithoutPersistingItAndResetOnlyAppliesToCustomPaths() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var values = new HashMap<String, String>();
            var settings = new bpsh.browser.runtime.BrowserExecutableSettings();
            var preferences = new BrowserRuntimePreferences(BrowserRuntimePreferencesTest.preferences(values), BrowserRuntimePreferencesTest.installation(settings, null));
            var holder = new BurpBrowserSettingsPanel[1];
            var resets = new AtomicInteger();
            holder[0] = new BurpBrowserSettingsPanel(preferences::select, () -> {}, () -> {
                resets.incrementAndGet(); preferences.select(""); holder[0].setOverride(""); holder[0].detecting();
            });
            var panel = holder[0]; var input = (JTextField) panel.focusTarget();
            var automatic = automaticButton(panel);
            assertFalse(automatic.isEnabled(), "Already automatic must not offer a redundant reset");
            var detected = Path.of("BurpSuite/burpbrowser/156.0/chrome.exe").toAbsolutePath();
            panel.showSelection(new bpsh.authentication.BrowserInstallation.Selection(detected, false));
            assertEquals(detected.toString(), input.getText());
            assertTrue(values.isEmpty()); assertEquals("", settings.executableOverride());
            automatic.doClick(0); assertEquals(0, resets.get());

            input.setText("invalid custom path");
            assertEquals("invalid custom path", settings.executableOverride()); assertTrue(automatic.isEnabled());
            panel.showFailure("Select the installed Burp Browser executable.");
            assertEquals("invalid custom path", input.getText()); assertTrue(automatic.isEnabled());
            automatic.doClick(0); assertEquals(1, resets.get());
            assertFalse(automatic.isEnabled()); assertTrue(values.isEmpty()); assertEquals("", settings.executableOverride());
            panel.showSelection(new bpsh.authentication.BrowserInstallation.Selection(detected, false));
            assertEquals(detected.toString(), input.getText()); assertTrue(values.isEmpty());
        });
    }

    private static JButton automaticButton(java.awt.Container parent) {
        for (var component : parent.getComponents()) {
            if (component instanceof JButton button && button.getText().toLowerCase(Locale.ROOT).contains("automatic")) return button;
            if (component instanceof java.awt.Container child) { var found = automaticButton(child); if (found != null) return found; }
        }
        return null;
    }

    @Test void automaticAndCustomStatesFitCompactAndWideForms() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            for (int width : new int[]{480, 840}) {
                var panel = new BurpBrowserSettingsPanel(value -> {}, () -> {}, () -> {});
                var path = Path.of("BurpSuiteDesktop/burpbrowser/156.0.8078.48/chrome.exe").toAbsolutePath();
                for (String state : List.of("automatic", "custom-error", "detecting")) {
                    if (state.equals("automatic")) panel.showSelection(new bpsh.authentication.BrowserInstallation.Selection(path, false));
                    else if (state.equals("custom-error")) { panel.setOverride("<html>invalid-custom-executable"); panel.showFailure("Select an executable in a supported Burp Browser installation."); }
                    else { panel.setOverride(""); panel.detecting(); }
                    panel.setSize(width, 300); layout(panel);
                    var button = automaticButton(panel);
                    assertTrue(button.getX() + button.getWidth() <= button.getParent().getWidth(), "Reset action must remain visible");
                    var input = panel.focusTarget();
                    assertTrue(input.getWidth() > 100, "Executable must remain readable in compact forms");
                    var image = new java.awt.image.BufferedImage(width, 300, java.awt.image.BufferedImage.TYPE_INT_RGB);
                    var graphics = image.createGraphics(); panel.printAll(graphics); graphics.dispose();
                    try {
                        var output = Path.of("build/ui-previews"); java.nio.file.Files.createDirectories(output);
                        javax.imageio.ImageIO.write(image, "png", output.resolve("burp-browser-" + state + "-" + width + ".png").toFile());
                    } catch (java.io.IOException error) { throw new AssertionError(error); }
                }
            }
        });
    }

    private static void layout(java.awt.Container parent) {
        parent.doLayout();
        for (var component : parent.getComponents()) if (component instanceof java.awt.Container child) layout(child);
    }
}
