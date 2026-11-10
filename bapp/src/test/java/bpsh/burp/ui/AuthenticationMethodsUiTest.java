package bpsh.burp.ui;

import bpsh.journey.*;
import bpsh.journey.persistence.*;
import java.awt.*;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import javax.swing.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class AuthenticationMethodsUiTest {
    @TempDir Path root;
    private JourneyRegistryTest.NativeUi harness() {
        var h = new JourneyRegistryTest().new NativeUi(); h.root = root; return h;
    }
    private void open(JourneyRegistryTest.NativeUi h, JourneyRegistryTest.NativeUi.Editor editor, JourneyKey key) throws Exception {
        h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, key));
        h.await(() -> { try { return !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception error) { return false; } });
    }
    @Test void everyMethodCombinationShowsItsPagesAndKeepsCaptureAvailable() throws Exception {
        var h = harness();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            open(h, editor, editor.registry.snapshot().resolve("employee").identity().key());
            h.edt(() -> {
                var flags = editor.checks(); JTabbedPane wizard = h.member(editor.ui, "wizard");
                assertTrue(flags.get("formAuthentication").isSelected());
                assertSame(flags.get("formAuthentication").getParent(), flags.get("httpAuthentication").getParent());
                for (int mask = 0; mask < 8; mask++) {
                    String[] keys = {"formAuthentication", "mtls", "httpAuthentication"};
                    for (int i = 0; i < keys.length; i++) if (flags.get(keys[i]).isSelected() != ((mask & (1 << i)) != 0)) flags.get(keys[i]).doClick(0);
                    assertEquals((mask & 1) != 0, wizard.indexOfTab("Login steps") >= 0);
                    assertEquals((mask & 2) != 0, wizard.indexOfTab("Client certificate") >= 0);
                    assertEquals((mask & 4) != 0, wizard.indexOfTab("HTTP authentication") >= 0);
                    assertTrue(wizard.indexOfTab("Capture credentials") >= 0);
                    assertEquals(mask != 0, wizard.indexOfTab("Test & use") >= 0);
                    assertEquals(mask != 0, ((JButton) h.member(editor.ui, "testButton")).isVisible());
                    assertEquals(mask == 0, ((JLabel) h.member(editor.ui, "authenticationMethodsHelp")).isVisible());
                    WizardTestPages.select(wizard, "Setup");
                    if (mask == 0 || mask == 7) for (int width : new int[]{980, 1280}) render(editor.component, "authentication-methods-" + mask + "-" + width, width);
                }
                WizardTestPages.select(wizard, "Login steps"); flags.get("formAuthentication").doClick(0);
                assertEquals("Setup", WizardTestPages.selected(wizard)); assertTrue(wizard.indexOfTab("Capture credentials") >= 0);
            });
        }
    }
    @Test void disablingFormLoginPersistsAndRetainsStepsForReenabling() throws Exception {
        var h = harness();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); open(h, editor, key);
            h.edt(() -> {
                editor.checks().get("httpAuthentication").doClick(0);
                Map<String,JTextField> httpFields = h.member(h.member(editor.ui, "httpAuthentication"), "fields");
                httpFields.get("httpUsername").setText("fixture-user");
                editor.checks().get("formAuthentication").doClick(0);
                h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false);
            });
            h.await(() -> { try { return editor.saved(); } catch (Exception error) { return false; } });
            var definition = editor.registry.snapshot().entries().get(key).definition();
            assertNull(definition.draft()); assertFalse(definition.browser().formAuthentication());
            assertEquals(1, definition.steps().size()); assertTrue(definition.loginSteps().isEmpty());
            try (var disk = JourneyJson.read(editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY), JourneyDocument.DocumentKind.PROJECT)) {
                assertFalse(disk.journeys().getFirst().browser().formAuthentication()); assertEquals(definition.steps(), disk.journeys().getFirst().steps());
            }
            open(h, editor, key);
            h.edt(() -> {
                JTabbedPane wizard = h.member(editor.ui, "wizard"); assertEquals(-1, wizard.indexOfTab("Login steps"));
                editor.checks().get("formAuthentication").doClick(0); assertTrue(wizard.indexOfTab("Login steps") >= 0);
                h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false);
            });
            h.await(() -> { try { return editor.saved(); } catch (Exception error) { return false; } });
            assertEquals(definition.steps(), editor.registry.snapshot().entries().get(key).definition().loginSteps());
        }
    }
    @Test void noMethodSelectionSavesAsAnUnfinishedJourneyAndSurvivesReload() throws Exception {
        var h = harness();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); open(h, editor, key);
            h.edt(() -> { editor.checks().get("formAuthentication").doClick(0); h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false); });
            h.await(() -> { try { return editor.saved(); } catch (Exception error) { return false; } });
            assertNotNull(editor.registry.snapshot().entries().get(key).definition().draft());
            open(h, editor, key);
            h.edt(() -> { assertFalse(editor.checks().get("formAuthentication").isSelected()); assertEquals(-1, ((JTabbedPane) h.member(editor.ui, "wizard")).indexOfTab("Test & use")); });
            assertTrue(editor.clock.workers.isEmpty());
        }
    }
    private static void render(Component component, String name, int width) throws Exception {
        component.setSize(width, 820); layout(component);
        var image = new java.awt.image.BufferedImage(width, 820, java.awt.image.BufferedImage.TYPE_INT_RGB);
        var graphics = image.createGraphics(); component.printAll(graphics); graphics.dispose();
        var output = Path.of("build", "ui-previews"); java.nio.file.Files.createDirectories(output);
        javax.imageio.ImageIO.write(image, "png", output.resolve(name + ".png").toFile());
    }
    private static void layout(Component component) { if (component instanceof Container container) { container.doLayout(); for (var child : container.getComponents()) layout(child); } }
}
