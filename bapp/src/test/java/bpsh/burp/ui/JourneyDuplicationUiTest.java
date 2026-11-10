package bpsh.burp.ui;

import bpsh.journey.JourneyDefinition;
import bpsh.journey.JourneyKey;
import bpsh.journey.persistence.JourneyDocument;
import bpsh.journey.persistence.JourneyJson;
import bpsh.journey.persistence.ProjectStore;
import java.nio.file.Path;
import javax.swing.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class JourneyDuplicationUiTest {
    @TempDir Path root;

    @Test void menuFlushesLatestEditsAndOpensThePersistedCopy() throws Exception {
        var h = new JourneyRegistryTest().new NativeUi(); h.root = root;
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, true, true))) {
            var key = new JourneyKey(JourneyDefinition.Scope.PROJECT, JourneyRegistryTest.JOURNEY);
            h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, key));
            h.await(() -> { try { return !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception e) { return false; } });
            h.edt(() -> {
                editor.fields().get("name").setText("Edited employee"); editor.fields().get("url").setText("unfinished URL");
                JMenuItem duplicate = h.member(editor.ui, "duplicateSelectedItem"); assertTrue(duplicate.isEnabled()); assertEquals("Duplicate selected", duplicate.getText()); duplicate.doClick(0);
            });
            h.await(() -> editor.registry.snapshot().entries().size() == 2);
            var copy = editor.registry.snapshot().resolve("edited-employee-copy");
            h.await(() -> { try { return copy.identity().key().equals(h.member(editor.ui, "editing")) && !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception e) { return false; } });
            h.edt(() -> {
                assertEquals("Edited employee copy", editor.fields().get("name").getText()); assertEquals("unfinished URL", editor.fields().get("url").getText());
                assertFalse(editor.checks().get("remember").isSelected());
                JMenuItem duplicate = h.member(editor.ui, "duplicateSelectedItem");
                var menu = (JPopupMenu) duplicate.getParent(); menu.setSize(menu.getPreferredSize()); menu.doLayout();
                var image = new java.awt.image.BufferedImage(menu.getWidth(), menu.getHeight(), java.awt.image.BufferedImage.TYPE_INT_RGB);
                var graphics = image.createGraphics(); menu.printAll(graphics); graphics.dispose();
                var output = Path.of("build", "ui-previews"); java.nio.file.Files.createDirectories(output);
                javax.imageio.ImageIO.write(image, "png", output.resolve("journey-duplication-menu.png").toFile());
            });
            try (var disk = JourneyJson.read(editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY), JourneyDocument.DocumentKind.PROJECT)) {
                assertEquals(2, disk.journeys().size()); assertTrue(disk.journeys().stream().anyMatch(j -> j.id().equals(copy.definition().id()))); assertFalse(disk.secrets().containsKey(copy.definition().id()));
            }
            assertTrue(editor.clock.workers.isEmpty(), "duplication must not start login");
            h.edt(() -> {
                JList<?> list = h.member(editor.ui, "saved"); list.setSelectionInterval(0, 1);
                assertFalse(((JMenuItem) h.member(editor.ui, "duplicateSelectedItem")).isEnabled());
            });
        }
    }

    @Test void aFailedSaveLeavesTheSourceDraftAndCreatesNoCopy() throws Exception {
        var h = new JourneyRegistryTest().new NativeUi(); h.root = root;
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            var key = new JourneyKey(JourneyDefinition.Scope.PROJECT, JourneyRegistryTest.JOURNEY);
            h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, key));
            h.await(() -> { try { return !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception e) { return false; } });
            editor.failWrites.set(true);
            h.edt(() -> { editor.fields().get("name").setText("Keep local draft"); ((JMenuItem) h.member(editor.ui, "duplicateSelectedItem")).doClick(0); });
            h.await(() -> { try { return (boolean) h.member(editor.ui, "savePaused"); } catch (Exception e) { return false; } });
            h.edt(() -> { assertEquals(key, h.member(editor.ui, "editing")); assertEquals("Keep local draft", editor.fields().get("name").getText()); });
            assertEquals(1, editor.registry.snapshot().entries().size());
            editor.failWrites.set(false);
        }
    }
}
