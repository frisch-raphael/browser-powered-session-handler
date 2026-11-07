package bpsh.ui;

import bpsh.config.JourneyTransfer;
import bpsh.model.JourneyDefinition;
import java.awt.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;
import javax.swing.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Checks that sorting and bulk checkbox changes preserve the exact reviewed source identities. */
class JourneyImportPanelTest {
    private static <T extends Component> T find(Component component, Class<T> type) {
        if (type.isInstance(component)) return type.cast(component);
        if (component instanceof Container parent) for (var child : parent.getComponents()) { T match = find(child, type); if (match != null) return match; }
        return null;
    }
    private static void layout(Component component) { if (component instanceof Container parent) { parent.doLayout(); for (var child : parent.getComponents()) layout(child); } }

    @Test void sortingAndCheckboxSelectionKeepAliasEditsWithTheRightFile() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            UUID id = UUID.randomUUID();
            var panel = new JourneyImportPanel(List.of(new JourneyImportPanel.Item(0, id, "Zulu account", "zulu", "first.json"), new JourneyImportPanel.Item(1, id, "Alpha account", "alpha", "second.json")), JourneyDefinition.Scope.PROJECT);
            var table = find(panel, JTable.class); table.getRowSorter().toggleSortOrder(1);
            assertEquals("Alpha account", table.getValueAt(0, 1)); table.setValueAt("edited-alpha", 0, 3); table.setValueAt(false, 1, 0);
            assertEquals(List.of(new JourneyTransfer.ImportSelection(1, id, "edited-alpha")), panel.selection());
            var actions = (JPanel) panel.getComponent(2); ((JButton) actions.getComponent(1)).doClick(); assertTrue(panel.selection().isEmpty());
            ((JButton) actions.getComponent(0)).doClick(); assertEquals(2, panel.selection().size()); assertEquals("edited-alpha", panel.selection().get(1).alias());
        });
    }

    @Test void importPreviewFitsWideAndCompactDialogs() throws Exception {
        var error = new java.util.concurrent.atomic.AtomicReference<Exception>();
        SwingUtilities.invokeAndWait(() -> {
            try {
                var panel = new JourneyImportPanel(List.of(new JourneyImportPanel.Item(0, UUID.randomUUID(), "Employee login", "employee", "team-journeys.json"), new JourneyImportPanel.Item(0, UUID.randomUUID(), "Admin login", "admin", "team-journeys.json"), new JourneyImportPanel.Item(1, UUID.randomUUID(), "Customer account", "customer", "other-journeys.json")), JourneyDefinition.Scope.PROJECT);
                var output = Path.of("build", "ui-previews"); Files.createDirectories(output);
                for (int width : List.of(850, 740)) {
                    panel.setSize(width, 330); layout(panel);
                    assertTrue(find(panel, JScrollPane.class).getHeight() > 200, "The first layout must leave the import rows visible.");
                    var image = new java.awt.image.BufferedImage(width, 330, java.awt.image.BufferedImage.TYPE_INT_RGB); var graphics = image.createGraphics(); panel.printAll(graphics); graphics.dispose(); javax.imageio.ImageIO.write(image, "png", output.resolve("batch-import-" + width + ".png").toFile());
                    assertEquals(3, panel.selection().size());
                }
            } catch (Exception ex) { error.set(ex); }
        });
        if (error.get() != null) throw error.get();
    }
}
