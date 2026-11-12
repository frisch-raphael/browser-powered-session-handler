package bpsh.burp.ui;

import bpsh.journey.JourneyDefinition;
import bpsh.journey.persistence.ProjectStore;
import java.awt.Component;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises storage failures with an empty list, expired feedback and collection changes. */
class StorageFeedbackTest {
    @TempDir Path root;

    @Test void unreadableProjectKeepsItsReasonVisibleAndCreationDoesNotOpenAPopup() throws Exception {
        var harness = harness();
        try (var editor = harness.new Editor("{invalid-native")) {
            harness.edt(() -> {
                installNoDialogs(editor.ui);
                ((SessionStatusBar) harness.member(editor.ui, "status")).clear();
                harness.call(editor.ui, "refreshJourneyUi", new Class<?>[]{});
                JTextArea feedback = harness.member(editor.ui, "collectionFeedback");
                assertTrue(feedback.isVisible());
                assertTrue(feedback.getText().contains("Project journey storage is unavailable"));
                assertTrue(feedback.getText().contains("invalid native JSON"));
                assertTrue(feedback.getText().contains("Reset project storage below"));
                editor.component.setSize(1000, 700); harness.layout(editor.component); harness.layout(editor.component);
                assertTrue(feedback.getWidth() > 0);
                assertTrue(feedback.getHeight() >= feedback.getPreferredSize().height, "The complete storage error must fit beside the list");
                String explanation = feedback.getText();
                harness.call(editor.ui, "createJourney", new Class<?>[]{});
                harness.call(editor.ui, "refreshJourneyUi", new Class<?>[]{});
                assertEquals(explanation, feedback.getText());
                assertTrue(editor.registry.snapshot().entries().isEmpty());
                assertEquals("{invalid-native", editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY));
                ((JTabbedPane) harness.member(editor.ui, "journeyScopes")).setSelectedIndex(1);
                assertFalse(feedback.getText().contains("Project journey storage is unavailable"));
                ((JTabbedPane) harness.member(editor.ui, "journeyScopes")).setSelectedIndex(0);
                assertEquals(explanation, feedback.getText());
            });
        }
    }

    @Test void unreadableUserLibraryShowsItsPathAndDoesNotBlockProjectCreation() throws Exception {
        Files.writeString(root.resolve("library.json"), "{invalid-private-library");
        var harness = harness();
        try (var editor = harness.new Editor(null)) {
            assertTrue(editor.registry.snapshot().unavailableScopes().contains(JourneyDefinition.Scope.LIBRARY));
            harness.edt(() -> {
                installNoDialogs(editor.ui);
                ((JTabbedPane) harness.member(editor.ui, "journeyScopes")).setSelectedIndex(1);
                ((SessionStatusBar) harness.member(editor.ui, "status")).clear();
                harness.call(editor.ui, "refreshJourneyUi", new Class<?>[]{});
                JTextArea feedback = harness.member(editor.ui, "collectionFeedback");
                assertTrue(feedback.isVisible());
                assertTrue(feedback.getText().contains("User journey storage is unavailable"));
                assertTrue(feedback.getText().contains(editor.library.path().toString()));
                assertTrue(feedback.getText().contains("invalid native JSON"));
                assertFalse(feedback.getText().contains("invalid-private-library"));
                editor.component.setSize(1000, 700); harness.layout(editor.component); harness.layout(editor.component);
                assertTrue(feedback.getHeight() >= feedback.getPreferredSize().height, "The library path and error must remain readable");
                harness.call(editor.ui, "createJourney", new Class<?>[]{});
                ((JTabbedPane) harness.member(editor.ui, "journeyScopes")).setSelectedIndex(0);
                harness.call(editor.ui, "createJourney", new Class<?>[]{});
            });
            harness.await(() -> { try { return editor.saved(); } catch (Exception failure) { return false; } });
            assertEquals(1, editor.registry.snapshot().entries().size());
            assertEquals("{invalid-private-library", Files.readString(editor.library.path()));
        }
    }

    /** @return Existing component/storage harness with an isolated library directory. */
    private JourneyRegistryTest.NativeUi harness() {
        var harness = new JourneyRegistryTest().new NativeUi(); harness.root = root; return harness;
    }

    /** @param controller Test controller whose located storage errors must never open a dialog. */
    private static void installNoDialogs(UiController controller) throws Exception {
        var field = UiController.class.getDeclaredField("dialogs"); field.setAccessible(true);
        field.set(controller, new JourneyDialogs() {
            @Override public Path file(Component parent, boolean save) { throw new AssertionError("Unexpected chooser"); }
            @Override public boolean confirm(Component parent, Object content, String title) { throw new AssertionError("Unexpected confirmation"); }
            @Override public void inform(Component parent, String text) { throw new AssertionError("Unexpected popup: " + text); }
        });
    }
}
