package bpsh.burp.ui;

import bpsh.journey.JourneyDefinition;
import bpsh.journey.persistence.JourneyDocument;
import bpsh.journey.persistence.JourneyJson;
import bpsh.journey.persistence.ProjectStore;
import bpsh.request.RequestSettings;
import java.awt.Component;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.swing.JButton;
import javax.swing.JTextArea;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

/** Verifies confirmed recovery in the existing project, including cancellation and failed writes. */
class ProjectStorageResetTest {
    @TempDir Path root;

    @Test void confirmedResetRepairsTheSameProjectAndPreservesUserJourneysAndOtherData() throws Exception {
        String library = JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.LIBRARY, false, false);
        Files.writeString(root.resolve("library.json"), library);
        var harness = harness();
        try (var editor = harness.new Editor("{broken-project")) {
            editor.disk.put("other-extension-data", "kept");
            var dialogs = new ResetDialogs(true); install(editor.ui, dialogs);
            harness.edt(() -> ((JButton) harness.member(editor.ui, "resetProjectStorageButton")).doClick(0));
            harness.await(() -> { try { return editor.status().contains("Project storage reset"); } catch (Exception failure) { return false; } });
            assertEquals(1, dialogs.confirmations);
            assertTrue(dialogs.message.contains("remembered secrets"));
            assertTrue(dialogs.message.contains("Session handling settings"));
            assertTrue(dialogs.message.contains("User journeys and all other Burp project data will be kept"));
            assertFalse(editor.registry.snapshot().unavailableScopes().contains(JourneyDefinition.Scope.PROJECT));
            try (var project = JourneyJson.read(editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY), JourneyDocument.DocumentKind.PROJECT)) {
                assertTrue(project.journeys().isEmpty()); assertEquals(RequestSettings.Controls.defaults(), project.controls());
            }
            assertEquals("kept", editor.disk.get("other-extension-data"));
            assertEquals("untouched old data", editor.disk.get("bpsh_config"));
            assertEquals(library, Files.readString(editor.library.path()));
            harness.edt(() -> {
                assertFalse(((JButton) harness.member(editor.ui, "resetProjectStorageButton")).isVisible());
                harness.call(editor.ui, "createJourney", new Class<?>[]{});
            });
            harness.await(() -> { try { return editor.saved(); } catch (Exception failure) { return false; } });
            assertEquals(1, editor.registry.snapshot().entries().keySet().stream().filter(key -> key.scope() == JourneyDefinition.Scope.PROJECT).count());
            assertEquals(1, editor.registry.snapshot().entries().keySet().stream().filter(key -> key.scope() == JourneyDefinition.Scope.LIBRARY).count());
            assertTrue(editor.clock.workers.isEmpty());
        }
    }

    @Test void cancellingResetDoesNotWriteAnything() throws Exception {
        var harness = harness();
        try (var editor = harness.new Editor("{broken-project")) {
            var before = java.util.Map.copyOf(editor.disk);
            var dialogs = new ResetDialogs(false); install(editor.ui, dialogs);
            harness.edt(() -> ((JButton) harness.member(editor.ui, "resetProjectStorageButton")).doClick(0));
            assertEquals(1, dialogs.confirmations); assertEquals(before, editor.disk);
            assertTrue(editor.registry.snapshot().unavailableScopes().contains(JourneyDefinition.Scope.PROJECT));
            harness.edt(() -> assertTrue(((JButton) harness.member(editor.ui, "resetProjectStorageButton")).isEnabled()));
        }
    }

    @Test void failedResetKeepsTheStoredDataAndAllowsRetry() throws Exception {
        var harness = harness();
        try (var editor = harness.new Editor("{broken-project")) {
            editor.failWrites.set(true); var dialogs = new ResetDialogs(true); install(editor.ui, dialogs);
            harness.edt(() -> ((JButton) harness.member(editor.ui, "resetProjectStorageButton")).doClick(0));
            harness.await(() -> {
                var ready = new java.util.concurrent.atomic.AtomicBoolean();
                try { harness.edt(() -> ready.set(((JButton) harness.member(editor.ui, "resetProjectStorageButton")).isEnabled()
                        && ((JTextArea) harness.member(editor.ui, "collectionFeedback")).getText().contains("could not be reset"))); }
                catch (Exception failure) { return false; } return ready.get();
            });
            assertEquals("{broken-project", editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY));
            assertTrue(editor.registry.snapshot().unavailableScopes().contains(JourneyDefinition.Scope.PROJECT));
            editor.failWrites.set(false);
            harness.edt(() -> ((JButton) harness.member(editor.ui, "resetProjectStorageButton")).doClick(0));
            harness.await(() -> { try { return editor.status().contains("Project storage reset"); } catch (Exception failure) { return false; } });
            assertEquals(2, dialogs.confirmations);
            assertFalse(editor.registry.snapshot().unavailableScopes().contains(JourneyDefinition.Scope.PROJECT));
        }
    }

    @ParameterizedTest @ValueSource(strings = {"unversioned", "unsupported"})
    void resetRecoversOldRuleStorageWithoutExposingOrKeepingProjectSecrets(String version) throws Exception {
        var project = (com.fasterxml.jackson.databind.node.ObjectNode) JourneyRegistryTest.JSON.readTree(
                JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, true, true));
        var controls = (com.fasterxml.jackson.databind.node.ObjectNode) project.get("controls");
        controls.putArray("rules");
        if (version.equals("unsupported")) controls.put("rulesVersion", 99);
        String stored = JourneyRegistryTest.JSON.writeValueAsString(project);
        String library = JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.LIBRARY, true, true);
        Files.writeString(root.resolve("library.json"), library);
        var harness = harness();
        try (var editor = harness.new Editor(stored)) {
            harness.edt(() -> {
                harness.call(editor.ui, "refreshJourneyUi", new Class<?>[]{});
                JTextArea feedback = harness.member(editor.ui, "collectionFeedback");
                assertTrue(feedback.getText().contains("Unsupported Session handling storage format"));
                assertTrue(feedback.getText().contains("Reset project storage"));
                assertFalse(feedback.getText().contains("EXAMPLE_SECRET"));
            });
            assertEquals(stored, editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY), "Rejected storage must survive until explicit confirmation");
            install(editor.ui, new ResetDialogs(true));
            harness.edt(() -> ((JButton) harness.member(editor.ui, "resetProjectStorageButton")).doClick(0));
            harness.await(() -> { try { return editor.status().contains("Project storage reset"); } catch (Exception failure) { return false; } });
            String reset = editor.disk.get(ProjectStore.NATIVE_PROJECT_KEY);
            assertFalse(reset.contains("EXAMPLE_SECRET"));
            try (var parsed = JourneyJson.read(reset, JourneyDocument.DocumentKind.PROJECT)) {
                assertTrue(parsed.journeys().isEmpty()); assertTrue(parsed.secrets().isEmpty());
                assertEquals(RequestSettings.Controls.defaults(), parsed.controls());
            }
            assertEquals(library, Files.readString(editor.library.path()), "User journeys and their remembered secrets must survive");
            assertEquals(1, editor.registry.snapshot().entries().size());
        }
    }

    /** @return Existing isolated component/storage harness. */
    private JourneyRegistryTest.NativeUi harness() {
        var harness = new JourneyRegistryTest().new NativeUi(); harness.root = root; return harness;
    }

    /** @param controller Test controller. @param dialogs Confirmation decision without native dialogs. */
    private static void install(UiController controller, ResetDialogs dialogs) throws Exception {
        var field = UiController.class.getDeclaredField("dialogs"); field.setAccessible(true); field.set(controller, dialogs);
    }

    /** Records the destructive confirmation and rejects every unexpected popup. */
    private static final class ResetDialogs implements JourneyDialogs {
        private final boolean approved;
        private volatile int confirmations;
        private volatile String message = "";
        /** @param approved Whether the user confirms the reset. */
        ResetDialogs(boolean approved) { this.approved = approved; }
        @Override public Path file(Component parent, boolean save) { throw new AssertionError("Unexpected chooser"); }
        @Override public boolean confirm(Component parent, Object content, String title) {
            assertEquals("Reset project storage", title); confirmations++; message = content.toString(); return approved;
        }
        @Override public void inform(Component parent, String text) { throw new AssertionError("Unexpected popup: " + text); }
    }
}
