import org.junit.jupiter.api.Test;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises generated tags, saved rename semantics and active duplicate rejection through the real editor. */
class JourneyNamesTest {
    @org.junit.jupiter.api.io.TempDir Path root;

    @Test void generatedNamesAreStablePortableAndBounded() {
        assertEquals("employee-login", JourneyNames.alias("Employee login"));
        assertEquals("equipe-finance", JourneyNames.alias("  Équipe / Finance! "));
        assertEquals("employee_login", JourneyNames.alias("Employee_login"));
        assertEquals("", JourneyNames.alias("  "));
        for (String name : List.of("中文", "🔑", "---", "x".repeat(128), "a".repeat(63) + " - account")) {
            String alias = JourneyNames.alias(name); assertEquals(alias, JourneyNames.alias(name));
            assertEquals(alias, ConfigManager.alias(alias)); assertTrue(alias.length() <= 64);
        }
    }

    @Test void newJourneyKeepsItsGeneratedAliasInternalAcrossRenames() throws Exception {
        var h = harness(); try (var editor = h.new Editor(null)) {
            h.edt(() -> {
                h.call(editor.ui, "newJourney", new Class<?>[]{});
                assertFalse(editor.fields().containsKey("alias"));
                assertEquals("new-journey", h.member(editor.ui, "draftAlias"));
                editor.fields().get("name").setText("Employee login"); assertEquals("employee-login", h.member(editor.ui, "draftAlias"));
                editor.fields().get("name").setText(""); assertEquals("", h.member(editor.ui, "draftAlias"));
                editor.fields().get("name").setText("Other login"); assertEquals("other-login", h.member(editor.ui, "draftAlias"));
            });
        }
    }

    @Test void existingAliasSurvivesOpeningAndUnrelatedEditsButRenameCommitsTheNewAlias() throws Exception {
        String json;
        try (var original = JourneyRegistryTest.document(ConfigManager.DocumentKind.PROJECT)) {
            var legacy = JourneyRegistryTest.changed(original.journeys().getFirst(), "legacy-tag", "Employee account");
            try (var changed = JourneyRegistryTest.definitions(original, List.of(legacy))) { json = ConfigManager.nativeToJson(changed); }
        }
        var h = harness(); try (var editor = h.new Editor(json)) {
            var key = editor.registry.snapshot().resolve("legacy-tag").identity().key();
            open(h, editor, key);
            h.edt(() -> {
                javax.swing.JList<?> journeys = h.member(editor.ui, "saved");
                assertEquals("Employee account", journeys.getModel().getElementAt(0).toString());
                AutomaticRulesPanel rules = h.member(editor.ui, "automaticRules");
                javax.swing.JComboBox<?> available = h.member(rules, "available");
                assertEquals("Employee account", available.getItemAt(0).toString());
                assertEquals("legacy-tag", h.member(editor.ui, "draftAlias"));
                editor.fields().get("url").setText("https://app.example/new-login"); h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false);
            });
            h.await(() -> { try { return editor.saved(); } catch (Exception error) { return false; } });
            h.edt(() -> {
                editor.fields().get("name").setText("Employee login"); assertEquals("employee-login", h.member(editor.ui, "draftAlias"));
                assertEquals(key, editor.registry.snapshot().resolve("legacy-tag").identity().key());
                h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false);
            });
            h.await(() -> { try { return editor.saved(); } catch (Exception error) { return false; } });
            assertEquals(key, editor.registry.snapshot().resolve("employee-login").identity().key());
            assertThrows(IllegalStateException.class, () -> editor.registry.snapshot().resolve("legacy-tag"));
            open(h, editor, key); h.edt(() -> assertEquals("employee-login", h.member(editor.ui, "draftAlias")));
        }
    }

    @Test void duplicateGeneratedTagCanBeSavedAndIsRejectedOnExecution() throws Exception {
        var h = harness(); try (var editor = h.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
            try (var source = JourneyRegistryTest.document(ConfigManager.DocumentKind.LIBRARY)) {
                var other = JourneyRegistryTest.changed(source.journeys().getFirst(), "employee-login", "Existing login");
                try (var document = JourneyRegistryTest.definitions(source, List.of(other))) { editor.registry.replaceLoaded(JourneyDefinition.Scope.LIBRARY, document); }
            }
            var key = editor.registry.snapshot().resolve("employee").identity().key(); open(h, editor, key);
            String previous = editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY);
            h.edt(() -> { editor.fields().get("name").setText("Employee login"); h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false); });
            h.await(() -> { try { return editor.saved(); } catch (Exception error) { return false; } });
            assertNotEquals(previous, editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY));
            assertThrows(IllegalStateException.class, () -> editor.registry.snapshot().resolve("employee-login"));
            h.edt(() -> ((javax.swing.JButton) h.member(editor.ui, "testButton")).doClick(0));
            h.await(() -> { try { return editor.status().contains("Choose a different journey name"); } catch (Exception error) { return false; } });
            assertTrue(editor.clock.workers.isEmpty());
        }
    }

    /** @return Local editor harness, with no installed host or shared persistence. */
    @Test void copyingNamedReferencesUsesSavedIdentityAndDoesNotAcquireCredentials() throws Exception {
        var h = harness(); var copied = new java.util.ArrayList<String>();
        try (var editor = h.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
            var key = editor.registry.snapshot().resolve("employee").identity().key(); open(h, editor, key);
            h.edt(() -> {
                var dialogs = new UiController.Dialogs() {
                    public Path file(java.awt.Component parent, boolean save) { return null; }
                    public boolean confirm(java.awt.Component parent, Object content, String title) { return false; }
                    public void inform(java.awt.Component parent, String text) { fail(text); }
                    public void copyText(String text) { copied.add(text); }
                };
                var field = UiController.class.getDeclaredField("dialogs"); field.setAccessible(true); field.set(editor.ui, dialogs);
                CredentialsPanel credentials = h.member(editor.ui, "credentials"); credentials.setDefinition(CombinedCredentialsTest.SOURCES);
                h.call(editor.ui, "edited", new Class<?>[]{}); h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false);
            });
            h.await(() -> { try { return editor.saved(); } catch (Exception error) { return false; } });
            h.edt(() -> {
                var entry = editor.registry.snapshot().resolve(key);
                var menu = (javax.swing.JPopupMenu) h.call(editor.ui, "referenceMenu", new Class<?>[]{JourneyRegistry.Entry.class}, entry);
                assertEquals(2, menu.getComponentCount());
                var access = (javax.swing.JMenu) menu.getComponent(0); assertEquals("access", access.getText());
                assertEquals(AuthenticationTagMenu.FORMATS.size(), access.getItemCount()); access.getItem(0).doClick(0); access.getItem(3).doClick(0);
                assertEquals(List.of("<@employee token=\"access\"/>", "<@json><@employee token=\"access\"/></@json>"), copied);
                assertTrue(editor.clock.workers.isEmpty()); assertNull(editor.coordinator.peek(entry.identity()));
            });
        }
    }

    /** @return Local editor harness, with no installed host or shared persistence. */
    private JourneyRegistryTest.NativeUi harness() { var h = new JourneyRegistryTest().new NativeUi(); h.root = root; return h; }
    /** @param h Owned harness. @param editor Local editor. @param key Saved journey to review. */
    private static void open(JourneyRegistryTest.NativeUi h, JourneyRegistryTest.NativeUi.Editor editor, SecretStore.Key key) throws Exception {
        h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{SecretStore.Key.class}, key));
        h.await(() -> { try { return !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception error) { return false; } });
    }
}
