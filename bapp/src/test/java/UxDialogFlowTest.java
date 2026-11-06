import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import javax.swing.*;
import java.awt.Component;
import java.awt.Container;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiFunction;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises modal decisions against private temporary stores, without controlling an installed application. */
class UxDialogFlowTest {
    @org.junit.jupiter.api.io.TempDir Path root;
    /** @return Isolated component harness sharing only this test's temporary root. */
    private JourneyRegistryTest.NativeUi harness() { var h = new JourneyRegistryTest().new NativeUi(); h.root = root; return h; }
    /** Supplies finite dialog decisions while retaining the real controller action and persistence pipeline. */
    private static final class Choices implements UiController.Dialogs {
        Path chosen; List<Path> imports; int files, confirmations; BiFunction<Object, String, Boolean> decision = (content, title) -> true;
        /** @return Predetermined path or cancellation, on the actual Swing event thread. */
        @Override public Path file(Component parent, boolean save) { assertTrue(SwingUtilities.isEventDispatchThread()); files++; return chosen; }
        @Override public List<Path> importFiles(Component parent) { return imports == null ? UiController.Dialogs.super.importFiles(parent) : imports; }
        /** @return Predetermined confirmation after allowing inspection/editing of the real preview component. */
        @Override public boolean confirm(Component parent, Object content, String title) { assertTrue(SwingUtilities.isEventDispatchThread()); confirmations++; return decision.apply(content, title); }
        /** Fails if the test reaches an unplanned information dialog. */
        @Override public void inform(Component parent, String text) { fail(text); }
    }
    /** @param editor Owned controller. @param choices Finite modal decisions. */
    private void install(JourneyRegistryTest.NativeUi.Editor editor, Choices choices) throws Exception {
        var field = UiController.class.getDeclaredField("dialogs"); field.setAccessible(true); field.set(editor.ui, choices);
        var api = UiController.class.getDeclaredField("api"); api.setAccessible(true); api.set(editor.ui, emptyHost(burp.api.montoya.MontoyaApi.class));
    }
    /** @param type SDK boundary interface. @return Interface-only host double with no native window or persistence. */
    private static Object emptyHost(Class<?> type) { return java.lang.reflect.Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (proxy, method, args) -> method.getReturnType().isInterface() ? emptyHost(method.getReturnType()) : null); }
    /** @param h Component harness. @param editor Initialized saved editor. */
    private void open(JourneyRegistryTest.NativeUi h, JourneyRegistryTest.NativeUi.Editor editor) throws Exception {
        var key = editor.registry.snapshot().resolve("employee").identity().key(); h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{SecretStore.Key.class}, key));
        h.await(() -> { try { return key.equals(h.member(editor.ui, "editing")) && !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception ex) { return false; } });
    }
    /** @param h Component harness. @param editor Controller. @param action Local action name. */
    private void action(JourneyRegistryTest.NativeUi h, JourneyRegistryTest.NativeUi.Editor editor, String action) throws Exception { h.edt(() -> h.call(editor.ui, action, new Class<?>[]{})); }
    /** @param h Component harness. @param editor Controller. @param text Safe feedback expected after the background action. */
    private void feedback(JourneyRegistryTest.NativeUi h, JourneyRegistryTest.NativeUi.Editor editor, String text) throws Exception { h.await(() -> { try { return text.startsWith("Saved ") ? editor.saved() : editor.status().contains(text); } catch (Exception ex) { return false; } }); }
    /** Retains the imported fixture's session value while removing remembered storage through the real Save action. */
    private void forgetPersistence(JourneyRegistryTest.NativeUi h, JourneyRegistryTest.NativeUi.Editor editor) throws Exception { h.edt(() -> { editor.checks().get("remember").doClick(); h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false); }); feedback(h, editor, "Saved employee"); }

    @Test void middlewareBrowseCancelAndChooseDoNotLoadADevice() throws Exception {
        var h = harness(); try (var editor = h.new Editor(null)) {
            var choices = new Choices(); install(editor, choices);
            h.edt(() -> { h.call(editor.ui, "newJourney", new Class<?>[]{}); editor.checks().get("mtls").doClick(); editor.fields().get("module").setText("old path"); h.call(editor.ui, "chooseFile", new Class<?>[]{String.class}, "module"); assertEquals("old path", editor.fields().get("module").getText()); });
            choices.chosen = root.resolve("not-loaded.dll");
            h.edt(() -> { h.call(editor.ui, "chooseFile", new Class<?>[]{String.class}, "module"); assertEquals(choices.chosen.toAbsolutePath().toString(), editor.fields().get("module").getText()); });
            assertEquals(2, choices.files);
        }
    }

    @Test void confirmationPreviewsFitCompactParentsAndTextMessagesWrap() throws Exception {
        var h = harness(); try (var editor = h.new Editor(null)) {
            h.edt(() -> {
                for (int width : new int[]{720, 900, 1280}) {
                    var parent = new JPanel(); parent.setSize(width, 820); var table = new JTable(2, 5); var preview = new JScrollPane(table); preview.setPreferredSize(new java.awt.Dimension(950, 330));
                    Object content = h.call(editor.ui, "dialogContent", new Class<?>[]{Component.class, Object.class}, parent, preview);
                    assertSame(preview, content); assertTrue(preview.getPreferredSize().width < width); assertTrue(preview.getPreferredSize().height < parent.getHeight()); assertEquals(5, table.getColumnCount());
                    var message = (JTextArea) h.call(editor.ui, "dialogContent", new Class<?>[]{Component.class, Object.class}, parent, "Reload discards the visible draft and reloads persisted values. Unremembered values must be entered again. Continue?");
                    assertTrue(message.getLineWrap()); assertFalse(message.isEditable()); assertTrue(message.getPreferredSize().width < width);
                }
            });
        }
    }

    @Test void certificatePreviewShowsCompleteSelectedIdentityForMouseAndKeyboardSelection() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var table = new JTable(new Object[][]{{"Same subject", "Long issuer", "11", "Tomorrow"}, {"Same subject", "Long issuer", "12", "Next week"}},
                    new Object[]{"Subject", "Issuer", "Serial", "Valid until"});
            table.setRowSelectionInterval(0, 0); var preview = UiController.certificatePreview(table);
            var details = (JTextArea) ((JScrollPane) preview.getComponent(1)).getViewport().getView();
            assertTrue(details.getText().contains("Serial: 11")); assertTrue(details.getLineWrap()); assertFalse(details.isEditable()); assertFalse(details.getText().contains("SHA-256"));
            table.setRowSelectionInterval(1, 1); assertTrue(details.getText().contains("Valid until: Next week")); assertTrue(details.getText().contains("Serial: 12"));
            table.clearSelection(); assertEquals("No certificate selected.", details.getText());
        });
    }

    @Test
    void automaticSaveBeforeNavigationKeepsSidebarAndEditorOnTheSameJourney() throws Exception {
        var h = harness(); String stored;
        try (var original = ConfigManager.parseNative(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false), ConfigManager.DocumentKind.PROJECT)) {
            var first = original.journeys().getFirst(); var second = JourneyRegistryTest.changed(first.withIdentity(java.util.UUID.randomUUID(), List.of(), false), "different", "Other account");
            try (var document = new ConfigManager.NativeDocument(original.kind(), original.revision(), List.of(first, second), original.retiredAliases(), original.controls(), Map.of())) { stored = ConfigManager.nativeToJson(document); }
        }
        try (var editor = h.new Editor(stored)) {
            open(h, editor); var target = editor.registry.snapshot().resolve("different").identity().key();

            h.edt(() -> {
                JTabbedPane wizard = h.member(editor.ui, "wizard"); var setup = (JScrollPane) wizard.getComponentAt(0);
                setup.getViewport().setViewSize(new java.awt.Dimension(400, 1500)); setup.getViewport().setExtentSize(new java.awt.Dimension(400, 500)); setup.getViewport().setViewPosition(new java.awt.Point(0, 120));
                ((SessionStatusBar) h.member(editor.ui, "status")).setText("Old journey PIN warning");
                editor.fields().get("name").setText("Unsaved edit"); JList<?> list = h.member(editor.ui, "saved"); list.setSelectedIndex(0);
            });
            h.await(() -> { try { return target.equals(h.member(editor.ui, "editing")) && !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception error) { return false; } });
            h.edt(() -> {
                JList<?> list = h.member(editor.ui, "saved"); assertEquals(target, h.member(list.getSelectedValue(), "key")); assertEquals("different", h.member(editor.ui, "draftAlias"));
                JTabbedPane wizard = h.member(editor.ui, "wizard"); assertEquals(0, ((JScrollPane) wizard.getComponentAt(0)).getViewport().getViewPosition().y);
                assertFalse(((SessionStatusBar) h.member(editor.ui, "status")).getText().contains("Old journey PIN warning"));
            });
        }
    }

    @Test void importChooserAndPreviewCancellationLeaveBothScopesUntouched() throws Exception {
        var h = harness(); try (var editor = h.new Editor(null)) {
            var choices = new Choices(); install(editor, choices); action(h, editor, "importJourneys"); assertEquals(0, choices.confirmations);
            choices.chosen = root.resolve("journey.json"); Files.writeString(choices.chosen, JourneyRegistryTest.fixture(ConfigManager.DocumentKind.EXPORT, false, true));
            choices.decision = (content, title) -> false; action(h, editor, "importJourneys"); h.await(() -> choices.confirmations == 1); h.edt(() -> {});
            assertTrue(editor.registry.snapshot().entries().isEmpty()); assertNull(editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY)); assertFalse(Files.exists(root.resolve("library.json")));
        }
    }

    @ParameterizedTest @ValueSource(strings={"malformed", "utf8", "oversized", "wrong-kind"})
    void invalidImportNeverOpensAPreviewOrChangesStorage(String kind) throws Exception {
        var h = harness(); try (var editor = h.new Editor(null)) {
            var choices = new Choices(); install(editor, choices); choices.chosen = root.resolve("invalid.json");
            switch (kind) { case "malformed" -> Files.writeString(choices.chosen, "{broken"); case "utf8" -> Files.write(choices.chosen, new byte[]{(byte) 0xff}); case "oversized" -> Files.write(choices.chosen, new byte[(4 << 20) + 1]); default -> Files.writeString(choices.chosen, JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false)); }
            action(h, editor, "importJourneys"); feedback(h, editor, switch (kind) { case "utf8" -> "UTF-8"; case "oversized" -> "4 MiB"; case "wrong-kind" -> "kind"; default -> "invalid native JSON"; });
            assertEquals(0, choices.confirmations); assertTrue(editor.registry.snapshot().entries().isEmpty()); assertNull(editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY));
        }
    }

    @ParameterizedTest @ValueSource(booleans={false,true})
    void importIntoEitherScopeAllocatesFreshIdsAndKeepsSecretsSessionOnly(boolean user) throws Exception {
        var h = harness(); try (var editor = h.new Editor(null)) {
            var choices = new Choices(); install(editor, choices); choices.chosen = root.resolve("import.json"); Files.writeString(choices.chosen, JourneyRegistryTest.fixture(ConfigManager.DocumentKind.EXPORT, false, true));
            if (user) h.edt(() -> h.call(editor.ui, "selectScope", new Class<?>[]{int.class}, 1)); action(h, editor, "importJourneys"); feedback(h, editor, "Imported 1 journey");
            var entry = editor.registry.snapshot().resolve("employee"); assertEquals(user ? JourneyDefinition.Scope.LIBRARY : JourneyDefinition.Scope.PROJECT, entry.identity().scope());
            assertNotEquals(JourneyRegistryTest.JOURNEY, entry.definition().id()); var step = entry.definition().steps().getFirst(); assertNotEquals(JourneyRegistryTest.STEP, step.id()); assertFalse(entry.definition().rememberSecrets());
            try (var values = editor.secrets.snapshot(entry.identity().key())) { assertArrayEquals("EXAMPLE_SECRET".toCharArray(), values.stepValue(step.id())); }
            String written = user ? Files.readString(root.resolve("library.json")) : editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY); assertFalse(written.contains("EXAMPLE_SECRET"));
        }
    }

    @Test void importCollisionRequiresExplicitAliasEditAndNeverOverwritesExistingJourney() throws Exception {
        var h = harness(); try (var editor = h.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
            var original = editor.registry.snapshot().resolve("employee"); var choices = new Choices(); install(editor, choices); choices.chosen = root.resolve("import.json"); Files.writeString(choices.chosen, JourneyRegistryTest.fixture(ConfigManager.DocumentKind.EXPORT, false, false));
            action(h, editor, "importJourneys"); feedback(h, editor, "Alias"); assertEquals(1, editor.registry.snapshot().entries().size()); assertEquals(original.identity(), editor.registry.snapshot().resolve("employee").identity());
            choices.decision = (content, title) -> { table((Component) content).setValueAt("imported-employee", 0, 3); return true; };
            action(h, editor, "importJourneys"); feedback(h, editor, "Imported 1 journey"); assertEquals(2, editor.registry.snapshot().entries().size()); assertEquals(original.identity(), editor.registry.snapshot().resolve("employee").identity()); assertNotNull(editor.registry.snapshot().resolve("imported-employee"));
        }
    }

    @Test void exportCancelAtBothDialogsAndDirtyDraftCreateNoFile() throws Exception {
        var h = harness(); try (var editor = h.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
            open(h, editor); var choices = new Choices(); install(editor, choices); choices.decision = (content, title) -> false;
            action(h, editor, "exportJourney"); assertEquals(0, choices.files);
            choices.decision = (content, title) -> true; action(h, editor, "exportJourney"); assertEquals(1, choices.files);
            choices.chosen = root.resolve("must-not-exist.json"); h.edt(() -> editor.fields().get("name").setText("Unsaved name")); action(h, editor, "exportJourney"); assertEquals(2, choices.confirmations); assertFalse(Files.exists(choices.chosen)); assertTrue(editor.status().contains("Save this journey"));
        }
    }

    @ParameterizedTest @ValueSource(booleans={false,true})
    void exportSecretChoiceIsIndependentOfRememberSecrets(boolean include) throws Exception {
        var h = harness(); try (var editor = h.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, true, true))) {
            open(h, editor); forgetPersistence(h, editor); var choices = new Choices(); install(editor, choices); choices.chosen = root.resolve("export.json"); choices.decision = (content, title) -> { if (content instanceof JCheckBox box) { assertFalse(box.isSelected()); box.setSelected(include); } return true; };
            action(h, editor, "exportJourney"); feedback(h, editor, "export saved"); String json = Files.readString(choices.chosen);
            assertEquals(include, json.contains("EXAMPLE_SECRET")); try (var parsed = ConfigManager.parseNative(json, ConfigManager.DocumentKind.EXPORT)) { assertFalse(parsed.journeys().getFirst().rememberSecrets()); assertEquals(include, !parsed.secrets().isEmpty()); }
        }
    }

    @Test void missingSecretExportFailsBeforeCreatingTheChosenFile() throws Exception {
        var h = harness(); try (var editor = h.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
            open(h, editor); var choices = new Choices(); install(editor, choices); choices.chosen = root.resolve("must-not-exist.json"); choices.decision = (content, title) -> { ((JCheckBox) content).setSelected(true); return true; };
            action(h, editor, "exportJourney"); feedback(h, editor, "missing"); assertFalse(Files.exists(choices.chosen));
        }
    }

    @Test void exportOverwriteCancelPreservesBytesAndConfirmationReplacesOnlyChosenFile() throws Exception {
        var h = harness(); try (var editor = h.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
            open(h, editor); var choices = new Choices(); install(editor, choices); choices.chosen = root.resolve("existing.json"); Files.writeString(choices.chosen, "original fixture bytes");
            choices.decision = (content, title) -> !title.equals("Export"); action(h, editor, "exportJourney"); h.await(() -> choices.confirmations == 2); h.edt(() -> {}); assertEquals("original fixture bytes", Files.readString(choices.chosen));
            choices.decision = (content, title) -> true; action(h, editor, "exportJourney"); feedback(h, editor, "export saved"); try (var parsed = ConfigManager.parseNative(Files.readString(choices.chosen), ConfigManager.DocumentKind.EXPORT)) { assertEquals("employee", parsed.journeys().getFirst().alias()); }
        }
    }

    @Test void deletionCancelPreservesIdentityAndConfirmationFreesAliasAndCancelsPendingLogin() throws Exception {
        var h = harness(); try (var editor = h.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
            open(h, editor); var entry = editor.registry.snapshot().resolve("employee"); var choices = new Choices(); install(editor, choices); choices.decision = (content, title) -> false;
            action(h, editor, "delete"); assertEquals(entry.identity(), editor.registry.snapshot().resolve("employee").identity());
            var ticket = editor.coordinator.test(entry, false); assertFalse(ticket.future().isDone()); choices.decision = (content, title) -> true; action(h, editor, "delete"); feedback(h, editor, "Deleted journey");
            assertTrue(editor.registry.snapshot().entries().isEmpty()); assertTrue(ticket.future().isCompletedExceptionally());
            assertTrue(editor.registry.document(JourneyDefinition.Scope.PROJECT).retiredAliases().isEmpty());
            h.edt(() -> { assertEquals("Select or create a journey.", ((SessionStatusBar) h.member(editor.ui, "status")).stateText()); assertFalse(((JMenuItem) h.member(editor.ui, "deleteSelectedItem")).isEnabled()); });
        }
    }

    /** Builds three valid journeys while keeping all fixture values within this test's private stores. */
    private String threeJourneys(ConfigManager.DocumentKind kind) throws Exception {
        var document = (com.fasterxml.jackson.databind.node.ObjectNode) JourneyRegistryTest.JSON.readTree(JourneyRegistryTest.fixture(kind, false, false));
        var journeys = (com.fasterxml.jackson.databind.node.ArrayNode) document.get("journeys");
        for (String alias : List.of("second", "third")) {
            var copy = journeys.get(0).deepCopy(); ((com.fasterxml.jackson.databind.node.ObjectNode) copy).put("id", java.util.UUID.randomUUID().toString()).put("alias", alias).put("displayName", alias + " account"); journeys.add(copy);
        }
        return document.toString();
    }

    @ParameterizedTest @ValueSource(booleans={false,true})
    void batchDeletionConfirmsOnceDeletesOnlySelectedAndCancelsTheirLogins(boolean user) throws Exception {
        var h = harness(); String stored = threeJourneys(user ? ConfigManager.DocumentKind.LIBRARY : ConfigManager.DocumentKind.PROJECT);
        if (user) Files.writeString(root.resolve("library.json"), stored);
        try (var editor = h.new Editor(user ? null : stored)) {
            if (user) h.edt(() -> h.call(editor.ui, "selectScope", new Class<?>[]{int.class}, 1));
            open(h, editor); var first = editor.registry.snapshot().resolve("employee"); var second = editor.registry.snapshot().resolve("second"); var retained = editor.registry.snapshot().resolve("third");
            var firstLogin = editor.coordinator.test(first, false); var secondLogin = editor.coordinator.test(second, false); var retainedLogin = editor.coordinator.test(retained, false);
            var choices = new Choices(); install(editor, choices); choices.decision = (content, title) -> { assertEquals("Delete 2 journeys", title); return false; };
            h.edt(() -> {
                JList<?> list = h.member(editor.ui, "saved"); list.setSelectionInterval(0, 1);
                h.call(editor.ui, "refreshChoices", new Class<?>[]{});
            });
            h.edt(() -> { JList<?> list = h.member(editor.ui, "saved"); assertEquals(2, list.getSelectedIndices().length); assertEquals("2 journeys selected", ((JLabel) h.member(editor.ui, "batchSelection")).getText()); });
            action(h, editor, "delete"); assertEquals(1, choices.confirmations); assertEquals(3, editor.registry.snapshot().entries().size()); assertFalse(firstLogin.future().isDone());
            choices.decision = (content, title) -> true; action(h, editor, "delete"); feedback(h, editor, "Deleted 2 journeys");
            assertEquals(1, editor.registry.snapshot().entries().size()); assertEquals(retained.identity(), editor.registry.snapshot().resolve("third").identity());
            assertTrue(firstLogin.future().isCompletedExceptionally()); assertTrue(secondLogin.future().isCompletedExceptionally()); assertFalse(retainedLogin.future().isDone());
            String saved = user ? Files.readString(root.resolve("library.json")) : editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY);
            try (var parsed = ConfigManager.parseNative(saved, user ? ConfigManager.DocumentKind.LIBRARY : ConfigManager.DocumentKind.PROJECT)) { assertEquals(List.of("third"), parsed.journeys().stream().map(JourneyDefinition::alias).toList()); }
        }
    }

    @Test void savingADirtyDraftBeforeBatchDeletionKeepsTheWholeCapturedSelection() throws Exception {
        var h = harness(); try (var editor = h.new Editor(threeJourneys(ConfigManager.DocumentKind.PROJECT))) {
            open(h, editor); var choices = new Choices(); install(editor, choices);

            h.edt(() -> { editor.fields().get("name").setText("Saved before deletion"); ((JList<?>) h.member(editor.ui, "saved")).setSelectionInterval(0, 1); });
            action(h, editor, "delete"); feedback(h, editor, "Deleted 2 journeys"); assertEquals(1, choices.confirmations); assertEquals(1, editor.registry.snapshot().entries().size()); assertNotNull(editor.registry.snapshot().resolve("third"));
        }
    }

    @Test void aChangedSelectedIdentityPreventsTheWholeDeletion() throws Exception {
        var h = harness(); try (var editor = h.new Editor(threeJourneys(ConfigManager.DocumentKind.PROJECT))) {
            open(h, editor); String before = editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY); var choices = new Choices(); install(editor, choices);
            choices.decision = (content, title) -> {
                var document = editor.registry.document(JourneyDefinition.Scope.PROJECT);
                try (var changed = JourneyRegistryTest.definitions(document, document.journeys().stream().map(j -> j.alias().equals("second") ? JourneyRegistryTest.changed(j, "changed-second", j.displayName()) : j).toList())) { editor.registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, changed); }
                return true;
            };
            h.edt(() -> ((JList<?>) h.member(editor.ui, "saved")).setSelectionInterval(0, 1)); action(h, editor, "delete"); feedback(h, editor, "changed after it was selected");
            assertEquals(3, editor.registry.snapshot().entries().size()); assertEquals(before, editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY));
        }
    }

    @Test void severalFilesCanImportAReviewedSubsetWithIndependentAliasEdits() throws Exception {
        var h = harness(); try (var editor = h.new Editor(null)) {
            Path first = root.resolve("first.json"), second = root.resolve("second.json");
            Files.writeString(first, threeJourneys(ConfigManager.DocumentKind.EXPORT)); Files.writeString(second, JourneyRegistryTest.fixture(ConfigManager.DocumentKind.EXPORT, false, true));
            var choices = new Choices(); install(editor, choices); choices.imports = List.of(first, second);
            choices.decision = (content, title) -> {
                var preview = table((Component) content); assertEquals(4, preview.getRowCount());
                preview.setValueAt(false, 1, 0); preview.setValueAt(false, 2, 0);
                preview.setValueAt("first-import", 0, 3); preview.setValueAt("second-import", 3, 3); return true;
            };
            action(h, editor, "importJourneys"); feedback(h, editor, "Imported 2 journeys"); assertEquals(1, choices.confirmations); assertEquals(2, editor.registry.snapshot().entries().size());
            var firstImported = editor.registry.snapshot().resolve("first-import"); var secondImported = editor.registry.snapshot().resolve("second-import");
            assertNotEquals(firstImported.identity().journeyId(), secondImported.identity().journeyId());
            try (var values = editor.secrets.snapshot(secondImported.identity().key())) { assertArrayEquals("EXAMPLE_SECRET".toCharArray(), values.stepValue(secondImported.definition().steps().getFirst().id())); }
            assertFalse(editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY).contains("EXAMPLE_SECRET"));
        }
    }

    @Test void collisionInAnyImportedFileOrAnEmptySelectionLeavesStorageUntouched() throws Exception {
        var h = harness(); try (var editor = h.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
            String before = editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY); Path first = root.resolve("a.json"), second = root.resolve("b.json");
            Files.writeString(first, JourneyRegistryTest.fixture(ConfigManager.DocumentKind.EXPORT, false, false)); Files.writeString(second, Files.readString(first));
            var choices = new Choices(); install(editor, choices); choices.imports = List.of(first, second);
            choices.decision = (content, title) -> { table((Component) content).setValueAt("new-alias", 0, 3); return true; };
            action(h, editor, "importJourneys"); feedback(h, editor, "Alias"); assertEquals(before, editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY)); assertEquals(1, editor.registry.snapshot().entries().size());
            choices.decision = (content, title) -> { var preview = table((Component) content); for (int i = 0; i < preview.getRowCount(); i++) preview.setValueAt(false, i, 0); return true; };
            action(h, editor, "importJourneys"); feedback(h, editor, "Select at least one journey"); assertEquals(before, editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY));
        }
    }

    @Test void invalidSecondImportFileCannotPartiallyImportTheFirst() throws Exception {
        var h = harness(); try (var editor = h.new Editor(null)) {
            Path first = root.resolve("valid.json"), second = root.resolve("invalid.json"); Files.writeString(first, JourneyRegistryTest.fixture(ConfigManager.DocumentKind.EXPORT, false, false)); Files.writeString(second, "{broken");
            var choices = new Choices(); install(editor, choices); choices.imports = List.of(first, second);
            action(h, editor, "importJourneys"); feedback(h, editor, "invalid native JSON"); assertEquals(0, choices.confirmations); assertTrue(editor.registry.snapshot().entries().isEmpty()); assertNull(editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY));
        }
    }

    @Test void severalSelectedJourneysExportTogetherAndRenderTheBatchView() throws Exception {
        var h = harness(); try (var editor = h.new Editor(threeJourneys(ConfigManager.DocumentKind.PROJECT))) {
            open(h, editor); var choices = new Choices(); install(editor, choices); choices.chosen = root.resolve("batch.json");
            h.edt(() -> {
                ((JList<?>) h.member(editor.ui, "saved")).setSelectionInterval(0, 1);
                var output = Path.of("build", "ui-previews"); Files.createDirectories(output);
                for (int width : List.of(1280, 900)) {
                    editor.component.setSize(width, 820); h.layout(editor.component);
                    var image = new java.awt.image.BufferedImage(width, 820, java.awt.image.BufferedImage.TYPE_INT_RGB); var graphics = image.createGraphics(); editor.component.printAll(graphics); graphics.dispose(); javax.imageio.ImageIO.write(image, "png", output.resolve("batch-selection-" + width + ".png").toFile());
                }
            });
            action(h, editor, "exportJourney"); feedback(h, editor, "export saved");
            try (var parsed = ConfigManager.parseNative(Files.readString(choices.chosen), ConfigManager.DocumentKind.EXPORT)) { assertEquals(List.of("employee", "second"), parsed.journeys().stream().map(JourneyDefinition::alias).toList()); }
        }
    }

    /** @param component Owned preview tree. @return Its editable alias table. */
    private static JTable table(Component component) { if (component instanceof JTable table) return table; if (component instanceof Container container) for (var child : container.getComponents()) { var result = tableOrNull(child); if (result != null) return result; } throw new AssertionError("Missing preview table"); }
    /** @param component Owned preview subtree. @return Its table or null. */
    private static JTable tableOrNull(Component component) { if (component instanceof JTable table) return table; if (component instanceof Container container) for (var child : container.getComponents()) { var result = tableOrNull(child); if (result != null) return result; } return null; }
}
