package bpsh.burp.ui;

import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.persistence.JourneyDocument;
import java.nio.file.Path;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import bpsh.browser.runtime.*;
import javax.swing.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class BrowserRuntimeUiTest {
    @TempDir Path root;
    private static final class Dialogs implements JourneyDialogs {
        int popups;
        @Override public Path file(java.awt.Component parent, boolean save) { return null; }
        @Override public boolean confirm(java.awt.Component parent, Object content, String title) { throw new AssertionError("Unexpected confirmation"); }
        @Override public void inform(java.awt.Component parent, String text) { popups++; }
        @Override public void loginResult(java.awt.Component parent, String title, String text, boolean error) { popups++; }
    }
    private void open(JourneyRegistryTest.NativeUi harness, JourneyRegistryTest.NativeUi.Editor editor) throws Exception {
        var key = editor.registry.snapshot().resolve("employee").identity().key();
        harness.edt(() -> harness.call(editor.ui, "open", new Class<?>[]{bpsh.journey.JourneyKey.class}, key));
        harness.await(() -> { try { return key.equals(harness.member(editor.ui, "editing")) && !(boolean) harness.member(editor.ui, "editorLoading"); } catch (Exception error) { return false; } });
    }
    private Dialogs dialogs(JourneyRegistryTest.NativeUi harness, UiController ui) throws Exception {
        var dialogs = new Dialogs(); harness.edt(() -> { var field = UiController.class.getDeclaredField("dialogs"); field.setAccessible(true); field.set(ui, dialogs); }); return dialogs;
    }
    private static AuthenticationFailure browserFailure() {
        return new AuthenticationFailure(AuthenticationFailure.Phase.SETUP, AuthenticationFailure.Cause.ASSET_MISSING,
                "Burp Browser is missing.").atInput(AuthenticationFailure.Input.BROWSER_EXECUTABLE);
    }
    @Test void testAndRetryBrowserErrorsNeverOpenAPopup() throws Exception {
        var harness = new JourneyRegistryTest().new NativeUi(); harness.root = root;
        try (var editor = harness.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false),
                (entry, recovery, deadline, cancelled) -> { throw browserFailure(); })) {
            open(harness, editor); var dialogs = dialogs(harness, editor.ui);
            for (String action : List.of("testButton", "retryButton")) {
                harness.edt(() -> { JTabbedPane tabs = harness.member(editor.ui, "mainTabs"); tabs.setSelectedIndex(0); ((JButton) harness.member(editor.ui, action)).doClick(0); });
                harness.await(() -> !editor.clock.workers.isEmpty()); editor.clock.runWorker();
                harness.await(() -> { try { JTabbedPane tabs = harness.member(editor.ui, "mainTabs"); return tabs.getSelectedIndex() == 2; } catch (Exception error) { return false; } });
                assertEquals(0, dialogs.popups);
            }
        }
    }
    @Test void backgroundBrowserFailureIsInlineWithoutChangingTheSelectedPage() throws Exception {
        var harness = new JourneyRegistryTest().new NativeUi(); harness.root = root;
        try (var editor = harness.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false),
                (entry, recovery, deadline, cancelled) -> { throw browserFailure(); })) {
            open(harness, editor); var dialogs = dialogs(harness, editor.ui);
            harness.edt(() -> { JTabbedPane tabs = harness.member(editor.ui, "mainTabs"); tabs.setSelectedIndex(1); });
            try (var ticket = editor.coordinator.acquire(List.of(editor.registry.snapshot().resolve("employee")))) {
                editor.clock.runWorker(); assertThrows(CompletionException.class, () -> ticket.future().join());
                harness.edt(() -> {
                    harness.call(editor.ui, "refreshJourneyUi", new Class<?>[]{});
                    JTabbedPane tabs = harness.member(editor.ui, "mainTabs"); assertEquals(1, tabs.getSelectedIndex());
                    BurpBrowserSettingsPanel panel = harness.member(editor.ui, "browserSettingsPanel");
                    assertTrue(((JTextArea) panel.focusTarget().getClientProperty("validationMessage")).isVisible()); assertEquals(0, dialogs.popups);
                });
            }
        }
    }
    @Test void cancelledPickerKeepsUserSelectionOutOfTheProject() throws Exception {
        var harness = new JourneyRegistryTest().new NativeUi(); harness.root = root;
        try (var editor = harness.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            var values = new HashMap<String, String>(); var settings = new BrowserExecutableSettings();
            var preferences = new BrowserRuntimePreferences(BrowserRuntimePreferencesTest.preferences(values), BrowserRuntimePreferencesTest.installation(settings, null)); preferences.select("invalid literal path");
            var before = Map.copyOf(editor.disk); dialogs(harness, editor.ui);
            harness.edt(() -> {
                editor.ui.browserRuntime(BrowserRuntimePreferencesTest.installation(settings, new BurpBrowserResolver(new BurpBrowserResolver.Environment("windows-x64", List.of(), List.of()), settings::executableOverride)), preferences);
                harness.call(editor.ui, "chooseBrowserExecutable", new Class<?>[]{});
            });
            assertEquals("invalid literal path", settings.executableOverride()); assertEquals(before, editor.disk);
            assertEquals(Map.of("bpsh.browser.executable", "invalid literal path"), values);
        }
    }
    @Test void staleDiscoveryCannotOverwriteANewerSelectionOrClosedUi() throws Exception {
        var harness = new JourneyRegistryTest().new NativeUi(); harness.root = root;
        Path first = root.resolve("a/burpbrowser/156.0.0.0/chrome.exe"), second = root.resolve("b/burpbrowser/156.0.0.0/chrome.exe");
        for (Path executable : List.of(first, second)) { Files.createDirectories(executable.getParent()); Files.writeString(executable, "synthetic executable"); executable.toFile().setExecutable(true); }
        var entered = new CountDownLatch(1); var release = new CountDownLatch(1); var reads = new AtomicInteger();
        var newerEntered = new CountDownLatch(1); var newerRelease = new CountDownLatch(1);
        try (var editor = harness.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            var settings = new BrowserExecutableSettings();
            var preferences = new BrowserRuntimePreferences(null, BrowserRuntimePreferencesTest.installation(settings, null));
            var installation = new bpsh.authentication.BrowserInstallation() {
                @Override public String executableOverride() { return settings.executableOverride(); }
                @Override public void setExecutableOverride(String value) { settings.setExecutableOverride(value); }
                @Override public Selection discover(long deadline, java.util.function.BooleanSupplier cancelled) {
                    boolean firstRead = reads.incrementAndGet() == 1;
                    (firstRead ? entered : newerEntered).countDown();
                    try {
                        if (!(firstRead ? release : newerRelease).await(5, TimeUnit.SECONDS)) throw new AssertionError("Discovery release missing");
                    } catch (InterruptedException error) { Thread.currentThread().interrupt(); throw new AssertionError(error); }
                    // Deliberately complete despite cancellation to exercise the UI's stale-result fence.
                    return new Selection(firstRead ? first : second, !firstRead);
                }
            };
            try {
                harness.edt(() -> editor.ui.browserRuntime(installation, preferences)); assertTrue(entered.await(5, TimeUnit.SECONDS));
                harness.edt(() -> { BurpBrowserSettingsPanel panel = harness.member(editor.ui, "browserSettingsPanel"); ((JTextField) panel.focusTarget()).setText(second.toString()); });
                release.countDown(); assertTrue(newerEntered.await(5, TimeUnit.SECONDS));
                harness.edt(() -> {
                    BurpBrowserSettingsPanel panel = harness.member(editor.ui, "browserSettingsPanel");
                    assertEquals(second.toString(), ((JTextField) panel.focusTarget()).getText(), "A late automatically detected path must not overwrite an edit");
                });
            } finally { release.countDown(); newerRelease.countDown(); }
            harness.await(() -> { try { BurpBrowserSettingsPanel panel = harness.member(editor.ui, "browserSettingsPanel"); return ((JTextField) panel.focusTarget()).getText().equals(second.toString()) && ((JTextArea) harness.member(panel, "location")).getText().startsWith("Custom executable."); } catch (Exception error) { return false; } });
            assertEquals(second.toString(), settings.executableOverride());
            var lateEntered = new CountDownLatch(1); var lateRelease = new CountDownLatch(1);
            var late = new BurpBrowserResolver(new BurpBrowserResolver.Environment("windows-x64", List.of(), List.of()), () -> {
                lateEntered.countDown(); try { if (!lateRelease.await(5, TimeUnit.SECONDS)) throw new AssertionError("Late discovery release missing"); }
                catch (InterruptedException error) { Thread.currentThread().interrupt(); } return first.toString();
            });
            var beforeClose = new java.util.concurrent.atomic.AtomicReference<String>();
            try {
                harness.edt(() -> editor.ui.browserRuntime(BrowserRuntimePreferencesTest.installation(settings, late), preferences)); assertTrue(lateEntered.await(5, TimeUnit.SECONDS));
                harness.edt(() -> {
                    BurpBrowserSettingsPanel panel = harness.member(editor.ui, "browserSettingsPanel"); beforeClose.set(((JTextArea) harness.member(panel, "location")).getText());
                    editor.ui.shutdown();
                });
            } finally { lateRelease.countDown(); }
            editor.ui.awaitSaves(5000);
            harness.edt(() -> { BurpBrowserSettingsPanel panel = harness.member(editor.ui, "browserSettingsPanel"); assertEquals(beforeClose.get(), ((JTextArea) harness.member(panel, "location")).getText()); });
        }
    }
    @Test void explicitBrowserPrerequisiteRevealsSettingsAndRecordingUsesTheSameLocation() throws Exception {
        var harness = new JourneyRegistryTest().new NativeUi(); harness.root = root;
        try (var editor = harness.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false))) {
            var entry = editor.registry.snapshot().resolve("employee");
            var failure = new AuthenticationFailure(AuthenticationFailure.Phase.SETUP, AuthenticationFailure.Cause.ASSET_MISSING,
                    "Burp Browser is missing.").atInput(AuthenticationFailure.Input.valueOf("BROWSER_EXECUTABLE"));
            harness.edt(() -> {
                JTabbedPane tabs = harness.member(editor.ui, "mainTabs"); tabs.setSelectedIndex(0);
                assertEquals(true, harness.call(editor.ui, "revealTestFailure", new Class<?>[]{bpsh.journey.JourneyCatalog.Entry.class, AuthenticationFailure.class}, entry, failure));
                assertEquals("Settings", tabs.getTitleAt(tabs.getSelectedIndex()));
                BurpBrowserSettingsPanel browser = harness.member(editor.ui, "browserSettingsPanel");
                assertTrue(((JTextArea) browser.focusTarget().getClientProperty("validationMessage")).isVisible());
                tabs.setSelectedIndex(0);
                harness.call(editor.ui, "revealRecordingProblem", new Class<?>[]{bpsh.journey.JourneyRecording.Problem.class},
                        new bpsh.journey.JourneyRecording.Problem(bpsh.journey.JourneyRecording.Field.valueOf("BROWSER_EXECUTABLE"), "Burp Browser is missing."));
                assertEquals("Settings", tabs.getTitleAt(tabs.getSelectedIndex()));
            });
        }
    }
}
