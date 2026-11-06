import burp.api.montoya.persistence.Preferences;
import org.junit.jupiter.api.Test;
import javax.swing.SwingUtilities;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

/** Verifies independent picker folders across chooser and extension lifetimes without opening a modal. */
class RememberingFileChooserTest {
    @org.junit.jupiter.api.io.TempDir Path root;

    private static Preferences preferences(Map<String, String> values) {
        return (Preferences) Proxy.newProxyInstance(Preferences.class.getClassLoader(), new Class<?>[]{Preferences.class}, (proxy, method, args) -> {
            if (method.getName().equals("getString")) return values.get(args[0]);
            if (method.getName().equals("setString")) { values.put((String) args[0], (String) args[1]); return null; }
            return null;
        });
    }

    @Test void importAndExportShareApprovedAndCancelledNavigationAcrossNewInstances() throws Exception {
        var values = new HashMap<String, String>();
        var preferences = preferences(values);
        Path imported = Files.createDirectory(root.resolve("imports")), exported = Files.createDirectory(root.resolve("exports"));
        SwingUtilities.invokeAndWait(() -> {
            var first = new RememberingFileChooser(preferences, RememberingFileChooser.Purpose.JOURNEYS); var load = first.create(true);
            assertTrue(load.isMultiSelectionEnabled()); load.setSelectedFile(imported.resolve("journeys.json").toFile()); first.remember(load, true);
            var afterRestart = new RememberingFileChooser(preferences, RememberingFileChooser.Purpose.JOURNEYS); var save = afterRestart.create(false);
            assertFalse(save.isMultiSelectionEnabled()); assertEquals(imported, save.getCurrentDirectory().toPath());
            save.setCurrentDirectory(exported.toFile()); afterRestart.remember(save, false);
            var anotherLoad = new RememberingFileChooser(preferences, RememberingFileChooser.Purpose.JOURNEYS).create(true);
            assertEquals(exported, anotherLoad.getCurrentDirectory().toPath());
        });
        assertEquals(exported.toString(), values.get("bpsh_journey_file_directory"));
    }

    @Test void middlewareRemembersItsOwnApprovedAndCancelledFoldersAcrossRestarts() throws Exception {
        var values = new HashMap<String, String>();
        var preferences = preferences(values);
        Path journeyFolder = Files.createDirectory(root.resolve("journeys"));
        Path libraryFolder = Files.createDirectory(root.resolve("libraries"));
        Path browsedFolder = Files.createDirectory(root.resolve("browsed"));
        SwingUtilities.invokeAndWait(() -> {
            var journeys = new RememberingFileChooser(preferences, RememberingFileChooser.Purpose.JOURNEYS);
            var export = journeys.create(false); export.setSelectedFile(journeyFolder.resolve("journeys.json").toFile()); journeys.remember(export, true);

            var middleware = new RememberingFileChooser(preferences, RememberingFileChooser.Purpose.MIDDLEWARE);
            var library = middleware.create(false); assertFalse(library.isMultiSelectionEnabled());
            library.setSelectedFile(libraryFolder.resolve("pkcs11.dll").toFile()); middleware.remember(library, true);

            var afterRestart = new RememberingFileChooser(preferences, RememberingFileChooser.Purpose.MIDDLEWARE);
            var reopened = afterRestart.create(false); assertEquals(libraryFolder, reopened.getCurrentDirectory().toPath());
            reopened.setCurrentDirectory(browsedFolder.toFile()); afterRestart.remember(reopened, false);

            assertEquals(browsedFolder, new RememberingFileChooser(preferences, RememberingFileChooser.Purpose.MIDDLEWARE).create(false).getCurrentDirectory().toPath());
            assertEquals(journeyFolder, new RememberingFileChooser(preferences, RememberingFileChooser.Purpose.JOURNEYS).create(false).getCurrentDirectory().toPath());
        });
        assertEquals(browsedFolder.toString(), values.get("bpsh_middleware_file_directory"));
        assertEquals(journeyFolder.toString(), values.get("bpsh_journey_file_directory"));
    }

    @Test void preferenceFailuresKeepInSessionNavigationAvailable() throws Exception {
        var unavailable = (Preferences) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{Preferences.class}, (proxy, method, args) -> { throw new IllegalStateException("Unavailable test preference store"); });
        SwingUtilities.invokeAndWait(() -> {
            var dialogs = new RememberingFileChooser(unavailable, RememberingFileChooser.Purpose.JOURNEYS); var chooser = dialogs.create(true);
            chooser.setCurrentDirectory(root.toFile()); assertDoesNotThrow(() -> dialogs.remember(chooser, false));
            assertEquals(root, dialogs.create(false).getCurrentDirectory().toPath());
        });
    }
}
