package bpsh.ui;

import burp.api.montoya.persistence.Preferences;
import java.nio.file.Path;
import javax.swing.JFileChooser;

/** Remembers each file picker's navigation separately through Burp's user preferences. */
final class RememberingFileChooser {
    enum Purpose {
        JOURNEYS("bpsh_journey_file_directory"), MIDDLEWARE("bpsh_middleware_file_directory"), TRUSTED_CA("bpsh_trusted_ca_file_directory");

        private final String directoryKey;

        Purpose(String directoryKey) { this.directoryKey = directoryKey; }
    }

    private final Preferences preferences;
    private final String directoryKey;
    private Path directory;

    RememberingFileChooser(Preferences preferences, Purpose purpose) {
        this.preferences = preferences;
        this.directoryKey = purpose.directoryKey;
        if (preferences != null) try {
            String saved = preferences.getString(directoryKey);
            if (saved != null && !saved.isBlank()) directory = Path.of(saved).toAbsolutePath().normalize();
        } catch (RuntimeException ignored) { /* An unavailable preference must not block file selection. */ }
    }

    /** Creates a standard chooser; JFileChooser falls back to its default if the old folder is gone. */
    JFileChooser create(boolean multiple) {
        var chooser = directory == null ? new JFileChooser() : new JFileChooser(directory.toFile());
        chooser.setMultiSelectionEnabled(multiple);
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        return chooser;
    }

    /** Remembers navigation even after cancellation; an approved full path takes precedence. */
    void remember(JFileChooser chooser, boolean approved) {
        var selected = approved ? chooser.getSelectedFile() : null;
        var folder = selected == null ? chooser.getCurrentDirectory() : selected.getAbsoluteFile().getParentFile();
        if (folder == null) return;
        directory = folder.toPath().toAbsolutePath().normalize();
        if (preferences != null) try { preferences.setString(directoryKey, directory.toString()); }
        catch (RuntimeException ignored) { /* Keep the in-session location if the host cannot persist it. */ }
    }
}
