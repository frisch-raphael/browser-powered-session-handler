package bpsh.journey.persistence;

import bpsh.journey.ConfigurationException;
import burp.api.montoya.persistence.PersistedObject;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Validates and persists only the native project/journey formats, leaving previous stored data untouched.
 * File, JSON and persistence operations belong off Swing's EDT; secret-bearing documents must be closed.
 */
public final class ProjectStore {
    private final PersistedObject storage;

    /**
     * Binds the native project store without reading or converting any other persistence keys.
     * @param storage Burp extension data; its lifetime is temporary without a saved project file.
     */
    public ProjectStore(PersistedObject storage) { this.storage = Objects.requireNonNull(storage); }

    /**
     * Stores native project envelopes separately from untouched legacy configuration.
     */
    public static final String NATIVE_PROJECT_KEY = "bpsh_project_v3";
    /**
     * Loads only the native project key, preserving malformed data for explicit repair.
     *
     * No legacy key is consulted and no default is silently substituted for invalid native JSON.
     *
     * @return Empty if the native key is absent; otherwise a caller-owned document to close.
     * @throws bpsh.journey.ConfigurationException If stored native data is malformed or has the wrong kind.
     */
    public Optional<JourneyDocument> loadNativeProject() {
        String json = storage.getString(NATIVE_PROJECT_KEY);
        return json == null ? Optional.empty() : Optional.of(JourneyJson.read(json, JourneyDocument.DocumentKind.PROJECT));
    }

    /**
     * Commits a native project edit only when its captured revision still matches.
     *
     * Saves are serialized within this manager. Capture expectedRevision when editing begins; a stale
     * editor must reload instead of overwriting a later save. The legacy key remains untouched.
     * Remembered values follow native writer policy; the returned document retains session values.
     *
     * @param edited Validated project document; caller retains ownership.
     * @param expectedRevision Previously loaded revision, or null only when the native key was absent.
     * @return Independently owned committed document with a fresh revision; caller closes it.
     * @throws bpsh.journey.ConfigurationException If kind, revision or native data is invalid/stale.
     */
    public synchronized JourneyDocument saveNativeProject(JourneyDocument edited, UUID expectedRevision) {
        if (edited.kind() != JourneyDocument.DocumentKind.PROJECT) throw invalid("kind", "must be project");
        Optional<JourneyDocument> current = loadNativeProject();
        try {
            UUID disk = current.map(JourneyDocument::revision).orElse(null);
            if (!Objects.equals(disk, expectedRevision))
                throw invalid("revision", "project changed; reload and reapply the edit");
            JourneyDocument next = edited.withRevision(UUID.randomUUID());
            try { storage.setString(NATIVE_PROJECT_KEY, JourneyJson.write(next)); return next; }
            catch (RuntimeException ex) { next.close(); throw ex; }
        } finally { current.ifPresent(JourneyDocument::close); }
    }

    private static ConfigurationException invalid(String path, String reason) { return new ConfigurationException(path + ": " + reason + "."); }
}
