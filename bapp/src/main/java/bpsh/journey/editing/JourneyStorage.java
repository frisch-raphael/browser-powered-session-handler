package bpsh.journey.editing;

import bpsh.journey.JourneyDefinition;
import bpsh.journey.SecretStore;
import bpsh.journey.persistence.JourneyDocument;
import bpsh.journey.persistence.ProjectStore;
import bpsh.journey.persistence.UserLibraryStore;
import java.io.IOException;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * Owns storage revisions and external-load epochs independently of the Swing editor.
 * Mutations run on the caller's serialized storage worker. UI readers borrow immutable epoch views.
 */
public final class JourneyStorage implements AutoCloseable {
    private final ProjectStore projects;
    private final UserLibraryStore library;
    private UUID projectRevision;
    private UserLibraryStore.Version libraryVersion = UserLibraryStore.Version.absent();
    private final EnumMap<JourneyDefinition.Scope, Long> epochs = new EnumMap<>(JourneyDefinition.Scope.class);
    private volatile Map<JourneyDefinition.Scope, Long> visibleEpochs;

    /** Binds stores without reading them or starting watchers. */
    public JourneyStorage(ProjectStore projects, UserLibraryStore library) {
        this.projects = projects; this.library = library;
        for (var scope : JourneyDefinition.Scope.values()) epochs.put(scope, 0L);
        visibleEpochs = Map.copyOf(epochs);
    }

    /** @return A caller-owned project load; missing storage keeps a null expected revision. */
    public JourneyDocument loadProject() {
        var loaded = projects.loadNativeProject();
        projectRevision = loaded.map(JourneyDocument::revision).orElse(null);
        return loaded.orElseGet(() -> JourneyDocument.empty(JourneyDocument.DocumentKind.PROJECT));
    }

    /** @return Caller-owned library load and its captured exact-byte version. */
    public UserLibraryStore.Loaded loadLibrary() throws IOException {
        var loaded = library.load(); libraryVersion = loaded.version(); return loaded;
    }

    /** @return Whether a watcher event echoes the last loaded/committed version. */
    public boolean isCurrent(UserLibraryStore.Loaded loaded) { return Objects.equals(loaded.version(), libraryVersion); }
    /** Checks actual storage on its serialized I/O worker before an unsaved recording changes the editor. */
    public void checkRecordingRevision(JourneyDefinition.Scope scope, UUID revision, long epoch) throws IOException {
        checkEpoch(scope, epoch);
        if (scope == JourneyDefinition.Scope.PROJECT) {
            var loaded = projects.loadNativeProject();
            if (loaded.isEmpty()) { if (projectRevision != null) throw new IllegalStateException("The journey storage changed."); return; }
            try (var stored = loaded.orElseThrow()) {
                if (!Objects.equals(stored.revision(), revision) || !Objects.equals(projectRevision, revision)) throw new IllegalStateException("The journey storage changed.");
            }
        } else {
            try (var loaded = library.load()) {
                if (!isCurrent(loaded) || !loaded.version().equals(UserLibraryStore.Version.absent()) && !Objects.equals(loaded.document().revision(), revision)) throw new IllegalStateException("The journey storage changed.");
            }
        }
    }

    /** Captures an external library revision before the caller publishes its definitions. */
    public void accept(UserLibraryStore.Loaded loaded) { libraryVersion = loaded.version(); }

    /**
     * Persists using the captured revision before returning a caller-owned publication.
     * Does not publish active definitions or start authentication.
     */
    public JourneyDocument save(JourneyDefinition.Scope scope, JourneyDocument edited) throws IOException {
        if (scope == JourneyDefinition.Scope.PROJECT) {
            var saved = projects.saveNativeProject(edited, projectRevision); projectRevision = saved.revision(); return saved;
        }
        // Loaded owns its document; ownership is deliberately transferred to this method's caller.
        var saved = library.save(edited, libraryVersion); libraryVersion = saved.version(); return saved.document();
    }

    /** Advances the external-load epoch after a reload, watcher update or scope failure. */
    public void changed(JourneyDefinition.Scope scope) { epochs.put(scope, epochs.get(scope) + 1); visibleEpochs = Map.copyOf(epochs); }

    /** @return Current immutable external-load epoch for capture on any thread. */
    public long epoch(JourneyDefinition.Scope scope) { return visibleEpochs.getOrDefault(scope, -1L); }

    /** Rejects a stale editor before its first persistence mutation. */
    public void checkEpoch(JourneyDefinition.Scope scope, long expected) {
        if (epoch(scope) != expected) throw new IllegalStateException("Storage changed after this draft opened. Reload the journey and reapply the edit.");
    }

    /** Starts the existing library observer; callbacks own their supplied loaded document. */
    public void watch(Consumer<UserLibraryStore.Loaded> changed, Consumer<IOException> failed) throws IOException { library.watch(changed, failed); }

    /**
     * Merges a captured final edit without touching a live catalog, UI or authentication service.
     * The supplied values remain caller-owned; all copied document values are wiped after writing.
     */
    public void saveFinal(JourneyDefinition.Scope scope, long epoch, JourneyDefinition changed, SecretStore.Values values) throws IOException {
        checkEpoch(scope, epoch);
        try (var loaded = scope == JourneyDefinition.Scope.LIBRARY ? library.load() : null;
             var current = scope == JourneyDefinition.Scope.PROJECT
                     ? projects.loadNativeProject().orElseGet(() -> JourneyDocument.empty(JourneyDocument.DocumentKind.PROJECT))
                     : loaded.document().withRevision(loaded.document().revision())) {
            if (scope == JourneyDefinition.Scope.LIBRARY && !Objects.equals(loaded.version(), libraryVersion))
                throw new IllegalStateException("Storage changed before the final save.");
            var journeys = new ArrayList<>(current.journeys()); journeys.removeIf(j -> j.id().equals(changed.id())); journeys.add(changed);
            var all = new LinkedHashMap<UUID, SecretStore.Values>();
            current.secrets().forEach((id, secret) -> { if (!id.equals(changed.id())) all.put(id, secret.copy()); });
            all.put(changed.id(), values.copy());
            try (var edited = new JourneyDocument(current.kind(), current.revision(), journeys, current.retiredAliases(), current.controls(), all);
                 var saved = save(scope, edited)) { /* Persistence owns no runtime publication during unload. */ }
        }
    }

    /** Stops observation after the serialized final save. */
    @Override public void close() { library.close(); }
}
