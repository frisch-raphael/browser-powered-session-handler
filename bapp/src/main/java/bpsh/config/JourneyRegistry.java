package bpsh.config;

import bpsh.model.AuthStep;
import bpsh.model.JourneyDefinition;
import bpsh.model.JourneyKey;
import bpsh.secrets.SecretStore;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Publishes immutable, secret-free snapshots of the active project and user library.
 *
 * Mutations are synchronized on this registry; readers use the volatile snapshot without locking.
 * Aliases have no scope winner: loaded collisions remain visible but unusable until repaired.
 * Generations are retained across deletion/recreation so old work cannot become current again.
 * The caller owns the supplied SecretStore and closes it separately.
 */
public final class JourneyRegistry {
    /**
     * Binds an immutable journey definition to its scoped configuration generation.
     *
     * @param identity Scope, internal UUID and generation used to reject stale work.
     * @param definition Validated definition without live tokens or secret values.
     */
    public record Entry(JourneyDefinition.Identity identity, JourneyDefinition definition) {}
    /**
     * Captures one consistent registry publication for lock-free resolution.
     *
     * Alias lists preserve every loaded candidate instead of silently choosing one. Resolution also
     * honors unavailable scopes, including for explicit ID selection. Previously used aliases are reusable.
     *
     * @param entries Definitions indexed by scoped journey key.
     * @param aliases Canonical aliases mapped to all candidate keys.
     * @param unavailableScopes Containers retained for repair but unavailable for authentication.
     */
    public record Snapshot(Map<JourneyKey, Entry> entries, Map<String, List<JourneyKey>> aliases,
                           Set<JourneyDefinition.Scope> unavailableScopes) {
        /**
         * Defensively copies the entry map, alias candidate lists and status sets.
         */
        public Snapshot {
            entries = Map.copyOf(entries);
            Map<String, List<JourneyKey>> copy = new HashMap<>();
            aliases.forEach((alias, keys) -> copy.put(alias, List.copyOf(keys)));
            aliases = Map.copyOf(copy); unavailableScopes = Set.copyOf(unavailableScopes);
        }
        /**
         * Resolves an ASCII alias only when exactly one available current owner exists.
         *
         * @param alias User-facing alias; spelling is validated before case folding.
         * @return The unambiguous entry from this snapshot.
         * @throws bpsh.model.ConfigurationException If alias syntax is invalid.
         * @throws IllegalStateException If the name is missing, ambiguous or unavailable.
         */
        public Entry resolve(String alias) {
            String name = ConfigManager.alias(alias).toLowerCase(Locale.ROOT);
            List<JourneyKey> keys = aliases.getOrDefault(name, List.of());
            if (keys.isEmpty()) throw new IllegalStateException("Journey alias is missing; load its project/library or correct the tag.");
            if (keys.size() != 1) throw new IllegalStateException("Journey alias is ambiguous; rename the conflicting project/library journeys.");
            return resolve(keys.getFirst());
        }
        /**
         * Resolves an explicit journey selection while retaining alias-conflict protections.
         *
         * Selecting by UUID must not bypass a collision that blocks ordinary tag resolution.
         *
         * @param key Scoped internal journey key.
         * @return An available entry from this snapshot.
         * @throws IllegalStateException If the journey is missing or its scope/alias is unusable.
         */
        public Entry resolve(JourneyKey key) {
            Entry entry = entries.get(key);
            if (entry == null) throw new IllegalStateException("Selected journey was removed; select an existing journey.");
            if (unavailableScopes.contains(key.scope())) throw new IllegalStateException("Journey storage is unavailable; repair the library file and Reload.");
            String name = entry.definition().canonicalAlias();
            if (aliases.getOrDefault(name, List.of()).size() != 1)
                throw new IllegalStateException("Journey alias is conflicting; rename the duplicate before authenticating.");
            return entry;
        }
        /**
         * Checks whether work for a captured identity may still be used or published.
         *
         * @param identity Identity captured before authentication or request resolution began.
         * @return True only when the same generation is still resolvable; blocked/deleted entries return false.
         */
        public boolean isCurrent(JourneyDefinition.Identity identity) {
            try { return resolve(identity.key()).identity().equals(identity); }
            catch (IllegalStateException ex) { return false; }
        }
    }

    /**
     * Borrows session storage; registry shutdown does not transfer or end the caller's ownership.
     */
    private final SecretStore secrets;
    /**
     * Retains redacted managed envelopes for full-scope edit previews; guarded by the registry monitor.
     */
    private final Map<JourneyDefinition.Scope, ConfigManager.NativeDocument> documents = new EnumMap<>(JourneyDefinition.Scope.class);
    /**
     * Retains the highest generation even after deletion so reusing a UUID cannot revive stale work.
     */
    private final Map<JourneyKey, Long> generations = new HashMap<>();
    /**
     * Tracks containers blocked for repair while keeping their definitions visible to the editor.
     */
    private final Set<JourneyDefinition.Scope> unavailable = new HashSet<>();
    /**
     * Publishes one immutable view for lock-free readers; mutation paths replace the whole reference.
     */
    private volatile Snapshot snapshot = new Snapshot(Map.of(), Map.of(), Set.of());

    /**
     * Creates an empty registry using a caller-owned session secret store.
     *
     * @param secrets Store used for replacement, comparison and cleanup of journey-owned values.
     */
    public JourneyRegistry(SecretStore secrets) { this.secrets = Objects.requireNonNull(secrets); }
    /**
     * Reads the latest immutable publication without acquiring the mutation monitor.
     *
     * @return A stable view that will not be changed by later edits.
     */
    public Snapshot snapshot() { return snapshot; }
    /**
     * Builds a redacted managed-document view for editing one scope.
     *
     * The view preserves the current revision but owns no active secret buffers.
     * An unloaded scope receives an empty document with the appropriate default controls.
     *
     * @param scope Container whose definitions are requested.
     * @return A secret-free document; closing it cannot close the registry's session secrets.
     */
    public synchronized ConfigManager.NativeDocument document(JourneyDefinition.Scope scope) {
        return documents.getOrDefault(scope, ConfigManager.NativeDocument.empty(kind(scope))).redacted();
    }
    /**
     * Maps a managed scope to its required storage envelope type.
     *
     * @param scope Project or library ownership boundary.
     * @return The matching managed document kind; export is never a managed scope.
     */
    static ConfigManager.DocumentKind kind(JourneyDefinition.Scope scope) {
        return scope == JourneyDefinition.Scope.PROJECT ? ConfigManager.DocumentKind.PROJECT : ConfigManager.DocumentKind.LIBRARY;
    }

    /**
     * Replaces one scope with a validated load or successfully committed edit.
     *
     * Pass a document validated by the native parser or edit preview. Secret buffers are copied;
     * a missing secret entry clears the journey's effective values. Colliding aliases are retained
     * for repair, removed journeys lose their secrets, and effective changes advance generations.
     * This method does not write storage or consume the caller's document.
     *
     * @param scope Container being replaced; the other scope remains present.
     * @param document Validated document of the matching managed kind; the caller closes it.
     * @return Previous snapshot identities that are no longer usable and whose work should be invalidated.
     * @throws IllegalArgumentException If document kind does not match scope.
     * @throws IllegalStateException If the session secret store is closed.
     */
    public synchronized Set<JourneyDefinition.Identity> replaceLoaded(JourneyDefinition.Scope scope, ConfigManager.NativeDocument document) {
        if (document.kind() != kind(scope)) throw new IllegalArgumentException("Managed document has the wrong scope.");
        Set<UUID> incoming = new HashSet<>();
        Map<JourneyKey, Entry> entries = new HashMap<>(snapshot.entries());
        for (JourneyDefinition j : document.journeys()) {
            incoming.add(j.id()); JourneyKey key = new JourneyKey(scope, j.id());
            Entry previous = entries.get(key);
            SecretStore.Values supplied = document.secrets().get(j.id());
            boolean secretChanged;
            try (SecretStore.Values empty = SecretStore.Values.empty()) { secretChanged = secrets.put(key, supplied == null ? empty : supplied); }
            boolean changed = previous == null || !j.sameAuthenticationConfiguration(previous.definition()) || secretChanged || unavailable.contains(scope);
            long generation = changed ? generations.getOrDefault(key, 0L) + 1 : previous.identity().generation();
            generations.put(key, generation);
            entries.put(key, new Entry(new JourneyDefinition.Identity(scope, j.id(), generation), j));
        }
        for (JourneyKey key : List.copyOf(entries.keySet())) if (key.scope() == scope && !incoming.contains(key.journeyId())) {
            entries.remove(key); secrets.remove(key);
        }
        documents.put(scope, document.redacted()); unavailable.remove(scope);
        return publish(entries);
    }

    /**
     * Blocks authentication for an unavailable container while preserving definitions for repair.
     *
     * Session secrets in the scope are wiped. Publication also invalidates captured identities;
     * loading a repaired document later establishes usable generations again.
     *
     * @param scope Container whose read/validation failed.
     * @return Previous identities that callers must stop using.
     */
    public synchronized Set<JourneyDefinition.Identity> disableScope(JourneyDefinition.Scope scope) {
        unavailable.add(scope);
        for (JourneyKey key : snapshot.entries().keySet()) if (key.scope() == scope) secrets.remove(key);
        return publish(new HashMap<>(snapshot.entries()));
    }

    /**
     * Applies a session-secret edit and advances generation only for an effective change.
     *
     * Ownership is checked against the current secure-step/mTLS/proxy definition before replacement.
     * The caller retains its supplied snapshot and remains responsible for persisting remembered values.
     *
     * @param key Existing scoped journey receiving the edit.
     * @param values Open, caller-owned replacement values to copy.
     * @return Previous unusable identities, or an empty set when values were unchanged.
     * @throws IllegalStateException If the journey is missing or the store/snapshot is closed.
     * @throws bpsh.model.ConfigurationException If a supplied secret has no matching owner.
     */
    public synchronized Set<JourneyDefinition.Identity> secretChanged(JourneyKey key, SecretStore.Values values) {
        Entry previous = snapshot.entries().get(key);
        if (previous == null) throw new IllegalStateException("Journey was removed; reload before changing its secrets.");
        ConfigManager.validateSecretOwnership(previous.definition(), values);
        if (!secrets.put(key, values)) return Set.of();
        long next = generations.merge(key, 1L, Long::sum);
        Map<JourneyKey, Entry> entries = new HashMap<>(snapshot.entries());
        entries.put(key, new Entry(new JourneyDefinition.Identity(key.scope(), key.journeyId(), next), previous.definition()));
        return publish(entries);
    }

    /**
     * Builds and validates a complete scope edit without changing active state or disk.
     *
     * Only active aliases across the two scopes must be unique. Renamed/deleted names are immediately
     * reusable; legacy retirement records are ignored and dropped on save. Secret copies are filtered
     * to the edited definition so removed/retyped steps cannot leave dangling values.
     *
     * The caller retains its captured storage version, persists through the revision-checked writer,
     * and only then publishes the committed document. Close the returned preview when finished.
     *
     * @param scope Container whose full journey list is being edited.
     * @param journeys Complete intended list, including retained definitions.
     * @param controls Project controls, or null for the library.
     * @return Caller-owned preview containing filtered copies of session secrets.
     * @throws IllegalArgumentException If identities, active aliases or definitions are invalid.
     * @throws IllegalStateException If the destination scope is unavailable or the secret store is closed.
     */
    public synchronized ConfigManager.NativeDocument prepareEdit(JourneyDefinition.Scope scope,
            List<JourneyDefinition> journeys, Config.Controls controls) {
        if (unavailable.contains(scope)) throw new IllegalStateException("Storage is unavailable; repair it and Reload before editing.");
        ConfigManager.NativeDocument old = document(scope);
        Map<UUID, JourneyDefinition> incoming = new HashMap<>();
        for (JourneyDefinition j : journeys) if (incoming.put(j.id(), j) != null) throw new IllegalArgumentException("Duplicate journey identity.");
        Map<UUID, SecretStore.Values> values = new HashMap<>();
        try {
            for (JourneyDefinition j : journeys) {
                SecretStore.Values value = secrets.snapshot(new JourneyKey(scope, j.id()));
                // Removed or retyped steps must not leave secret references behind.
                Set<UUID> valid = new HashSet<>(); j.steps().stream().filter(s -> s.type() == AuthStep.Type.SECURE_INPUT).forEach(s -> valid.add(s.id()));
                SecretStore.Values filtered = value.retain(valid, j.mtls() != null);
                value.close(); values.put(j.id(), filtered);
            }
            ConfigManager.NativeDocument edited = new ConfigManager.NativeDocument(kind(scope), old.revision(), journeys,
                    List.of(), controls, values);
            ConfigManager.nativeToJson(edited); // Whole-preview validation, before any storage side effect.
            return edited;
        } catch (RuntimeException ex) { values.values().forEach(SecretStore.Values::close); throw ex; }
    }

    /**
     * Rebuilds alias/status indexes and atomically replaces the visible snapshot.
     *
     * The caller holds the registry monitor and supplies a mutable working entry map. Changes in
     * resolvability also advance retained generations, so blocking then repairing an alias cannot
     * resurrect an earlier result even when the underlying definition is unchanged.
     *
     * @param entries Working entries; availability transitions may replace their identities.
     * @return Previous snapshot identities that are not current in the new publication.
     */
    private Set<JourneyDefinition.Identity> publish(Map<JourneyKey, Entry> entries) {
        Map<String, List<JourneyKey>> aliases = new HashMap<>();
        entries.forEach((key, entry) -> aliases.computeIfAbsent(entry.definition().canonicalAlias(), ignored -> new ArrayList<>()).add(key));
        Snapshot next = new Snapshot(entries, aliases, unavailable);
        // Blocking then unblocking an alias must not resurrect results from before the conflict.
        for (JourneyKey key : List.copyOf(entries.keySet())) {
            Entry previous = snapshot.entries().get(key), current = entries.get(key);
            if (previous != null && previous.identity().equals(current.identity())
                    && snapshot.isCurrent(previous.identity()) != next.isCurrent(current.identity())) {
                long generation = generations.merge(key, 1L, Long::sum);
                entries.put(key, new Entry(new JourneyDefinition.Identity(key.scope(), key.journeyId(), generation), current.definition()));
            }
        }
        next = new Snapshot(entries, aliases, unavailable);
        Set<JourneyDefinition.Identity> invalidated = new HashSet<>();
        for (Entry e : snapshot.entries().values()) if (!next.isCurrent(e.identity())) invalidated.add(e.identity());
        snapshot = next;
        return Set.copyOf(invalidated);
    }
}
