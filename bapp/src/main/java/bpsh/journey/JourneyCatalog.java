package bpsh.journey;

import java.util.*;

/** Read-only journey publication boundary used by authentication and request handling. */
public interface JourneyCatalog {
    /** @return One immutable publication; readers never observe a partial edit. */
    Snapshot snapshot();
    /**
     * Binds an immutable journey definition to its scoped configuration generation.
     *
     * @param identity Scope, internal UUID and generation used to reject stale work.
     * @param definition Validated definition without live tokens or secret values.
     */
    public record Entry(JourneyDefinition.Identity identity,JourneyDefinition definition,long authenticationSecretRevision) {
        public Entry(JourneyDefinition.Identity identity,JourneyDefinition definition) {this(identity,definition,0);}
        public boolean sameHttpAuthentication(Entry other) {
            return authenticationSecretRevision==other.authenticationSecretRevision && Objects.equals(definition.httpAuthentication(),other.definition.httpAuthentication())
                    && Objects.equals(definition.mtls(),other.definition.mtls()) && Objects.equals(definition.browser().proxy(),other.definition.browser().proxy())
                    && definition.browser().ignoreHttpsErrors()==other.definition.browser().ignoreHttpsErrors();
        }
    }
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
         * @throws bpsh.journey.ConfigurationException If alias syntax is invalid.
         * @throws IllegalStateException If the name is missing, ambiguous or unavailable.
         */
        public Entry resolve(String alias) {
            String name = JourneyNames.validateAlias(alias).toLowerCase(Locale.ROOT);
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

}
