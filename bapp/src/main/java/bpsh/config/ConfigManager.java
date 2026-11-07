package bpsh.config;

import bpsh.credentials.JsonPathSelector;
import bpsh.model.ConfigurationException;
import bpsh.model.JourneyDefinition;
import bpsh.secrets.SecretStore;
import burp.api.montoya.persistence.PersistedObject;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Validates and persists only the native project/journey formats, leaving previous stored data untouched.
 * File, JSON and persistence operations belong off Swing's EDT; secret-bearing documents must be closed.
 */
public final class ConfigManager {
    private final PersistedObject storage;

    /**
     * Binds the native project store without reading or converting any other persistence keys.
     * @param storage Burp extension data; its lifetime is temporary without a saved project file.
     */
    public ConfigManager(PersistedObject storage) { this.storage = Objects.requireNonNull(storage); }

    /**
     * Stores native project envelopes separately from untouched legacy configuration.
     */
    public static final String NATIVE_PROJECT_KEY = "bpsh_project_v3";
    /**
     * Rejects duplicate keys and trailing JSON values before native field-level validation.
     */


    /**
     * Discriminates project storage, user-library storage and native transfer envelopes.
     */
    public enum DocumentKind {
        PROJECT, LIBRARY, EXPORT;
        /**
         * Returns the exact lowercase discriminator used in native JSON.
         *
         * @return project, library or export; independent of the host locale.
         */
        public String wire() { return name().toLowerCase(Locale.ROOT); }
    }

    /**
     * Reads retirement metadata from older native files for compatibility; it no longer reserves a name.
     *
     * @param alias Original validated spelling; comparisons use its canonical ASCII form.
     * @param formerJourneyId Internal UUID of the former owner.
     * @param retiredAt UTC retirement instant used for managed-storage history.
     */
    public record RetiredAlias(String alias, UUID formerJourneyId, Instant retiredAt) {
        /**
         * Produces the comparison key for a previously validated retirement record.
         *
         * @return Locale-independent lowercase alias; this method does not validate new input.
         */
        public String canonicalAlias() { return alias.toLowerCase(Locale.ROOT); }
    }
    /**
     * Owns a native envelope and any secret snapshots attached to its definitions.
     *
     * Collections are defensively copied, but Values instances are adopted rather than deep-cloned.
     * Close after transferring copies into the session store. The redacted view shares immutable
     * definitions only; withRevision creates independent secret copies. Full schema validation is
     * performed by the codec, not by this record constructor.
     *
     * @param kind Container discriminator; exports have no project controls.
     * @param revision Envelope UUID used for persistence conflicts, not a token generation.
     * @param journeys Immutable definitions without embedded runtime state.
     * @param retiredAliases Legacy metadata accepted on read; all new writes serialize an empty array.
     * @param controls Project-wide controls, or null for library/export documents.
     * @param secrets Owned values indexed by journey UUID; may include session-only values before writing.
     */
    public record NativeDocument(DocumentKind kind, UUID revision, List<JourneyDefinition> journeys,
                                 List<RetiredAlias> retiredAliases, Config.Controls controls,
                                 Map<UUID, SecretStore.Values> secrets) implements AutoCloseable {
        /**
         * Copies envelope collections and requires kind/revision without consuming supplied Values.
         */
        public NativeDocument {
            Objects.requireNonNull(kind); Objects.requireNonNull(revision);
            journeys = List.copyOf(journeys); retiredAliases = List.copyOf(retiredAliases);
            secrets = Map.copyOf(secrets);
        }
        /**
         * Creates an empty envelope with a fresh revision and scope-appropriate defaults.
         *
         * @param kind Requested container type.
         * @return Secret-free document; only project documents receive default controls.
         */
        public static NativeDocument empty(DocumentKind kind) {
            return new NativeDocument(kind, UUID.randomUUID(), List.of(), List.of(),
                    kind == DocumentKind.PROJECT ? Config.Controls.defaults() : null, Map.of());
        }
        /**
         * Drops all secret values while retaining definitions, revision and retirement history.
         *
         * @return A view with an empty secret map; closing it cannot close this document's values.
         */
        public NativeDocument redacted() {
            return new NativeDocument(kind, revision, journeys, retiredAliases, controls, Map.of());
        }
        /**
         * Copies the envelope under a replacement revision, cloning every owned secret snapshot.
         *
         * @param value Revision for the new envelope.
         * @return Independently owned document that its caller must close.
         * @throws IllegalStateException If any source secret snapshot is already closed.
         */
        public NativeDocument withRevision(UUID value) {
            Map<UUID, SecretStore.Values> copies = new HashMap<>();
            secrets.forEach((id, secret) -> copies.put(id, secret.copy()));
            return new NativeDocument(kind, value, journeys, retiredAliases, controls, copies);
        }
        /**
         * Wipes every adopted secret snapshot; definitions and redacted views remain usable.
         */
        @Override public void close() { secrets.values().forEach(SecretStore.Values::close); }
        /**
         * Returns only envelope kind and revision for diagnostics.
         *
         * @return Metadata with no definitions or secret values.
         */
        @Override public String toString() { return "NativeDocument[kind=" + kind + ", revision=" + revision + "]"; }
    }

    /**
     * Loads only the native project key, preserving malformed data for explicit repair.
     *
     * No legacy key is consulted and no default is silently substituted for invalid native JSON.
     *
     * @return Empty if the native key is absent; otherwise a caller-owned document to close.
     * @throws bpsh.model.ConfigurationException If stored native data is malformed or has the wrong kind.
     */
    public Optional<NativeDocument> loadNativeProject() {
        String json = storage.getString(NATIVE_PROJECT_KEY);
        return json == null ? Optional.empty() : Optional.of(parseNative(json, DocumentKind.PROJECT));
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
     * @throws bpsh.model.ConfigurationException If kind, revision or native data is invalid/stale.
     */
    public synchronized NativeDocument saveNativeProject(NativeDocument edited, UUID expectedRevision) {
        if (edited.kind() != DocumentKind.PROJECT) throw invalid("kind", "must be project");
        Optional<NativeDocument> current = loadNativeProject();
        try {
            UUID disk = current.map(NativeDocument::revision).orElse(null);
            if (!Objects.equals(disk, expectedRevision))
                throw invalid("revision", "project changed; reload and reapply the edit");
            NativeDocument next = edited.withRevision(UUID.randomUUID());
            try { storage.setString(NATIVE_PROJECT_KEY, nativeToJson(next)); return next; }
            catch (RuntimeException ex) { next.close(); throw ex; }
        } finally { current.ifPresent(NativeDocument::close); }
    }

    public static NativeDocument parseNative(String json, DocumentKind expected) { return NativeDocumentCodec.parseNative(json, expected); }
    public static String nativeToJson(NativeDocument document) { return NativeDocumentCodec.nativeToJson(document); }
    public static String nativeToJson(NativeDocument document, boolean includeExportSecrets) { return NativeDocumentCodec.nativeToJson(document, includeExportSecrets); }
    public static String alias(String value) { return NativeJson.alias(value); }
    public static void validateJsonPath(String path) { JsonPathSelector.validate(path); }
    public static java.net.URI certificateLoginOrigin(java.net.URI url) { return NativeJourneyCodec.certificateLoginOrigin(url); }
    public static void validateSecretOwnership(JourneyDefinition journey, SecretStore.Values values) { NativeJourneyCodec.validateSecretOwnership(journey, values); }
    public static void requireCompleteSecrets(JourneyDefinition journey, SecretStore.Values values) { NativeJourneyCodec.requireCompleteSecrets(journey, values); }
    public static ObjectNode extractionNode(JourneyDefinition.Extraction extraction) { return NativeJourneyCodec.extractionNode(extraction); }
    public static ObjectNode injectionNode(JourneyDefinition.Injection injection) { return NativeJourneyCodec.injectionNode(injection); }
    private static ConfigurationException invalid(String path, String reason) { return new ConfigurationException(path + ": " + reason + "."); }
}
