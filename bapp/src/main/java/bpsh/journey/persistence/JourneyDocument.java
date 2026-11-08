package bpsh.journey.persistence;

import bpsh.request.RequestSettings;

import bpsh.journey.JourneyDefinition;
import bpsh.journey.SecretStore;
import java.util.*;
import java.time.Instant;

/** Owned journey storage/transfer envelope, independent of the project persistence implementation. */
public record JourneyDocument(DocumentKind kind, UUID revision, List<JourneyDefinition> journeys,
                             List<RetiredAlias> retiredAliases, RequestSettings.Controls controls,
                             Map<UUID, SecretStore.Values> secrets) implements AutoCloseable {
    /**
     * Copies envelope collections and requires kind/revision without consuming supplied Values.
     */
    public JourneyDocument {
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
    public static JourneyDocument empty(DocumentKind kind) {
        return new JourneyDocument(kind, UUID.randomUUID(), List.of(), List.of(),
                kind == DocumentKind.PROJECT ? RequestSettings.Controls.defaults() : null, Map.of());
    }
    /**
     * Drops all secret values while retaining definitions, revision and retirement history.
     *
     * @return A view with an empty secret map; closing it cannot close this document's values.
     */
    public JourneyDocument redacted() {
        return new JourneyDocument(kind, revision, journeys, retiredAliases, controls, Map.of());
    }
    /**
     * Copies the envelope under a replacement revision, cloning every owned secret snapshot.
     *
     * @param value Revision for the new envelope.
     * @return Independently owned document that its caller must close.
     * @throws IllegalStateException If any source secret snapshot is already closed.
     */
    public JourneyDocument withRevision(UUID value) {
        Map<UUID, SecretStore.Values> copies = new HashMap<>();
        secrets.forEach((id, secret) -> copies.put(id, secret.copy()));
        return new JourneyDocument(kind, value, journeys, retiredAliases, controls, copies);
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
    @Override public String toString() { return "JourneyDocument[kind=" + kind + ", revision=" + revision + "]"; }
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
}
