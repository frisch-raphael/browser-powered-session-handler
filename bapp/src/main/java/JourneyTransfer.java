import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Transfers native journeys without treating managed or legacy files as imports.
 *
 * Import creates an uncommitted preview with new identities. Export uses a separate explicit
 * secret-inclusion choice. Neither operation writes storage or changes the active registry.
 */
public final class JourneyTransfer {
    /** Identifies one reviewed journey by file position and source UUID, with its chosen destination alias. */
    public record ImportSelection(int source, UUID journeyId, String alias) {}
    /**
     * Prevents instantiation of the stateless native transfer utility.
     */
    private JourneyTransfer() {}

    /**
     * Builds a destination preview with fresh journey/step UUIDs and remapped secrets.
     *
     * Only export envelopes are accepted. Existing destination definitions are retained; imported
     * Remember secrets flags are cleared. Collisions require explicit alias edits, with no overwrite
     * or automatic scope winner. Validation failure leaves files, registry and SecretStore unchanged.
     *
     * The caller closes the preview and retains the storage version captured for the edit. Persist
     * through the destination's revision-checked writer before publishing; imported values remain
     * session-only unless the user subsequently enables Remember secrets.
     *
     * @param json Native export JSON; never a managed project/library storage file.
     * @param destination Explicit scope receiving the imported journeys.
     * @param registry Current definitions used to validate the whole destination preview.
     * @param aliasEdits Explicit replacement aliases keyed by source canonical alias.
     * @return Caller-owned managed preview containing independent session-secret copies.
     * @throws ConfigManager.NativeFormatException If the export or replacement alias is invalid.
     * @throws IllegalArgumentException If aliases collide or the complete preview is invalid.
     * @throws IllegalStateException If destination storage is unavailable.
     */
    public static ConfigManager.NativeDocument previewImport(String json, JourneyDefinition.Scope destination,
            JourneyRegistry registry, Map<String, String> aliasEdits) {
        try (ConfigManager.NativeDocument source = ConfigManager.parseNative(json, ConfigManager.DocumentKind.EXPORT)) {
            var selection = source.journeys().stream().map(j -> new ImportSelection(0, j.id(), aliasEdits.getOrDefault(j.canonicalAlias(), j.alias()))).toList();
            return previewImport(List.of(json), destination, registry, selection);
        }
    }

    /** Validates all selected files and imports the reviewed subset as one uncommitted, atomic scope edit. */
    public static ConfigManager.NativeDocument previewImport(List<String> exports, JourneyDefinition.Scope destination,
            JourneyRegistry registry, List<ImportSelection> selection) {
        if (selection.isEmpty()) throw new IllegalArgumentException("Select at least one journey to import.");
        var sources = new ArrayList<ConfigManager.NativeDocument>();
        try {
            for (String json : exports) sources.add(ConfigManager.parseNative(json, ConfigManager.DocumentKind.EXPORT));
            List<JourneyDefinition> journeys = new ArrayList<>(registry.document(destination).journeys());
            var occupied = new java.util.HashSet<String>();
            registry.snapshot().entries().values().forEach(e -> occupied.add(e.definition().canonicalAlias()));
            Map<UUID, SecretStore.Values> imported = new HashMap<>();
            try {
                var selected = new java.util.HashSet<String>();
                for (var item : selection) {
                    if (item.source() < 0 || item.source() >= sources.size()) throw new IllegalArgumentException("The selected import file is unavailable. Choose the files again.");
                    var source = sources.get(item.source());
                    var j = source.journeys().stream().filter(candidate -> candidate.id().equals(item.journeyId())).findFirst()
                            .orElseThrow(() -> new IllegalArgumentException("The selected journey is missing from its import file. Choose the files again."));
                    if (!selected.add(item.source() + ":" + item.journeyId())) throw new IllegalArgumentException("Select each imported journey only once.");
                    Map<UUID, UUID> stepIds = new HashMap<>();
                    List<AuthStep.Definition> steps = j.steps().stream().map(s -> {
                        UUID id = UUID.randomUUID(); stepIds.put(s.id(), id); return s.withId(id);
                    }).toList();
                    UUID id = UUID.randomUUID(); String alias = item.alias();
                    if (!occupied.add(ConfigManager.alias(alias).toLowerCase(java.util.Locale.ROOT)))
                        throw new IllegalArgumentException("Alias is already used by an active journey; choose a unique alias.");
                    JourneyDefinition copy = j.withIdentity(id, steps, false);
                    copy = new JourneyDefinition(id, copy.displayName(), ConfigManager.alias(alias), copy.authenticationUrl(), false,
                            steps, copy.browser(), copy.extraction(), copy.injection(), copy.cache(), copy.mtls(),
                            copy.draft() == null ? null : copy.draft().remap(steps, alias, false));
                    journeys.add(copy);
                    SecretStore.Values values = source.secrets().get(j.id());
                    if (values != null) imported.put(id, values.remapSteps(stepIds));
                }
                ConfigManager.NativeDocument old = registry.document(destination);
                try (ConfigManager.NativeDocument preview = registry.prepareEdit(destination, journeys, old.controls())) {
                    Map<UUID, SecretStore.Values> values = new HashMap<>();
                    preview.secrets().forEach((id, secret) -> values.put(id, secret.copy()));
                    imported.forEach((id, secret) -> { SecretStore.Values previous = values.put(id, secret.copy()); if (previous != null) previous.close(); });
                    return new ConfigManager.NativeDocument(preview.kind(), UUID.randomUUID(), preview.journeys(), preview.retiredAliases(), preview.controls(), values);
                }
            } finally { imported.values().forEach(SecretStore.Values::close); }
        } finally { sources.forEach(ConfigManager.NativeDocument::close); }
    }

    /**
     * Serializes selected definitions with a fresh export revision and optional complete secrets.
     *
     * The caller captures entries and their secret state consistently with registry edits. Output
     * clears Remember secrets and retirement records. Temporary secret snapshots are always closed;
     * an explicit secret export fails with guidance instead of silently omitting required values.
     *
     * @param selected Validated entries chosen for export.
     * @param secrets Session store holding values for the selected entries.
     * @param includeSecrets Explicit Include secrets choice, independent of each remembering flag.
     * @return Native export JSON; readable secret strings appear only when explicitly included.
     * @throws ConfigManager.NativeFormatException If output is invalid or an included required value is missing.
     * @throws IllegalStateException If the secret store is closed while values are captured.
     */
    public static String exportJourneys(List<JourneyRegistry.Entry> selected, SecretStore secrets, boolean includeSecrets) {
        List<JourneyDefinition> journeys = selected.stream().map(JourneyRegistry.Entry::definition).toList();
        Map<UUID, SecretStore.Values> values = new HashMap<>();
        try {
            if (includeSecrets) for (JourneyRegistry.Entry entry : selected) {
                SecretStore.Values value = secrets.snapshot(entry.identity().key());
                try { ConfigManager.requireCompleteSecrets(entry.definition(), value); }
                catch (RuntimeException ex) { value.close(); throw ex; }
                SecretStore.Values previous = values.put(entry.definition().id(), value);
                if (previous != null) previous.close();
            }
            try (ConfigManager.NativeDocument export = new ConfigManager.NativeDocument(ConfigManager.DocumentKind.EXPORT,
                    UUID.randomUUID(), journeys, List.of(), null, values)) {
                return ConfigManager.nativeToJson(export, includeSecrets);
            }
        } finally { values.values().forEach(SecretStore.Values::close); }
    }
}
