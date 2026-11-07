package lab.auth;

import com.google.gson.GsonBuilder;
import java.nio.file.Files;
import java.nio.file.Path;

/** Explicit maintenance of reviewed source/configuration fingerprints; never grants test acceptance. */
public final class RefreshBindings {
    private RefreshBindings() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("Supply the repository root.");
        Path workspace = Path.of(args[0]).toRealPath();
        int count = refresh(workspace);
        System.out.println("Refreshed " + count + " reviewed bindings. Review the diff and run the owning profiles; no acceptance is claimed.");
    }

    static int refresh(Path workspace) throws Exception {
        workspace = workspace.toRealPath();
        Path catalog = workspace.resolve("test/authentication-lab/src/main/resources/catalog");
        var index = ScenarioCatalog.parseJson(Files.readAllBytes(catalog.resolve("catalog.json"))).getAsJsonObject();
        var json = new GsonBuilder().setPrettyPrinting().serializeNulls().disableHtmlEscaping().create();
        var sourceHashes = new java.util.HashMap<String, String>();
        var configurations = new java.util.HashMap<String, String>();
        var updated = new java.util.LinkedHashMap<Path, String>();
        int count = 0;
        for (var name : index.getAsJsonArray("dataFiles")) {
            Path file = catalog.resolve(name.getAsString()).normalize();
            if (!file.toRealPath().startsWith(catalog.toRealPath())) throw new IllegalArgumentException("Foreign catalog input.");
            var document = ScenarioCatalog.parseJson(Files.readAllBytes(file)).getAsJsonObject();
            for (var element : document.getAsJsonArray("requirements")) {
                var row = element.getAsJsonObject();
                if (!row.has("binding") || row.get("binding").isJsonNull()) continue;
                var binding = row.getAsJsonObject("binding");
                var hashes = binding.getAsJsonObject("sourceHashes");
                for (var source : hashes.entrySet()) {
                    Path input = workspace.resolve(source.getKey()).normalize();
                    if (!input.toRealPath().startsWith(workspace) || !Files.isRegularFile(input))
                        throw new IllegalArgumentException("Missing or foreign reviewed source.");
                    String hash = sourceHashes.get(source.getKey());
                    if (hash == null) { hash = LabEvidence.sha256(Files.readAllBytes(input)); sourceHashes.put(source.getKey(), hash); }
                    source.setValue(new com.google.gson.JsonPrimitive(hash));
                }
                String task = binding.get("taskPath").getAsString();
                String configuration = configurations.get(task);
                if (configuration == null) { configuration = task.equals(":auth-lab:test")
                        ? LabEvidence.configurationFingerprint(workspace)
                        : LabProductionEvidence.configurationFingerprint(workspace, task); configurations.put(task, configuration); }
                binding.addProperty("configurationHash", configuration);
                count++;
            }
            updated.put(file, json.toJson(document) + "\n");
        }
        for (var entry : updated.entrySet()) Files.writeString(entry.getKey(), entry.getValue());
        return count;
    }
}
