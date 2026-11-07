package lab.auth;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/** Shared configuration inventory for the Gradle launchers and evidence collectors. */
final class LabBuildInputs {
    private LabBuildInputs() {}

    static List<String> configurationFiles(Path workspace) throws IOException {
        var input = ScenarioCatalog.parseJson(Files.readAllBytes(workspace.resolve(
                "test/authentication-lab/src/main/resources/configuration-inputs.json"))).getAsJsonObject();
        if (!input.keySet().equals(java.util.Set.of("configurationFiles"))) throw new IOException("Invalid configuration inventory.");
        var files = new ArrayList<String>();
        var unique = new HashSet<String>();
        Path root = workspace.toRealPath();
        for (var value : input.getAsJsonArray("configurationFiles")) {
            String name = value.getAsString();
            Path file = workspace.resolve(name).normalize();
            if (!unique.add(name) || !file.toRealPath().startsWith(root) || !Files.isRegularFile(file))
                throw new IOException("Missing, duplicate or foreign configuration input.");
            files.add(name);
        }
        if (files.isEmpty()) throw new IOException("Empty configuration inventory.");
        return List.copyOf(files);
    }
}
