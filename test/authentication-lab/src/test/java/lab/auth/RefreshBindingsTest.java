package lab.auth;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class RefreshBindingsTest {
    @TempDir Path workspace;

    @Test void refreshChangesFingerprintsAndPreservesRequiredNullsAndUnboundRows() throws Exception {
        Path resources = workspace.resolve("test/authentication-lab/src/main/resources");
        Path catalog = resources.resolve("catalog");
        Files.createDirectories(catalog);
        Files.writeString(resources.resolve("configuration-inputs.json"), "{\"configurationFiles\":[\"build.gradle\"]}");
        Files.writeString(workspace.resolve("build.gradle"), "// controlled configuration fixture\n");
        Files.writeString(workspace.resolve("Fixture.java"), "class Fixture {}\n");
        Files.writeString(catalog.resolve("catalog.json"), "{\"dataFiles\":[\"fixtures.json\"]}");
        Path file = catalog.resolve("fixtures.json");
        Files.writeString(file, """
                {"requirements":[
                  {"id":"fixture","recipe":null,"binding":{"parameterKey":null,"taskPath":":auth-lab:test",
                    "configurationHash":"old","sourceHashes":{"Fixture.java":"old"}}},
                  {"id":"manual","binding":null}
                ]}
                """);
        assertEquals(1, RefreshBindings.refresh(workspace));
        var rows = ScenarioCatalog.parseJson(Files.readAllBytes(file)).getAsJsonObject().getAsJsonArray("requirements");
        var first = rows.get(0).getAsJsonObject();
        assertTrue(first.has("recipe") && first.get("recipe").isJsonNull());
        assertTrue(first.getAsJsonObject("binding").has("parameterKey"));
        assertTrue(first.getAsJsonObject("binding").get("parameterKey").isJsonNull());
        assertEquals(LabEvidence.sha256(Files.readAllBytes(workspace.resolve("Fixture.java"))),
                first.getAsJsonObject("binding").getAsJsonObject("sourceHashes").get("Fixture.java").getAsString());
        assertEquals(LabEvidence.configurationFingerprint(workspace), first.getAsJsonObject("binding").get("configurationHash").getAsString());
        assertTrue(rows.get(1).getAsJsonObject().has("binding") && rows.get(1).getAsJsonObject().get("binding").isJsonNull());
        String after = Files.readString(file);
        assertEquals(1, RefreshBindings.refresh(workspace));
        assertEquals(after, Files.readString(file));
    }
}
