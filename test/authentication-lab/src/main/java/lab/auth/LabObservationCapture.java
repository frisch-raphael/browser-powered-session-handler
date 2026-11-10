package lab.auth;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.LinkedHashMap;
import java.util.Map;

/** Writes safe observations only inside the existing isolated invocation's report directory. */
public final class LabObservationCapture {
    private LabObservationCapture() { }

    public static void write(String id, Map<String, ?> observed, Map<String, Long> timings) throws Exception {
        String input = System.getProperty("authlab.plan");
        if (input == null) return;
        var plan = ScenarioCatalog.parseJson(Files.readAllBytes(Path.of(input))).getAsJsonObject();
        Path directory = Path.of(plan.get("reportDirectory").getAsString()).resolve("component-observations");
        Files.createDirectories(directory);
        var capture = new LinkedHashMap<String, Object>();
        capture.put("version", timings == null ? 1 : 2);
        capture.put("invocationId", plan.get("invocationId").getAsString());
        capture.put("requirementId", id);
        capture.put("taskPath", ":" + plan.get("taskName").getAsString());
        capture.put("productionRevision", plan.get("productionRevision").getAsString());
        capture.put("observed", observed);
        capture.put("cleanup", "COMPLETE");
        if (timings != null) {
            capture.put("configurationHash", plan.get("configurationHash").getAsString());
            capture.put("timings", timings);
        }
        String name = LabEvidence.sha256(id.getBytes(StandardCharsets.UTF_8));
        Files.writeString(directory.resolve(name + ".json"), LabRun.JSON.toJson(capture), StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
    }
}
