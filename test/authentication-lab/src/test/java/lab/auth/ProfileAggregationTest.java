package lab.auth;

import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.io.IOException;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** Synthetic report inputs qualify the report join only, never product authentication. */
class ProfileAggregationTest {
    @TempDir Path temporary;
    final Path workspace = Path.of("../..").toAbsolutePath().normalize();
    final String task = ":authLabComponentTest";
    final List<String> profiles = List.of("diagnostics");
    final List<ScenarioCatalog.Requirement> rows = LabProductionEvidence.profileRows(profiles);

    Path scope(String fault) throws Exception {
        UUID invocation = UUID.randomUUID();
        Path directory = Files.createDirectories(temporary.resolve(invocation.toString()));
        Path scope = Files.createDirectory(directory.resolve(LabEvidence.sha256(task.getBytes(StandardCharsets.UTF_8))));
        var plan = new JsonObject(); plan.add("selectedProfiles", LabRun.JSON.toJsonTree(profiles));
        plan.add("selectedRequirementIds", LabRun.JSON.toJsonTree(rows.stream().map(ScenarioCatalog.Requirement::id).toList()));
        plan.add("selectedMethods", LabRun.JSON.toJsonTree(LabProductionEvidence.profileMethods(rows, task)));
        Files.writeString(scope.resolve("plan.json"), plan.toString());
        var context = Map.of("contextVersion", 1, "invocationId", invocation.toString(), "taskPath", task,
                "configurationHash", LabProductionEvidence.configurationFingerprint(workspace, task), "catalogRevision", LabEvidence.catalogFingerprint(workspace),
                "productionRevision", rows.getFirst().binding().sourceRevision(), "artifactSha256", "a".repeat(64), "state", "COMPLETED");
        Path contextPath = scope.resolve("report-context.json"); Files.writeString(contextPath, LabRun.JSON.toJson(context));
        String contextHash = LabEvidence.sha256(Files.readAllBytes(contextPath));
        Path xml = Files.createDirectories(scope.resolve("junit-xml")).resolve("TEST-profile.xml");
        var cases = new LinkedHashMap<String, ScenarioCatalog.Binding>();
        rows.forEach(r -> cases.putIfAbsent(r.binding().executionId(), r.binding()));
        var body = new StringBuilder("<testsuite>"); boolean first = true;
        for (var binding : cases.values()) {
            body.append("<testcase classname=\"").append(escape(binding.className())).append("\" name=\"").append(escape(binding.xmlCaseName())).append("\">");
            if (first && fault.equals("failed-xml")) body.append("<failure message=\"induced harness control\"/>");
            first = false; body.append("</testcase>");
        }
        Files.writeString(xml, body.append("</testsuite>").toString());
        String xmlHash = LabEvidence.sha256(Files.readAllBytes(xml));
        try (var stream = new LabEvidence(scope.resolve("report.jsonl"), invocation, UUID.randomUUID())) {
            stream.write("RUN_STARTED", Map.of("productionRevision", context.get("productionRevision"), "artifacts", List.of(), "dependencyPins", List.of(),
                    "profiles", profiles, "selectedRequirementIds", rows.stream().map(ScenarioCatalog.Requirement::id).toList()));
            for (int i = 0; i < rows.size(); i++) {
                var row = rows.get(fault.equals("duplicate") && i == 1 ? 0 : i);
                var observedBinding = Map.of("executionId", row.binding().executionId(), "contextSha256", contextHash,
                        "reportPath", "junit-xml/TEST-profile.xml", "reportSha256", xmlHash);
                var result = new LinkedHashMap<String, Object>();
                result.put("requirementIds", List.of(row.id())); result.put("executionId", row.binding().executionId()); result.put("observedBinding", observedBinding);
                result.put("caseRevision", row.revision()); result.put("layer", row.layer()); result.put("classification", "SUPPORTED"); result.put("outcome", "PASS");
                result.put("expected", row.expected()); result.put("observed", List.of()); result.put("missingEvidence", List.of());
                result.put("timings", Map.of("startupMs", 0, "caseMs", 0, "cleanupMs", 0)); result.put("cleanup", "COMPLETE"); result.put("host", null);
                stream.write("CASE_RESULT", result);
            }
            if (!fault.equals("missing-completion")) stream.write("RUN_COMPLETED", Map.of("complete", !fault.equals("incomplete-cleanup"),
                    "cleanupOutcome", fault.equals("incomplete-cleanup") ? "INCOMPLETE" : "COMPLETE"));
        }
        return directory;
    }
    private String escape(String value) { return value.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;").replace(">", "&gt;"); }

    @Test void completeCurrentScopesAreProjectedWithoutInventingMoreRequirements() throws Exception {
        Path directory = scope("none");
        assertTrue(LabProductionEvidence.collectProfiles(directory, workspace, profiles));
        var lines = Files.readAllLines(directory.resolve("report-profiles.jsonl"));
        assertEquals(rows.size() + 2, lines.size());
        assertTrue(ScenarioCatalog.parseJson(lines.getLast().getBytes(StandardCharsets.UTF_8)).getAsJsonObject().getAsJsonObject("data").get("complete").getAsBoolean());
    }
    @Test void missingCompletionAndDuplicateRequirementsCannotBecomeAnOverallPass() throws Exception {
        for (String fault : List.of("missing-completion", "duplicate")) {
            Path directory = scope(fault);
            assertThrows(IOException.class, () -> LabProductionEvidence.collectProfiles(directory, workspace, profiles), fault);
        }
    }
    @Test void aPassingLabelCannotOverrideTheMatchingFailedJunitCase() throws Exception {
        Path directory = scope("failed-xml");
        assertThrows(IOException.class, () -> LabProductionEvidence.collectProfiles(directory, workspace, profiles));
    }
    @Test void completeCaseResultsCannotHideIncompleteScopeCleanup() throws Exception {
        Path directory = scope("incomplete-cleanup");
        assertFalse(LabProductionEvidence.collectProfiles(directory, workspace, profiles));
        var lines = Files.readAllLines(directory.resolve("report-profiles.jsonl"));
        var completion = ScenarioCatalog.parseJson(lines.getLast().getBytes(StandardCharsets.UTF_8)).getAsJsonObject().getAsJsonObject("data");
        assertFalse(completion.get("complete").getAsBoolean());
        assertEquals("INCOMPLETE", completion.get("cleanupOutcome").getAsString());
    }
}
