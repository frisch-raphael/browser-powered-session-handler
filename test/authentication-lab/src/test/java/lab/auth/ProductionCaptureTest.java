package lab.auth;

import com.google.gson.JsonObject;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class ProductionCaptureTest {
    @TempDir Path workspace;

    @Test void captureRequiresExactAuditSourceAndProductionRevision() throws Exception {
        Path capture = workspace.resolve("test/authentication-lab/build/captures/run");
        Path source = capture.resolve("production/bapp/src/main/java/Example.java");
        Files.createDirectories(source.getParent());
        Files.writeString(source, "class Example {}\n");
        var files = new JsonObject();
        files.addProperty("bapp/src/main/java/Example.java", LabEvidence.sha256(Files.readAllBytes(source)));
        var audit = new JsonObject();
        audit.addProperty("head", "reviewed-head");
        audit.addProperty("boundaryHash", "a".repeat(64));
        audit.add("files", files);
        Path auditFile = capture.resolve("production-audit.json");
        Files.writeString(auditFile, audit.toString());
        var plan = new JsonObject();
        plan.addProperty("auditFile", auditFile.toString());
        plan.addProperty("auditSha256", LabEvidence.sha256(Files.readAllBytes(auditFile)));
        plan.addProperty("boundaryHash", "a".repeat(64));
        plan.addProperty("productionRevision", "reviewed-head+working-copy:" + "a".repeat(64));
        plan.addProperty("productionRoot", capture.resolve("production").toString());
        assertTrue(LabProductionEvidence.productionInputsCurrent(plan, workspace));

        plan.addProperty("productionRevision", "foreign-revision");
        assertFalse(LabProductionEvidence.productionInputsCurrent(plan, workspace));
        plan.addProperty("productionRevision", "reviewed-head+working-copy:" + "a".repeat(64));
        Files.writeString(source, "class Changed {}\n");
        assertFalse(LabProductionEvidence.productionInputsCurrent(plan, workspace));
        Files.writeString(source, "class Example {}\n");
        Files.writeString(auditFile, audit + "\n");
        assertFalse(LabProductionEvidence.productionInputsCurrent(plan, workspace));
    }
}
