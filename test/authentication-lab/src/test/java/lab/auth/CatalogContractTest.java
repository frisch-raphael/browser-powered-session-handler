package lab.auth;

import com.google.gson.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

class CatalogContractTest {
    @TempDir Path temporary;
    private static final List<String> FILES = List.of("catalog.json", "fixtures.json", "browser.json", "credentials.json",
            "recovery.json", "registry.json", "federation.json", "transport.json", "http-authentication.json", "burp.json", "assessments.json");

    @Test void catalogRetainsEveryDeclaredRequirementWithoutClaimingExecutedCoverage() {
        var catalog = ScenarioCatalog.load();
        assertEquals(1030, catalog.requirements().size());
        assertEquals(52, catalog.requirements().stream().map(ScenarioCatalog.Requirement::group).distinct().count());
        assertEquals(27, catalog.requirements().stream().filter(r -> r.layer() == ScenarioCatalog.Layer.HOST).count());
        assertEquals(16, catalog.requirements().stream().filter(r -> r.layer() == ScenarioCatalog.Layer.ASSESSMENT).count());
        assertTrue(catalog.requirements().stream().filter(r -> r.layer() != ScenarioCatalog.Layer.FIXTURE && !LabProductionEvidence.supported(r)).allMatch(r -> r.binding() == null));
        assertTrue(catalog.requirements().stream().filter(r -> r.layer() == ScenarioCatalog.Layer.FIXTURE&&r.disposition()!=ScenarioCatalog.Disposition.EXCLUDED).allMatch(r -> r.binding() != null));
        var selected = catalog.select(List.of("all"));
        assertEquals(898, selected.uniqueBoundExecutions());
        assertEquals(43, selected.unboundRequirements());
        assertEquals(0, selected.requirements().stream().filter(r -> r.readiness().equals("BLOCKED")).count());
        assertEquals(28,selected.requirements().stream().filter(r->r.readiness().equals("EXCLUDED")).count());
        assertEquals(959, selected.requirements().stream().filter(r -> r.readiness().equals("BOUND_NOT_EXECUTED")).count());
    }
    @Test void tagMatrixUsesItsDeclaredAlphanumericScopeAndRetainsSeparateLiteralOutputOwnership() {
        var catalog = ScenarioCatalog.load();
        for (var row : catalog.requirements()) if (row.group().equals("CORE.tag-matrix")) {
            assertEquals("one-snapshot-per-journey", fact(row, "publication")); assertEquals(2, row.revision());
            assertEquals("test/authentication-lab/production-tests/bpsh/burp/http/NativeTagPipelineTest.java", row.binding().witnesses().getFirst().sourcePath());
        }
        var literal = catalog.requirement("CORE.encoding.literal-prefix").binding();
        assertEquals("wrapperLiteralTextWorksWithoutStartingAnyAuthenticationAndTagOutputIsNeverReparsed()", literal.methodSignature());
        assertNull(literal.parameterKey());
    }
    @Test void excludedProviderValidationCannotLaunchOrBecomePassingProductCoverage() throws Exception {
        var catalog=ScenarioCatalog.load();Path directory;
        try(var run=LabRun.start(new LabRun.RunSpec(UUID.randomUUID(),List.of("federation"),catalog,temporary.resolve("runs"),List.of(),5000))) {
            directory=run.directory();var error=assertThrows(LabRun.ControlException.class,()->run.prepareCase("FED.saml.invalid-signature"));
            assertEquals("OUT_OF_SCOPE",error.code());
        }
        var records=Files.readAllLines(directory.resolve("report.jsonl")).stream().map(line->JsonParser.parseString(line).getAsJsonObject()).toList();
        var result=records.stream().filter(r->r.get("type").getAsString().equals("CASE_RESULT"))
                .map(r->r.getAsJsonObject("data")).filter(r->r.getAsJsonArray("requirementIds").get(0).getAsString().equals("FED.saml.invalid-signature")).findFirst().orElseThrow();
        assertEquals("EXCLUDED",result.get("outcome").getAsString());assertEquals(0,result.getAsJsonArray("missingEvidence").size());
        var outcomes=records.getLast().getAsJsonObject("data").getAsJsonObject("outcomes");
        assertEquals(14,outcomes.get("EXCLUDED").getAsInt());assertEquals(17,outcomes.get("BLOCKED").getAsInt());assertEquals(0,outcomes.get("PASS").getAsInt());
    }

    @Test void matrixMetadataPreservesIndependentIdentityAndSameIssuanceExpectations() {
        var catalog = ScenarioCatalog.load();
        var matrix = catalog.requirements().stream().filter(r -> r.group().equals("FIX.matrix")).toList();
        assertEquals(511, matrix.size());
        assertEquals(42, matrix.stream().filter(r -> fact(r, "httpStatus").equals("200")).count());
        assertEquals(469, matrix.stream().filter(r -> fact(r, "httpStatus").equals("401")).count());
        assertEquals("user", fact(catalog.requirement("FIX.matrix.required=b_c1~b=s0~c1=s0"), "account"));
        assertEquals("401", fact(catalog.requirement("FIX.matrix.required=b_c1~b=s0~c1=s1"), "httpStatus"));
        assertEquals("401", fact(catalog.requirement("FIX.matrix.required=b_c1_c2~b=s0~c1=s2~c2=none"), "httpStatus"));
        assertEquals("admin", fact(catalog.requirement("FIX.matrix.required=c2~c2=s5"), "account"));
        assertEquals("user2", fact(catalog.requirement("FIX.extra.other-account-complete-set"), "account"));
        assertEquals("CORE.retry.PIN-rejected", catalog.requirement("CORE.retry.PIN-rejected").id());
    }

    @Test void profilesHaveExactScopeAndUnionDoesNotMultiplyRequirements() {
        var catalog = ScenarioCatalog.load();
        var counts = Map.ofEntries(Map.entry("fixtures", 523), Map.entry("baseline", 12), Map.entry("revised", 103),
                Map.entry("credentials", 179), Map.entry("diagnostics", 18), Map.entry("browser", 49), Map.entry("federation", 31),
                Map.entry("recovery", 106), Map.entry("transport", 19), Map.entry("http-auth", 47), Map.entry("burp", 25), Map.entry("deployment", 2), Map.entry("all", 1030));
        counts.forEach((profile, expected) -> assertEquals(expected, catalog.select(List.of(profile)).requirements().size(), profile));
        assertEquals(186, catalog.select(List.of("baseline", "credentials", "baseline")).requirements().size());
        assertEquals(12, catalog.select(List.of("baseline")).requirements().size());
        assertThrows(ScenarioCatalog.CatalogException.class, () -> catalog.select(List.of()));
        assertThrows(ScenarioCatalog.CatalogException.class, () -> catalog.select(List.of("unknown")));
    }

    @Test void diagnosticExpectationsDistinguishMissingCookieFromConnectionFailure() {
        var catalog = ScenarioCatalog.load();
        assertEquals("selected-cookie-missing", fact(catalog.requirement("CORE.diagnostics.missing-cookie"), "requiredMessageFact"));
        assertEquals("connection-failed", fact(catalog.requirement("CORE.diagnostics.missing-cookie"), "forbiddenMessageClaim"));
        assertEquals("connection-failed", fact(catalog.requirement("CORE.diagnostics.connection-refused"), "requiredMessageFact"));
        assertEquals("3", fact(catalog.requirement("CORE.diagnostics.attempts-exhausted"), "attempts"));
        assertEquals("PAUSED", fact(catalog.requirement("CORE.diagnostics.attempts-exhausted"), "state"));
        assertTrue(catalog.requirement("FED.negative.code-expired").expected().stream()
                .anyMatch(f -> f.value().equals("backend-rejection-no-credential-and-no-invented-connection-error")));
    }

    @Test void positiveAndNegativeRecipesDeclareDifferentRequiredOutcomes() {
        var catalog = ScenarioCatalog.load();
        assertEquals("selected-output-authenticates-user", fact(catalog.requirement("BROW.basic.json"), "outcome"));
        assertEquals("login-rejected-no-output", fact(catalog.requirement("BROW.basic.invalid-credentials"), "outcome"));
        assertEquals("ambiguous-selection-rejected", fact(catalog.requirement("BROW.cookie-selection.ambiguous"), "outcome"));
        assertEquals("no-partial-set", fact(catalog.requirement("CORE.outputs.missing-member"), "publication"));
        assertEquals("over-limit-rejected", fact(catalog.requirement("CORE.limits.dimension=wrapper_depth~point=above"), "outcome"));
        assertEquals("within-declared-limit-accepted", fact(catalog.requirement("CORE.limits.dimension=wrapper_depth~point=at"), "outcome"));
        assertEquals("ordinary-request-unchanged", fact(catalog.requirement("CORE.tool-policy.tool=repeater~urlMode=all_requests~enabled=false~tagged=false"), "outcome"));
        assertEquals("native-tags-resolved-independent-of-ordinary-policy", fact(catalog.requirement("CORE.tool-policy.tool=repeater~urlMode=all_requests~enabled=false~tagged=true"), "outcome"));
        assertEquals("1", fact(catalog.requirement("CORE.retry.PIN-unknown"), "attempts"));
        assertEquals("0", fact(catalog.requirement("H05.save"), "attempts"));
    }

    @TestFactory Stream<DynamicTest> invalidCatalogsAreRejectedInsteadOfSilentlyChangingCoverage() {
        record Invalid(String name, String file, Consumer<JsonObject> change) {}
        var invalid = List.of(
                new Invalid("unknown index field", "catalog.json", o -> o.addProperty("schemaVersion", 1)),
                new Invalid("missing index field", "catalog.json", o -> o.remove("dataFiles")),
                new Invalid("unsupported catalog version", "catalog.json", o -> o.addProperty("labCatalogVersion", 2)),
                new Invalid("numeric coercion is forbidden", "catalog.json", o -> o.addProperty("labCatalogVersion", "1")),
                new Invalid("path escape", "catalog.json", o -> o.getAsJsonArray("dataFiles").set(0, new JsonPrimitive("../fixtures.json"))),
                new Invalid("baseline cannot grow", "catalog.json", o -> o.getAsJsonObject("profiles").getAsJsonArray("baseline").add("BROW.basic.cookie-two")),
                new Invalid("duplicate profile member", "catalog.json", o -> o.getAsJsonObject("profiles").getAsJsonArray("baseline").add("BROW.basic.json")),
                new Invalid("missing profile member", "catalog.json", o -> o.getAsJsonObject("profiles").getAsJsonArray("all").remove(0)),
                new Invalid("case removed", "fixtures.json", o -> o.getAsJsonArray("requirements").remove(0)),
                new Invalid("duplicate case ID", "fixtures.json", o -> o.getAsJsonArray("requirements").add(first(o).deepCopy())),
                new Invalid("unknown case variant", "fixtures.json", o -> first(o).addProperty("id", "FIX.matrix.unreviewed")),
                new Invalid("unknown requirement field", "fixtures.json", o -> first(o).addProperty("nativeJourney", "invented")),
                new Invalid("missing assertion", "fixtures.json", o -> first(o).add("expected", new JsonArray())),
                new Invalid("missing observation evidence", "fixtures.json", o -> first(o).add("evidence", new JsonArray())),
                new Invalid("unknown expected fact", "fixtures.json", o -> first(o).getAsJsonArray("expected").get(0).getAsJsonObject().addProperty("fact", "secretToken")),
                new Invalid("wrong identity", "fixtures.json", o -> first(o).getAsJsonArray("expected").add(pair("fact", "account", "value", "admin"))),
                new Invalid("unknown axis value", "fixtures.json", o -> first(o).getAsJsonArray("axes").get(1).getAsJsonObject().addProperty("value", "s6")),
                new Invalid("duplicate axis", "fixtures.json", o -> first(o).getAsJsonArray("axes").add(first(o).getAsJsonArray("axes").get(0).deepCopy())),
                new Invalid("incorrect owning layer", "fixtures.json", o -> first(o).addProperty("layer", "RUNNER")),
                new Invalid("unknown capability", "fixtures.json", o -> first(o).getAsJsonArray("capabilities").add("UNREVIEWED_CAPABILITY")),
                new Invalid("unknown assignment slot", "fixtures.json", o -> first(o).getAsJsonArray("assignments").add(pair("slot", "password", "value", "not-a-lab-slot"))),
                new Invalid("raw credential in place of issuance label", "fixtures.json", o -> first(o).getAsJsonArray("assignments").get(2).getAsJsonObject().addProperty("value", "private-output-value")),
                new Invalid("empty budget", "fixtures.json", o -> first(o).getAsJsonObject("budgetMs").addProperty("case", 0)),
                new Invalid("fractional budget", "fixtures.json", o -> first(o).getAsJsonObject("budgetMs").addProperty("case", 0.5)),
                new Invalid("reuse without a binding", "fixtures.json", o -> { first(o).addProperty("disposition", "REUSE"); first(o).add("binding", JsonNull.INSTANCE); }),
                new Invalid("extension behavior hidden as provider exclusion", "fixtures.json", o -> { first(o).addProperty("disposition", "EXCLUDED"); first(o).add("binding", JsonNull.INSTANCE); }),
                new Invalid("unknown binding field", "fixtures.json", o -> { var binding = new JsonObject(); binding.addProperty("plannedName", "not-evidence"); first(o).add("binding", binding); }),
                new Invalid("manual converted into automated pass", "burp.json", o -> first(o).addProperty("disposition", "NEW")),
                new Invalid("unknown nested fault field", "fixtures.json", o -> { var fault = new JsonObject(); fault.addProperty("expression", "arbitrary"); first(o).getAsJsonArray("faults").add(fault); })
        );
        return invalid.stream().map(test -> DynamicTest.dynamicTest(test.name(), () -> {
            Path directory = temporary.resolve(test.name().replace(' ', '-')); copyCatalog(directory);
            Path file = directory.resolve(test.file()); var object = JsonParser.parseString(Files.readString(file)).getAsJsonObject();
            test.change().accept(object); Files.writeString(file, object.toString());
            assertThrows(ScenarioCatalog.CatalogException.class, () -> ScenarioCatalog.load(directory));
        }));
    }

    @Test void sharedDeclaredInvocationIsCountedOnceAcrossSeveralRequirementsAndProfiles() throws IOException {
        copyCatalog(temporary);
        var before=ScenarioCatalog.load(temporary).select(List.of("baseline","credentials"));
        assertEquals(2,before.requirements().stream().filter(row->Set.of("CORE.lifetime.fresh","CORE.lifetime.exact-expiry").contains(row.id())).map(row->row.binding().executionId()).distinct().count());
        Path file = temporary.resolve("credentials.json");
        var document = JsonParser.parseString(Files.readString(file)).getAsJsonObject();
        for (var element : document.getAsJsonArray("requirements")) {
            var requirement = element.getAsJsonObject();
            if (!Set.of("CORE.lifetime.fresh", "CORE.lifetime.exact-expiry").contains(requirement.get("id").getAsString())) continue;
            var binding = new JsonObject();
            binding.addProperty("executionId", "shared-clock-assertions"); binding.addProperty("executor", "JUNIT");
            binding.addProperty("className", "ExampleTest"); binding.addProperty("methodSignature", "clockAssertions()");
            binding.add("parameterKey", JsonNull.INSTANCE); binding.addProperty("sourceRevision", "test-fixture-only");
            binding.addProperty("taskPath", ":authLabComponentTest"); binding.addProperty("configurationHash", "a".repeat(64));
            binding.addProperty("xmlCaseName", "clockAssertions()");
            var witness = new JsonObject(); witness.addProperty("requirementId", requirement.get("id").getAsString());
            witness.addProperty("assertionId", requirement.get("id").getAsString()); witness.addProperty("sourcePath", "test/ExampleTest.java");
            witness.addProperty("sourceSymbol", "clockAssertions"); witness.add("inputKey", JsonNull.INSTANCE);
            var witnesses = new JsonArray(); witnesses.add(witness); binding.add("witnesses", witnesses);
            var hashes = new JsonObject(); hashes.addProperty("test/ExampleTest.java", "b".repeat(64)); binding.add("sourceHashes", hashes);
            requirement.add("binding", binding); requirement.addProperty("disposition", "REUSE");
        }
        Files.writeString(file, document.toString());
        var selection = ScenarioCatalog.load(temporary).select(List.of("baseline", "credentials"));
        assertEquals(before.requirements().size(),selection.requirements().size());
        assertEquals(before.uniqueBoundExecutions()-1,selection.uniqueBoundExecutions());
        assertEquals(before.unboundRequirements(),selection.unboundRequirements());
        assertEquals(before.requirements().stream().filter(r->r.readiness().equals("BOUND_NOT_EXECUTED")).count(),selection.requirements().stream().filter(r->r.readiness().equals("BOUND_NOT_EXECUTED")).count());
    }

    @Test void strictReaderRejectsDuplicateMembersCommentsTrailingContentAndInvalidUtf8() throws IOException {
        for (String text : List.of("{\"labCatalogVersion\":1,\"labCatalogVersion\":1}", "{/* comment */}", "{} {}", "{\"labCatalogVersion\":NaN}")) {
            Path directory = Files.createTempDirectory(temporary, "strict-"); copyCatalog(directory);
            Files.writeString(directory.resolve("catalog.json"), text);
            assertThrows(ScenarioCatalog.CatalogException.class, () -> ScenarioCatalog.load(directory));
        }
        Path directory = Files.createTempDirectory(temporary, "utf8-"); copyCatalog(directory);
        Files.write(directory.resolve("catalog.json"), new byte[] {(byte) 0xff});
        assertThrows(ScenarioCatalog.CatalogException.class, () -> ScenarioCatalog.load(directory));
    }

    @Test void metadataCommandsShowBlockedWorkAndUnavailableCommandsCannotSucceed() {
        var bytes = new ByteArrayOutputStream(); var output = new PrintStream(bytes, true, StandardCharsets.UTF_8);
        assertEquals(0, LabMain.run(new String[] {"matrix", "--profiles", "baseline,baseline"}, output, output));
        var baseline=ScenarioCatalog.load().select(List.of("baseline"));
        assertTrue(bytes.toString(StandardCharsets.UTF_8).contains("Requirements="+baseline.requirements().size()+" uniqueBoundExecutions="+baseline.uniqueBoundExecutions()+" unboundRequirements="+baseline.unboundRequirements()));
        bytes.reset();
        assertEquals(3, LabMain.run(new String[] {"doctor", "--profiles", "baseline"}, output, output));
        assertTrue(bytes.toString(StandardCharsets.UTF_8).contains("Selected capabilities:"));
        assertFalse(bytes.toString(StandardCharsets.UTF_8).contains("KEYCLOAK"));
        for (String command : List.of("run", "reset", "stop", "components"))
            assertEquals(3, LabMain.run(new String[] {command, "--profiles", "all"}, output, output));
        assertEquals(2, LabMain.run(new String[] {"matrix", "--profiles", "unknown"}, output, output));
        assertEquals(2, LabMain.run(new String[] {"matrix", "--profiles", "baseline,"}, output, output));
        assertEquals(2, LabMain.run(new String[] {"unknown", "--profiles", "baseline"}, output, output));
    }

    private static String fact(ScenarioCatalog.Requirement r, String name) {
        return r.expected().stream().filter(f -> f.fact().equals(name)).findFirst().orElseThrow().value();
    }
    private static JsonObject first(JsonObject document) { return document.getAsJsonArray("requirements").get(0).getAsJsonObject(); }
    private static JsonObject pair(String key, String value, String otherKey, String otherValue) {
        var object = new JsonObject(); object.addProperty(key, value); object.addProperty(otherKey, otherValue); return object;
    }
    private static void copyCatalog(Path directory) throws IOException {
        Files.createDirectories(directory);
        for (String name : FILES) {
            try (var stream = CatalogContractTest.class.getResourceAsStream("/catalog/" + name)) {
                assertNotNull(stream); Files.copy(stream, directory.resolve(name), StandardCopyOption.REPLACE_EXISTING);
            }
        }
    }
}
