package lab.auth;

import com.google.gson.JsonElement;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.security.MessageDigest;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;

/** Safe lifecycle report. An unbound/unperformed check is never recorded as passing. */
public final class LabEvidence implements AutoCloseable {
    private final BufferedWriter writer;
    private final UUID invocationId, runId;
    private List<ScenarioCatalog.Requirement> selected = List.of();
    private long sequence;
    LabEvidence(Path report, UUID invocationId, UUID runId) throws IOException {
        this.invocationId = invocationId; this.runId = runId;
        writer = Files.newBufferedWriter(report, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW); LabRun.restrict(report);
    }
    synchronized void started(LabRun.RunSpec spec) throws IOException {
        selected = spec.catalog().select(spec.profiles()).requirements();
        var data = new LinkedHashMap<String, Object>(); data.put("productionRevision", null); data.put("artifacts", spec.preparedArtifacts());
        String gsonHash;
        try {
            var location = Path.of(com.google.gson.Gson.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            gsonHash = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(location)));
        } catch (Exception ex) { throw new IOException("Resolved JSON dependency integrity unavailable."); }
        data.put("dependencyPins", List.of(Map.of("coordinates", "com.google.code.gson:gson", "version", "2.13.2", "integrity", "sha256:" + gsonHash)));
        data.put("profiles", spec.profiles()); data.put("selectedRequirementIds", selected.stream().map(ScenarioCatalog.Requirement::id).toList());
        write("RUN_STARTED", data);
    }
    synchronized void completed(boolean cleanupComplete, List<String> remaining) throws IOException {
        for (var requirement : selected) {
            boolean excluded=requirement.disposition()==ScenarioCatalog.Disposition.EXCLUDED;
            boolean manual = requirement.layer() == ScenarioCatalog.Layer.HOST || requirement.layer() == ScenarioCatalog.Layer.ASSESSMENT;
            var record = new LinkedHashMap<String, Object>();
            record.put("requirementIds", List.of(requirement.id())); record.put("executionId", "unperformed:" + requirement.id());
            record.put("observedBinding", null); record.put("caseRevision", requirement.revision()); record.put("layer", requirement.layer());
            record.put("classification", excluded?"EXCLUDED":requirement.layer() == ScenarioCatalog.Layer.HOST ? "MANUAL" : requirement.layer() == ScenarioCatalog.Layer.FIXTURE ? "SUPPORTED" : "UNASSESSED");
            record.put("outcome", excluded?"EXCLUDED":manual ? "NOT_RUN" : "BLOCKED"); record.put("expected", requirement.expected()); record.put("observed", List.of());
            record.put("missingEvidence", excluded?List.of():requirement.evidence()); record.put("timings", Map.of("startupMs", 0, "caseMs", 0, "cleanupMs", 0));
            record.put("cleanup", cleanupComplete ? "COMPLETE" : "INCOMPLETE"); record.put("host", null); write("CASE_RESULT", record);
        }
        long manual = selected.stream().filter(r -> r.layer() == ScenarioCatalog.Layer.HOST || r.layer() == ScenarioCatalog.Layer.ASSESSMENT).count();
        long excluded=selected.stream().filter(r->r.disposition()==ScenarioCatalog.Disposition.EXCLUDED).count();
        var outcomes = Map.of("PASS", 0, "FAIL", 0, "BLOCKED", selected.size() - manual-excluded, "NOT_RUN", manual, "INTERRUPTED", 0,"EXCLUDED",excluded);
        // These are owned target environments, not an authentication test runner. JUnit owns fixture assertion results.
        write("RUN_COMPLETED", Map.of("outcomes", outcomes, "cleanupOutcome", cleanupComplete ? "COMPLETE" : "INCOMPLETE", "remainingResources", remaining, "complete", false));
    }
    void write(String type, Map<String, ?> data) throws IOException {
        writer.write(LabRun.JSON.toJson(Map.of("resultVersion", 1, "type", type, "invocationId", invocationId.toString(), "runId", runId.toString(), "sequence", ++sequence, "time", Instant.now().toString(), "data", data)));
        writer.newLine(); writer.flush();
    }
    @Override public synchronized void close() throws IOException { writer.close(); }

    static String sha256(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (java.security.NoSuchAlgorithmException ex) { throw new IllegalStateException(ex); }
    }
    /** Captured by the owning test after HTTP assertions and case cleanup, never synthesized from its expected data. */
    public static void captureFixture(ScenarioCatalog.Requirement row, List<ScenarioCatalog.Fact> observed, long startupMs, long caseMs, long cleanupMs) throws IOException {
        String target = System.getProperty("lab.fixtureReportDirectory"); if (target == null) return;
        if (row.layer() != ScenarioCatalog.Layer.FIXTURE) throw new IOException("Fixture observations cannot claim another layer.");
        validateObservations(observed.stream().collect(java.util.stream.Collectors.toMap(ScenarioCatalog.Fact::fact, ScenarioCatalog.Fact::value)));
        var capture = new LinkedHashMap<String, Object>();
        capture.put("captureVersion", 1); capture.put("invocationId", System.getProperty("lab.fixtureInvocationId"));
        capture.put("taskPath", ":auth-lab:test"); capture.put("requirementId", row.id()); capture.put("caseRevision", row.revision());
        capture.put("observed", observed); capture.put("cleanup", "COMPLETE"); capture.put("startupMs", startupMs); capture.put("caseMs", caseMs); capture.put("cleanupMs", cleanupMs);
        Path directory = Path.of(target).resolve("observations"); Files.createDirectories(directory);
        Files.writeString(directory.resolve(sha256(row.id().getBytes(StandardCharsets.UTF_8)) + ".json"), LabRun.JSON.toJson(capture), StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
    }
    static JsonElement canonical(JsonElement value) {
        if (value.isJsonObject()) {
            var sorted = new com.google.gson.JsonObject(); value.getAsJsonObject().entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(e -> sorted.add(e.getKey(), canonical(e.getValue()))); return sorted;
        }
        if (value.isJsonArray()) { var array = new com.google.gson.JsonArray(); value.getAsJsonArray().forEach(e -> array.add(canonical(e))); return array; }
        return value;
    }
    record XmlCase(String className, String name, String outcome, Path report) {}
    /** Join retained current-invocation XML and safe HTTP observations to the audited fixture owners. */
    public static boolean collectFixtures(Path directory, Path workspace, Path artifact) throws Exception {
        Path contextFile = directory.resolve("report-context.json");
        byte[] contextBytes = Files.readAllBytes(contextFile);
        var context = ScenarioCatalog.parseJson(contextBytes).getAsJsonObject();
        String contextHash = sha256(contextBytes);
        if (!context.keySet().equals(Set.of("contextVersion", "invocationId", "taskPath", "configurationHash", "productionRevision", "artifactSha256", "catalogRevision", "state")) || LabRun.number(context, "contextVersion", false) != 1) throw new IOException("Invalid fixture report context.");
        UUID invocation = UUID.fromString(LabRun.text(context, "invocationId"));
        String task = LabRun.text(context, "taskPath"), configuration = LabRun.text(context, "configurationHash");
        if (!task.equals(":auth-lab:test") || !directory.getFileName().toString().equals(sha256(task.getBytes(StandardCharsets.UTF_8))) || !directory.getParent().getFileName().toString().equals(invocation.toString())) throw new IOException("Foreign report identity.");
        String actualArtifact = sha256(Files.readAllBytes(artifact));
        boolean contextValid = context.get("productionRevision").isJsonNull() && configuration.equals(configurationFingerprint(workspace)) && actualArtifact.equals(LabRun.text(context, "artifactSha256")) && catalogFingerprint(workspace).equals(LabRun.text(context, "catalogRevision")) && Set.of("COMPLETED", "FAILED").contains(LabRun.text(context, "state"));
        var xmlCases = junitCases(directory);
        var reportHashes = new HashMap<Path, String>();
        for (var row : xmlCases) if (!reportHashes.containsKey(row.report())) reportHashes.put(row.report(), sha256(Files.readAllBytes(row.report())));
        var catalog = ScenarioCatalog.load(); var selection = catalog.select(List.of("fixtures"));
        var counts = new LinkedHashMap<String, Integer>(); for (String name : List.of("PASS", "FAIL", "BLOCKED", "NOT_RUN", "INTERRUPTED","EXCLUDED")) counts.put(name, 0);
        boolean complete = contextValid && LabRun.text(context, "state").equals("COMPLETED");
        var inspectedSources = new HashMap<Map<String, String>, Boolean>();
        UUID runId = UUID.randomUUID();
        Path output = directory.resolve("report.jsonl");
        try (var report = new LabEvidence(output, invocation, runId)) {
            report.started(new LabRun.RunSpec(invocation, List.of("fixtures"), catalog, workspace.resolve("test/authentication-lab/build/runs"), List.of(new LabRun.ArtifactRecord("fixture-runtime", "P1", actualArtifact)), 5_000));
            for (var requirement : selection.requirements()) {
                var binding = requirement.binding(); var record = new LinkedHashMap<String, Object>();
                String outcome = "BLOCKED"; Object observedBinding = null; JsonElement observations = new com.google.gson.JsonArray();
                var missing = new ArrayList<>(requirement.evidence()); long startupMs = 0, caseMs = 0, cleanupMs = 0;
                boolean sourcesMatch = false;
                if (binding != null) {
                    Boolean inspected = inspectedSources.get(binding.sourceHashes());
                    if (inspected == null) { inspected = currentSources(binding, workspace); inspectedSources.put(binding.sourceHashes(), inspected); }
                    sourcesMatch = inspected;
                }
                List<XmlCase> matches = binding == null ? List.of() : xmlCases.stream().filter(c -> c.className.equals(binding.className()) && c.name.equals(binding.xmlCaseName())).toList();
                if (contextValid && binding != null && binding.executor().equals("JUNIT") && binding.taskPath().equals(task) && binding.configurationHash().equals(configuration) && matches.size() == 1 && sourcesMatch) {
                    var match = matches.getFirst(); var key = java.util.regex.Pattern.compile("\\[case=([^]]+)]").matcher(match.name);
                    if (match.outcome.equals("FAIL")) outcome = "FAIL";
                    boolean keyMatches = key.find() && key.group(1).equals(binding.parameterKey()) && !key.find();
                    Path captureFile = directory.resolve("observations").resolve(sha256(requirement.id().getBytes(StandardCharsets.UTF_8)) + ".json");
                    if (keyMatches && Files.isRegularFile(captureFile) && captureFile.toRealPath().startsWith(directory.toRealPath())) {
                        var capture = ScenarioCatalog.parseJson(Files.readAllBytes(captureFile)).getAsJsonObject();
                        if (capture.keySet().equals(Set.of("captureVersion", "invocationId", "taskPath", "requirementId", "caseRevision", "observed", "cleanup", "startupMs", "caseMs", "cleanupMs")) && LabRun.number(capture, "captureVersion", false) == 1 && invocation.toString().equals(LabRun.text(capture, "invocationId")) && task.equals(LabRun.text(capture, "taskPath")) && requirement.id().equals(LabRun.text(capture, "requirementId")) && LabRun.number(capture, "caseRevision", false) == requirement.revision() && "COMPLETE".equals(LabRun.text(capture, "cleanup"))) {
                            observations = capture.getAsJsonArray("observed"); var facts = new HashSet<String>();
                            var observedValues = new HashMap<String, String>();
                            for (var observation : observations.getAsJsonArray()) {
                                var fact = observation.getAsJsonObject();
                                if (!fact.keySet().equals(Set.of("fact", "value"))) throw new IOException("Invalid captured observation.");
                                String name = LabRun.text(fact, "fact"), value = LabRun.text(fact, "value");
                                if (!Set.of("httpStatus", "account", "issuance", "actions", "outcome").contains(name) || observedValues.putIfAbsent(name, value) != null) throw new IOException("Invalid/duplicate captured fact."); facts.add(name);
                            }
                            validateObservations(observedValues);
                            boolean valuesAgree = requirement.expected().stream().filter(f -> Set.of("httpStatus", "account", "issuance", "actions").contains(f.fact())).allMatch(f -> f.value().equals(observedValues.get(f.fact())));
                            facts.add("completion"); missing.removeIf(facts::contains); startupMs = LabRun.number(capture, "startupMs", true); caseMs = LabRun.number(capture, "caseMs", true); cleanupMs = LabRun.number(capture, "cleanupMs", true);
                            if (!valuesAgree) missing.add("outcome");
                            outcome = match.outcome.equals("PASS") && missing.isEmpty() ? "PASS" : match.outcome.equals("FAIL") ? "FAIL" : "BLOCKED";
                            var observed = new LinkedHashMap<String, Object>();
                            observed.put("executionId", binding.executionId()); observed.put("executor", "JUNIT"); observed.put("invocationId", invocation.toString()); observed.put("taskPath", task); observed.put("configurationHash", configuration);
                            observed.put("observedClassName", match.className); observed.put("observedCaseName", match.name); observed.put("observedParameterKey", binding.parameterKey());
                            observed.put("bindingSha256", sha256(LabRun.JSON.toJson(canonical(LabRun.JSON.toJsonTree(binding))).getBytes(StandardCharsets.UTF_8)));
                            observed.put("witnessIds", binding.witnesses().stream().map(ScenarioCatalog.Witness::assertionId).toList());
                            observed.put("reportPath", directory.relativize(match.report).toString().replace('\\', '/')); observed.put("reportSha256", reportHashes.get(match.report)); observed.put("contextSha256", contextHash); observed.put("outcome", outcome); observedBinding = observed;
                        }
                    }
                }
                boolean excluded=requirement.disposition()==ScenarioCatalog.Disposition.EXCLUDED;
                if(excluded){outcome="EXCLUDED";missing.clear();}
                if (!outcome.equals("PASS")&&!excluded) complete = false; counts.merge(outcome, 1, Integer::sum);
                record.put("requirementIds", List.of(requirement.id())); record.put("executionId", excluded?"excluded:"+requirement.id():binding == null ? "unbound:" + requirement.id() : binding.executionId()); record.put("observedBinding", observedBinding);
                record.put("caseRevision", requirement.revision()); record.put("layer", requirement.layer()); record.put("classification", excluded?"EXCLUDED":"SUPPORTED"); record.put("outcome", outcome);
                record.put("expected", requirement.expected()); record.put("observed", observations); record.put("missingEvidence", missing); record.put("timings", Map.of("startupMs", startupMs, "caseMs", caseMs, "cleanupMs", cleanupMs)); record.put("cleanup", excluded||observedBinding !=null?"COMPLETE":"INCOMPLETE"); record.put("host", null);
                report.write("CASE_RESULT", record);
            }
            report.write("RUN_COMPLETED", Map.of("outcomes", counts, "cleanupOutcome", complete ? "COMPLETE" : "INCOMPLETE", "remainingResources", List.of(), "complete", complete));
        }
        return complete;
    }
    static List<XmlCase> junitCases(Path directory) throws Exception {
        var xmlCases = new ArrayList<XmlCase>();
        var parser = DocumentBuilderFactory.newInstance(); parser.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        parser.setFeature("http://xml.org/sax/features/external-general-entities", false); parser.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        parser.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD, ""); parser.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_SCHEMA, ""); parser.setXIncludeAware(false); parser.setExpandEntityReferences(false);
        if (Files.isDirectory(directory.resolve("junit-xml"))) try (var reports = Files.list(directory.resolve("junit-xml"))) {
            for (var file : reports.filter(p -> p.getFileName().toString().matches("TEST-.+\\.xml")).toList()) {
                if (!file.toRealPath().startsWith(directory.toRealPath())) throw new IOException("Report escaped its owner directory.");
                byte[] reportBytes = Files.readAllBytes(file);
                var document = parser.newDocumentBuilder().parse(new ByteArrayInputStream(reportBytes));
                if (!Set.of("testsuite", "testsuites").contains(document.getDocumentElement().getTagName())) throw new IOException("Not a JUnit suite report.");
                var cases = document.getElementsByTagName("testcase");
                for (int i = 0; i < cases.getLength(); i++) {
                    var element = (Element) cases.item(i); String outcome = element.getElementsByTagName("skipped").getLength() > 0 ? "BLOCKED" : element.getElementsByTagName("failure").getLength() + element.getElementsByTagName("error").getLength() > 0 ? "FAIL" : "PASS";
                    xmlCases.add(new XmlCase(element.getAttribute("classname"), element.getAttribute("name"), outcome, file));
                }
            }
        }
        return List.copyOf(xmlCases);
    }
    static boolean currentSources(ScenarioCatalog.Binding binding, Path workspace) throws IOException {
        Path realRoot = workspace.toRealPath();
        for (var entry : binding.sourceHashes().entrySet()) {
            Path source = workspace.resolve(entry.getKey());
            if (!Files.isRegularFile(source) || !source.toRealPath().startsWith(realRoot) || !sha256(Files.readAllBytes(source)).equalsIgnoreCase(entry.getValue())) return false;
        }
        return true;
    }
    public static String catalogFingerprint(Path workspace) throws IOException {
        var parts = new ArrayList<String>();
        try (var files = Files.list(workspace.resolve("test/authentication-lab/src/main/resources/catalog"))) {
            for (var file : files.filter(p -> p.toString().endsWith(".json")).sorted().toList()) parts.add(file.getFileName() + ":" + sha256(Files.readAllBytes(file)));
        }
        return sha256(String.join("\n", parts).getBytes(StandardCharsets.UTF_8));
    }
    public static String configurationFingerprint(Path workspace) throws IOException {
        var parts = new ArrayList<>(List.of("authlab-fixture-config-v1", ":auth-lab:test"));
        for (String file : List.of("bapp/build.gradle.kts", "bapp/gradle/auth-lab.gradle.kts", "bapp/settings.gradle.kts", "bapp/gradle/verification-metadata.xml", "test/authentication-lab/build.gradle.kts", "test/authentication-lab/gradle.lockfile", "bapp/gradle/auth-lab-production.gradle.kts", "bapp/gradle/auth-lab-production.init.gradle", "test/authentication-lab/src/main/resources/production-policy.json", "test/authentication-lab/src/main/resources/production-selection.json")) parts.add(sha256(Files.readAllBytes(workspace.resolve(file))));
        return sha256(String.join("\n", parts).getBytes(StandardCharsets.UTF_8));
    }
    public static boolean fixtureBindingsCurrent(ScenarioCatalog.Selection selected, Path workspace) throws IOException {
        String configuration = configurationFingerprint(workspace);
        var inspected = new HashSet<Map<String, String>>();
        for (var row : selected.requirements()) {
            if (row.layer() != ScenarioCatalog.Layer.FIXTURE || row.binding() == null || !configuration.equals(row.binding().configurationHash())) return false;
            if (inspected.add(row.binding().sourceHashes()) && !currentSources(row.binding(), workspace)) return false;
        }
        return true;
    }
    private static void validateObservations(Map<String, String> observations) throws IOException {
        for (var entry : observations.entrySet()) {
            boolean safe = switch (entry.getKey()) {
                case "httpStatus" -> entry.getValue().matches("[1-5][0-9]{2}(,[1-5][0-9]{2})*");
                case "account" -> Set.of("user", "user2", "admin").contains(entry.getValue());
                case "issuance" -> entry.getValue().matches("s[0-9]+");
                case "actions" -> entry.getValue().matches("[0-9]+");
                case "outcome" -> entry.getValue().equals("independent-witness-comparisons-passed");
                default -> false;
            };
            if (!safe) throw new IOException("Unsafe/unknown fixture observation.");
        }
    }
}
