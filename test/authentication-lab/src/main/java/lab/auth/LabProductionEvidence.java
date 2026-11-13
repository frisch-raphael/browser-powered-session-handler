package lab.auth;

import com.google.gson.JsonObject;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Joins audited production owners to real JUnit XML; never executes authentication. */
public final class LabProductionEvidence {
    private LabProductionEvidence() {}
    private static final Set<String> FOCUSED_PROFILES = Set.of("baseline", "revised", "credentials", "diagnostics", "browser", "recovery", "http-auth");
    static List<ScenarioCatalog.Requirement> profileRows(List<String> profiles) {
        if (profiles.isEmpty() || !FOCUSED_PROFILES.containsAll(profiles)) throw new IllegalArgumentException("Unsupported production profile selection.");
        return ScenarioCatalog.load().select(profiles).requirements();
    }
    static List<String> profileMethods(List<ScenarioCatalog.Requirement> rows, String task) {
        return rows.stream().map(ScenarioCatalog.Requirement::binding).filter(Objects::nonNull).filter(b -> b.taskPath().equals(task))
                .map(b -> b.className() + "." + b.methodSignature().substring(0, b.methodSignature().indexOf('('))).distinct().sorted().toList();
    }
    private static List<String> strings(JsonObject object, String name) {
        return object.getAsJsonArray(name).asList().stream().map(com.google.gson.JsonElement::getAsString).toList();
    }
    static List<ScenarioCatalog.Requirement> scopedProfileRows(JsonObject plan, String task) throws IOException {
        var all = profileRows(strings(plan, "selectedProfiles"));
        var ids = strings(plan, "selectedRequirementIds");
        if (ids.size() != new HashSet<>(ids).size() || !new HashSet<>(ids).equals(new HashSet<>(all.stream().map(ScenarioCatalog.Requirement::id).toList())) ||
                !strings(plan, "selectedMethods").equals(profileMethods(all, task))) throw new IOException("Selected profile plan differs from its catalog owners.");
        var rows = all.stream().filter(r -> r.binding() != null && r.binding().taskPath().equals(task)).toList();
        if (rows.isEmpty()) throw new IOException("Selected profile has no scoped requirements.");
        return rows;
    }
    record DiagnosticSpec(String phase, String nativeCause, String stage, String cause, String required, String forbidden) {}
    private static final Map<String, DiagnosticSpec> DIAGNOSTICS = Map.ofEntries(
            Map.entry("connection-refused", new DiagnosticSpec("NAVIGATION", "TRANSPORT", "connection", "connection-refused", "connection-failed", "selected-cookie-missing")),
            Map.entry("tls-untrusted", new DiagnosticSpec("NAVIGATION", "TRUST", "tls", "untrusted-certificate", "certificate-trust-rejected", "selected-cookie-missing")),
            Map.entry("missing-cookie", new DiagnosticSpec("EXTRACTION", "EXTRACTION", "extraction", "missing-selected-cookie", "selected-cookie-missing", "connection-failed")),
            Map.entry("ambiguous-cookie", new DiagnosticSpec("EXTRACTION", "EXTRACTION", "extraction", "ambiguous-selected-cookie", "cookie-selection-ambiguous", "selected-cookie-missing")),
            Map.entry("missing-response-token", new DiagnosticSpec("EXTRACTION", "EXTRACTION", "extraction", "missing-selected-response-output", "selected-response-output-missing", "connection-failed")),
            Map.entry("invalid-response-format", new DiagnosticSpec("EXTRACTION", "EXTRACTION", "extraction", "invalid-format", "response-format-invalid", "connection-failed")),
            Map.entry("incomplete-output-set", new DiagnosticSpec("EXTRACTION", "EXTRACTION", "publication", "incomplete-required-set", "required-output-missing", "authentication-success")),
            Map.entry("cancelled", new DiagnosticSpec("LIFECYCLE", "CANCELLED", "attempt", "user-cancelled", "attempt-cancelled", "connection-failed")),
            Map.entry("navigation-timeout",new DiagnosticSpec("NAVIGATION","STEP_TIMEOUT","navigation","deadline","navigation-timed-out","password-rejected")),
            Map.entry("login-rejected",new DiagnosticSpec("NAVIGATION","AUTH_REJECTED","login","confirmed-rejection","login-rejected","connection-failed")),
            Map.entry("unsupported-capability",new DiagnosticSpec("SETUP","UNSUPPORTED_PLATFORM","prerequisite","unavailable","capability-unavailable-blocked","login-failed")),
            Map.entry("step-target-missing",new DiagnosticSpec("STEP","STEP_TIMEOUT","action","action-deadline","step-timed-out","connection-failed")),
            Map.entry("protected-use-rejected",new DiagnosticSpec("EXTRACTION","AUTH_REJECTED","protected","service-rejected","protected-use-rejected","extraction-failed")),
            Map.entry("attempts-exhausted",new DiagnosticSpec("NAVIGATION","TRANSPORT","recovery","temporary-network-failures","three-attempts-exhausted-paused","automatic-fourth-attempt")),
            Map.entry("stale-result",new DiagnosticSpec("READY","NONE","presentation","retired-attempt","current-result-preserved","stale-result-replaced-current")),
            Map.entry("success-after-failure",new DiagnosticSpec("READY","NONE","presentation","current-success","current-success-stale-active-error-cleared","stale-active-failure")),
            Map.entry("extraction-only-success", new DiagnosticSpec("READY", "NONE", "extraction", "not-verified-at-service", "extraction-success-protected-unverified", "protected-access-verified")));
    static DiagnosticSpec diagnosticSpec(ScenarioCatalog.Requirement row) {
        return row.group().equals("CORE.diagnostics") ? DIAGNOSTICS.get(row.id().substring("CORE.diagnostics.".length())) : null;
    }
    static boolean diagnosticSuccess(ScenarioCatalog.Requirement row){return Set.of("CORE.diagnostics.extraction-only-success","CORE.diagnostics.stale-result","CORE.diagnostics.success-after-failure").contains(row.id());}
    public static String configurationFingerprint(Path workspace, String task) throws IOException {
        var parts = new ArrayList<>(List.of("authlab-production-config-v1", task));
        for (String path : LabBuildInputs.configurationFiles(workspace)) parts.add(path + ":" + LabEvidence.sha256(Files.readAllBytes(workspace.resolve(path))));
        try (var files = Files.walk(workspace.resolve("test/authentication-lab/production-tests"))) {
            for (var path : files.filter(p -> p.toString().endsWith(".java")).sorted(Comparator.comparing(p -> workspace.relativize(p).toString().replace('\\', '/'))).toList())
                parts.add(workspace.relativize(path).toString().replace('\\', '/') + ":" + LabEvidence.sha256(Files.readAllBytes(path)));
        }
        if(task.equals(":authLabFederationTest"))for(String path:federationInputs(workspace))parts.add(path+":"+LabEvidence.sha256(Files.readAllBytes(workspace.resolve(path))));
        return LabEvidence.sha256(String.join("\n", parts).getBytes(StandardCharsets.UTF_8));
    }
    public static List<String> federationInputs(Path workspace) throws IOException {
        var files=new ArrayList<>(List.of("test/federation-client/build.gradle.kts","test/federation-client/gradle.lockfile","test/federation-client/provider-assets.lock.json"));
        try(var paths=Files.walk(workspace.resolve("test/federation-client/src/main"))){paths.filter(Files::isRegularFile).forEach(path->files.add(workspace.relativize(path).toString().replace('\\','/')));}
        return files.stream().sorted().toList();
    }
    private static JsonObject read(Path path) throws IOException { return ScenarioCatalog.parseJson(Files.readAllBytes(path)).getAsJsonObject(); }
    private static String text(JsonObject value, String key) { return LabRun.text(value, key); }
    private static long number(JsonObject value, String key) { return LabRun.number(value, key, true); }
    private static Path owned(Path root, Path candidate) throws IOException {
        if (!candidate.toRealPath().startsWith(root.toRealPath())) throw new IOException("Evidence escaped its owner directory.");
        return candidate;
    }
    /** Projects only the selected requirements from current scoped executions; shared owners run once. */
    public static boolean collectProfiles(Path directory, Path workspace, List<String> profiles) throws Exception {
        directory = directory.toRealPath(); workspace = workspace.toRealPath();
        UUID invocation = UUID.fromString(directory.getFileName().toString());
        var rows = profileRows(profiles);
        var tasks = rows.stream().map(ScenarioCatalog.Requirement::binding).filter(Objects::nonNull).map(ScenarioCatalog.Binding::taskPath).distinct().toList();
        var results = new LinkedHashMap<String, JsonObject>(); var artifacts = new LinkedHashSet<Object>(); var pins = new LinkedHashMap<String, Object>();
        boolean complete = true, cleaned = true; String revision = null;
        for (String task : tasks) {
            Path scope = owned(directory, directory.resolve(LabEvidence.sha256(task.getBytes(StandardCharsets.UTF_8))));
            var plan = read(owned(scope, scope.resolve("plan.json")));
            if (!new HashSet<>(strings(plan, "selectedProfiles")).equals(new HashSet<>(profiles))) throw new IOException("Foreign profile selection.");
            var expectedRows = scopedProfileRows(plan, task);
            var expectedIds = new HashSet<>(expectedRows.stream().map(ScenarioCatalog.Requirement::id).toList());
            var context = read(owned(scope, scope.resolve("report-context.json")));
            if (!text(context, "invocationId").equals(invocation.toString()) || !text(context, "taskPath").equals(task) ||
                    !text(context, "configurationHash").equals(configurationFingerprint(workspace, task)) ||
                    !text(context, "catalogRevision").equals(LabEvidence.catalogFingerprint(workspace))) throw new IOException("Foreign or stale profile scope.");
            complete &= text(context, "state").equals("COMPLETED");
            String contextHash = LabEvidence.sha256(Files.readAllBytes(scope.resolve("report-context.json")));
            if (revision != null && !revision.equals(text(context, "productionRevision"))) throw new IOException("Profile scopes used different production inputs.");
            revision = text(context, "productionRevision");
            var lines = Files.readAllLines(owned(scope, scope.resolve("report.jsonl")), StandardCharsets.UTF_8);
            if (lines.size() != expectedIds.size() + 2) throw new IOException("Incomplete or unexpected profile scope stream.");
            var xmlCases = LabEvidence.junitCases(scope);
            var seen = new HashSet<String>(); String run = null;
            for (int i = 0; i < lines.size(); i++) {
                var event = ScenarioCatalog.parseJson(lines.get(i).getBytes(StandardCharsets.UTF_8)).getAsJsonObject();
                if (!text(event, "invocationId").equals(invocation.toString()) || number(event, "sequence") != i + 1) throw new IOException("Foreign profile event.");
                if (run != null && !run.equals(text(event, "runId"))) throw new IOException("Mixed profile runs.");
                run = text(event, "runId"); var data = event.getAsJsonObject("data"); String type = text(event, "type");
                if (i == 0) {
                    if (!type.equals("RUN_STARTED") || !new HashSet<>(strings(data, "selectedRequirementIds")).equals(expectedIds)) throw new IOException("Missing profile scope start.");
                    data.getAsJsonArray("artifacts").forEach(artifacts::add);
                    data.getAsJsonArray("dependencyPins").forEach(pin -> pins.put(pin.getAsJsonObject().get("coordinates").getAsString(), pin));
                } else if (i == lines.size() - 1) {
                    if (!type.equals("RUN_COMPLETED")) throw new IOException("Missing profile scope completion.");
                    complete &= data.get("complete").getAsBoolean(); cleaned &= text(data, "cleanupOutcome").equals("COMPLETE");
                } else {
                    if (!type.equals("CASE_RESULT") || data.getAsJsonArray("requirementIds").size() != 1) throw new IOException("Invalid profile result.");
                    String id = data.getAsJsonArray("requirementIds").get(0).getAsString();
                    if (!expectedIds.contains(id) || !seen.add(id)) throw new IOException("Unexpected or duplicate profile result.");
                    var row = expectedRows.stream().filter(r -> r.id().equals(id)).findFirst().orElseThrow();
                    if (!LabEvidence.currentSources(row.binding(), workspace)) throw new IOException("Stale profile sources.");
                    if (text(data, "outcome").equals("PASS")) {
                        var matches = xmlCases.stream().filter(c -> c.className().equals(row.binding().className()) && c.name().equals(row.binding().xmlCaseName())).toList();
                        if (matches.size() != 1 || !matches.get(0).outcome().equals("PASS")) throw new IOException("Passing profile result contradicts its JUnit result.");
                    }
                    var observed = data.get("observedBinding");
                    if (!observed.isJsonNull()) {
                        var binding = observed.getAsJsonObject();
                        if (!text(binding, "contextSha256").equals(contextHash) || !text(binding, "executionId").equals(row.binding().executionId())) throw new IOException("Profile result context differs.");
                        Path xml = owned(scope, scope.resolve(text(binding, "reportPath")));
                        if (!text(binding, "reportSha256").equals(LabEvidence.sha256(Files.readAllBytes(xml)))) throw new IOException("Profile XML changed.");
                        binding.addProperty("reportPath", directory.relativize(xml).toString().replace('\\', '/'));
                    } else if (text(data, "outcome").equals("PASS")) throw new IOException("Passing profile result lacks its observed binding.");
                    if (results.putIfAbsent(id, data) != null) throw new IOException("Duplicate profile result across scopes.");
                }
            }
            if (!seen.equals(expectedIds)) throw new IOException("Missing profile requirements.");
        }
        var counts = new LinkedHashMap<String, Integer>(); for (String state : List.of("PASS", "FAIL", "BLOCKED", "NOT_RUN", "INTERRUPTED", "EXCLUDED")) counts.put(state, 0);
        try (var report = new LabEvidence(directory.resolve("report-profiles.jsonl"), invocation, UUID.randomUUID())) {
            report.write("RUN_STARTED", Map.of("productionRevision", Objects.requireNonNull(revision), "artifacts", artifacts, "dependencyPins", pins.values(), "profiles", profiles,
                    "selectedRequirementIds", rows.stream().map(ScenarioCatalog.Requirement::id).toList()));
            for (var row : rows) {
                JsonObject result = results.get(row.id());
                if (row.disposition() == ScenarioCatalog.Disposition.EXCLUDED) result = excludedResult(row);
                if (result == null) throw new IOException("Missing selected profile result.");
                String outcome = text(result, "outcome"); if (!counts.containsKey(outcome)) throw new IOException("Unknown profile outcome.");
                counts.merge(outcome, 1, Integer::sum); complete &= outcome.equals("PASS") || outcome.equals("EXCLUDED"); cleaned &= text(result, "cleanup").equals("COMPLETE");
                report.write("CASE_RESULT", LabRun.JSON.fromJson(result, new com.google.gson.reflect.TypeToken<LinkedHashMap<String, Object>>(){}.getType()));
            }
            complete &= cleaned;
            report.write("RUN_COMPLETED", Map.of("outcomes", counts, "cleanupOutcome", cleaned ? "COMPLETE" : "INCOMPLETE", "remainingResources", List.of(), "complete", complete));
        }
        return complete;
    }
    private static JsonObject excludedResult(ScenarioCatalog.Requirement row) {
        var result = new JsonObject(); result.add("requirementIds", LabRun.JSON.toJsonTree(List.of(row.id()))); result.addProperty("executionId", "excluded:" + row.id());
        result.add("observedBinding", com.google.gson.JsonNull.INSTANCE); result.addProperty("caseRevision", row.revision()); result.addProperty("layer", row.layer().name());
        result.addProperty("classification", "EXCLUDED"); result.addProperty("outcome", "EXCLUDED"); result.add("expected", LabRun.JSON.toJsonTree(row.expected()));
        result.add("observed", new com.google.gson.JsonArray()); result.add("missingEvidence", new com.google.gson.JsonArray());
        result.add("timings", LabRun.JSON.toJsonTree(Map.of("startupMs", 0, "caseMs", 0, "cleanupMs", 0))); result.addProperty("cleanup", "COMPLETE"); result.add("host", com.google.gson.JsonNull.INSTANCE);
        return result;
    }
    static boolean productionInputsCurrent(JsonObject plan, Path workspace) throws IOException {
        Path auditFile = Path.of(text(plan, "auditFile"));
        owned(workspace.resolve("test/authentication-lab/build/captures"), auditFile);
        if (!text(plan, "auditSha256").equals(LabEvidence.sha256(Files.readAllBytes(auditFile)))) return false;
        var audit = read(auditFile);
        if (!text(audit, "boundaryHash").equals(text(plan, "boundaryHash")) ||
                !text(plan, "productionRevision").equals(text(audit, "head") + "+working-copy:" + text(audit, "boundaryHash"))) return false;
        Path snapshot = Path.of(text(plan, "productionRoot"));
        for (var entry : audit.getAsJsonObject("files").entrySet()) {
            // Audit paths include bapp/; productionRoot is the captured repository root.
            Path file = snapshot.resolve(entry.getKey());
            if (!Files.isRegularFile(file) || !entry.getValue().getAsString().equals(LabEvidence.sha256(Files.readAllBytes(owned(snapshot, file))))) return false;
        }
        return true;
    }
    /** Combines the existing scoped reports; it never reruns an input or promotes a failed task. */
    public static boolean collectTransportProfile(Path directory,Path workspace) throws Exception {
        directory=directory.toRealPath();workspace=workspace.toRealPath();UUID invocation=UUID.fromString(directory.getFileName().toString());
        var rows=ScenarioCatalog.load().select(List.of("transport")).requirements();
        var results=new LinkedHashMap<String,JsonObject>();var artifacts=new LinkedHashSet<Object>();var pins=new LinkedHashMap<String,Object>();
        boolean complete=true;
        String revision=null;
        for(String task:List.of(":authLabBrowserTest",":authLabTransportTest")) {
            String key=LabEvidence.sha256(task.getBytes(StandardCharsets.UTF_8));Path scope=owned(directory,directory.resolve(key));
            var context=read(owned(scope,scope.resolve("report-context.json")));
            if(!text(context,"invocationId").equals(invocation.toString())||!text(context,"taskPath").equals(task)||
                    !text(context,"configurationHash").equals(configurationFingerprint(workspace,task))||
                    !text(context,"catalogRevision").equals(LabEvidence.catalogFingerprint(workspace)))throw new IOException("Foreign or stale transport scope.");
            complete &= text(context,"state").equals("COMPLETED");
            String contextHash=LabEvidence.sha256(Files.readAllBytes(scope.resolve("report-context.json")));
            if(revision!=null&&!revision.equals(text(context,"productionRevision")))throw new IOException("Transport scopes used different production inputs.");
            revision=text(context,"productionRevision");
            var lines=Files.readAllLines(owned(scope,scope.resolve("report.jsonl")),StandardCharsets.UTF_8);
            if(lines.size()<3)throw new IOException("Incomplete transport scope stream.");
            for(int i=0;i<lines.size();i++) {
                var event=ScenarioCatalog.parseJson(lines.get(i).getBytes(StandardCharsets.UTF_8)).getAsJsonObject();
                if(!text(event,"invocationId").equals(invocation.toString()))throw new IOException("Foreign transport scope stream.");
                var data=event.getAsJsonObject("data");String type=text(event,"type");
                if(i==0) {
                    if(!type.equals("RUN_STARTED"))throw new IOException("Missing transport scope start.");
                    data.getAsJsonArray("artifacts").forEach(artifact->artifacts.add(artifact));
                    data.getAsJsonArray("dependencyPins").forEach(pin->pins.put(pin.getAsJsonObject().get("coordinates").getAsString(),pin));
                } else if(type.equals("CASE_RESULT")) {
                    String id=data.getAsJsonArray("requirementIds").get(0).getAsString();
                    if(!id.startsWith("TLS."))continue;
                    var row=rows.stream().filter(r->r.id().equals(id)).findFirst().orElseThrow();
                    if(row.disposition()==ScenarioCatalog.Disposition.EXCLUDED) {
                        if(!LabTransportEvidence.input(id).task().equals(task)||!text(data,"outcome").equals("EXCLUDED")||!data.get("observedBinding").isJsonNull()||data.getAsJsonArray("observed").size()!=0||data.getAsJsonArray("missingEvidence").size()!=0||results.putIfAbsent(id,data)!=null)throw new IOException("Invalid or duplicated excluded transport entry.");
                        continue;
                    }
                    if(!row.binding().taskPath().equals(task)||!LabEvidence.currentSources(row.binding(),workspace)||results.containsKey(id))throw new IOException("Duplicate or stale transport result.");
                    var observed=data.get("observedBinding");
                    if(!observed.isJsonNull()) {
                        var binding=observed.getAsJsonObject();
                        if(!text(binding,"contextSha256").equals(contextHash))throw new IOException("Transport result context differs.");
                        Path xml=owned(scope,scope.resolve(text(binding,"reportPath")));
                        if(!text(binding,"reportSha256").equals(LabEvidence.sha256(Files.readAllBytes(xml))))throw new IOException("Transport XML changed.");
                        binding.addProperty("reportPath",directory.relativize(xml).toString().replace('\\','/'));
                    }
                    results.put(id,data);
                }
                if(i==lines.size()-1&&!type.equals("RUN_COMPLETED"))throw new IOException("Missing transport scope completion.");
            }
        }
        if(results.size()!=rows.size())throw new IOException("Missing transport requirements in scope reports.");
        var counts=new LinkedHashMap<String,Integer>();for(String outcome:List.of("PASS","FAIL","BLOCKED","NOT_RUN","INTERRUPTED","EXCLUDED"))counts.put(outcome,0);
        boolean cleaned=true;
        try(var report=new LabEvidence(directory.resolve("report-transport.jsonl"),invocation,UUID.randomUUID())) {
            report.write("RUN_STARTED",Map.of("productionRevision",revision,"artifacts",artifacts,"dependencyPins",pins.values(),"profiles",List.of("transport"),"selectedRequirementIds",rows.stream().map(ScenarioCatalog.Requirement::id).toList()));
            for(var row:rows) {
                var result=results.get(row.id());String outcome=text(result,"outcome");counts.merge(outcome,1,Integer::sum);
                complete &= outcome.equals("PASS")||outcome.equals("EXCLUDED");cleaned &= text(result,"cleanup").equals("COMPLETE");
                report.write("CASE_RESULT",LabRun.JSON.fromJson(result,new com.google.gson.reflect.TypeToken<LinkedHashMap<String,Object>>(){}.getType()));
            }
            complete &= cleaned;
            report.write("RUN_COMPLETED",Map.of("outcomes",counts,"cleanupOutcome",cleaned?"COMPLETE":"INCOMPLETE","remainingResources",List.of(),"complete",complete));
        }
        return complete;
    }
    /** A report's actual context, source, XML, observations and cleanup must all agree. */
    public static boolean collect(Path directory, Path workspace) throws Exception {
        directory = directory.toRealPath(); workspace = workspace.toRealPath();
        var earlyContext = LabJson.read(owned(directory, directory.resolve("report-context.json")), 1_048_576);
        if (LabHostEvidence.TASK.equals(text(earlyContext, "taskPath"))) return LabHostEvidence.collect(directory, workspace);
        var plan = read(owned(directory, directory.resolve("plan.json")));
        byte[] contextBytes = Files.readAllBytes(owned(directory, directory.resolve("report-context.json")));
        var context = ScenarioCatalog.parseJson(contextBytes).getAsJsonObject();
        if (!context.keySet().equals(Set.of("contextVersion", "invocationId", "taskPath", "configurationHash", "productionRevision", "artifactSha256", "catalogRevision", "state")) || number(context, "contextVersion") != 1) throw new IOException("Invalid production report context.");
        UUID invocation = UUID.fromString(text(context, "invocationId")); String task = text(context, "taskPath");
        if (!Set.of(":authLabComponentTest", ":authLabBrowserTest",":authLabFederationTest",":authLabTransportTest").contains(task) || !directory.getParent().getFileName().toString().equals(invocation.toString()) ||
                !directory.getFileName().toString().equals(LabEvidence.sha256(task.getBytes(StandardCharsets.UTF_8))) ||
                !invocation.toString().equals(text(plan, "invocationId")) || !directory.equals(Path.of(text(plan, "reportDirectory")).toRealPath()) ||
                !text(context, "productionRevision").equals(text(plan, "productionRevision"))) throw new IOException("Foreign production report identity.");
        String configuration = configurationFingerprint(workspace, task), contextHash = LabEvidence.sha256(contextBytes);
        boolean valid = configuration.equals(text(context, "configurationHash")) && configuration.equals(text(plan, "configurationHash")) &&
                LabEvidence.catalogFingerprint(workspace).equals(text(context, "catalogRevision")) && productionInputsCurrent(plan, workspace) &&
                Set.of("COMPLETED", "FAILED").contains(text(context, "state"));
        var outputs = read(owned(directory, directory.resolve("production-outputs.json"))); var parts = new ArrayList<String>();
        Path productionRoot = Path.of(text(plan, "productionRoot"));
        for (var entry : outputs.entrySet().stream().sorted(Map.Entry.comparingByKey()).toList()) {
            Path file = productionRoot.resolve(entry.getKey());
            if (!Files.isRegularFile(file) || !file.toRealPath().startsWith(productionRoot.toRealPath()) || !entry.getValue().getAsString().equals(LabEvidence.sha256(Files.readAllBytes(file)))) valid = false;
            parts.add(entry.getKey() + ":" + entry.getValue().getAsString());
        }
        if (outputs.isEmpty() || !LabEvidence.sha256(String.join("\n", parts).getBytes(StandardCharsets.UTF_8)).equals(text(context, "artifactSha256"))) valid = false;
        var xml = LabEvidence.junitCases(directory);
        var pins = ScenarioCatalog.parseJson(Files.readAllBytes(owned(directory, directory.resolve("production-dependency-pins.json")))).getAsJsonArray();
        var coordinates = new HashSet<String>();
        for (var pin : pins) {
            var entry = pin.getAsJsonObject();
            if (!entry.keySet().equals(Set.of("coordinates", "version", "integrity")) || !coordinates.add(text(entry, "coordinates")) ||
                    !text(entry, "coordinates").matches("[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+") || !text(entry, "version").matches("[A-Za-z0-9_.+-]+") ||
                    !text(entry, "integrity").matches("sha256:[0-9a-f]{64}")) throw new IOException("Invalid production dependency evidence.");
        }
        if (pins.isEmpty()) valid = false;
        JsonObject federationCompletion=null;
        if(task.equals(":authLabFederationTest")) {
            Path completion=directory.resolve("federation-run-completion.json");
            if(Files.isRegularFile(completion))federationCompletion=read(owned(directory,completion));
            valid &= federationInputsCurrent(plan,workspace,directory)&&validFederationCompletion(federationCompletion,plan);
        }
        if(task.equals(":authLabTransportTest"))valid &= LabTransportEvidence.preparationCurrent(plan);
        var rows = ScenarioCatalog.load().requirements().stream().filter(LabProductionEvidence::supported)
                .filter(row -> LabHttpAuthenticationEvidence.supports(row.id())?LabHttpAuthenticationEvidence.task(row.id()).equals(task):row.group().startsWith("TLS.")?LabTransportEvidence.input(row.id()).task().equals(task):
                        task.equals(":authLabFederationTest")?row.group().startsWith("FED."):
                        !task.equals(":authLabTransportTest")&&!row.group().startsWith("FED.")&&(row.group().equals("BROW.fresh")||LabBrowserEvidence.supports(row.id())||row.id().equals(LabRecoveryBrowserEvidence.ID)||row.id().equals("CORE.retry.subresource-error")) == task.equals(":authLabBrowserTest")).toList();
        if (plan.has("selectedProfiles")) rows = scopedProfileRows(plan, task);
        var counts = new LinkedHashMap<String, Integer>(); for (String state : List.of("PASS", "FAIL", "BLOCKED", "NOT_RUN", "INTERRUPTED","EXCLUDED")) counts.put(state, 0);
        boolean complete = valid && text(context, "state").equals("COMPLETED"), cleanupComplete = true;
        try (var report = new LabEvidence(directory.resolve("report.jsonl"), invocation, UUID.randomUUID())) {
            report.write("RUN_STARTED", Map.of("productionRevision", text(context, "productionRevision"), "artifacts", List.of(Map.of("role", "production-classes-resources", "version", text(plan, "boundaryHash"), "sha256", text(context, "artifactSha256"))),
                    "dependencyPins", pins, "profiles", List.of(), "selectedRequirementIds", rows.stream().map(ScenarioCatalog.Requirement::id).toList()));
            for (var row : rows) {
                if(row.disposition()==ScenarioCatalog.Disposition.EXCLUDED) {
                    counts.merge("EXCLUDED",1,Integer::sum);
                    report.write("CASE_RESULT",LabRun.JSON.fromJson(excludedResult(row),new com.google.gson.reflect.TypeToken<LinkedHashMap<String,Object>>(){}.getType()));continue;
                }
                var binding = row.binding(); String outcome = "BLOCKED"; Object observedBinding = null;
                var missing = new ArrayList<>(row.evidence()); var facts = new ArrayList<ScenarioCatalog.Fact>();
                var timings = Map.of("startupMs", 0L, "caseMs", 0L, "cleanupMs", 0L); boolean cleaned = false;
                boolean current = valid && binding != null && binding.taskPath().equals(task) && binding.configurationHash().equals(configuration) &&
                        LabEvidence.currentSources(binding, workspace);
                // Binding provenance describes reviewed test sources. The invocation audit, outputs and
                // observations independently bind the production revision; source edits receive a fresh capture.
                var matches = binding == null ? List.<LabEvidence.XmlCase>of() : xml.stream().filter(c -> c.className().equals(binding.className()) && c.name().equals(binding.xmlCaseName())).toList();
                if (current && matches.size() == 1) {
                    var match = matches.getFirst();
                    var marker = java.util.regex.Pattern.compile("\\[case=([^]]+)]").matcher(match.name());
                    boolean keyMatches = binding.parameterKey() == null ? !marker.find() : marker.find() && marker.group(1).equals(binding.parameterKey()) && !marker.find();
                    if (keyMatches) {
                        if (match.outcome().equals("FAIL")) outcome = "FAIL";
                        Path capturePath = directory.resolve(task.equals(":authLabFederationTest")?"federation-observations":"component-observations").resolve(LabEvidence.sha256(row.id().getBytes(StandardCharsets.UTF_8)) + ".json");
                        JsonObject capture=null;boolean accepted=false;
                        if(row.group().startsWith("TLS.")) {
                            var transport=LabTransportEvidence.read(directory,row,context);
                            if(transport!=null){capture=new JsonObject();capture.add("observed",transport.observed());capture.add("timings",transport.timings());accepted=true;}
                        } else if (Files.isRegularFile(capturePath)) {
                            capture = read(owned(directory, capturePath));
                            accepted=validCapture(capture, row, context) &&(!task.equals(":authLabFederationTest")||
                                    text(capture.getAsJsonObject("observed"),"runtimeIdentity").equals(text(federationCompletion,"runtimeIdentity"))&&
                                    text(capture.getAsJsonObject("observed"),"runId").equals(text(federationCompletion,"runId")));
                        }
                        if(accepted) {
                                var actualTimings = capture.getAsJsonObject("timings");
                                timings = Map.of("startupMs", number(actualTimings, "startupMs"), "caseMs", number(actualTimings, "caseMs"), "cleanupMs", number(actualTimings, "cleanupMs"));
                                var actual = capture.get("observed").isJsonNull()?null:capture.getAsJsonObject("observed");
                                // Detailed safe metrics stay in the capture; formal facts use the catalog vocabulary only.
                                // Labels are earned by the owning input's assertions, never copied from expected facts.
                                var established = actual==null?List.<ScenarioCatalog.Fact>of():establishedFacts(row, actual); facts.addAll(established);
                                missing.remove("completion");
                                if(LabHttpAuthenticationEvidence.supports(row.id())&&LabHttpAuthenticationEvidence.valid(row.id(),actual)){missing.remove("browserLaunch");missing.remove("contextClose");missing.remove("resources");}
                                if (row.group().equals("BROW.fresh")) { missing.remove("browserLaunch"); missing.remove("contextClose"); }
                                if(LabBrowserEvidence.supports(row.id())&&LabBrowserEvidence.valid(row.id(),actual)){missing.remove("browserLaunch");missing.remove("contextClose");missing.remove("resources");}
                                if(row.id().equals(LabRecoveryBrowserEvidence.ID)&&LabRecoveryBrowserEvidence.valid(actual)){missing.remove("browserLaunch");missing.remove("contextClose");missing.remove("resources");}
                                if(row.group().startsWith("FED.")){missing.remove("browserLaunch");missing.remove("contextClose");missing.remove("resources");}
                                if(row.group().startsWith("TLS.")){missing.remove("browserLaunch");missing.remove("contextClose");missing.remove("resources");}
                                for (var expected : row.expected()) if (established.contains(expected)) missing.remove(expected.fact());
                                cleaned = true;
                                if (match.outcome().equals("PASS") && missing.isEmpty()) outcome = "PASS";
                        }
                        var observed = new LinkedHashMap<String, Object>();
                        observed.put("executionId", binding.executionId()); observed.put("executor", "JUNIT"); observed.put("invocationId", invocation.toString()); observed.put("taskPath", task); observed.put("configurationHash", configuration);
                        observed.put("observedClassName", match.className()); observed.put("observedCaseName", match.name()); observed.put("observedParameterKey", binding.parameterKey());
                        observed.put("bindingSha256", LabEvidence.sha256(LabRun.JSON.toJson(LabEvidence.canonical(LabRun.JSON.toJsonTree(binding))).getBytes(StandardCharsets.UTF_8)));
                        observed.put("witnessIds", binding.witnesses().stream().map(ScenarioCatalog.Witness::assertionId).toList());
                        observed.put("reportPath", directory.relativize(match.report()).toString().replace('\\', '/')); observed.put("reportSha256", LabEvidence.sha256(Files.readAllBytes(match.report()))); observed.put("contextSha256", contextHash); observed.put("outcome", outcome); observedBinding = observed;
                    }
                }
                if (!outcome.equals("PASS")) complete = false; if (!cleaned) cleanupComplete = false; counts.merge(outcome, 1, Integer::sum);
                var record = new LinkedHashMap<String, Object>();
                record.put("requirementIds", List.of(row.id())); record.put("executionId", binding == null ? "unbound:" + row.id() : binding.executionId()); record.put("observedBinding", observedBinding);
                record.put("caseRevision", row.revision()); record.put("layer", row.layer()); record.put("classification", "SUPPORTED"); record.put("outcome", outcome); record.put("expected", row.expected()); record.put("observed", facts); record.put("missingEvidence", missing);
                record.put("timings", timings); record.put("cleanup", cleaned ? "COMPLETE" : "INCOMPLETE"); record.put("host", null); report.write("CASE_RESULT", record);
            }
            report.write("RUN_COMPLETED", Map.of("outcomes", counts, "cleanupOutcome", cleanupComplete ? "COMPLETE" : "INCOMPLETE", "remainingResources", List.of(), "complete", complete));
        }
        return complete;
    }
    static String policyOutcome(JsonObject actual) {
        return actual.get("tagged").getAsBoolean() ? "native-tags-resolved-independent-of-ordinary-policy" :
                actual.get("enabled").getAsBoolean() ? "eligible-request-mutated" : "ordinary-request-unchanged";
    }
    private static boolean federationInputsCurrent(JsonObject plan,Path workspace,Path directory) throws IOException {
        var names=new HashSet<>(federationInputs(workspace));
        if(!plan.getAsJsonObject("federationInputs").keySet().equals(names)||!plan.getAsJsonObject("federationInputHashes").keySet().equals(names))return false;
        for(String name:names) {
            String hash=text(plan.getAsJsonObject("federationInputHashes"),name);
            Path retained=owned(directory,Path.of(text(plan.getAsJsonObject("federationInputs"),name)));
            if(!hash.equals(LabEvidence.sha256(Files.readAllBytes(retained)))||!hash.equals(LabEvidence.sha256(Files.readAllBytes(workspace.resolve(name)))))return false;
        }
        Path manifest=Path.of(text(plan,"federationRuntimeManifest"));
        if(!text(plan,"federationRuntimeManifestSha256").equals(LabEvidence.sha256(Files.readAllBytes(manifest))))return false;
        var runtime=read(manifest);String identity=text(runtime,"identity");
        if(!identity.matches("[a-f0-9]{64}")||!identity.equals(text(runtime,"directory")))return false;
        Path root=manifest.toRealPath().getParent().resolve(identity);var parts=new ArrayList<String>();var files=new HashSet<String>();
        for(var item:runtime.getAsJsonArray("artifacts")) {
            var artifact=item.getAsJsonObject();String file=text(artifact,"file"),hash=text(artifact,"sha256");
            if(!file.matches("[0-9]{3}-[A-Za-z0-9._-]+\\.jar")||!files.add(file))return false;
            Path path=owned(root,root.resolve(file));if(Files.size(path)!=number(artifact,"bytes")||!hash.equals(fileHash(path)))return false;
            parts.add(file+":"+hash);
        }
        return !parts.isEmpty()&&identity.equals(LabEvidence.sha256(String.join("\n",parts).getBytes(StandardCharsets.UTF_8)));
    }
    private static String fileHash(Path path) throws IOException {
        try {
            var digest=java.security.MessageDigest.getInstance("SHA-256");
            try(var input=Files.newInputStream(path)){byte[] buffer=new byte[65536];for(int n;(n=input.read(buffer))>=0;)digest.update(buffer,0,n);}
            return HexFormat.of().formatHex(digest.digest());
        }catch(java.security.NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}
    }
    static boolean validFederationCompletion(JsonObject value,JsonObject plan) {
        try {
            if(value==null||!value.keySet().equals(Set.of("version","invocationId","runId","runtimeIdentity","state","remainingResources","independentlyAbsentResources","startupMs"))
                    ||number(value,"version")!=1||!text(value,"invocationId").equals(text(plan,"invocationId"))||!text(value,"state").equals("CLOSED")||number(value,"remainingResources")!=0||number(value,"startupMs")<=0)return false;
            UUID.fromString(text(value,"runId"));
            if(!text(value,"runtimeIdentity").equals(text(read(Path.of(text(plan,"federationRuntimeManifest"))),"identity")))return false;
            String requested=plan.has("requestedTests")?text(plan,"requestedTests"):"";boolean broker=requested.isEmpty()||requested.contains("brokeredJourney")||requested.contains("*");
            int containers=0,networks=0;var ids=new HashSet<String>();
            for(var item:value.getAsJsonArray("independentlyAbsentResources")) {
                var resource=item.getAsJsonObject();String kind=text(resource,"kind"),id=text(resource,"id");
                if(!resource.keySet().equals(Set.of("kind","id"))||!id.matches("[a-f0-9]{64}")||!ids.add(id))return false;
                if(kind.equals("CONTAINER"))containers++;else if(kind.equals("NETWORK"))networks++;else return false;
            }
            return containers==(broker?2:1)&&networks==1;
        }catch(Exception incomplete){return false;}
    }
    static String federationOwner(String id) {
        if(id.equals("FED.outputs.client-cookie")||id.equals("FED.flow.backend-oidc"))return "realBackendOidcPublishesOnlyACookieAfterItsHiddenTokenReachesTheApi";
        if(id.equals("FED.flow.saml-sp"))return "realSamlPostResponseProducesAUsableClientCookieWithoutInventingAnAccessToken";
        if(id.equals("FED.negative.code-expired"))return "backendRejectionProducesAnAccurateExtensionFailure";
        if(Set.of("FED.broker.success","FED.broker.combined-outputs").contains(id))return "brokeredJourneyReturnsUsableCredentialsForTheExpectedAccount";
        if(id.equals("FED.broker.upstream-rejected"))return "brokeredJourneyReturnsNoCredentialAfterUpstreamLoginRejection";
        if(id.equals("FED.broker.cancelled"))return "brokeredJourneyCancellationClosesItsBrowserBeforeReturningPartialCredentials";
        if(id.equals("FED.flow.browser-oidc")||id.startsWith("FED.outputs.")||id.startsWith("FED.sso."))return "realBrowserOutputsAuthenticateExpectedAccountsWithFreshIssuances";
        return null;
    }
    private static boolean falseFact(JsonObject actual,String key){return actual.get(key).isJsonPrimitive()&&actual.get(key).getAsJsonPrimitive().isBoolean()&&!actual.get(key).getAsBoolean();}
    static boolean validFederationCapture(ScenarioCatalog.Requirement row,JsonObject actual) {
        try {
            String owner=federationOwner(row.id());if(owner==null||row.disposition()==ScenarioCatalog.Disposition.EXCLUDED||!owner.equals(text(actual,"ownerMethod")))return false;
            boolean browser=owner.equals("realBrowserOutputsAuthenticateExpectedAccountsWithFreshIssuances"),idp=row.id().equals("FED.outputs.idp-cookie")||row.group().equals("FED.sso")&&!row.id().endsWith("fresh-production-attempt");
            boolean backend=owner.startsWith("realBackendOidc"),saml=owner.startsWith("realSaml"),rejection=owner.equals("backendRejectionProducesAnAccurateExtensionFailure");
            boolean broker=owner.equals("brokeredJourneyReturnsUsableCredentialsForTheExpectedAccount"),cancel=row.id().equals("FED.broker.cancelled"),upstreamRejected=row.id().equals("FED.broker.upstream-rejected");
            String caseId=browser?"FED.outputs.client-cookie-plus-bearer":backend?"FED.flow.backend-oidc":saml?"FED.flow.saml-sp":broker?"FED.broker.combined-outputs":row.id();
            if(!caseId.equals(text(actual,"caseId"))||number(actual,"caseGeneration")<1||!trueFact(actual,"childJvmsClosed")||!text(actual,"runtimeIdentity").matches("[a-f0-9]{64}"))return false;
            UUID.fromString(text(actual,"runId"));
            var fields=new HashSet<>(Set.of("ownerMethod","caseId","caseGeneration","runId","attempts","verifier","childJvmsClosed","runtimeIdentity"));
            if(idp)fields.addAll(Set.of("singleSelectedCookieAccepted","missingCookieRejected","otherAccountIdentifiedSeparately","clientCookieRejectedAsIdpCookie","passwordSubmissions","clientLogoutLeavesIdpSessionUsable","productionBrowserSeeded"));
            else if(browser)fields.addAll(Set.of("protectedProofs","freshInteractiveAccounts","repeatedAccountLogins","freshAfterVerifier"));
            else if(backend)fields.addAll(Set.of("backendApiAcceptance","clientCookieAccepted","hiddenTokenReturned"));
            else if(saml)fields.addAll(Set.of("realSamlIdentityAccepted","clientCookieAccepted","oauthTokenInvented"));
            else if(rejection)fields.addAll(Set.of("validComparisonAccepted","noCredentialReturnedAfterRejection","extensionMessageMatchesAvailableObservation","simulatedFixtureFailure","providerProtocolValidationTested"));
            else if(broker)fields.addAll(Set.of("actualUpstreamPageRequired","protectedAccountsVerified","capturedOutputsPerJourney","upstreamCookieAuthenticated","providerValidationTested"));
            else if(cancel)fields.addAll(Set.of("actualClientPublicationCheckpointObserved","cancellationReturned","noPartialCredentialReturned","ownedBrowserProcessesClosed"));
            else if(upstreamRejected)fields.addAll(Set.of("validComparisonAccepted","noCredentialReturned","freshInteractiveAttempt","providerValidationTested"));
            if(!actual.keySet().equals(fields))return false;
            var attempts=actual.getAsJsonArray("attempts");int count=browser?3:backend||saml||cancel?1:2;
            if(attempts.size()!=count)return false;var contexts=new HashSet<Long>();var journeys=new HashSet<String>();
            for(int i=0;i<count;i++) {
                var attempt=attempts.get(i).getAsJsonObject();boolean failed=(rejection||upstreamRejected)&&i==count-1||cancel;
                boolean stepCancellation=cancel&&"STEP".equals(text(attempt,"failurePhase"));
                var keys=new HashSet<>(Set.of("journeyId","contexts","closedContexts","contextId","contextIdentityObserved","contextClosed","browsers","closedBrowsers","browserClosed","osProcessClosureObserved","observedProcesses","drivers","alive"));
                if(failed)keys.addAll(Set.of("failurePhase","failureCause"));
                if(stepCancellation)keys.addAll(Set.of("failedStepNumber","failedStepType"));
                if(!attempt.keySet().equals(keys)||number(attempt,"contexts")!=1||number(attempt,"browsers")!=1
                        ||number(attempt,"drivers")!=1||number(attempt,"alive")!=0||number(attempt,"observedProcesses")<2||number(attempt,"contextId")<1||!contexts.add(number(attempt,"contextId"))||!journeys.add(text(attempt,"journeyId")))return false;
                UUID.fromString(text(attempt,"journeyId"));
                for(String flag:List.of("contextIdentityObserved","osProcessClosureObserved"))if(!trueFact(attempt,flag))return false;
                long closedContexts=number(attempt,"closedContexts"),closedBrowsers=number(attempt,"closedBrowsers");
                if(cancel) {
                    if(closedContexts>1||closedBrowsers>1||
                            !(closedContexts==1?trueFact(attempt,"contextClosed"):falseFact(attempt,"contextClosed"))||
                            !(closedBrowsers==1?trueFact(attempt,"browserClosed"):falseFact(attempt,"browserClosed")))return false;
                }else if(closedContexts!=1||closedBrowsers!=1||!trueFact(attempt,"contextClosed")||!trueFact(attempt,"browserClosed"))return false;
                if(failed) {
                    if(!text(attempt,"failureCause").equals(cancel?"CANCELLED":"EXTRACTION"))return false;
                    if(stepCancellation) {
                        // Only the broker's final submit/completion wait can overlap the independently observed publication checkpoint.
                        long step=number(attempt,"failedStepNumber");String type=text(attempt,"failedStepType");
                        if(!(step==5&&type.equals("CLICK")||step==6&&type.equals("WAIT_SELECTOR")))return false;
                    }else if(!text(attempt,"failurePhase").equals("EXTRACTION"))return false;
                }
            }
            if(browser||broker) {
                var verifier=actual.getAsJsonObject("verifier");
                if(!verifier.keySet().equals(Set.of("upstream","contexts","drivers","processes","alive","missingCookieRejected","otherAccountIdentified","wrongServiceRejected","passwordSubmissions"))
                        ||!verifier.get("upstream").getAsJsonPrimitive().isBoolean()||verifier.get("upstream").getAsBoolean()!=broker
                        ||number(verifier,"contexts")!=4||number(verifier,"drivers")!=1||number(verifier,"processes")<2||number(verifier,"alive")!=0||number(verifier,"passwordSubmissions")!=0)return false;
                for(String flag:List.of("missingCookieRejected","otherAccountIdentified","wrongServiceRejected"))if(!trueFact(verifier,flag))return false;
            }else if(!actual.get("verifier").isJsonNull())return false;
            if(idp)return trueFact(actual,"singleSelectedCookieAccepted")&&trueFact(actual,"missingCookieRejected")&&trueFact(actual,"otherAccountIdentifiedSeparately")&&trueFact(actual,"clientCookieRejectedAsIdpCookie")
                    &&trueFact(actual,"clientLogoutLeavesIdpSessionUsable")&&number(actual,"passwordSubmissions")==0&&falseFact(actual,"productionBrowserSeeded");
            if(browser)return number(actual,"protectedProofs")==3&&number(actual,"freshInteractiveAccounts")==2&&number(actual,"repeatedAccountLogins")==1&&trueFact(actual,"freshAfterVerifier");
            if(backend)return trueFact(actual,"backendApiAcceptance")&&trueFact(actual,"clientCookieAccepted")&&falseFact(actual,"hiddenTokenReturned");
            if(saml)return trueFact(actual,"realSamlIdentityAccepted")&&trueFact(actual,"clientCookieAccepted")&&falseFact(actual,"oauthTokenInvented");
            if(rejection)return trueFact(actual,"validComparisonAccepted")&&trueFact(actual,"noCredentialReturnedAfterRejection")&&trueFact(actual,"extensionMessageMatchesAvailableObservation")&&trueFact(actual,"simulatedFixtureFailure")&&falseFact(actual,"providerProtocolValidationTested");
            if(broker)return trueFact(actual,"actualUpstreamPageRequired")&&number(actual,"protectedAccountsVerified")==2&&number(actual,"capturedOutputsPerJourney")==3&&trueFact(actual,"upstreamCookieAuthenticated")&&falseFact(actual,"providerValidationTested");
            if(cancel)return trueFact(actual,"actualClientPublicationCheckpointObserved")&&trueFact(actual,"cancellationReturned")&&trueFact(actual,"noPartialCredentialReturned")&&trueFact(actual,"ownedBrowserProcessesClosed");
            return upstreamRejected&&trueFact(actual,"validComparisonAccepted")&&trueFact(actual,"noCredentialReturned")&&trueFact(actual,"freshInteractiveAttempt")&&falseFact(actual,"providerValidationTested");
        }catch(RuntimeException malformed){return false;}
    }
    private static List<ScenarioCatalog.Fact> federationFacts(ScenarioCatalog.Requirement row,JsonObject actual) {
        if(!validFederationCapture(row,actual))return List.of();
        String outcome=switch(row.group()) {
            case "FED.flow"->"real-provider-protocol-completes-and-available-output-authenticates";
            case "FED.outputs"->"selected-output-authenticates-its-own-service-and-expected-identity";
            case "FED.negative"->"backend-rejection-no-credential-and-no-invented-connection-error";
            case "FED.sso"->"Explicit cookie proof identifies actual user without password; fresh production attempt does not inherit it.";
            case "FED.broker"->Set.of("FED.broker.success","FED.broker.combined-outputs").contains(row.id())?"full-two-provider-chain-and-available-output-authenticates":"bounded-failure-no-output-and-owned-resources-closed";
            default->throw new IllegalArgumentException("Uninspected federation fact.");
        };
        return List.of(new ScenarioCatalog.Fact("outcome",outcome));
    }
    static boolean supported(ScenarioCatalog.Requirement row) {
        return row.layer()==ScenarioCatalog.Layer.HOST && row.binding()!=null && row.binding().executor().equals("HOST") || LabHttpAuthenticationEvidence.supports(row.id())||LabConfigurationEvidence.supports(row.id())||LabResourceEvidence.supports(row.id())||LabInjectionEvidence.supports(row.id())||LabTagFailureEvidence.supports(row.id())||LabLimitEvidence.supports(row.id())||row.id().equals("CORE.tag-failure.output-contains-tag")||LabTagSelectionEvidence.supports(row.id())||LabEncodingEvidence.supports(row.id())||LabOutputEvidence.supports(row.id())||LabLifetimeEvidence.supports(row.id())||row.id().equals(LabRecoveryBrowserEvidence.ID)||LabRetryEvidence.supports(row.id())||LabBrowserEvidence.supports(row.id())||row.group().startsWith("TLS.")||row.group().startsWith("FED.")||Set.of("CORE.tool-policy", "CORE.tag-matrix", "CORE.recovery", "BROW.fresh").contains(row.group()) || row.id().equals("CORE.encoding.literal-prefix") || diagnosticSpec(row) != null;
    }
    static List<ScenarioCatalog.Fact> establishedFacts(ScenarioCatalog.Requirement row, JsonObject actual) {
        if(LabHttpAuthenticationEvidence.supports(row.id()))return LabHttpAuthenticationEvidence.facts(row.id(),actual);
        if(LabConfigurationEvidence.supports(row.id()))return LabConfigurationEvidence.facts(row.id(),actual);
        if(LabResourceEvidence.supports(row.id()))return LabResourceEvidence.facts(row.id(),actual);
        if(LabInjectionEvidence.supports(row.id()))return LabInjectionEvidence.facts(row.id(),actual);
        if(LabTagFailureEvidence.supports(row.id()))return LabTagFailureEvidence.facts(row.id(),actual);
        if(LabLimitEvidence.supports(row.id()))return LabLimitEvidence.facts(row,actual);
        if(row.id().equals("CORE.tag-failure.output-contains-tag"))return List.of(new ScenarioCatalog.Fact("outcome","source-looking-output-inserted-literally-without-recursive-acquisition"));
        if(LabTagSelectionEvidence.supports(row.id()))return LabTagSelectionEvidence.facts(row.id(),actual);
        if(LabEncodingEvidence.supports(row.id()))return LabEncodingEvidence.facts(row.id(),actual);
        if(LabOutputEvidence.supports(row.id()))return LabOutputEvidence.facts(row.id(),actual);
        if(LabLifetimeEvidence.supports(row.id()))return LabLifetimeEvidence.facts(row.id(),actual);
        if(row.id().equals(LabRecoveryBrowserEvidence.ID))return LabRecoveryBrowserEvidence.facts(actual);
        if(LabRetryEvidence.supports(row.id()))return LabRetryEvidence.facts(row.id(),actual);
        if(LabBrowserEvidence.supports(row.id()))return LabBrowserEvidence.facts(row.id(),actual);
        if(row.group().startsWith("TLS."))return LabTransportEvidence.facts(row.id(),actual);
        if(row.group().startsWith("FED."))return federationFacts(row,actual);
        if (row.group().equals("BROW.fresh")) return List.of(new ScenarioCatalog.Fact("state", "positive-prime-A-and-absent-probe-B-before-login-same-saved-definition"),
                new ScenarioCatalog.Fact("resources", "actual-A-context-close-and-distinct-B-context"),
                new ScenarioCatalog.Fact("outcome", "both-fresh-outputs-authenticate-and-B-has-no-A-browser-state"));
        if (row.group().equals("CORE.recovery")) {
            String trigger = text(actual, "trigger");
            boolean quiet = Set.of("no-match", "disabled", "success", "original-timeout").contains(trigger);
            boolean paused = Set.of("replacement-rejected", "replay-once", "acquisition-failed").contains(trigger);
            var facts = new ArrayList<ScenarioCatalog.Fact>();
            facts.add(new ScenarioCatalog.Fact("attempts", "at-most-three-including-initial"));
            facts.add(new ScenarioCatalog.Fact("replays", quiet ? "0" : "at-most-one-per-original"));
            facts.add(new ScenarioCatalog.Fact("outcome", quiet ? "no-recovery-or-replay" : paused ? "paused-after-bounded-failed-recovery" : "shared-recovery-and-single-replay-per-original"));
            if (paused) facts.add(new ScenarioCatalog.Fact("state", "PAUSED"));
            if (trigger.equals("post-action")) facts.add(new ScenarioCatalog.Fact("actions", Long.toString(number(actual, "actions"))));
            return List.copyOf(facts);
        }
        if (row.group().equals("CORE.tool-policy")) return List.of(new ScenarioCatalog.Fact("outcome", policyOutcome(actual)));
        if (row.group().equals("CORE.tag-matrix")) return List.of(new ScenarioCatalog.Fact("outcome", "complete-byte-exact-plan-with-declared-location-encoding-reference-count"),
                new ScenarioCatalog.Fact("publication", "one-snapshot-per-journey"));
        if (row.id().equals("CORE.encoding.literal-prefix")) return List.of(new ScenarioCatalog.Fact("outcome", "exact-independently-calculated-encoded-bytes-and-unrelated-bytes-preserved"));
        var spec = diagnosticSpec(row);
        if (spec != null) {
            var facts = new ArrayList<ScenarioCatalog.Fact>();
            boolean channels = trueFact(actual, "summaryMatches") && trueFact(actual, "detailsMatch") && trueFact(actual, "stateMatches");
            if(row.id().equals("CORE.diagnostics.step-target-missing"))channels&=trueFact(actual,"stepAttributionMatches")&&trueFact(actual,"stepLinkCurrent")&&trueFact(actual,"stepLinkRetired");
            if (!diagnosticSuccess(row)) channels &= trueFact(actual, "requestFeedbackMatches") && trueFact(actual, "noPartialPublication");
            if (channels) {
                facts.add(new ScenarioCatalog.Fact("stage", spec.stage())); facts.add(new ScenarioCatalog.Fact("cause", spec.cause()));
                if (trueFact(actual, "requiredMessageMatches")) facts.add(new ScenarioCatalog.Fact("requiredMessageFact", spec.required()));
                if (trueFact(actual, "forbiddenClaimAbsent")) facts.add(new ScenarioCatalog.Fact("forbiddenMessageClaim", spec.forbidden()));
            }
            if (trueFact(actual, "currentRevision")) facts.add(new ScenarioCatalog.Fact("currentRevision", "current-attempt-only"));
            if (trueFact(actual, "redacted")) facts.add(new ScenarioCatalog.Fact("redaction", "no-secrets-or-sensitive-urls"));
            if(row.id().equals("CORE.diagnostics.attempts-exhausted")&&number(actual,"attempts")==3&&text(actual,"state").equals("PAUSED")){facts.add(new ScenarioCatalog.Fact("attempts","3"));facts.add(new ScenarioCatalog.Fact("state","PAUSED"));}
            return List.copyOf(facts);
        }
        return List.of();
    }
    private static boolean trueFact(JsonObject actual, String key) {
        return actual.get(key).isJsonPrimitive() && actual.get(key).getAsJsonPrimitive().isBoolean() && actual.get(key).getAsBoolean();
    }
    /** Only inspected component inputs are supported here; other groups stay unbound. */
    static boolean validCapture(JsonObject capture, ScenarioCatalog.Requirement row, JsonObject context) {
        if (!capture.keySet().equals(Set.of("version", "invocationId", "requirementId", "taskPath", "productionRevision", "observed", "cleanup", "configurationHash", "timings")) || number(capture, "version") != 2 ||
                !text(context, "invocationId").equals(text(capture, "invocationId")) || !row.id().equals(text(capture, "requirementId")) ||
                !text(context, "taskPath").equals(text(capture, "taskPath")) || !text(context, "productionRevision").equals(text(capture, "productionRevision")) ||
                !text(context, "configurationHash").equals(text(capture, "configurationHash")) || !text(capture, "cleanup").equals("COMPLETE")) return false;
        var timings = capture.getAsJsonObject("timings");
        if (!timings.keySet().equals(Set.of("startupMs", "caseMs", "cleanupMs"))) return false;
        for (String key : timings.keySet()) number(timings, key);
        var actual = capture.getAsJsonObject("observed");
        if(LabHttpAuthenticationEvidence.supports(row.id()))return text(context,"taskPath").equals(LabHttpAuthenticationEvidence.task(row.id()))&&LabHttpAuthenticationEvidence.valid(row.id(),actual);
        if(LabConfigurationEvidence.supports(row.id()))return text(context,"taskPath").equals(":authLabComponentTest")&&LabConfigurationEvidence.valid(row.id(),actual);
        if(LabResourceEvidence.supports(row.id()))return text(context,"taskPath").equals(":authLabComponentTest")&&LabResourceEvidence.valid(row.id(),actual);
        if(LabInjectionEvidence.supports(row.id()))return text(context,"taskPath").equals(":authLabComponentTest")&&LabInjectionEvidence.valid(row.id(),actual);
        if(LabTagFailureEvidence.supports(row.id()))return text(context,"taskPath").equals(":authLabComponentTest")&&LabTagFailureEvidence.valid(row.id(),actual);
        if(LabLimitEvidence.supports(row.id()))return text(context,"taskPath").equals(":authLabComponentTest")&&LabLimitEvidence.valid(row,actual);
        if(LabTagSelectionEvidence.supports(row.id()))return text(context,"taskPath").equals(":authLabComponentTest")&&LabTagSelectionEvidence.valid(row.id(),actual);
        if(LabEncodingEvidence.supports(row.id()))return text(context,"taskPath").equals(":authLabComponentTest")&&LabEncodingEvidence.valid(row.id(),actual);
        if(LabOutputEvidence.supports(row.id()))return text(context,"taskPath").equals(":authLabComponentTest")&&LabOutputEvidence.valid(row.id(),actual);
        if(LabLifetimeEvidence.supports(row.id()))return text(context,"taskPath").equals(":authLabComponentTest")&&LabLifetimeEvidence.valid(row.id(),actual);
        if(row.id().equals(LabRecoveryBrowserEvidence.ID))return text(context,"taskPath").equals(":authLabBrowserTest")&&LabRecoveryBrowserEvidence.valid(actual);
        if(LabRetryEvidence.supports(row.id()))return text(context,"taskPath").equals(row.id().equals("CORE.retry.subresource-error")?":authLabBrowserTest":":authLabComponentTest")&&LabRetryEvidence.valid(row.id(),actual);
        if(row.group().startsWith("FED."))return text(context,"taskPath").equals(":authLabFederationTest")&&validFederationCapture(row,actual);
        if(LabBrowserEvidence.supports(row.id()))return text(context,"taskPath").equals(":authLabBrowserTest")&&LabBrowserEvidence.valid(row.id(),actual);
        if (row.group().equals("BROW.fresh") != text(context, "taskPath").equals(":authLabBrowserTest")) return false;
        if (row.group().equals("BROW.fresh")) {
            if (!actual.keySet().equals(Set.of("sameDefinition", "firstAccount", "secondAccount", "differentIssuance", "differentToken", "primeSequence", "firstLoginSequence", "probeSequence", "secondLoginSequence",
                    "firstContext", "secondContext", "firstClosedBeforeSecond", "closedContexts", "openedBrowsers", "closedBrowsers", "drivers", "processes", "alive"))) return false;
            return trueFact(actual, "sameDefinition") && trueFact(actual, "differentIssuance") && trueFact(actual, "differentToken") && trueFact(actual, "firstClosedBeforeSecond")
                    && text(actual, "firstAccount").equals("user2") && text(actual, "secondAccount").equals("user2")
                    && number(actual, "primeSequence") > 0 && number(actual, "firstLoginSequence") > number(actual, "primeSequence")
                    && number(actual, "probeSequence") > number(actual, "firstLoginSequence") && number(actual, "secondLoginSequence") > number(actual, "probeSequence")
                    && number(actual, "firstContext") > 0 && number(actual, "secondContext") > number(actual, "firstContext")
                    && number(actual, "closedContexts") == 2 && number(actual, "openedBrowsers") == 2 && number(actual, "closedBrowsers") == 2
                    && number(actual, "drivers") == 2 && number(actual, "processes") > 2 && number(actual, "alive") == 0;
        }
        if (row.group().equals("CORE.recovery")) {
            if (!actual.keySet().equals(Set.of("trigger", "tagged", "combined", "originals", "recoveryAttempts", "replays", "protectedProofs", "actions", "bytesMatch", "waitingRequests", "state"))) return false;
            var axes = new HashMap<String, String>(); row.axes().forEach(a -> axes.put(a.name(), a.value()));
            String trigger = axes.get("trigger"); int originals = Integer.parseInt(axes.get("originals"));
            boolean quiet = Set.of("no-match", "disabled", "success", "original-timeout").contains(trigger);
            boolean rejected = Set.of("replacement-rejected", "replay-once").contains(trigger), failed = trigger.equals("acquisition-failed");
            for (String key : List.of("tagged", "combined", "bytesMatch")) if (!actual.get(key).isJsonPrimitive() || !actual.get(key).getAsJsonPrimitive().isBoolean()) return false;
            return text(actual, "trigger").equals(trigger) && actual.get("tagged").getAsBoolean() == axes.get("requestMode").equals("tagged")
                    && actual.get("combined").getAsBoolean() == axes.get("outputs").equals("combined") && number(actual, "originals") == originals
                    && number(actual, "recoveryAttempts") == (quiet ? 0 : failed ? 3 : 1)
                    && number(actual, "replays") == (quiet || failed ? 0 : rejected ? 1 : originals)
                    && number(actual, "protectedProofs") == (quiet || failed || rejected ? 0 : originals)
                    && number(actual, "actions") == (trigger.equals("post-action") ? originals : 0)
                    && trueFact(actual, "bytesMatch") && number(actual, "waitingRequests") == 0
                    && text(actual, "state").equals(rejected || failed ? "PAUSED" : "READY");
        }
        var diagnostic = diagnosticSpec(row);
        if (diagnostic != null) {
            var fields = new HashSet<>(Set.of("nativePhase", "nativeCause", "summaryMatches", "detailsMatch", "stateMatches", "currentRevision", "requiredMessageMatches", "forbiddenClaimAbsent", "redacted"));
            boolean success = diagnosticSuccess(row);
            if (success) fields.add("protectedUseVerified"); else fields.addAll(Set.of("requestFeedbackMatches", "noPartialPublication"));
            if(row.id().equals("CORE.diagnostics.step-target-missing"))fields.addAll(Set.of("stepAttributionMatches","stepLinkCurrent","stepLinkRetired"));
            if(row.id().equals("CORE.diagnostics.attempts-exhausted"))fields.addAll(Set.of("attempts","state"));
            if (!actual.keySet().equals(fields) || !text(actual, "nativePhase").equals(diagnostic.phase()) || !text(actual, "nativeCause").equals(diagnostic.nativeCause())) return false;
            for (String field : fields) if (!Set.of("nativePhase", "nativeCause","attempts","state").contains(field) && (!actual.get(field).isJsonPrimitive() || !actual.get(field).getAsJsonPrimitive().isBoolean())) return false;
            if(row.id().equals("CORE.diagnostics.attempts-exhausted")&&(number(actual,"attempts")!=3||!text(actual,"state").equals("PAUSED")))return false;
            // False semantic flags are retained as missing facts/FAIL, never converted into passing evidence.
            return !success || !actual.get("protectedUseVerified").getAsBoolean();
        }
        if (row.group().equals("CORE.tag-matrix")) {
            if (!actual.keySet().equals(Set.of("location", "mode", "references", "plans", "bytesMatch", "snapshotVersionsMatch", "cachedBytesMatch", "extraAttemptsOnCacheUse", "attempts", "usedSnapshots", "waitingRequests"))) return false;
            var axes = new HashMap<String, String>(); row.axes().forEach(a -> axes.put(a.name(), a.value()));
            int references = Integer.parseInt(axes.get("references")), snapshots = references == 1 ? 1 : references + 1;
            return text(actual, "location").equals(axes.get("location")) && text(actual, "mode").equals(axes.get("mode")) && number(actual, "references") == references &&
                    number(actual, "plans") == (references == 1 ? 1 : 2) && number(actual, "attempts") == snapshots && number(actual, "usedSnapshots") == snapshots &&
                    number(actual, "extraAttemptsOnCacheUse") == 0 && number(actual, "waitingRequests") == 0 &&
                    trueFact(actual, "bytesMatch") && trueFact(actual, "snapshotVersionsMatch") && trueFact(actual, "cachedBytesMatch");
        }
        if (row.id().equals("CORE.encoding.literal-prefix")||row.id().equals("CORE.tag-failure.output-contains-tag")) {
            return actual.keySet().equals(Set.of("wrapperBytesMatch", "literalBytesMatch", "wrapperAttempts", "outputAttempts", "waitingRequests")) &&
                    trueFact(actual, "wrapperBytesMatch") && trueFact(actual, "literalBytesMatch") && number(actual, "wrapperAttempts") == 0 &&
                    number(actual, "outputAttempts") == 1 && number(actual, "waitingRequests") == 0;
        }
        if (!row.group().equals("CORE.tool-policy")) return false;
        if (!actual.keySet().equals(Set.of("tool", "urlMode", "enabled", "tagged", "policyChecks", "attempts", "waitingRequests", "bytesMatch", "continued", "urlHelperCalls"))) return false;
        var axes = new HashMap<String, String>(); row.axes().forEach(a -> axes.put(a.name(), a.value()));
        boolean tagged = Boolean.parseBoolean(axes.get("tagged")), enabled = Boolean.parseBoolean(axes.get("enabled"));
        return text(actual, "tool").equals(axes.get("tool").toUpperCase(Locale.ROOT)) && text(actual, "urlMode").equals(axes.get("urlMode").toUpperCase(Locale.ROOT)) &&
                actual.get("enabled").isJsonPrimitive() && actual.get("enabled").getAsJsonPrimitive().isBoolean() && actual.get("enabled").getAsBoolean() == enabled &&
                actual.get("tagged").isJsonPrimitive() && actual.get("tagged").getAsJsonPrimitive().isBoolean() && actual.get("tagged").getAsBoolean() == tagged &&
                number(actual, "policyChecks") == 4 && number(actual, "attempts") == (tagged || enabled ? 1 : 0) && number(actual, "waitingRequests") == 0 &&
                actual.get("bytesMatch").getAsJsonPrimitive().isBoolean() && actual.get("bytesMatch").getAsBoolean() &&
                actual.get("continued").getAsJsonPrimitive().isBoolean() && actual.get("continued").getAsBoolean() && (!tagged || enabled || number(actual, "urlHelperCalls") == 0);
    }
}
