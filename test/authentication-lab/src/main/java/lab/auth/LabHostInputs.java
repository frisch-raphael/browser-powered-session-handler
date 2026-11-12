package lab.auth;

import com.google.gson.*;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import static lab.auth.LabJson.*;

/** Closed host/guest plans. Private VM configuration never enters public evidence. */
public final class LabHostInputs {
    private LabHostInputs() {}
    public static final List<String> PLATFORMS = List.of("windows", "linux");
    public static final List<String> SCENARIOS = List.of("routing", "tags", "repeater", "http-auth", "recovery",
            "rejected-replay", "intercept", "unload", "ordinary-failure");
    public enum Mode { ACCEPTANCE, QUALIFICATION }
    public record Options(String command, Map<String,String> values) {
        public Options { values = Map.copyOf(values); }
        public Path path(String name) { return Path.of(values.get(name)).toAbsolutePath().normalize(); }
        public String platform() { return values.getOrDefault("--platform", "both"); }
        public String stage() { return values.getOrDefault("--stage", "scenarios"); }
    }
    public record Artifact(Path path, String sha256, long bytes, String role) {
        public JsonObject json(String pathValue) {
            var result = new JsonObject(); result.addProperty("path", pathValue); result.addProperty("sha256", sha256);
            result.addProperty("bytes", bytes); if (role != null) result.addProperty("role", role); return result;
        }
        public void verify() throws IOException {
            require(Files.isRegularFile(path) && Files.size(path) == bytes && LabJson.sha256(path).equals(sha256), "ARTIFACT_CHANGED");
        }
    }
    public record Plan(UUID invocationId, Mode mode, List<String> platforms, String taskPath, String configurationHash,
                       String catalogRevision, String sourceRevision, String head, Map<String,String> sourceHashes,
                       Artifact audit, Artifact product, Artifact helper, List<Artifact> runtime, Artifact scenarios,
                       Path captureDirectory) {
        public Plan { platforms = List.copyOf(platforms); sourceHashes = Map.copyOf(sourceHashes); runtime = List.copyOf(runtime); }
        public List<Artifact> artifacts() {
            var result = new ArrayList<>(List.of(audit, product, helper, scenarios)); result.addAll(runtime); return List.copyOf(result);
        }
    }
    public record Vm(String platform, Path helper, String guestRoot, String java, String labJava, String burpJar,
                     String approvedPreferences, String display) {}

    public static Options options(String[] args) {
        require(args.length > 0 && args.length % 2 == 1, "HOST_ARGUMENTS");
        String command = args[0]; require(Set.of("host-test", "host-qualify", "host-guest").contains(command), "HOST_COMMAND");
        var required = command.equals("host-guest") ? Set.of("--plan", "--report-directory") :
                Set.of("--workspace", "--report-directory", "--artifact", "--vm-config", "--plan");
        var allowed = new HashSet<>(required);
        if (command.equals("host-qualify")) allowed.addAll(Set.of("--platform", "--stage"));
        var values = new LinkedHashMap<String,String>();
        for (int i = 1; i < args.length; i += 2) {
            require(allowed.contains(args[i]) && !args[i+1].isBlank() && values.putIfAbsent(args[i], args[i+1]) == null, "HOST_ARGUMENTS");
        }
        require(values.keySet().containsAll(required), "HOST_MISSING_ARGUMENT");
        require(Set.of("windows", "linux", "both").contains(values.getOrDefault("--platform", "both")), "HOST_PLATFORM");
        require(Set.of("primitives", "scenarios").contains(values.getOrDefault("--stage", "scenarios")), "HOST_STAGE");
        return new Options(command, values);
    }

    public static Plan plan(Path path) throws IOException {
        var json = object(read(path, 1_048_576), "version", "invocationId", "mode", "platforms", "taskPath",
                "configurationHash", "catalogRevision", "sourceRevision", "head", "sourceHashes", "audit", "product",
                "helper", "runtime", "scenarios", "captureDirectory");
        version(json); var id = uuid(json.get("invocationId"));
        var mode = Mode.valueOf(member(json.get("mode"), "ACCEPTANCE", "QUALIFICATION"));
        var platforms = platforms(json.get("platforms"), mode);
        String task = text(json, "taskPath");
        require(task.equals(mode == Mode.ACCEPTANCE ? ":authLabHostTest" : ":authLabHostQualify"), "HOST_TASK");
        Path root = Path.of(text(json, "captureDirectory")); require(root.isAbsolute(), "HOST_CAPTURE_PATH"); root = root.toRealPath();
        require(root.getFileName().toString().equals("capture") && root.getParent().getFileName().toString().equals(id.toString()), "HOST_CAPTURE_OWNER");
        String head = text(json, "head"); require(head.matches("[0-9a-f]{40}|[0-9a-f]{64}"), "HOST_HEAD");
        var hashes = new TreeMap<String,String>();
        object(json.get("sourceHashes")).entrySet().forEach(e -> hashes.put(relative(new JsonPrimitive(e.getKey())), hash(e.getValue())));
        require(!hashes.isEmpty(), "HOST_SOURCE_INVENTORY");
        var artifacts = new ArrayList<Artifact>(); var identities = new HashSet<String>();
        require(json.get("runtime").isJsonArray(), "HOST_RUNTIME");
        for (var entry : json.getAsJsonArray("runtime")) {
            var artifact = artifact(entry, root, true);
            require(identities.add(artifact.role() + ":" + artifact.path()), "HOST_DUPLICATE_RUNTIME"); artifacts.add(artifact);
        }
        require(artifacts.stream().anyMatch(a -> a.role().equals("LAB")) && artifacts.stream().anyMatch(a -> a.role().equals("EXPORTER")), "HOST_RUNTIME_ROLES");
        var result = new Plan(id, mode, platforms, task, hash(json.get("configurationHash")), hash(json.get("catalogRevision")),
                hash(json.get("sourceRevision")), head, hashes, artifact(json.get("audit"), root, false),
                artifact(json.get("product"), root, false), artifact(json.get("helper"), root, false), artifacts,
                artifact(json.get("scenarios"), root, false), root);
        var audit = read(result.audit().path(), 1_048_576);
        require(text(audit, "boundaryHash").equals(result.sourceRevision()) && text(audit, "head").equals(head), "HOST_AUDIT_IDENTITY");
        var auditHashes = new TreeMap<String,String>();
        object(audit.get("files")).entrySet().forEach(e -> auditHashes.put(e.getKey(), hash(e.getValue())));
        require(auditHashes.equals(hashes), "HOST_AUDIT_SOURCES");
        inventory(read(result.scenarios().path(),65536)); return result;
    }
    private static Artifact artifact(JsonElement element, Path root, boolean runtime) throws IOException {
        var json = runtime ? object(element, "path", "sha256", "bytes", "role") : object(element, "path", "sha256", "bytes");
        Path path = Path.of(text(json, "path"));
        require(path.isAbsolute() && path.toRealPath().startsWith(root), "HOST_ARTIFACT_PATH");
        var result = new Artifact(path.toRealPath(), hash(json.get("sha256")), positive(json.get("bytes")),
                runtime ? member(json.get("role"), "LAB", "EXPORTER") : null);
        result.verify(); return result;
    }
    public static Map<String,Vm> vmConfig(Path path) throws IOException {
        var helpers = new HashMap<String,Path>();
        for(String platform:PLATFORMS)helpers.put(platform,Path.of(System.getProperty("user.home"),"orca","vm-tests",
                "bpsh-"+platform+"-20261106",platform.equals("linux")?"vm.py":"guest.py"));
        return vmConfig(path,helpers);
    }
    static Map<String,Vm> vmConfig(Path path, Map<String,Path> expectedHelpers) throws IOException {
        var json = object(read(path, 64 * 1024), "version", "windows", "linux"); version(json);
        var result = new LinkedHashMap<String,Vm>();
        for (String platform : PLATFORMS) {
            var vm = platform.equals("linux") ? object(json.get(platform), "helper", "guestRoot", "java", "labJava", "burpJar", "approvedPreferences", "display") :
                    object(json.get(platform), "helper", "guestRoot", "java", "labJava", "burpJar", "approvedPreferences");
            Path helper = Path.of(text(vm, "helper")).toRealPath();
            Path expected = expectedHelpers.get(platform); require(expected != null,"HOST_HELPER_IDENTITY");
            require(Files.isRegularFile(helper) && Files.isSameFile(helper, expected), "HOST_HELPER_IDENTITY");
            String root = guestAbsolute(text(vm, "guestRoot"), platform);
            String java = guestAbsolute(text(vm, "java"), platform), burp = guestAbsolute(text(vm, "burpJar"), platform);
            String labJava = guestAbsolute(text(vm,"labJava"),platform);
            String preferences = guestAbsolute(text(vm, "approvedPreferences"), platform);
            String normalized = root.replace('\\','/').replaceAll("/+$", "");
            require(normalized.split("/").length >= 3 && !Set.of("/home/tester", "C:/Users/tester", "C:/Program Files/BurpSuite").contains(normalized), "HOST_GUEST_ROOT");
            require(!isUnder(java, root, platform) && !isUnder(labJava,root,platform) && !isUnder(burp, root, platform) && !isUnder(preferences, root, platform), "HOST_PREREQUISITE_INSIDE_ROOT");
            String display = platform.equals("linux") ? text(vm, "display") : null;
            require(display == null || display.matches(":\\d{1,3}(?:\\.\\d)?"), "HOST_DISPLAY");
            result.put(platform, new Vm(platform, helper, root, java, labJava, burp, preferences, display));
        }
        return Map.copyOf(result);
    }
    static Map<String,List<String>> inventory(JsonObject json) {
        object(json,"version","platforms","scenarios","requirements"); version(json);
        require(strings(json.get("platforms")).equals(PLATFORMS)&&strings(json.get("scenarios")).equals(SCENARIOS),"HOST_SCENARIO_INVENTORY");
        require(json.get("requirements").isJsonArray()&&json.getAsJsonArray("requirements").size()==12,"HOST_REQUIREMENT_INVENTORY");
        var result = new LinkedHashMap<String,List<String>>(); var catalog = ScenarioCatalog.load();
        for(var entry:json.getAsJsonArray("requirements")) {
            var row=object(entry,"id","scenarios","protocol"); String id=text(row,"id");
            require(catalog.requirement(id).layer()==ScenarioCatalog.Layer.HOST,"HOST_REQUIREMENT_LAYER");
            var cases=strings(row.get("scenarios")); require(!cases.isEmpty()&&SCENARIOS.containsAll(cases)&&result.putIfAbsent(id,cases)==null,"HOST_REQUIREMENT_CASES");
            if(!row.get("protocol").isJsonNull()) {
                String protocol=member(row.get("protocol"),"BASIC","NTLM_V1","NTLM_V2");
                require(id.equals("HOST.http-auth."+switch(protocol){case "BASIC"->"basic";case "NTLM_V1"->"ntlm-v1";default->"ntlm-v2";})
                        &&cases.equals(List.of("http-auth")),"HOST_PROTOCOL_REQUIREMENT");
            }else require(!id.startsWith("HOST.http-auth."),"HOST_MISSING_PROTOCOL");
        }
        require(new HashSet<>(result.values().stream().flatMap(List::stream).toList()).equals(new HashSet<>(SCENARIOS)),"HOST_MISSING_SCENARIO");
        return Collections.unmodifiableMap(result);
    }
    static String guestAbsolute(String value, String platform) {
        require(value.chars().noneMatch(c -> c < 32 || c == 127), "HOST_GUEST_PATH");
        String normalized = value.replace('\\','/');
        require(platform.equals("windows") ? normalized.matches("[A-Za-z]:/.*") : normalized.startsWith("/"), "HOST_GUEST_PATH");
        require(Arrays.stream(normalized.split("/")).noneMatch(p -> p.equals("..") || p.equals(".")), "HOST_GUEST_PATH");
        return platform.equals("windows")?normalized.replace('/','\\'):normalized;
    }
    private static boolean isUnder(String path, String root, String platform) {
        String p = path.replace('\\','/'), r = root.replace('\\','/').replaceAll("/+$", "");
        if (platform.equals("windows")) { p = p.toLowerCase(Locale.ROOT); r = r.toLowerCase(Locale.ROOT); }
        return p.equals(r) || p.startsWith(r + "/");
    }
    static List<String> platforms(JsonElement value, Mode mode) {
        var result = strings(value); require(!result.isEmpty() && PLATFORMS.containsAll(result), "HOST_PLATFORMS");
        require(PLATFORMS.stream().filter(result::contains).toList().equals(result), "HOST_PLATFORM_ORDER");
        require(mode != Mode.ACCEPTANCE || result.equals(PLATFORMS), "HOST_ACCEPTANCE_PLATFORMS"); return result;
    }
    static void version(JsonObject json) { require(positive(json.get("version")) == 1, "HOST_VERSION"); }
}
