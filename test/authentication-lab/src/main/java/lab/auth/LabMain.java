package lab.auth;

import java.io.PrintStream;
import java.net.*;
import java.net.http.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;

/** Standalone target lifecycle and metadata. Production test execution stays separately gated. */
public final class LabMain {
    private LabMain() {}
    public static void main(String[] args) { System.exit(run(args, System.out, System.err)); }

    public static int run(String[] args, PrintStream out, PrintStream err) {
        if(args.length>0&&Set.of("host-test","host-qualify","host-guest").contains(args[0]))return LabHostCoordinator.runCommand(args,out,err);
        try {
            if (args.length == 0 || args[0].equals("help")) {
                out.println("Usage: matrix|doctor|run|serve|reset|stop|prepare-case|components --profiles baseline[,browser,...] [--run UUID] [--case ID] [--environment-root PATH]");
                out.println("serve starts foreground controlled targets. reset/stop use a private owned descriptor; keys are never printed.");
                out.println("host-test|host-qualify use captured --plan, --workspace, --artifact, --vm-config and --report-directory; host-guest accepts only --plan and --report-directory.");
                return 0;
            }
            if (args.length % 2 != 1) { err.println("Invalid arguments. Use help."); return 2; }
            var options = new LinkedHashMap<String, String>();
            for (int i = 1; i < args.length; i += 2) if (!Set.of("--profiles", "--run", "--case", "--environment-root", "--report-directory", "--workspace", "--artifact").contains(args[i]) || options.putIfAbsent(args[i], args[i + 1]) != null) { err.println("Unknown or duplicate argument."); return 2; }
            if (!Set.of("matrix", "doctor", "run", "serve", "reset", "stop", "prepare-case", "components", "collect-fixtures", "collect-components", "collect-transport-profile", "collect-profiles").contains(args[0])) {
                err.println("Unknown command. Use help."); return 2;
            }
            var profiles = Arrays.asList(options.getOrDefault("--profiles", "baseline").split(",", -1));
            var catalog = ScenarioCatalog.load();
            var selection = catalog.select(profiles);
            if (args[0].equals("collect-profiles")) {
                if (!options.keySet().containsAll(Set.of("--report-directory", "--workspace"))) { err.println("Missing profile report inputs."); return 2; }
                boolean complete = LabProductionEvidence.collectProfiles(Path.of(options.get("--report-directory")), Path.of(options.get("--workspace")), profiles);
                out.println(complete ? "Selected profiles complete." : "Selected profiles failed or are incomplete; retain the aggregate report."); return complete ? 0 : 3;
            }
            if(args[0].equals("collect-transport-profile")) {
                boolean complete=LabProductionEvidence.collectTransportProfile(Path.of(options.get("--report-directory")),Path.of(options.get("--workspace")));
                out.println(complete?"Transport profile complete.":"Transport profile failed or is incomplete; retain the aggregate report.");return complete?0:3;
            }
            if (args[0].equals("collect-components")) {
                if (!options.keySet().containsAll(Set.of("--report-directory", "--workspace"))) { err.println("Missing component report inputs."); return 2; }
                boolean complete = LabProductionEvidence.collect(Path.of(options.get("--report-directory")), Path.of(options.get("--workspace")));
                out.println(complete ? "Bound production scope passed; this is not complete profile acceptance." : "Bound production report retained; incomplete or failed execution cannot establish full acceptance.");
                return complete ? 0 : 3;
            }
            if (args[0].equals("collect-fixtures")) {
                if (!options.keySet().containsAll(Set.of("--report-directory", "--workspace", "--artifact"))) { err.println("Missing fixture report inputs."); return 2; }
                boolean complete = LabEvidence.collectFixtures(Path.of(options.get("--report-directory")), Path.of(options.get("--workspace")), Path.of(options.get("--artifact")));
                out.println(complete ? "Fixture profile passed: actual JUnit results, HTTP observations and current bindings matched." : "Fixture profile incomplete or failed; retained reports cannot establish a full pass.");
                out.println("Report: " + Path.of(options.get("--report-directory"), "report.jsonl")); return complete ? 0 : 3;
            }
            Path environment = Path.of(options.getOrDefault("--environment-root", System.getProperty("lab.environmentRoot", "test/authentication-lab/build/runs"))).toAbsolutePath().normalize();
            if (args[0].equals("serve")) return serve(catalog, profiles, environment, options.get("--case"),out);
            if (args[0].equals("reset") || args[0].equals("stop") || args[0].equals("prepare-case")) {
                if (!options.containsKey("--run")) { err.println("BLOCKED: specify the owned run ID using --run (Gradle: -PlabRun=UUID)."); return 3; }
                if (args[0].equals("prepare-case") && !options.containsKey("--case")) { err.println("BLOCKED: specify --case (Gradle: -PlabCase=ID)."); return 3; }
                return remote(args[0], environment, UUID.fromString(options.get("--run")), options.get("--case"), out, err);
            }
            if (args[0].equals("matrix")) {
                out.println("Authentication lab catalog v1; metadata only, no tests executed.");
                out.println("Profiles: " + String.join(",", profiles));
                for (var r : selection.requirements()) {
                    out.printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s%n", r.id(), r.layer(), r.readiness(),
                            "required=" + String.join(",", r.capabilities()),
                            "plannedMs=" + r.budget().startup() + "/" + r.budget().caseMs() + "/" + r.budget().cleanup(),
                            "disposition=" + r.disposition() + ";recipe=" + (r.recipe() == null ? "component assertion" : r.recipe()),
                            "expected=" + r.expected().stream().map(f -> f.fact() + "=" + f.value()).collect(java.util.stream.Collectors.joining(";")),
                            r.prerequisite());
                }
                summary(selection, out);
                out.println("Planning times are unmeasured; shared setup is not summed per requirement.");
                out.println("A bound execution is not a passing result. Missing bindings never establish coverage.");
                return 0;
            }
            if (args[0].equals("doctor")) {
                boolean javaReady = Runtime.version().feature() == 21;
                out.println("Java 21: " + (javaReady ? "AVAILABLE" : "BLOCKED (use Java 21)"));
                out.println("Catalog: VALID; profiles=" + String.join(",", profiles));
                var capabilities = new TreeSet<String>();
                selection.requirements().forEach(r -> capabilities.addAll(r.capabilities()));
                out.println("Selected capabilities: " + String.join(",", capabilities));
                summary(selection, out);
                if (javaReady && selection.requirements().stream().allMatch(r -> r.layer() == ScenarioCatalog.Layer.FIXTURE) && LabEvidence.fixtureBindingsCurrent(selection, Path.of(System.getProperty("lab.workspaceRoot", ".")))) {
                    out.println("AVAILABLE: fixture prerequisites and current source bindings. Run authLab -PlabProfiles=fixtures for actual execution; doctor has executed no tests."); return 0;
                }
                out.println("Controlled HTTP targets: AVAILABLE. This doctor currently qualifies fixture bindings only.");
                out.println("BLOCKED: selected production-profile readiness has not been qualified by this doctor. Use the documented explicit component/browser/federation/transport commands and their preparation requirements.");
                out.println("No Docker/browser/native/provider capability was inferred, downloaded or launched.");
                return 3;
            }
            err.println("BLOCKED: '" + args[0] + "' has no audited execution bindings. No authentication execution or resource mutation occurred.");
            err.println("Implement the owning phase and establish audited bindings before running this operation.");
            return 3;
        } catch (ScenarioCatalog.CatalogException ex) {
            err.println("Catalog rejected: " + ex.getMessage()); return 2;
        } catch (IllegalArgumentException ex) { err.println("Invalid command arguments."); return 2;
        } catch (Exception ex) { err.println(args.length > 0 && args[0].startsWith("collect-") ? "Report collection failed or is incomplete; retain the current XML/context/observations for inspection." : "Target lifecycle operation failed; no passing execution is inferred. See the private run directory for completion state."); return 3;
        }
    }
    private static int serve(ScenarioCatalog catalog, List<String> profiles, Path root,String selectedCase,PrintStream out) throws Exception {
        boolean federation=profiles.equals(List.of("federation"));
        boolean transport=profiles.equals(List.of("transport"));
        if(!transport&&catalog.select(profiles).requirements().stream().anyMatch(row->row.id().startsWith("TLS."))){out.println("BLOCKED: serve transport separately with --profiles transport and fresh -PlabPkcs11Fixture=<fixture.json>.");return 3;}
        String transportCase=selectedCase==null?"TLS.mtls.expected-fingerprint":selectedCase;
        if(transport&&!TransportFixtures.SERVABLE.contains(transportCase)){out.println("BLOCKED: this transport case has no standalone manual journey. Use its existing operational owner.");return 3;}
        if(!federation&&catalog.select(profiles).requirements().stream().anyMatch(row->row.group().startsWith("FED."))) {
            out.println("BLOCKED: serve federation separately with --profiles federation and one --case ID; its named origin tuple serves one active case at a time.");return 3;
        }
        String federationCase=selectedCase==null?"FED.flow.browser-oidc":selectedCase;
        if(federation&&catalog.select(profiles).requirements().stream().noneMatch(row->row.id().equals(federationCase)&&row.disposition()!=ScenarioCatalog.Disposition.EXCLUDED))throw new IllegalArgumentException("Unknown active federation case.");
        var spec = new LabRun.RunSpec(UUID.fromString(System.getProperty("lab.invocationId", UUID.randomUUID().toString())), profiles, catalog, root, List.of(), Long.parseLong(System.getProperty("lab.cycleDeadlineMs", "30000")));
        try (var run = LabRun.start(spec)) {
            var hook = new Thread(run::close, "authlab-owned-cleanup"); Runtime.getRuntime().addShutdownHook(hook);
            try {
                if(federation) {
                    Path workspace=Path.of(System.getProperty("lab.workspaceRoot",".")).toRealPath();
                    Path manifest=Path.of(Objects.requireNonNull(System.getProperty("lab.federationRuntimeManifest"),"Prepare the immutable federation runtime first."));
                    var provider=FederationEnvironment.startProvider(run,new FederationEnvironment.Spec(workspace.resolve("test/federation-client/provider-assets.lock.json"),
                            workspace.resolve("test/federation-client/src/main/resources/provider/downstream-realm.json"),
                            LabTls.loadPrepared(workspace.resolve("test/authentication-lab/build/prepared/federation/ca")),
                            workspace.resolve("test/federation-client/src/main/resources/provider/upstream-realm.json")));
                    run.enableFederationServing(manifest);var target=run.prepareServingCase(federationCase,run.generation());
                    out.println("Federation login: "+target.startUri());out.println("Client/API: "+provider.ports().clientOrigin()+" / "+provider.ports().resourceOrigin());
                    out.println("One federation case is active at a time. Reset closes its client/API pair and recreates provider state; prepare a case again afterward.");
                }else if(transport) {
                    String fixture=System.getProperty("lab.pkcs11Fixture");
                    if(fixture==null){out.println("BLOCKED: prepare a fresh disposable software token and pass -PlabPkcs11Fixture=<fixture.json>.");return 3;}
                    run.enableTransportServing(TransportFixtures.Material.load(Path.of(System.getProperty("lab.workspaceRoot",".")).toRealPath(),Path.of(fixture)));
                    var target=run.prepareServingCase(transportCase,run.generation());out.println("Transport login: "+target.startUri());
                    out.println("Transport topology and private software configuration path are available in the owned /targets inventory. Export with authLabExamples -PlabRun="+run.runId()+".");
                    out.println("One transport case is active at a time. Reset retires its listeners; prepare the next case afterward. This is a software token, not physical-device qualification.");
                }else for (var row : catalog.select(profiles).requirements())if(row.disposition()!=ScenarioCatalog.Disposition.EXCLUDED && !row.group().startsWith("HTTP.auth."))run.prepareCase(row.id());
                out.println("Controlled targets: " + run.applicationUri() + "/");
                out.println("Alternate origin: " + run.alternateUri());
                out.println("Run ID: " + run.runId()); out.println("Private run directory: " + run.directory());
                if(profiles.contains("http-auth"))out.println("HTTP fixture accounts: user-a/alpha-password and user-b/bravo-password; Basic, NTLMv1 and NTLMv2 links are on the target index.");
                if(profiles.stream().anyMatch(profile->!profile.equals("http-auth")))out.println("Fixture accounts: user/pass, user2/pass2, admin/adminpass.");
                if(!federation&&!transport)out.println("HTTPS/provider/native/browser execution prerequisites remain separate; unavailable target routes report them explicitly.");
                out.println("Targets stay in the foreground until authLabStop or interruption. Hosting targets is not a passing test run.");
                out.flush(); run.awaitStop(); return 0;
            } finally { try { Runtime.getRuntime().removeShutdownHook(hook); } catch (IllegalStateException ignored) { } }
        }
    }
    private static int remote(String operation, Path root, UUID runId, String caseId, PrintStream out, PrintStream err) throws Exception {
        Path descriptor = null;
        if (!Files.isDirectory(root)) { err.println("BLOCKED: no owned runtime directory."); return 3; }
        Path resolvedRoot = root.toRealPath();
        try (var invocations = Files.list(resolvedRoot)) {
            for (Path invocation : invocations.filter(p -> Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS)).toList()) {
                try { UUID.fromString(invocation.getFileName().toString()); } catch (IllegalArgumentException ex) { continue; }
                Path candidate = invocation.resolve(runId.toString()).resolve("run.json");
                if (Files.isRegularFile(candidate, LinkOption.NOFOLLOW_LINKS) && candidate.toRealPath().startsWith(resolvedRoot)) {
                    if (descriptor != null) throw new IllegalArgumentException("Duplicate runtime identity."); descriptor = candidate;
                }
            }
        }
        if (descriptor == null) { err.println("BLOCKED: owned run descriptor not found."); return 3; }
        var data = ScenarioCatalog.parseJson(Files.readAllBytes(descriptor)).getAsJsonObject();
        if (!data.keySet().equals(Set.of("descriptorVersion", "invocationId", "runId", "generation", "createdAt", "environmentRoot", "controlUri", "controlKey", "resources", "state")) || data.get("descriptorVersion").getAsInt() != 1 || !runId.toString().equals(LabRun.text(data, "runId")) || !descriptor.getParent().getParent().getFileName().toString().equals(LabRun.text(data, "invocationId")) || !resolvedRoot.toString().equals(LabRun.text(data, "environmentRoot"))) throw new IllegalArgumentException("Invalid owned descriptor.");
        String state = LabRun.text(data, "state");
        if (state.equals("CLOSED")) { if (operation.equals("stop")) { out.println("Owned run is already closed."); return 0; } err.println("BLOCKED: run is closed."); return 3; }
        URI uri = URI.create(LabRun.text(data, "controlUri"));
        if (!uri.getScheme().equals("http") || !"127.0.0.1".equals(uri.getHost()) || uri.getPort() <= 0 || uri.getUserInfo() != null || !uri.getPath().equals("/control/v1/runs/" + runId) || uri.getQuery() != null || uri.getFragment() != null) throw new IllegalArgumentException("Invalid owned control address.");
        boolean ownedDirectory = false;
        for (var element : data.getAsJsonArray("resources")) {
            var resource = element.getAsJsonObject();
            if ("DIRECTORY".equals(LabRun.text(resource, "kind")) && runId.toString().equals(LabRun.text(resource, "ownerRunId")) && descriptor.getParent().toRealPath().toString().equals(LabRun.text(resource.getAsJsonObject("proof"), "resolvedPath"))) ownedDirectory = true;
        }
        if (!ownedDirectory) throw new IllegalArgumentException("Ownership proof missing.");
        try (var client = ControlledApplication.localClientBuilder().connectTimeout(Duration.ofSeconds(2)).build()) {
            long generation = LabRun.number(data, "generation", false);
            boolean providerRun=data.getAsJsonArray("resources").asList().stream().anyMatch(resource->"CONTAINER".equals(LabRun.text(resource.getAsJsonObject(),"kind")));
            var payload = operation.equals("prepare-case") ? Map.of("caseId", caseId, "runGeneration", generation) : Map.of("generation", generation);
            var request = HttpRequest.newBuilder(URI.create(uri + "/" + (operation.equals("prepare-case") ? "cases" : operation))).timeout(Duration.ofSeconds(providerRun?50:6)).header("Authorization", "Bearer " + LabRun.text(data, "controlKey")).header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(LabRun.JSON.toJson(payload))).build();
            var result = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (result.statusCode() != (operation.equals("reset") ? 200 : operation.equals("prepare-case") ? 201 : 202)) { err.println("Owned control operation rejected: HTTP " + result.statusCode()); return 3; }
            if (operation.equals("prepare-case")) { out.println("Owned case prepared: " + caseId + ". Its generation is available from the existing target index."); return 0; }
            if (operation.equals("stop")) {
                long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(providerRun?40:8);
                while (System.nanoTime() < deadline) {
                    String latest = ScenarioCatalog.parseJson(Files.readAllBytes(descriptor)).getAsJsonObject().get("state").getAsString();
                    if (latest.equals("CLOSED")) { out.println("Owned run stopped; cleanup acknowledged."); return 0; }
                    if (latest.equals("INTERRUPTED")) break;
                    Thread.sleep(20);
                }
                err.println("BLOCKED: cleanup has not completed; preserve the private runtime state."); return 3;
            }
            out.println("Owned run reset to generation " + ScenarioCatalog.parseJson(result.body().getBytes(java.nio.charset.StandardCharsets.UTF_8)).getAsJsonObject().get("generation").getAsLong() + ". Cases must be prepared again with that version."); return 0;
        }
    }
    private static void summary(ScenarioCatalog.Selection selection, PrintStream out) {
        var counts = new TreeMap<String, Long>();
        selection.requirements().forEach(r -> counts.merge(r.readiness(), 1L, Long::sum));
        out.printf("Requirements=%d uniqueBoundExecutions=%d unboundRequirements=%d readiness=%s%n",
                selection.requirements().size(), selection.uniqueBoundExecutions(), selection.unboundRequirements(), counts);
        out.println("Manual/UNASSESSED are metadata categories; no operator results or capability conclusions have been recorded.");
    }
}
