package lab.auth;

import com.google.gson.*;
import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/** One owned environment; the HTTP driver and JUnit use exactly this lifecycle. */
public final class LabRun implements AutoCloseable {
    public enum Phase { LOGIN, HOP, EXTRACTION, TOKEN_EXCHANGE, PROTECTED }
    public enum FreshPhase { PRIME, PROBE }
    public record ArtifactRecord(String role, String version, String sha256) {}
    public record RunSpec(UUID invocationId, List<String> profiles, ScenarioCatalog catalog, Path environmentRoot,
                          List<ArtifactRecord> preparedArtifacts, long cycleDeadlineMs) {
        public RunSpec {
            Objects.requireNonNull(invocationId); profiles = List.copyOf(profiles); Objects.requireNonNull(catalog);
            Objects.requireNonNull(environmentRoot); preparedArtifacts = List.copyOf(preparedArtifacts);
            if (cycleDeadlineMs <= 0) throw new IllegalArgumentException("Positive cycle deadline required.");
            catalog.select(profiles);
        }
        public static RunSpec fixtures(Path root) { return new RunSpec(UUID.randomUUID(), List.of("fixtures"), ScenarioCatalog.load(), root, List.of(), 5_000); }
    }
    public record FaultSpec(Phase phase, int occurrence, String kind, FixtureIdentityStore.Role role, Integer status, String checkpoint) {
        public FaultSpec {
            var object = new JsonObject(); object.addProperty("phase", phase.name()); object.addProperty("occurrence", occurrence);
            object.addProperty("kind", kind); object.addProperty("role", role == null ? null : role.name());
            object.addProperty("status", status); object.addProperty("checkpoint", checkpoint);
            ScenarioCatalog.parseFault(object);
        }
        public static FaultSpec holdLogin(String gate) { return new FaultSpec(Phase.LOGIN, 1, "HOLD", null, null, gate); }
    }
    private record ScheduledFault(FaultSpec spec,int absoluteOccurrence) { }
    public static final class ControlException extends RuntimeException {
        final int status; final String code;
        ControlException(int status, String code) { super(code); this.status = status; this.code = code; }
        public int status() { return status; }
        public String code() { return code; }
    }
    static final Gson JSON = new GsonBuilder().serializeNulls().create();
    private final RunSpec spec;
    private final long issuanceLifetimeSeconds;
    private final UUID runId = UUID.randomUUID();
    private final FixtureIdentityStore.Secret controlKey = FixtureIdentityStore.randomSecret();
    private final Map<String, CaseLease> cases = new LinkedHashMap<>();
    private final ExecutorService controls = Executors.newVirtualThreadPerTaskExecutor();
    private final CountDownLatch stopped = new CountDownLatch(1);
    private final HttpServer control;
    private final ControlledApplication application;
    private final Path directory;
    private final Instant createdAt = Instant.now();
    private volatile long generation = 1;
    private long caseGeneration;
    private volatile String state = "STARTING";
    private boolean closing;
    private final LabEvidence evidence;
    private volatile FederationEnvironment federation;
    private volatile Path servingFederationRuntime;
    private volatile TransportFixtures.Material servingTransportMaterial;

    private LabRun(RunSpec spec,long issuanceLifetimeSeconds) throws IOException {
        this.spec = spec;
        this.issuanceLifetimeSeconds=issuanceLifetimeSeconds;
        Path environment = spec.environmentRoot().toAbsolutePath().normalize(); Files.createDirectories(environment);
        Path invocation = environment.resolve(spec.invocationId().toString()); Files.createDirectories(invocation);
        directory = Files.createDirectory(invocation.resolve(runId.toString())); restrict(directory);
        evidence = new LabEvidence(directory.resolve("report.jsonl"), spec.invocationId(), runId);
        control = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 32);
        ControlledApplication created = null;
        try {
            created = new ControlledApplication(this); application = created;
            control.setExecutor(controls); control.createContext("/", this::handleControl);
            application.start(); control.start(); state = "READY";
            writeDescriptor(); evidence.started(spec);
        } catch (IOException | RuntimeException ex) {
            if (created != null) try { created.close(); } catch (RuntimeException ignored) { }
            control.stop(0); controls.shutdownNow(); evidence.close(); throw ex;
        }
    }
    public static LabRun start(RunSpec spec) throws IOException { return new LabRun(spec,60); }
    /** Host GUI recipes test routing and explicit revocation, with a lifetime covering the whole owned run. */
    public static LabRun startHost(RunSpec spec) throws IOException { return new LabRun(spec,3600); }
    public UUID runId() { return runId; }
    public long generation() { return generation; }
    public URI applicationUri() { return application.origin(); }
    URI alternateUri() { return application.alternateOrigin(); }
    public URI controlUri() { return URI.create("http://127.0.0.1:" + control.getAddress().getPort() + "/control/v1/runs/" + runId); }
    public FixtureIdentityStore.Secret controlKey() { return controlKey; }
    public Path directory() { return directory; }
    RunSpec spec() { return spec; }
    public CaseLease prepareCase(String id) { long expected = generation; return prepareCase(id, expected); }
    public synchronized CaseLease prepareCase(String id, long expectedRunGeneration) {
        if (expectedRunGeneration != generation) throw error(409, "GENERATION_CONFLICT");
        ready();
        if (!id.matches("[A-Za-z0-9._=~-]{1,200}") || !spec.catalog().select(spec.profiles()).requirements().stream().anyMatch(r -> r.id().equals(id))) throw error(400, "BAD_INPUT");
        if(spec.catalog().requirement(id).disposition()==ScenarioCatalog.Disposition.EXCLUDED)throw error(409,"OUT_OF_SCOPE");
        var old = cases.get(id);
        if (old != null && !old.closed) throw error(409, "STATE_CONFLICT");
        var lease = new CaseLease(id, ++caseGeneration); cases.put(id, lease); return lease;
    }
    /** Foreground serving reuses the same case/child owners as operational tests. */
    public synchronized void enableFederationServing(Path runtimeManifest) throws IOException {
        ready();if(federation==null||servingFederationRuntime!=null)throw error(409,"STATE_CONFLICT");
        servingFederationRuntime=runtimeManifest.toRealPath();
    }
    public synchronized void enableTransportServing(TransportFixtures.Material material) throws IOException {
        ready();if(federation!=null||servingTransportMaterial!=null||cases.values().stream().anyMatch(c->!c.closed))throw error(409,"STATE_CONFLICT");
        material.claim(spec.invocationId(),runId);servingTransportMaterial=material;
    }
    synchronized CaseLease prepareServingCase(String id,long expectedRunGeneration) throws Exception {
        if(servingTransportMaterial!=null&&cases.values().stream().anyMatch(c->!c.closed))throw error(409,"STATE_CONFLICT");
        var lease=prepareCase(id,expectedRunGeneration);
        try {
            if(servingFederationRuntime!=null&&id.startsWith("FED."))federation.startApplications(lease,servingFederationRuntime);
            if(servingTransportMaterial!=null)lease.transport=new TransportFixtures.Serving(lease,servingTransportMaterial);
            return lease;
        }catch(Exception failure){try{lease.close();}catch(Exception cleanup){failure.addSuppressed(cleanup);}throw failure;}
    }
    synchronized CaseLease find(String id, long expected) { return find(id, expected, false); }
    private synchronized CaseLease find(String id, long expected, boolean readableHistory) {
        var lease = cases.get(id);
        if (lease == null) throw error(404, "NOT_FOUND");
        if (lease.generation != expected) throw error(409, "GENERATION_CONFLICT");
        if (!readableHistory) lease.check(); return lease;
    }
    private void ready() { if (!state.equals("READY")) throw error(409, "STATE_CONFLICT"); }
    public synchronized long reset(long expected) throws IOException {
        if (expected != generation) throw error(409, "GENERATION_CONFLICT"); ready();
        long deadline=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(spec.cycleDeadlineMs());
        state = "STARTING";
        try {
            for (var lease : cases.values()) lease.close(deadline);
            cases.clear(); generation++; writeDescriptor();
            if(federation!=null)try{federation.resetProvider(deadline);}catch(ControlException|IOException ex){throw ex;}catch(Exception ex){throw new IOException("Owned provider reset failed.");}
            state = "READY"; writeDescriptor(); return generation;
        } catch (RuntimeException | IOException ex) { state = "INTERRUPTED"; writeDescriptor(); throw ex; }
    }
    @Override public void close() {
        List<CaseLease> owned;
        synchronized (this) {
            if (state.equals("CLOSED") && stopped.getCount() == 0) return;
            if (closing) { owned = null; }
            else { closing = true; state = "STOPPING"; owned = List.copyOf(cases.values()); }
        }
        if (owned == null) {
            try { if (!stopped.await(8, TimeUnit.SECONDS)) throw new IllegalStateException("Run cleanup deadline."); }
            catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException("Run cleanup interrupted."); }
            if (!state.equals("CLOSED")) throw new IllegalStateException("Run cleanup incomplete."); return;
        }
        boolean complete = true;
        for (var lease : owned) try { lease.close(); } catch (RuntimeException ex) { complete = false; }
        var provider = federation;
        if (provider != null) try { provider.close(); } catch (Exception ex) { complete = false; }
        try { application.close(); } catch (RuntimeException ex) { complete = false; }
        control.stop(0); controls.shutdownNow();
        try { if (!controls.awaitTermination(3, TimeUnit.SECONDS)) complete = false; }
        catch (InterruptedException ex) { Thread.currentThread().interrupt(); complete = false; }
        try {
            evidence.completed(complete, complete ? List.of() : List.of("unsettled-case-work")); evidence.close();
            state = complete ? "CLOSED" : "INTERRUPTED"; writeDescriptor();
        }
        catch (IOException ex) { state = "INTERRUPTED"; try { writeDescriptor(); } catch (IOException ignored) { } throw new UncheckedIOException(ex); }
        finally { stopped.countDown(); }
        if (!complete) throw new IllegalStateException("Run cleanup incomplete.");
    }
    public void awaitStop() throws InterruptedException { stopped.await(); }
    public synchronized List<CaseLease> cases() { return List.copyOf(cases.values()); }
    /** Publishes provider ownership before resource allocation, while ordinary mutation admission is closed. */
    synchronized void attachFederation(FederationEnvironment environment) throws IOException {
        ready(); if(federation!=null||closing||cases.values().stream().anyMatch(c->!c.closed))throw error(409,"STATE_CONFLICT");
        federation=environment;state="STARTING";writeDescriptor();
    }
    synchronized void federationReady(FederationEnvironment environment) throws IOException {
        if(federation!=environment||closing)throw error(409,"STATE_CONFLICT");state="READY";writeDescriptor();
    }
    synchronized void federationChanged() throws IOException { if(!state.equals("CLOSED"))writeDescriptor(); }
    synchronized void federationFailed() throws IOException { if(!closing){state="INTERRUPTED";writeDescriptor();} }
    synchronized void detachFederation(FederationEnvironment environment) throws IOException { if(federation==environment){federation=null;writeDescriptor();} }
    static ControlException error(int status, String code) { return new ControlException(status, code); }
    private void writeDescriptor() throws IOException {
        var descriptor = new LinkedHashMap<String, Object>();
        descriptor.put("descriptorVersion", 1); descriptor.put("invocationId", spec.invocationId()); descriptor.put("runId", runId);
        descriptor.put("generation", generation); descriptor.put("createdAt", createdAt.toString()); descriptor.put("environmentRoot", spec.environmentRoot().toRealPath().toString());
        descriptor.put("controlUri", controlUri().toString()); descriptor.put("controlKey", controlKey.reveal()); descriptor.put("state", state);
        var resources = new ArrayList<Map<String,Object>>();
        if(!state.equals("CLOSED")) {
            resources.add(Map.of("kind", "DIRECTORY", "id", directory.toString(), "ownerRunId", runId.toString(), "createdAt", createdAt.toString(), "proof", Map.of("resolvedPath", directory.toRealPath().toString())));
            var provider=federation;if(provider!=null)resources.addAll(provider.resources());
        }
        descriptor.put("resources",resources);
        Path file = directory.resolve("run.json"), pending = directory.resolve("run.json.pending");
        Files.writeString(pending, JSON.toJson(descriptor), StandardCharsets.UTF_8); restrict(pending);
        // Windows scanners can briefly open a newly published descriptor without delete sharing.
        // Retain atomic publication and its private ACL; never fall back to rewriting the live file.
        for (int attempt = 0; ; attempt++) {
            try { Files.move(pending, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING); break; }
            catch (AccessDeniedException ex) {
                if (attempt == 4) throw ex;
                try { Thread.sleep(25L << attempt); }
                catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt(); throw new IOException("Descriptor publication interrupted.", interrupted);
                }
            }
        }
    }
    static void restrict(Path path) throws IOException {
        var posix = Files.getFileAttributeView(path, PosixFileAttributeView.class);
        if (posix != null) Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(Files.isDirectory(path) ? "rwx------" : "rw-------"));
        else {
            var acl = Files.getFileAttributeView(path, AclFileAttributeView.class);
            if (acl == null) throw new IOException("Private runtime permissions unavailable.");
            acl.setAcl(List.of(AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(acl.getOwner()).setPermissions(EnumSet.allOf(AclEntryPermission.class)).build()));
        }
    }

    public final class CaseLease implements AutoCloseable {
        private final String id;
        private final long generation;
        final FixtureIdentityStore identities = new FixtureIdentityStore(issuanceLifetimeSeconds);
        final long preparedNanos = System.nanoTime();
        final Map<String, LoginFlows.Transaction> transactions = new HashMap<>();
        private final List<ScheduledFault> faults = new ArrayList<>();
        final Map<Phase, Integer> occurrences = new EnumMap<>(Phase.class);
        final Map<String, Gate> gates = new LinkedHashMap<>();
        final List<Map<String, Object>> events = new ArrayList<>();
        final LabHostObservations hostObservations = new LabHostObservations();
        final AtomicLong ingress = new AtomicLong(), routed = new AtomicLong(), actions = new AtomicLong();
        private long eventSequence;
        private int active;
        private IngressSentinel sentinel;
        private FederationApplications federationApplications;
        private TransportFixtures.Serving transport;
        private volatile boolean closed;
        private String caseState = "PREPARED";
        FreshPhase freshPhase;
        boolean primed, probeObserved, loginCompleted;
        FixtureIdentityStore.Issuance current;
        final Map<String, Map<String, Object>> outputSessions = new HashMap<>();
        final FixtureIdentityStore.Secret marker = FixtureIdentityStore.randomSecret();
        private CaseLease(String id, long generation) { this.id = id; this.generation = generation; }
        public String id() { return id; }
        public long generation() { return generation; }
        public URI endpoint(String path) { return endpoint(path, false); }
        public synchronized URI startUri() {
            if(transport!=null&&!closed)return transport.startUri();
            if(federationApplications==null||closed)return endpoint("start");
            String path=id.startsWith("FED.broker.")?"/spa?broker=upstream-saml":id.equals("FED.flow.saml-sp")?"/saml2/authenticate/keycloak":
                    Set.of("FED.flow.backend-oidc","FED.outputs.client-cookie","FED.negative.code-expired").contains(id)?"/oauth2/authorization/backend":"/spa";
            return URI.create(federationApplications.clientOrigin()+path);
        }
        URI endpoint(String path, boolean alternate) {
            try { return new URI((alternate ? alternateUri() : applicationUri()).toString() + "/cases/" + id + "/" + path + (path.contains("?") ? "&" : "?") + "generation=" + generation); }
            catch (URISyntaxException ex) { throw new IllegalArgumentException("Invalid fixture route."); }
        }
        public synchronized FixtureIdentityStore.Issuance seeded(String label) { check(); return identities.seeded(label); }
        public synchronized IngressSentinel openSentinel(javax.net.ssl.SSLContext tls) throws IOException {
            check(); if (sentinel != null) throw error(409, "STATE_CONFLICT"); sentinel = new IngressSentinel(tls); return sentinel;
        }
        synchronized void check() { if (closed || caseState.equals("CLOSING")) throw error(410, "RETIRED"); }
        synchronized void attachFederationApplications(FederationApplications applications) {
            check();if(federationApplications!=null)throw error(409,"STATE_CONFLICT");federationApplications=applications;
        }
        synchronized void enter() { check(); active++; caseState = "RUNNING"; ingress.incrementAndGet(); }
        synchronized void leave() { active--; notifyAll(); }
        public synchronized void armFault(FaultSpec fault) {
            check();Objects.requireNonNull(fault);scheduleFault(fault,fault.occurrence());
        }
        /** Typed host recipes may schedule 1-32 hits ahead without changing the absolute catalog/control contract. */
        public synchronized void armRelativeFault(FaultSpec fault) {
            check();Objects.requireNonNull(fault);
            long absolute=(long)occurrences.getOrDefault(fault.phase(),0)+fault.occurrence();
            if(absolute<1||absolute>10_000)throw error(400,"BAD_INPUT");
            scheduleFault(fault,(int)absolute);
        }
        synchronized boolean hasFaultCheckpoint(String checkpoint) {
            check();Objects.requireNonNull(checkpoint);
            return faults.stream().anyMatch(fault->checkpoint.equals(fault.spec().checkpoint()));
        }
        private void scheduleFault(FaultSpec fault,int absolute) {
            if(faults.stream().anyMatch(scheduled->scheduled.absoluteOccurrence()==absolute&&scheduled.spec().phase()==fault.phase()
                    &&scheduled.spec().kind().equals(fault.kind())&&scheduled.spec().role()==fault.role()
                    &&Objects.equals(scheduled.spec().status(),fault.status())&&Objects.equals(scheduled.spec().checkpoint(),fault.checkpoint())))
                throw error(409,"STATE_CONFLICT");
            faults.add(new ScheduledFault(fault,absolute));
            if (fault.checkpoint() != null) gates.computeIfAbsent(fault.checkpoint(), k -> new Gate());
        }
        List<FaultSpec> hit(Phase phase) {
            List<FaultSpec> selected;
            synchronized (this) {
                check(); int occurrence = occurrences.merge(phase, 1, Integer::sum);
                selected = faults.stream().filter(f -> f.spec().phase() == phase && f.absoluteOccurrence() == occurrence).map(ScheduledFault::spec).toList();
                event(phase, "phase-entered", List.of());
            }
            for (var fault : selected) if (fault.kind().equals("HOLD")) {
                Gate gate; synchronized (this) { gate = gates.get(fault.checkpoint()); gate.waiting = true; event(phase, fault.checkpoint(), List.of()); notifyAll(); }
                try { if (!gate.latch.await(spec.cycleDeadlineMs(), TimeUnit.MILLISECONDS)) throw error(504, "DEADLINE"); }
                catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw error(410, "RETIRED"); }
                synchronized (this) { check(); }
            }
            return selected;
        }
        public synchronized Map<String, Object> awaitCheckpoint(String name, Duration timeout) {
            long deadline = System.nanoTime() + timeout.toNanos();
            while (true) {
                check(); var gate = gates.get(name);
                if (gate != null && gate.waiting) return snapshot();
                long remaining = deadline - System.nanoTime(); if (remaining <= 0) throw error(504, "DEADLINE");
                try { TimeUnit.NANOSECONDS.timedWait(this, remaining); }
                catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw error(410, "RETIRED"); }
            }
        }
        public synchronized void release(String name) {
            check();
            if(federationApplications!=null) {
                try{federationApplications.releaseProtocol(name);return;}catch(ControlException failure){throw failure;}catch(Exception failure){throw error(500,"INTERNAL");}
            }
            var gate = gates.get(name); if (gate == null) throw error(404, "NOT_FOUND"); gate.released = true; gate.latch.countDown();
        }
        synchronized void armFederationProtocol(String variant,String checkpoint) throws Exception {
            check();if(federationApplications==null)throw error(409,"STATE_CONFLICT");federationApplications.armProtocol(variant,checkpoint);
        }
        synchronized Object controlSnapshot() throws Exception {
            if(transport!=null&&!closed)return Map.of("case",snapshot(),"transport",transport.observations());
            if(federationApplications==null||closed)return snapshot();return federationApplications.clientSnapshot();
        }
        public synchronized void revoke(String issuanceId) { check(); identities.revoke(issuanceId); }
        public synchronized void advanceFixtureClock(Duration delta) { check(); identities.advance(delta); }
        public synchronized void selectFreshPhase(FreshPhase phase) {
            check(); if (!id.startsWith("BROW.fresh.") || phase == null) throw error(400, "BAD_INPUT");
            if (freshPhase == phase) return;
            if (freshPhase == null && phase == FreshPhase.PRIME || freshPhase == FreshPhase.PRIME && phase == FreshPhase.PROBE && primed && loginCompleted) freshPhase = phase;
            else throw error(409, "STATE_CONFLICT");
        }
        synchronized void requireFreshObservation() {
            if (id.startsWith("BROW.fresh.") && (freshPhase == null || freshPhase == FreshPhase.PRIME && !primed || freshPhase == FreshPhase.PROBE && !probeObserved)) throw error(409, "STATE_CONFLICT");
        }
        synchronized void event(Phase phase, String name, List<Map<String, String>> safeIds) {
            long sequence = ++eventSequence;
            if (events.size() < 10_000) events.add(Map.of("sequence", sequence, "time", Instant.now().toString(), "phase", phase.name(), "name", name, "safeIds", List.copyOf(safeIds)));
        }
        public synchronized Map<String, Object> snapshot() {
            var counters = new LinkedHashMap<String, Object>(); counters.put("httpIngress", ingress.get()); counters.put("routed", routed.get()); counters.put("actions", actions.get());
            var network = sentinel == null ? null : sentinel.snapshot();
            counters.put("connections", network == null ? null : network.connections()); counters.put("tlsHandshakes", network == null ? null : network.tlsHandshakes()); counters.put("applicationBytes", network == null ? null : network.applicationBytes());
            if(id.startsWith("FED."))counters.replaceAll((name,value)->null);
            return Map.of("runId", runId.toString(), "caseId", id, "generation", generation, "state", caseState,
                    "checkpoints", gates.entrySet().stream().map(e -> Map.of("name", e.getKey(), "state", closed ? "RETIRED" : e.getValue().released ? "RELEASED" : "WAITING")).toList(),
                    "counters", counters, "events", List.copyOf(events), "truncated", eventSequence > 10_000,
                    "hostObservations", hostObservations.snapshot());
        }
        @Override public void close() {
            close(System.nanoTime()+TimeUnit.SECONDS.toNanos(5));
            if(federationApplications!=null)try{federationChanged();}catch(IOException error){throw new UncheckedIOException(error);}
        }
        private void close(long deadline) {
            synchronized(this){if (closed) return; caseState = "CLOSING"; gates.values().forEach(g -> g.latch.countDown()); notifyAll();}
            if (sentinel != null) sentinel.close();
            if(transport!=null)try{transport.close();}catch(Exception error){throw new IllegalStateException("Transport case cleanup incomplete.",error);}
            if(federationApplications!=null)try{federationApplications.close(deadline);}catch(Exception error){throw new IllegalStateException("Federation case cleanup incomplete.",error);}
            synchronized(this){
            while (active != 0) {
                long remaining = deadline - System.nanoTime(); if (remaining <= 0) throw error(504, "DEADLINE");
                try { TimeUnit.NANOSECONDS.timedWait(this, remaining); }
                catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw error(504, "DEADLINE"); }
            }
            closed = true; caseState = "CLOSED"; transactions.clear(); current = null; outputSessions.clear(); identities.clear();
            }
        }
    }
    private static final class Gate { final CountDownLatch latch = new CountDownLatch(1); volatile boolean waiting, released; }

    /** Current live endpoints and case versions only; contains no credential or control key. */
    synchronized Map<String,Object> servingTargets(long expectedGeneration) {
        if(expectedGeneration!=generation)throw error(409,"GENERATION_CONFLICT");ready();
        var targets=new ArrayList<Map<String,Object>>();
        for(var lease:cases.values())if(!lease.closed)targets.add(Map.of("caseId",lease.id(),"generation",lease.generation(),"startUri",lease.startUri().toString()));
        var view=new LinkedHashMap<String,Object>();view.put("runId",runId.toString());view.put("generation",generation);
        view.put("applicationOrigin",applicationUri().toString());view.put("alternateOrigin",alternateUri().toString());view.put("cases",targets);
        Map<String,Object> topology=null;
        if(federation!=null) {
            var ports=federation.ports();topology=new LinkedHashMap<>();topology.put("clientOrigin",ports.clientOrigin().toString());topology.put("resourceOrigin",ports.resourceOrigin().toString());
            topology.put("issuer",ports.issuer().toString());topology.put("upstreamIssuer",ports.upstream()>0?ports.upstreamIssuer().toString():null);
        }
        view.put("federation",topology);
        view.put("httpAuthentication",application.httpAuthenticationTargets());
        view.put("transport",cases.values().stream().filter(lease->!lease.closed&&lease.transport!=null).findFirst().map(lease->lease.transport.targets()).orElse(null));return view;
    }

    private void handleControl(HttpExchange exchange) throws IOException {
        String caseId = null; Long expected = null;
        try {
            var auth = exchange.getRequestHeaders().get("Authorization");
            if (auth == null || auth.size() != 1 || !MessageDigest.isEqual(auth.getFirst().getBytes(StandardCharsets.UTF_8), ("Bearer " + controlKey.reveal()).getBytes(StandardCharsets.UTF_8))) throw error(401, "UNAUTHORIZED");
            String prefix = "/control/v1/runs/" + runId;
            String path = exchange.getRequestURI().getPath(); if (!path.startsWith(prefix + "/")) throw error(404, "NOT_FOUND");
            String route = path.substring(prefix.length()); String method = exchange.getRequestMethod();
            if(route.equals("/targets")&&method.equals("GET")) {
                ControlledApplication.json(exchange,200,servingTargets(ControlledApplication.generation(exchange)));return;
            }
            if (route.equals("/cases") && method.equals("POST")) {
                var body = body(exchange, Set.of("caseId", "runGeneration")); caseId = text(body, "caseId");
                var lease = prepareServingCase(caseId, number(body, "runGeneration", false));
                ControlledApplication.json(exchange, 201, Map.of("runId", runId, "caseId", caseId, "generation", lease.generation)); return;
            }
            if (route.equals("/reset") && method.equals("POST")) {
                long next = reset(number(body(exchange, Set.of("generation")), "generation", false));
                ControlledApplication.json(exchange, 200, Map.of("generation", next)); return;
            }
            if (route.equals("/stop") && method.equals("POST")) {
                expected = number(body(exchange, Set.of("generation")), "generation", false);
                if (expected != generation) throw error(409, "GENERATION_CONFLICT");
                ControlledApplication.json(exchange, 202, Map.of("state", "STOPPING")); Thread.startVirtualThread(this::close); return;
            }
            String[] parts = route.split("/");
            if (parts.length < 3 || !parts[1].equals("cases")) throw error(404, "NOT_FOUND"); caseId = parts[2];
            if (method.equals("GET") && parts.length == 4 && parts[3].equals("snapshot") || method.equals("DELETE") && parts.length == 3) {
                expected = ControlledApplication.generation(exchange); var lease = find(caseId, expected, method.equals("GET"));
                if (method.equals("DELETE")) { lease.close(); ControlledApplication.json(exchange, 200, Map.of("generation", expected, "closed", true)); }
                else ControlledApplication.json(exchange, 200, lease.controlSnapshot());
                return;
            }
            if (!method.equals("POST") || parts.length < 4) throw error(404, "NOT_FOUND");
            if (parts[3].equals("gates") ? parts.length != 6 || !parts[5].equals("release") : parts.length != 4) throw error(404, "NOT_FOUND");
            Set<String> fields = switch (parts[3]) {
                case "faults" -> Set.of("generation", "fault"); case "revoke" -> Set.of("generation", "issuanceId");
                case "clock" -> Set.of("generation", "advanceMs"); case "fresh-phase" -> Set.of("generation", "phase"); case "gates" -> Set.of("generation");
                case "federation-control" -> Set.of("generation","variant","checkpoint");default -> throw error(404, "NOT_FOUND");
            };
            var payload = body(exchange, fields); expected = number(payload, "generation", false); var lease = find(caseId, expected);
            if(caseId.startsWith("FED.")&&!Set.of("federation-control","gates").contains(parts[3]))throw error(400,"BAD_INPUT");
            String resultField;
            switch (parts[3]) {
                case "faults" -> { var f = ScenarioCatalog.parseFault(payload.get("fault")); lease.armFault(new FaultSpec(Phase.valueOf(f.phase()), f.occurrence(), f.kind(), f.role() == null ? null : FixtureIdentityStore.Role.valueOf(f.role()), f.status(), f.checkpoint())); resultField = "armed"; }
                case "revoke" -> { lease.revoke(text(payload, "issuanceId")); resultField = "revoked"; }
                case "clock" -> { lease.advanceFixtureClock(Duration.ofMillis(number(payload, "advanceMs", true))); ControlledApplication.json(exchange, 200, Map.of("generation", expected, "fixtureTimeMs", lease.identities.timeMillis())); return; }
                case "fresh-phase" -> { lease.selectFreshPhase(FreshPhase.valueOf(text(payload, "phase"))); ControlledApplication.json(exchange, 200, Map.of("generation", expected, "phase", lease.freshPhase.name())); return; }
                case "gates" -> { if (parts.length != 6 || !parts[5].equals("release")) throw error(404, "NOT_FOUND"); lease.release(parts[4]); resultField = "released"; }
                case "federation-control" -> {lease.armFederationProtocol(text(payload,"variant"),text(payload,"checkpoint"));resultField="armed";}
                default -> throw error(404, "NOT_FOUND");
            }
            ControlledApplication.json(exchange, 200, Map.of("generation", expected, resultField, true));
        } catch (ControlException ex) { controlError(exchange, ex, caseId, expected); }
        catch (IllegalArgumentException | ArithmeticException ex) { controlError(exchange, error(400, "BAD_INPUT"), caseId, expected); }
        catch (Exception ex) { controlError(exchange, error(500, "INTERNAL"), caseId, expected); }
        finally { exchange.close(); }
    }
    private void controlError(HttpExchange exchange, ControlException error, String caseId, Long generation) throws IOException {
        var detail = new LinkedHashMap<String, Object>(); detail.put("code", error.code); detail.put("message", error.code); detail.put("runId", runId.toString()); detail.put("caseId", caseId); detail.put("generation", generation);
        ControlledApplication.json(exchange, error.status, Map.of("error", detail));
    }
    static JsonObject body(HttpExchange exchange, Set<String> fields) throws IOException {
        var type = exchange.getRequestHeaders().getFirst("Content-Type");
        if (type == null || !type.split(";", 2)[0].trim().equalsIgnoreCase("application/json")) throw error(400, "BAD_INPUT");
        byte[] bytes = exchange.getRequestBody().readNBytes(65_537); if (bytes.length > 65_536) throw error(413, "TOO_LARGE");
        var value = ScenarioCatalog.parseJson(bytes); if (!value.isJsonObject() || !value.getAsJsonObject().keySet().equals(fields)) throw error(400, "BAD_INPUT"); return value.getAsJsonObject();
    }
    static String text(JsonObject body, String key) {
        var value = body.get(key); if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString() || value.getAsString().isBlank()) throw error(400, "BAD_INPUT"); return value.getAsString();
    }
    static long number(JsonObject body, String key, boolean zeroAllowed) {
        var value = body.get(key); if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isNumber()) throw error(400, "BAD_INPUT");
        try { long result = value.getAsBigDecimal().longValueExact(); if (result < (zeroAllowed ? 0 : 1)) throw error(400, "BAD_INPUT"); return result; }
        catch (ArithmeticException ex) { throw error(400, "BAD_INPUT"); }
    }
}
