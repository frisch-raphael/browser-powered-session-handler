package lab.auth;

import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import lab.auth.FixtureIdentityStore.Role;

/** Canonical controlled HTTP serving; no production authentication implementation lives here. */
public final class ControlledApplication implements AutoCloseable {
    /** Private controls and local proofs always use their owned loopback listeners directly. */
    public static java.net.http.HttpClient.Builder localClientBuilder() {
        return java.net.http.HttpClient.newBuilder().proxy(new ProxySelector() {
            @Override public List<Proxy> select(URI uri) { return List.of(Proxy.NO_PROXY); }
            @Override public void connectFailed(URI uri, SocketAddress address, IOException error) { }
        });
    }
    /** Shared listener ownership for canonical routes and predecessor test-specific callbacks. */
    public static final class Origin implements AutoCloseable {
        private static final ConcurrentMap<Integer,Integer> OWNED_PORTS=new ConcurrentHashMap<>();
        private final HttpServer server;
        private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
        private final String scheme, host;
        private boolean closed,registered=true;
        public Origin(HttpServer server, String scheme, String host) {
            this.server = Objects.requireNonNull(server);
            if (!Set.of("http", "https").contains(scheme) || !Set.of("127.0.0.1", "localhost").contains(host))
                throw new IllegalArgumentException("Expected a local HTTP(S) origin.");
            this.scheme = scheme; this.host = host; server.setExecutor(executor);
            OWNED_PORTS.merge(server.getAddress().getPort(),1,Integer::sum);
        }
        public static Origin http(String host) throws IOException {
            return new Origin(listener(false), "http", host);
        }
        /** Creates an owned TLS listener from prepared lab material without changing any client trust store. */
        public static Origin https(javax.net.ssl.SSLContext context, String host) throws IOException {
            var server = (HttpsServer) listener(true);
            server.setHttpsConfigurator(new com.sun.net.httpserver.HttpsConfigurator(context));
            return new Origin(server, "https", host);
        }
        /** Keeps browser fixtures above Chromium's restricted service ports, even with a custom OS ephemeral range. */
        static HttpServer listener(boolean tls) throws IOException {
            for (int attempt = 0; attempt < 64; attempt++) {
                var address = new InetSocketAddress("127.0.0.1", ThreadLocalRandom.current().nextInt(16384, 65536));
                try { return tls ? HttpsServer.create(address, 128) : HttpServer.create(address, 64); }
                catch (BindException unavailable) { /* Retry only address collisions, without releasing a successfully bound listener. */ }
            }
            throw new IOException("The lab could not allocate a browser-compatible local port above 16383.");
        }
        public HttpServer server() { return server; }
        public ExecutorService executor() { return executor; }
        public Origin route(String path, HttpHandler handler) { server.createContext(path, handler); return this; }
        public Origin start() { server.start(); return this; }
        public URI url(String path) { return URI.create(scheme + "://" + host + ":" + server.getAddress().getPort() + path); }
        public static boolean ownsPort(int port){return OWNED_PORTS.containsKey(port);}
        /** Completes a fixture callback response; keep-alive remains available unless its handler requests closure. */
        public static void reply(HttpExchange exchange,int status,String type,String text) throws IOException {
            byte[] bytes=text.getBytes(StandardCharsets.UTF_8);exchange.getResponseHeaders().set("Content-Type",type);exchange.sendResponseHeaders(status,bytes.length);
            try(var out=exchange.getResponseBody()){out.write(bytes);}finally{exchange.close();}
        }
        @Override public synchronized void close() {
            if (closed) return;
            server.stop(0); executor.shutdownNow();
            if(registered){OWNED_PORTS.computeIfPresent(server.getAddress().getPort(),(port,count)->count==1?null:count-1);registered=false;}
            try { if (!executor.awaitTermination(3, TimeUnit.SECONDS)) throw new IllegalStateException("Origin cleanup incomplete."); }
            catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException("Origin cleanup interrupted."); }
            closed = true;
        }
    }
    private final LabRun run;
    private final HttpServer app, alternate;
    private final Origin appOwner, alternateOwner;
    private final Semaphore slots = new Semaphore(64);
    private final LoginFlows flows;
    private final Map<HttpAuthenticationFixture.Protocol,HttpAuthenticationFixture> httpAuthentication = new LinkedHashMap<>();
    private static final Map<String,String> HTTP_ACCOUNTS=Map.of("user-a","alpha-password","user-b","bravo-password");
    static Map<String,String> hostFixtureSecrets() {
        return Map.of("FORM_A",FixtureIdentityStore.fixturePassword("user").reveal(),"FORM_B",FixtureIdentityStore.fixturePassword("user2").reveal(),
                "HTTP_A",HTTP_ACCOUNTS.get("user-a"),"HTTP_B",HTTP_ACCOUNTS.get("user-b"));
    }
    ControlledApplication(LabRun run) throws IOException {
        this.run = run; appOwner = Origin.http("127.0.0.1"); app = appOwner.server();
        try { alternateOwner = Origin.http("127.0.0.1"); alternate = alternateOwner.server(); }
        catch (IOException ex) { appOwner.close(); throw ex; }
        try {
            if (run.spec().profiles().contains("http-auth")) for (var protocol : HttpAuthenticationFixture.Protocol.values())
                httpAuthentication.put(protocol,new HttpAuthenticationFixture(protocol,HTTP_ACCOUNTS,null));
        } catch (InterruptedException | RuntimeException failure) {
            httpAuthentication.values().forEach(HttpAuthenticationFixture::close);appOwner.close();alternateOwner.close();
            if(failure instanceof InterruptedException)Thread.currentThread().interrupt();
            throw new IOException("HTTP authentication lab startup failed.",failure);
        }
        flows = new LoginFlows(run);
        for (var server : List.of(app, alternate)) server.createContext("/", this::handle);
    }
    void start() { app.start(); alternate.start(); }
    URI origin() { return URI.create("http://127.0.0.1:" + app.getAddress().getPort()); }
    URI alternateOrigin() { return URI.create("http://127.0.0.1:" + alternate.getAddress().getPort()); }
    List<Map<String,Object>> httpAuthenticationTargets() {
        return httpAuthentication.entrySet().stream().map(entry -> Map.<String,Object>of("protocol",entry.getKey().name(),
                "origin",entry.getValue().url("/").toString(),"request",entry.getValue().url("/whoami").toString(),
                "login",entry.getValue().url("/login").toString(),"users",List.of("user-a","user-b"))).toList();
    }
    @Override public void close() {
        try { httpAuthentication.values().forEach(HttpAuthenticationFixture::close); }
        finally { try { appOwner.close(); } finally { alternateOwner.close(); } }
    }
    private void handle(HttpExchange exchange) throws IOException {
        var correlation=exchange.getRequestHeaders().get("X-AuthLab-Request");
        if(correlation!=null&&correlation.size()==1&&correlation.getFirst().matches("h[0-9a-f]{16}"))
            exchange.getResponseHeaders().set("X-AuthLab-Request",correlation.getFirst());
        LabRun.CaseLease lease = null; boolean entered = false;
        long observation=0; var acceptedFacts=new LinkedHashMap<String,Object>();
        if (!slots.tryAcquire()) { json(exchange, 503, Map.of("error", "fixture_capacity")); exchange.close(); return; }
        try {
            String path = exchange.getRequestURI().getPath();
            if (path.equals("/") && exchange.getRequestMethod().equals("GET")) {
                var links = new StringBuilder("<html><body><h1>Authentication lab targets</h1><p>Fixture pages; production journeys and host checks remain separately gated.</p><ul>");
                for (var target : httpAuthenticationTargets()) links.append("<li><a href=\"").append(target.get("login")).append("\">")
                        .append(target.get("protocol")).append(" protected login</a>; <a href=\"").append(target.get("request")).append("\">account proof</a></li>");
                if(!httpAuthentication.isEmpty())links.append("<li><a href=\"/http-auth/observations\">HTTP authentication observations</a></li>");
                for (var c : run.cases()) links.append("<li><a href=\"").append(c.startUri()).append("\">").append(c.id()).append("</a> (generation ").append(c.generation()).append(")</li>");
                reply(exchange, 200, "text/html; charset=utf-8", links.append("</ul></body></html>").toString()); return;
            }
            if(path.equals("/http-auth/observations") && exchange.getRequestMethod().equals("GET")) {
                json(exchange,200,Map.of("applications",httpAuthentication.entrySet().stream().map(entry->Map.of(
                        "protocol",entry.getKey().name(),"observations",entry.getValue().observations,
                        "requests",entry.getValue().requests,"truncated",entry.getValue().observationOverflow.get(),
                        "handshakes",entry.getValue().handshakes.get(),"posts",entry.getValue().applicationPosts.get(),
                        "applicationAuthorizations",entry.getValue().applicationAuthorizations.get(),
                        "leakedDirectives",entry.getValue().leakedDirectives.get())).toList()));return;
            }
            String[] parts = path.split("/", 4);
            if (parts.length < 4 || !parts[1].equals("cases")) throw LabRun.error(404, "NOT_FOUND");
            lease = run.find(parts[2], generation(exchange)); lease.enter(); entered = true;
            String route = parts[3];
            if (route.startsWith("protected/")) {
                byte[] body=exchange.getRequestBody().readNBytes(LabHostObservations.BODY_LIMIT+1);
                var shape=LabHostObservations.shape(exchange.getRequestHeaders(),exchange.getRequestMethod(),route.substring(10),body);
                observation=lease.hostObservations.begin(lease.id(),lease.generation(),exchange.getLocalAddress().getPort(),shape);
                protectedRoute(exchange,lease,route.substring(10),acceptedFacts);
            }
            else if (flows.handle(exchange, lease, route)) lease.routed.incrementAndGet();
            else throw LabRun.error(404, "NOT_FOUND");
        } catch (LabRun.ControlException ex) {
            int status = ex.status();
            if (exchange.getRequestURI().getPath().contains("/login/") && status == 413) status = 400;
            json(exchange, status, Map.of("error", ex.code()));
        } catch (IllegalArgumentException ex) { json(exchange, 400, Map.of("error", "BAD_INPUT")); }
        catch (Exception ex) { json(exchange, 500, Map.of("error", "INTERNAL")); }
        finally {
            try {
                if(observation!=0) {
                    @SuppressWarnings("unchecked") var roles=(List<String>)acceptedFacts.getOrDefault("roles",List.of());
                    lease.hostObservations.complete(observation,exchange.getResponseCode(),(String)acceptedFacts.get("account"),
                            (String)acceptedFacts.get("issuance"),roles);
                }
            } finally { if(entered)lease.leave();exchange.close();slots.release(); }
        }
    }
    private static void protectedRoute(HttpExchange exchange, LabRun.CaseLease lease, String subset,Map<String,Object> acceptedFacts) throws IOException {
        String method = exchange.getRequestMethod();
        if (!method.equals("GET") && !method.equals("POST")) { json(exchange, 405, Map.of("error", "method_not_allowed")); return; }
        boolean independent = subset.equals("independent-cookies");
        if (!independent && !Set.of("b", "c1", "c2", "b_c1", "b_c2", "c1_c2", "b_c1_c2").contains(subset)) throw LabRun.error(404, "NOT_FOUND");
        lease.routed.incrementAndGet(); if (!faults(exchange, lease.hit(LabRun.Phase.PROTECTED))) return;
        var required = EnumSet.noneOf(Role.class);
        if (independent) required.addAll(List.of(Role.C1, Role.C2));
        else for (var role : subset.split("_")) required.add(Role.valueOf(role.toUpperCase(Locale.ROOT)));
        var supplied = new EnumMap<Role, String>(Role.class);
        var authorization = exchange.getRequestHeaders().get("Authorization");
        if (authorization != null) {
            if (authorization.size() != 1 || !authorization.getFirst().matches("Bearer [A-Za-z0-9._~-]+")) throw LabRun.error(400, "BAD_INPUT");
            supplied.put(Role.B, authorization.getFirst().substring(7));
        }
        var cookies = cookies(exchange);
        for (Role role : List.of(Role.C1, Role.C2)) if (cookies.containsKey("LAB_" + role.name())) {
            String value = cookies.get("LAB_" + role.name()); if (!value.matches("[A-Za-z0-9._~-]+")) throw LabRun.error(400, "BAD_INPUT"); supplied.put(role, value);
        }
        if (!required.containsAll(supplied.keySet())) throw LabRun.error(400, "BAD_INPUT");
        if (!supplied.keySet().equals(required)) { json(exchange, 401, Map.of("error", "not_authenticated")); return; }
        Map<String, Object> response;
        synchronized (lease) {
            lease.check(); var accepted = lease.identities.accept(supplied, independent);
            if (accepted == null) { json(exchange, 401, Map.of("error", "not_authenticated")); return; }
            Long action = method.equals("POST") ? lease.actions.incrementAndGet() : null;
            response = new LinkedHashMap<>(); response.put("accountId", accepted.accountId());
            response.put("issuanceId", independent ? null : accepted.issuanceIds().getFirst());
            if (independent) response.put("issuanceIds", accepted.issuanceIds());
            response.put("acceptedRoles", accepted.roles()); response.put("actionId", action);
            acceptedFacts.put("account",accepted.accountId());
            acceptedFacts.put("issuance",independent?null:accepted.issuanceIds().getFirst());
            acceptedFacts.put("roles",accepted.roles().stream().map(Enum::name).toList());
            lease.event(LabRun.Phase.PROTECTED, "protected-accepted", List.of(Map.of("kind", "account", "value", accepted.accountId())));
        }
        json(exchange, 200, response);
    }
    static boolean faults(HttpExchange exchange, List<LabRun.FaultSpec> faults) throws IOException {
        for (var fault : faults) switch (fault.kind()) {
            case "CLOSE_BEFORE_RESPONSE" -> { exchange.close(); return false; }
            case "HTTP_ERROR" -> { json(exchange, fault.status(), Map.of("error", "controlled_http_error")); return false; }
            case "REJECT", "REJECT_REPLACEMENT" -> { json(exchange, 401, Map.of("error", "login_rejected")); return false; }
            default -> { }
        }
        return true;
    }
    static Map<String, String> cookies(HttpExchange exchange) {
        var result = new LinkedHashMap<String, String>();
        for (String header : exchange.getRequestHeaders().getOrDefault("Cookie", List.of())) for (String item : header.split(";")) {
            String[] pair = item.trim().split("=", 2); String name = pair[0];
            if (Set.of("LAB_C1", "LAB_C2").contains(name) && (pair.length != 2 || result.containsKey(name))) throw LabRun.error(400, "BAD_INPUT");
            if (pair.length == 2) result.put(name, pair[1]);
        }
        return result;
    }
    static Map<String, String> parameters(String raw) {
        var result = new LinkedHashMap<String, String>(); if (raw == null || raw.isEmpty()) return result;
        for (String field : raw.split("&")) {
            String[] pair = field.split("=", 2); String key = URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
            String value = pair.length == 2 ? URLDecoder.decode(pair[1], StandardCharsets.UTF_8) : "";
            if (result.putIfAbsent(key, value) != null) throw LabRun.error(400, "BAD_INPUT");
        }
        return result;
    }
    static long generation(HttpExchange exchange) {
        String raw = parameters(exchange.getRequestURI().getRawQuery()).get("generation");
        if (raw == null || !raw.matches("[1-9][0-9]*")) throw LabRun.error(409, "GENERATION_CONFLICT");
        try { return Long.parseLong(raw); } catch (NumberFormatException ex) { throw LabRun.error(400, "BAD_INPUT"); }
    }
    static void json(HttpExchange exchange, int status, Object body) throws IOException { reply(exchange, status, "application/json; charset=utf-8", LabRun.JSON.toJson(body)); }
    static void redirect(HttpExchange exchange, int status, URI destination) throws IOException { exchange.getResponseHeaders().set("Location", destination.toString()); reply(exchange, status, "text/plain; charset=utf-8", "Redirect"); }
    static void reply(HttpExchange exchange, int status, String type, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8); exchange.getResponseHeaders().set("Content-Type", type);
        exchange.getResponseHeaders().set("Cache-Control", "no-store"); exchange.getResponseHeaders().set("Connection", "close");
        exchange.sendResponseHeaders(status, bytes.length); exchange.getResponseBody().write(bytes);
    }
}
