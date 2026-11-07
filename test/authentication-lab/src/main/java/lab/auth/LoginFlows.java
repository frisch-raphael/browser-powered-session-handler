package lab.auth;

import com.google.gson.*;
import com.sun.net.httpserver.HttpExchange;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import lab.auth.FixtureIdentityStore.Role;

/** The test application's login state machine, independent of the extension's journey runner. */
public final class LoginFlows {
    static final class Transaction {
        final FixtureIdentityStore.Secret state = FixtureIdentityStore.randomSecret();
        final FixtureIdentityStore.Secret csrf = FixtureIdentityStore.randomSecret();
        final FixtureIdentityStore.Secret decoy = FixtureIdentityStore.randomSecret();
        final String variant;
        byte[] bodyHash;
        boolean decoyDone;
        String account;
        int stage, hop;
        FixtureIdentityStore.Issuance output;
        Transaction(String variant, String body) { this.variant = variant; }
    }
    private final LabRun run;
    LoginFlows(LabRun run) { this.run = run; }
    private static String variant(LabRun.CaseLease lease) { return lease.id().substring(lease.id().lastIndexOf('.') + 1); }
    public boolean handle(HttpExchange exchange, LabRun.CaseLease lease, String route) throws IOException {
        if (route.equals("fixture.js") || route.equals("sw.js")) {
            resource(exchange, route.equals("fixture.js") ? "fixture.js" : "service-worker.js", lease); return true;
        }
        if (route.startsWith("fresh/")) return fresh(exchange, lease, route);
        if (route.startsWith("surface/")) return surface(exchange, lease, route);
        if (route.equals("outputs") && exchange.getRequestMethod().equals("GET")) {
            synchronized (lease) {
                lease.check();
                if (!lease.loginCompleted || lease.current == null || !lease.marker.reveal().equals(ControlledApplication.cookies(exchange).get("LAB_FLOW")))
                    throw LabRun.error(401, "NOT_AUTHENTICATED");
                ControlledApplication.json(exchange, 200, lease.responseOutputs);
            }
            return true;
        }
        if (route.equals("selection/decoy")) {
            var tx = transaction(exchange, lease);
            if(exchange.getLocalAddress().getPort()!=run.alternateUri().getPort())throw LabRun.error(400,"WRONG_DECOY_ORIGIN");
            synchronized (lease) { lease.check(); tx.decoyDone = true;lease.event(LabRun.Phase.LOGIN,"decoy-cookie-set",List.of(Map.of("kind","origin","value","alternate"))); }
            cookie(exchange, lease, "LAB_C1", tx.decoy.reveal(), "HttpOnly; SameSite=Lax");
            ControlledApplication.redirect(exchange, 302, lease.endpoint("start?tx=" + tx.state.reveal())); return true;
        }
        if (route.equals("selection/final")) {
            var tx = transaction(exchange, lease);
            synchronized (lease) {
                lease.check(); if (tx.output == null || tx.stage != 4) throw LabRun.error(409, "STATE_CONFLICT");
                if (variant(lease).equals("early-cookie-rotated")){lease.identities.rotate(tx.output.id(), Role.C1);lease.event(LabRun.Phase.LOGIN,"selected-cookie-rotated",List.of(Map.of("kind","issuance","value",tx.output.id())));}
            }
            complete(exchange, lease, tx.output, List.of(), true); return true;
        }
        if (route.equals("start") && exchange.getRequestMethod().equals("GET")) {
            var row = run.spec().catalog().requirement(lease.id());
            if (row.capabilities().contains("HTTPS") || row.capabilities().contains("KEYCLOAK") || variant(lease).equals("lax-top-navigation")) {
                ControlledApplication.json(exchange, 503, Map.of("error", "selected_target_requires_later_prepared_environment")); return true;
            }
            if (lease.id().startsWith("BROW.fresh.")) { ControlledApplication.redirect(exchange, 302, lease.endpoint("fresh/" + variant(lease) + "/start")); return true; }
            String kind = lease.id().startsWith("BROW.basic.") ? variant(lease) : "json";
            boolean resume = ControlledApplication.parameters(exchange.getRequestURI().getRawQuery()).containsKey("tx");
            Transaction tx = resume ? transaction(exchange, lease) : new Transaction(kind, "");
            synchronized (lease) { lease.check(); if (resume && !tx.decoyDone) throw LabRun.error(409, "STATE_CONFLICT"); lease.transactions.put(tx.state.reveal(), tx); }
            if (Set.of("idp-client-decoy","same-name-domains").contains(variant(lease)) && !tx.decoyDone) {
                URI target = lease.endpoint("selection/decoy?tx=" + tx.state.reveal(), true);
                ControlledApplication.redirect(exchange, 302, URI.create(target.toString().replace("127.0.0.1", "localhost"))); return true;
            }
            if (kind.equals("csrf-cookie")) cookie(exchange, lease, "LAB_CSRF", tx.csrf.reveal(), "HttpOnly; SameSite=Lax");
            String fields = kind.equals("two-page") ? userField() : userField() + passField();
            if (kind.equals("csrf-cookie")) fields += "<input type=hidden name=csrf value=\"" + tx.csrf.reveal() + "\">";
            page(exchange, lease, "Login", form(lease.endpoint(kind.equals("two-page") ? "login/username?tx=" + tx.state.reveal() : "login/form?tx=" + tx.state.reveal()), fields, kind.equals("two-page") ? "next" : "login"), kind.equals("javascript") ? "javascript-login" : "form-login"); return true;
        }
        if ((route.equals("login/json") || route.equals("login/jwt")) && exchange.getRequestMethod().equals("POST")) {
            var faults = lease.hit(LabRun.Phase.LOGIN); if (!ControlledApplication.faults(exchange, faults)) return true;
            var body = LabRun.body(exchange, Set.of("username", "password"));
            FixtureIdentityStore.Issuance output;
            synchronized (lease) { lease.check(); lease.requireFreshObservation(); output = lease.identities.login(loginField(body, "username"), loginField(body, "password"), route.equals("login/jwt")); }
            if (output == null) {
                synchronized (lease) { lease.event(LabRun.Phase.LOGIN, "login-rejected-http-401", List.of()); }
                ControlledApplication.json(exchange, 401, Map.of("error", "login_rejected"));
            }
            else complete(exchange, lease, output, faults, false);
            return true;
        }
        if (route.equals("login/username") && exchange.getRequestMethod().equals("POST")) {
            var tx = transaction(exchange, lease); var fields = formBody(exchange);
            if (!fields.keySet().equals(Set.of("username"))) throw LabRun.error(400, "BAD_INPUT");
            synchronized (lease) { lease.check(); if (tx.stage != 0) throw LabRun.error(409, "STATE_CONFLICT"); tx.account = fields.get("username"); tx.stage = 1; }
            page(exchange, lease, "Password", form(lease.endpoint("login/form?tx=" + tx.state.reveal()), passField(), "login"), "form-login"); return true;
        }
        if (route.equals("login/form") && exchange.getRequestMethod().equals("POST")) {
            var tx = transaction(exchange, lease); String raw = formText(exchange); var fields = ControlledApplication.parameters(raw);
            var faults = lease.hit(LabRun.Phase.LOGIN); if (!ControlledApplication.faults(exchange, faults)) return true;
            synchronized (lease) {
                lease.check();
                lease.requireFreshObservation();
                if (tx.variant.equals("two-page")) {
                    if (tx.stage != 1 || !fields.keySet().equals(Set.of("password"))) throw LabRun.error(409, "STATE_CONFLICT");
                } else {
                    if (tx.stage != 0 || !fields.keySet().equals(tx.variant.equals("csrf-cookie") ? Set.of("username", "password", "csrf") : Set.of("username", "password"))) throw LabRun.error(400, "BAD_INPUT");
                    tx.account = fields.get("username");
                }
                if (tx.variant.equals("csrf-cookie") && (!tx.csrf.reveal().equals(fields.get("csrf")) || !tx.csrf.reveal().equals(ControlledApplication.cookies(exchange).get("LAB_CSRF")))) throw LabRun.error(403, "BAD_INPUT");
                if (!FixtureIdentityStore.valid(tx.account, fields.get("password"))) {
                    lease.event(LabRun.Phase.LOGIN, "login-rejected-http-401", List.of());
                    ControlledApplication.json(exchange, 401, Map.of("error", "login_rejected")); return true;
                }
                tx.stage = 2;
                tx.bodyHash = digest(raw);
            }
            if (tx.variant.equals("interstitial")) {
                page(exchange, lease, "Consent", form(lease.endpoint("login/consent?tx=" + tx.state.reveal()), "", "consent"), "consent"); return true;
            }
            if (lease.id().startsWith("BROW.redirect")) {
                if (variant(lease).equals("zero")) { finish(exchange, lease, tx, faults); return true; }
                int status = variant(lease).equals("post-303") ? 303 : variant(lease).equals("post-307") ? 307 : 302;
                synchronized (lease) { tx.stage = 3; }
                ControlledApplication.redirect(exchange, status, lease.endpoint("hop/0?tx=" + tx.state.reveal() + "&state=" + tx.state.reveal())); return true;
            }
            finish(exchange, lease, tx, faults); return true;
        }
        if (route.equals("login/consent") && exchange.getRequestMethod().equals("POST")) {
            var tx = transaction(exchange, lease); if (!formBody(exchange).isEmpty()) throw LabRun.error(400, "BAD_INPUT");
            synchronized (lease) { lease.check(); if (tx.stage != 2 || !tx.variant.equals("interstitial")) throw LabRun.error(409, "STATE_CONFLICT"); }
            finish(exchange, lease, tx, List.of()); return true;
        }
        if (route.startsWith("hop/")) { hop(exchange, lease, Integer.parseInt(route.substring(4))); return true; }
        if (route.equals("finish")) {
            var tx = transaction(exchange, lease); var query = ControlledApplication.parameters(exchange.getRequestURI().getRawQuery());
            synchronized (lease) {
                lease.check(); if (tx.stage != 3 || tx.hop != hops(lease) || !tx.state.reveal().equals(query.get("state")) || !"/login-complete".equals(query.get("return"))) throw LabRun.error(400, "BAD_INPUT");
                requireHopCookies(exchange, lease, tx, tx.hop);
            }
            finish(exchange, lease, tx, List.of()); return true;
        }
        return false;
    }
    private static int hops(LabRun.CaseLease lease) { return variant(lease).equals("one") || variant(lease).startsWith("post-") ? 1 : 3; }
    private void hop(HttpExchange exchange, LabRun.CaseLease lease, int index) throws IOException {
        var tx = transaction(exchange, lease); var query = ControlledApplication.parameters(exchange.getRequestURI().getRawQuery());
        var faults = lease.hit(LabRun.Phase.HOP); if (!ControlledApplication.faults(exchange, faults)) return;
        String kind = variant(lease);
        synchronized (lease) {
            lease.check();
            if (tx.stage != 3 || index != tx.hop || !tx.state.reveal().equals(query.get("state"))) throw LabRun.error(400, "BAD_INPUT");
            String method = exchange.getRequestMethod();
            if (kind.equals("post-307")) {
                if (!method.equals("POST") || !java.security.MessageDigest.isEqual(tx.bodyHash, digest(formText(exchange)))) throw LabRun.error(400, "BAD_INPUT");
            } else if (!method.equals("GET") || exchange.getRequestBody().read() != -1) throw LabRun.error(400, "BAD_INPUT");
            requireHopCookies(exchange, lease, tx, index);
            lease.event(LabRun.Phase.HOP, "hop-" + index + "-" + method, List.of());
            if (kind.equals("loop") || faults.stream().anyMatch(f -> f.kind().equals("REDIRECT_LOOP"))) { ControlledApplication.redirect(exchange, 302, lease.endpoint("hop/" + index + "?tx=" + tx.state.reveal() + "&state=" + tx.state.reveal())); return; }
            if (kind.equals("cookie-each-hop") && faults.stream().noneMatch(f -> f.kind().equals("OMIT_HOP_COOKIE"))) cookie(exchange, lease, "LAB_H" + index, tx.state.reveal(), "HttpOnly; SameSite=Lax");
            tx.hop++;
        }
        if (tx.hop < hops(lease)) {
            ControlledApplication.redirect(exchange, 302, lease.endpoint("hop/" + tx.hop + "?tx=" + tx.state.reveal() + "&state=" + tx.state.reveal(), kind.equals("cross-origin") && tx.hop % 2 == 1)); return;
        }
        String state = kind.equals("missing-state") ? "" : "&state=" + tx.state.reveal();
        String path = kind.equals("missing-callback") ? "missing-callback" : "finish";
        if (kind.equals("unreachable-hop")) {
            // A case-owned closed listener supplies a concrete refused connection, never an arbitrary external URL.
            try (var socket = new java.net.ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
                int port = socket.getLocalPort(); socket.close(); ControlledApplication.redirect(exchange, 302, URI.create("http://127.0.0.1:" + port + "/unreachable")); return;
            }
        }
        if (kind.equals("cancel-before-callback")) {
            lease.armFault(new LabRun.FaultSpec(LabRun.Phase.EXTRACTION, 1, "HOLD", null, null, "cancel-before-callback")); lease.hit(LabRun.Phase.EXTRACTION);
        }
        ControlledApplication.redirect(exchange, 302, lease.endpoint(path + "?tx=" + tx.state.reveal() + state + "&return=" + (kind.equals("wrong-return") ? "/wrong" : "/login-complete")));
    }
    private static void requireHopCookies(HttpExchange exchange, LabRun.CaseLease lease, Transaction tx, int count) {
        if (!variant(lease).equals("cookie-each-hop")) return;
        var cookies = ControlledApplication.cookies(exchange);
        for (int i = 0; i < count; i++) if (!tx.state.reveal().equals(cookies.get("LAB_H" + i))) throw LabRun.error(401, "BAD_INPUT");
    }
    private void finish(HttpExchange exchange, LabRun.CaseLease lease, Transaction tx, List<LabRun.FaultSpec> faults) throws IOException {
        FixtureIdentityStore.Issuance output;
        synchronized (lease) { lease.check(); if (tx.stage < 2) throw LabRun.error(409, "STATE_CONFLICT"); if (tx.output == null) tx.output = lease.identities.issueVerified(tx.account); output = tx.output; tx.stage = 4; }
        if (Set.of("early-cookie-rotated", "deleted-mid-flow").contains(variant(lease))) {
            cookie(exchange, lease, "LAB_C1", output.credential(Role.C1).reveal(), "HttpOnly; SameSite=Lax");
            ControlledApplication.redirect(exchange, 303, lease.endpoint("selection/final?tx=" + tx.state.reveal())); return;
        }
        complete(exchange, lease, output, faults, true);
    }
    private void complete(HttpExchange exchange, LabRun.CaseLease lease, FixtureIdentityStore.Issuance output, List<LabRun.FaultSpec> faults, boolean html) throws IOException {
        synchronized (lease) {
            lease.check(); lease.current = output; lease.loginCompleted = true;
            for (var f : faults) if (f.kind().equals("ROTATE_OUTPUT")) lease.identities.rotate(output.id(), f.role());
            for (Role role : List.of(Role.C1, Role.C2)) if (faults.stream().noneMatch(f -> f.kind().equals("OMIT_OUTPUT") && f.role() == role)) {
                String kind = variant(lease), attributes = kind.equals("secure-http-negative") ? "HttpOnly; SameSite=Lax; Secure" : "HttpOnly; SameSite=Lax";
                if (role == Role.C1 && kind.equals("deleted-mid-flow")) cookie(exchange, lease, "LAB_C1", "", "HttpOnly; SameSite=Lax; Max-Age=0");
                else if (role == Role.C1 && kind.equals("path")) cookieAt(exchange, "LAB_C1", output.credential(role).reveal(), "/cases/" + lease.id() + "/protected", attributes);
                else cookie(exchange, lease, "LAB_" + role, output.credential(role).reveal(), attributes);
            }
            if (Set.of("same-name-paths", "ambiguous").contains(variant(lease))) {cookieAt(exchange, "LAB_C1", lease.seeded("s2").credential(Role.C1).reveal(), "/", "HttpOnly; SameSite=Lax");lease.event(LabRun.Phase.LOGIN,"competing-path-cookie-set",List.of());}
            cookie(exchange, lease, "LAB_FLOW", lease.marker.reveal(), "HttpOnly; SameSite=Lax");
            lease.event(LabRun.Phase.LOGIN, "login-completed", List.of(Map.of("kind", "account", "value", output.account()), Map.of("kind", "issuance", "value", output.id())));
        }
        var body = new LinkedHashMap<String, Object>();
        if (faults.stream().noneMatch(f -> f.kind().equals("OMIT_OUTPUT") && f.role() == Role.B)) body.put("access_token", output.credential(Role.B).reveal());
        body.put("accountId", output.account()); body.put("issuanceId", output.id());
        synchronized (lease) { lease.check(); lease.responseOutputs = Map.copyOf(body); }
        if (variant(lease).equals("deep-link")) {
            cookie(exchange, lease, "LAB_B", output.credential(Role.B).reveal(), "HttpOnly; SameSite=Lax");
            ControlledApplication.redirect(exchange, 303, lease.endpoint("protected/b?view=details"));
        } else if (html) {
            String entry = "";
            if (lease.id().startsWith("BROW.surfaces.")) {
                String surface = switch (variant(lease)) {
                    case "early-response" -> "early"; case "late-response" -> "late"; case "nested-json" -> "nested";
                    case "popup" -> "popup-parent"; case "frame" -> "frame-parent"; case "cors-fetch" -> "cors"; case "service-worker" -> "sw/page";
                    default -> throw LabRun.error(400, "BAD_INPUT");
                };
                entry = "<a id=surface-entry href=\"" + escape(lease.endpoint("surface/" + surface).toString()) + "\">Open response surface</a>";
            }
            page(exchange, lease, "Login complete", "<div id=login-complete>Authenticated fixture account " + escape(output.account()) + "</div>" + entry + "<script type=application/json id=outputs>" + LabRun.JSON.toJson(body) + "</script>", "complete");
        }
        else ControlledApplication.json(exchange, 200, body);
    }
    private static Transaction transaction(HttpExchange exchange, LabRun.CaseLease lease) {
        String key = ControlledApplication.parameters(exchange.getRequestURI().getRawQuery()).get("tx");
        synchronized (lease) { lease.check(); var tx = lease.transactions.get(key); if (tx == null) throw LabRun.error(400, "BAD_INPUT"); return tx; }
    }
    private static Map<String, String> formBody(HttpExchange exchange) throws IOException {
        return ControlledApplication.parameters(formText(exchange));
    }
    private static String loginField(JsonObject object, String key) {
        var field = object.get(key); if (field == null || !field.isJsonPrimitive() || !field.getAsJsonPrimitive().isString()) throw LabRun.error(400, "BAD_INPUT"); return field.getAsString();
    }
    private static String formText(HttpExchange exchange) throws IOException {
        String type = exchange.getRequestHeaders().getFirst("Content-Type");
        if (type == null || !type.split(";", 2)[0].equalsIgnoreCase("application/x-www-form-urlencoded")) throw LabRun.error(400, "BAD_INPUT");
        byte[] body = exchange.getRequestBody().readNBytes(65_537); if (body.length > 65_536) throw LabRun.error(400, "BAD_INPUT");
        return new String(body, StandardCharsets.UTF_8);
    }
    private static byte[] digest(String value) { try { return java.security.MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)); } catch (java.security.NoSuchAlgorithmException ex) { throw new IllegalStateException(ex); } }
    static void cookie(HttpExchange exchange, LabRun.CaseLease lease, String name, String value, String attributes) {
        cookieAt(exchange, name, value, "/cases/" + lease.id(), attributes);
    }
    private static void cookieAt(HttpExchange exchange, String name, String value, String path, String attributes) { exchange.getResponseHeaders().add("Set-Cookie", name + "=" + value + "; Path=" + path + "; " + attributes); }
    private static String userField() { return "<input id=user name=username autocomplete=username>"; }
    private static String passField() { return "<input id=pass name=password type=password autocomplete=current-password>"; }
    private static String form(URI action, String fields, String button) { return "<form id=login-form method=post action=\"" + escape(action.toString()) + "\">" + fields + "<button id=" + button + " type=submit>Continue</button></form>"; }
    static String escape(String value) { return value.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;").replace(">", "&gt;"); }
    private static void page(HttpExchange exchange, LabRun.CaseLease lease, String title, String content, String kind) throws IOException {
        String template = readResource("login.html");
        String root = "/cases/" + lease.id() + "/";
        String result = template.replace("{{TITLE}}", title).replace("{{CONTENT}}", content).replace("{{ROOT}}", root).replace("{{GENERATION}}", Long.toString(lease.generation())).replace("{{KIND}}", kind)
                .replace("{{SCRIPT}}", escape(lease.endpoint("fixture.js").toString()));
        ControlledApplication.reply(exchange, 200, "text/html; charset=utf-8", result);
    }
    private static String readResource(String name) throws IOException {
        try (var stream = LoginFlows.class.getResourceAsStream("/web/" + name)) { if (stream == null) throw new IOException("Missing fixture web resource."); return new String(stream.readAllBytes(), StandardCharsets.UTF_8); }
    }
    private static void resource(HttpExchange exchange, String name, LabRun.CaseLease lease) throws IOException {
        exchange.getResponseHeaders().set("Service-Worker-Allowed", "/cases/" + lease.id() + "/");
        ControlledApplication.reply(exchange, 200, "text/javascript; charset=utf-8", readResource(name));
    }
    // The browser performs these observations; HTTP contract tests do not claim browser policy or context isolation.
    private boolean fresh(HttpExchange exchange, LabRun.CaseLease lease, String route) throws IOException {
        String[] parts = route.split("/");
        if (parts.length != 3 || !Set.of("cookies", "local-storage", "session-storage", "service-worker").contains(parts[1]) || !lease.id().equals("BROW.fresh." + parts[1])) throw LabRun.error(404, "NOT_FOUND");
        LabRun.FreshPhase phase;
        synchronized (lease) { lease.check(); phase = lease.freshPhase; if (phase == null) throw LabRun.error(409, "STATE_CONFLICT"); }
        String kind = parts[1], action = parts[2];
        if (action.equals("start")) { ControlledApplication.redirect(exchange, 302, lease.endpoint("fresh/" + kind + "/" + (phase == LabRun.FreshPhase.PRIME ? "prime" : "probe"))); return true; }
        if (action.equals("observe") && exchange.getRequestMethod().equals("POST")) {
            var body = LabRun.body(exchange, Set.of("phase", "present"));
            if (!LabRun.text(body, "phase").equals(phase.name()) || !body.get("present").isJsonPrimitive() || !body.getAsJsonPrimitive("present").isBoolean()) throw LabRun.error(409, "STATE_CONFLICT");
            boolean present = body.get("present").getAsBoolean();
            if (kind.equals("cookies")) {
                var cookies = ControlledApplication.cookies(exchange);
                present = phase == LabRun.FreshPhase.PRIME ? lease.marker.reveal().equals(cookies.get("LAB_FRESH_MARK")) : cookies.containsKey("LAB_FRESH_MARK");
            }
            synchronized (lease) {
                lease.check(); if (lease.freshPhase != phase) throw LabRun.error(409, "STATE_CONFLICT");
                if (phase == LabRun.FreshPhase.PRIME && present) lease.primed = true;
                if (phase == LabRun.FreshPhase.PROBE) lease.probeObserved = true;
                lease.event(LabRun.Phase.LOGIN, phase == LabRun.FreshPhase.PRIME ? "fresh-prime-observed" : "fresh-probe-observed",
                        List.of(Map.of("kind", "variant", "value", kind), Map.of("kind", "phase", "value", phase.name()), Map.of("kind", "presence", "value", present ? "present" : "absent")));
            }
            ControlledApplication.json(exchange, 200, Map.of("present", present)); return true;
        }
        if (!exchange.getRequestMethod().equals("GET") || !action.equals(phase == LabRun.FreshPhase.PRIME ? "prime" : "probe")) throw LabRun.error(409, "STATE_CONFLICT");
        if (kind.equals("cookies") && phase == LabRun.FreshPhase.PRIME) cookie(exchange, lease, "LAB_FRESH_MARK", lease.marker.reveal(), "HttpOnly; SameSite=Lax");
        var tx = new Transaction("json", ""); synchronized (lease) { lease.check(); lease.transactions.put(tx.state.reveal(), tx); }
        String content = "<div id=fresh-observation data-variant=\"" + kind + "\" data-phase=\"" + phase + "\" data-marker=\"" + lease.marker.reveal() + "\"></div><section id=fresh-form hidden>" + form(lease.endpoint("login/form?tx=" + tx.state.reveal()), userField() + passField(), "login") + "</section>";
        page(exchange, lease, "Fresh browser state", content, "fresh"); return true;
    }
    private boolean surface(HttpExchange exchange, LabRun.CaseLease lease, String route) throws IOException {
        synchronized (lease) {
            lease.check();
            if (lease.current == null || !lease.marker.reveal().equals(ControlledApplication.cookies(exchange).get("LAB_FLOW"))) throw LabRun.error(401, "UNAUTHORIZED");
        }
        if (route.equals("surface/ready") && exchange.getRequestMethod().equals("POST")) {
            LabRun.body(exchange, Set.of()); synchronized (lease) { lease.event(LabRun.Phase.EXTRACTION, "ready", List.of()); }
            ControlledApplication.json(exchange, 200, Map.of("ready", true)); return true;
        }
        if (route.equals("surface/observe") && exchange.getRequestMethod().equals("POST")) {
            var body = LabRun.body(exchange, Set.of("surface", "stage"));
            String surface = LabRun.text(body, "surface"), stage = LabRun.text(body, "stage");
            String selected = switch (variant(lease)) {
                case "early-response" -> "early"; case "late-response" -> "late"; case "nested-json" -> "nested";
                case "popup" -> "popup-parent"; case "frame" -> "frame-parent"; case "cors-fetch" -> "cors"; case "service-worker" -> "worker";
                default -> "";
            };
            var stages = surface.equals("cors") ? Set.of("ready", "cors-done", "cors-denied", "cors-unexpected", "fixture-stage-failed") :
                    surface.equals("worker") ? Set.of("ready", "worker-controlled", "done", "fixture-stage-failed") :
                    surface.equals("early") ? Set.of("ready", "fixture-stage-failed") : Set.of("ready", "done", "fixture-stage-failed");
            if (!lease.id().startsWith("BROW.surfaces.") || !surface.equals(selected) || !stages.contains(stage)) throw LabRun.error(400, "BAD_INPUT");
            String eventStage = stage.startsWith(surface + "-") ? stage.substring(surface.length() + 1) : stage;
            synchronized (lease) { lease.check(); lease.event(LabRun.Phase.EXTRACTION, "page-" + surface + "-" + eventStage, List.of()); }
            ControlledApplication.json(exchange, 200, Map.of("observed", true)); return true;
        }
        if (route.equals("surface/cors-denied")) {
            synchronized (lease) { lease.check(); lease.event(LabRun.Phase.EXTRACTION, "cors-probe-requested", List.of()); }
            ControlledApplication.json(exchange, 200, Map.of("probe", "denied")); return true;
        }
        if (route.equals("surface/token")) {
            String kind = ControlledApplication.parameters(exchange.getRequestURI().getRawQuery()).get("kind");
            if (kind == null || !Set.of("early", "late", "nested", "popup", "frame", "cors", "worker").contains(kind)) throw LabRun.error(400, "BAD_INPUT");
            if (kind.equals("cors")) {
                if (!run.applicationUri().toString().equals(exchange.getRequestHeaders().getFirst("Origin"))) throw LabRun.error(403, "BAD_INPUT");
                exchange.getResponseHeaders().set("Access-Control-Allow-Origin", run.applicationUri().toString());
                exchange.getResponseHeaders().set("Access-Control-Allow-Credentials", "true"); exchange.getResponseHeaders().set("Vary", "Origin");
            }
            if (kind.equals("late")) synchronized (lease) {
                lease.event(LabRun.Phase.EXTRACTION, "late-token-requested", List.of());
                if (lease.faults.stream().noneMatch(f -> "late-token".equals(f.checkpoint()))) lease.armFault(new LabRun.FaultSpec(LabRun.Phase.EXTRACTION, lease.occurrences.getOrDefault(LabRun.Phase.EXTRACTION, 0) + 1, "HOLD", null, null, "late-token"));
            }
            var faults = lease.hit(LabRun.Phase.EXTRACTION); if (!ControlledApplication.faults(exchange, faults)) return true;
            String token;
            synchronized (lease) { lease.check(); token = lease.current.credential(Role.B).reveal(); lease.event(LabRun.Phase.EXTRACTION, "token-emitted", List.of(Map.of("kind", "surface", "value", kind))); }
            Object body = kind.equals("nested") ? Map.of("result", Map.of("authentication", Map.of("access_token", token))) : Map.of("data", Map.of("access_token", token));
            ControlledApplication.json(exchange, 200, body); return true;
        }
        String content = switch (route) {
            case "surface/early" -> "<div id=surface-stage data-surface=early></div>";
            case "surface/late", "surface/nested", "surface/cors", "surface/sw/page" -> "<div id=surface-stage data-surface=\"" + (route.endsWith("page") ? "worker" : route.substring(8)) + "\" data-api=\"" + run.alternateUri() + "\"></div><button id=fetch-token>Fetch token</button>";
            case "surface/popup-parent" -> "<div id=surface-stage data-surface=popup-parent></div><button id=open-popup>Open login popup</button>";
            case "surface/frame-parent" -> "<div id=surface-stage data-surface=frame-parent></div><button id=load-frame>Load login frame</button>";
            case "surface/popup-child" -> "<div id=surface-stage data-surface=popup-child></div>";
            case "surface/frame-child" -> "<div id=surface-stage data-surface=frame-child></div>";
            default -> null;
        };
        if (content == null) return false;
        page(exchange, lease, "Browser response surface", content, "surface"); return true;
    }
}
