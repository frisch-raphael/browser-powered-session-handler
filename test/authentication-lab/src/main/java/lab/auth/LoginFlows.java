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
    /** Reuses the controlled origins and control endpoints for password/metadata and rapid-Stop qualification. */
    public static ControlObservations recording(ControlledApplication.Origin origin, ControlledApplication.Origin cross) {
        var observed = journeyControls(origin, cross);
        origin.route("/recording", exchange -> ControlledApplication.Origin.reply(exchange, 200, "text/html; charset=utf-8",
                readResource("recording.html").replace("{{OUTER}}", cross.url("/controls/outer").toString())));
        origin.route("/recording-submit", exchange -> {
            observed.recordedSubmission.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            ControlledApplication.Origin.reply(exchange, 200, "application/json", "{\"access_token\":\"recording-token\"}");
        });
        return observed;
    }
    /** Shared control/frame/popup evidence for native replay and recorder qualification. */
    public static final class ControlObservations {
        public final java.util.concurrent.atomic.AtomicReference<String> nested = new java.util.concurrent.atomic.AtomicReference<>();
        public final java.util.concurrent.atomic.AtomicReference<String> popup = new java.util.concurrent.atomic.AtomicReference<>();
        public final java.util.concurrent.atomic.AtomicInteger popupSubmissions = new java.util.concurrent.atomic.AtomicInteger();
        public final java.util.concurrent.atomic.AtomicInteger completed = new java.util.concurrent.atomic.AtomicInteger();
        public final java.util.concurrent.atomic.AtomicReference<String> recordedSubmission = new java.util.concurrent.atomic.AtomicReference<>();
    }

    /** Installs common form controls, nested cross-origin frames and popup fault controls on owned origins. */
    public static ControlObservations journeyControls(ControlledApplication.Origin origin, ControlledApplication.Origin cross) {
        var observed = new ControlObservations();
        origin.route("/login", exchange -> ControlledApplication.Origin.reply(exchange, 200, "text/html; charset=utf-8", """
                <label><input type=checkbox id=check>Remember</label>
                <label><input type=radio name=role id=radio>Administrator</label>
                <select id=single><option value=guest>Guest</option><option value=admin>Administrator</option></select>
                <select id=multi multiple><option value=''>Empty value</option><option value='blue,green'>Two colors</option><option value=old selected>Old</option></select>
                <input id=enter aria-label='Submission field'><output id=key-proof></output>
                <iframe id=outer src='%s'></iframe>
                <button id=open onclick="window.open('/controls/popup')">Open login popup</button>
                <button id=double onclick="window.open('/controls/popup');window.open('/controls/popup')">Open two popups</button>
                <button id=closed onclick="window.open('/controls/closed')">Open closing popup</button>
                <button id=detach onclick="document.querySelector('#outer').remove()">Remove frame</button>
                <button id=finish>Finish</button>
                <script>
                document.querySelector('#enter').onkeydown=e=>{if(e.key==='Enter'&&e.ctrlKey)document.querySelector('#key-proof').textContent='ctrl-enter'};
                document.querySelector('#finish').onclick=()=>fetch('/token',{method:'POST',body:JSON.stringify({
                  checked:document.querySelector('#check').checked,radio:document.querySelector('#radio').checked,
                  single:document.querySelector('#single').value,multi:Array.from(document.querySelector('#multi').selectedOptions,o=>o.value),
                  key:document.querySelector('#key-proof').textContent})});
                </script>
                """.formatted(cross.url("/controls/outer"))));
        cross.route("/controls/outer", exchange -> ControlledApplication.Origin.reply(exchange, 200, "text/html",
                "<p id=outer-marker>Outer frame</p><iframe id=inner src='" + origin.url("/controls/inner") + "'></iframe>"));
        origin.route("/controls/inner", exchange -> ControlledApplication.Origin.reply(exchange, 200, "text/html", """
                <input id=nested><button id=framebutton>Continue inside frame</button>
                <script>document.querySelector('#framebutton').onclick=()=>fetch('/controls/frame-state',{method:'POST',body:document.querySelector('#nested').value})
                  .then(()=>{history.pushState({},'', '/controls/inner?done');let marker=document.createElement('p');marker.id='frame-done';marker.textContent='Frame completed';document.body.append(marker)})</script>
                """));
        origin.route("/controls/frame-state", exchange -> {
            observed.nested.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            ControlledApplication.Origin.reply(exchange, 200, "text/plain", "ok");
        });
        origin.route("/controls/popup", exchange -> ControlledApplication.Origin.reply(exchange, 200, "text/html", """
                <form><input id=popup-text><button>Submit</button></form><script>
                document.querySelector('form').onsubmit=e=>{e.preventDefault();fetch('/controls/popup-state',{method:'POST',body:document.querySelector('#popup-text').value})
                  .then(()=>{let marker=document.createElement('p');marker.id='submitted';marker.textContent='Submitted';document.body.append(marker)})}</script>
                """));
        origin.route("/controls/closed", exchange -> ControlledApplication.Origin.reply(exchange, 200, "text/html", "<script>setTimeout(()=>window.close(),100)</script>"));
        origin.route("/controls/popup-state", exchange -> {
            observed.popup.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            observed.popupSubmissions.incrementAndGet();
            ControlledApplication.Origin.reply(exchange, 200, "text/plain", "ok");
        });
        origin.route("/token", exchange -> {
            JsonObject state = JsonParser.parseString(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)).getAsJsonObject();
            boolean correct = !state.get("checked").getAsBoolean() && state.get("radio").getAsBoolean()
                    && state.get("single").getAsString().equals("admin") && state.get("multi").toString().equals("[\"\",\"blue,green\"]")
                    && state.get("key").getAsString().equals("ctrl-enter") && "nested value".equals(observed.nested.get()) && "popup value".equals(observed.popup.get());
            if (correct) observed.completed.incrementAndGet();
            ControlledApplication.Origin.reply(exchange, correct ? 200 : 400, "application/json", correct ? "{\"access_token\":\"controls-token\"}" : "{}");
        });
        return observed;
    }

    /** Token-response variants shared by focused browser regressions. */
    public enum TokenResponse { SUCCESS, MISSING_OUTPUT, AUTH_REJECTED, TEMPORARY_SERVICE }

    /** Installs a token-fetch login on an owned HTTP or HTTPS origin; the caller starts it. */
    public static ControlledApplication.Origin tokenFetch(ControlledApplication.Origin origin, String token, TokenResponse response) {
        return tokenFetch(origin, token, response, ignored -> {});
    }

    /** Installs the shared response while leaving production-specific request assertions in the caller. */
    public static ControlledApplication.Origin tokenFetch(ControlledApplication.Origin origin, String token, TokenResponse response,
            java.util.function.Consumer<HttpExchange> tokenObserved) {
        origin.route("/login", exchange -> ControlledApplication.Origin.reply(exchange, 200, "text/html", "<script>fetch('/token')</script>"));
        origin.route("/token", exchange -> {
            tokenObserved.accept(exchange);
            int status = switch (response) { case AUTH_REJECTED -> 401; case TEMPORARY_SERVICE -> 503; default -> 200; };
            if (response != TokenResponse.SUCCESS) exchange.getResponseHeaders().set("Retry-After", "7");
            ControlledApplication.Origin.reply(exchange, status, "application/json", response == TokenResponse.SUCCESS
                    ? LabRun.JSON.toJson(Map.of("access_token", token)) : "{}");
        });
        return origin;
    }

    /** Installs one login exposing JSON, cookies and an optional regex capture surface. */
    public static ControlledApplication.Origin combinedOutputs(ControlledApplication.Origin origin, boolean tenantCookie, boolean csrfMeta) {
        origin.route("/login", exchange -> {
            exchange.getResponseHeaders().add("Set-Cookie", "sid=session-value; Path=/; HttpOnly");
            ControlledApplication.Origin.reply(exchange, 200, "text/html; charset=utf-8",
                    (csrfMeta ? "<meta name='csrf' content='csrf-value'>" : "") + "<script>fetch('/token')</script>");
        });
        origin.route("/token", exchange -> {
            if (tenantCookie) exchange.getResponseHeaders().add("Set-Cookie", "tenant=tenant-value; Path=/; HttpOnly");
            ControlledApplication.Origin.reply(exchange, 200, "application/json", "{\"access_token\":\"access-value\"}");
        });
        return origin;
    }

    /** Installs the standalone form used by isolated artifact/runtime probes. */
    public static ControlledApplication.Origin probeForm(ControlledApplication.Origin origin, String token, String cookie) {
        return probeForm(origin, token, cookie, null);
    }

    /** Installs the same form with an optional anonymous session cookie issued before submission. */
    public static ControlledApplication.Origin probeForm(ControlledApplication.Origin origin, String token, String cookie, String anonymousCookie) {
        origin.route("/login", exchange -> {
            if (anonymousCookie != null) exchange.getResponseHeaders().add("Set-Cookie", "session=" + anonymousCookie + "; Path=/; HttpOnly");
            ControlledApplication.Origin.reply(exchange, 200, "text/html",
                    "<form method='POST' action='/token'><input id='user' name='user'><button id='submit'>Sign in</button></form>");
        });
        origin.route("/token", exchange -> {
            exchange.getRequestBody().readAllBytes();
            if (cookie != null) exchange.getResponseHeaders().add("Set-Cookie", "session=" + cookie + "; Path=/; HttpOnly");
            ControlledApplication.Origin.reply(exchange, 200, "application/json", LabRun.JSON.toJson(Map.of("access_token", token)));
        });
        return origin;
    }

    /** Installs an output-free login; observation can request cancellation in its test owner. */
    public static ControlledApplication.Origin noOutput(ControlledApplication.Origin origin, Runnable observed) {
        origin.route("/login", exchange -> {
            observed.run();
            ControlledApplication.Origin.reply(exchange, 200, "text/html", "never emits token");
        });
        return origin;
    }

    /** Fresh-cookie observations are local to one fixture and never shared between tests. */
    public static final class FreshCookie {
        private final java.util.concurrent.atomic.AtomicInteger visits = new java.util.concurrent.atomic.AtomicInteger();
        private final java.util.concurrent.atomic.AtomicInteger oldCookies = new java.util.concurrent.atomic.AtomicInteger();
        public int visits() { return visits.get(); }
        public int oldCookies() { return oldCookies.get(); }
    }

    /** Installs a new cookie per visit and detects cookies carried from a previous context. */
    public static FreshCookie freshCookie(ControlledApplication.Origin origin) {
        var observation = new FreshCookie();
        origin.route("/login", exchange -> {
            if (exchange.getRequestHeaders().getFirst("Cookie") != null) observation.oldCookies.incrementAndGet();
            exchange.getResponseHeaders().add("Set-Cookie", "session=fresh-" + observation.visits.incrementAndGet() + "; Path=/; HttpOnly");
            ControlledApplication.Origin.reply(exchange, 200, "text/html", "<script>fetch('/token')</script>");
        });
        origin.route("/token", exchange -> ControlledApplication.Origin.reply(exchange, 200, "application/json", "{\"access_token\":\"early-token\"}"));
        return observation;
    }

    /** Observations and invalidation control for the browser session-recovery fixture. */
    public static final class Recovery {
        public final java.util.concurrent.atomic.AtomicInteger loginAttempts = new java.util.concurrent.atomic.AtomicInteger();
        public final java.util.concurrent.atomic.AtomicInteger issuances = new java.util.concurrent.atomic.AtomicInteger();
        public final java.util.concurrent.atomic.AtomicInteger protectedIngress = new java.util.concurrent.atomic.AtomicInteger();
        public final java.util.concurrent.atomic.AtomicInteger acceptedActions = new java.util.concurrent.atomic.AtomicInteger();
        public final java.util.concurrent.atomic.AtomicReference<String> acceptedToken = new java.util.concurrent.atomic.AtomicReference<>();
    }

    /** Installs one successful acquisition, two temporary failures, then successful recovery. */
    public static Recovery recovery(ControlledApplication.Origin origin) {
        var state = new Recovery();
        origin.route("/login", exchange -> {
            int attempt = state.loginAttempts.incrementAndGet();
            boolean unavailable = attempt == 2 || attempt == 3;
            ControlledApplication.Origin.reply(exchange, unavailable ? 503 : 200, "text/html",
                    unavailable ? "temporarily unavailable" : "<script>fetch('/token')</script>");
        });
        origin.route("/token", exchange -> {
            String token = "browser-recovery-" + state.issuances.incrementAndGet(); state.acceptedToken.set(token);
            ControlledApplication.Origin.reply(exchange, 200, "application/json", LabRun.JSON.toJson(Map.of("access_token", token)));
        });
        origin.route("/protected", exchange -> {
            state.protectedIngress.incrementAndGet();
            boolean accepted = state.acceptedToken.get() != null
                    && ("Bearer " + state.acceptedToken.get()).equals(exchange.getRequestHeaders().getFirst("Authorization"));
            if (accepted) state.acceptedActions.incrementAndGet();
            ControlledApplication.Origin.reply(exchange, accepted ? 200 : 401, "text/plain", accepted ? "fixture-account" : "session lost");
        });
        return state;
    }

    /** Installs the retained-step form, redirect and delayed normalized-token response. */
    public static java.util.concurrent.atomic.AtomicInteger normalizedForm(ControlledApplication.Origin origin) {
        var posted = new java.util.concurrent.atomic.AtomicInteger();
        origin.route("/login", exchange -> ControlledApplication.Origin.reply(exchange, 200, "text/html", """
                <input id='name'><input id='password' type='password'><button id='submit'>Sign in</button>
                <script>submit.onclick=async()=>{await fetch('/credentials',{method:'POST',body:JSON.stringify({user:document.querySelector('#name').value,password:document.querySelector('#password').value})});location.href='/done'};</script>
                """));
        origin.route("/credentials", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            if (body.contains("fixture-user") && body.contains("fixture-password")) posted.incrementAndGet();
            ControlledApplication.Origin.reply(exchange, 200, "text/plain", "ok");
        });
        origin.route("/done", exchange -> ControlledApplication.Origin.reply(exchange, 200, "text/html", "<div id='done'>Ready</div><script>setTimeout(()=>fetch('/token'),1200)</script>"));
        origin.route("/token", exchange -> ControlledApplication.Origin.reply(exchange, 200, "application/json", "{\"access_token\":\"  Bearer fixture-token  \"}"));
        return posted;
    }

    /** Installs an unrelated failing asset and exposes its actual request observations. */
    public static void unrelatedFailure(ControlledApplication.Origin origin, Runnable loginObserved, Runnable assetObserved) {
        origin.route("/login", exchange -> {
            loginObserved.run();
            ControlledApplication.Origin.reply(exchange, 200, "text/html", "<body><script>fetch('/unrelated').then(()=>{let done=document.createElement('div');done.id='asset-observed';done.textContent='Asset observed';document.body.append(done)})</script>");
        });
        origin.route("/unrelated", exchange -> {
            assetObserved.run(); ControlledApplication.Origin.reply(exchange, 503, "text/plain", "temporary third-party asset");
        });
    }

    /** Bounded response hold used by actual-browser step-failure assertions. */
    public static final class StepFailure {
        private final java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        public void release() { release.countDown(); }
    }

    /** Installs missing/ambiguous controls and a bounded busy response on the shared origin. */
    public static StepFailure stepFailure(ControlledApplication.Origin origin, boolean presentCanary) {
        var state = new StepFailure();
        origin.route("/login", exchange -> ControlledApplication.Origin.reply(exchange, 200, "text/html", "<input><input>"
                + (presentCanary ? "<input id=CANARY_SELECTOR>" : "")
                + "<button id=begin-busy onclick=\"fetch('/busy')\">Begin</button>"));
        origin.route("/busy", exchange -> {
            try { state.release.await(5, java.util.concurrent.TimeUnit.SECONDS); ControlledApplication.Origin.reply(exchange, 200, "text/plain", "ready"); }
            catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); exchange.close(); }
        });
        return state;
    }

    /** Live, read-only observations for the complete owned browser-surface recipe. */
    public record BrowserSurfaces(Set<String> requiredPaths, Set<String> reachedPaths) {
        public BrowserSurfaces { requiredPaths = Set.copyOf(requiredPaths); reachedPaths = Collections.unmodifiableSet(reachedPaths); }
    }

    /** Installs redirect/frame/popup/fetch/worker/WebSocket coverage without extension-specific policy. */
    public static BrowserSurfaces ownedBrowserSurfaces(ControlledApplication.Origin origin,
            ControlledApplication.Origin cross, java.util.function.Consumer<HttpExchange> webSocketObserved) {
            var requiredPaths=Set.of("/redirect","/redirected","/frame-fetch","/popup-fetch","/cross","/dedicated-fetch","/sw-fetch","/ws");
            Set<String> reachedPaths=java.util.concurrent.ConcurrentHashMap.newKeySet();
            java.util.function.Consumer<String> reached=path->{if(requiredPaths.contains(path))reachedPaths.add(path);};
            cross.route("/cross", e -> { reached.accept("/cross");e.getResponseHeaders().set("Access-Control-Allow-Origin", "*"); ControlledApplication.Origin.reply(e, 200, "text/plain", "cross"); });
            origin.route("/login", e -> ControlledApplication.Origin.reply(e, 200, "text/html", """
                <body><script>
                (async()=>{
                const signal=name=>new Promise(resolve=>{const listener=e=>{if(e.data===name){window.removeEventListener('message',listener);resolve();}};window.addEventListener('message',listener);});
                await fetch('/redirect');await fetch('%s');
                const frameReady=signal('frame-ready'),frame=document.createElement('iframe');frame.src='/frame';document.body.append(frame);await frameReady;
                const popupReady=signal('popup-ready');window.open('/popup');await popupReady;
                const worker=new Worker('/worker.js');await new Promise(resolve=>worker.onmessage=()=>resolve());
                const swReady=new Promise(resolve=>navigator.serviceWorker.addEventListener('message',e=>{if(e.data==='sw-ready')resolve();}));
                const registration=await navigator.serviceWorker.register('/sw.js');await navigator.serviceWorker.ready;registration.active.postMessage('go');
                await swReady;await new Promise(resolve=>{const ws=new WebSocket('ws://'+location.host+'/ws');ws.onopen=()=>{ws.close();resolve();};});
                await fetch('/token');
                })().catch(()=>fetch('/fixture-error'));</script>
                """.formatted(cross.url("/cross"))));
            origin.route("/redirect", e -> { reached.accept("/redirect");e.getResponseHeaders().set("Location", "/redirected"); e.sendResponseHeaders(302, -1); e.close(); });
            for (String path : List.of("/redirected", "/frame-fetch", "/popup-fetch", "/dedicated-fetch", "/sw-fetch")) origin.route(path, e -> {reached.accept(path);ControlledApplication.Origin.reply(e, 200, "text/plain", "ok");});
            origin.route("/frame", e -> ControlledApplication.Origin.reply(e, 200, "text/html", "<script>fetch('/frame-fetch').then(()=>parent.postMessage('frame-ready','*'))</script>"));
            origin.route("/popup", e -> ControlledApplication.Origin.reply(e, 200, "text/html", "<script>fetch('/popup-fetch').then(()=>opener.postMessage('popup-ready','*'))</script>"));
            origin.route("/worker.js", e -> ControlledApplication.Origin.reply(e, 200, "application/javascript", "fetch('/dedicated-fetch').then(()=>postMessage('worker-ready'))"));
            origin.route("/sw.js", e -> ControlledApplication.Origin.reply(e, 200, "application/javascript", "self.addEventListener('install',e=>self.skipWaiting());self.addEventListener('activate',e=>e.waitUntil(clients.claim()));self.addEventListener('message',e=>e.waitUntil(fetch('/sw-fetch').then(()=>e.source.postMessage('sw-ready'))));"));
            origin.route("/ws", exchange -> {
                reached.accept("/ws"); webSocketObserved.accept(exchange); TransportFixtures.webSocketUpgrade(exchange);
            });
            origin.route("/token", e -> {
                if(reachedPaths.containsAll(requiredPaths))ControlledApplication.Origin.reply(e,200,"application/json","{\"access_token\":\"marked-token\"}");
                else ControlledApplication.Origin.reply(e,500,"text/plain","owned browser surfaces incomplete");
            });
        return new BrowserSurfaces(requiredPaths, reachedPaths);
    }

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
        // This opt-in host observation precedes response delivery, so it does not claim browser DOM readiness.
        if(lease.id().equals("BROW.basic.json")&&exchange.getRequestMethod().equals("GET")&&exchange.getRequestURI().getPath().equals(root+"start")) {
            String alias=ControlledApplication.parameters(exchange.getRequestURI().getRawQuery()).get("bpsh_host_journey");
            if(alias!=null) {
                if(!Set.of("host_a","host_b","host_failure_a","host_failure_b").contains(alias))throw LabRun.error(400,"BAD_INPUT");
                synchronized(lease){lease.check();lease.event(LabRun.Phase.LOGIN,"host-login-page-response-start",List.of(Map.of("kind","journey-alias","value",alias)));}
            }
        }
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
                if (!lease.hasFaultCheckpoint("late-token")) lease.armFault(new LabRun.FaultSpec(LabRun.Phase.EXTRACTION, lease.occurrences.getOrDefault(LabRun.Phase.EXTRACTION, 0) + 1, "HOLD", null, null, "late-token"));
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
