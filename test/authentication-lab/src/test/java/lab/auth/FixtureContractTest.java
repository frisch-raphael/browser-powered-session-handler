package lab.auth;

import com.google.gson.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.net.*;
import java.net.http.*;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;
import lab.auth.FixtureIdentityStore.Role;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FixtureContractTest {
    @TempDir static Path root;
    LabRun run;
    HttpClient http;
    final AtomicInteger matrixAccepted = new AtomicInteger(), matrixRejected = new AtomicInteger();
    boolean matrixSelected;
    @BeforeAll void startTargets() throws Exception {
        run = LabRun.start(new LabRun.RunSpec(UUID.randomUUID(), List.of("all"), ScenarioCatalog.load(), root, List.of(), 5_000));
        http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).followRedirects(HttpClient.Redirect.NEVER).build();
    }
    @AfterAll void closeTargets() {
        try { if(matrixSelected){assertEquals(42, matrixAccepted.get()); assertEquals(469, matrixRejected.get());} }
        finally { http.close(); run.close(); }
    }
    @TestFactory Stream<DynamicTest> everyRequiredCredentialCombinationAuthenticatesItsActualIdentity() {
        matrixSelected=true;
        return ScenarioCatalog.load().requirements().stream().filter(r -> r.group().equals("FIX.matrix")&&r.disposition()!=ScenarioCatalog.Disposition.EXCLUDED).map(row -> DynamicTest.dynamicTest("[case=" + row.id() + "]", () -> {
            long started = System.nanoTime();
            try (var lease = run.prepareCase(row.id())) {
                var assigned = new LinkedHashMap<String, String>(); row.assignments().forEach(a -> assigned.put(a.slot(), a.value()));
                var supplied = new EnumMap<Role, String>(Role.class);
                for (Role role : Role.values()) if (assigned.containsKey(role.name()) && !assigned.get(role.name()).equals("none")) supplied.put(role, lease.seeded(assigned.get(role.name())).credential(role).reveal());
                var response = request(lease, assigned.get("required"), supplied, "GET", null);
                int expected = Integer.parseInt(fact(row, "httpStatus")); assertEquals(expected, response.statusCode());
                if (expected == 200) {
                    matrixAccepted.incrementAndGet(); var body = json(response);
                    assertEquals(fact(row, "account"), body.get("accountId").getAsString());
                    assertEquals(fact(row, "issuance"), body.get("issuanceId").getAsString());
                    assertEquals(supplied.size(), body.getAsJsonArray("acceptedRoles").size());
                } else matrixRejected.incrementAndGet();
                assertEquals(0L, counters(lease).get("actions"));
                capture(row, lease, response, started);
            }
        }));
    }
    @TestFactory Stream<DynamicTest> explicitMalformedExpiredMixedAndIndependentWitnesses() {
        return ScenarioCatalog.load().requirements().stream().filter(r -> r.group().equals("FIX.extra")).map(row -> DynamicTest.dynamicTest("[case=" + row.id() + "]", () -> {
            long started = System.nanoTime();
            try (var lease = run.prepareCase(row.id())) {
                String variant = row.recipe(), subset = "b_c1_c2";
                var supplied = credentials(lease, "s0"); var headers = new LinkedHashMap<String, List<String>>();
                switch (variant) {
                    case "unknown" -> supplied.put(Role.B, "not_registered");
                    case "expired" -> lease.advanceFixtureClock(Duration.ofSeconds(61));
                    case "revoked" -> lease.revoke("s0");
                    case "wrong-kind" -> supplied.put(Role.B, supplied.get(Role.C1));
                    case "duplicated-role-value" -> supplied.put(Role.C2, supplied.get(Role.C1));
                    case "duplicate-authorization" -> headers.put("Authorization", List.of("Bearer " + supplied.get(Role.B), "Bearer " + supplied.get(Role.B)));
                    case "duplicate-cookie" -> headers.put("Cookie", List.of("LAB_C1=" + supplied.get(Role.C1) + "; LAB_C1=" + supplied.get(Role.C1) + "; LAB_C2=" + supplied.get(Role.C2)));
                    case "extra-unrequired" -> { subset = "b"; supplied.remove(Role.C2); supplied.put(Role.C1, lease.seeded("s2").credential(Role.C1).reveal()); }
                    case "empty-value" -> supplied.put(Role.B, "");
                    case "same-account-other-login" -> { subset = "b_c1"; supplied.remove(Role.C2); supplied.put(Role.C1, lease.seeded("s1").credential(Role.C1).reveal()); }
                    case "other-account-complete-set" -> supplied = credentials(lease, "s2");
                    case "generator-witness" -> {
                        var valid = request(lease, "b_c1_c2", credentials(lease, "s0"), "GET", null); int complete = valid.statusCode(); assertEquals(200, complete);
                        assertEquals("user", json(valid).get("accountId").getAsString()); assertEquals("s0", json(valid).get("issuanceId").getAsString());
                        var missing = credentials(lease, "s0"); missing.remove(Role.C1);
                        int absent = request(lease, "b_c1_c2", missing, "GET", null).statusCode(); assertEquals(401, absent);
                        var mixed = credentials(lease, "s0"); mixed.put(Role.C1, lease.seeded("s2").credential(Role.C1).reveal());
                        int wrong = request(lease, "b_c1_c2", mixed, "GET", null).statusCode(); assertEquals(401, wrong);
                        record(row, lease, List.of(new ScenarioCatalog.Fact("httpStatus", complete + "," + absent + "," + wrong), new ScenarioCatalog.Fact("account", json(valid).get("accountId").getAsString()), new ScenarioCatalog.Fact("issuance", json(valid).get("issuanceId").getAsString()), new ScenarioCatalog.Fact("actions", counters(lease).get("actions").toString()), new ScenarioCatalog.Fact("outcome", "independent-witness-comparisons-passed")), started); return;
                    }
                    default -> fail("Unowned fixture variant.");
                }
                var response = request(lease, subset, supplied, "POST", headers);
                int expected = Integer.parseInt(fact(row, "httpStatus")); assertEquals(expected, response.statusCode());
                assertEquals(expected == 200 ? 1L : 0L, counters(lease).get("actions"));
                if (expected == 200) { assertEquals("user2", json(response).get("accountId").getAsString()); assertEquals("s2", json(response).get("issuanceId").getAsString()); }
                capture(row, lease, response, started);
            }
        }));
    }
    @Test void actualLoginIssuesDistinctCredentialsThatAuthenticateAndNeverTrustsAnExpectedAccountHint() throws Exception {
        try (var lease = run.prepareCase("BROW.basic.json")) {
            for (var input : List.of(new String[]{"user", "pass"}, new String[]{"user2", "pass2"}, new String[]{"admin", "adminpass"})) {
                var login = login(lease, input[0], input[1]); assertEquals(200, login.statusCode());
                var values = new EnumMap<Role, String>(Role.class); var body = json(login);
                values.put(Role.B, body.get("access_token").getAsString()); values.put(Role.C1, cookie(login, "LAB_C1")); values.put(Role.C2, cookie(login, "LAB_C2"));
                assertEquals(3, new HashSet<>(values.values()).size());
                var response = request(lease, "b_c1_c2", values, "POST", Map.of("X-Expected-Account", List.of("untrusted-hint")));
                assertEquals(200, response.statusCode()); assertEquals(input[0], json(response).get("accountId").getAsString());
                assertEquals(body.get("issuanceId").getAsString(), json(response).get("issuanceId").getAsString());
            }
            var invalid = login(lease, "user", "wrong"); assertEquals(401, invalid.statusCode()); assertTrue(invalid.headers().allValues("Set-Cookie").isEmpty());
            assertEquals(401, login(lease, "", "").statusCode());
            var duplicate = send(http, lease.endpoint("login/json"), "POST", "{\"username\":\"user\",\"username\":\"admin\",\"password\":\"pass\"}", "application/json"); assertEquals(400, duplicate.statusCode());
            assertEquals(400, send(http, lease.endpoint("login/json"), "POST", "{\"username\":\"user\",\"password\":\"pass\",\"unexpected\":true}", "application/json").statusCode());
            assertEquals(400, send(http, lease.endpoint("login/json"), "POST", "x".repeat(65_537), "application/json").statusCode());
        }
    }
    @Test void outputsStayWithTheirOriginalBrowserWhenAnotherAccountLogsInBeforeTheyAreFetched() throws Exception {
        try(var lease=run.prepareCase("BROW.basic.json");var first=browser();var second=browser()) {
            var loginA=send(first,lease.endpoint("login/json"),"POST","{\"username\":\"user\",\"password\":\"pass\"}","application/json");
            var loginB=send(second,lease.endpoint("login/json"),"POST","{\"username\":\"user2\",\"password\":\"pass2\"}","application/json");
            assertEquals(200,loginA.statusCode());assertEquals(200,loginB.statusCode());
            var outputsA=send(first,lease.endpoint("outputs"),"GET",null,null);
            var outputsB=send(second,lease.endpoint("outputs"),"GET",null,null);
            assertEquals(200,outputsA.statusCode());assertEquals(200,outputsB.statusCode());
            assertEquals("user",json(outputsA).get("accountId").getAsString());
            assertEquals("user2",json(outputsB).get("accountId").getAsString());
            for(var pair:List.of(List.of(loginA,outputsA),List.of(loginB,outputsB))) {
                var login=pair.get(0);var outputs=pair.get(1);var original=json(login);var fetched=json(outputs);
                assertTrue(original.get("access_token").equals(fetched.get("access_token")),"Outputs must preserve the original login's bearer.");
                assertEquals(original.get("issuanceId"),fetched.get("issuanceId"));
                var accepted=request(lease,"b_c1",Map.of(Role.B,fetched.get("access_token").getAsString(),Role.C1,cookie(login,"LAB_C1")),"GET",null);
                assertEquals(200,accepted.statusCode());assertEquals(original.get("accountId"),json(accepted).get("accountId"));
                assertEquals(original.get("issuanceId"),json(accepted).get("issuanceId"));
            }
            assertEquals(401,request(lease,"b_c1",Map.of(Role.B,json(outputsA).get("access_token").getAsString(),Role.C1,cookie(loginB,"LAB_C1")),"GET",null).statusCode());
        }
    }

    @Test void outputsKeepPerLoginBearerOmissionWhenOtherBrowserOutputsAreComplete() throws Exception {
        for(boolean omitFirst:List.of(true,false))try(var lease=run.prepareCase("BROW.basic.json");var first=browser();var second=browser()) {
            lease.armFault(new LabRun.FaultSpec(LabRun.Phase.LOGIN,omitFirst?1:2,"OMIT_OUTPUT",Role.B,null,null));
            var loginA=send(first,lease.endpoint("login/json"),"POST","{\"username\":\"user\",\"password\":\"pass\"}","application/json");
            var loginB=send(second,lease.endpoint("login/json"),"POST","{\"username\":\"user2\",\"password\":\"pass2\"}","application/json");
            var outputsA=send(first,lease.endpoint("outputs"),"GET",null,null);var outputsB=send(second,lease.endpoint("outputs"),"GET",null,null);
            assertEquals(200,loginA.statusCode());assertEquals(200,loginB.statusCode());assertEquals(200,outputsA.statusCode());assertEquals(200,outputsB.statusCode());
            assertEquals(!omitFirst,json(outputsA).has("access_token"));assertEquals(omitFirst,json(outputsB).has("access_token"));
            assertEquals("user",json(outputsA).get("accountId").getAsString());assertEquals("user2",json(outputsB).get("accountId").getAsString());
            assertTrue(json(loginA).equals(json(outputsA)),"An omitted output must not be reconstructed or replaced by another login.");
            assertTrue(json(loginB).equals(json(outputsB)),"Each session retains its actual emitted output map.");
            assertEquals(200,request(lease,"c1",Map.of(Role.C1,cookie(loginA,"LAB_C1")),"GET",null).statusCode());
            assertEquals(200,request(lease,"c1",Map.of(Role.C1,cookie(loginB,"LAB_C1")),"GET",null).statusCode());
        }
    }

    @Test void outputsRefuseMissingForgedAndCrossCaseSessionsEvenWithTheValidFlowMarker() throws Exception {
        try(var first=run.prepareCase("BROW.basic.json");var second=run.prepareCase("BROW.basic.cookie-one");var a=browser();var b=browser()) {
            var loginA=send(a,first.endpoint("login/json"),"POST","{\"username\":\"user\",\"password\":\"pass\"}","application/json");
            var loginB=send(b,second.endpoint("login/json"),"POST","{\"username\":\"user2\",\"password\":\"pass2\"}","application/json");
            String flowA="LAB_FLOW="+cookie(loginA,"LAB_FLOW"),flowB="LAB_FLOW="+cookie(loginB,"LAB_FLOW");
            String sessionA="LAB_OUTPUT_SESSION="+cookie(loginA,"LAB_OUTPUT_SESSION");
            assertEquals(401,outputsWithCookie(first,flowA).statusCode());
            assertEquals(401,outputsWithCookie(first,sessionA).statusCode());
            assertEquals(401,outputsWithCookie(first,flowA+"; LAB_OUTPUT_SESSION=forged-session").statusCode());
            assertEquals(401,outputsWithCookie(second,flowB+"; "+sessionA).statusCode());
            assertEquals(200,outputsWithCookie(first,flowA+"; "+sessionA).statusCode());
            assertEquals("user2",json(send(b,second.endpoint("outputs"),"GET",null,null)).get("accountId").getAsString());
        }
    }
    private HttpResponse<String> outputsWithCookie(LabRun.CaseLease lease,String cookies) throws Exception {
        return http.send(HttpRequest.newBuilder(lease.endpoint("outputs")).header("Cookie",cookies).timeout(Duration.ofSeconds(3)).GET().build(),HttpResponse.BodyHandlers.ofString());
    }
    /** Qualifies the retained legacy verifier route; it does not compose extension journeys. */
    @Test void independentCookieRoutePreservesSameAccountDifferentLoginSemantics() throws Exception {
        try (var lease = run.prepareCase("FIX.extra.same-account-other-login")) {
            var supplied = new EnumMap<Role, String>(Role.class);
            supplied.put(Role.C1, lease.seeded("s0").credential(Role.C1).reveal());
            supplied.put(Role.C2, lease.seeded("s1").credential(Role.C2).reveal());
            var accepted = request(lease, "independent-cookies", supplied, "GET", null);
            assertEquals(200, accepted.statusCode());
            var body = json(accepted); assertEquals("user", body.get("accountId").getAsString());
            assertTrue(body.get("issuanceId").isJsonNull(), "An independent set must not claim one common login issuance");
            assertEquals(Set.of("s0", "s1"), body.getAsJsonArray("issuanceIds").asList().stream().map(JsonElement::getAsString).collect(java.util.stream.Collectors.toSet()));
            assertEquals(Set.of("C1", "C2"), body.getAsJsonArray("acceptedRoles").asList().stream().map(JsonElement::getAsString).collect(java.util.stream.Collectors.toSet()));
            supplied.put(Role.C2, lease.seeded("s2").credential(Role.C2).reveal());
            assertEquals(401, request(lease, "independent-cookies", supplied, "GET", null).statusCode());
            assertEquals(0L, counters(lease).get("actions"));
        }
    }
    @Test void unrelatedCookiesAreIgnoredButAnotherCaseCannotAuthenticate() throws Exception {
        try (var first = run.prepareCase("BROW.basic.cookie-one"); var second = run.prepareCase("BROW.basic.cookie-two")) {
            var token = first.seeded("s0").credential(Role.B).reveal();
            assertEquals(200, request(first, "b", Map.of(Role.B, token), "GET", Map.of("Cookie", List.of("preferences=dark"))).statusCode());
            assertEquals(401, request(second, "b", Map.of(Role.B, token), "GET", null).statusCode());
            assertEquals(0L, counters(second).get("actions"));
        }
    }
    @Test void formsRequireTheirActualUsernamePasswordCsrfAndConsentStages() throws Exception {
        for (String variant : List.of("json", "cookie-one", "cookie-two", "two-page", "csrf-cookie", "javascript", "interstitial")) {
            try (var lease = run.prepareCase("BROW.basic." + variant); var browser = browser()) {
                assertEquals(401, send(browser, lease.endpoint("outputs"), "GET", null, null).statusCode());
                var start = send(browser, lease.endpoint("start"), "GET", null, null);
                assertEquals(200, start.statusCode()); assertTrue(start.body().contains("id=user"));
                var action = action(start);
                String fields = "username=user&password=pass";
                if (variant.equals("two-page")) {
                    var next = send(browser, action, "POST", "username=user", "application/x-www-form-urlencoded");
                    assertEquals(200, next.statusCode()); assertTrue(next.body().contains("id=pass")); action = action(next); fields = "password=pass";
                }
                if (variant.equals("csrf-cookie")) {
                    assertEquals(403, send(browser, action, "POST", fields + "&csrf=wrong", "application/x-www-form-urlencoded").statusCode());
                    String csrf = extract(start.body(), "name=csrf value=\"([^\"]+)\""); fields += "&csrf=" + csrf;
                }
                var result = send(browser, action, "POST", fields, "application/x-www-form-urlencoded");
                assertEquals(200, result.statusCode());
                if (variant.equals("interstitial")) {
                    assertTrue(result.headers().allValues("Set-Cookie").isEmpty()); assertFalse(result.body().contains("id=login-complete"));
                    assertEquals(401, send(browser, lease.endpoint("outputs"), "GET", null, null).statusCode());
                    result = send(browser, action(result), "POST", "", "application/x-www-form-urlencoded");
                }
                assertEquals(200, result.statusCode()); assertTrue(result.body().contains("id=login-complete"));
                String bearer = JsonParser.parseString(extract(result.body(), "id=outputs>([^<]+)</script>")).getAsJsonObject().get("access_token").getAsString();
                assertEquals(200, request(lease, "b", Map.of(Role.B, bearer), "GET", null).statusCode());
                var outputs = send(browser, lease.endpoint("outputs"), "GET", null, null);
                assertEquals(200, outputs.statusCode()); assertEquals("user", json(outputs).get("accountId").getAsString());
                assertEquals(200, request(lease, "b", Map.of(Role.B, json(outputs).get("access_token").getAsString()), "GET", null).statusCode());
                assertEquals(401, send(http, lease.endpoint("outputs"), "GET", null, null).statusCode());
            }
        }
    }
    @Test void completedJsonFetchDoesNotRestoreADeliberatelyOmittedBearer() throws Exception {
        try (var lease = run.prepareCase("BROW.basic.json"); var browser = browser()) {
            lease.armFault(new LabRun.FaultSpec(LabRun.Phase.LOGIN, 1, "OMIT_OUTPUT", Role.B, null, null));
            var login = send(browser, lease.endpoint("login/json"), "POST", "{\"username\":\"user\",\"password\":\"pass\"}", "application/json");
            assertEquals(200, login.statusCode()); assertFalse(json(login).has("access_token"));
            var outputs = send(browser, lease.endpoint("outputs"), "GET", null, null);
            assertEquals(200, outputs.statusCode()); assertFalse(json(outputs).has("access_token"));
            assertEquals(401, request(lease, "b", Map.of(), "GET", null).statusCode());
            assertEquals(200, request(lease, "c1", Map.of(Role.C1, cookie(login, "LAB_C1")), "GET", null).statusCode());
        }
    }
    @Test void redirectHopsRequireStateCookiesAndExactMethodBodyBeforeIssuingOutput() throws Exception {
        for (String variant : List.of("zero", "one", "multi", "cross-origin", "cookie-each-hop", "post-303", "post-307", "deep-link")) {
            try (var lease = run.prepareCase("BROW.redirect." + variant); var browser = browser()) {
                var start = send(browser, lease.endpoint("start"), "GET", null, null);
                var response = send(browser, action(start), "POST", "username=user&password=pass", "application/x-www-form-urlencoded");
                int hops = 0; boolean alternate = false; String carrier = null;
                while (response.statusCode() >= 300 && response.statusCode() < 400 && hops++ < 8) {
                    if (response.headers().allValues("Set-Cookie").stream().anyMatch(c -> c.startsWith("LAB_B="))) carrier = cookie(response, "LAB_B");
                    URI next = URI.create(response.headers().firstValue("Location").orElseThrow()); alternate |= next.getPort() != lease.endpoint("start").getPort();
                    boolean preserve = response.statusCode() == 307;
                    response = send(browser, next, preserve ? "POST" : "GET", preserve ? "username=user&password=pass" : null, preserve ? "application/x-www-form-urlencoded" : null);
                }
                if (variant.equals("deep-link")) {
                    assertNotNull(carrier); assertTrue(response.uri().getPath().endsWith("/protected/b")); assertTrue(response.uri().getQuery().contains("view=details"));
                    assertEquals(200, request(lease, "b", Map.of(Role.B, carrier), "GET", null).statusCode());
                } else {
                    assertEquals(200, response.statusCode()); assertTrue(response.body().contains("id=login-complete"));
                }
                if (variant.equals("cross-origin")) assertTrue(alternate);
                assertTrue(hops <= 8);
            }
        }
        try (var lease = run.prepareCase("BROW.redirect.cookie-each-hop"); var browser = browser()) {
            var start = send(browser, lease.endpoint("start"), "GET", null, null);
            var first = send(browser, action(start), "POST", "username=user&password=pass", "application/x-www-form-urlencoded");
            URI hop0 = URI.create(first.headers().firstValue("Location").orElseThrow());
            assertEquals(400, send(browser, URI.create(hop0.toString().replace("/hop/0", "/hop/2")), "GET", null, null).statusCode());
            var hop1 = send(browser, hop0, "GET", null, null);
            assertEquals(401, send(http, URI.create(hop1.headers().firstValue("Location").orElseThrow()), "GET", null, null).statusCode());
        }
    }
    @Test void completedFormsLinkToTheirSelectedSurfaceWithoutAnotherLogin() throws Exception {
        var routes = Map.of("early-response", "early", "late-response", "late", "nested-json", "nested", "popup", "popup-parent", "frame", "frame-parent", "cors-fetch", "cors", "service-worker", "sw/page");
        for (var entry : routes.entrySet()) try (var lease = run.prepareCase("BROW.surfaces." + entry.getKey()); var browser = browser()) {
            var start = send(browser, lease.endpoint("start"), "GET", null, null);
            var completed = send(browser, action(start), "POST", "username=user2&password=pass2", "application/x-www-form-urlencoded");
            assertEquals(200, completed.statusCode());
            assertTrue(completed.body().contains("id=surface-entry href=\"" + lease.endpoint("surface/" + entry.getValue())));
            assertEquals(200, send(browser, lease.endpoint("surface/" + entry.getValue()), "GET", null, null).statusCode());
            assertEquals(0L, counters(lease).get("actions"));
        }
    }
    @Test void responseSurfacesEmitTheLoggedInIssuanceAndKeepLateReleaseResponsive() throws Exception {
        try (var lease = run.prepareCase("BROW.surfaces.early-response")) {
            assertEquals(401, send(http, lease.endpoint("surface/token?kind=early"), "GET", null, null).statusCode());
            var login = login(lease, "user2", "pass2"); String flow = cookie(login, "LAB_FLOW");
            for (String kind : List.of("early", "nested", "popup", "frame", "worker")) {
                var response = http.send(HttpRequest.newBuilder(lease.endpoint("surface/token?kind=" + kind)).header("Cookie", "LAB_FLOW=" + flow).GET().build(), HttpResponse.BodyHandlers.ofString());
                assertEquals(200, response.statusCode());
                var parsed = json(response); String token = kind.equals("nested") ? parsed.getAsJsonObject("result").getAsJsonObject("authentication").get("access_token").getAsString() : parsed.getAsJsonObject("data").get("access_token").getAsString();
                var proof = request(lease, "b", Map.of(Role.B, token), "GET", null); assertEquals(200, proof.statusCode()); assertEquals("user2", json(proof).get("accountId").getAsString());
            }
            var late = http.sendAsync(HttpRequest.newBuilder(lease.endpoint("surface/token?kind=late")).header("Cookie", "LAB_FLOW=" + flow).GET().build(), HttpResponse.BodyHandlers.ofString());
            lease.awaitCheckpoint("late-token", Duration.ofSeconds(2)); assertFalse(late.isDone()); lease.release("late-token"); assertEquals(200, late.get(2, TimeUnit.SECONDS).statusCode());
            var cors = http.send(HttpRequest.newBuilder(lease.endpoint("surface/token?kind=cors", true)).header("Cookie", "LAB_FLOW=" + flow).header("Origin", run.applicationUri().toString()).GET().build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, cors.statusCode()); assertEquals(run.applicationUri().toString(), cors.headers().firstValue("Access-Control-Allow-Origin").orElseThrow());
            var denied = http.send(HttpRequest.newBuilder(lease.endpoint("surface/cors-denied", true)).header("Cookie", "LAB_FLOW=" + flow).GET().build(), HttpResponse.BodyHandlers.ofString());
            assertTrue(denied.headers().firstValue("Access-Control-Allow-Origin").isEmpty()); assertFalse(denied.body().contains("access_token"));
            assertEquals(404, http.send(HttpRequest.newBuilder(lease.endpoint("surface/sw/token")).header("Cookie", "LAB_FLOW=" + flow).GET().build(), HttpResponse.BodyHandlers.ofString()).statusCode());
        }
    }
    @Test void pageObservationsRequireTheLoggedInCaseAndClosedTypedFields() throws Exception {
        try (var lease = run.prepareCase("BROW.surfaces.cors-fetch")) {
            URI endpoint = lease.endpoint("surface/observe");
            java.util.function.BiFunction<String, String, HttpRequest> observation = (flow, body) -> {
                var request = HttpRequest.newBuilder(endpoint).header("Content-Type", "application/json");
                if (flow != null) request.header("Cookie", "LAB_FLOW=" + flow);
                return request.POST(HttpRequest.BodyPublishers.ofString(body)).build();
            };
            assertEquals(401, http.send(observation.apply(null, "{\"surface\":\"cors\",\"stage\":\"ready\"}"), HttpResponse.BodyHandlers.ofString()).statusCode());
            String flow = cookie(login(lease, "user2", "pass2"), "LAB_FLOW");
            for (String invalid : List.of("{\"surface\":\"worker\",\"stage\":\"ready\"}", "{\"surface\":\"cors\",\"stage\":\"reset\"}",
                    "{\"surface\":\"cors\",\"stage\":\"ready\",\"token\":\"must-not-record\"}"))
                assertEquals(400, http.send(observation.apply(flow, invalid), HttpResponse.BodyHandlers.ofString()).statusCode());
            assertTrue(lease.snapshot().get("events").toString().contains("login-completed"));
            assertFalse(lease.snapshot().get("events").toString().contains("page-cors-ready"));
            for (String stage : List.of("ready", "cors-done", "cors-denied")) {
                String body = LabRun.JSON.toJson(Map.of("surface", "cors", "stage", stage));
                assertEquals(200, http.send(observation.apply(flow, body), HttpResponse.BodyHandlers.ofString()).statusCode());
            }
            String events = lease.snapshot().get("events").toString();
            assertTrue(events.contains("page-cors-ready")); assertTrue(events.contains("page-cors-done")); assertTrue(events.contains("page-cors-denied"));
            assertFalse(events.contains("must-not-record")); assertFalse(events.contains(flow));
            assertEquals(0L, counters(lease).get("actions"));
        }
    }
    @Test void signedSchedulingTokenExpiresAtItsActualDeclaredBoundaryWithoutWaiting() throws Exception {
        try (var lease = run.prepareCase("BROW.basic.json")) {
            var response = send(http, lease.endpoint("login/jwt"), "POST", "{\"username\":\"user\",\"password\":\"pass\"}", "application/json");
            assertEquals(200, response.statusCode()); String token = json(response).get("access_token").getAsString();
            String[] parts = token.split("\\."); assertEquals(3, parts.length);
            var claims = JsonParser.parseString(new String(Base64.getUrlDecoder().decode(parts[1]), java.nio.charset.StandardCharsets.UTF_8)).getAsJsonObject();
            assertEquals(200, request(lease, "b", Map.of(Role.B, token), "GET", null).statusCode());
            lease.advanceFixtureClock(Duration.ofMillis(claims.get("exp").getAsLong() * 1000 - lease.identities.timeMillis()));
            assertEquals(401, request(lease, "b", Map.of(Role.B, token), "GET", null).statusCode());
        }
    }
    @Test void rotationDeletionAndCookieTupleFixturesHaveDistinctObservableOutcomes() throws Exception {
        for (String variant : List.of("early-cookie-rotated", "deleted-mid-flow", "same-name-paths", "ambiguous", "idp-client-decoy")) {
            try (var lease = run.prepareCase("BROW.cookie-selection." + variant); var browser = browser()) {
                var start = send(browser, lease.endpoint("start"), "GET", null, null); String decoy = null;
                if (variant.equals("idp-client-decoy")) {
                    var idp = send(browser, URI.create(start.headers().firstValue("Location").orElseThrow()), "GET", null, null); assertEquals("localhost", idp.uri().getHost()); decoy = cookie(idp, "LAB_C1");
                    start = send(browser, URI.create(idp.headers().firstValue("Location").orElseThrow()), "GET", null, null);
                }
                var response = send(browser, action(start), "POST", "username=user&password=pass", "application/x-www-form-urlencoded");
                String early = null;
                if (response.statusCode() == 303) { early = cookie(response, "LAB_C1"); response = send(browser, URI.create(response.headers().firstValue("Location").orElseThrow()), "GET", null, null); }
                assertEquals(200, response.statusCode()); String current = cookie(response, "LAB_C1");
                if (variant.equals("deleted-mid-flow")) { assertEquals("", current); assertTrue(response.headers().allValues("Set-Cookie").stream().anyMatch(v -> v.contains("Max-Age=0"))); }
                else {
                    assertEquals(200, request(lease, "c1", Map.of(Role.C1, current), "GET", null).statusCode());
                    if (early != null) { assertFalse(current.equals(early)); assertEquals(401, request(lease, "c1", Map.of(Role.C1, early), "GET", null).statusCode()); }
                    if (decoy != null) assertEquals(401, request(lease, "c1", Map.of(Role.C1, decoy), "GET", null).statusCode());
                    if (variant.equals("same-name-paths") || variant.equals("ambiguous")) assertEquals(2, response.headers().allValues("Set-Cookie").stream().filter(v -> v.startsWith("LAB_C1=")).count());
                }
            }
        }
    }
    @TestFactory Stream<DynamicTest> declaredRedirectFailuresCannotReachCredentialIssuance() {
        return Stream.of("missing-callback", "wrong-return", "missing-state", "loop", "unreachable-hop", "cancel-before-callback").map(variant -> DynamicTest.dynamicTest(variant, () -> {
            try (var lease = run.prepareCase("BROW.redirect-failure." + variant); var browser = browser()) {
                var start = send(browser, lease.endpoint("start"), "GET", null, null);
                var response = send(browser, action(start), "POST", "username=user&password=pass", "application/x-www-form-urlencoded");
                for (int count = 0; count < 5 && response.statusCode() == 302; count++) {
                    URI next = URI.create(response.headers().firstValue("Location").orElseThrow());
                    if (variant.equals("loop") && count == 1) { assertEquals(response.uri(), next); break; }
                    if (next.getPath().equals("/unreachable")) { assertThrows(java.io.IOException.class, () -> send(browser, next, "GET", null, null)); break; }
                    if (variant.equals("cancel-before-callback") && next.getPath().endsWith("/hop/2")) {
                        var pending = browser.sendAsync(HttpRequest.newBuilder(next).GET().build(), HttpResponse.BodyHandlers.ofString());
                        lease.awaitCheckpoint("cancel-before-callback", Duration.ofSeconds(2)); lease.close(); assertEquals(410, pending.get(2, TimeUnit.SECONDS).statusCode()); break;
                    }
                    response = send(browser, next, "GET", null, null);
                }
                assertFalse(response.headers().allValues("Set-Cookie").stream().anyMatch(v -> v.startsWith("LAB_C1=")));
                assertEquals(0L, counters(lease).get("actions"));
                if (variant.equals("missing-callback")) assertEquals(404, response.statusCode());
                if (variant.equals("missing-state") || variant.equals("wrong-return")) assertEquals(400, response.statusCode());
            }
        }));
    }
    static HttpClient browser() { return HttpClient.newBuilder().cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL)).followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(2)).build(); }
    static HttpResponse<String> send(HttpClient client, URI uri, String method, String body, String type) throws Exception {
        var builder = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(3)); if (type != null) builder.header("Content-Type", type);
        return client.send(builder.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }
    HttpResponse<String> login(LabRun.CaseLease lease, String user, String password) throws Exception { return send(http, lease.endpoint("login/json"), "POST", LabRun.JSON.toJson(Map.of("username", user, "password", password)), "application/json"); }
    HttpResponse<String> request(LabRun.CaseLease lease, String subset, Map<Role, String> supplied, String method, Map<String, List<String>> overrides) throws Exception {
        var headers = new LinkedHashMap<String, List<String>>();
        if (supplied.containsKey(Role.B)) headers.put("Authorization", List.of("Bearer " + supplied.get(Role.B)));
        var cookies = new ArrayList<String>(); for (Role role : List.of(Role.C1, Role.C2)) if (supplied.containsKey(role)) cookies.add("LAB_" + role + "=" + supplied.get(role));
        if (!cookies.isEmpty()) headers.put("Cookie", List.of(String.join("; ", cookies))); if (overrides != null) headers.putAll(overrides);
        var builder = HttpRequest.newBuilder(lease.endpoint("protected/" + subset)).timeout(Duration.ofSeconds(3)); headers.forEach((k, vs) -> vs.forEach(v -> builder.header(k, v)));
        return http.send(builder.method(method, HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
    }
    static EnumMap<Role, String> credentials(LabRun.CaseLease lease, String label) { var result = new EnumMap<Role, String>(Role.class); for (var role : Role.values()) result.put(role, lease.seeded(label).credential(role).reveal()); return result; }
    @SuppressWarnings("unchecked") static Map<String, Object> counters(LabRun.CaseLease lease) { return (Map<String, Object>) lease.snapshot().get("counters"); }
    static JsonObject json(HttpResponse<String> response) { return JsonParser.parseString(response.body()).getAsJsonObject(); }
    static String cookie(HttpResponse<String> response, String name) { return response.headers().allValues("Set-Cookie").stream().filter(h -> h.startsWith(name + "=")).findFirst().orElseThrow().split(";", 2)[0].substring(name.length() + 1); }
    static URI action(HttpResponse<String> response) { return URI.create(extract(response.body(), "action=\"([^\"]+)\"").replace("&amp;", "&")); }
    static String extract(String body, String regex) { var matcher = Pattern.compile(regex).matcher(body); assertTrue(matcher.find(), "Required fixture stage was absent."); return matcher.group(1); }
    static String fact(ScenarioCatalog.Requirement row, String name) { return row.expected().stream().filter(f -> f.fact().equals(name)).findFirst().orElseThrow().value(); }
    private static void capture(ScenarioCatalog.Requirement row, LabRun.CaseLease lease, HttpResponse<String> response, long started) throws Exception {
        var observations = new ArrayList<ScenarioCatalog.Fact>();
        observations.add(new ScenarioCatalog.Fact("httpStatus", Integer.toString(response.statusCode())));
        observations.add(new ScenarioCatalog.Fact("actions", counters(lease).get("actions").toString()));
        if (response.statusCode() == 200) {
            var actual = json(response); observations.add(new ScenarioCatalog.Fact("account", actual.get("accountId").getAsString())); observations.add(new ScenarioCatalog.Fact("issuance", actual.get("issuanceId").getAsString()));
        }
        record(row, lease, observations, started);
    }
    private static void record(ScenarioCatalog.Requirement row, LabRun.CaseLease lease, List<ScenarioCatalog.Fact> observed, long started) throws Exception {
        long cleanup = System.nanoTime(); lease.close(); long finished = System.nanoTime();
        LabEvidence.captureFixture(row, observed, Math.max(0, lease.preparedNanos - started) / 1_000_000, Math.max(0, cleanup - lease.preparedNanos) / 1_000_000, (finished - cleanup) / 1_000_000);
    }
}
