package bpsh.http;

import bpsh.Extension;
import bpsh.browser.AuthTrafficGuard;
import bpsh.config.Config;
import bpsh.config.JourneyRegistry;
import bpsh.credentials.AuthenticationResult;
import bpsh.credentials.CredentialUse;
import bpsh.diagnostics.Diagnostics;
import bpsh.model.AuthenticationFailure;
import bpsh.model.JourneyDefinition;
import bpsh.secrets.SecretStore;
import bpsh.session.AuthenticationCoordinator;
import bpsh.session.AuthenticationCoordinatorTest;
import bpsh.session.CoordinatorFixtures;
import bpsh.support.AuthLabSupport;
import bpsh.ui.AuthenticationTagMenu;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletionException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises complete raw messages with fake authentication, without claiming real-Burp URL handling. */
public class NativeTagPipelineTest {
    /** Shares a registry and bounded fake runner with actual parser/resolver code. */
    public static final class Fixture implements AutoCloseable {
        public final SecretStore secrets = new SecretStore();
        public final JourneyRegistry registry = new JourneyRegistry(secrets);
        public final CoordinatorFixtures.ManualRuntime clock = new CoordinatorFixtures.ManualRuntime();
        public final List<JourneyDefinition> definitions = List.of(CoordinatorFixtures.journey("employee"), CoordinatorFixtures.journey("admin"), CoordinatorFixtures.journey("url"));
        public final AuthenticationCoordinator coordinator;
        public final NativeTagResolver resolver;
        public final java.util.Map<String, String> values = new java.util.HashMap<>(Map.of("employee", "employee-token", "admin", "admin-token", "url", "url-token"));
        public int attempts;
        public String failedAlias;
        /** Publishes unique aliases and injects no network/browser implementation. */
        public Fixture() {
            CoordinatorFixtures.load(registry, definitions);
            coordinator = new AuthenticationCoordinator(registry, Config.Controls.defaults(), clock, (entry, recovery, deadline, cancelled) -> {
                attempts++;
                if (entry.definition().canonicalAlias().equals(failedAlias)) throw CoordinatorFixtures.failure(AuthenticationFailure.Cause.AUTH_REJECTED);
                return new AuthenticationResult(entry.identity(), values.get(entry.definition().canonicalAlias()), clock.instant(), clock.nanos());
            }, entry -> null);
            resolver = new NativeTagResolver(registry, coordinator);
        }
        /** @param request Complete Latin-1 wire fixture. @return Detached complete message, after executing admitted workers. */
        public String resolve(String request) throws Exception {
            var operation = resolver.resolve(wire(request), registry.snapshot().resolve("admin"), false);
            while (!clock.workers.isEmpty()) clock.runWorker(); return new String(operation.future().join().commit(), StandardCharsets.ISO_8859_1);
        }
        /** Closes test-owned token and secret state. */
        @Override public void close() { coordinator.close(); secrets.close(); }
    }
    /** @param value Raw request fixture. @return Exact byte-preserving one-byte representation. */
    public static byte[] wire(String value) { return value.getBytes(StandardCharsets.ISO_8859_1); }
    /** @param value Header value fixture. @return Complete raw request preserving unusual casing and whitespace. */
    public static String header(String value) { return "GET /protected HTTP/1.1\r\nHost: app.example\r\nX-Retain:\t  untouched  \r\nAuthorization: " + value + "\r\n\r\n"; }
    /** @param operation Failing atomic operation. @return Safe typed cause. */
    public static AuthenticationFailure error(NativeTagResolver.Operation operation) {
        var error = assertThrows(CompletionException.class, () -> operation.future().join()); return assertInstanceOf(AuthenticationFailure.class, error.getCause());
    }

    public @Test void rawReferencesPreserveEveryOtherByteAndDoNotApplyAutomaticCredentials() throws Exception {
        Map<String, Object> facts;
        long start = System.nanoTime(), ready, checked;
        try (var f = new Fixture()) {
            ready = System.nanoTime();
            String raw = header("Bearer <@EMPLOYEE/>").replace("\r\n\r\n", "\r\nCookie: existing=keep\r\n\r\n");
            var operation = f.resolver.resolve(wire(raw), f.registry.snapshot().resolve("admin"), true); assertTrue(operation.tagsOnly()); f.clock.runWorker();
            var resolved = operation.future().join(); byte[] output = resolved.commit(); String expected = raw.replace("<@EMPLOYEE/>", "employee-token");
            assertEquals(expected, new String(output, StandardCharsets.ISO_8859_1));
            assertEquals(1, f.attempts); assertEquals(1, resolved.uses().size()); assertFalse(resolved.toString().contains("employee-token"));
            facts = tagPlanFacts(f, raw, expected, resolved, List.of("employee"));
            facts.put("location", "header"); facts.put("mode", "raw"); facts.put("references", 1); facts.put("plans", 1);
            checked = System.nanoTime();
        }
        AuthLabSupport.component("CORE.tag-matrix.location=header~mode=raw~references=1", facts, elapsed(start, ready, checked));
        AuthLabSupport.component("CORE.encoding.unrelated-bytes",facts,elapsed(start,ready,checked));
        AuthLabSupport.component("CORE.tag-selection.case-only-alias",facts,elapsed(start,ready,checked));
        AuthLabSupport.component("CORE.injection.tag-precedence",facts,elapsed(start,ready,checked));
    }
    public @Test void wrappersEncodeWholeContentInsideOutAndSelfClosingWrapperNamesRemainAliases() throws Exception {
        long start=System.nanoTime(),ready,checked;Map<String,Object> observed;
        try (var f = new Fixture()) {
            ready=System.nanoTime();
            f.values.put("employee", "a b+/\"\\");
            String raw = "GET /path?token=<@url>Bearer <@employee/></@url> HTTP/1.1\r\nHost: app.example\r\n"
                    + "X-Form: <@form><@employee/></@form>\r\nX-Json: <@json><@employee/></@json>\r\n"
                    + "X-Nested: <@url><@url><@employee/></@url></@url>\r\nX-Alias: <@url/>\r\n\r\n";
            String output = f.resolve(raw);
            assertTrue(output.startsWith("GET /path?token=Bearer%20a%20b%2B%2F%22%5C HTTP/1.1\r\n"));
            assertTrue(output.contains("X-Form: a+b%2B%2F%22%5C\r\n")); assertTrue(output.contains("X-Json: a b+/\\\"\\\\\r\n"));
            assertTrue(output.contains("X-Nested: a%2520b%252B%252F%2522%255C\r\n")); assertTrue(output.contains("X-Alias: url-token\r\n")); assertEquals(2, f.attempts);
            String expected="GET /path?token=Bearer%20a%20b%2B%2F%22%5C HTTP/1.1\r\nHost: app.example\r\n"
                    +"X-Form: a+b%2B%2F%22%5C\r\nX-Json: a b+/\\\"\\\\\r\nX-Nested: a%2520b%252B%252F%2522%255C\r\nX-Alias: url-token\r\n\r\n";
            assertEquals(expected,output);int initialAttempts=f.attempts;int multipleSnapshots;boolean multipleBytes;
            String multi=header("<@url>prefix <@employee/> and <@admin/></@url>");
            try(var operation=f.resolver.resolve(wire(multi),null,false)) {
                while(!f.clock.workers.isEmpty())f.clock.runWorker();var resolved=operation.future().join();byte[] bytes=resolved.commit();
                byte[] independent=wire(header("prefix%20a%20b%2B%2F%22%5C%20and%20admin-token"));assertArrayEquals(independent,bytes);
                assertEquals(2,resolved.uses().size());assertEquals(3,f.attempts);multipleSnapshots=resolved.uses().size();multipleBytes=Arrays.equals(independent,bytes);
            }
            int beforeLiteral=f.attempts;String body="<@json>line\nbreak</@json>";
            String newline=f.resolve("POST / HTTP/1.1\r\nHost: app.example\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Length: "+body.length()+"\r\n\r\n"+body);
            String newlineExpected="POST / HTTP/1.1\r\nHost: app.example\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Length: 11\r\n\r\nline\\nbreak";assertEquals(newlineExpected,newline);assertEquals(beforeLiteral,f.attempts);
            observed=Map.of("wrapperBytesMatch",expected.equals(output),"initialAttempts",initialAttempts,"multipleBytesMatch",multipleBytes,"multipleSnapshots",multipleSnapshots,"multipleAttempts",beforeLiteral,"newlineBytesMatch",newlineExpected.equals(newline),"newlineExtraAttempts",f.attempts-beforeLiteral,"waitingRequests",f.coordinator.capacity().waitingRequests());checked=System.nanoTime();
        }
        for(String variant:List.of("space","reserved","quote","nested-wrappers","multiple-inner-references","newline"))AuthLabSupport.component("CORE.encoding."+variant,observed,elapsed(start,ready,checked));
    }
    public @Test void wrapperLiteralTextWorksWithoutStartingAnyAuthenticationAndTagOutputIsNeverReparsed() throws Exception {
        Map<String, Object> facts; long start = System.nanoTime(), ready, checked;
        try (var f = new Fixture()) {
            ready = System.nanoTime();
            String wrapper = f.resolve(header("<@url>ordinary text</@url>"));
            assertTrue(wrapper.contains("Authorization: ordinary%20text")); assertEquals(0, f.attempts);
            boolean wrapperBytesMatch = header("ordinary%20text").equals(wrapper); assertEquals(header("ordinary%20text"), wrapper);
            int wrapperAttempts = f.attempts;
            f.values.put("employee", "<@admin/>");
            String literal = f.resolve(header("<@employee/>"));
            assertTrue(literal.contains("Authorization: <@admin/>")); assertEquals(1, f.attempts);
            boolean literalBytesMatch = header("<@admin/>").equals(literal); assertEquals(header("<@admin/>"), literal);
            assertNull(f.coordinator.peek(f.registry.snapshot().resolve("admin").identity()), "Token text must not start the journey it resembles.");
            facts = Map.of("wrapperBytesMatch", wrapperBytesMatch, "literalBytesMatch", literalBytesMatch, "wrapperAttempts", wrapperAttempts,
                    "outputAttempts", f.attempts, "waitingRequests", f.coordinator.capacity().waitingRequests());
            checked = System.nanoTime();
        }
        AuthLabSupport.component("CORE.encoding.literal-prefix", facts, elapsed(start, ready, checked));
        AuthLabSupport.component("CORE.tag-failure.output-contains-tag",facts,elapsed(start,ready,checked));
    }
    public @ParameterizedTest(name="[case=CORE.tag-failure.malformed-{index}]") @ValueSource(strings = {"<@employee>", "<@employee />", "<@employee x=1/>", "<@BPSH:employee/>", "<@URL>hello</@URL>", "<@url>x</@form>", "</@url>", "<@employee", "<@bpsh />", "<@url><@employee/>"})
    void malformedNativeSourceFailsBeforeAnyCycleOrReplacement(String source) throws Exception {
        long began=System.nanoTime();Map<String,Object> observed=null;
        try (var f = new Fixture()) {
            var failure=assertThrows(AuthenticationFailure.class, () -> f.resolver.resolve(wire(header(source)), null, false)); assertEquals(0, f.attempts); assertTrue(f.clock.workers.isEmpty());
            if(source.equals("<@employee>"))observed=tagFailureFacts(f,header(source),failure.reason().name());
        }
        if(observed!=null)tagFailureObservation("malformed",observed,began);
    }
    public @ParameterizedTest(name="[case=CORE.tag-failure.{0}]",quoteTextArguments=false)
    @ValueSource(strings={"unknown","mixed-valid-invalid","deleted","ambiguous"})
    void unknownMixedReferenceFailsBeforeStartingTheValidJourney(String variant) throws Exception {
        long began=System.nanoTime();Map<String,Object> observed;
        var diagnostic=new java.util.LinkedHashMap<String,Object>();
        try (var f = new Fixture()) {
            if(variant.equals("deleted"))CoordinatorFixtures.load(f.registry,f.definitions.subList(1,f.definitions.size()));
            if(variant.equals("ambiguous")){var definitions=new ArrayList<>(f.definitions);definitions.add(CoordinatorFixtures.journey("EMPLOYEE"));CoordinatorFixtures.load(f.registry,definitions);}
            String raw=header(variant.equals("mixed-valid-invalid")?"<@employee/> <@missing/>":variant.equals("unknown")?"<@missing/>":"<@employee/>");
            if(variant.equals("unknown"))raw=raw.replace("\r\n\r\n","\r\nCookie: existing=CANARY_REQUEST_SECRET\r\n\r\n");
            String source=raw;
            var failure = assertThrows(AuthenticationFailure.class, () -> f.resolver.resolve(wire(source), null, false));
            if(variant.equals("unknown")||variant.equals("mixed-valid-invalid"))assertTrue(failure.getMessage().contains("missing"));
            assertEquals(0, f.attempts);assertEquals(0, f.coordinator.capacity().waitingRequests()); assertTrue(f.clock.workers.isEmpty());
            observed=variant.equals("unknown")?tagFailureFacts(f,raw,failure.reason().name(),failure,diagnostic):tagFailureFacts(f,raw,failure.reason().name());
        }
        tagFailureObservation(variant,observed,began);
        if(!diagnostic.isEmpty()) {
            AuthLabSupport.component("CORE.diagnostics.unresolved-tag",diagnostic,Map.of("startupMs",0L,"caseMs",java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-began),"cleanupMs",0L));
            assertAll(diagnostic.entrySet().stream().filter(e->e.getValue() instanceof Boolean).map(e->(org.junit.jupiter.api.function.Executable)()->assertTrue((boolean)e.getValue(),"Unresolved-tag feedback must satisfy "+e.getKey())));
        }
    }
    /** The actual request hook must drop the intact failed source without another acquisition or replay. */
    public Map<String,Object> tagFailureFacts(Fixture f,String raw,String cause) throws Exception {
        return tagFailureFacts(f,raw,cause,null,null);
    }
    public Map<String,Object> tagFailureFacts(Fixture f,String raw,String cause,AuthenticationFailure failure,Map<String,Object> diagnostic) throws Exception {
        int attempts=f.attempts;var sends=new java.util.concurrent.atomic.AtomicInteger();var hooks=new ProductionHooks();
        var before=diagnostic==null?null:f.registry.snapshot().resolve("employee").identity();
        try(var host=hooks.new Host(f,(request,timeout)->sends.incrementAndGet())) {
            var request=host.request(raw,901,false);byte[] original=request.toByteArray().getBytes();
            var action=hooks.callback(f,()->host.handler.handleHttpRequestToBeSent(request));
            assertEquals(burp.api.montoya.http.handler.RequestAction.DROP,action.action());assertNull(action.request());assertArrayEquals(original,request.toByteArray().getBytes());assertEquals(attempts,f.attempts);assertEquals(0,sends.get());assertEquals(0,f.coordinator.capacity().waitingRequests());assertTrue(f.clock.workers.isEmpty());
            if(diagnostic!=null) {
                String note=action.annotations().notes();var messages=new ArrayList<>(host.logs);messages.add(note);
                diagnostic.put("nativePhase",failure.phase().name());diagnostic.put("nativeCause",failure.reason().name());diagnostic.put("requestStopped",action.action()==burp.api.montoya.http.handler.RequestAction.DROP);diagnostic.put("sourceUnchanged",Arrays.equals(original,request.toByteArray().getBytes()));diagnostic.put("noReplacement",action.request()==null);
                diagnostic.put("correctAlias",note.contains("missing"));diagnostic.put("requestMessageMatches",note.contains("Request was not sent.")&&note.contains(failure.getMessage()));diagnostic.put("logMessageMatches",host.logs.stream().anyMatch(text->text.contains("Request 901:")&&text.contains(failure.problem())));
                diagnostic.put("currentRevision",before.equals(f.registry.snapshot().resolve("employee").identity())&&f.coordinator.peek(before)==null);
                diagnostic.put("forbiddenClaimAbsent",messages.stream().noneMatch(text->text.toLowerCase(java.util.Locale.ROOT).contains("connection")||text.toLowerCase(java.util.Locale.ROOT).contains("password")));diagnostic.put("redacted",messages.stream().noneMatch(text->text.contains("CANARY_REQUEST_SECRET")));
                diagnostic.put("waitingRequests",f.coordinator.capacity().waitingRequests());diagnostic.put("pendingWorkers",f.clock.workers.size());diagnostic.put("extraAttempts",f.attempts-attempts);
            }
            return Map.of("cause",cause,"drop",action.action().name(),"sourceUnchanged",Arrays.equals(original,request.toByteArray().getBytes()),"noReplacement",action.request()==null,"extraAttemptsOnDrop",f.attempts-attempts,"waitingRequests",f.coordinator.capacity().waitingRequests(),"pendingWorkers",f.clock.workers.size(),"replaySends",sends.get());
        }
    }
    public static void tagFailureObservation(String variant,Map<String,Object> observed,long began) throws Exception {
        AuthLabSupport.component("CORE.tag-failure."+variant,observed,Map.of("startupMs",0L,"caseMs",java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-began),"cleanupMs",0L));
    }
    public @org.junit.jupiter.api.TestFactory java.util.stream.Stream<org.junit.jupiter.api.DynamicTest> depthNodesAndReferenceCeilingsAreRequestWide() {
        return List.of("wrapper_depth","reference_count").stream().flatMap(dimension->List.of("below","at","above").stream().map(point->
            org.junit.jupiter.api.DynamicTest.dynamicTest("[case=CORE.limits.dimension="+dimension+"~point="+point+"]",()->{
                long began=System.nanoTime();Map<String,Object> observed;int limit=dimension.equals("wrapper_depth")?8:16,value=limit+(point.equals("below")?-1:point.equals("above")?1:0);boolean accepted=!point.equals("above");
                try(var f=new Fixture()) {
                    String marked,expected;
                    if(dimension.equals("wrapper_depth")){marked="<@url>".repeat(value)+"x"+"</@url>".repeat(value);expected="x";}
                    else {
                        var definitions=new ArrayList<JourneyDefinition>();var aliases=new ArrayList<String>();
                        for(int i=0;i<value;i++){String alias="journey"+i;definitions.add(CoordinatorFixtures.journey(alias));f.values.put(alias,"Value"+i);aliases.add(alias);}
                        CoordinatorFixtures.load(f.registry,definitions);marked=aliases.stream().map(alias->"<@"+alias+"/>").collect(java.util.stream.Collectors.joining("-"));expected=aliases.stream().map(f.values::get).collect(java.util.stream.Collectors.joining("-"));
                    }
                    byte[] raw=wire(header(marked)),original=raw.clone();boolean bytesMatch=false;String cause="NONE";
                    if(accepted){try(var operation=f.resolver.resolve(raw,null,false)){while(!f.clock.workers.isEmpty())f.clock.runWorker();byte[] result=operation.future().join().commit();bytesMatch=Arrays.equals(wire(header(expected)),result);assertTrue(bytesMatch);}}
                    else{var failure=assertThrows(AuthenticationFailure.class,()->f.resolver.resolve(raw,null,false));cause=failure.reason().name();assertEquals("CONFIGURATION",cause);}
                    assertArrayEquals(original,raw);assertEquals(accepted&&dimension.equals("reference_count")?value:0,f.attempts);assertEquals(0,f.coordinator.capacity().waitingRequests());assertTrue(f.clock.workers.isEmpty());
                    observed=limitFacts(dimension,point,value,limit,accepted,bytesMatch,cause,f.attempts,Arrays.equals(original,raw),f.coordinator.capacity().waitingRequests(),f.clock.workers.size());
                    if(dimension.equals("wrapper_depth")&&point.equals("below")){String nodes="<@employee/>".repeat(256);assertTrue(f.resolve(header(nodes)).contains("employee-token".repeat(256)));assertThrows(AuthenticationFailure.class,()->f.resolver.resolve(wire(header(nodes+"<@employee/>")),null,false));}
                }
                limitObservation(dimension,point,observed,began);
            })));
    }
    public static Map<String,Object> limitFacts(String dimension,String point,int value,int limit,boolean accepted,boolean bytesMatch,String cause,int attempts,boolean unchanged,int waiting,int workers) {
        var facts=new java.util.LinkedHashMap<String,Object>();facts.put("dimension",dimension);facts.put("point",point);facts.put("value",value);facts.put("limit",limit);facts.put("accepted",accepted);facts.put("bytesMatch",bytesMatch);facts.put("cause",cause);facts.put("attempts",attempts);facts.put("sourceUnchanged",unchanged);facts.put("waitingRequests",waiting);facts.put("pendingWorkers",workers);return facts;
    }
    public static void limitObservation(String dimension,String point,Map<String,Object> observed,long began) throws Exception {
        AuthLabSupport.component("CORE.limits.dimension="+dimension+"~point="+point,observed,Map.of("startupMs",0L,"caseMs",java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-began),"cleanupMs",0L));
    }
    public @Test void textBodiesPreserveCharsetAndRebuildActualByteLength() throws Exception {
        for (String charset : List.of("UTF-8", "US-ASCII", "ISO-8859-1")) try (var f = new Fixture()) {
            String body = "{\"token\":\"<@employee/>\"}";
            String raw = "POST /resource HTTP/1.1\r\nHost: app.example\r\nContent-Type: application/json; charset=" + charset + "\r\nContent-Length: " + body.length() + "\r\nX-Keep:  unchanged\r\n\r\n" + body;
            String output = f.resolve(raw); String expected = body.replace("<@employee/>", "employee-token");
            assertEquals(raw.replace("Content-Length: " + body.length(), "Content-Length: " + expected.length()).replace(body, expected), output);
        }
    }
    public @Test void utf8BodyUsesByteCountNotCharactersAndLatin1CannotSilentlyReplaceUnicode() throws Exception {
        long start=System.nanoTime(),ready,checked;Map<String,Object> observed;
        try (var f = new Fixture()) {
            ready=System.nanoTime();
            f.values.put("employee", "snow-\u96ea");
            String raw = "POST / HTTP/1.1\r\nHost: app.example\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n<@employee/>";
            var operation = f.resolver.resolve(wire(raw), null, false); f.clock.runWorker(); byte[] output = operation.future().join().commit();
            assertTrue(new String(output, StandardCharsets.UTF_8).contains("Content-Length: 8\r\n")); assertTrue(new String(output, StandardCharsets.UTF_8).endsWith("snow-\u96ea"));
            byte[] expected="POST / HTTP/1.1\r\nHost: app.example\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Length: 8\r\n\r\nsnow-\u96ea".getBytes(StandardCharsets.UTF_8);assertArrayEquals(expected,output);
            byte[] resized;
            try(var resize=f.resolver.resolve(wire(raw.replace("\r\n\r\n","\r\nContent-Length: 12\r\n\r\n")),null,false)){resized=resize.future().join().commit();assertArrayEquals(expected,resized);}
            var invalid = f.resolver.resolve(wire(header("<@employee/>")), null, false);
            var rejected=error(invalid);assertEquals(AuthenticationFailure.Cause.CONFIGURATION,rejected.reason());
            int split=new String(output,StandardCharsets.ISO_8859_1).indexOf("\r\n\r\n")+4;
            int declared=Integer.parseInt(new String(output,StandardCharsets.ISO_8859_1).lines().filter(line->line.startsWith("Content-Length:")).findFirst().orElseThrow().substring("Content-Length:".length()).trim());
            observed=Map.of("bytesMatch",Arrays.equals(expected,output),"rebuildBytesMatch",Arrays.equals(expected,resized),"bodyBytes",output.length-split,"declaredLength",declared,"characters","snow-\u96ea".length(),"headerCause",rejected.reason().name(),"attempts",f.attempts,"waitingRequests",f.coordinator.capacity().waitingRequests());checked=System.nanoTime();
        }
        for(String variant:List.of("unicode","body-length"))AuthLabSupport.component("CORE.encoding."+variant,observed,elapsed(start,ready,checked));
    }
    public @ParameterizedTest @ValueSource(strings = {"application/octet-stream", "multipart/form-data; boundary=test", "text/plain; charset=UTF-16", "image/png"})
    void unsupportedBodyTypeReportsTheFormatRequirementWithoutAssumingARemedy(String contentType) {
        try (var f = new Fixture()) {
            var ex = assertThrows(AuthenticationFailure.class, () -> f.resolver.resolve(wire("POST / HTTP/1.1\r\nHost: app.example\r\nContent-Type: " + contentType + "\r\n\r\n<@employee/>"), null, false));
            assertTrue(ex.problem().contains("Content-Type")); assertEquals("", ex.recovery()); assertTrue(f.clock.workers.isEmpty());
        }
    }
    public @Test void compressedAndChunkedMarkedBodiesAndUnsupportedLocationsNeverAuthenticate() throws Exception {
        long began=System.nanoTime();Map<String,Object> observed;
        try (var f = new Fixture()) {
            AuthenticationFailure firstFailure=null;
            for (String raw : List.of("POST / HTTP/1.1\r\nHost: app.example\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\n\r\n<@employee/>",
                    "POST / HTTP/1.1\r\nHost: app.example\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n<@employee/>",
                    "<@employee/> / HTTP/1.1\r\nHost: app.example\r\n\r\n", "GET http://<@employee/>/path HTTP/1.1\r\nHost: app.example\r\n\r\n",
                    "GET / HTTP/1.1\r\nHost: <@employee/>\r\n\r\n", "GET / HTTP/1.1\r\n<@employee/>: value\r\n\r\n")) {
                var failure=assertThrows(AuthenticationFailure.class, () -> f.resolver.resolve(wire(raw), null, false));if(firstFailure==null)firstFailure=failure;
            }
            assertTrue(f.clock.workers.isEmpty());
            observed=tagFailureFacts(f,"POST / HTTP/1.1\r\nHost: app.example\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\n\r\n<@employee/>",firstFailure.reason().name());
        }
        tagFailureObservation("unsupported-body",observed,began);
    }
    public @Test void percentEncodedTargetNotationIsNotExecutedOrSilentlyLeakedAsLiteralNativeSource() {
        try (var f = new Fixture()) {
            for (String marker : List.of("%3C%40bpsh%3Aemployee%2F%3E", "<%40BPSH:employee/>", "%3c@bpsh:employee/>")) {
                byte[] raw = wire("GET /?token=" + marker + " HTTP/1.1\r\nHost: app.example\r\n\r\n");
                assertTrue(NativeTagResolver.tagged(raw)); var ex = assertThrows(AuthenticationFailure.class, () -> f.resolver.resolve(raw, null, false)); assertTrue(ex.getMessage().contains("raw"));
            }
            assertTrue(f.clock.workers.isEmpty());
        }
    }
    public @Test void invalidRawTargetAndHeaderControlsFailAtomicallyAfterAcquisition() throws Exception {
        long start=System.nanoTime(),ready,checked;Map<String,Object> observed;
        try (var f = new Fixture()) {
            ready=System.nanoTime();byte[] source=wire("GET /?token=<@employee/> HTTP/1.1\r\nHost: app.example\r\n\r\n"),original=source.clone();
            f.values.put("employee", "a b"); var invalid = f.resolver.resolve(source, null, false);
            f.clock.runWorker();var targetFailure=error(invalid);assertEquals(AuthenticationFailure.Cause.CONFIGURATION,targetFailure.reason());
            var headerFailure=assertThrows(AuthenticationFailure.class, () -> f.resolver.resolve(wire(header("<@url>text</@url>\tbad")), null, false));assertArrayEquals(original,source);
            observed=Map.of("targetCause",targetFailure.reason().name(),"headerCause",headerFailure.reason().name(),"sourceUnchanged",Arrays.equals(original,source),"attempts",f.attempts,"waitingRequests",f.coordinator.capacity().waitingRequests(),"pendingWorkers",f.clock.workers.size());checked=System.nanoTime();
        }
        AuthLabSupport.component("CORE.encoding.invalid-target",observed,elapsed(start,ready,checked));
        long began=System.nanoTime();Map<String,Object> headerFailure;
        try(var f=new Fixture()) {
            f.values.put("employee","bad\r\nInjected: value");String raw=header("<@employee/>");byte[] original=wire(raw),copy=original.clone();
            try(var operation=f.resolver.resolve(original,null,false)){f.clock.runWorker();var failure=error(operation);assertEquals(AuthenticationFailure.Cause.EXTRACTION,failure.reason());assertArrayEquals(copy,original);headerFailure=tagFailureFacts(f,raw,failure.reason().name());}
        }
        tagFailureObservation("invalid-header-output",headerFailure,began);
    }
    public @org.junit.jupiter.api.TestFactory java.util.stream.Stream<org.junit.jupiter.api.DynamicTest> oversizedTaggedTextAndExpandedMessagesFailButLargeUntaggedUploadsRemainUntouched() {
        return List.of("tagged_request_bytes","output_bytes").stream().flatMap(dimension->List.of("below","at","above").stream().map(point->
            org.junit.jupiter.api.DynamicTest.dynamicTest("[case=CORE.limits.dimension="+dimension+"~point="+point+"]",()->{
                long began=System.nanoTime();Map<String,Object> observed;int limit=dimension.equals("tagged_request_bytes")?1<<20:4<<20,value=limit+(point.equals("below")?-1:point.equals("above")?1:0);boolean accepted=!point.equals("above");
                try(var f=new Fixture()) {
                    String source,expected;
                    if(dimension.equals("tagged_request_bytes")) {
                        String body="<@employee/>"+"x".repeat(value-"<@employee/>".length());source=textRequest(body);expected=textRequest("employee-token"+body.substring("<@employee/>".length()));
                    } else {
                        int bodySize=value-textRequest("").length()-7;while(textRequest("a".repeat(bodySize)).length()!=value)bodySize+=value-textRequest("a".repeat(bodySize)).length();
                        f.values.put("employee","a".repeat(65_536));f.values.put("admin","b".repeat(bodySize-63*65_536));
                        source=textRequest("<@employee/>".repeat(63)+"<@admin/>");expected=textRequest("a".repeat(63*65_536)+"b".repeat(bodySize-63*65_536));assertEquals(value,wire(expected).length);
                    }
                    byte[] raw=wire(source),original=raw.clone();boolean bytesMatch=false;String cause="NONE";
                    if(dimension.equals("tagged_request_bytes")&&!accepted){var failure=assertThrows(AuthenticationFailure.class,()->f.resolver.resolve(raw,null,false));cause=failure.reason().name();}
                    else try(var operation=f.resolver.resolve(raw,null,false)) {
                        while(!f.clock.workers.isEmpty())f.clock.runWorker();
                        if(accepted){byte[] result=operation.future().join().commit();bytesMatch=Arrays.equals(wire(expected),result);assertTrue(bytesMatch);}
                        else cause=error(operation).reason().name();
                    }
                    assertEquals(accepted?"NONE":"CONFIGURATION",cause);assertArrayEquals(original,raw);assertEquals(0,f.coordinator.capacity().waitingRequests());assertTrue(f.clock.workers.isEmpty());
                    observed=limitFacts(dimension,point,value,limit,accepted,bytesMatch,cause,f.attempts,Arrays.equals(original,raw),f.coordinator.capacity().waitingRequests(),f.clock.workers.size());
                    if(dimension.equals("tagged_request_bytes")&&point.equals("below")){byte[] upload=wire("POST /upload HTTP/1.1\r\nHost: app.example\r\nContent-Type: application/octet-stream\r\n\r\n"+"x".repeat(5<<20));try(var untouched=f.resolver.resolve(upload,null,false)){assertFalse(untouched.tagsOnly());assertFalse(untouched.future().join().changed());assertArrayEquals(upload,untouched.future().join().commit());}}
                }
                limitObservation(dimension,point,observed,began);
            })));
    }
    public static String textRequest(String body){return "POST / HTTP/1.1\r\nHost: app.example\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Length: "+body.length()+"\r\n\r\n"+body;}
    public @Test void lateGenerationAndVersionChangesPreventCommitAndReservationsAlwaysRelease() throws Exception {
        try (var f = new Fixture()) {
            var operation = f.resolver.resolve(wire(header("<@employee/> <@admin/>")), null, false); assertEquals(1, f.coordinator.capacity().waitingRequests());
            f.clock.runWorker(); f.clock.runWorker(); var result = operation.future().join(); assertEquals(0, f.coordinator.capacity().waitingRequests());
            var used = result.uses().stream().filter(u -> u.identity().equals(f.registry.snapshot().resolve("employee").identity())).findFirst().orElseThrow();
            f.coordinator.invalidateVersion(used.identity(), used.version()); assertThrows(AuthenticationFailure.class, result::commit);
            var next = f.resolver.resolve(wire(header("<@employee/>")), null, false); next.close();
            assertEquals(AuthenticationFailure.Cause.CANCELLED, error(next).reason()); assertEquals(0, f.coordinator.capacity().waitingRequests());
        }
    }
    public @Test void ordinaryCookieInjectionReplacesNamedCookieOnceWithoutChangingOthersOrSharedState() throws Exception {
        long began=System.nanoTime();Map<String,Object> observed;
        try (var f = new Fixture()) {
            var old = f.definitions.getFirst(); var cookie = new JourneyDefinition(old.id(), old.displayName(), old.alias(), old.authenticationUrl(), false, old.steps(), old.browser(), old.extraction(),
                    JourneyDefinition.Injection.perToken(List.of(new JourneyDefinition.TokenInjection(null, JourneyDefinition.InjectionType.COOKIE, "session"))), old.cache(), null);
            CoordinatorFixtures.load(f.registry, List.of(cookie));
            String raw = "POST /upload HTTP/1.1\r\nHost: app.example\r\nCookie: other=a; session=old; keep=b; session=duplicate\r\nX-Keep: unchanged\r\n\r\nopaque body";
            byte[] original=wire(raw),copy=original.clone();var operation = f.resolver.resolve(original, f.registry.snapshot().resolve("employee"), true); f.clock.runWorker();
            var resolved=operation.future().join();String expected=raw.replace(" session=old","session=employee-token").replace("; session=duplicate","");byte[] result=resolved.commit();
            assertFalse(operation.tagsOnly());assertArrayEquals(wire(expected),result);assertArrayEquals(copy,original);assertEquals(1,resolved.uses().size());assertEquals(1,f.attempts);assertEquals(0,f.coordinator.capacity().waitingRequests());
            observed=Map.of("bytesMatch",Arrays.equals(wire(expected),result),"sourceUnchanged",Arrays.equals(copy,original),"attempts",f.attempts,"usedSnapshots",resolved.uses().size(),"waitingRequests",f.coordinator.capacity().waitingRequests());
        }
        for(String variant:List.of("cookie","replace-stale","preserve-other-cookie","duplicate-name"))AuthLabSupport.component("CORE.injection."+variant,observed,Map.of("startupMs",0L,"caseMs",java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-began),"cleanupMs",0L));
    }
    public @Test void failedMixedJourneyResolutionNeverReturnsPartialBytesAndReleasesAllReservations() throws Exception {
        try (var f = new Fixture()) {
            f.failedAlias = "admin"; byte[] original = wire(header("<@employee/> <@admin/>")); byte[] preserved = original.clone();
            var operation = f.resolver.resolve(original, f.registry.snapshot().resolve("employee"), true);
            f.clock.runWorker(); f.clock.runWorker(); var failure = error(operation);
            assertEquals(AuthenticationFailure.Cause.AUTH_REJECTED, failure.reason()); assertTrue(failure.getMessage().contains("Journey admin:"));
            assertEquals(f.registry.snapshot().resolve("admin").identity(), failure.journey()); assertFalse(failure.getMessage().contains("employee"));
            assertArrayEquals(preserved, original); assertEquals(0, f.coordinator.capacity().waitingRequests());
        }
    }
    public @Test void finiteAdmissionFailureLeavesBothOrdinaryAndTaggedSourceBytesUntouched() throws Exception {
        long began=System.nanoTime();Map<String,Object> observed;
        try (var f = new Fixture()) {
            f.coordinator.updateControls(CoordinatorFixtures.limits(1, null));
            var first = f.resolver.resolve(wire(header("<@employee/>")), null, false);
            int rejected=0;boolean unchanged=true;for (boolean tagged : List.of(true, false)) {
                byte[] raw = wire(header(tagged ? "<@admin/>" : "existing")), original = raw.clone();
                var operation = f.resolver.resolve(raw, f.registry.snapshot().resolve("admin"), true);
                assertEquals(tagged, operation.tagsOnly()); assertEquals(AuthenticationFailure.Cause.CAPACITY, error(operation).reason()); assertArrayEquals(original, raw);
                rejected++;unchanged&=Arrays.equals(original,raw);
            }
            int before=f.coordinator.capacity().waitingRequests();
            first.close(); assertEquals(0, f.coordinator.capacity().waitingRequests());
            f.coordinator.close();while(!f.clock.workers.isEmpty())f.clock.runWorker();
            observed=Map.of("waitingBefore",before,"rejected",rejected,"sourceUnchanged",unchanged,"waitingRequests",f.coordinator.capacity().waitingRequests(),"runningAttempts",f.coordinator.capacity().runningAttempts(),"queuedCycles",f.coordinator.capacity().queuedCycles());
        }
        AuthenticationCoordinatorTest.recordResources("waiter-finite",observed,began);
    }

    /** Confirms each selected generation/version supplied the bytes, and a second use retains that publication. */
    public static Map<String, Object> tagPlanFacts(Fixture f, String raw, String expected, NativeTagResolver.Resolved resolved, List<String> aliases) throws Exception {
        var versions = resolved.uses().stream().collect(java.util.stream.Collectors.toMap(CredentialUse::identity, CredentialUse::version));
        var identities = aliases.stream().map(a -> f.registry.snapshot().resolve(a).identity()).collect(java.util.stream.Collectors.toSet());
        assertEquals(identities, versions.keySet());
        boolean snapshotsMatch = identities.equals(versions.keySet());
        for (String alias : new java.util.LinkedHashSet<>(aliases)) {
            var identity = f.registry.snapshot().resolve(alias).identity(); var snapshot = f.coordinator.peek(identity); assertNotNull(snapshot);
            assertEquals(identity, snapshot.identity()); assertEquals(versions.get(identity).longValue(), snapshot.version()); assertEquals(f.values.get(alias), snapshot.value());
            snapshotsMatch &= identity.equals(snapshot.identity()) && versions.get(identity) == snapshot.version() && f.values.get(alias).equals(snapshot.value());
        }
        assertEquals(identities.size(), f.attempts, "Repeated references must share one acquisition per journey.");
        byte[] first = resolved.commit(); assertArrayEquals(wire(expected), first);
        int attemptsBefore = f.attempts;
        // A mistakenly launched second acquisition now produces observably different bytes.
        f.values.replaceAll((alias, value) -> "Changed" + alias);
        boolean cachedBytesMatch;
        try (var operation = f.resolver.resolve(wire(raw), f.registry.snapshot().resolve("admin"), true)) {
            assertTrue(operation.tagsOnly()); assertTrue(operation.future().isDone(), "Current publications must resolve without another acquisition.");
            var cached = operation.future().join(); var output = cached.commit(); assertArrayEquals(wire(expected), output);
            assertEquals(versions, cached.uses().stream().collect(java.util.stream.Collectors.toMap(CredentialUse::identity, CredentialUse::version)));
            assertEquals(attemptsBefore, f.attempts); cachedBytesMatch = Arrays.equals(wire(expected), output);
        }
        assertEquals(0, f.coordinator.capacity().waitingRequests());
        return new java.util.LinkedHashMap<>(Map.of("bytesMatch", Arrays.equals(wire(expected), first), "snapshotVersionsMatch", snapshotsMatch,
                "cachedBytesMatch", cachedBytesMatch, "extraAttemptsOnCacheUse", f.attempts - attemptsBefore, "attempts", f.attempts,
                "usedSnapshots", versions.size(), "waitingRequests", f.coordinator.capacity().waitingRequests()));
    }
    public static Map<String, Long> elapsed(long start, long ready, long checked) {
        return Map.of("startupMs", java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(ready - start), "caseMs", java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(checked - ready),
                "cleanupMs", java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - checked));
    }
    /** Missing account/issuance inputs; reuses the existing HTTP acquisition and raw-wire proof adapters. */
    public @ParameterizedTest(name="[case=CORE.tag-selection.{0}]",quoteTextArguments=false)
    @ValueSource(strings={"same-account-distinct-journeys","alternating-users"})
    void journeyTagsRetainTheirOwnLoginAcrossAccountSwitchesAndIndependentRefresh(String variant) throws Exception {
        String id="CORE.tag-selection."+variant;long began=System.nanoTime();Map<String,Object> observed,automatic=null;
        try(var targets=new AuthLabSupport(List.of("credentials"));var target=targets.prepare(id)) {
            var employee=SessionRecoveryTest.matrixJourney(target,false);var base=CoordinatorFixtures.journey("admin");
            var admin=new JourneyDefinition(base.id(),base.displayName(),base.alias(),employee.authenticationUrl(),false,List.of(),base.browser(),employee.extraction(),employee.injection(),base.cache(),null);
            var runtime=new java.util.concurrent.atomic.AtomicReference<CoordinatorFixtures.ManualRuntime>();
            var issuance=new java.util.HashMap<String,String>();var allIssuances=new java.util.HashSet<String>();
            var accounts=Map.of("employee","user2","admin",variant.equals("alternating-users")?"admin":"user2");
            var passwords=Map.of("employee","pass2","admin",variant.equals("alternating-users")?"adminpass":"pass2");
            try(var f=new AuthenticationCoordinatorTest.Fixture(Config.Controls.defaults(),List.of(employee,admin),(entry,recovery,deadline,cancelled)->{
                String alias=entry.definition().canonicalAlias();var outcome=target.acquire(entry,runtime.get(),accounts.get(alias),passwords.get(alias));
                try{issuance.put(alias,target.currentLoginIssuance());}catch(Exception failure){throw new AssertionError("The completed HTTP login must have a safe issuance observation.",failure);}
                assertTrue(allIssuances.add(issuance.get(alias)),"Every actual acquisition must have a distinct issuance.");return outcome;
            })) {
                runtime.set(f.clock);f.clock.wall=java.time.Instant.now();var resolver=new NativeTagResolver(f.registry,f.coordinator);
                long initialAdminVersion=0,initialEmployeeVersion=0;String initialAdminIssuance=null;boolean preserved=true,automaticBytes=true,automaticVersions=true;var proofs=new ArrayList<Map<String,Object>>();var automaticProofs=new ArrayList<Map<String,Object>>();
                for(int i=0;i<4;i++) {
                    String alias=i%2==0?"employee":"admin";var entry=f.registry.snapshot().resolve(alias);
                    if(i==2)assertTrue(f.coordinator.invalidateVersion(f.entry(0).identity(),initialEmployeeVersion));
                    var endpoint=target.url("protected/b");String raw="GET "+endpoint.getRawPath()+"?"+endpoint.getRawQuery()+" HTTP/1.1\r\nHost: "+endpoint.getRawAuthority()+"\r\nX-Keep:\t unchanged\r\nAuthorization: Bearer <@"+alias+"/>\r\n\r\n";
                    try(var operation=resolver.resolve(wire(raw),null,false)) {
                        while(!f.clock.workers.isEmpty())f.clock.runWorker();var resolved=operation.future().join();var snapshot=f.coordinator.peek(entry.identity());
                        assertEquals(1,resolved.uses().size());assertEquals(entry.identity(),resolved.uses().getFirst().identity());assertEquals(snapshot.version(),resolved.uses().getFirst().version());
                        byte[] bytes=resolved.commit();assertArrayEquals(wire(raw.replace("<@"+alias+"/>",snapshot.value())),bytes);
                        var proof=target.proveWire(bytes,"b",accounts.get(alias),alias+"-"+i,issuance.get(alias));
                        proofs.add(Map.of("alias",alias,"account",proof.path("accountId").asText(),"issuance",proof.path("issuanceId").asText(),"status",200));
                        if(i==0)initialEmployeeVersion=snapshot.version();
                        if(i==1){initialAdminVersion=snapshot.version();initialAdminIssuance=issuance.get(alias);}
                        if(i==2)assertTrue(snapshot.version()>initialEmployeeVersion);
                        if(i==3){preserved=snapshot.version()==initialAdminVersion&&issuance.get(alias).equals(initialAdminIssuance);assertTrue(preserved);}
                        if(variant.equals("alternating-users")&&i>=2) {
                            int before=f.attempts.get();String ordinary=raw.replace("<@"+alias+"/>","stale");var rule=SessionRecoveryTest.lossRule();
                            try(var automaticOperation=resolver.resolveAutomatic(wire(ordinary),List.of(new NativeTagResolver.Automatic(entry,rule)))) {
                                assertTrue(automaticOperation.future().isDone());var automaticResolved=automaticOperation.future().join();byte[] bytesOut=automaticResolved.commit();
                                boolean matches=Arrays.equals(wire(ordinary.replace("Bearer stale","Bearer "+snapshot.value())),bytesOut);assertTrue(matches);automaticBytes&=matches;
                                assertEquals(1,automaticResolved.uses().size());boolean sameVersion=automaticResolved.uses().getFirst().identity().equals(entry.identity())&&automaticResolved.uses().getFirst().version()==snapshot.version();assertTrue(sameVersion);automaticVersions&=sameVersion;
                                var accepted=target.proveWire(bytesOut,"b",accounts.get(alias),"automatic-"+i,issuance.get(alias));automaticProofs.add(Map.of("account",accepted.path("accountId").asText(),"issuance",accepted.path("issuanceId").asText(),"status",200));assertEquals(before,f.attempts.get());
                            }
                        }
                    }
                }
                assertEquals(3,f.attempts.get());assertEquals(3,allIssuances.size());assertNotEquals(proofs.get(0).get("issuance"),proofs.get(1).get("issuance"));assertEquals(0,f.coordinator.capacity().waitingRequests());
                observed=Map.of("proofs",proofs,"attempts",f.attempts.get(),"distinctIssuances",allIssuances.size(),"unaffectedJourneyPreserved",preserved,"waitingRequests",f.coordinator.capacity().waitingRequests());
                if(variant.equals("alternating-users"))automatic=Map.of("proofs",automaticProofs,"bytesMatch",automaticBytes,"sameVersion",automaticVersions,"attempts",f.attempts.get(),"waitingRequests",f.coordinator.capacity().waitingRequests());
            }
        }
        AuthLabSupport.component(id,observed,Map.of("startupMs",0L,"caseMs",java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-began),"cleanupMs",0L));
        if(automatic!=null)AuthLabSupport.component("CORE.injection.selected-journey-change",automatic,Map.of("startupMs",0L,"caseMs",java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-began),"cleanupMs",0L));
    }
    public @org.junit.jupiter.api.TestFactory
    java.util.stream.Stream<org.junit.jupiter.api.DynamicTest> missingRepresentableLocationEncodingAndReferenceCombinations() {
        var cases = new ArrayList<org.junit.jupiter.api.DynamicTest>();
        for (String location : List.of("header", "path", "query", "text-body")) for (String mode : List.of("raw", "url", "form", "json")) for (int count = 1; count <= 3; count++) {
            // The retained rawReferences... method already owns this request-wide single-reference case.
            if (location.equals("header") && mode.equals("raw") && count == 1) continue;
            int references = count;
            String id = "CORE.tag-matrix.location=" + location + "~mode=" + mode + "~references=" + count;
            cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("[case=" + id + "]", () -> {
                var facts = new java.util.LinkedHashMap<String, Object>();
                long startupNs = 0, caseNs = 0, cleanupNs = 0;
                int attempts = 0, snapshots = 0, extraAttempts = 0, waiting = 0;
                boolean bytesMatch = true, snapshotVersionsMatch = true, cachedBytesMatch = true;
                int plans = references == 1 ? 1 : 2;
                for (int plan = 0; plan < plans; plan++) {
                    long start = System.nanoTime(), ready, checked;
                    try (var f = new Fixture()) {
                        ready = System.nanoTime();
                        f.values.putAll(Map.of("employee", "Alpha1", "admin", "Beta2", "url", "Gamma3"));
                        var aliases = plan == 0 ? List.of("employee", "admin", "url").subList(0, references) : java.util.Collections.nCopies(references, "employee");
                        String source = aliases.stream().map(alias -> "<@" + alias + "/>").map(tag -> mode.equals("raw") ? tag : "<@" + mode + ">" + tag + "</@" + mode + ">").collect(java.util.stream.Collectors.joining("-"));
                        String value = aliases.stream().map(f.values::get).collect(java.util.stream.Collectors.joining("-"));
                        String raw = switch (location) {
                            case "header" -> header(source);
                            case "path" -> "GET /prefix/" + source + "/tail HTTP/1.1\r\nHost: app.example\r\nX-Keep:\t unchanged\r\n\r\n";
                            case "query" -> "GET /protected?keep=yes&token=" + source + "&after=stay HTTP/1.1\r\nHost: app.example\r\n\r\n";
                            default -> "POST /protected HTTP/1.1\r\nHost: app.example\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Length: " + source.length() + "\r\nX-Keep: unchanged\r\n\r\n" + source;
                        };
                        String expected = raw.replace(source, value);
                        if (location.equals("text-body")) expected = expected.replace("Content-Length: " + source.length(), "Content-Length: " + value.length());
                        try (var operation = f.resolver.resolve(wire(raw), f.registry.snapshot().resolve("admin"), true)) {
                            assertTrue(operation.tagsOnly()); assertEquals(1, f.coordinator.capacity().waitingRequests());
                            while (!f.clock.workers.isEmpty()) f.clock.runWorker();
                            var resolved = operation.future().join(); byte[] output = resolved.commit(); assertArrayEquals(wire(expected), output);
                            assertEquals(plan == 0 ? references : 1, f.attempts); assertEquals(plan == 0 ? references : 1, resolved.uses().size());
                            assertEquals(0, f.coordinator.capacity().waitingRequests());
                            var observed = tagPlanFacts(f, raw, expected, resolved, aliases);
                            bytesMatch &= (boolean) observed.get("bytesMatch"); snapshotVersionsMatch &= (boolean) observed.get("snapshotVersionsMatch"); cachedBytesMatch &= (boolean) observed.get("cachedBytesMatch");
                            attempts += (int) observed.get("attempts"); snapshots += (int) observed.get("usedSnapshots"); extraAttempts += (int) observed.get("extraAttemptsOnCacheUse"); waiting += (int) observed.get("waitingRequests");
                        }
                        checked = System.nanoTime();
                    }
                    startupNs += ready - start; caseNs += checked - ready; cleanupNs += System.nanoTime() - checked;
                }
                facts.putAll(Map.of("location", location, "mode", mode, "references", references, "plans", plans, "bytesMatch", bytesMatch,
                        "snapshotVersionsMatch", snapshotVersionsMatch, "cachedBytesMatch", cachedBytesMatch, "extraAttemptsOnCacheUse", extraAttempts));
                facts.put("attempts", attempts); facts.put("usedSnapshots", snapshots); facts.put("waitingRequests", waiting);
                AuthLabSupport.component(id, facts, Map.of("startupMs", java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(startupNs),
                        "caseMs", java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(caseNs), "cleanupMs", java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(cleanupNs)));
                if(location.equals("header")&&mode.equals("raw")) {
                    var timing=Map.of("startupMs",java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(startupNs),"caseMs",java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(caseNs),"cleanupMs",java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(cleanupNs));
                    AuthLabSupport.component("CORE.tag-selection."+(references==2?"two-identities":"three-identities"),facts,timing);
                    if(references==3)AuthLabSupport.component("CORE.tag-selection.repeat-one-output",facts,timing);
                }
            }));
        }
        return cases.stream();
    }

    /** Runs the actual production hooks against a small host factory double, never a Burp process. */
    public @org.junit.jupiter.api.Nested class ProductionHooks {
        /** Replaces only the SDK test JVM's factory and restores it after every hook test. */
        public final class Host implements AutoCloseable {
            public final burp.api.montoya.internal.MontoyaObjectFactory previous = burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;
            public final java.util.concurrent.atomic.AtomicReference<Config.Controls> controls = new java.util.concurrent.atomic.AtomicReference<>(Config.Controls.defaults());
            public final java.util.concurrent.atomic.AtomicInteger largeReads = new java.util.concurrent.atomic.AtomicInteger(), urls = new java.util.concurrent.atomic.AtomicInteger(), bodyAccesses = new java.util.concurrent.atomic.AtomicInteger();
            public final List<String> logs = new java.util.concurrent.CopyOnWriteArrayList<>();
            public final AuthTrafficGuard guard = new AuthTrafficGuard(); public final Diagnostics diagnostics = new Diagnostics(logs::add);
            public final SessionRecovery recovery; public final HttpSessionHandler handler;
            public boolean supportsDrop = true;
            public burp.api.montoya.core.ToolType selectedTool = burp.api.montoya.core.ToolType.EXTENSIONS;
            /** @param fixture Shared deterministic coordinator and saved aliases. */
            public Host(Fixture fixture) { this(fixture, null); }
            public Host(Fixture fixture, HttpSessionHandler.ReplayTransport transport) {
                this(fixture.registry,fixture.resolver,fixture.coordinator,fixture.clock::nanos,transport);
            }
            public Host(JourneyRegistry registry,NativeTagResolver resolver,AuthenticationCoordinator coordinator,java.util.function.LongSupplier nanos,HttpSessionHandler.ReplayTransport transport) {
                recovery = new SessionRecovery(coordinator,nanos);
                burp.api.montoya.internal.ObjectFactoryLocator.FACTORY = stub(burp.api.montoya.internal.MontoyaObjectFactory.class, (method, args) -> factory(method, args));
                handler = new HttpSessionHandler(registry,resolver,guard,recovery,diagnostics,controls,transport);
            }
            /** @param type SDK interface. @param call Observed public API behavior. @return Small test-only dynamic implementation. */
            public <T> T stub(Class<T> type, java.util.function.BiFunction<java.lang.reflect.Method, Object[], Object> call) {
                return type.cast(java.lang.reflect.Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (proxy, method, args) -> {
                    if (method.getName().equals("toString")) return "Montoya test double";
                    if (method.getName().equals("hashCode")) return System.identityHashCode(proxy);
                    if (method.getName().equals("equals")) return proxy == args[0];
                    return call.apply(method, args == null ? new Object[0] : args);
                }));
            }
            /** @param method SDK factory signature. @param a Factory arguments. @return Pure in-memory host object, with no network or installed app access. */
            public Object factory(java.lang.reflect.Method method, Object[] a) {
                var result = method.getReturnType(); String name = method.getName();
                if (result == burp.api.montoya.core.ByteArray.class) return bytes((byte[]) a[0]);
                if (result == burp.api.montoya.core.Annotations.class) return annotations(a.length > 0 && a[0] instanceof String s ? s : "", null);
                if (result == burp.api.montoya.http.message.requests.HttpRequest.class) {
                    Object raw = a[a.length - 1]; return request(raw instanceof String s ? s : new String(((burp.api.montoya.core.ByteArray) raw).getBytes(), StandardCharsets.ISO_8859_1), 99, false);
                }
                if (result == burp.api.montoya.http.handler.RequestToBeSentAction.class) {
                    if (!supportsDrop) throw new UnsupportedOperationException("Controlled unsupported host factory");
                    boolean full = a.length == 4; var action = full ? a[0] : burp.api.montoya.http.handler.RequestAction.CONTINUE;
                    Object request = full ? a[1] : a[0], notes = full ? a[3] : a.length > 1 ? a[1] : annotations("", null);
                    return stub(burp.api.montoya.http.handler.RequestToBeSentAction.class, (m, x) -> switch (m.getName()) { case "action" -> action; case "request" -> request; case "annotations" -> notes; default -> null; });
                }
                if (result == burp.api.montoya.http.handler.ResponseReceivedAction.class) return stub(burp.api.montoya.http.handler.ResponseReceivedAction.class, (m, x) -> m.getName().equals("response") ? a[0] : m.getName().equals("annotations") && a.length > 1 ? a[1] : null);
                if (result == burp.api.montoya.proxy.http.ProxyRequestReceivedAction.class || result == burp.api.montoya.proxy.http.ProxyResponseReceivedAction.class) {
                    Object action = a.length == 3 ? a[2] : java.lang.Enum.valueOf(burp.api.montoya.proxy.MessageReceivedAction.class, name.contains("DoNotIntercept") ? "DO_NOT_INTERCEPT" : "CONTINUE");
                    return stub(result, (m, x) -> switch (m.getName()) { case "action" -> action; case "request", "response" -> a[0]; case "annotations" -> a.length > 1 ? a[1] : annotations("", null); default -> null; });
                }
                throw new AssertionError("Unexpected SDK factory boundary: " + name);
            }
            /** @param value Exact wire bytes. @return Byte-array view whose large materialization is counted. */
            public burp.api.montoya.core.ByteArray bytes(byte[] value) {
                return stub(burp.api.montoya.core.ByteArray.class, (method, a) -> switch (method.getName()) {
                    case "length" -> value.length; case "getByte" -> value[(int) a[0]];
                    case "getBytes" -> { if (value.length > 65_536) largeReads.incrementAndGet(); yield value.clone(); }
                    case "subArray" -> bytes(Arrays.copyOfRange(value, (int) a[0], (int) a[1]));
                    case "indexOf" -> {
                        byte[] needle = a[0] instanceof String s ? wire(s) : ((burp.api.montoya.core.ByteArray) a[0]).getBytes();
                        boolean sensitive = a.length == 1 || (boolean) a[1]; int start = a.length > 2 ? (int) a[2] : 0, end = a.length > 3 ? (int) a[3] : value.length, found = -1;
                        outer: for (int i = start; i + needle.length <= end; i++) {
                            for (int j = 0; j < needle.length; j++) if ((sensitive ? value[i + j] : Character.toLowerCase((char) (value[i + j] & 255))) != (sensitive ? needle[j] : Character.toLowerCase((char) (needle[j] & 255)))) continue outer;
                            found = i; break;
                        }
                        yield found;
                    }
                    default -> throw new AssertionError("Unexpected byte access: " + method.getName());
                });
            }
            /** @param notes Existing/new notes. @param color Optional existing highlight. @return Annotation value preserving unrelated user notes. */
            public burp.api.montoya.core.Annotations annotations(String notes, burp.api.montoya.core.HighlightColor color) {
                var current = new java.util.concurrent.atomic.AtomicReference<>(notes);
                return stub(burp.api.montoya.core.Annotations.class, (m, a) -> switch (m.getName()) {
                    case "notes" -> current.get(); case "withNotes" -> annotations((String) a[0], color); case "withHighlightColor" -> annotations(current.get(), (burp.api.montoya.core.HighlightColor) a[0]);
                    case "setNotes" -> { current.set((String) a[0]); yield null; } case "highlightColor" -> color; default -> null;
                });
            }
            /** @param raw Complete raw request. @param id Host correlation ID. @param inScope Ordinary scope status. @return Global/Proxy-compatible request double. */
            public burp.api.montoya.http.handler.HttpRequestToBeSent request(String raw, int id, boolean inScope) {
                byte[] wire = wire(raw); int end = raw.indexOf("\r\n\r\n");
                var headers = new ArrayList<burp.api.montoya.http.message.HttpHeader>();
                for (String line : raw.substring(raw.indexOf("\r\n") + 2, end).split("\r\n")) {
                    int colon = line.indexOf(':'); if (colon < 0) continue; String name = line.substring(0, colon), value = line.substring(colon + 1).stripLeading();
                    headers.add(stub(burp.api.montoya.http.message.HttpHeader.class, (m, a) -> m.getName().equals("name") ? name : value));
                }
                var notes = annotations("existing user note", null);
                Object request = java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{burp.api.montoya.http.handler.HttpRequestToBeSent.class, burp.api.montoya.proxy.http.InterceptedRequest.class}, (proxy, m, args) -> {
                    Object[] a = args == null ? new Object[0] : args;
                    return switch (m.getName()) {
                        case "messageId" -> id; case "headers" -> headers; case "toByteArray" -> bytes(wire); case "annotations" -> notes; case "isInScope" -> inScope;
                        case "httpService" -> null; case "toolSource" -> stub(burp.api.montoya.core.ToolSource.class, (method, x) -> ToolTypeForTest());
                        case "headerValue" -> headers.stream().filter(h -> h.name().equalsIgnoreCase((String) a[0])).map(h -> h.value()).findFirst().orElse(null);
                        case "url" -> { urls.incrementAndGet(); if (raw.contains("<@bpsh")) throw new AssertionError("URL helpers must not receive literal native syntax"); yield "https://app.example/protected"; }
                        case "hasHeader" -> headers.stream().anyMatch(h -> h.name().equalsIgnoreCase((String) a[0]));
                        case "withAddedHeader" -> request(raw.substring(0, end) + "\r\n" + a[0] + ": " + a[1] + raw.substring(end), id, inScope);
                        case "withUpdatedHeader" -> {
                            String changed = raw.replaceAll("(?im)^" + java.util.regex.Pattern.quote((String) a[0]) + ":[^\\r\\n]*", a[0] + ": " + a[1]); yield request(changed, id, inScope);
                        }
                        case "toString" -> "Request test double";
                        default -> throw new AssertionError("Unexpected request boundary: " + m.getName());
                    };
                });
                return (burp.api.montoya.http.handler.HttpRequestToBeSent) request;
            }
            /** @return A tool which ordinary policy may exclude but explicit native tags still support. */
            private burp.api.montoya.core.ToolType ToolTypeForTest() { return selectedTool; }
            /** @param id Correlated message ID. @param status Actual status. @param type MIME value. @param body Exact body bytes. @return Global/Proxy-compatible response. */
            public burp.api.montoya.http.handler.HttpResponseReceived response(int id, short status, String type, byte[] body) {
                return (burp.api.montoya.http.handler.HttpResponseReceived) java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{burp.api.montoya.http.handler.HttpResponseReceived.class, burp.api.montoya.proxy.http.InterceptedResponse.class}, (proxy, m, a) -> switch (m.getName()) {
                    case "messageId" -> id; case "statusCode" -> status; case "toByteArray" -> bytes(body); case "bodyOffset" -> 0;
                    case "body" -> { bodyAccesses.incrementAndGet(); yield bytes(body); } case "annotations" -> annotations("", null);
                    case "headerValue" -> ((String) a[0]).equalsIgnoreCase("Content-Type") ? type : null;
                    case "bodyToString" -> throw new AssertionError("Response body must not be materialized as text before guards");
                    case "toString" -> "Response test double"; default -> null;
                });
            }
            /** Restores the SDK test factory and closes only this test's hook services. */
            @Override public void close() { handler.close(); recovery.close(); guard.close(); diagnostics.close(); burp.api.montoya.internal.ObjectFactoryLocator.FACTORY = previous; }
        }

        /** @param f Deterministic acquisition fixture. @param action Blocking host callback. @return Completed action after one admitted worker executes. */
        public <T> T callback(Fixture f, java.util.concurrent.Callable<T> action) throws Exception {
            var thread = java.util.concurrent.Executors.newSingleThreadExecutor();
            try {
                var result = thread.submit(action); long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(5);
                while (!result.isDone() && deadline - System.nanoTime() > 0) { if (!f.clock.workers.isEmpty()) f.clock.runWorker(); else Thread.sleep(1); }
                return result.get(5, java.util.concurrent.TimeUnit.SECONDS);
            } finally { thread.shutdownNow(); assertTrue(thread.awaitTermination(2, java.util.concurrent.TimeUnit.SECONDS), "Owned hook callback must finish before fixture cleanup completes."); }
        }
        public @org.junit.jupiter.api.TestFactory
        java.util.stream.Stream<org.junit.jupiter.api.DynamicTest> ordinaryAndTaggedPolicyAcrossEveryBaselineTool() {
            var cases = new ArrayList<org.junit.jupiter.api.DynamicTest>();
            for (var tool : List.of(burp.api.montoya.core.ToolType.SCANNER, burp.api.montoya.core.ToolType.PROXY, burp.api.montoya.core.ToolType.REPEATER, burp.api.montoya.core.ToolType.EXTENSIONS, burp.api.montoya.core.ToolType.INTRUDER))
                for (var mode : Config.UrlMode.values()) for (boolean enabled : List.of(true, false)) for (boolean tagged : List.of(true, false)) {
                    String id = "CORE.tool-policy.tool=" + tool.name().toLowerCase(java.util.Locale.ROOT) + "~urlMode=" + mode.name().toLowerCase(java.util.Locale.ROOT) + "~enabled=" + enabled + "~tagged=" + tagged;
                    cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("[case=" + id + "]", () -> {
                        Map<String, Object> facts,filterFacts=null;
                        long start = System.nanoTime(), ready, checked;
                        try (var f = new Fixture(); var host = new Host(f)) {
                            ready = System.nanoTime();
                            host.selectedTool = tool; var entry = f.registry.snapshot().resolve("employee"); var defaults = Config.Controls.defaults(); int message = 100;
                            boolean bytesMatch = true, continued = true;
                            for (boolean toolAllowed : List.of(true, false)) for (boolean matches : List.of(true, false)) {
                                var alternative = tool == burp.api.montoya.core.ToolType.REPEATER ? burp.api.montoya.core.ToolType.PROXY : burp.api.montoya.core.ToolType.REPEATER;
                                var rule = new Config.AutomaticRule(true, new Config.JourneySelection(entry.identity().scope(), entry.identity().journeyId()), mode,
                                        mode == Config.UrlMode.SINGLE_URL ? java.net.URI.create(matches ? "https://app.example/protected" : "https://different.example/") : null,
                                        new JourneyDefinition.Recovery(false, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null));
                                host.controls.set(new Config.Controls(enabled, List.of(rule), List.of(toolAllowed ? tool : alternative), defaults.requestWaitTimeoutMs(), defaults.attemptTimeoutMs(), defaults.cycleTimeoutMs(), null, null));
                                String raw = header(tagged ? "Bearer <@employee/>" : "existing");
                                var request = host.request(raw, message++, matches);
                                int attemptsBefore=f.attempts;
                                var action = callback(f, () -> host.handler.handleHttpRequestToBeSent(request));
                                boolean inject = tagged || enabled && toolAllowed && (mode == Config.UrlMode.ALL_REQUESTS || matches);
                                byte[] expected = wire(inject ? header("Bearer employee-token") : raw), actual = action.request().toByteArray().getBytes();
                                bytesMatch &= Arrays.equals(expected, actual); continued &= action.action() == burp.api.montoya.http.handler.RequestAction.CONTINUE;
                                assertArrayEquals(expected, actual);
                                assertEquals(burp.api.montoya.http.handler.RequestAction.CONTINUE, action.action());
                                assertEquals(0, f.coordinator.capacity().waitingRequests());
                                if(tool==burp.api.montoya.core.ToolType.EXTENSIONS&&!tagged&&mode==Config.UrlMode.SINGLE_URL&&enabled&&toolAllowed&&!matches)
                                    filterFacts=Map.of("checkedRequests",1,"unchanged",Arrays.equals(wire(raw),actual),"action",action.action().name(),"extraAttempts",f.attempts-attemptsBefore,"waitingRequests",f.coordinator.capacity().waitingRequests());
                            }
                            assertEquals(tagged || enabled ? 1 : 0, f.attempts);
                            if (tagged && !enabled) assertEquals(0, host.urls.get(), "Disabled automatic handling must not consult ordinary URL filters for explicit tags.");
                            facts = new java.util.LinkedHashMap<>(Map.of("tool", tool.name(), "urlMode", mode.name(), "enabled", enabled, "tagged", tagged, "policyChecks", 4,
                                    "attempts", f.attempts, "waitingRequests", f.coordinator.capacity().waitingRequests()));
                            facts.put("bytesMatch", bytesMatch); facts.put("continued", continued); facts.put("urlHelperCalls", host.urls.get());
                            checked = System.nanoTime();
                        }
                        AuthLabSupport.component(id, facts, Map.of("startupMs", java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(ready - start),
                                "caseMs", java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(checked - ready), "cleanupMs", java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - checked)));
                        if(tool==burp.api.montoya.core.ToolType.EXTENSIONS&&!tagged&&!enabled&&mode==Config.UrlMode.ALL_REQUESTS)
                            AuthLabSupport.component("CORE.injection.disabled",Map.of("checkedRequests",facts.get("policyChecks"),"unchanged",facts.get("bytesMatch"),"action",(boolean)facts.get("continued")?"CONTINUE":"OTHER","extraAttempts",facts.get("attempts"),"waitingRequests",facts.get("waitingRequests")),elapsed(start,ready,checked));
                        if(filterFacts!=null)AuthLabSupport.component("CORE.injection.url-filter",filterFacts,elapsed(start,ready,checked));
                    }));
                }
            return cases.stream();
        }
        public @Test void explicitGlobalHookResolvesOutOfScopeWithAutomaticDisabledBeforeAnyUrlHelper() throws Exception {
            try (var f = new Fixture(); var host = new Host(f)) {
                String raw = header("Bearer <@employee/>"); var request = host.request(raw, 10, false);
                var result = callback(f, () -> host.handler.handleHttpRequestToBeSent(request));
                assertEquals(burp.api.montoya.http.handler.RequestAction.CONTINUE, result.action());
                assertArrayEquals(wire(raw.replace("<@employee/>", "employee-token")), result.request().toByteArray().getBytes()); assertEquals(0, host.urls.get());
            }
        }
        public @Test void requestContextMenuInsertsLiteralTagsAndRejectsStaleEditorOrJourney() {
            try (var f = new Fixture(); var host = new Host(f)) {
                String raw = header("Existing"); int caret = raw.indexOf("Existing");
                var current = new java.util.concurrent.atomic.AtomicReference<burp.api.montoya.http.message.requests.HttpRequest>(host.request(raw, 8, false));
                var writes = new java.util.concurrent.atomic.AtomicInteger(); var reports = new ArrayList<String>();
                var pair = host.stub(burp.api.montoya.http.message.HttpRequestResponse.class, (m, a) -> m.getName().equals("request") ? current.get() : null);
                var editor = host.stub(burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.class, (m, a) -> switch (m.getName()) {
                    case "selectionContext" -> burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.SelectionContext.REQUEST;
                    case "selectionOffsets" -> java.util.Optional.empty(); case "caretPosition" -> caret; case "requestResponse" -> pair;
                    case "setRequest" -> { current.set((burp.api.montoya.http.message.requests.HttpRequest) a[0]); writes.incrementAndGet(); yield null; }
                    default -> null;
                });
                var event = host.stub(burp.api.montoya.ui.contextmenu.ContextMenuEvent.class, (m, a) -> m.getName().equals("messageEditorRequestResponse") ? java.util.Optional.of(editor) : null);
                var provider = new AuthenticationTagMenu(f.registry, reports::add);
                var root = (javax.swing.JMenu) provider.provideMenuItems(event).getFirst();
                var employee = java.util.stream.IntStream.range(0, root.getItemCount()).mapToObj(root::getItem).filter(item -> item.getText().equals("employee")).map(javax.swing.JMenu.class::cast).findFirst().orElseThrow();
                employee.getItem(1).doClick();
                assertEquals(raw.substring(0, caret) + "<@url><@employee/></@url>" + raw.substring(caret), new String(current.get().toByteArray().getBytes(), StandardCharsets.ISO_8859_1));
                assertEquals(1, writes.get()); assertTrue(f.clock.workers.isEmpty());
                employee.getItem(0).doClick(); assertEquals(1, writes.get()); assertTrue(reports.getLast().contains("request changed"));
                CoordinatorFixtures.load(f.registry, List.of()); employee.getItem(0).doClick(); assertEquals(1, writes.get()); assertTrue(reports.getLast().contains("journey changed"));
            }
        }
        public @Test void orderedAutomaticRulesRespectActivationToolsScopesOrderAndUsedExpiration() throws Exception {
            try (var f = new Fixture(); var host = new Host(f)) {
                var employee = f.registry.snapshot().resolve("employee"); var admin = f.registry.snapshot().resolve("admin"); var disabled = f.registry.snapshot().resolve("url");
                var first = new Config.AutomaticRule(true, new Config.JourneySelection(employee.identity().scope(), employee.identity().journeyId()), Config.UrlMode.BURP_SCOPE, null, new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null));
                var second = new Config.AutomaticRule(true, new Config.JourneySelection(admin.identity().scope(), admin.identity().journeyId()), Config.UrlMode.SINGLE_URL, java.net.URI.create("https://app.example/"), new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 403, null));
                var off = new Config.AutomaticRule(false, new Config.JourneySelection(disabled.identity().scope(), disabled.identity().journeyId()), Config.UrlMode.ALL_REQUESTS, null, first.recovery());
                var defaults = Config.Controls.defaults();
                host.controls.set(new Config.Controls(true, List.of(first, off, second), defaults.tools(), 60_000, 60_000, 300_000, null, null));
                var sent = callback(f, () -> host.handler.handleHttpRequestToBeSent(host.request(header("stale"), 501, true)));
                assertTrue(new String(sent.request().toByteArray().getBytes(), StandardCharsets.ISO_8859_1).contains("Bearer admin-token")); assertEquals(2, f.attempts);
                host.handler.handleHttpResponseReceived(host.response(501, (short) 401, null, new byte[0])); assertNotNull(f.coordinator.peek(admin.identity())); assertNotNull(f.coordinator.peek(employee.identity()));
                host.controls.set(new Config.Controls(true, List.of(second, first), defaults.tools(), 60_000, 60_000, 300_000, null, null));
                sent = callback(f, () -> host.handler.handleHttpRequestToBeSent(host.request(header("stale"), 502, true)));
                assertTrue(new String(sent.request().toByteArray().getBytes(), StandardCharsets.ISO_8859_1).contains("Bearer employee-token")); assertEquals(2, f.attempts);
                sent = callback(f, () -> host.handler.handleHttpRequestToBeSent(host.request(header("stale"), 503, false)));
                assertTrue(new String(sent.request().toByteArray().getBytes(), StandardCharsets.ISO_8859_1).contains("Bearer admin-token"));
                host.handler.handleHttpResponseReceived(host.response(503, (short) 403, null, new byte[0])); assertNull(f.coordinator.peek(admin.identity())); assertNotNull(f.coordinator.peek(employee.identity()));
                host.controls.set(new Config.Controls(true, List.of(first, second), List.of(burp.api.montoya.core.ToolType.REPEATER), 60_000, 60_000, 300_000, null, null));
                var excluded = host.request(header("stale"), 504, true); assertSame(excluded, host.handler.handleHttpRequestToBeSent(excluded).request()); assertEquals(2, f.attempts);
                host.controls.set(new Config.Controls(false, List.of(first, second), defaults.tools(), 60_000, 60_000, 300_000, null, null));
                assertSame(excluded, host.handler.handleHttpRequestToBeSent(excluded).request());
                var missing = new Config.AutomaticRule(true, new Config.JourneySelection(JourneyDefinition.Scope.PROJECT, java.util.UUID.randomUUID()), Config.UrlMode.ALL_REQUESTS, null, first.recovery());
                host.controls.set(new Config.Controls(true, List.of(first, missing), defaults.tools(), 60_000, 60_000, 300_000, null, null));
                var rejected = host.handler.handleHttpRequestToBeSent(excluded); assertSame(excluded, rejected.request()); assertTrue(rejected.annotations().notes().contains("unavailable")); assertEquals(1, f.clock.workers.size(), "the prior observed loss owns the only recovery; missing identities start no extra work");
            }
        }
        public @Test void actualHookDropsTaggedFailureAndPreservesOrdinaryFailureBytesWithWarning() throws Exception {
            try (var f = new Fixture(); var host = new Host(f)) {
                f.failedAlias = "employee"; var tagged = host.request(header("<@employee/>"), 1, false);
                var stopped = callback(f, () -> host.handler.handleHttpRequestToBeSent(tagged)); assertEquals(burp.api.montoya.http.handler.RequestAction.DROP, stopped.action());
                assertTrue(stopped.annotations().notes().contains("not sent")); assertTrue(stopped.annotations().notes().contains("employee")); assertTrue(stopped.annotations().notes().contains("existing user note"));
                var d = Config.Controls.defaults(); var entry = f.registry.snapshot().resolve("employee");
                host.controls.set(new Config.Controls(true, List.of(new Config.AutomaticRule(true, new Config.JourneySelection(entry.identity().scope(), entry.identity().journeyId()), Config.UrlMode.ALL_REQUESTS, null, new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null))), d.tools(), 60_000, 60_000, 300_000, null, null));
                var ordinary = host.request(header("Existing"), 2, true); var unchanged = host.handler.handleHttpRequestToBeSent(ordinary);
                assertSame(ordinary, unchanged.request()); assertTrue(unchanged.annotations().notes().contains("unchanged request was sent")); assertFalse(host.logs.isEmpty());
            }
        }
        public @Test void proxyOwnedCarrierIsRetainedUntilGlobalSendAndResponseLedgersRemainIndependent() throws Exception {
            try (var f = new Fixture(); var host = new Host(f); var lease = host.guard.begin()) {
                var entry = f.registry.snapshot().resolve("employee"); var defaults = Config.Controls.defaults();
                var rule = new Config.AutomaticRule(true, new Config.JourneySelection(entry.identity().scope(), entry.identity().journeyId()),
                        Config.UrlMode.ALL_REQUESTS, null, new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null));
                host.controls.set(new Config.Controls(true, List.of(rule), defaults.tools(), 60_000, 60_000, 300_000, null, null));
                String raw = header("existing").replace("\r\n\r\n", "\r\nUser-Agent: " + lease.decorate("Actual full agent") + "\r\n\r\n"); var request = host.request(raw, 77, false);
                var proxy = host.handler.handleRequestReceived((burp.api.montoya.proxy.http.InterceptedRequest) request);
                assertEquals(burp.api.montoya.proxy.MessageReceivedAction.DO_NOT_INTERCEPT, proxy.action());
                var global = callback(f, () -> host.handler.handleHttpRequestToBeSent(request));
                assertEquals("Actual full agent", global.request().headerValue("User-Agent")); assertTrue(f.clock.workers.isEmpty());
                var response = host.response(77, (short) 401, "application/octet-stream", new byte[0]);
                assertSame(response, host.handler.handleHttpResponseReceived(response).response());
                assertEquals(0, f.attempts, "Owned login traffic must not authenticate itself even when its URL and 401 match automatic handling.");
                assertTrue(f.clock.workers.isEmpty()); assertEquals(0, f.coordinator.capacity().waitingRequests());
                var proxyResponse = host.handler.handleResponseReceived((burp.api.montoya.proxy.http.InterceptedResponse) response);
                assertEquals(burp.api.montoya.proxy.MessageReceivedAction.DO_NOT_INTERCEPT, proxyResponse.action());
                assertEquals(burp.api.montoya.proxy.MessageReceivedAction.CONTINUE, host.handler.handleResponseReceived((burp.api.montoya.proxy.http.InterceptedResponse) response).action());
            }
        }
        public @Test void staleAndNestedOwnedRequestsStopWithoutAcquisitionWhileNormalProxyTrafficKeepsUserRules() throws Exception {
            try (var f = new Fixture(); var host = new Host(f)) {
                String marked; try (var lease = host.guard.begin()) { marked = lease.decorate("Agent"); }
                var stale = host.request(header("existing").replace("\r\n\r\n", "\r\nUser-Agent: " + marked + "\r\n\r\n"), 1, false);
                assertEquals(burp.api.montoya.http.handler.RequestAction.DROP, host.handler.handleHttpRequestToBeSent(stale).action());
                try (var lease = host.guard.begin()) {
                    var nested = host.request(header("<@employee/>").replace("\r\n\r\n", "\r\nUser-Agent: " + lease.decorate("Agent") + "\r\n\r\n"), 2, false);
                    assertEquals(burp.api.montoya.http.handler.RequestAction.DROP, host.handler.handleHttpRequestToBeSent(nested).action());
                }
                var normal = host.request(header("existing"), 3, false);
                assertEquals(burp.api.montoya.proxy.MessageReceivedAction.CONTINUE, host.handler.handleRequestReceived((burp.api.montoya.proxy.http.InterceptedRequest) normal).action()); assertTrue(f.clock.workers.isEmpty());
            }
        }
        public @ParameterizedTest(name="[case=CORE.tag-failure.paused-{0}]") @ValueSource(booleans = {false, true})
        void actualReplaySendTraversesTheHooksOnceAndRejectedReplacementPausesBothRequestPolicies(boolean reject) throws Exception {
            // Main owns both header variants; this lab witness uses the formerly unmarked, absent-header case.
            boolean hasAgent=false;
            long began=System.nanoTime();Map<String,Object> paused=null;
            try (var f = new Fixture()) {
                var hostRef = new java.util.concurrent.atomic.AtomicReference<Host>();
                var deliveryFailure = new java.util.concurrent.atomic.AtomicReference<Throwable>();
                var delivered = new java.util.concurrent.CountDownLatch(1); var sends = new java.util.concurrent.atomic.AtomicInteger();
                try (var host = new Host(f, (marked, timeout) -> {
                    try {
                        assertEquals(60_000, timeout); var h = hostRef.get(); sends.incrementAndGet();
                        String raw = new String(marked.toByteArray().getBytes(), StandardCharsets.ISO_8859_1);
                        assertTrue(raw.contains("BPSHAuth/"));
                        var outgoing = h.handler.handleHttpRequestToBeSent(h.request(raw, 900, true));
                        assertEquals(burp.api.montoya.http.handler.RequestAction.CONTINUE, outgoing.action());
                        String wire = new String(outgoing.request().toByteArray().getBytes(), StandardCharsets.ISO_8859_1);
                        assertFalse(wire.contains("BPSHAuth/")); assertTrue(wire.contains("Bearer replacement-token"));
                        assertTrue(wire.endsWith("body=data")); assertTrue(wire.contains("Cookie: unrelated=keep")); assertEquals(hasAgent, wire.contains("User-Agent: application-agent")); assertEquals(hasAgent, wire.contains("User-Agent:"));
                        assertTrue(outgoing.annotations().notes().contains("request 50"));
                        var response = h.response(900, (short) (reject ? 401 : 200), null, new byte[0]);
                        var returned = h.handler.handleHttpResponseReceived(response);
                        assertSame(response, returned.response());
                        assertTrue(returned.annotations().notes().contains("request 50"), "The response callback must restore correlation even with fresh host annotations.");
                    } catch (Throwable failure) { deliveryFailure.set(failure); }
                    finally { delivered.countDown(); }
                })) {
                    hostRef.set(host); var entry = f.registry.snapshot().resolve("employee");
                    var rule = new Config.AutomaticRule(true, new Config.JourneySelection(entry.identity().scope(), entry.identity().journeyId()), Config.UrlMode.ALL_REQUESTS, null,
                            new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null));
                    host.controls.set(new Config.Controls(true, List.of(rule), Config.Controls.defaults().tools(), 60_000, 60_000, 300_000, null, null));
                    f.coordinator.acquire(List.of(entry)); f.clock.runWorker();
                    String raw = "POST /protected HTTP/1.1\r\nHost: app.example\r\n" + (hasAgent ? "User-Agent: application-agent\r\n" : "") + "Authorization: Bearer stale\r\nCookie: unrelated=keep\r\nContent-Length: 9\r\n\r\nbody=data";
                    host.handler.handleHttpRequestToBeSent(host.request(raw, 50, true));
                    var original = host.response(50, (short) 401, null, new byte[0]);
                    var originalOutcome = host.handler.handleHttpResponseReceived(original); assertSame(original, originalOutcome.response());
                    String persistedOriginalNotes = originalOutcome.annotations().notes();
                    assertTrue(persistedOriginalNotes.contains("request 50"), "Original correlation must exist before the host copies the callback result.");
                    assertEquals(0, sends.get()); f.values.put("employee", "replacement-token"); f.clock.runWorker();
                    assertTrue(delivered.await(5, java.util.concurrent.TimeUnit.SECONDS)); assertNull(deliveryFailure.get());
                    assertEquals(1, sends.get()); assertEquals(2, f.attempts); assertTrue(originalOutcome.annotations().notes().contains("request 900"));
                    host.handler.handleHttpResponseReceived(original); assertEquals(1, sends.get());
                    if (reject) {
                        int attemptsBefore=f.attempts,sendsBefore=sends.get();
                        assertEquals(AuthenticationCoordinator.Phase.PAUSED, f.coordinator.status(entry.identity()).phase());
                        f.clock.advance(3_600_000); assertTrue(f.clock.workers.isEmpty());
                        var ordinary = host.request(raw, 51, true); var forwarded = host.handler.handleHttpRequestToBeSent(ordinary);
                        assertSame(ordinary, forwarded.request()); assertTrue(forwarded.annotations().notes().contains("paused"));
                        String source=raw.replace("Bearer stale","Bearer <@employee/>");var taggedRequest=host.request(source,52,true);var tagged = host.handler.handleHttpRequestToBeSent(taggedRequest);
                        assertEquals(burp.api.montoya.http.handler.RequestAction.DROP, tagged.action()); assertTrue(f.clock.workers.isEmpty());
                        assertNull(tagged.request());assertArrayEquals(wire(source),taggedRequest.toByteArray().getBytes());assertEquals(attemptsBefore,f.attempts);assertEquals(sendsBefore,sends.get());
                        paused=Map.of("cause",f.coordinator.status(entry.identity()).failure().reason().name(),"drop",tagged.action().name(),"sourceUnchanged",Arrays.equals(wire(source),taggedRequest.toByteArray().getBytes()),"noReplacement",tagged.request()==null,"extraAttemptsOnDrop",f.attempts-attemptsBefore,"waitingRequests",f.coordinator.capacity().waitingRequests(),"pendingWorkers",f.clock.workers.size(),"replaySends",sends.get()-sendsBefore);
                        var healthy = callback(f, () -> host.handler.handleHttpRequestToBeSent(host.request(raw.replace("Bearer stale", "Bearer <@admin/>"), 53, true)));
                        assertEquals(burp.api.montoya.http.handler.RequestAction.CONTINUE, healthy.action());
                    } else assertTrue(f.coordinator.status(entry.identity()).acceptedUse());
                }
            }
            if(paused!=null)tagFailureObservation("paused",paused,began);
        }

        public @Test void actualHostByteScanningSkipsLargeUntaggedUploadsAndStatusRecoveryNeverReadsLargeBodies() throws Exception {
            try (var f = new Fixture(); var host = new Host(f)) {
                var upload = host.request(header("existing") + "x".repeat(5 << 20), 1, false);
                assertSame(upload, host.handler.handleHttpRequestToBeSent(upload).request()); assertEquals(0, host.largeReads.get());
                f.coordinator.acquire(List.of(f.registry.snapshot().resolve("employee"))); f.clock.runWorker(); var token = f.coordinator.peek(f.registry.snapshot().resolve("employee").identity());
                host.controls.set(new Config.Controls(true, List.of(), Config.Controls.defaults().tools(), 60_000, 60_000, 300_000, null, null));
                host.recovery.record(2, List.of(new CredentialUse(token.identity(), token.version(), new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null))), false);
                host.handler.handleHttpResponseReceived(host.response(2, (short) 401, "application/octet-stream", new byte[5 << 20])); assertNull(f.coordinator.peek(token.identity())); assertEquals(0, host.largeReads.get()); assertEquals(0, host.bodyAccesses.get());
            }
        }
        public @Test void unsupportedHostReportsMinimumRequirementsBeforeRegisteringAnyAuthenticationHook() throws Exception {
            try (var f = new Fixture(); var host = new Host(f)) {
                host.supportsDrop = false; var tabs = new java.util.concurrent.atomic.AtomicInteger();
                var logger = host.stub(burp.api.montoya.logging.Logging.class, (m, a) -> { if (a.length > 0 && a[0] instanceof String text) host.logs.add(text); return null; });
                var ui = host.stub(burp.api.montoya.ui.UserInterface.class, (m, a) -> { if (m.getName().equals("registerSuiteTab")) tabs.incrementAndGet(); else throw new AssertionError("Unexpected unsupported-host UI action"); return null; });
                var extension = host.stub(burp.api.montoya.extension.Extension.class, (m, a) -> { assertEquals("setName", m.getName()); return null; });
                var api = host.stub(burp.api.montoya.MontoyaApi.class, (m, a) -> switch (m.getName()) { case "extension" -> extension; case "logging" -> logger; case "userInterface" -> ui; default -> throw new AssertionError("Unsupported host must not register or compose native authentication services"); });
                new Extension().initialize(api); javax.swing.SwingUtilities.invokeAndWait(() -> {});
                assertEquals(1, tabs.get()); assertTrue(host.logs.stream().anyMatch(s -> s.contains("no authentication hooks were registered"))); assertTrue(f.clock.workers.isEmpty());
            }
        }
        public @Test void attributedOversizedRegexBodyIsSkippedBeforeFetchingHostBodyBytes() throws Exception {
            try (var f = new Fixture(); var host = new Host(f)) {
                var entry = f.registry.snapshot().resolve("employee"); f.coordinator.acquire(List.of(entry)); f.clock.runWorker(); var token = f.coordinator.peek(entry.identity());
                host.recovery.record(1, List.of(new CredentialUse(token.identity(), token.version(), new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.REGEX, null, "sign in"))), false);
                host.handler.handleHttpResponseReceived(host.response(1, (short) 200, "text/html", new byte[65_537]));
                assertNotNull(f.coordinator.peek(token.identity())); assertEquals(0, host.largeReads.get()); assertEquals(0, host.bodyAccesses.get());
            }
        }
    }
}
