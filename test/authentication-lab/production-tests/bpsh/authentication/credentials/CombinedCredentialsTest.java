package bpsh.authentication.credentials;

import bpsh.journey.persistence.JourneyDocument;
import bpsh.journey.persistence.JourneyJson;

import bpsh.request.RequestSettings;
import bpsh.journey.persistence.ProjectStore;
import bpsh.journey.editing.JourneyWorkspace;
import bpsh.burp.http.NativeTagPipelineTest;
import bpsh.burp.http.NativeTagResolver;
import bpsh.burp.http.SessionRecovery;
import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.ConfigurationException;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.SecretStore;
import bpsh.authentication.session.AuthenticationCoordinator;
import bpsh.authentication.session.AuthenticationCoordinatorTest;
import bpsh.authentication.session.CoordinatorFixtures;
import bpsh.support.AuthLabSupport;
import bpsh.burp.ui.JourneyRegistryTest;
import bpsh.authentication.credentials.CapturedCookie;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.concurrent.CompletionException;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Verifies complete named credential acquisition and atomic insertion without a native device. */
public class CombinedCredentialsTest {
    public static final JourneyDefinition.JsonExtraction JSON = new JourneyDefinition.JsonExtraction(URI.create("https://login.example"), "/token", "access_token");
    public static final JourneyDefinition.CookieExtraction COOKIE = new JourneyDefinition.CookieExtraction(URI.create("https://app.example/"), "sid", null, null);
    public static final JourneyDefinition.CombinedExtraction SOURCES = new JourneyDefinition.CombinedExtraction(List.of(new JourneyDefinition.NamedExtraction("access", JSON), new JourneyDefinition.NamedExtraction("session", COOKIE)));
    public static final JourneyDefinition.Injection INJECTION = JourneyDefinition.Injection.perToken(List.of(new JourneyDefinition.TokenInjection("access", JourneyDefinition.InjectionType.BEARER, null)));

    public @Test void namedSourcesAndBothRecoveryRoundTripAndRejectDuplicateNames() {
        String base = JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false);
        try {
            String value = JourneyRegistryTest.edit(base, "/journeys/0", "extraction", JourneyJson.extractionNode(SOURCES));
            value = JourneyRegistryTest.edit(value, "/journeys/0", "injection", JourneyJson.injectionNode(INJECTION));
            try (var parsed = JourneyJson.read(value, JourneyDocument.DocumentKind.PROJECT); var roundTrip = JourneyJson.read(JourneyJson.write(parsed), parsed.kind())) {
                assertEquals(SOURCES, roundTrip.journeys().getFirst().extraction());
            }
            String duplicate = value.replace("\"session\"", "\"access\"");
            assertTrue(assertThrows(ConfigurationException.class, () -> JourneyJson.read(duplicate, JourneyDocument.DocumentKind.PROJECT)).getMessage().contains("unique"));
        } catch (Exception ex) { throw new AssertionError(ex); }
    }

    public @org.junit.jupiter.api.TestFactory java.util.stream.Stream<org.junit.jupiter.api.DynamicTest> everySourceMustArriveAndJsonResponsesAreRoutedToTheirOwnSelectors() {
        return List.of("token-before-cookie","cookie-before-token","missing-member","one-member-expired").stream().map(variant->org.junit.jupiter.api.DynamicTest.dynamicTest("[case=CORE.outputs."+variant+"]",()->combinedArrival(variant)));
    }
    private void combinedArrival(String variant) throws Exception {
        long began=System.nanoTime();var order=new java.util.ArrayList<String>();var incomplete=new java.util.ArrayList<Boolean>();
        var second = new JourneyDefinition.JsonExtraction(URI.create("https://other.example"), "/other", "value");
        var definition = new JourneyDefinition.CombinedExtraction(List.of(new JourneyDefinition.NamedExtraction("access", JSON), new JourneyDefinition.NamedExtraction("other", second), new JourneyDefinition.NamedExtraction("session", COOKIE)));
        var runtime=new CoordinatorFixtures.ManualRuntime();Clock clock=new Clock(){public java.time.ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(java.time.ZoneId zone){return Clock.fixed(instant(),zone);}public Instant instant(){return runtime.instant();}};
        var extractor = new TokenExtractor(definition, clock);
        CapturedCookie cookie = new bpsh.authentication.credentials.CapturedCookie("sid", "cookie-value", "app.example", "/", 2_000_000_020d);
        if(variant.equals("cookie-before-token")){extractor.collectCookies(url->{assertEquals("https://app.example/",url);return List.of(cookie);});order.add("session");incomplete.add(!extractor.hasToken());assertFalse(extractor.hasToken());}
        extractor.considerJson("https://login.example/token", "{\"access_token\":\"access-value\",\"value\":\"wrong-value\"}".getBytes(StandardCharsets.UTF_8), true);
        order.add("access");incomplete.add(!extractor.hasToken());assertFalse(extractor.hasToken());
        extractor.considerJson("https://other.example/other", "{\"value\":\"other-value\"}".getBytes(StandardCharsets.UTF_8), true);
        order.add("other");
        if(!variant.equals("cookie-before-token")){incomplete.add(!extractor.hasToken());assertFalse(extractor.hasToken());}
        if(!variant.equals("cookie-before-token")&&!variant.equals("missing-member")){extractor.collectCookies(url -> { assertEquals("https://app.example/", url); return List.of(cookie); });order.add("session");}
        boolean initiallyComplete=extractor.hasToken();
        if(variant.equals("one-member-expired")){assertTrue(initiallyComplete);runtime.advance(20_000);}
        if(variant.equals("missing-member")||variant.equals("one-member-expired")) {
            assertFalse(extractor.hasToken());var failure=assertThrows(AuthenticationFailure.class,extractor::result);
            var publication=publication(definition,extractor,runtime,false);assertFalse((boolean)publication.get("published"));
            var observed=new java.util.LinkedHashMap<String,Object>(publication);observed.put("arrivalOrder",order);observed.put("initiallyComplete",initiallyComplete);observed.put("finallyComplete",extractor.hasToken());observed.put("failureCause",failure.reason().name());
            output(variant,observed,began);return;
        }
        assertTrue(extractor.hasToken()); assertEquals("access-value", extractor.result());
        assertEquals(Map.of("access", "access-value", "other", "other-value", "session", "cookie-value"), extractor.namedValues());
        long acquiredExpiry=extractor.expirySeconds().orElseThrow();assertEquals(2_000_000_020L,acquiredExpiry);
        var publication=publication(definition,extractor,runtime,true);
        var lifetime = TokenLifetime.acquire(extractor.result(), new JourneyDefinition.Cache(1800, 10), clock.instant(), 100, extractor.expirySeconds());
        assertFalse(lifetime.usable(100, clock.instant().plusSeconds(20)));
        extractor.collectCookies(url -> List.of(new bpsh.authentication.credentials.CapturedCookie("sid", "rotated", "app.example", "/", null)));
        assertEquals("rotated", extractor.cookieValues().get("sid"));
        extractor.collectCookies(url -> List.of()); assertFalse(extractor.hasToken());
        var observed=new java.util.LinkedHashMap<String,Object>(publication);observed.put("arrivalOrder",order);observed.put("incompleteBeforeLastMember",incomplete);observed.put("expirySeconds",acquiredExpiry);observed.put("wholeSetExpiredAtBoundary",!lifetime.usable(100,clock.instant().plusSeconds(20)));observed.put("deletedCookieRemovesCompleteSet",!extractor.hasToken());
        output(variant,observed,began);if(variant.equals("token-before-cookie"))output("complete-set",observed,began);
    }
    private static Map<String,Object> publication(JourneyDefinition.CombinedExtraction definition,TokenExtractor extractor,CoordinatorFixtures.ManualRuntime runtime,boolean succeeds) throws Exception {
        Map<String,Object> observed;
        try(var secrets=new SecretStore()) {
            var registry=new JourneyWorkspace(secrets);var base=CoordinatorFixtures.journey("combined");
            var injection=JourneyDefinition.Injection.perToken(List.of(new JourneyDefinition.TokenInjection("access",JourneyDefinition.InjectionType.BEARER,null),new JourneyDefinition.TokenInjection("other",JourneyDefinition.InjectionType.DISABLED,null)));
            var journey=new JourneyDefinition(base.id(),base.displayName(),base.alias(),base.authenticationUrl(),false,base.steps(),base.browser(),definition,injection,base.cache(),null);CoordinatorFixtures.load(registry,List.of(journey));
            try(var coordinator=new AuthenticationCoordinator(registry,RequestSettings.Controls.defaults(),runtime,(entry,recovery,deadline,cancelled)->new AuthenticationResult(entry.identity(),extractor.result(),runtime.instant(),runtime.nanos(),extractor.cookieValues(),extractor.namedValues(),extractor.expirySeconds()),entry->null)) {
                var entry=registry.snapshot().resolve("combined");var ticket=coordinator.acquire(List.of(entry));assertNull(coordinator.peek(entry.identity()));runtime.runWorker();
                if(succeeds){var snapshot=ticket.future().join().get(entry.identity());assertEquals(entry.identity(),snapshot.identity());assertEquals(extractor.namedValues(),snapshot.namedTokens());assertEquals(extractor.cookieValues(),snapshot.cookies());observed=Map.of("published",true,"values",snapshot.namedTokens().size(),"sameIdentity",snapshot.identity().equals(entry.identity()),"namedValuesMatch",snapshot.namedTokens().equals(extractor.namedValues()),"cookiesMatch",snapshot.cookies().equals(extractor.cookieValues()),"waitingRequests",coordinator.capacity().waitingRequests());}
                else{assertThrows(CompletionException.class,()->ticket.future().join());assertNull(coordinator.peek(entry.identity()));observed=Map.of("published",coordinator.peek(entry.identity())!=null,"values",0,"sameIdentity",registry.snapshot().isCurrent(entry.identity()),"namedValuesMatch",false,"cookiesMatch",false,"waitingRequests",coordinator.capacity().waitingRequests());}
            }
        }
        return observed;
    }
    public static void output(String variant,Map<String,Object> observed,long began) throws Exception {AuthLabSupport.component("CORE.outputs."+variant,observed,Map.of("startupMs",0L,"caseMs",java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-began),"cleanupMs",0L));}

    public @org.junit.jupiter.params.ParameterizedTest(name="[case=CORE.tag-selection.named-{0}]")
    @org.junit.jupiter.params.provider.ValueSource(ints={2,3})
    void namedTagsShareOneLoginAndAutomaticInjectionAddsJsonAndAllCookies(int outputs) throws Exception {
        long began=System.nanoTime();Map<String,Object> observed,selectorFailure=null;
        try (var secrets = new SecretStore()) {
            var registry = new JourneyWorkspace(secrets); var base = CoordinatorFixtures.journey("employee");
            var sources=outputs==2?SOURCES:new JourneyDefinition.CombinedExtraction(List.of(new JourneyDefinition.NamedExtraction("access",JSON),new JourneyDefinition.NamedExtraction("session",COOKIE),new JourneyDefinition.NamedExtraction("other",JSON)));
            var injection=outputs==2?INJECTION:JourneyDefinition.Injection.perToken(List.of(new JourneyDefinition.TokenInjection("access",JourneyDefinition.InjectionType.BEARER,null),new JourneyDefinition.TokenInjection("other",JourneyDefinition.InjectionType.DISABLED,null)));
            var values=outputs==2?Map.of("access","access-value","session","cookie-value"):Map.of("access","access-value","session","cookie-value","other","other-value");
            var journey = new JourneyDefinition(base.id(), base.displayName(), base.alias(), base.authenticationUrl(), false, base.steps(), base.browser(), sources, injection, base.cache(), null);
            CoordinatorFixtures.load(registry, List.of(journey)); var clock = new CoordinatorFixtures.ManualRuntime(); var attempts = new java.util.concurrent.atomic.AtomicInteger();
            try (var coordinator = new AuthenticationCoordinator(registry, RequestSettings.Controls.defaults(), clock, (entry, recovery, deadline, cancelled) -> {
                attempts.incrementAndGet(); return new AuthenticationResult(entry.identity(), "access-value", clock.instant(), clock.nanos(), Map.of("sid", "cookie-value", "tenant", "tenant-value"), values, OptionalLong.empty());
            }, entry -> null)) {
                var resolver = new NativeTagResolver(registry, coordinator); var entry = registry.snapshot().resolve("employee");
                String raw = "GET / HTTP/1.1\r\nHost: app.example\r\nAuthorization: Bearer <@employee token=\"access\"/>\r\nCookie: sid=<@employee token=\"session\"/>\r\n\r\n";
                if(outputs==3)raw=raw.replace("\r\n\r\n","\r\nX-Other: <@employee token=\"other\"/>\r\n\r\n");
                var tagged = resolver.resolve(raw.getBytes(StandardCharsets.US_ASCII), null, false); clock.runWorker();
                String expanded = new String(tagged.future().join().commit(), StandardCharsets.US_ASCII);
                assertTrue(expanded.contains("Bearer access-value")); assertTrue(expanded.contains("sid=cookie-value")); assertEquals(1, attempts.get()); assertEquals(1, tagged.future().join().uses().size());
                String expected=raw.replace("<@employee token=\"access\"/>","access-value").replace("<@employee token=\"session\"/>","cookie-value").replace("<@employee token=\"other\"/>","other-value");assertEquals(expected,expanded);
                var snapshot=coordinator.peek(entry.identity());assertEquals(values,snapshot.namedTokens());assertEquals(snapshot.version(),tagged.future().join().uses().getFirst().version());
                var missing = resolver.resolve(raw.replace(" token=\"access\"", "").getBytes(StandardCharsets.US_ASCII), null, false);
                var missingFailure=assertThrows(CompletionException.class, () -> missing.future().join()).getCause();assertTrue(missingFailure.getMessage().contains("token="));
                if(outputs==2) {
                    String source=raw.replace(" token=\"access\"","");var hooks=new NativeTagPipelineTest().new ProductionHooks();var sends=new java.util.concurrent.atomic.AtomicInteger();int before=attempts.get();
                    try(var host=hooks.new Host(registry,resolver,coordinator,clock::nanos,(request,timeout)->sends.incrementAndGet())) {
                        var request=host.request(source,902,false);var action=host.handler.handleHttpRequestToBeSent(request);assertEquals(burp.api.montoya.http.handler.RequestAction.DROP,action.action());assertNull(action.request());assertArrayEquals(source.getBytes(StandardCharsets.US_ASCII),request.toByteArray().getBytes());assertEquals(before,attempts.get());assertEquals(0,sends.get());
                        selectorFailure=Map.of("cause",((AuthenticationFailure)missingFailure).reason().name(),"drop",action.action().name(),"sourceUnchanged",java.util.Arrays.equals(source.getBytes(StandardCharsets.US_ASCII),request.toByteArray().getBytes()),"noReplacement",action.request()==null,"extraAttemptsOnDrop",attempts.get()-before,"waitingRequests",coordinator.capacity().waitingRequests(),"pendingWorkers",clock.workers.size(),"replaySends",sends.get());
                    }
                }
                var unknown = resolver.resolve(raw.replace("token=\"access\"", "token=\"unknown\"").getBytes(StandardCharsets.US_ASCII), null, false);
                assertThrows(CompletionException.class, () -> unknown.future().join());
                var ordinary = resolver.resolve("GET / HTTP/1.1\r\nHost: app.example\r\nCookie: sid=old; unrelated=keep\r\nCookie: sid=duplicate\r\n\r\n".getBytes(StandardCharsets.US_ASCII), entry, true);
                String injected = new String(ordinary.future().join().commit(), StandardCharsets.US_ASCII);
                assertTrue(injected.contains("Authorization: Bearer access-value\r\n")); assertTrue(injected.contains("sid=cookie-value")); assertFalse(injected.contains("tenant=tenant-value")); assertTrue(injected.contains("unrelated=keep")); assertFalse(injected.contains("sid=old")); assertFalse(injected.contains("sid=duplicate")); assertEquals(1, attempts.get());
                assertFalse(injected.contains("other-value"));assertEquals(snapshot.version(),ordinary.future().join().uses().getFirst().version());assertEquals(0,coordinator.capacity().waitingRequests());
                observed=Map.of("outputs",outputs,"bytesMatch",expected.equals(expanded),"namedSnapshotMatches",values.equals(snapshot.namedTokens()),"sameVersion",snapshot.version()==ordinary.future().join().uses().getFirst().version(),"usedSnapshots",tagged.future().join().uses().size(),"attempts",attempts.get(),"unselectedCookieAbsent",!injected.contains("tenant=tenant-value"),"disabledOutputAbsent",!injected.contains("other-value"),"waitingRequests",coordinator.capacity().waitingRequests());
            }
        }
        AuthLabSupport.component("CORE.tag-selection."+(outputs==2?"two-outputs":"three-outputs"),observed,Map.of("startupMs",0L,"caseMs",java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-began),"cleanupMs",0L));
        if(selectorFailure!=null)NativeTagPipelineTest.tagFailureObservation("incomplete-selector",selectorFailure,began);
    }

    public @Test void eitherRecoveryConditionInvalidatesAndStatusMatchAvoidsReadingBody() {
        for (boolean status : List.of(true, false)) try (var f = new AuthenticationCoordinatorTest.Fixture(RequestSettings.Controls.defaults()); var recovery = new SessionRecovery(f.coordinator, f.clock::nanos)) {
            f.acquire(0); f.clock.runWorker(); var token = f.coordinator.peek(f.entry(0).identity());
            recovery.record(1, List.of(new CredentialUse(token.identity(), token.version(), new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.BOTH, 401, "session.*expired"))), false);
            byte[] body = "session expired".getBytes(StandardCharsets.UTF_8);
            assertEquals(1, recovery.received(1, status ? 401 : 200, () -> { assertFalse(status); return new SessionRecovery.Response(200, "text/plain", null, body.length, () -> new java.io.ByteArrayInputStream(body)); }, false));
        }
    }
    public @Test void severalJsonValuesRequireExplicitDestinationsAndInjectTheChosenValue() throws Exception {
        var sources = new JourneyDefinition.CombinedExtraction(List.of(new JourneyDefinition.NamedExtraction("first", JSON), new JourneyDefinition.NamedExtraction("second", JSON)));
        String value = JourneyRegistryTest.edit(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT, false, false), "/journeys/0", "extraction", JourneyJson.extractionNode(sources));
        String missing = value;
        assertTrue(assertThrows(ConfigurationException.class, () -> JourneyJson.read(missing, JourneyDocument.DocumentKind.PROJECT)).getMessage().contains("injection.tokens"));
        value = JourneyRegistryTest.edit(value, "/journeys/0", "injection", JourneyJson.injectionNode(JourneyDefinition.Injection.perToken(List.of(
                new JourneyDefinition.TokenInjection("first", JourneyDefinition.InjectionType.DISABLED, null),
                new JourneyDefinition.TokenInjection("second", JourneyDefinition.InjectionType.BEARER, null)))));
        try (var document = JourneyJson.read(value, JourneyDocument.DocumentKind.PROJECT); var secrets = new SecretStore()) {
            var registry = new JourneyWorkspace(secrets); registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, document); var clock = new CoordinatorFixtures.ManualRuntime();
            try (var coordinator = new AuthenticationCoordinator(registry, RequestSettings.Controls.defaults(), clock, (entry, recovery, deadline, cancelled) -> new AuthenticationResult(entry.identity(), "first-value", clock.instant(), clock.nanos(), Map.of(), Map.of("first", "first-value", "second", "second-value"), OptionalLong.empty()), entry -> null)) {
                var resolver = new NativeTagResolver(registry, coordinator);
                var operation = resolver.resolve("GET / HTTP/1.1\r\nHost: app.example\r\n\r\n".getBytes(StandardCharsets.US_ASCII), registry.snapshot().resolve("employee"), true); clock.runWorker();
                String request = new String(operation.future().join().commit(), StandardCharsets.US_ASCII);
                assertTrue(request.contains("Authorization: Bearer second-value\r\n")); assertFalse(request.contains("first-value"));
            }
        }
    }
}
