import org.junit.jupiter.api.Test;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import static org.junit.jupiter.api.Assertions.*;

/** Covers boundary extraction and complete request edits through the production coordinator/resolver. */
class RegexInjectionTest {
    static final JourneyDefinition.RegexExtraction REGEX = new JourneyDefinition.RegexExtraction(URI.create("https://login.example"), "/page", "<token[^>]*>", "</token>");
    static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }

    @Test void regexUsesFirstStartAndNextEndWithoutCapturingDelimitersOrLaterValues() throws Exception {
        var extractor = new TokenExtractor(REGEX, TokenExtractorTest.CLOCK);
        assertTrue(extractor.matchesResponse("https://LOGIN.example:443/page?x=1"));
        for (String url : List.of("https://other.example/page", "https://login.example/other?path=/page", "http://login.example/page", "bad-url")) {
            extractor.considerResponse(url, bytes("<token>wrong</token>"), true); assertFalse(extractor.hasToken());
        }
        extractor.considerResponse("https://login.example/page", bytes("before<token id='a'> first-value </token><token>second</token>after"), true);
        assertEquals("first-value", extractor.result());
        extractor.considerResponse("https://login.example/page", bytes("<token>replacement</token>"), true);
        assertEquals("first-value", extractor.result());
    }

    @Test void missingAndEmptyBoundariesWaitForAnotherResponseAndInvalidBodiesNeverLeak() throws Exception {
        for(String point:List.of("below","at","above")) {
            long began=System.nanoTime();int limit=4096,value=limit+(point.equals("below")?-1:point.equals("above")?1:0);boolean accepted=!point.equals("above"),matches=false;String cause="NONE",source="a".repeat(value);
            if(accepted){matches=TokenExtractor.compileRegex(source).matcher(source).matches();assertTrue(matches);}
            else{cause=assertThrows(AuthenticationFailure.class,()->TokenExtractor.compileRegex(source)).reason().name();assertEquals("EXTRACTION",cause);}
            NativeTagPipelineTest.limitObservation("regex_source_bytes",point,NativeTagPipelineTest.limitFacts("regex_source_bytes",point,value,limit,accepted,matches,cause,0,true,0,0),began);
        }
        var extractor = new TokenExtractor(REGEX, TokenExtractorTest.CLOCK);
        for (String body : List.of("no pair", "<token>missing end", "</token>wrong order", "<token></token>")) {
            extractor.considerResponse("https://login.example/page", bytes(body), true); assertFalse(extractor.hasToken());
        }
        extractor.considerResponse("https://login.example/page", bytes("<token>fixture-secret\r\nInjected: x</token>"), true);
        assertFalse(assertThrows(AuthenticationFailure.class, extractor::result).getMessage().contains("fixture-secret"));
        extractor.considerResponse("https://login.example/page", new byte[]{(byte) 0xc3, 0x28}, true);
        assertThrows(AuthenticationFailure.class, extractor::result);
        extractor.considerResponse("https://login.example/page", new byte[TokenExtractor.MAX_JSON_BYTES + 1], true);
        assertThrows(AuthenticationFailure.class, extractor::result);
        extractor.considerResponse("https://login.example/page", bytes("<token>fresh</token>"), true); assertEquals("fresh", extractor.result());
        for (String pattern : List.of("", "(?<=secret)", "(a)\\1", "a".repeat(4097))) {
            var error = assertThrows(AuthenticationFailure.class, () -> TokenExtractor.compileRegex(pattern));
            assertFalse(error.getMessage().contains("secret"));
        }
        var multiline = new TokenExtractor(new JourneyDefinition.RegexExtraction(REGEX.responseOrigin(), REGEX.pathSubstring(), "begin.*boundary:", ":end"), TokenExtractorTest.CLOCK);
        multiline.considerResponse("https://login.example/page", bytes("begin\nother\nboundary:value:end"), true); assertEquals("value", multiline.result());
    }

    static JourneyDefinition.CombinedExtraction sources() {
        return new JourneyDefinition.CombinedExtraction(List.of(
                new JourneyDefinition.NamedExtraction("access", CombinedCredentialsTest.JSON),
                new JourneyDefinition.NamedExtraction("csrf", REGEX),
                new JourneyDefinition.NamedExtraction("cookievalue", REGEX),
                new JourneyDefinition.NamedExtraction("refresh", REGEX),
                new JourneyDefinition.NamedExtraction("session", CombinedCredentialsTest.COOKIE),
                new JourneyDefinition.NamedExtraction("tenant", new JourneyDefinition.CookieExtraction(URI.create("https://app.example/"), "tenant", null, null))));
    }
    static JourneyDefinition.Injection mappings() {
        return JourneyDefinition.Injection.perToken(List.of(
                new JourneyDefinition.TokenInjection("access", JourneyDefinition.InjectionType.BEARER, null),
                new JourneyDefinition.TokenInjection("csrf", JourneyDefinition.InjectionType.HEADER, "X-CSRF-Token"),
                new JourneyDefinition.TokenInjection("cookievalue", JourneyDefinition.InjectionType.COOKIE, "csrf"),
                new JourneyDefinition.TokenInjection("refresh", JourneyDefinition.InjectionType.DISABLED, null)));
    }
    static String configured(JourneyDefinition.Extraction extraction, JourneyDefinition.Injection injection) throws Exception {
        String value = JourneyRegistryTest.edit(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT, false, false), "/journeys/0", "extraction", ConfigManager.extractionNode(extraction));
        return JourneyRegistryTest.edit(value, "/journeys/0", "injection", ConfigManager.injectionNode(injection));
    }

    @Test void namedJsonRegexAndCookieDestinationsRoundTripAndInjectAtomically() throws Exception {
        try (var parsed = ConfigManager.parseNative(configured(sources(), mappings()), ConfigManager.DocumentKind.PROJECT);
             var roundTrip = ConfigManager.parseNative(ConfigManager.nativeToJson(parsed), parsed.kind()); var secrets = new SecretStore()) {
            assertEquals(sources(), roundTrip.journeys().getFirst().extraction());
            assertEquals(mappings(), roundTrip.journeys().getFirst().injection());
            var registry = new JourneyRegistry(secrets); registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, roundTrip);
            var clock = new CoordinatorFixtures.ManualRuntime();
            try (var coordinator = new AuthenticationCoordinator(registry, Config.Controls.defaults(), clock, (entry, recovery, deadline, cancelled) ->
                    new BrowserFlowRunner.Outcome(entry.identity(), "access-value", clock.instant(), clock.nanos(), Map.of("sid", "session-value", "tenant", "tenant-value"), Map.of("access", "access-value", "csrf", "csrf-value", "cookievalue", "cookie-value", "refresh", "refresh-value", "session", "session-value", "tenant", "tenant-value"), OptionalLong.empty()), entry -> null)) {
                var resolver = new NativeTagResolver(registry, coordinator); var entry = registry.snapshot().resolve("employee");
                var operation = resolver.resolve(bytes("POST / HTTP/1.1\r\nHost: app.example\r\nAuthorization: old\r\nX-CSRF-Token: old\r\nx-csrf-token: duplicate\r\nCookie: sid=old; csrf=old; keep=yes\r\nCookie: sid=duplicate\r\nContent-Length: 4\r\n\r\nbody"), entry, true); clock.runWorker();
                String request = new String(operation.future().join().commit(), StandardCharsets.UTF_8);
                assertTrue(request.contains("Authorization: Bearer access-value\r\n"));
                assertTrue(request.contains("X-CSRF-Token: csrf-value\r\n"));
                assertTrue(request.contains("sid=session-value")); assertTrue(request.contains("tenant=tenant-value")); assertTrue(request.contains("csrf=cookie-value")); assertTrue(request.contains("keep=yes"));
                assertFalse(request.contains("old")); assertFalse(request.contains("duplicate")); assertFalse(request.contains("refresh-value"));
                assertTrue(request.endsWith("Content-Length: 4\r\n\r\nbody"));
                var tagged = resolver.resolve(bytes("GET / HTTP/1.1\r\nHost: app.example\r\nX-Refresh: <@employee token=\"refresh\"/>\r\n\r\n"), null, false);
                String explicit = new String(tagged.future().join().commit(), StandardCharsets.UTF_8);
                assertTrue(explicit.contains("X-Refresh: refresh-value")); assertFalse(explicit.contains("Authorization:")); assertFalse(explicit.contains("Cookie:"));
            }
        }
    }

    @Test void invalidCookieDestinationValueNeverCommitsAnEarlierHeaderEdit() throws Exception {
        try (var parsed = ConfigManager.parseNative(configured(sources(), mappings()), ConfigManager.DocumentKind.PROJECT); var secrets = new SecretStore()) {
            var registry = new JourneyRegistry(secrets); registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, parsed); var clock = new CoordinatorFixtures.ManualRuntime();
            try (var coordinator = new AuthenticationCoordinator(registry, Config.Controls.defaults(), clock, (entry, recovery, deadline, cancelled) ->
                    new BrowserFlowRunner.Outcome(entry.identity(), "access-value", clock.instant(), clock.nanos(), Map.of("sid", "session-value", "tenant", "tenant-value"), Map.of("access", "access-value", "csrf", "csrf-value", "cookievalue", "invalid;cookie", "refresh", "refresh-value", "session", "session-value", "tenant", "tenant-value"), OptionalLong.empty()), entry -> null)) {
                byte[] original = bytes("GET / HTTP/1.1\r\nHost: app.example\r\nAuthorization: original\r\n\r\n"), copy = original.clone();
                var operation = new NativeTagResolver(registry, coordinator).resolve(original, registry.snapshot().resolve("employee"), true); clock.runWorker();
                assertThrows(java.util.concurrent.CompletionException.class, () -> operation.future().join());
                assertArrayEquals(copy, original);
            }
        }
    }

    @Test void singleJsonAndRegexSupportEveryDestinationAndSingleCookieUsesOriginalName() throws Exception {
        for (var extraction : List.of(CombinedCredentialsTest.JSON, REGEX, CombinedCredentialsTest.COOKIE)) {
            for (var mode : List.of(JourneyDefinition.InjectionType.BEARER, JourneyDefinition.InjectionType.HEADER, JourneyDefinition.InjectionType.COOKIE, JourneyDefinition.InjectionType.DISABLED)) {
                var mapping = JourneyDefinition.Injection.perToken(extraction instanceof JourneyDefinition.CookieExtraction ? List.of() : List.of(new JourneyDefinition.TokenInjection(null, mode, mode == JourneyDefinition.InjectionType.HEADER ? "X-Token" : mode == JourneyDefinition.InjectionType.COOKIE ? "custom" : null)));
                try (var parsed = ConfigManager.parseNative(configured(extraction, mapping), ConfigManager.DocumentKind.PROJECT); var secrets = new SecretStore()) {
                    var registry = new JourneyRegistry(secrets); registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, parsed); var clock = new CoordinatorFixtures.ManualRuntime();
                    try (var coordinator = new AuthenticationCoordinator(registry, Config.Controls.defaults(), clock, (entry, recovery, deadline, cancelled) -> new BrowserFlowRunner.Outcome(entry.identity(), "value", clock.instant(), clock.nanos()), entry -> null)) {
                        var operation = new NativeTagResolver(registry, coordinator).resolve(bytes("GET / HTTP/1.1\r\nHost: app.example\r\n\r\n"), registry.snapshot().resolve("employee"), true); clock.runWorker();
                        String request = new String(operation.future().join().commit(), StandardCharsets.UTF_8);
                        String expected = extraction instanceof JourneyDefinition.CookieExtraction ? "Cookie: sid=value" : switch (mode) { case BEARER -> "Authorization: Bearer value"; case HEADER -> "X-Token: value"; case COOKIE -> "Cookie: custom=value"; default -> "Host: app.example"; };
                        assertTrue(request.contains(expected));
                        if (!(extraction instanceof JourneyDefinition.CookieExtraction) && mode == JourneyDefinition.InjectionType.DISABLED) assertEquals("GET / HTTP/1.1\r\nHost: app.example\r\n\r\n", request);
                    }
                }
            }
        }
    }

    @Test void conflictingMissingUnknownAndInvalidDestinationsAreRejected() throws Exception {
        for (var replacement : List.of(
                new JourneyDefinition.TokenInjection("csrf", JourneyDefinition.InjectionType.HEADER, "authorization"),
                new JourneyDefinition.TokenInjection("csrf", JourneyDefinition.InjectionType.BEARER, null),
                new JourneyDefinition.TokenInjection("csrf", JourneyDefinition.InjectionType.COOKIE, "sid"),
                new JourneyDefinition.TokenInjection("csrf", JourneyDefinition.InjectionType.COOKIE, "csrf"),
                new JourneyDefinition.TokenInjection("csrf", JourneyDefinition.InjectionType.HEADER, "Bad\r\nName"),
                new JourneyDefinition.TokenInjection("csrf", JourneyDefinition.InjectionType.HEADER, "Cookie"),
                new JourneyDefinition.TokenInjection("unknown", JourneyDefinition.InjectionType.DISABLED, null),
                new JourneyDefinition.TokenInjection("access", JourneyDefinition.InjectionType.DISABLED, null),
                new JourneyDefinition.TokenInjection("session", JourneyDefinition.InjectionType.DISABLED, null))) {
            var tokens = new java.util.ArrayList<>(mappings().tokens()); tokens.set(1, replacement);
            String value = configured(sources(), JourneyDefinition.Injection.perToken(tokens));
            assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.parseNative(value, ConfigManager.DocumentKind.PROJECT));
        }
        String missing = configured(sources(), JourneyDefinition.Injection.perToken(List.of()));
        assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.parseNative(missing, ConfigManager.DocumentKind.PROJECT));
        var invalid = new JourneyDefinition.RegexExtraction(REGEX.responseOrigin(), REGEX.pathSubstring(), "(?<=fixture-secret)", "end");
        String value = configured(invalid, JourneyDefinition.Injection.perToken(List.of(new JourneyDefinition.TokenInjection(null, JourneyDefinition.InjectionType.DISABLED, null))));
        var error = assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.parseNative(value, ConfigManager.DocumentKind.PROJECT));
        assertTrue(error.getMessage().contains("startRegex")); assertFalse(error.getMessage().contains("fixture-secret"));
    }
}
