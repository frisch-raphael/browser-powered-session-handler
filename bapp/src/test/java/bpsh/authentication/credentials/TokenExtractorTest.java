package bpsh.authentication.credentials;

import bpsh.browser.BrowserFailureClassifier;
import bpsh.journey.AuthStep;
import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.JourneyDefinition;
import bpsh.authentication.credentials.CapturedCookie;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises bounded extraction and classification without initializing a browser or native module. */
public class TokenExtractorTest {
    public static final Clock CLOCK = Clock.fixed(Instant.ofEpochSecond(2_000_000_000L), ZoneOffset.UTC);
    /** @param path Limited native JSON selector. @return Collector with deterministic wall time. */
    public static TokenExtractor json(String path) { return new TokenExtractor(new JourneyDefinition.JsonExtraction(URI.create("https://login.example"), "/token", path), CLOCK); }
    /** @param value Controlled JSON fixture body. @return UTF-8 bytes for the production parser. */
    public static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    /** @param payload Bounded JWT metadata fixture. @return Structurally JWT-shaped text without signature-validation claims. */
    public static String jwt(String payload) { return "e30." + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes(payload)) + ".fixture-signature"; }

    public @Test void exactOriginEncodedPathFilterExcludesQueryAndFragment() {
        var extractor = json("access_token");
        assertTrue(extractor.matchesJson("https://LOGIN.example:443/api/token?other=/ignore#fragment"));
        assertFalse(extractor.matchesJson("https://other.example/api/token")); assertFalse(extractor.matchesJson("http://login.example/api/token"));
        assertFalse(extractor.matchesJson("https://login.example:444/api/token")); assertFalse(extractor.matchesJson("https://login.example/other?path=/token"));
        assertFalse(extractor.matchesJson("https://login.example/%74oken")); assertFalse(extractor.matchesJson("not a URL"));
    }
    public @ParameterizedTest @ValueSource(strings = {"data.tokens[0].value", "data.tokens.0.value"})
    void numericArraySegmentsAndBearerNormalizationAreRetained(String path) throws Exception {
        var extractor = json(path); extractor.considerJson(bytes("{\"data\":{\"tokens\":[{\"value\":\"  bEaReR normalized-token  \"}]}}"));
        assertEquals("normalized-token", extractor.result());
    }
    public @Test void numericObjectKeysDifferFromBracketArrayIndices() throws Exception {
        var dotted = json("data.0.value"); dotted.considerJson(bytes("{\"data\":{\"0\":{\"value\":\"object-token\"}}}")); assertEquals("object-token", dotted.result());
        var bracket = json("data[0].value"); bracket.considerJson(bytes("{\"data\":{\"0\":{\"value\":\"object-token\"}}}")); assertThrows(AuthenticationFailure.class, bracket::result);
        var root = json("[0].value"); root.considerJson(bytes("[{\"value\":\"array-token\"}]")); assertEquals("array-token", root.result());
    }
    public @Test void malformedCandidateCanBeSupersededButNeverOverwritesTheFirstValidString() throws Exception {
        var extractor = json("access_token"); extractor.considerJson(bytes("not JSON fixture-secret"));
        var error = assertThrows(AuthenticationFailure.class, extractor::result); assertFalse(error.getMessage().contains("fixture-secret")); assertNull(error.getCause());
        extractor.considerJson(bytes("{\"access_token\":\"first\"}")); extractor.considerJson(bytes("{\"access_token\":\"second\"}")); assertEquals("first", extractor.result());
    }
    public @Test void duplicateKeysWrongTypesMissingPathsAndMalformedUtf8FailSafely() {
        for (byte[] data : List.of(bytes("{\"access_token\":\"a\",\"access_token\":\"b\"}"), bytes("{\"access_token\":7}"), bytes("{}"), new byte[]{(byte) 0xc3, 0x28})) {
            var extractor = json("access_token"); extractor.considerJson(data); assertEquals(AuthenticationFailure.Cause.EXTRACTION, assertThrows(AuthenticationFailure.class, extractor::result).reason());
        }
    }
    public @Test void boundsApplyBeforeJsonParsingAndBeforeTokenPublication() throws Exception {
        assertDoesNotThrow(() -> TokenExtractor.checkDeclaredLength("1048576")); assertDoesNotThrow(() -> TokenExtractor.checkDeclaredLength(null));
        for (String length : List.of("1048577", "-1", "1.5", "not-a-length", "999999999999999999999")) assertThrows(AuthenticationFailure.class, () -> TokenExtractor.checkDeclaredLength(length));
        var extractor = json("access_token"); extractor.considerJson(new byte[TokenExtractor.MAX_JSON_BYTES + 1]); assertThrows(AuthenticationFailure.class, extractor::result);
        assertEquals(65_536, TokenExtractor.normalize("a".repeat(65_536), CLOCK).length());
        for (String value : List.of("a".repeat(65_537), "é".repeat(32_769), "Bearer ", "token\r\nInjected: value", "a\0b", "a\tb"))
            assertThrows(AuthenticationFailure.class, () -> TokenExtractor.normalize(value, CLOCK));
    }
    public @Test void httpErrorBodiesDoNotInventMalformedTokenCausesButActualInvalidCandidatesRemainErrors() throws Exception {
        var extractor = json("access_token");
        extractor.observe(new AuthenticationFailure(AuthenticationFailure.Phase.NAVIGATION, AuthenticationFailure.Cause.TEMPORARY_SERVICE, "HTTP 503.", "Retry."));
        extractor.considerJson(bytes("{}"), false); extractor.considerJson(bytes("error page"), false);
        assertEquals(AuthenticationFailure.Cause.TEMPORARY_SERVICE, assertThrows(AuthenticationFailure.class, extractor::result).reason());
        extractor.considerJson(bytes("{\"access_token\":null}"), false); assertEquals(AuthenticationFailure.Cause.EXTRACTION, assertThrows(AuthenticationFailure.class, extractor::result).reason());
    }
    public @Test void cookieSelectionRequiresApplicabilityAndUnambiguousIdentity() throws Exception {
        var extraction = new JourneyDefinition.CookieExtraction(URI.create("https://app.example/"), "session", null, null);
        CapturedCookie first = new bpsh.authentication.credentials.CapturedCookie("session", "first", "app.example", "/", null);
        CapturedCookie second = new bpsh.authentication.credentials.CapturedCookie("session", "second", ".example", "/", null);
        var ambiguous = new TokenExtractor(extraction, CLOCK); ambiguous.considerCookies(List.of(first, second)); assertThrows(AuthenticationFailure.class, ambiguous::result);
        var exact = new TokenExtractor(new JourneyDefinition.CookieExtraction(extraction.originUrl(), "session", "app.example", "/"), CLOCK);
        exact.considerCookies(List.of(first, second)); assertEquals("first", exact.result());
        var absent = new TokenExtractor(extraction, CLOCK); absent.considerCookies(List.of(new bpsh.authentication.credentials.CapturedCookie("session", "old", "app.example", "/", 1d)));
        var missing = assertThrows(AuthenticationFailure.class, absent::result);
        assertTrue(missing.problem().contains("session"));
        assertEquals(AuthenticationFailure.Cause.EXTRACTION, missing.reason());
        assertFalse(missing.problem().contains("old")); assertFalse(missing.problem().contains("app.example"));
    }
    public @Test void incompleteCombinedOutputsKeepObservedFailuresAndCompleteOutputsSupersedeThem() throws Exception {
        var definition = new JourneyDefinition.CombinedExtraction(List.of(
                new JourneyDefinition.NamedExtraction("bearer", new JourneyDefinition.JsonExtraction(URI.create("https://login.example"), "/token", "access_token")),
                new JourneyDefinition.NamedExtraction("cookie", new JourneyDefinition.CookieExtraction(URI.create("https://app.example/"), "session", null, null))));
        var step = new AuthenticationFailure.Step(java.util.UUID.randomUUID(), 2, AuthStep.Type.WAIT_SELECTOR);
        var timeout = new AuthenticationFailure(AuthenticationFailure.Phase.STEP, AuthenticationFailure.Cause.STEP_TIMEOUT, "Step 2 timed out.").atStep(step);
        var connection = BrowserFailureClassifier.networkFailure("ERR_CONNECTION_REFUSED");
        for (var observed : List.of(timeout, connection)) for (boolean partial : List.of(false, true)) {
            var extractor = new TokenExtractor(definition, CLOCK);
            if (partial) extractor.considerJson("https://login.example/token", bytes("{\"access_token\":\"usable\"}"), true);
            extractor.observe(observed);
            var result = assertThrows(AuthenticationFailure.class, extractor::result);
            assertEquals(observed.phase(), result.phase()); assertEquals(observed.reason(), result.reason());
            assertEquals(observed.step(), result.step()); assertEquals(observed.input(), result.input());
            extractor.considerJson("https://login.example/token", bytes("{\"access_token\":\"usable\"}"), true);
            extractor.collectCookies(url -> List.of(new bpsh.authentication.credentials.CapturedCookie("session", "cookie-value", "app.example", "/", null)));
            assertEquals("usable", extractor.result());
        }
    }
    public @Test void expiryMetadataIsNotSignatureValidationAndIsRecheckedAtCompletion() throws Exception {
        assertEquals(AuthenticationFailure.Cause.TOKEN_EXPIRED, assertThrows(AuthenticationFailure.class, () -> TokenExtractor.normalize(jwt("{\"exp\":2000000000}"), CLOCK)).reason());
        assertEquals(2_000_000_001L, TokenExtractor.jwtExpiry(jwt("{\"exp\":2000000001}")).orElseThrow());
        assertTrue(TokenExtractor.jwtExpiry("opaque-token").isEmpty()); assertTrue(TokenExtractor.jwtExpiry(jwt("{\"exp\":\"2000000001\"}")).isEmpty());
        AtomicReference<Instant> now = new AtomicReference<>(CLOCK.instant());
        Clock moving = new Clock() {
            /** @return Fixed UTC fixture zone. */
            @Override public ZoneId getZone() { return ZoneOffset.UTC; }
            /** @param zone Requested zone. @return Same instant source with the requested fixed view. */
            @Override public Clock withZone(ZoneId zone) { return Clock.fixed(instant(), zone); }
            /** @return Current controlled fixture instant. */
            @Override public Instant instant() { return now.get(); }
        };
        var extractor = new TokenExtractor(new JourneyDefinition.JsonExtraction(URI.create("https://login.example"), "/token", "access_token"), moving);
        extractor.considerJson(bytes("{\"access_token\":\"" + jwt("{\"exp\":2000000001}") + "\"}")); assertTrue(extractor.hasToken());
        now.set(now.get().plusSeconds(1)); assertEquals(AuthenticationFailure.Cause.TOKEN_EXPIRED, assertThrows(AuthenticationFailure.class, extractor::result).reason());
    }
    public @Test void onlyPositiveMainFrameSymbolsAreTemporaryAndRetryAfterCannotInventMoreBudget() {
        assertTrue(BrowserFailureClassifier.networkFailure("net::ERR_CONNECTION_RESET").retryable()); assertNull(BrowserFailureClassifier.networkFailure("selector includes ERR_CONNECTION_RESET"));
        assertFalse(BrowserFailureClassifier.networkFailure("net::ERR_CERT_AUTHORITY_INVALID").retryable()); assertNull(BrowserFailureClassifier.networkFailure("generic handshake failure"));
        assertEquals(CLOCK.instant().plusSeconds(7), BrowserFailureClassifier.retryAfter("7", CLOCK.instant()));
        assertNull(BrowserFailureClassifier.retryAfter("-1", CLOCK.instant())); assertNull(BrowserFailureClassifier.retryAfter("garbage", CLOCK.instant()));
    }
}
