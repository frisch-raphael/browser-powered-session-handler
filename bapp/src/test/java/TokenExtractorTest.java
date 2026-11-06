import com.microsoft.playwright.options.Cookie;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises bounded extraction and classification without initializing a browser or native module. */
class TokenExtractorTest {
    static final Clock CLOCK = Clock.fixed(Instant.ofEpochSecond(2_000_000_000L), ZoneOffset.UTC);
    /** @param path Limited native JSON selector. @return Collector with deterministic wall time. */
    static TokenExtractor json(String path) { return new TokenExtractor(new JourneyDefinition.JsonExtraction(URI.create("https://login.example"), "/token", path), CLOCK); }
    /** @param value Controlled JSON fixture body. @return UTF-8 bytes for the production parser. */
    static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    /** @param payload Bounded JWT metadata fixture. @return Structurally JWT-shaped text without signature-validation claims. */
    static String jwt(String payload) { return "e30." + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes(payload)) + ".fixture-signature"; }

    @Test void exactOriginEncodedPathFilterExcludesQueryAndFragment() {
        var extractor = json("access_token");
        assertTrue(extractor.matchesJson("https://LOGIN.example:443/api/token?other=/ignore#fragment"));
        assertFalse(extractor.matchesJson("https://other.example/api/token")); assertFalse(extractor.matchesJson("http://login.example/api/token"));
        assertFalse(extractor.matchesJson("https://login.example:444/api/token")); assertFalse(extractor.matchesJson("https://login.example/other?path=/token"));
        assertFalse(extractor.matchesJson("https://login.example/%74oken")); assertFalse(extractor.matchesJson("not a URL"));
    }
    @ParameterizedTest @ValueSource(strings = {"data.tokens[0].value", "data.tokens.0.value"})
    void numericArraySegmentsAndBearerNormalizationAreRetained(String path) throws Exception {
        var extractor = json(path); extractor.considerJson(bytes("{\"data\":{\"tokens\":[{\"value\":\"  bEaReR normalized-token  \"}]}}"));
        assertEquals("normalized-token", extractor.result());
    }
    @Test void numericObjectKeysDifferFromBracketArrayIndices() throws Exception {
        var dotted = json("data.0.value"); dotted.considerJson(bytes("{\"data\":{\"0\":{\"value\":\"object-token\"}}}")); assertEquals("object-token", dotted.result());
        var bracket = json("data[0].value"); bracket.considerJson(bytes("{\"data\":{\"0\":{\"value\":\"object-token\"}}}")); assertThrows(AuthenticationFailure.class, bracket::result);
        var root = json("[0].value"); root.considerJson(bytes("[{\"value\":\"array-token\"}]")); assertEquals("array-token", root.result());
    }
    @Test void malformedCandidateCanBeSupersededButNeverOverwritesTheFirstValidString() throws Exception {
        var extractor = json("access_token"); extractor.considerJson(bytes("not JSON fixture-secret"));
        var error = assertThrows(AuthenticationFailure.class, extractor::result); assertFalse(error.getMessage().contains("fixture-secret")); assertNull(error.getCause());
        extractor.considerJson(bytes("{\"access_token\":\"first\"}")); extractor.considerJson(bytes("{\"access_token\":\"second\"}")); assertEquals("first", extractor.result());
    }
    @Test void duplicateKeysWrongTypesMissingPathsAndMalformedUtf8FailSafely() {
        for (byte[] data : List.of(bytes("{\"access_token\":\"a\",\"access_token\":\"b\"}"), bytes("{\"access_token\":7}"), bytes("{}"), new byte[]{(byte) 0xc3, 0x28})) {
            var extractor = json("access_token"); extractor.considerJson(data); assertEquals(AuthenticationFailure.Cause.EXTRACTION, assertThrows(AuthenticationFailure.class, extractor::result).reason());
        }
    }
    @Test void boundsApplyBeforeJsonParsingAndBeforeTokenPublication() throws Exception {
        assertDoesNotThrow(() -> TokenExtractor.checkDeclaredLength("1048576")); assertDoesNotThrow(() -> TokenExtractor.checkDeclaredLength(null));
        for (String length : List.of("1048577", "-1", "1.5", "not-a-length", "999999999999999999999")) assertThrows(AuthenticationFailure.class, () -> TokenExtractor.checkDeclaredLength(length));
        var extractor = json("access_token"); extractor.considerJson(new byte[TokenExtractor.MAX_JSON_BYTES + 1]); assertThrows(AuthenticationFailure.class, extractor::result);
        assertEquals(65_536, TokenExtractor.normalize("a".repeat(65_536), CLOCK).length());
        for (String value : List.of("a".repeat(65_537), "é".repeat(32_769), "Bearer ", "token\r\nInjected: value", "a\0b", "a\tb"))
            assertThrows(AuthenticationFailure.class, () -> TokenExtractor.normalize(value, CLOCK));
    }
    @Test void httpErrorBodiesDoNotInventMalformedTokenCausesButActualInvalidCandidatesRemainErrors() throws Exception {
        var extractor = json("access_token");
        extractor.observe(new AuthenticationFailure(AuthenticationFailure.Phase.NAVIGATION, AuthenticationFailure.Cause.TEMPORARY_SERVICE, "HTTP 503.", "Retry."));
        extractor.considerJson(bytes("{}"), false); extractor.considerJson(bytes("error page"), false);
        assertEquals(AuthenticationFailure.Cause.TEMPORARY_SERVICE, assertThrows(AuthenticationFailure.class, extractor::result).reason());
        extractor.considerJson(bytes("{\"access_token\":null}"), false); assertEquals(AuthenticationFailure.Cause.EXTRACTION, assertThrows(AuthenticationFailure.class, extractor::result).reason());
    }
    @Test void cookieSelectionRequiresApplicabilityAndUnambiguousIdentity() throws Exception {
        var extraction = new JourneyDefinition.CookieExtraction(URI.create("https://app.example/"), "session", null, null);
        Cookie first = new Cookie("session", "first").setDomain("app.example").setPath("/");
        Cookie second = new Cookie("session", "second").setDomain(".example").setPath("/");
        var ambiguous = new TokenExtractor(extraction, CLOCK); ambiguous.considerCookies(List.of(first, second)); assertThrows(AuthenticationFailure.class, ambiguous::result);
        var exact = new TokenExtractor(new JourneyDefinition.CookieExtraction(extraction.originUrl(), "session", "app.example", "/"), CLOCK);
        exact.considerCookies(List.of(first, second)); assertEquals("first", exact.result());
        var absent = new TokenExtractor(extraction, CLOCK); absent.considerCookies(List.of(new Cookie("session", "old").setDomain("app.example").setPath("/").setExpires(1))); assertThrows(AuthenticationFailure.class, absent::result);
    }
    @Test void expiryMetadataIsNotSignatureValidationAndIsRecheckedAtCompletion() throws Exception {
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
    @Test void onlyPositiveMainFrameSymbolsAreTemporaryAndRetryAfterCannotInventMoreBudget() {
        assertTrue(BrowserFlowRunner.networkFailure("net::ERR_CONNECTION_RESET").retryable()); assertNull(BrowserFlowRunner.networkFailure("selector includes ERR_CONNECTION_RESET"));
        assertFalse(BrowserFlowRunner.networkFailure("net::ERR_CERT_AUTHORITY_INVALID").retryable()); assertNull(BrowserFlowRunner.networkFailure("generic handshake failure"));
        assertEquals(CLOCK.instant().plusSeconds(7), BrowserFlowRunner.retryAfter("7", CLOCK.instant()));
        assertNull(BrowserFlowRunner.retryAfter("-1", CLOCK.instant())); assertNull(BrowserFlowRunner.retryAfter("garbage", CLOCK.instant()));
    }
}
