import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

/** Checks clock movement and bounded metadata without sleeping or claiming JWT signature verification. */
class TokenLifetimeTest {
    final Instant now = Instant.ofEpochSecond(2_000_000_000L);
    /** @param payload Controlled untrusted JWT metadata. @return Structurally JWT-shaped fixture text. */
    static String jwt(String payload) { return "e30." + Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + ".signature"; }

    @Test void finiteAgeAppliesToOpaqueMalformedAndNonExpiringTokens() throws Exception {
        for (String token : new String[]{"opaque", "a.b.c", jwt("{}"), jwt("{\"exp\":\"tomorrow\"}"), jwt("{\"exp\":1.5}")}) {
            var window = TokenLifetime.acquire(token, new JourneyDefinition.Cache(5, 10), now, -100);
            assertTrue(window.usable(-100, now)); assertEquals(TimeUnit.MILLISECONDS.toNanos(2500), window.refreshNanos());
            assertFalse(window.usable(-100 + TimeUnit.SECONDS.toNanos(5), now.minusSeconds(1000)));
        }
    }
    @Test void jwtExpiryAndConfiguredAgeIndependentlyBoundLifetimeAndClockMovement() throws Exception {
        var window = TokenLifetime.acquire(jwt("{\"exp\":2000000020}"), new JourneyDefinition.Cache(1800, 10), now, 0);
        assertEquals(TimeUnit.SECONDS.toNanos(20), window.usableNanos()); assertEquals(TimeUnit.SECONDS.toNanos(10), window.refreshNanos());
        assertFalse(window.usable(0, now.plusSeconds(20))); assertFalse(window.usable(TimeUnit.SECONDS.toNanos(20), now.minusSeconds(100)));
        assertEquals(0, window.refreshDelay(TimeUnit.SECONDS.toNanos(1), now.plusSeconds(11)));
        assertEquals(TimeUnit.SECONDS.toNanos(9), window.refreshDelay(TimeUnit.SECONDS.toNanos(1), now.minusSeconds(100)));
    }
    @Test void boundaryExpiryAndFractionalWallTimeDoNotGrantAnExtraSecond() throws Exception {
        assertEquals(AuthenticationFailure.Cause.TOKEN_EXPIRED, assertThrows(AuthenticationFailure.class,
                () -> TokenLifetime.acquire(jwt("{\"exp\":2000000000}"), new JourneyDefinition.Cache(1800, 10), now, 0)).reason());
        var window = TokenLifetime.acquire(jwt("{\"exp\":2000000001}"), new JourneyDefinition.Cache(1800, 10), now.plusNanos(900_000_000), 0);
        assertEquals(100_000_000, window.usableNanos()); assertEquals(50_000_000, window.refreshNanos());
        var huge = TokenLifetime.acquire(jwt("{\"exp\":9223372036854775807}"), new JourneyDefinition.Cache(86400, 0), now, 0);
        assertEquals(TimeUnit.DAYS.toNanos(1), huge.usableNanos());
    }
}
