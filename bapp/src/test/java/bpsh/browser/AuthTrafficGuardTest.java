package bpsh.browser;

import bpsh.model.AuthenticationFailure;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Verifies marker ownership and separate bounded hook ledgers without invoking Burp factories. */
class AuthTrafficGuardTest {
    @Test void markerStrippingPreservesTheWholeAgentAndOverridesRemainOwned() throws Exception {
        try (var guard = new AuthTrafficGuard(); var lease = guard.begin()) {
            String base = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HeadlessChrome/156.0.8078.4 Safari/537.36  ";
            String marked = lease.decorate(base); assertEquals(marked, lease.decorate(marked));
            var decision = guard.classify(marked, AuthTrafficGuard.Family.GLOBAL, 17); assertEquals(AuthTrafficGuard.Classification.OWNED, decision.classification()); assertEquals(base, decision.userAgent());
            assertEquals("Custom-Agent/1", guard.classify(lease.decorate("Custom-Agent/1"), AuthTrafficGuard.Family.GLOBAL, 18).userAgent());
            assertFalse(lease.toString().contains("BPSHAuth/")); assertFalse(decision.toString().contains("Mozilla"));
            assertTrue(guard.consumeResponse(AuthTrafficGuard.Family.GLOBAL, 17)); assertFalse(guard.consumeResponse(AuthTrafficGuard.Family.GLOBAL, 17));
        }
    }
    @Test void replayLeaseDoesNotGrantAuthenticationTrafficInterceptionOrResponseExemption() throws Exception {
        try (var guard = new AuthTrafficGuard(); var lease = guard.beginReplay()) {
            String marked = lease.decorate("user-agent");
            var global = guard.classify(marked, AuthTrafficGuard.Family.GLOBAL, 12);
            var proxy = guard.classify(marked, AuthTrafficGuard.Family.PROXY, 12);
            assertNotNull(global.replayKey()); assertEquals(global.replayKey(), proxy.replayKey());
            assertFalse(guard.consumeResponse(AuthTrafficGuard.Family.GLOBAL, 12)); assertFalse(guard.consumeResponse(AuthTrafficGuard.Family.PROXY, 12));
            assertFalse(global.toString().contains(global.replayKey())); lease.close();
            assertEquals(AuthTrafficGuard.Classification.INVALID, guard.classify(marked, AuthTrafficGuard.Family.GLOBAL, 13).classification());
        }
    }
    @Test void unknownExpiredAmbiguousAndAnotherLeaseSuffixCannotEnterAuthentication() throws Exception {
        try (var guard = new AuthTrafficGuard(); var one = guard.begin(); var two = guard.begin()) {
            String marked = one.decorate("agent"); assertThrows(AuthenticationFailure.class, () -> two.decorate(marked));
            assertEquals(AuthTrafficGuard.Classification.INVALID, guard.classify(marked + " extra", AuthTrafficGuard.Family.GLOBAL, 1).classification());
            assertEquals(AuthTrafficGuard.Classification.INVALID, guard.classify(marked + " " + two.decorate(""), AuthTrafficGuard.Family.GLOBAL, 1).classification());
            one.close(); var stale = guard.classify(marked, AuthTrafficGuard.Family.GLOBAL, 1); assertEquals(AuthTrafficGuard.Classification.INVALID, stale.classification());
            assertFalse(stale.failure().getMessage().contains(marked)); assertTrue(stale.failure().recovery().contains("remove the BPSHAuth marker"));
            assertEquals(AuthTrafficGuard.Classification.INVALID, guard.classify("agent BPSHAuth/invalid", AuthTrafficGuard.Family.GLOBAL, 1).classification());
            assertEquals(AuthTrafficGuard.Classification.NORMAL, guard.classify("normal", AuthTrafficGuard.Family.GLOBAL, 1).classification());
        }
    }
    @Test void globalAndProxyLedgersAreIndependentAndKeepLateResponsesAfterLeaseCleanup() throws Exception {
        AtomicLong now = new AtomicLong(1000);
        try (var guard = new AuthTrafficGuard(now::get); var lease = guard.begin()) {
            String marked = lease.decorate("agent"); guard.classify(marked, AuthTrafficGuard.Family.PROXY, 7);
            assertFalse(guard.consumeResponse(AuthTrafficGuard.Family.GLOBAL, 7)); assertTrue(guard.consumeResponse(AuthTrafficGuard.Family.PROXY, 7));
            guard.classify(marked, AuthTrafficGuard.Family.GLOBAL, 8); lease.close(); assertTrue(guard.consumeResponse(AuthTrafficGuard.Family.GLOBAL, 8));
        }
    }
    @Test void ledgerExpiryRollbackAndCapacityBoundOnlyExtensionOwnedState() throws Exception {
        AtomicLong now = new AtomicLong(1000);
        try (var guard = new AuthTrafficGuard(now::get); var lease = guard.begin()) {
            String marked = lease.decorate("agent");
            for (int i = 0; i <= 10_000; i++) guard.classify(marked, AuthTrafficGuard.Family.GLOBAL, i);
            assertFalse(guard.consumeResponse(AuthTrafficGuard.Family.GLOBAL, 0)); assertTrue(guard.consumeResponse(AuthTrafficGuard.Family.GLOBAL, 10_000));
            now.addAndGet(300_000); assertFalse(guard.consumeResponse(AuthTrafficGuard.Family.GLOBAL, 1));
            guard.classify(marked, AuthTrafficGuard.Family.GLOBAL, 99); now.set(0); assertFalse(guard.consumeResponse(AuthTrafficGuard.Family.GLOBAL, 99));
        }
    }
    @Test void shutdownRevokesMarkersAndNativeSyntaxIsDetectedWithoutResolution() throws Exception {
        var guard = new AuthTrafficGuard(); var lease = guard.begin(); String marked = lease.decorate("agent"); guard.close();
        assertThrows(AuthenticationFailure.class, guard::begin); assertThrows(AuthenticationFailure.class, () -> lease.decorate("agent"));
        assertEquals(AuthTrafficGuard.Classification.INVALID, guard.classify(marked, AuthTrafficGuard.Family.GLOBAL, 1).classification());
        assertTrue(AuthTrafficGuard.containsNativeTag("Authorization: <@employee/>")); assertTrue(AuthTrafficGuard.containsNativeTag("<@url>literal</@url>"));
        assertFalse(AuthTrafficGuard.containsNativeTag(null)); lease.close();
    }
}
