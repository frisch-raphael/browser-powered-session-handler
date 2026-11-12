package bpsh.burp.http;

import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.JourneyKey;
import bpsh.request.RequestSettings;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Verifies atomic, nonblocking admission and complete release across callback stages. */
class RequestCapacityTest {
    @Test void defaultsAreFiniteAndPerJourneyRefusalDoesNotLeakGlobalCapacity() throws Exception {
        assertEquals(64, RequestSettings.Controls.defaults().maxWaitingRequestsGlobal());
        assertEquals(16, RequestSettings.Controls.defaults().maxWaitingRequestsPerJourney());
        var cfg = new RequestSettings.Controls(false, List.of(), List.of(), 60000, 60000, 300000, 2, 1);
        var a = new JourneyKey(JourneyDefinition.Scope.PROJECT, UUID.randomUUID());
        var b = new JourneyKey(JourneyDefinition.Scope.PROJECT, UUID.randomUUID());
        var capacity = new RequestCapacity();
        try (var first = capacity.admit(cfg, List.of(a), 1)) {
            assertEquals(AuthenticationFailure.Cause.CAPACITY, assertThrows(AuthenticationFailure.class, () -> capacity.admit(cfg, List.of(a), 1)).reason());
            try (var second = capacity.admit(cfg, List.of(), 1)) {
                assertThrows(AuthenticationFailure.class, () -> second.bind(List.of(b, a)));
                second.bind(List.of(b)); second.bind(List.of(b));
                assertThrows(AuthenticationFailure.class, () -> capacity.admit(cfg, List.of(), 1));
            }
            try (var released = capacity.admit(cfg, List.of(b), 1)) { released.close(); }
        }
        assertThrows(AuthenticationFailure.class, () -> capacity.admit(cfg, List.of(), Long.MAX_VALUE));
        try (var allMemory = capacity.admit(cfg, List.of(a), 512L << 20)) {
            assertThrows(AuthenticationFailure.class, () -> capacity.admit(cfg, List.of(b), 1));
        }
        try (var released = capacity.admit(cfg, List.of(a), 512L << 20)) { assertNotNull(released); }
    }
}
