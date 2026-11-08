package bpsh.browser.mtls;

import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.JourneyDefinition;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** Establishes deterministic PIN outcomes using an empty software keystore, not hardware evidence. */
public class Pkcs11IdentityManagerTest {
    public @TempDir Path temp;
    /** @return Existing fake module path; injected NativeAccess never loads it as a library. */
    public JourneyDefinition.Mtls definition() throws Exception {
        Path module = temp.resolve("fake-module.dll"); if (!Files.exists(module)) Files.writeString(module, "not a native library");
        return new JourneyDefinition.Mtls(module.toString(), new JourneyDefinition.Slot(JourneyDefinition.SlotKind.INDEX, 0), "a".repeat(64), List.of(URI.create("https://localhost")), null);
    }
    /** @return Finite monotonic budget for a symbolic native operation. */
    public static long deadline() { return System.nanoTime() + TimeUnit.SECONDS.toNanos(5); }
    /** @return Empty JKS for deterministic successful login/enumeration without private key export. */
    public static KeyStore empty() throws Exception { var store = KeyStore.getInstance("JKS"); store.load(null, null); return store; }
    /** @return Unregistered unique test provider with no native services. */
    public static Provider provider() { return new Provider("BPSH-symbolic-" + UUID.randomUUID(), "1", "Disposable test boundary") {}; }
    /** @param action Poll condition. @throws Exception If native worker completion is not observed promptly. */
    public static void await(java.util.function.BooleanSupplier action) throws Exception {
        long end = deadline(); while (!action.getAsBoolean() && end - System.nanoTime() > 0) TimeUnit.MILLISECONDS.sleep(5); assertTrue(action.getAsBoolean());
    }

    public @Test void initializationDiagnosticsKeepKnownCauseWithoutNativeTextOrPinSubmission() throws Exception {
        for (String problem : List.of("CKR_SLOT_ID_INVALID", "CKR_GENERAL_ERROR", "Cryptoki unavailable.")) {
            var backend = new Pkcs11IdentityManager.NativeAccess() {
                @Override public Provider configure(Pkcs11IdentityManager.Device device) { throw new java.security.ProviderException("Initialization failed", new IllegalStateException(problem.equals("Cryptoki unavailable.") ? problem : problem + " private-native-detail")); }
                @Override public KeyStore load(Provider provider, char[] pin) { fail("Configuration failure must not submit a PIN"); return null; }
            };
            try (var manager = new Pkcs11IdentityManager(backend)) {
                var failure = assertThrows(AuthenticationFailure.class, () -> manager.listCertificates(definition(), "unit-pin".toCharArray(), false, deadline(), () -> false));
                assertEquals(AuthenticationFailure.Cause.CONFIGURATION, failure.reason());
                assertTrue(failure.problem().contains(problem.equals("Cryptoki unavailable.") ? "SunPKCS11" : problem));
                assertFalse(failure.getMessage().contains("private-native-detail")); assertFalse(failure.getMessage().contains("unit-pin"));
            }
        }
    }

    public @Test void outOfRangeSlotIndexExplainsTheSelectorWithoutSubmittingPin() throws Exception {
        var backend = new Pkcs11IdentityManager.NativeAccess() {
            @Override public Provider configure(Pkcs11IdentityManager.Device device) {
                throw new java.security.ProviderException("Initialization failed",
                        new java.security.ProviderException("slotListIndex is 1546920271 but token only has 2 slots"));
            }
            @Override public KeyStore load(Provider provider, char[] pin) { fail("An unavailable slot must not submit a PIN"); return null; }
        };
        try (var manager = new Pkcs11IdentityManager(backend)) {
            var failure = assertThrows(AuthenticationFailure.class,
                    () -> manager.listCertificates(definition(), "unit-pin".toCharArray(), false, deadline(), () -> false));
            assertEquals(AuthenticationFailure.Cause.CONFIGURATION, failure.reason());
            assertEquals("The saved security-device selection is no longer available.", failure.problem());
            assertTrue(failure.getMessage().contains("Refresh the security devices"));
            assertEquals(AuthenticationFailure.Input.SECURITY_DEVICE, failure.input().input());
            assertFalse(failure.getMessage().contains("1546920271"));
            assertFalse(failure.getMessage().contains("unit-pin"));
        }
    }

    public @Test void initializationFailuresDistinguishNativeLoadingAccessAndDeviceState() throws Exception {
        record Case(Throwable error, String explanation, String action) {}
        for (var item : List.of(
                new Case(new UnsatisfiedLinkError("private-native-path"), "load or link", "architecture"),
                new Case(new java.nio.file.AccessDeniedException("private-native-path"), "denied", "permissions"),
                new Case(new java.security.InvalidParameterException("private-native-path"), "configuration", "choose the certificate"),
                new Case(new IOException("CKR_TOKEN_NOT_PRESENT private-native-path"), "No token is present", "Connect the token"),
                new Case(new IOException("CKR_DEVICE_REMOVED private-native-path"), "disconnected", "Reconnect"),
                new Case(new IOException("CKR_TOKEN_NOT_RECOGNIZED private-native-path"), "does not recognize", "supports this token"))) {
            var backend = new Pkcs11IdentityManager.NativeAccess() {
                @Override public Provider configure(Pkcs11IdentityManager.Device device) throws Exception {
                    if (item.error() instanceof Error error) throw error;
                    throw new java.security.ProviderException("unit-pin", item.error());
                }
                @Override public KeyStore load(Provider provider, char[] pin) { fail("Initialization failure must not submit a PIN"); return null; }
            };
            try (var manager = new Pkcs11IdentityManager(backend)) {
                var failure = assertThrows(AuthenticationFailure.class, () -> manager.listCertificates(definition(), "unit-pin".toCharArray(), false, deadline(), () -> false));
                assertEquals(AuthenticationFailure.Phase.PROVIDER, failure.phase()); assertEquals(AuthenticationFailure.Cause.CONFIGURATION, failure.reason());
                assertTrue(failure.problem().contains(item.explanation()), failure.problem()); assertTrue(failure.recovery().contains(item.action()), failure.recovery());
                assertFalse(failure.getMessage().contains("private-native-path")); assertFalse(failure.getMessage().contains("unit-pin")); assertNull(failure.getCause());
                assertNull(manager.status(definition()).paused());
            }
        }
    }

    public @Test void loginFailuresGiveSpecificPinOrDeviceGuidanceAndRemainLatched() throws Exception {
        record Case(String code, String explanation, AuthenticationFailure.Cause reason) {}
        for (var item : List.of(
                new Case("CKR_PIN_LOCKED", "locked", AuthenticationFailure.Cause.PIN_REJECTED),
                new Case("CKR_PIN_EXPIRED", "expired", AuthenticationFailure.Cause.PIN_REJECTED),
                new Case("CKR_PIN_INCORRECT", "incorrect", AuthenticationFailure.Cause.PIN_REJECTED),
                new Case("CKR_TOKEN_NOT_PRESENT", "No token is present", AuthenticationFailure.Cause.PIN_INDETERMINATE),
                new Case("CKR_DEVICE_REMOVED", "disconnected", AuthenticationFailure.Cause.PIN_INDETERMINATE),
                new Case("UNKNOWN_CKR_PIN_INCORRECT_SUFFIX", "did not report", AuthenticationFailure.Cause.PIN_INDETERMINATE))) {
            AtomicInteger loads = new AtomicInteger();
            var backend = new Pkcs11IdentityManager.NativeAccess() {
                @Override public Provider configure(Pkcs11IdentityManager.Device device) { return provider(); }
                @Override public KeyStore load(Provider provider, char[] pin) throws Exception {
                    loads.incrementAndGet(); throw new IOException("private-native-detail unit-pin", new IOException(item.code()));
                }
            };
            try (var manager = new Pkcs11IdentityManager(backend)) {
                var definition = definition();
                for (int attempt = 0; attempt < 2; attempt++) {
                    var failure = assertThrows(AuthenticationFailure.class, () -> manager.listCertificates(definition, "unit-pin".toCharArray(), false, deadline(), () -> false));
                    assertEquals(AuthenticationFailure.Phase.PIN, failure.phase()); assertEquals(item.reason(), failure.reason());
                    assertTrue(failure.problem().contains(item.explanation()), failure.problem()); assertTrue(failure.recovery().contains("paused"));
                    assertFalse(failure.getMessage().contains("private-native-detail")); assertFalse(failure.getMessage().contains("unit-pin"));
                }
                assertEquals(1, loads.get()); assertEquals(item.reason(), manager.status(definition).paused());
            }
        }
    }

    public @Test void certificatePreparationFailureIsNotMisreportedAsInitializationOrPinRejection() throws Exception {
        var backend = new Pkcs11IdentityManager.NativeAccess() {
            @Override public Provider configure(Pkcs11IdentityManager.Device device) { return provider(); }
            @Override public KeyStore load(Provider provider, char[] pin) throws Exception { return KeyStore.getInstance("JKS"); }
        };
        try (var manager = new Pkcs11IdentityManager(backend)) {
            var definition = definition();
            var failure = assertThrows(AuthenticationFailure.class, () -> manager.listCertificates(definition, "unit-pin".toCharArray(), false, deadline(), () -> false));
            assertEquals(AuthenticationFailure.Phase.PROVIDER, failure.phase()); assertEquals(AuthenticationFailure.Cause.CERTIFICATE, failure.reason());
            assertTrue(failure.problem().startsWith("The token login completed")); assertFalse(failure.problem().contains("initialization"));
            assertNull(manager.status(definition).paused());
        }
    }

    public @Test void unknownAndCyclicCausesStayBoundedRedactedAndDoNotInventRecoveryAdvice() {
        Throwable cyclic = new IOException("private-value CKR_VENDOR_DEFINED") { @Override public synchronized Throwable getCause() { return this; } };
        var failure = Pkcs11Failures.from(Pkcs11Failures.Operation.INITIALIZE, cyclic);
        assertTrue(failure.problem().contains("no recognized cause")); assertEquals("", failure.recovery());
        assertFalse(failure.getMessage().contains("private-value")); assertFalse(failure.getMessage().contains("CKR_VENDOR_DEFINED")); assertNull(failure.getCause());
    }

    public @Test void warmMaterialAvoidsAutomaticResubmissionAndOwnedProvidersAreAppendedThenRemoved() throws Exception {
        AtomicInteger loads = new AtomicInteger(), configurations = new AtomicInteger(); AtomicReference<Provider> owned = new AtomicReference<>();
        AtomicReference<char[]> submitted = new AtomicReference<>(); var before = java.util.Arrays.stream(Security.getProviders()).map(Provider::getName).toList();
        var backend = new Pkcs11IdentityManager.NativeAccess() {
            /** @param device Fake module/slot. @return Unregistered test provider. */
            @Override public Provider configure(Pkcs11IdentityManager.Device device) { configurations.incrementAndGet(); Provider value = provider(); owned.set(value); return value; }
            /** @param provider Test provider. @param pin Owned copy captured to verify wiping. @return Empty successful store. */
            @Override public KeyStore load(Provider provider, char[] pin) throws Exception { loads.incrementAndGet(); submitted.set(pin); return empty(); }
        };
        var definition = definition(); char[] pin = "unit-pin".toCharArray();
        try (var manager = new Pkcs11IdentityManager(backend)) {
            assertTrue(manager.listCertificates(definition, pin, false, deadline(), () -> false).isEmpty());
            assertTrue(manager.listCertificates(definition, "another-configured-value".toCharArray(), false, deadline(), () -> false).isEmpty());
            assertEquals(1, configurations.get()); assertEquals(1, loads.get()); assertArrayEquals("unit-pin".toCharArray(), pin);
            assertArrayEquals(new char[pin.length], submitted.get()); assertSame(owned.get(), Security.getProvider(owned.get().getName()));
            assertEquals(before, java.util.Arrays.stream(Security.getProviders()).limit(before.size()).map(Provider::getName).toList());
        }
        assertNull(Security.getProvider(owned.get().getName()));
    }
    public @Test void explicitRejectionPausesOtherJourneysAndFieldEditsDoNotSubmitAgain() throws Exception {
        AtomicInteger loads = new AtomicInteger(); AtomicReference<char[]> submitted = new AtomicReference<>();
        var backend = new Pkcs11IdentityManager.NativeAccess() {
            /** @param device Fake selector. @return Unique owned test provider. */
            @Override public Provider configure(Pkcs11IdentityManager.Device device) { return provider(); }
            /** @param provider Fake provider. @param pin Owned buffer. @return Empty store after explicit recovery. */
            @Override public KeyStore load(Provider provider, char[] pin) throws Exception {
                submitted.set(pin); if (loads.incrementAndGet() == 1) throw new IOException("CKR_PIN_INCORRECT (unit fixture value omitted)"); return empty();
            }
        };
        var first = definition(); var other = new JourneyDefinition.Mtls(first.modulePath(), first.slot(), "b".repeat(64), first.origins(), null);
        try (var manager = new Pkcs11IdentityManager(backend)) {
            assertEquals(AuthenticationFailure.Cause.PIN_REJECTED, assertThrows(AuthenticationFailure.class, () -> manager.listCertificates(first, "unit-pin".toCharArray(), false, deadline(), () -> false)).reason());
            assertEquals(AuthenticationFailure.Cause.PIN_REJECTED, assertThrows(AuthenticationFailure.class, () -> manager.select(other, "corrected-value".toCharArray(), false, deadline(), () -> false)).reason());
            assertEquals(1, loads.get()); assertEquals(AuthenticationFailure.Cause.PIN_REJECTED, manager.status(first).paused()); assertArrayEquals(new char[8], submitted.get());
            assertTrue(manager.listCertificates(other, "corrected-value".toCharArray(), true, deadline(), () -> false).isEmpty()); assertEquals(2, loads.get()); assertNull(manager.status(first).paused());
        }
    }
    public @Test void unknownSubmissionOutcomeAndVendorErrorsAlsoSuppressAutomaticPinRetry() throws Exception {
        for (boolean error : List.of(false, true)) {
            AtomicInteger loads = new AtomicInteger();
            var backend = new Pkcs11IdentityManager.NativeAccess() {
                /** @param device Fake selector. @return Unique unregistered provider. */
                @Override public Provider configure(Pkcs11IdentityManager.Device device) { return provider(); }
                /** @param provider Fake backend. @param pin Test value, never printed. @return Never returns for this failure case. */
                @Override public KeyStore load(Provider provider, char[] pin) throws Exception {
                    loads.incrementAndGet(); if (error) throw new LinkageError("symbolic vendor error"); throw new IOException("unmapped native result");
                }
            };
            try (var manager = new Pkcs11IdentityManager(backend)) {
                var definition = definition();
                for (int i = 0; i < 2; i++) assertEquals(AuthenticationFailure.Cause.PIN_INDETERMINATE, assertThrows(AuthenticationFailure.class,
                        () -> manager.listCertificates(definition, "unit-pin".toCharArray(), false, deadline(), () -> false)).reason());
                assertEquals(1, loads.get());
            }
        }
    }
    public @Test void deadlineReleasesTheCallerButExplicitRecoveryCannotDuplicateAnOutstandingPinCall() throws Exception {
        CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1); AtomicInteger loads = new AtomicInteger();
        var backend = new Pkcs11IdentityManager.NativeAccess() {
            /** @param device Fake selector. @return Unique owned provider. */
            @Override public Provider configure(Pkcs11IdentityManager.Device device) { return provider(); }
            /** @param provider Fake backend. @param pin Owned buffer retained until the simulated vendor returns. @return Empty store after release. */
            @Override public KeyStore load(Provider provider, char[] pin) throws Exception { loads.incrementAndGet(); entered.countDown(); release.await(); return empty(); }
        };
        var definition = definition();
        try (var manager = new Pkcs11IdentityManager(backend)) {
            try {
                var ex = assertThrows(AuthenticationFailure.class, () -> manager.listCertificates(definition, "unit-pin".toCharArray(), false,
                        System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(150), () -> false));
                assertTrue(entered.await(1, TimeUnit.SECONDS)); assertEquals(AuthenticationFailure.Cause.PIN_INDETERMINATE, ex.reason());
                assertTrue(manager.status(definition).pinInProgress());
                assertEquals(AuthenticationFailure.Cause.PIN_IN_PROGRESS, assertThrows(AuthenticationFailure.class,
                        () -> manager.listCertificates(definition, "unit-pin".toCharArray(), true, deadline(), () -> false)).reason()); assertEquals(1, loads.get());
            } finally { release.countDown(); }
            await(() -> !manager.status(definition).operationOutstanding());
            assertEquals(AuthenticationFailure.Cause.PIN_INDETERMINATE, manager.status(definition).paused(), "late success cannot silently clear suppression");
            manager.listCertificates(definition, "unit-pin".toCharArray(), true, deadline(), () -> false); assertEquals(2, loads.get());
        }
    }
    public @Test void missingPinAndModuleAreTerminalBeforeNativeSubmission() throws Exception {
        var definition = definition();
        try (var manager = new Pkcs11IdentityManager()) {
            assertEquals(AuthenticationFailure.Cause.MISSING_SECRET, assertThrows(AuthenticationFailure.class, () -> manager.listCertificates(definition, null, false, deadline(), () -> false)).reason());
            var missing = new JourneyDefinition.Mtls(temp.resolve("missing.dll").toString(), definition.slot(), definition.certificateSha256(), definition.origins(), null);
            assertEquals(AuthenticationFailure.Cause.CONFIGURATION, assertThrows(AuthenticationFailure.class, () -> manager.select(missing, "unit-pin".toCharArray(), false, deadline(), () -> false)).reason());
        }
    }

    public @Test void discoveryTimeoutDoesNotDuplicateOutstandingNativeWorkOrSubmitAnyPin() throws Exception {
        var calls = new AtomicInteger(); var started = new CountDownLatch(1); var release = new CountDownLatch(1);
        var backend = new Pkcs11IdentityManager.NativeAccess() {
            @Override public List<Pkcs11IdentityManager.TokenInfo> tokens(Path module) throws Exception {
                calls.incrementAndGet(); started.countDown(); release.await();
                return List.of(new Pkcs11IdentityManager.TokenInfo(77, "Token", "Vendor", "Model", "serial"));
            }
            @Override public Provider configure(Pkcs11IdentityManager.Device device) { fail("Discovery must not configure a login provider"); return null; }
            @Override public KeyStore load(Provider provider, char[] pin) { fail("Discovery must never submit a PIN"); return null; }
        };
        var module = definition().modulePath();
        try (var manager = new Pkcs11IdentityManager(backend)) {
            try {
                for (int attempt = 0; attempt < 2; attempt++) {
                    var failure = assertThrows(AuthenticationFailure.class, () -> manager.discoverTokens(module, System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(150), () -> false));
                    assertEquals(AuthenticationFailure.Cause.TIMEOUT, failure.reason());
                }
                assertTrue(started.await(1, TimeUnit.SECONDS)); assertEquals(1, calls.get());
                assertNull(manager.status(definition()).paused());
            } finally { release.countDown(); }
            assertEquals(77, manager.discoverTokens(module, deadline(), () -> false).getFirst().slotId());
        }
    }
}
