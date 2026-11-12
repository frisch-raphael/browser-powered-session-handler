package bpsh.transport.tls;

import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.JourneyDefinition;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** Stuck child work must not keep the host alive or retain a PIN after manager shutdown. */
class Pkcs11ProcessAccessTest {
    @TempDir Path root;

    @Test void setupFailurePreservesItsInputAndRequiresExplicitRetryInsteadOfTrappingTheDevice() throws Exception {
        Path marker = Files.createFile(root.resolve("rejected.dll"));
        var access = new Pkcs11ProcessAccess(RejectedHelper.class);
        try (var manager = new Pkcs11IdentityManager(access)) {
            var mtls = new JourneyDefinition.Mtls(marker.toString(), new JourneyDefinition.Slot(JourneyDefinition.SlotKind.INDEX, 0),
                    "0".repeat(64), List.of(URI.create("https://app.example")), null);
            var failure = assertThrows(AuthenticationFailure.class, () -> manager.select(mtls, new char[]{'1'}, false,
                    System.nanoTime() + TimeUnit.SECONDS.toNanos(10), () -> false));
            assertEquals(AuthenticationFailure.Cause.DEVICE_SESSION_LOST, failure.reason());
            assertEquals(AuthenticationFailure.Input.MIDDLEWARE, failure.input().input()); assertTrue(failure.recovery().contains("Retry"));
            assertEquals("x", Files.readString(marker));
            assertEquals(AuthenticationFailure.Cause.DEVICE_SESSION_LOST, assertThrows(AuthenticationFailure.class, () -> manager.select(mtls, new char[]{'1'}, false,
                    System.nanoTime() + TimeUnit.SECONDS.toNanos(10), () -> false)).reason());
            assertEquals("x", Files.readString(marker), "A paused device must not restart automatically");
            assertThrows(AuthenticationFailure.class, () -> manager.select(mtls, new char[]{'1'}, true, System.nanoTime() + TimeUnit.SECONDS.toNanos(10), () -> false));
            assertEquals("xx", Files.readString(marker), "Explicit retry can reopen the failed helper");
        }
    }

    @Test void isolatedSigningFailureKeepsDeviceGuidanceInsteadOfBlamingTheServerCertificate() {
        var safe = new AuthenticationFailure(AuthenticationFailure.Phase.PROVIDER, AuthenticationFailure.Cause.CONFIGURATION,
                "The device helper stopped.", "Use Retry.").atInput(AuthenticationFailure.Input.SECURITY_DEVICE);
        var handshake = new javax.net.ssl.SSLHandshakeException("Controlled handshake failure");
        handshake.initCause(new java.security.SignatureException("Controlled signing failure", safe));
        assertSame(safe, JourneyTlsContexts.destinationFailure(handshake, true));
    }

    @Test void unloadTerminatesAHelperThatIgnoresCancellationAndReleasesTheCaller() throws Exception {
        Path marker = Files.createFile(root.resolve("middleware.dll"));
        var access = new Pkcs11ProcessAccess(StalledHelper.class);
        var ownedPin = new java.util.concurrent.atomic.AtomicReference<char[]>();
        var manager = new Pkcs11IdentityManager(new Pkcs11IdentityManager.NativeAccess() {
            @Override public java.security.Provider configure(Pkcs11IdentityManager.Device device) throws Exception { return access.configure(device); }
            @Override public java.security.KeyStore load(java.security.Provider provider, char[] pin) throws Exception {
                ownedPin.set(pin); return access.load(provider, pin);
            }
            @Override public void close() { access.close(); }
        });
        var workers = Executors.newSingleThreadExecutor();
        var mtls = new JourneyDefinition.Mtls(marker.toString(), new JourneyDefinition.Slot(JourneyDefinition.SlotKind.INDEX, 0),
                "0".repeat(64), List.of(URI.create("https://app.example")), null);
        try {
            var waiting = workers.submit(() -> {
                try { manager.select(mtls, "123456".toCharArray(), false, System.nanoTime() + TimeUnit.SECONDS.toNanos(30), () -> false); return null; }
                catch (AuthenticationFailure failure) { return failure.reason(); }
            });
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            while (Files.size(marker) == 0 && System.nanoTime() < deadline && !waiting.isDone()) Thread.sleep(10);
            assertEquals("stalled", Files.readString(marker));
            assertArrayEquals(new char[6], ownedPin.get(), "The host PIN copy must already be wiped while native work is still stalled in the child");
            var owned = access.processes(); assertEquals(1, owned.size()); assertTrue(owned.getFirst().isAlive());
            long started = System.nanoTime(); manager.close();
            assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(5));
            assertFalse(owned.getFirst().isAlive());
            assertEquals(AuthenticationFailure.Cause.CLOSED, waiting.get(5, TimeUnit.SECONDS));
            manager.close(); assertTrue(access.processes().isEmpty());
        } finally { manager.close(); workers.shutdownNow(); assertTrue(workers.awaitTermination(5, TimeUnit.SECONDS)); }
    }

    /** A separate JVM deliberately ignores EOF/cancellation after accepting the disposable PIN. */
    public static final class StalledHelper {
        private StalledHelper() {}
        public static void main(String[] arguments) throws Exception {
            byte[] token = System.in.readNBytes(32);
            try (var socket = new Socket(InetAddress.getLoopbackAddress(), Integer.parseInt(arguments[0]));
                 var input = new DataInputStream(socket.getInputStream()); var output = new DataOutputStream(socket.getOutputStream())) {
                output.write(token); output.flush(); Arrays.fill(token, (byte) 0);
                String marker = input.readUTF(); input.readUTF(); input.readLong();
                int count = input.readInt(); for (int i = 0; i < count; i++) input.readChar();
                Files.writeString(Path.of(marker), "stalled");
                while (true) try { Thread.sleep(Long.MAX_VALUE); } catch (InterruptedException ignored) { /* Deliberately noncooperative middleware stand-in. */ }
            }
        }
    }

    /** Reports a controlled setup error after authentication, without loading a real module. */
    public static final class RejectedHelper {
        private RejectedHelper() {}
        public static void main(String[] arguments) throws Exception {
            byte[] token = System.in.readNBytes(32);
            try (var socket = new Socket(InetAddress.getLoopbackAddress(), Integer.parseInt(arguments[0]));
                 var input = new DataInputStream(socket.getInputStream()); var output = new DataOutputStream(socket.getOutputStream())) {
                output.write(token); output.flush(); Arrays.fill(token, (byte) 0);
                String marker = input.readUTF(); input.readUTF(); input.readLong();
                int count = input.readInt(); for (int i = 0; i < count; i++) input.readChar();
                Files.writeString(Path.of(marker), "x", StandardOpenOption.APPEND);
                output.writeBoolean(false); output.writeUTF("PROVIDER"); output.writeUTF("CONFIGURATION");
                output.writeUTF("The middleware could not initialize."); output.writeUTF("Check the middleware."); output.writeUTF("MIDDLEWARE"); output.flush();
            }
        }
    }
}
