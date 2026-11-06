import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import java.io.InputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Owns shared PKCS#11 providers/login state and slot-level PIN suppression inside the extension.
 *
 * Native operations run on two bounded daemon workers and are serialized per canonical module/slot
 * selection. A deadline releases callers but cannot interrupt a hung vendor call. No logout is
 * performed when an attempt ends. Automatic retries reuse established material instead of PIN
 * resubmission; explicit recovery is required after rejected/indeterminate PIN outcomes.
 */
public final class Pkcs11IdentityManager implements AutoCloseable {
    /** Stable provider owner; the exact configured slot selector is part of its identity. */
    record Device(Path module, JourneyDefinition.Slot slot) {}

    /** Public device identity discovered without opening a session or submitting a PIN. */
    public record TokenInfo(long slotId, String label, String manufacturer, String model, String serial) {
        /** @return Diagnostic label without device identifiers. */
        @Override public String toString() { return "Pkcs11Token[public metadata]"; }
    }

    /** Public certificate metadata for an asynchronous list action; common name never selects a key. */
    public record CertificateInfo(String subject, String issuer, String serial, Instant notBefore, Instant notAfter, String sha256) {
        /**
         * Returns fingerprint-only diagnostic label, excluding token/module/PIN state.
         *
         * @return Fingerprint-only diagnostic label, excluding token/module/PIN state.
         */
        @Override public String toString() { return "Certificate[sha256=" + sha256 + "]"; }
    }

    /** Holds an immutable fingerprint-pinned key manager; private-key material stays in the provider. */
    public record Selected(CertificateInfo certificate, X509ExtendedKeyManager keyManager) {
        /**
         * Returns safe selection label without a private-key object's representation.
         *
         * @return Safe selection label without a private-key object's representation.
         */
        @Override public String toString() { return "Pkcs11Selection[" + certificate.sha256() + "]"; }
    }

    /** Safe device status for asynchronous UI/tests; no PIN, key handles or native exception text. */
    public record Status(boolean operationOutstanding, boolean pinInProgress, AuthenticationFailure.Cause paused) {}

    /** Injects native setup/load boundaries for symbolic PIN-state tests without hardware claims. */
    interface NativeAccess {
        /** @param module Canonical middleware file. @return Present initialized tokens, without a login. @throws Exception On discovery failure. */
        default List<TokenInfo> tokens(Path module) throws Exception { throw new UnsupportedOperationException("Token discovery unavailable."); }
        /**
         * Configures a uniquely named owned provider for the canonical native module and selected slot.
         *
         * @param device Canonical module and exact slot.
         * @return Unregistered owned provider.
         * @throws Exception On native setup failure.
         */
        Provider configure(Device device) throws Exception;
        /**
         * Loads the selected token through its owned provider using a temporary PIN copy.
         *
         * @param provider Owned configured provider.
         * @param pin Owned temporary copy.
         * @return Loaded private-key store.
         * @throws Exception On login failure.
         */
        KeyStore load(Provider provider, char[] pin) throws Exception;
    }

    /** Retains loaded provider material across attempts without selecting a global client alias. */
    private record Material(Map<String, X509Certificate> certificates, Map<String, CertificateInfo> metadata, X509ExtendedKeyManager manager) {}

    /** Uses only short monitor sections; no vendor calls occur while this state monitor is held. */
    private static final class State {
        Provider provider;
        Material material;
        Future<Material> operation;
        boolean pinInProgress;
        char[] queuedPin;
        AuthenticationFailure latch;
    }

    private final Object lifecycle = new Object();
    private final Map<Device, State> devices = new HashMap<>();
    private final Map<Path, Future<List<TokenInfo>>> discoveries = new HashMap<>();
    private final NativeAccess access;
    private final ThreadPoolExecutor nativeWorkers;
    private volatile boolean closed;

    /** Creates the Java SunPKCS11 backend without loading a module or submitting a PIN. */
    public Pkcs11IdentityManager() { this(new SunAccess()); }

    /**
     * Creates bounded daemon native workers using the supplied provider boundary.
     *
     * @param access Test backend used to establish deterministic native-operation outcomes.
     */
    Pkcs11IdentityManager(NativeAccess access) {
        this.access = access;
        nativeWorkers = new ThreadPoolExecutor(2, 2, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(16), r -> {
            Thread thread = new Thread(r, "bpsh-pkcs11-native"); thread.setDaemon(true); return thread;
        }, new ThreadPoolExecutor.AbortPolicy());
    }

    /**
     * Enumerates devices on a bounded worker; concurrent callers share an outstanding discovery and no PIN is accepted.
     * @param modulePath Configured middleware file.
     * @param deadline Original caller deadline.
     * @param cancelled Caller cancellation signal; does not cancel shared native work.
     * @return Present initialized tokens, identified by actual slot IDs.
     * @throws AuthenticationFailure On unavailable middleware, discovery, capacity, cancellation or deadline failure.
     */
    public List<TokenInfo> discoverTokens(String modulePath, long deadline, BooleanSupplier cancelled) throws AuthenticationFailure {
        checkDiscovery(deadline, cancelled); Path module = canonicalModule(modulePath); Future<List<TokenInfo>> operation;
        synchronized (lifecycle) {
            if (closed) throw closed();
            operation = discoveries.get(module);
            if (operation == null || operation.isDone()) {
                var task = new FutureTask<List<TokenInfo>>(() -> {
                    try { return List.copyOf(access.tokens(module)); }
                    catch (AuthenticationFailure error) { throw error; }
                    catch (Exception | LinkageError error) { throw Pkcs11Failures.from(Pkcs11Failures.Operation.DISCOVERY, error); }
                });
                try { nativeWorkers.execute(task); }
                catch (RejectedExecutionException error) { throw failure(AuthenticationFailure.Cause.CAPACITY, "Too many security-device operations are waiting.", "Wait for the current operations to finish, then choose Choose certificate again."); }
                discoveries.put(module, task); operation = task;
            }
        }
        while (true) {
            try {
                checkDiscovery(deadline, cancelled);
                var result = operation.get(Math.min(TimeUnit.MILLISECONDS.toNanos(50), Math.max(1, deadline - System.nanoTime())), TimeUnit.NANOSECONDS);
                checkDiscovery(deadline, cancelled); return result;
            } catch (TimeoutException ignored) { /* native discovery may outlive one caller */ }
            catch (InterruptedException error) { Thread.currentThread().interrupt(); throw failure(AuthenticationFailure.Cause.CANCELLED, "Waiting for security-device discovery was interrupted.", ""); }
            catch (CancellationException error) { throw closed ? closed() : failure(AuthenticationFailure.Cause.CANCELLED, "Security-device discovery was cancelled.", ""); }
            catch (ExecutionException error) {
                if (error.getCause() instanceof AuthenticationFailure known) throw known;
                throw Pkcs11Failures.from(Pkcs11Failures.Operation.DISCOVERY, error);
            }
        }
    }

    /** @param deadline Original discovery deadline. @param cancelled Caller signal. @throws AuthenticationFailure Without cancelling shared native discovery. */
    private void checkDiscovery(long deadline, BooleanSupplier cancelled) throws AuthenticationFailure {
        if (closed) throw closed();
        AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.PROVIDER, deadline, cancelled);
    }

    /** @param modulePath Configured library path. @return Canonical regular file. @throws AuthenticationFailure On invalid or inaccessible middleware. */
    private static Path canonicalModule(String modulePath) throws AuthenticationFailure {
        try {
            Path module = Path.of(modulePath).toRealPath();
            if (!Files.isRegularFile(module)) throw failure(AuthenticationFailure.Cause.CONFIGURATION,
                    "The configured PKCS#11 middleware path is not a regular file.", "Choose the middleware library file.").atInput(AuthenticationFailure.Input.MIDDLEWARE);
            return module;
        } catch (AuthenticationFailure error) { throw error; }
        catch (Exception error) { throw Pkcs11Failures.from(Pkcs11Failures.Operation.MODULE, error); }
    }

    /**
     * Reads operation/suppression state without waiting for a vendor call; run path canonicalization off EDT.
     * @param definition Exact module/slot selector whose status is requested.
     * @return Empty status for an unused/unavailable module path; otherwise the shared device status.
     */
    public Status status(JourneyDefinition.Mtls definition) {
        try {
            Device device = new Device(Path.of(definition.modulePath()).toRealPath(), definition.slot()); State state;
            synchronized (lifecycle) { state = devices.get(device); }
            if (state != null) synchronized (state) { return new Status(state.operation != null && !state.operation.isDone(), state.pinInProgress, state.latch == null ? null : state.latch.reason()); }
        } catch (Exception ignored) { /* no native probing for an unavailable module */ }
        return new Status(false, false, null);
    }

    /**
     * Lists certificate metadata for private-key entries without a common-name selection fallback.
     * @param definition Validated module/slot configuration.
     * @param pin Supplied PIN buffer; caller retains ownership and should wipe its copy.
     * @param explicitRecovery Explicit Retry after checking/correcting device state, never ordinary demand.
     * @param deadline Original attempt/setup deadline.
     * @param cancelled Caller cancellation predicate; the native operation may outlive it.
     * @return Immutable metadata list, possibly empty when no private-key certificate exists.
     * @throws AuthenticationFailure On setup, suppression, PIN failure, cancellation or deadline.
     */
    public List<CertificateInfo> listCertificates(JourneyDefinition.Mtls definition, char[] pin, boolean explicitRecovery,
                                                 long deadline, BooleanSupplier cancelled) throws AuthenticationFailure {
        Material material = material(definition, pin, explicitRecovery, deadline, cancelled);
        return List.copyOf(material.metadata().values());
    }

    /**
     * Pins a new per-attempt key manager to exactly one private-key certificate fingerprint.
     * @param definition Validated fingerprint/module/slot/origin settings.
     * @param pin Caller-owned configured PIN; even a warm provider requires a supplied configuration value.
     * @param explicitRecovery Whether the operator explicitly acknowledged recovery from a PIN latch.
     * @param deadline Original attempt deadline.
     * @param cancelled Caller cancellation predicate.
     * @return Immutable selected certificate/key-manager binding; no key bytes are exported.
     * @throws AuthenticationFailure On missing/ambiguous/expired selection or provider/PIN failure.
     */
    public Selected select(JourneyDefinition.Mtls definition, char[] pin, boolean explicitRecovery,
                           long deadline, BooleanSupplier cancelled) throws AuthenticationFailure {
        Material material = material(definition, pin, explicitRecovery, deadline, cancelled);
        try {
            String chosen = null; X509Certificate certificate = null;
            for (String alias : material.certificates().keySet()) if (material.metadata().get(alias).sha256().equals(definition.certificateSha256())) {
                if (chosen != null) throw failure(AuthenticationFailure.Cause.CERTIFICATE, "Several certificates on the device match the selected fingerprint.", "Choose a certificate with a unique fingerprint in Client certificate.");
                chosen = alias; certificate = material.certificates().get(alias);
            }
            if (chosen == null) throw failure(AuthenticationFailure.Cause.CERTIFICATE, "The selected client certificate was not found on the device.", "Use Choose certificate to select an available certificate.");
            certificate.checkValidity();
            return new Selected(info(certificate), new PinnedKeyManager(material.manager(), chosen));
        } catch (AuthenticationFailure ex) { throw ex; }
        catch (CertificateExpiredException ex) { throw failure(AuthenticationFailure.Cause.CERTIFICATE, "The selected client certificate has expired.", "Renew the certificate on the device or choose a valid certificate."); }
        catch (CertificateNotYetValidException ex) { throw failure(AuthenticationFailure.Cause.CERTIFICATE, "The selected client certificate's validity period has not started.", ""); }
        catch (Exception ex) { throw failure(AuthenticationFailure.Cause.CERTIFICATE, "The selected client certificate could not be used.", ""); }
    }

    /**
     * Joins one shared native load or reuses established login material without resubmitting a PIN.
     * @param definition Exact configured device/slot.
     * @param pin Supplied configuration value, copied only for an actual native submission.
     * @param recovery Explicit operator recovery request.
     * @param deadline Original caller deadline.
     * @param cancelled Cancellation predicate.
     * @return Shared material; each select call wraps it in a separate pinned key manager.
     * @throws AuthenticationFailure If blocked, incomplete, cancelled or failed.
     */
    private Material material(JourneyDefinition.Mtls definition, char[] pin, boolean recovery, long deadline,
                              BooleanSupplier cancelled) throws AuthenticationFailure {
        check(deadline, cancelled);
        if (pin == null) throw failure(AuthenticationFailure.Cause.MISSING_SECRET, "The client-certificate PIN is missing.", "Enter the PIN in Client certificate, then run Test login or Choose certificate.");
        Device device = new Device(canonicalModule(definition.modulePath()), definition.slot());
        State state;
        synchronized (lifecycle) { if (closed) throw closed(); state = devices.computeIfAbsent(device, ignored -> new State()); }
        Future<Material> operation;
        synchronized (state) {
            boolean outstanding = state.operation != null && !state.operation.isDone();
            if (recovery && outstanding) throw failure(AuthenticationFailure.Cause.PIN_IN_PROGRESS, "The security device is still processing a request.", "Wait for the device to finish before choosing Retry.");
            if (recovery) { state.latch = null; state.material = null; }
            if (state.latch != null) throw state.latch;
            if (state.material != null) return state.material;
            if (!outstanding) {
                char[] ownedPin = pin.clone();
                state.queuedPin = ownedPin;
                FutureTask<Material> task = new FutureTask<>(() -> load(device, state, ownedPin, deadline, cancelled)); state.operation = task;
                try { nativeWorkers.execute(task); }
                catch (RejectedExecutionException ex) { Arrays.fill(ownedPin, '\0'); state.queuedPin = null; state.operation = null; throw failure(AuthenticationFailure.Cause.CAPACITY, "Too many security-device operations are waiting.", "Wait for the current device operations to finish, then choose Retry."); }
            }
            operation = state.operation;
        }
        while (true) {
            try {
                check(deadline, cancelled);
                Material result = operation.get(Math.min(TimeUnit.MILLISECONDS.toNanos(50), Math.max(1, deadline - System.nanoTime())), TimeUnit.NANOSECONDS);
                check(deadline, cancelled); return result;
            } catch (TimeoutException ignored) { /* recheck original budget/cancellation */ }
            catch (InterruptedException ex) { Thread.currentThread().interrupt(); markIndeterminate(state); throw new AuthenticationFailure(AuthenticationFailure.Phase.PIN, AuthenticationFailure.Cause.CANCELLED, "Waiting for the security device was interrupted.", ""); }
            catch (CancellationException ex) { if (closed) throw closed(); throw failure(AuthenticationFailure.Cause.CANCELLED, "The pending security-device operation was cancelled.", ""); }
            catch (ExecutionException ex) {
                synchronized (state) { if (state.latch != null) throw state.latch; }
                if (ex.getCause() instanceof AuthenticationFailure failure) throw failure;
                throw failure(AuthenticationFailure.Cause.UNKNOWN, "The security-device operation failed.", "");
            } catch (AuthenticationFailure ex) {
                AuthenticationFailure pinOutstanding = markIndeterminate(state);
                if (pinOutstanding != null && ex.reason() == AuthenticationFailure.Cause.TIMEOUT) throw pinOutstanding;
                throw ex;
            }
        }
    }

    /**
     * Performs the one serialized native load, recording PIN outcome before releasing its owned copy.
     * @param device Canonical module/slot selection.
     * @param state Shared operation state, never held locked across vendor calls.
     * @param pin Owned copy retained until the actual native call returns, even after caller timeout.
     * @param deadline Original submitting caller's deadline, checked before starting PIN entry.
     * @param cancelled Submitting attempt's cancellation predicate.
     * @return Loaded provider/key-manager state for later no-resubmission retries.
     * @throws AuthenticationFailure On definite rejection, unknown PIN outcome or setup failure.
     */
    private Material load(Device device, State state, char[] pin, long deadline, BooleanSupplier cancelled) throws AuthenticationFailure {
        boolean submitted = false, completed = false;
        Pkcs11Failures.Operation operation = Pkcs11Failures.Operation.INITIALIZE;
        try {
            synchronized (state) { state.queuedPin = null; }
            check(deadline, cancelled);
            Provider provider;
            synchronized (state) { provider = state.provider; }
            if (provider == null) {
                provider = access.configure(device);
                synchronized (lifecycle) {
                    if (closed) throw closed();
                    if (Security.getProvider(provider.getName()) != null || Security.addProvider(provider) < 1)
                        throw failure(AuthenticationFailure.Cause.CONFIGURATION, "The PKCS#11 module could not be registered with Java.", "");
                    synchronized (state) { state.provider = provider; }
                }
            }
            check(deadline, cancelled);
            synchronized (state) { state.pinInProgress = true; }
            operation = Pkcs11Failures.Operation.LOGIN;
            submitted = true; KeyStore keys = access.load(provider, pin); completed = true;
            synchronized (state) { state.pinInProgress = false; }
            operation = Pkcs11Failures.Operation.CERTIFICATES;
            KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()); factory.init(keys, null);
            X509ExtendedKeyManager manager = Arrays.stream(factory.getKeyManagers()).filter(X509ExtendedKeyManager.class::isInstance)
                    .map(X509ExtendedKeyManager.class::cast).findFirst().orElseThrow();
            Map<String, X509Certificate> certificates = new HashMap<>(); Map<String, CertificateInfo> metadata = new HashMap<>();
            var aliases = keys.aliases();
            while (aliases.hasMoreElements()) {
                check(deadline, cancelled); String alias = aliases.nextElement();
                if (keys.isKeyEntry(alias) && keys.getCertificate(alias) instanceof X509Certificate certificate) {
                    certificates.put(alias, certificate); metadata.put(alias, info(certificate));
                }
            }
            Material material = new Material(Map.copyOf(certificates), Map.copyOf(metadata), manager);
            synchronized (state) { state.material = material; }
            return material;
        } catch (AuthenticationFailure ex) { throw ex; }
        catch (Exception | LinkageError ex) {
            AuthenticationFailure result = Pkcs11Failures.from(operation, ex);
            if (submitted && !completed) {
                synchronized (state) { state.latch = result; }
            }
            throw result;
        } finally {
            synchronized (state) {
                // Even an Error from vendor code cannot turn an unknown submitted PIN into a retry.
                if (submitted && !completed && state.latch == null) state.latch = indeterminate();
                state.pinInProgress = false;
            }
            Arrays.fill(pin, '\0');
        }
    }

    /**
     * Latches an outstanding PIN outcome without cancelling/replacing its native future.
     * @param state Shared module/slot state.
     * @return Captured immutable latch when a PIN call was in progress, otherwise null.
     */
    private static AuthenticationFailure markIndeterminate(State state) {
        synchronized (state) { if (!state.pinInProgress) return null; if (state.latch == null) state.latch = indeterminate(); return state.latch; }
    }


    /**
     * Returns shared unknown-PIN guidance; no supplied value or raw vendor detail is retained.
     *
     * @return Shared unknown-PIN guidance; no supplied value or raw vendor detail is retained.
     */
    private static AuthenticationFailure indeterminate() { return failure(AuthenticationFailure.Cause.PIN_INDETERMINATE, "The security device did not report whether it accepted the PIN.", "Automatic PIN attempts are paused."); }
    /**
     * Returns safe manager shutdown failure.
     *
     * @return Safe manager shutdown failure.
     */
    private static AuthenticationFailure closed() { return failure(AuthenticationFailure.Cause.CLOSED, "The client-certificate service has stopped.", "Reload the extension before authentication."); }
    /**
     * Checks extension lifecycle, caller cancellation and the original native-operation budget.
     *
     * @param deadline Original budget.
     * @param cancelled Caller predicate.
     * @throws AuthenticationFailure If closed/cancelled/expired.
     */
    private void check(long deadline, BooleanSupplier cancelled) throws AuthenticationFailure { if (closed) throw closed(); AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.PIN, deadline, cancelled); }
    /**
     * Builds a typed failure with operator recovery guidance and no raw exception cause.
     *
     * @param cause Symbolic provider/PIN category.
     * @param safe Safe problem.
     * @param recovery Operator action.
     * @return Redacted failure without vendor cause.
     */
    private static AuthenticationFailure failure(AuthenticationFailure.Cause cause, String safe, String recovery) {
        var phase = cause == AuthenticationFailure.Cause.CONFIGURATION || cause == AuthenticationFailure.Cause.CERTIFICATE
                ? AuthenticationFailure.Phase.PROVIDER : AuthenticationFailure.Phase.PIN;
        var result = new AuthenticationFailure(phase, cause, safe, recovery);
        return switch (cause) {
            case MISSING_SECRET, PIN_REJECTED -> result.atInput(AuthenticationFailure.Input.MTLS_PIN);
            case CERTIFICATE -> result.atInput(AuthenticationFailure.Input.CERTIFICATE);
            case PIN_INDETERMINATE, PIN_IN_PROGRESS -> result.atInput(AuthenticationFailure.Input.SECURITY_DEVICE);
            default -> result;
        };
    }
    /**
     * Derives public certificate display data and its exact SHA-256 identity, independently of its common name.
     *
     * @param cert Public X.509 certificate.
     * @return Display metadata and exact encoded-certificate digest.
     * @throws Exception If certificate encoding fails.
     */
    private static CertificateInfo info(X509Certificate cert) throws Exception {
        return new CertificateInfo(cert.getSubjectX500Principal().getName(), cert.getIssuerX500Principal().getName(), cert.getSerialNumber().toString(16),
                cert.getNotBefore().toInstant(), cert.getNotAfter().toInstant(), HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(cert.getEncoded())));
    }

    /** Restricts all socket/engine key-manager entry points to the immutable selected alias. */
    static final class PinnedKeyManager extends X509ExtendedKeyManager {
        private final X509ExtendedKeyManager delegate;
        private final String alias;
        /**
         * Wraps shared login material with one immutable certificate alias for this selected identity.
         *
         * @param delegate Shared loaded provider manager.
         * @param alias Exact fingerprint-selected private-key entry.
         */
        PinnedKeyManager(X509ExtendedKeyManager delegate, String alias) { this.delegate = delegate; this.alias = alias; }
        /**
         * Returns the pinned client alias only when the peer's key-type and issuer constraints allow it.
         *
         * @param types Handshake-supported key types.
         * @param issuers Accepted issuers.
         * @return Only the selected alias when compatible, otherwise null.
         */
        private String choose(String[] types, Principal[] issuers) {
            if (types != null) for (String type : types) { String[] available = delegate.getClientAliases(type, issuers); if (available != null && Arrays.asList(available).contains(alias)) return alias; }
            return null;
        }
        /**
         * Restricts a socket handshake to the selected compatible client identity.
         *
         * @param types Requested types.
         * @param issuers Accepted issuers.
         * @param socket Handshake socket.
         * @return Pinned compatible alias or null.
         */
        @Override public String chooseClientAlias(String[] types, Principal[] issuers, Socket socket) { return choose(types, issuers); }
        /**
         * Restricts an engine handshake to the selected compatible client identity.
         *
         * @param types Requested types.
         * @param issuers Accepted issuers.
         * @param engine Handshake engine.
         * @return Pinned compatible alias or null.
         */
        @Override public String chooseEngineClientAlias(String[] types, Principal[] issuers, SSLEngine engine) { return choose(types, issuers); }
        /**
         * Exposes at most the pinned alias when it satisfies the requested key and issuer constraints.
         *
         * @param type Requested key type.
         * @param issuers Accepted issuers.
         * @return Singleton selected alias or null.
         */
        @Override public String[] getClientAliases(String type, Principal[] issuers) { return choose(new String[]{type}, issuers) == null ? null : new String[]{alias}; }
        /**
         * Refuses certificate-chain access through any alias other than the selected identity.
         *
         * @param name Requested alias.
         * @return Only the pinned certificate chain.
         */
        @Override public X509Certificate[] getCertificateChain(String name) { return alias.equals(name) ? delegate.getCertificateChain(name) : null; }
        /**
         * Returns only the selected provider key handle; this code never encodes or exports the private key.
         *
         * @param name Requested alias.
         * @return Only the pinned provider private-key handle; never encoded/exported here.
         */
        @Override public PrivateKey getPrivateKey(String name) { return alias.equals(name) ? delegate.getPrivateKey(name) : null; }
        /**
         * Provides no server aliases because the token key manager is used only for upstream client authentication.
         *
         * @param type Server key type.
         * @param issuers Accepted issuers.
         * @return Null; this manager never supplies server identities.
         */
        @Override public String[] getServerAliases(String type, Principal[] issuers) { return null; }
        /**
         * Refuses server-identity selection on socket handshakes.
         *
         * @param type Server key type.
         * @param issuers Accepted issuers.
         * @param socket Server socket.
         * @return Null.
         */
        @Override public String chooseServerAlias(String type, Principal[] issuers, Socket socket) { return null; }
        /**
         * Refuses server-identity selection on engine handshakes.
         *
         * @param type Server key type.
         * @param issuers Accepted issuers.
         * @param engine Server engine.
         * @return Null.
         */
        @Override public String chooseEngineServerAlias(String type, Principal[] issuers, SSLEngine engine) { return null; }
    }

    /** Configures SunPKCS11 through its public Provider API, never a JDK-internal wrapper or exported key. */
    private static final class SunAccess implements NativeAccess {
        private final Pkcs11DiscoveryProcess discovery = new Pkcs11DiscoveryProcess();
        /** @param module Canonical middleware file. @return Tokens discovered without submitting a PIN. @throws Exception On native discovery failure. */
        @Override public List<TokenInfo> tokens(Path module) throws Exception { return discovery.tokens(module); }
        /**
         * Configures a uniquely named owned provider for the canonical native module and selected slot.
         *
         * @param device Canonical absolute native module and exact slot.
         * @return Unique unregistered provider.
         * @throws Exception On configuration failure.
         */
        @Override public Provider configure(Device device) throws Exception {
            Provider base = Security.getProvider("SunPKCS11"); if (base == null) throw new IllegalStateException("Cryptoki unavailable.");
            String module = device.module().toString().replace('\\', '/');
            if (module.contains("\n") || module.contains("\r") || module.contains("\"")) throw new IllegalArgumentException("Unsafe module path.");
            Path config = Files.createTempFile("bpsh-pkcs11-", ".cfg");
            try {
                String slot = device.slot().kind() == JourneyDefinition.SlotKind.INDEX ? "slotListIndex" : "slot";
                Files.writeString(config, "name = BPSH_" + UUID.randomUUID().toString().replace("-", "") + "\nlibrary = \"" + module + "\"\n" + slot + " = " + device.slot().value() + "\n", StandardCharsets.UTF_8);
                return base.configure(config.toString());
            } finally {
                // This file contains no PIN. Cleanup must not replace the provider's actual outcome.
                try { Files.deleteIfExists(config); } catch (java.io.IOException | SecurityException ignored) { /* best-effort temporary-file cleanup */ }
            }
        }
        /**
         * Loads the selected token through its owned provider using a temporary PIN copy.
         *
         * @param provider Owned configured SunPKCS11 provider.
         * @param pin Owned temporary characters.
         * @return Loaded token keystore.
         * @throws Exception On PIN/native failure.
         */
        @Override public KeyStore load(Provider provider, char[] pin) throws Exception { KeyStore store = KeyStore.getInstance("PKCS11", provider); store.load((InputStream) null, pin); return store; }
    }

    /**
     * Stops admission and removes only the exact providers this manager appended, without token logout.
     * Hung native calls may remain daemon work; late configuration cannot register another provider.
     */
    @Override public void close() {
        synchronized (lifecycle) {
            if (closed) return; closed = true; nativeWorkers.shutdownNow();
            for (State state : devices.values()) synchronized (state) {
                if (state.queuedPin != null) {
                    Arrays.fill(state.queuedPin, '\0'); state.queuedPin = null;
                    if (state.operation != null) state.operation.cancel(false);
                }
                Provider provider = state.provider;
                if (provider != null && Security.getProvider(provider.getName()) == provider) Security.removeProvider(provider.getName());
            }
        }
    }
}
