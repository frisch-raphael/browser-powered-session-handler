package bpsh.transport.tls;

import bpsh.authentication.AuthenticationFailure;
import java.io.*;
import java.net.*;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/** Owns one terminable middleware process per configured device; keys never leave that process. */
final class Pkcs11ProcessAccess implements Pkcs11IdentityManager.NativeAccess {
    /** Tests remote ownership without submitting a PIN or calling the native provider. */
    static boolean usable(PrivateKey key) {
        if (key == null) return false;
        if (!(key instanceof RemoteKey remote)) return true;
        Process child = remote.channel.child;
        return !remote.channel.closed && child != null && child.isAlive();
    }
    private final Set<RemoteProvider> providers = ConcurrentHashMap.newKeySet();
    private volatile boolean closed;
    private final Class<?> entryPoint;
    Pkcs11ProcessAccess() { this(Pkcs11KeyMain.class); }
    /** Allows lifecycle tests to substitute a deliberately stalled helper without loading middleware. */
    Pkcs11ProcessAccess(Class<?> entryPoint) { this.entryPoint = entryPoint; }
    /** Observes only owned child identities for cleanup qualification. */
    List<ProcessHandle> processes() { return providers.stream().map(p -> p.channel.child).filter(Objects::nonNull).map(Process::toHandle).toList(); }
    @Override public List<Pkcs11IdentityManager.TokenInfo> tokens(Path module) throws Exception { return new Pkcs11DiscoveryProcess().tokens(module); }
    @Override public Provider configure(Pkcs11IdentityManager.Device device) throws Exception {
        var provider = new RemoteProvider(device, entryPoint); providers.add(provider);
        if (closed) { provider.close(); providers.remove(provider); throw new IOException("Device service closed."); }
        return provider;
    }
    @Override public KeyStore load(Provider provider, char[] pin) throws Exception { return ((RemoteProvider) provider).load(pin); }
    @Override public void close() {
        closed = true; boolean failed = false;
        for (var provider : List.copyOf(providers)) try { provider.close(); providers.remove(provider); }
        catch (RuntimeException | LinkageError failure) { failed = true; }
        if (failed) throw new IllegalStateException("A security-device helper did not finish cleanup.");
    }

    /** Registers only signatures using our nonexportable remote keys, never ordinary host keys. */
    private static final class RemoteProvider extends Provider {
        private volatile Channel channel;
        private final Pkcs11IdentityManager.Device device;
        private boolean disposed;
        private final Class<?> entryPoint;
        private RemoteProvider(Pkcs11IdentityManager.Device device, Class<?> entryPoint) {
            super("BPSH_Remote_" + UUID.randomUUID(), "1", "Isolated PKCS11 signing"); this.device = device; this.entryPoint = entryPoint; channel = new Channel(device, entryPoint);
            for (String algorithm : List.of("SHA256withRSA", "SHA384withRSA", "SHA512withRSA", "RSASSA-PSS",
                    "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA", "Ed25519", "Ed448"))
                putService(new Service(this, "Signature", algorithm, RemoteSignature.class.getName(), List.of(),
                        Map.of("SupportedKeyClasses", RemoteKey.class.getName())) {
                    @Override public Object newInstance(Object parameter) { return new RemoteSignature(getAlgorithm()); }
                    @Override public boolean supportsParameter(Object parameter) { return parameter instanceof RemoteKey; }
                });
        }
        /** Loads public chains and opaque key references; explicit retry may replace a failed helper. */
        private KeyStore load(char[] pin) throws Exception {
            Channel owner;
            synchronized (this) {
                if (disposed) throw new IOException("Device service closed.");
                channel.close(); channel = new Channel(device, entryPoint);
                owner = channel;
            }
            Map<String, Certificate[]> chains = owner.login(pin);
            return new RemoteStore(new Store(chains, owner), this);
        }
        /** Revokes replacement before stopping the currently owned helper. */
        private void close() { Channel owner; synchronized (this) { disposed = true; owner = channel; } owner.close(); }
    }

    /** A host-side key reference with no native handle or private-key encoding. */
    private static class RemoteKey implements PrivateKey {
        final String alias; final PublicKey publicKey; final Channel channel;
        private RemoteKey(String alias, PublicKey publicKey, Channel channel) { this.alias = alias; this.publicKey = publicKey; this.channel = channel; }
        @Override public String getAlgorithm() { return publicKey.getAlgorithm(); }
        @Override public String getFormat() { return null; }
        @Override public byte[] getEncoded() { return null; }
        @Override public String toString() { return "IsolatedPrivateKey"; }
        /** Preserves public key-size/curve information JSSE needs to select a signature scheme. */
        static RemoteKey of(String alias, PublicKey key, Channel channel) {
            if (key instanceof java.security.interfaces.RSAKey) return new RsaKey(alias, key, channel);
            if (key instanceof java.security.interfaces.ECKey) return new EcKey(alias, key, channel);
            if (key instanceof java.security.interfaces.EdECKey) return new EdKey(alias, key, channel);
            return new RemoteKey(alias, key, channel);
        }
    }
    /** Public RSA modulus only; private exponents remain in the child. */
    private static final class RsaKey extends RemoteKey implements java.security.interfaces.RSAKey {
        private RsaKey(String alias, PublicKey key, Channel channel) { super(alias, key, channel); }
        @Override public java.math.BigInteger getModulus() { return ((java.security.interfaces.RSAKey) publicKey).getModulus(); }
    }
    /** Public curve parameters only. */
    private static final class EcKey extends RemoteKey implements java.security.interfaces.ECKey {
        private EcKey(String alias, PublicKey key, Channel channel) { super(alias, key, channel); }
        @Override public java.security.spec.ECParameterSpec getParams() { return ((java.security.interfaces.ECKey) publicKey).getParams(); }
    }

    /** Public named Edwards curve parameters only. */
    private static final class EdKey extends RemoteKey implements java.security.interfaces.EdECKey {
        private EdKey(String alias, PublicKey key, Channel channel) { super(alias, key, channel); }
        @Override public java.security.spec.NamedParameterSpec getParams() { return ((java.security.interfaces.EdECKey) publicKey).getParams(); }
    }

    /** JSSE-compatible signature SPI forwarding only bounded signing input to the key owner. */
    private static final class RemoteSignature extends SignatureSpi {
        private final String algorithm;
        private final ByteArrayOutputStream message = new ByteArrayOutputStream();
        private RemoteKey key;
        private AlgorithmParameterSpec parameters;
        private RemoteSignature(String algorithm) { this.algorithm = algorithm; }
        @Override protected void engineInitVerify(PublicKey key) throws InvalidKeyException { throw new InvalidKeyException("Signing only."); }
        @Override protected void engineInitSign(PrivateKey key) throws InvalidKeyException {
            if (!(key instanceof RemoteKey remote)) throw new InvalidKeyException("Isolated key required.");
            this.key = remote; message.reset();
        }
        @Override protected void engineUpdate(byte value) throws SignatureException { engineUpdate(new byte[]{value}, 0, 1); }
        @Override protected void engineUpdate(byte[] value, int offset, int length) throws SignatureException {
            if (length > Pkcs11KeyMain.MAX_FIELD - message.size()) throw new SignatureException("Signing input exceeds limit.");
            message.write(value, offset, length);
        }
        @Override protected byte[] engineSign() throws SignatureException {
            if (key == null) throw new SignatureException("No isolated key.");
            try {
                byte[] encoded = new byte[0];
                if (parameters != null) { var p = AlgorithmParameters.getInstance("RSASSA-PSS"); p.init(parameters); encoded = p.getEncoded(); }
                return key.channel.sign(key.alias, algorithm, encoded, message.toByteArray());
            } catch (Exception failure) {
                var safe = failure instanceof AuthenticationFailure classified ? classified : new AuthenticationFailure(
                        AuthenticationFailure.Phase.PROVIDER, AuthenticationFailure.Cause.DEVICE_SESSION_LOST,
                        "The security-device helper could not complete the TLS signature.",
                        "Check the device, then use Retry to reopen its authentication session.").atInput(AuthenticationFailure.Input.SECURITY_DEVICE);
                throw new SignatureException("Isolated security-device signing failed.", safe);
            }
            finally { message.reset(); }
        }
        @Override protected boolean engineVerify(byte[] signature) throws SignatureException { throw new SignatureException("Signing only."); }
        @Override protected void engineSetParameter(AlgorithmParameterSpec value) throws InvalidAlgorithmParameterException {
            if (!(value instanceof PSSParameterSpec) || !algorithm.equals("RSASSA-PSS")) throw new InvalidAlgorithmParameterException("Unsupported signing parameters.");
            parameters = value;
        }
        @Override protected AlgorithmParameters engineGetParameters() {
            if (parameters == null) return null;
            try { var result = AlgorithmParameters.getInstance("RSASSA-PSS"); result.init(parameters); return result; }
            catch (GeneralSecurityException failure) { throw new ProviderException("Invalid signing parameters."); }
        }
        @SuppressWarnings("deprecation") @Override protected void engineSetParameter(String name, Object value) { throw new InvalidParameterException("Unsupported parameter."); }
        @SuppressWarnings("deprecation") @Override protected Object engineGetParameter(String name) { throw new InvalidParameterException("Unsupported parameter."); }
    }

    /** Read-only keystore allowing the existing fingerprint-pinned key manager to use remote keys. */
    private static final class RemoteStore extends KeyStore {
        private RemoteStore(Store store, Provider provider) throws Exception { super(store, provider, "BPSH"); load(null, null); }
    }
    /** Exposes only public chains and remote references to the standard key-manager factory. */
    private static final class Store extends KeyStoreSpi {
        private final Map<String, Certificate[]> chains;
        private final Channel channel;
        private Store(Map<String, Certificate[]> chains, Channel channel) { this.chains = Map.copyOf(chains); this.channel = channel; }
        @Override public Key engineGetKey(String alias, char[] password) { var chain = chains.get(alias); return chain == null ? null : RemoteKey.of(alias, chain[0].getPublicKey(), channel); }
        @Override public Certificate[] engineGetCertificateChain(String alias) { var chain = chains.get(alias); return chain == null ? null : chain.clone(); }
        @Override public Certificate engineGetCertificate(String alias) { var chain = chains.get(alias); return chain == null ? null : chain[0]; }
        @Override public Date engineGetCreationDate(String alias) { return chains.containsKey(alias) ? new Date(0) : null; }
        @Override public Enumeration<String> engineAliases() { return Collections.enumeration(chains.keySet()); }
        @Override public boolean engineContainsAlias(String alias) { return chains.containsKey(alias); }
        @Override public int engineSize() { return chains.size(); }
        @Override public boolean engineIsKeyEntry(String alias) { return chains.containsKey(alias); }
        @Override public boolean engineIsCertificateEntry(String alias) { return false; }
        @Override public String engineGetCertificateAlias(Certificate certificate) { return chains.entrySet().stream().filter(e -> e.getValue()[0].equals(certificate)).map(Map.Entry::getKey).findFirst().orElse(null); }
        @Override public void engineLoad(InputStream input, char[] password) { }
        @Override public void engineStore(OutputStream output, char[] password) throws IOException { throw new IOException("Read only."); }
        @Override public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException { throw new KeyStoreException("Read only."); }
        @Override public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException { throw new KeyStoreException("Read only."); }
        @Override public void engineSetCertificateEntry(String alias, Certificate certificate) throws KeyStoreException { throw new KeyStoreException("Read only."); }
        @Override public void engineDeleteEntry(String alias) throws KeyStoreException { throw new KeyStoreException("Read only."); }
    }

    /** Serializes device calls; close never takes the exchange lock and interrupts blocked socket reads. */
    private static final class Channel implements AutoCloseable {
        private final Pkcs11IdentityManager.Device device;
        private volatile Process child;
        private volatile Socket socket;
        private volatile ServerSocket listener;
        private volatile boolean closed;
        private DataInputStream input;
        private DataOutputStream output;
        private final Class<?> entryPoint;
        private Channel(Pkcs11IdentityManager.Device device, Class<?> entryPoint) { this.device = device; this.entryPoint = entryPoint; }
        /** Starts without passing credentials through arguments, files, environment or logs. */
        private void start() throws Exception {
            if (closed) throw new IOException("Device helper closed.");
            try (var ownedListener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
                listener = ownedListener; if (closed) throw new IOException("Device helper closed.");
                listener.setSoTimeout(10_000);
                byte[] token = new byte[32]; new SecureRandom().nextBytes(token);
                String executable = System.getProperty("os.name", "").startsWith("Windows") ? "javaw.exe" : "java";
                var locations = new LinkedHashSet<String>();
                for (Class<?> type : List.of(Pkcs11KeyMain.class, entryPoint)) locations.add(Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString());
                String cp = String.join(File.pathSeparator, locations);
                child = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", executable).toString(),
                        "--enable-native-access=ALL-UNNAMED", "-cp", cp, entryPoint.getName(), Integer.toString(listener.getLocalPort()))
                        .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
                if (closed) throw new IOException("Device helper closed.");
                try (var bootstrap = child.getOutputStream()) { bootstrap.write(token); }
                socket = listener.accept(); socket.setSoTimeout(45_000);
                input = new DataInputStream(socket.getInputStream()); output = new DataOutputStream(socket.getOutputStream());
                byte[] received = input.readNBytes(32);
                boolean valid = MessageDigest.isEqual(token, received); Arrays.fill(token, (byte) 0); Arrays.fill(received, (byte) 0);
                if (!valid || closed) throw new IOException("Device helper authentication failed.");
            }
        }
        /** Returns public certificates only after a definite login outcome from the child. */
        private synchronized Map<String, Certificate[]> login(char[] pin) throws Exception {
            try {
                start(); output.writeUTF(device.module().toString()); output.writeUTF(device.slot().kind().name()); output.writeLong(device.slot().value());
                if (pin.length > 4096) throw new IOException("PIN exceeds limit.");
                output.writeInt(pin.length); for (char c : pin) output.writeChar(c); output.flush(); Arrays.fill(pin, '\0');
                checkResult(); int count = input.readInt(); if (count < 0 || count > 256) throw new IOException("Certificate count exceeds limit.");
                var result = new LinkedHashMap<String, Certificate[]>(); int total = 0;
                for (int i = 0; i < count; i++) {
                    String alias = input.readUTF(); int length = input.readInt();
                    if (length < 1 || length > 16) throw new IOException("Certificate chain exceeds limit.");
                    Certificate[] chain = new Certificate[length];
                    for (int j = 0; j < length; j++) { byte[] bytes = Pkcs11KeyMain.readField(input); total += bytes.length;
                        if (total > 16 << 20) throw new IOException("Certificate metadata exceeds limit.");
                        chain[j] = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(bytes)); }
                    if (result.put(alias, chain) != null) throw new IOException("Duplicate certificate alias.");
                }
                return result;
            } catch (Exception failure) {
                close();
                if (failure instanceof AuthenticationFailure safe && safe.reason() != AuthenticationFailure.Cause.PIN_REJECTED
                        && safe.reason() != AuthenticationFailure.Cause.PIN_INDETERMINATE) {
                    var stopped = new AuthenticationFailure(safe.phase(), AuthenticationFailure.Cause.DEVICE_SESSION_LOST,
                            safe.problem(), safe.recovery() + " Use Retry to reopen the device session.");
                    throw safe.input() == null ? stopped.atInput(AuthenticationFailure.Input.SECURITY_DEVICE) : stopped.atInput(safe.input().input());
                }
                throw failure;
            }
        }
        /** A signing timeout permanently closes the helper; no native operation is automatically retried. */
        private synchronized byte[] sign(String alias, String algorithm, byte[] parameters, byte[] message) throws Exception {
            try {
                if (closed || socket == null) throw new IOException("Device helper closed.");
                output.writeUTF(alias); output.writeUTF(algorithm); Pkcs11KeyMain.writeField(output, parameters); Pkcs11KeyMain.writeField(output, message); output.flush();
                checkResult(); return Pkcs11KeyMain.readField(input);
            } catch (Exception failure) { close(); throw failure; }
        }
        /** Transfers only classifier-owned safe observations, never vendor exception strings. */
        private void checkResult() throws Exception {
            if (input.readBoolean()) return;
            var phase = AuthenticationFailure.Phase.valueOf(input.readUTF());
            var reason = AuthenticationFailure.Cause.valueOf(input.readUTF());
            var failure = new AuthenticationFailure(phase, reason, input.readUTF(), input.readUTF());
            String field = input.readUTF();
            throw field.isEmpty() ? failure : failure.atInput(AuthenticationFailure.Input.valueOf(field));
        }
        @Override public void close() {
            closed = true; ServerSocket accepting = listener;
            if (accepting != null) try { accepting.close(); } catch (IOException ignored) { /* Continue with connected resources. */ }
            Socket connection = socket;
            if (connection != null) try { connection.close(); } catch (IOException ignored) { /* Still terminate the child. */ }
            Pkcs11Processes.stop(child);
        }
    }
}
