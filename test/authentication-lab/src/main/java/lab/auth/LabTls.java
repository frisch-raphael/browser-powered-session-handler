package lab.auth;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.*;

/** Dedicated keytool material. This never changes OS/browser/global Java trust stores. */
public final class LabTls {
    private static final Set<String> HOSTS = Set.of("localhost", "127.0.0.1", "app.authlab.test", "api.authlab.test", "idp.federation.test", "idp.upstream-sso.test");
    public record PreparedCa(Path directory, FixtureIdentityStore.Secret password) {}
    public record Material(Path keyStore, FixtureIdentityStore.Secret password, Path caCertificate) {
        /** Exports only this owned leaf's PEM inputs for the provider container; the CA signing key stays private. */
        public void exportServerPem() throws Exception {
            var keys = store(keyStore, password); var certificate = new StringBuilder();
            for (var entry : keys.getCertificateChain("server")) certificate.append(pem("CERTIFICATE", entry.getEncoded()));
            Files.writeString(keyStore.getParent().resolve("server-chain.pem"), certificate, StandardOpenOption.CREATE_NEW);
            Path key = keyStore.getParent().resolve("server-key.pem"); Files.createFile(key); LabRun.restrict(key);
            byte[] encoded = keys.getKey("server", password.reveal().toCharArray()).getEncoded();
            try { Files.writeString(key, pem("PRIVATE KEY", encoded), StandardOpenOption.TRUNCATE_EXISTING); }
            finally { Arrays.fill(encoded, (byte) 0); }
        }
        public SSLContext serverContext() throws Exception {
            var keys = store(keyStore, password); var factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            factory.init(keys, password.reveal().toCharArray()); var context = SSLContext.getInstance("TLS"); context.init(factory.getKeyManagers(), null, null); return context;
        }
        public SSLContext clientContext() throws Exception {
            var trust = KeyStore.getInstance("PKCS12"); trust.load(null, null);
            try (var input = Files.newInputStream(caCertificate)) { trust.setCertificateEntry("authlab-ca", java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(input)); }
            var managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); managers.init(trust);
            var context = SSLContext.getInstance("TLS"); context.init(null, managers.getTrustManagers(), null); return context;
        }
        public String fingerprint() throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(store(keyStore, password).getCertificate("server").getEncoded())); }
    }
    private LabTls() {}
    private static String pem(String kind, byte[] encoded) { return "-----BEGIN " + kind + "-----\n" + Base64.getMimeEncoder(64, new byte[]{10}).encodeToString(encoded) + "\n-----END " + kind + "-----\n"; }
    public static PreparedCa prepare(Path directory) throws Exception {
        Files.createDirectory(directory); LabRun.restrict(directory); var password = FixtureIdentityStore.randomSecret();
        keytool(directory, password, "-genkeypair", "-alias", "ca", "-keyalg", "RSA", "-keysize", "2048", "-dname", "CN=AuthLab dedicated CA", "-validity", "7", "-ext", "BC=ca:true", "-keystore", "ca.p12");
        keytool(directory, password, "-exportcert", "-rfc", "-alias", "ca", "-keystore", "ca.p12", "-file", "ca.crt");
        LabRun.restrict(directory.resolve("ca.p12"));
        Path descriptor = directory.resolve("ca.json"); Files.writeString(descriptor, LabRun.JSON.toJson(Map.of("materialVersion", 1, "password", password.reveal(), "fingerprint", certificateHash(directory.resolve("ca.crt"))))); LabRun.restrict(descriptor);
        return new PreparedCa(directory.toRealPath(), password);
    }
    public static PreparedCa loadPrepared(Path directory) throws Exception {
        var descriptor = ScenarioCatalog.parseJson(Files.readAllBytes(directory.resolve("ca.json"))).getAsJsonObject();
        if (!descriptor.keySet().equals(Set.of("materialVersion", "password", "fingerprint")) || descriptor.get("materialVersion").getAsInt() != 1 || !certificateHash(directory.resolve("ca.crt")).equals(LabRun.text(descriptor, "fingerprint"))) throw new IOException("Invalid dedicated CA material.");
        return new PreparedCa(directory.toRealPath(), newSecret(LabRun.text(descriptor, "password")));
    }
    /** Loads an owned prepared leaf only after matching its actual chain and retained fingerprints. */
    public static Material loadServer(PreparedCa ca, Path directory) throws Exception {
        var secret = ScenarioCatalog.parseJson(Files.readAllBytes(directory.resolve("key-material.json"))).getAsJsonObject();
        var fingerprints = ScenarioCatalog.parseJson(Files.readAllBytes(directory.resolve("fingerprints.json"))).getAsJsonObject();
        if (!secret.keySet().equals(Set.of("materialVersion", "password")) || secret.get("materialVersion").getAsInt() != 1
                || !fingerprints.keySet().equals(Set.of("caSha256", "leafSha256", "coveredHosts"))
                || !certificateHash(ca.directory().resolve("ca.crt")).equals(LabRun.text(fingerprints, "caSha256")))
            throw new IOException("Invalid prepared server material.");
        var material = new Material(directory.resolve("server.p12").toRealPath(), newSecret(LabRun.text(secret, "password")), ca.directory().resolve("ca.crt"));
        var chain = store(material.keyStore(), material.password()).getCertificateChain("server");
        java.security.cert.X509Certificate authority;
        try (var input = Files.newInputStream(material.caCertificate())) {
            authority = (java.security.cert.X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(input);
        }
        if (chain == null || chain.length != 2 || !MessageDigest.isEqual(authority.getEncoded(), chain[1].getEncoded())
                || !material.fingerprint().equals(LabRun.text(fingerprints, "leafSha256"))) throw new IOException("Prepared server identity differs.");
        authority.checkValidity(); var leaf = (java.security.cert.X509Certificate) chain[0]; leaf.checkValidity(); leaf.verify(authority.getPublicKey());
        return material;
    }
    public static Material createServer(PreparedCa ca, Path directory) throws Exception {
        return createServer(ca, directory, List.of("localhost", "127.0.0.1"));
    }
    /** Creates a leaf for declared local lab roles; no wildcard or arbitrary external identity is accepted. */
    public static Material createServer(PreparedCa ca, Path directory, List<String> coveredHosts) throws Exception {
        coveredHosts = List.copyOf(coveredHosts);
        if (coveredHosts.isEmpty() || new HashSet<>(coveredHosts).size() != coveredHosts.size() || !HOSTS.containsAll(coveredHosts)) throw new IllegalArgumentException("Use distinct declared lab hosts.");
        String subject = "CN=" + coveredHosts.getFirst();
        String alternativeNames = String.join(",", coveredHosts.stream().map(host -> (host.equals("127.0.0.1") ? "ip:" : "dns:") + host).toList());
        Files.createDirectory(directory); LabRun.restrict(directory); var password = FixtureIdentityStore.randomSecret();
        keytool(directory, password, "-genkeypair", "-alias", "server", "-keyalg", "RSA", "-keysize", "2048", "-dname", subject, "-validity", "2", "-keystore", "server.p12");
        keytool(directory, password, "-certreq", "-alias", "server", "-keystore", "server.p12", "-file", "server.csr");
        keytool(directory, ca.password(), "-gencert", "-rfc", "-alias", "ca", "-keystore", ca.directory().resolve("ca.p12").toString(), "-infile", "server.csr", "-outfile", "server.crt", "-validity", "2", "-ext", "SAN=" + alternativeNames, "-ext", "EKU=serverAuth");
        keytool(directory, password, "-importcert", "-noprompt", "-alias", "ca", "-keystore", "server.p12", "-file", ca.directory().resolve("ca.crt").toString());
        keytool(directory, password, "-importcert", "-noprompt", "-alias", "server", "-keystore", "server.p12", "-file", "server.crt");
        LabRun.restrict(directory.resolve("server.p12"));
        var material = new Material(directory.resolve("server.p12").toRealPath(), password, ca.directory().resolve("ca.crt"));
        Path privateFile = directory.resolve("key-material.json"); Files.writeString(privateFile, LabRun.JSON.toJson(Map.of("materialVersion", 1, "password", password.reveal()))); LabRun.restrict(privateFile);
        Files.writeString(directory.resolve("fingerprints.json"), LabRun.JSON.toJson(Map.of("caSha256", certificateHash(ca.directory().resolve("ca.crt")), "leafSha256", material.fingerprint(), "coveredHosts", coveredHosts)));
        return material;
    }
    private static FixtureIdentityStore.Secret newSecret(String value) { return FixtureIdentityStore.secretFromPrivateMaterial(value); }
    private static String certificateHash(Path file) throws Exception {
        try (var input = Files.newInputStream(file)) { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(input).getEncoded())); }
    }
    private static KeyStore store(Path path, FixtureIdentityStore.Secret password) throws Exception {
        var result = KeyStore.getInstance("PKCS12"); try (var input = Files.newInputStream(path)) { result.load(input, password.reveal().toCharArray()); } return result;
    }
    private static void keytool(Path directory, FixtureIdentityStore.Secret password, String... arguments) throws Exception {
        String executable = Path.of(System.getProperty("java.home"), "bin", System.getProperty("os.name").startsWith("Windows") ? "keytool.exe" : "keytool").toString();
        var command = new ArrayList<>(List.of(executable)); command.addAll(List.of(arguments)); command.addAll(List.of("-storetype", "PKCS12", "-storepass:env", "AUTHLAB_STORE_PASSWORD"));
        var builder = new ProcessBuilder(command).directory(directory.toFile()).redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD);
        builder.environment().put("AUTHLAB_STORE_PASSWORD", password.reveal());
        var process = builder.start();
        try { if (!process.waitFor(15, TimeUnit.SECONDS)) { process.destroyForcibly(); throw new IOException("Dedicated certificate preparation deadline."); } if (process.exitValue() != 0) throw new IOException("Dedicated certificate preparation failed."); }
        catch (InterruptedException ex) { process.destroyForcibly(); Thread.currentThread().interrupt(); throw ex; }
    }
}
