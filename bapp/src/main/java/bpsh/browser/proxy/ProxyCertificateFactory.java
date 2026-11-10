package bpsh.browser.proxy;

import java.math.BigInteger;
import java.net.IDN;
import java.net.InetAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Locale;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Creates ephemeral host-appropriate browser-facing certificates for one owned mTLS proxy key.
 *
 * Certificate construction uses Bouncy Castle builders with ordinary JDK RSA signing, never
 * JDK-internal certificate APIs, global JCE registration, OpenSSL or an installed CA. Only the
 * owned Chromium process receives this key's SPKI exception; upstream verification is separate.
 */
public final class ProxyCertificateFactory implements AutoCloseable {
    private KeyPair keys;
    private final Clock clock;
    private final String spki;
    private final LinkedHashMap<String, SSLContext> contexts = new LinkedHashMap<>(16, 0.75f, true);

    /**
     * Generates one attempt-owned RSA key, without persisting any private material.
     * @param clock Clock for short certificate validity windows.
     * @throws Exception If the JVM cannot generate/sign the ephemeral proxy identity.
     */
    public ProxyCertificateFactory(Clock clock) throws Exception {
        this.clock = clock; KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); keys = generator.generateKeyPair();
        spki = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(keys.getPublic().getEncoded()));
    }

    /**
     * Returns the public-key SPKI hash for this proxy only, suitable for the owned Chromium flag.
     *
     * @return The public-key SPKI hash for this proxy only, suitable for the owned Chromium flag.
     */
    public String spkiSha256() { return spki; }

    /**
     * Returns a host-specific inbound server engine with no browser client-certificate request.
     * @param host Exact verified upstream peer hostname/IP from the CONNECT handshake.
     * @return Fresh server-mode engine; at most 128 host contexts are retained per attempt.
     * @throws Exception If the hostname is invalid, issuance fails or this factory is closed.
     */
    public synchronized SSLEngine engine(String host) throws Exception {
        if (keys == null) throw new IllegalStateException("Proxy certificate factory is closed.");
        String canonical = host(host); SSLContext context = contexts.get(canonical);
        if (context == null) {
            X509Certificate certificate = certificate(canonical); char[] password = new char[32];
            byte[] random = new byte[32]; new SecureRandom().nextBytes(random); for (int i = 0; i < password.length; i++) password[i] = (char) ('A' + (random[i] & 15)); Arrays.fill(random, (byte) 0);
            try {
                KeyStore store = KeyStore.getInstance("JKS"); store.load(null, null); store.setKeyEntry("owned-proxy", keys.getPrivate(), password, new java.security.cert.Certificate[]{certificate});
                KeyManagerFactory managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()); managers.init(store, password);
                context = SSLContext.getInstance("TLS"); context.init(managers.getKeyManagers(), null, new SecureRandom());
                context.getServerSessionContext().setSessionCacheSize(64); context.getServerSessionContext().setSessionTimeout(300); contexts.put(canonical, context);
                while (contexts.size() > 128) contexts.remove(contexts.keySet().iterator().next());
            } finally { Arrays.fill(password, '\0'); }
        }
        SSLEngine engine = context.createSSLEngine(); engine.setUseClientMode(false); engine.setNeedClientAuth(false); return engine;
    }

    /**
     * Builds a self-signed leaf with a DNS/IP SAN; the same attempt-owned key signs each host leaf.
     * @param host Validated canonical hostname/IP.
     * @return Short-lived public leaf certificate, never a globally installed trust anchor.
     * @throws Exception If certificate construction/signature conversion fails.
     */
    synchronized X509Certificate certificate(String host) throws Exception {
        if (keys == null) throw new IllegalStateException("Proxy certificate factory is closed.");
        String value = host(host); boolean ip = value.contains(":") || value.matches("[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+");
        X500Name name = new X500Name("CN=BPSH owned authentication proxy");
        var builder = new JcaX509v3CertificateBuilder(name, new BigInteger(159, new SecureRandom()).add(BigInteger.ONE),
                Date.from(clock.instant().minus(5, ChronoUnit.MINUTES)), Date.from(clock.instant().plus(1, ChronoUnit.DAYS)), name, keys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName(ip ? GeneralName.iPAddress : GeneralName.dNSName, value)));
        return new JcaX509CertificateConverter().getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(keys.getPrivate())));
    }

    /**
     * Validates DNS/IP SAN input without resolving DNS or embedding it into an X.500 subject string.
     * @param host Peer name supplied by the authenticated proxy's TLS engine creation.
     * @return Canonical ASCII DNS or numeric IP spelling.
     * @throws Exception If invalid, blank or unsupported literal syntax is supplied.
     */
    private static String host(String host) throws Exception {
        if (host == null || host.isBlank() || host.indexOf('\0') >= 0) throw new IllegalArgumentException("Invalid proxy certificate host.");
        String value = host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
        if (value.contains(":") || value.matches("[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+")) return InetAddress.getByName(value).getHostAddress();
        value = IDN.toASCII(value, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
        if (value.length() > 253) throw new IllegalArgumentException("Invalid proxy certificate hostname."); return value;
    }

    /** Drops owned context/key references after proxy channels close; no global trust/provider state is changed. */
    @Override public synchronized void close() { contexts.clear(); keys = null; }
}
