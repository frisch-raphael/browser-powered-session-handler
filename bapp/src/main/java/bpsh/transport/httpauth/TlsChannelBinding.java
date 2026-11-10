package bpsh.transport.httpauth;

import javax.net.ssl.SSLSession;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.spec.PSSParameterSpec;
import java.io.IOException;
import java.util.Locale;

/** RFC 5929 destination certificate binding, encoded as the MS-NLMP GSS channel-binding hash. */
final class TlsChannelBinding {
    private TlsChannelBinding() { }
    static byte[] from(SSLSession session) throws GeneralSecurityException, IOException {
        if (session == null) return null;
        X509Certificate certificate = (X509Certificate) session.getPeerCertificates()[0];
        String signature = certificate.getSigAlgName().toUpperCase(Locale.ROOT).replace("-", "");
        String digest;
        if (signature.equals("RSASSAPSS") || signature.equals("RSASSA-PSS")) {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("RSASSA-PSS");
            parameters.init(certificate.getSigAlgParams());
            digest = parameters.getParameterSpec(PSSParameterSpec.class).getDigestAlgorithm();
        } else if (signature.startsWith("SHA512")) digest = "SHA-512";
        else if (signature.startsWith("SHA384")) digest = "SHA-384";
        else if (signature.startsWith("SHA256") || signature.startsWith("SHA1") || signature.startsWith("MD5")) digest = "SHA-256";
        else throw new GeneralSecurityException("Unsupported destination certificate channel-binding algorithm.");
        if (digest.equalsIgnoreCase("SHA-1") || digest.equalsIgnoreCase("MD5")) digest = "SHA-256";
        byte[] prefix = "tls-server-end-point:".getBytes(StandardCharsets.US_ASCII);
        byte[] hash = MessageDigest.getInstance(digest).digest(certificate.getEncoded());
        ByteBuffer binding = ByteBuffer.allocate(20 + prefix.length + hash.length).order(ByteOrder.LITTLE_ENDIAN);
        binding.position(16); binding.putInt(prefix.length + hash.length).put(prefix).put(hash);
        return MessageDigest.getInstance("MD5").digest(binding.array());
    }
}
