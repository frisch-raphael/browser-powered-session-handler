package bpsh.mtls;

import java.security.MessageDigest;
import java.security.Security;
import java.time.Clock;
import java.util.Arrays;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Verifies certificate construction without a browser, token, trust-store change or global BC provider. */
class ProxyCertificateFactoryTest {
    @Test void issuedLeavesHaveHostSansAndTheAttemptKeySpkiWithoutProviderMutation() throws Exception {
        var providers = Arrays.stream(Security.getProviders()).map(p -> p.getName()).toList();
        try (var factory = new ProxyCertificateFactory(Clock.systemUTC())) {
            for (String host : java.util.List.of("localhost", "127.0.0.1", "::1")) {
                var certificate = factory.certificate(host); certificate.checkValidity(); certificate.verify(certificate.getPublicKey());
                assertEquals(factory.spkiSha256(), Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(certificate.getPublicKey().getEncoded())));
                assertNotNull(certificate.getSubjectAlternativeNames()); assertFalse(factory.engine(host).getUseClientMode());
                assertFalse(factory.engine(host).getNeedClientAuth());
            }
        }
        assertEquals(providers, Arrays.stream(Security.getProviders()).map(p -> p.getName()).toList());
    }
}
