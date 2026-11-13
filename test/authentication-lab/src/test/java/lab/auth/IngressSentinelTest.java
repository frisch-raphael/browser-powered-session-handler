package lab.auth;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import javax.net.ssl.*;
import static org.junit.jupiter.api.Assertions.*;

class IngressSentinelTest {
    @TempDir Path directory;
    @Test void preparedAuthorityRemainsValidAcrossYearsOfLocalTestRuns() throws Exception {
        var ca = LabTls.prepare(directory.resolve("long-lived-ca"));
        try (var input = java.nio.file.Files.newInputStream(ca.directory().resolve("ca.crt"))) {
            var certificate = (java.security.cert.X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(input);
            certificate.checkValidity(java.util.Date.from(java.time.Instant.now().plus(Duration.ofDays(3649))));
        }
    }
    @Test void validAndMalformedHttpBothCountBeforeAnyRouteParser() throws Exception {
        for (String input : new String[]{"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", "malformed\u0000request"}) {
            try (var sentinel = new IngressSentinel(null); var socket = new Socket()) {
                socket.connect(sentinel.address()); socket.getOutputStream().write(input.getBytes(StandardCharsets.UTF_8)); socket.shutdownOutput();
                var seen = sentinel.await(s -> s.applicationBytes() == input.getBytes(StandardCharsets.UTF_8).length, Duration.ofSeconds(2));
                assertEquals(1, seen.connections()); assertEquals(0, seen.tlsHandshakes()); assertTrue(seen.applicationBytes() > 0);
            }
        }
    }
    @Test void tlsHandshakeAloneIsNotApplicationDeliveryButDecryptedMalformedDataIs() throws Exception {
        LabTls.prepare(directory.resolve("ca")); var ca = LabTls.loadPrepared(directory.resolve("ca")); var material = LabTls.createServer(ca, directory.resolve("leaf"));
        try (var sentinel = new IngressSentinel(material.serverContext())) {
            try (var socket = (SSLSocket) material.clientContext().getSocketFactory().createSocket()) {
                socket.connect(sentinel.address()); socket.startHandshake(); sentinel.await(s -> s.tlsHandshakes() == 1, Duration.ofSeconds(2));
                assertEquals(0, sentinel.snapshot().applicationBytes());
                var cert = socket.getSession().getPeerCertificates()[0];
                assertEquals(material.fingerprint(), java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(cert.getEncoded())));
            }
            try (var socket = (SSLSocket) material.clientContext().getSocketFactory().createSocket()) {
                socket.connect(sentinel.address()); socket.startHandshake(); socket.getOutputStream().write(new byte[]{0, 1, 2}); socket.shutdownOutput();
                var seen = sentinel.await(s -> s.applicationBytes() == 3, Duration.ofSeconds(2)); assertEquals(2, seen.tlsHandshakes());
            }
        }
        var named = LabTls.createServer(ca, directory.resolve("named-leaf"), java.util.List.of("app.authlab.test", "api.authlab.test"));
        assertEquals(named.fingerprint(), LabTls.loadServer(ca, directory.resolve("named-leaf")).fingerprint());
        var metadataPath = directory.resolve("named-leaf/fingerprints.json");
        String metadata = java.nio.file.Files.readString(metadataPath);
        try {
            for (String key : java.util.List.of("caSha256", "leafSha256")) {
                var altered = com.google.gson.JsonParser.parseString(metadata).getAsJsonObject(); altered.addProperty(key, "0".repeat(64));
                java.nio.file.Files.writeString(metadataPath, LabRun.JSON.toJson(altered));
                assertThrows(java.io.IOException.class, () -> LabTls.loadServer(ca, directory.resolve("named-leaf")));
            }
        } finally { java.nio.file.Files.writeString(metadataPath, metadata); }
        named.exportServerPem();
        try (var input = java.nio.file.Files.newInputStream(named.keyStore().getParent().resolve("server-chain.pem"))) {
            var chain = java.security.cert.CertificateFactory.getInstance("X.509").generateCertificates(input); assertEquals(2, chain.size());
            assertEquals(named.fingerprint(), java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(chain.iterator().next().getEncoded())));
        }
        try (var sentinel = new IngressSentinel(named.serverContext())) {
            for (String host : java.util.List.of("app.authlab.test", "api.authlab.test", "unlisted.authlab.test")) {
                try (var plain = new Socket()) {
                    plain.connect(sentinel.address());
                    try (var socket = (SSLSocket) named.clientContext().getSocketFactory().createSocket(plain, host, sentinel.address().getPort(), true)) {
                        socket.setSoTimeout(2000); var parameters = socket.getSSLParameters(); parameters.setEndpointIdentificationAlgorithm("HTTPS"); socket.setSSLParameters(parameters);
                        if (host.startsWith("unlisted")) assertThrows(SSLHandshakeException.class, socket::startHandshake);
                        else { socket.startHandshake(); assertEquals(named.fingerprint(), java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(socket.getSession().getPeerCertificates()[0].getEncoded()))); }
                    }
                }
            }
            assertEquals(0, sentinel.snapshot().applicationBytes());
        }
        assertThrows(IllegalArgumentException.class, () -> LabTls.createServer(ca, directory.resolve("forbidden-leaf"), java.util.List.of("*.authlab.test")));
        assertFalse(java.nio.file.Files.exists(directory.resolve("forbidden-leaf")));
    }
    @Test void closingTheSentinelClosesItsActualListener() throws Exception {
        var sentinel = new IngressSentinel(null); var address = sentinel.address(); sentinel.close(); sentinel.close();
        try (var socket = new Socket()) { assertThrows(java.io.IOException.class, () -> socket.connect(address, 1000)); }
    }
}
