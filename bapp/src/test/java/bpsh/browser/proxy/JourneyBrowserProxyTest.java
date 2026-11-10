package bpsh.browser.proxy;

import bpsh.journey.HttpAuthentication;
import bpsh.support.IntegrationFixtures;
import bpsh.transport.httpauth.HttpClientAuthenticationTransport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Base64;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

class JourneyBrowserProxyTest {
    @TempDir Path temporary;

    @ParameterizedTest @EnumSource(HttpAuthentication.Protocol.class)
    void browserTunnelUsesSharedAuthenticationBeforeReceivingProtectedPage(HttpAuthentication.Protocol protocol) throws Exception {
        var ca=lab.auth.LabTls.prepare(temporary.resolve("ca"));
        var tls=lab.auth.LabTls.createServer(ca,temporary.resolve("server"));
        AtomicReference<Throwable> failure=new AtomicReference<>();
        try(var lab=IntegrationFixtures.httpAuthentication(protocol.name(),tls.serverContext());
            var workers=Executors.newFixedThreadPool(4);var deadlines=Executors.newSingleThreadScheduledExecutor();
            var service=new HttpClientAuthenticationTransport(new HttpAuthentication(protocol,"user-a","LAB","",Set.of(lab.url("/"))),
                    "alpha-password".toCharArray(),tls.clientContext(),workers,deadlines);
            var proxy=new JourneyBrowserProxy(uri->service,new bpsh.authentication.http.HttpMessageBody.Allocator(64L*1024*1024),Clock.systemUTC(),System.nanoTime()+TimeUnit.SECONDS.toNanos(30),failure::set)) {
            try(Socket unauthenticated=new Socket()) {
                unauthenticated.connect(proxy.address());unauthenticated.setSoTimeout(5000);
                unauthenticated.getOutputStream().write(("CONNECT "+lab.url("/").getAuthority()+" HTTP/1.1\r\nHost: "+lab.url("/").getAuthority()+"\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                assertTrue(headers(unauthenticated.getInputStream()).startsWith("HTTP/1.1 407"));
                assertEquals(0,lab.handshakes.get());
            }
            try(Socket browser=tunnel(proxy,lab.url("/"))) {
                String response=get(browser,lab.url("/whoami"),false);
                assertTrue(response.contains("\"user\":\"user-a\""));
                assertTrue(response.contains("\"protocol\":\""+protocol.name()+"\""));
                assertTrue(get(browser,lab.url("/whoami"),false).contains("\"user\":\"user-a\""));
            }
            if(protocol!=HttpAuthentication.Protocol.BASIC)assertEquals(1,lab.handshakes.get());
            assertEquals(0,lab.leakedDirectives.get());assertNull(failure.get());
        }
    }

    @ParameterizedTest @EnumSource(HttpAuthentication.Protocol.class)
    void forwarderUsesTheInjectedRuntimeForItsProtectedPage(HttpAuthentication.Protocol protocol) throws Exception {
        try(var lab=IntegrationFixtures.httpAuthentication(protocol.name(),null);
            var runtime=new bpsh.transport.httpauth.HttpTransportRuntime()) {
            var setup=new bpsh.journey.BrowserSetup(lab.url("/"),
                    new bpsh.journey.JourneyDefinition.Browser(true,null,30000,3000),null,
                    new HttpAuthentication(protocol,"user-a","LAB","",Set.of(lab.url("/"))));
            try(var proxy=bpsh.support.IntegrationFixtures.browserProxy(runtime,setup,null,"alpha-password".toCharArray(),Clock.systemUTC(),
                    System.nanoTime()+TimeUnit.SECONDS.toNanos(20));var browser=new Socket()) {
                browser.connect(proxy.address());browser.setSoTimeout(5000);
                var options=proxy.browserProxy();
                String credentials=Base64.getEncoder().encodeToString((options.username+":"+options.password).getBytes(StandardCharsets.UTF_8));
                browser.getOutputStream().write(("GET "+lab.url("/whoami")+" HTTP/1.1\r\nHost: "+lab.url("/").getAuthority()+
                        "\r\nProxy-Authorization: Basic "+credentials+"\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                String head=headers(browser.getInputStream());assertTrue(head.startsWith("HTTP/1.1 200"),head);
                String body=new String(browser.getInputStream().readAllBytes(),StandardCharsets.UTF_8);
                assertTrue(body.contains("user-a"),body);
                assertEquals(protocol,proxy.authentication().protocol());
                assertEquals(1,lab.handshakes.get());
                assertNull(proxy.failure());
            }
        }
    }

    @Test void browserTrustConsentAppliesOnlyToItsOwnAttempt() throws Exception {
        var ca=lab.auth.LabTls.prepare(temporary.resolve("consent-ca"));
        var tls=lab.auth.LabTls.createServer(ca,temporary.resolve("consent-server"));
        try(var lab=IntegrationFixtures.httpAuthentication("NTLM_V2",tls.serverContext());
            var runtime=new bpsh.transport.httpauth.HttpTransportRuntime()) {
            var auth=new HttpAuthentication(HttpAuthentication.Protocol.NTLM_V2,"user-a","LAB","",Set.of(lab.url("/")));
            for(boolean consent:new boolean[]{true,false}) {
                var setup=new bpsh.journey.BrowserSetup(lab.url("/"),
                        new bpsh.journey.JourneyDefinition.Browser(true,null,30000,3000,consent),null,auth);
                try(var forwarder=bpsh.support.IntegrationFixtures.browserProxy(runtime,setup,null,"alpha-password".toCharArray(),Clock.systemUTC(),
                        System.nanoTime()+TimeUnit.SECONDS.toNanos(20))) {
                    try(var browser=tunnel(forwarder.address(),forwarder.browserProxy(),forwarder.spkiSha256(),lab.url("/"))) {
                        browser.getOutputStream().write(("GET /whoami HTTP/1.1\r\nHost: "+lab.url("/").getAuthority()+
                                "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                        String head=headers(browser.getInputStream());
                        assertTrue(head.startsWith(consent?"HTTP/1.1 200":"HTTP/1.1 502"),head);
                    }
                }
            }
            assertEquals(1,lab.handshakes.get());
        }
    }

    @Test void abandonedLocalTlsHandshakeDoesNotPoisonOtherBrowserChannels() throws Exception {
        var ca=lab.auth.LabTls.prepare(temporary.resolve("abandoned-ca"));
        var tls=lab.auth.LabTls.createServer(ca,temporary.resolve("abandoned-server"));
        AtomicReference<Throwable> failure=new AtomicReference<>();
        try(var lab=IntegrationFixtures.httpAuthentication("BASIC",tls.serverContext());
            var workers=Executors.newFixedThreadPool(2);var deadlines=Executors.newSingleThreadScheduledExecutor();
            var service=new HttpClientAuthenticationTransport(new HttpAuthentication(HttpAuthentication.Protocol.BASIC,"user-a","LAB","",Set.of(lab.url("/"))),
                    "alpha-password".toCharArray(),tls.clientContext(),workers,deadlines);
            var proxy=new JourneyBrowserProxy(uri->service,new bpsh.authentication.http.HttpMessageBody.Allocator(64L*1024*1024),Clock.systemUTC(),System.nanoTime()+TimeUnit.SECONDS.toNanos(20),failure::set)) {
            try(var abandoned=new Socket()) {
                abandoned.connect(proxy.address());abandoned.setSoTimeout(5000);var options=proxy.browserProxy();
                String credentials=Base64.getEncoder().encodeToString((options.username+":"+options.password).getBytes(StandardCharsets.UTF_8));
                abandoned.getOutputStream().write(("CONNECT "+lab.url("/").getAuthority()+" HTTP/1.1\r\nHost: "+lab.url("/").getAuthority()+
                        "\r\nProxy-Authorization: Basic "+credentials+"\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                assertTrue(headers(abandoned.getInputStream()).startsWith("HTTP/1.1 200"));
                abandoned.getOutputStream().write("This is not a TLS handshake".getBytes(StandardCharsets.US_ASCII));
                abandoned.getOutputStream().flush();assertEquals(-1,abandoned.getInputStream().read());
            }
            try(var browser=tunnel(proxy,lab.url("/"))) {assertTrue(get(browser,lab.url("/whoami"),true).contains("user-a"));}
            assertNull(failure.get());assertEquals(1,lab.handshakes.get());
        }
    }

    @Test void slowDestinationDoesNotBlockTheIngressEventLoops() throws Exception {
        var entered=new java.util.concurrent.CountDownLatch(1);
        var released=new java.util.concurrent.CompletableFuture<bpsh.authentication.http.HttpAuthenticationService.Response>();
        bpsh.authentication.http.HttpAuthenticationService service=new bpsh.authentication.http.HttpAuthenticationService() {
            @Override public boolean isOpen() {return true;}
            @Override public Delivery admit(long deadline) {return bpsh.support.IntegrationFixtures.httpDelivery(request->{
                if(request.uri().getPath().equals("/slow")) {entered.countDown();return released;}
                return java.util.concurrent.CompletableFuture.completedFuture(response("fast"));
            });}
            @Override public void close() {released.cancel(true);}
        };
        try(service;var executor=Executors.newFixedThreadPool(2);
            var proxy=new JourneyBrowserProxy(uri->service,new bpsh.authentication.http.HttpMessageBody.Allocator(64L*1024*1024),Clock.systemUTC(),System.nanoTime()+TimeUnit.SECONDS.toNanos(10),ignored->{})) {
            URI origin=URI.create("https://127.0.0.1:8443/");
            var slow=executor.submit(()->{try(Socket browser=tunnel(proxy,origin)) {return get(browser,origin.resolve("/slow"),false);}});
            assertTrue(entered.await(5,TimeUnit.SECONDS));
            try(Socket browser=tunnel(proxy,origin)) {assertEquals("fast",get(browser,origin.resolve("/fast"),false));}
            assertFalse(slow.isDone());released.complete(response("finished"));assertEquals("finished",slow.get(5,TimeUnit.SECONDS));
        }
    }

    @Test void aTunnelCannotChangeItsDestinationAndClosingItCancelsItsExchange() throws Exception {
        var pending=new java.util.concurrent.CompletableFuture<bpsh.authentication.http.HttpAuthenticationService.Response>();
        var entered=new java.util.concurrent.CountDownLatch(1);
        bpsh.authentication.http.HttpAuthenticationService service=new bpsh.authentication.http.HttpAuthenticationService() {
            @Override public boolean isOpen() {return true;}
            @Override public Delivery admit(long deadline) {return bpsh.support.IntegrationFixtures.httpDelivery(request->{entered.countDown();return pending;});}
            @Override public void close() {pending.cancel(true);}
        };
        try(service;var proxy=new JourneyBrowserProxy(uri->service,new bpsh.authentication.http.HttpMessageBody.Allocator(64L*1024*1024),Clock.systemUTC(),System.nanoTime()+TimeUnit.SECONDS.toNanos(10),ignored->{})) {
            URI origin=URI.create("https://127.0.0.1:8443/");
            try(Socket browser=tunnel(proxy,origin)) {
                browser.getOutputStream().write("GET https://localhost:8443/ HTTP/1.1\r\nHost: localhost:8443\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
                assertTrue(headers(browser.getInputStream()).startsWith("HTTP/1.1 502"));assertEquals(1,entered.getCount());
            }
            Socket browser=tunnel(proxy,origin);
            browser.getOutputStream().write("GET / HTTP/1.1\r\nHost: 127.0.0.1:8443\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
            assertTrue(entered.await(5,TimeUnit.SECONDS));browser.close();
            // Explicit scope close must cancel even while reads are paused for backpressure.
            proxy.close();assertTrue(pending.isCancelled());
        }
    }

    private static bpsh.authentication.http.HttpAuthenticationService.Response response(String text) {
        return new bpsh.authentication.http.HttpAuthenticationService.Response(200,java.util.List.of(),bpsh.support.IntegrationFixtures.httpBody(text.getBytes(StandardCharsets.UTF_8)),
                new bpsh.authentication.http.HttpAuthenticationEvidence(null,bpsh.authentication.http.HttpAuthenticationEvidence.Status.UNCONFIRMED));
    }
    private static Socket tunnel(JourneyBrowserProxy proxy,URI origin) throws Exception {
        return tunnel(proxy.address(),proxy.browserProxy(),proxy.spkiSha256(),origin);
    }
    private static Socket tunnel(java.net.InetSocketAddress address,com.microsoft.playwright.options.Proxy options,String pin,URI origin) throws Exception {
        Socket socket=new Socket();socket.connect(address);socket.setSoTimeout(5000);
        String authorization=Base64.getEncoder().encodeToString((options.username+":"+options.password).getBytes(StandardCharsets.UTF_8));
        socket.getOutputStream().write(("CONNECT "+origin.getAuthority()+" HTTP/1.1\r\nHost: "+origin.getAuthority()+"\r\nProxy-Authorization: Basic "+authorization+"\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
        assertTrue(headers(socket.getInputStream()).startsWith("HTTP/1.1 200"));
        SSLContext trust=SSLContext.getInstance("TLS");
        trust.init(null,new TrustManager[]{new X509TrustManager() {
            @Override public void checkClientTrusted(X509Certificate[] certificates,String auth) throws CertificateException {throw new CertificateException("No client trust.");}
            @Override public void checkServerTrusted(X509Certificate[] certificates,String auth) throws CertificateException {
                try {
                    String observedPin=Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(certificates[0].getPublicKey().getEncoded()));
                    if(!pin.equals(observedPin))throw new CertificateException("Wrong attempt key.");
                    certificates[0].checkValidity();certificates[0].verify(certificates[0].getPublicKey());
                } catch(Exception error) {throw new CertificateException("Invalid attempt certificate.",error);}
            }
            @Override public X509Certificate[] getAcceptedIssuers() {return new X509Certificate[0];}
        }},null);
        SSLSocket browser=(SSLSocket)trust.getSocketFactory().createSocket(socket,origin.getHost(),origin.getPort(),true);
        var parameters=browser.getSSLParameters();parameters.setEndpointIdentificationAlgorithm("HTTPS");browser.setSSLParameters(parameters);browser.startHandshake();return browser;
    }
    private static String get(Socket socket,URI target,boolean close) throws Exception {
        socket.getOutputStream().write(("GET "+target.getRawPath()+" HTTP/1.1\r\nHost: "+target.getAuthority()+"\r\n"+(close?"Connection: close\r\n":"")+"\r\n").getBytes(StandardCharsets.US_ASCII));
        String headers=headers(socket.getInputStream());assertTrue(headers.startsWith("HTTP/1.1 200"),headers);
        int length=0;for(String line:headers.split("\r\n"))if(line.toLowerCase(java.util.Locale.ROOT).startsWith("content-length:"))length=Integer.parseInt(line.substring(15).trim());
        return new String(socket.getInputStream().readNBytes(length),StandardCharsets.UTF_8);
    }
    private static String headers(InputStream input) throws Exception {
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();int suffix=0;
        while(bytes.size()<65536) {int next=input.read();if(next<0)throw new java.io.EOFException();bytes.write(next);suffix=(suffix<<8)|next;if(suffix==0x0d0a0d0a)return bytes.toString(StandardCharsets.US_ASCII);}
        throw new java.io.IOException("Header limit.");
    }
}
