package lab.federation;

import java.io.*;
import java.net.URI;
import java.nio.file.*;
import java.security.KeyStore;
import java.util.*;
import javax.net.ssl.*;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.MapPropertySource;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.context.ConfigurableApplicationContext;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.*;
import tools.jackson.databind.json.JsonMapper;

/** Isolated child JVM; credentials are read from an owned private settings file, never command arguments. */
@SpringBootApplication
public class FederationApplication {
    static final JsonMapper JSON = JsonMapper.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).build();

    /** Explicit role settings; string rendering never includes passwords or the private control key. */
    public record Settings(UUID invocationId, UUID runId, String caseId, long generation, String role,
                           URI clientOrigin, URI resourceOrigin, URI issuer, Path keyStore, String keyStorePassword,
                           Path caCertificate, String controlKey, String backendClientSecret, URI upstreamIssuer,Path directory) {
        public Settings {
            Objects.requireNonNull(invocationId); Objects.requireNonNull(runId);
            if (caseId == null || !caseId.matches("[A-Za-z0-9._=~-]{1,200}") || generation < 1 || !Set.of("client", "resource").contains(role))
                throw new IllegalArgumentException("Invalid federation role or case identity.");
            origin(clientOrigin, "app.authlab.test"); origin(resourceOrigin, "api.authlab.test");
            FederationSecurity.accessTokenValidator(issuer);
            if (Set.of(clientOrigin.getPort(), resourceOrigin.getPort(), issuer.getPort()).size() != 3)
                throw new IllegalArgumentException("Federation roles require distinct leased ports.");
            if(upstreamIssuer!=null&&(!upstreamIssuer.toString().matches("https://idp\\.upstream-sso\\.test:4[0-9]{4}/realms/authlab-upstream")
                    ||Set.of(clientOrigin.getPort(),resourceOrigin.getPort(),issuer.getPort()).contains(upstreamIssuer.getPort())))
                throw new IllegalArgumentException("Use the prepared distinct upstream issuer.");
            if (keyStorePassword == null || keyStorePassword.isBlank() || controlKey == null || !controlKey.matches("[A-Za-z0-9_-]{43}")
                    || role.equals("client") && (backendClientSecret == null || backendClientSecret.isBlank()))
                throw new IllegalArgumentException("Required private federation settings are absent.");
            Objects.requireNonNull(keyStore); Objects.requireNonNull(caCertificate); Objects.requireNonNull(directory);
        }
        public URI applicationOrigin() { return role.equals("client") ? clientOrigin : resourceOrigin; }
        @Override public String toString() { return "FederationSettings[role=" + role + ", runId=" + runId + ", generation=" + generation + "]"; }
    }

    /** Validates exact host/origin identities without accepting URL credentials or implicit ports. */
    private static void origin(URI value, String host) {
        if (value == null || !"https".equals(value.getScheme()) || !host.equals(value.getHost()) || value.getPort() < 40000 || value.getPort() > 49999
                || value.getRawUserInfo() != null || value.getRawQuery() != null || value.getRawFragment() != null
                || value.getRawPath() != null && !value.getRawPath().isEmpty()) throw new IllegalArgumentException("Use the prepared named HTTPS origin.");
    }

    /** Reads closed-field bounded JSON and replaces parser details with safe startup guidance. */
    static Settings readSettings(Path path) throws IOException {
        try {
            if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.size(path) > 65_536) throw new IOException();
            byte[] bytes;
            try (var input = Files.newInputStream(path)) { bytes = input.readNBytes(65_537); }
            if (bytes.length > 65_536) throw new IOException();
            JsonNode n = JSON.readTree(bytes);
            var keys = Set.of("settingsVersion", "invocationId", "runId", "caseId", "generation", "role", "clientOrigin", "resourceOrigin", "issuer",
                    "keyStore", "keyStorePassword", "caCertificate", "controlKey", "backendClientSecret","upstreamIssuer");
            if (!n.isObject() || !new HashSet<>(n.propertyNames()).equals(keys) || !n.get("settingsVersion").isIntegralNumber()
                    || !n.get("settingsVersion").canConvertToInt() || n.get("settingsVersion").asInt() != 2 || !n.get("generation").isIntegralNumber() || !n.get("generation").canConvertToLong()) throw new IOException();
            return new Settings(UUID.fromString(text(n, "invocationId")), UUID.fromString(text(n, "runId")), text(n, "caseId"), n.get("generation").asLong(),
                    text(n, "role"), URI.create(text(n, "clientOrigin")), URI.create(text(n, "resourceOrigin")), URI.create(text(n, "issuer")),
                    ownedInput(path, text(n, "keyStore")), text(n, "keyStorePassword"), ownedInput(path, text(n, "caCertificate")), text(n, "controlKey"),
                    n.get("backendClientSecret").isNull() ? null : text(n, "backendClientSecret"),n.get("upstreamIssuer").isNull()?null:URI.create(text(n,"upstreamIssuer")), path.toRealPath().getParent());
        } catch (Exception error) { throw new IOException("Invalid private federation settings."); }
    }

    /** Keeps launch inputs inside the run-owned material directory, rejecting symlink escape. */
    private static Path ownedInput(Path settings, String value) throws IOException {
        Path root = settings.toRealPath().getParent(); Path file = root.resolve(value).normalize();
        if (!file.startsWith(root) || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) || !file.toRealPath().startsWith(root)) throw new IOException();
        return file.toRealPath();
    }
    private static String text(JsonNode n, String key) {
        if (!n.get(key).isString()) throw new IllegalArgumentException(); return n.get(key).asString();
    }

    /** Builds a run-scoped trust context; normal Java and browser trust stores remain unchanged. */
    static SSLContext trust(Settings settings) throws Exception {
        var store = KeyStore.getInstance("PKCS12"); store.load(null, null);
        try (var input = Files.newInputStream(settings.caCertificate())) {
            var cert = java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(input);
            ((java.security.cert.X509Certificate) cert).checkValidity(); store.setCertificateEntry("authlab", cert);
        }
        var factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); factory.init(store);
        var context = SSLContext.getInstance("TLS"); context.init(null, factory.getTrustManagers(), null); return context;
    }

    /** Starts only after validating private launch settings; failed startup publishes no readiness. */
    public static void main(String[] args) {
        boolean started = false;
        try {
            if (args.length != 2 || !args[0].equals("--settings")) throw new IllegalArgumentException();
            Settings settings = readSettings(Path.of(args[1]));
            if(settings.role().equals("client"))verifyBrowserAdapter();
            var app = new SpringApplication(FederationApplication.class); app.setLogStartupInfo(false);
            app.setBannerMode(org.springframework.boot.Banner.Mode.OFF); app.setAddCommandLineProperties(false);
            Map<String,Object> properties = new LinkedHashMap<>();
            properties.put("server.address", "127.0.0.1"); properties.put("server.port", settings.applicationOrigin().getPort());
            properties.put("server.ssl.enabled", true); properties.put("server.ssl.key-store", settings.keyStore().toUri().toString());
            properties.put("server.ssl.key-store-password", settings.keyStorePassword()); properties.put("server.ssl.key-store-type", "PKCS12");
            properties.put("server.ssl.key-alias", "server"); properties.put("server.error.include-message", "never");
            properties.put("server.error.include-stacktrace", "never"); properties.put("logging.level.root", "OFF");
            properties.put("server.servlet.session.timeout", "90s"); properties.put("server.servlet.session.cookie.name", "LAB_TRANSACTION");
            properties.put("server.servlet.session.cookie.http-only", true); properties.put("server.servlet.session.cookie.secure", true);
            properties.put("server.servlet.session.cookie.same-site", "none"); properties.put("server.servlet.session.cookie.path", "/");
            properties.put("server.servlet.session.tracking-modes", "cookie");
            properties.put("lab.federation.role", settings.role());
            app.setDefaultProperties(properties);
            app.addInitializers(context -> { context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("owned-federation", properties));
                context.getBeanFactory().registerSingleton("federationSettings", settings); });
            var context = app.run(); started = true;
            context.getBean(FederationControl.class).awaitClosed();
        } catch (Exception error) { System.err.println(started ? "Federation role stopped with incomplete cleanup." : "Federation role startup failed; no readiness is established."); System.exit(3); }
    }

    @Bean SSLContext federationTrust(Settings settings) throws Exception { return trust(settings); }
    @Bean
    JwtDecoder resourceDecoder(Settings settings, SSLContext federationTrust) { return FederationSecurity.providerDecoder(settings.issuer(), federationTrust); }
    @Bean @ConditionalOnProperty(name="lab.federation.role", havingValue="resource")
    SecurityFilterChain resourceSecurity(HttpSecurity http, JwtDecoder resourceDecoder, Settings settings) throws Exception {
        return FederationSecurity.resourceChain(http, resourceDecoder, settings);
    }
    @Bean @ConditionalOnProperty(name="lab.federation.role", havingValue="client")
    org.springframework.security.oauth2.client.registration.ClientRegistrationRepository backendRegistrations(Settings settings,FederationProtocol protocol) { return FederationOAuth.registrations(settings,protocol); }
    @Bean @ConditionalOnProperty(name="lab.federation.role", havingValue="client")
    FederationProtocol federationProtocol(Settings settings) { return new FederationProtocol(settings); }
    @Bean @ConditionalOnProperty(name="lab.federation.role", havingValue="client")
    org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository authorizedClients() { return new org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository(); }
    @Bean @ConditionalOnProperty(name="lab.federation.role", havingValue="client")
    org.springframework.security.oauth2.jwt.JwtDecoderFactory<org.springframework.security.oauth2.client.registration.ClientRegistration> idTokenDecoders(SSLContext federationTrust) { return FederationOAuth.idTokens(federationTrust); }
    @Bean @ConditionalOnProperty(name="lab.federation.role", havingValue="client")
    org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository samlRegistrations(Settings settings,SSLContext federationTrust) throws Exception { return FederationSaml.registrations(settings,federationTrust); }
    @Bean @ConditionalOnProperty(name="lab.federation.role", havingValue="client")
    SecurityFilterChain clientSecurity(HttpSecurity http, org.springframework.security.oauth2.client.registration.ClientRegistrationRepository registrations,
            JwtDecoder resourceDecoder, SSLContext federationTrust, org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository clients,
            FederationClientEndpoints endpoints,org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository samlRegistrations,Settings settings,FederationProtocol protocol) throws Exception {
        return FederationOAuth.security(http,registrations,resourceDecoder,federationTrust,clients,endpoints,samlRegistrations,settings,protocol);
    }
    @Bean FederationControl federationControl(Settings settings, ConfigurableApplicationContext context) throws IOException { return new FederationControl(settings, context); }

    /** A client cannot become ready with a missing or modified browser adapter. */
    private static void verifyBrowserAdapter() throws Exception {
        try(var lock=FederationApplication.class.getResourceAsStream("/provider/provider-lock.json")) {
            if(lock==null)throw new IOException("Prepared browser adapter lock absent.");
            var expected=JSON.readTree(lock).path("browserAdapter");
            verifyModule("keycloak.js",expected.path("moduleBytes").asInt(),expected.path("moduleSha256").asString());
            if(!expected.path("imports").isArray())throw new IOException("Prepared adapter import inventory absent.");
            for(var imported:expected.path("imports"))verifyModule(imported.path("file").asString(),imported.path("bytes").asInt(),imported.path("sha256").asString());
        }
    }
    private static void verifyModule(String file,int size,String hash) throws Exception {
        if(!file.matches("[A-Za-z0-9_-]+\\.js")||size<1||size>1_048_576||!hash.matches("[a-f0-9]{64}"))throw new IOException("Invalid browser adapter module declaration.");
        try(var module=FederationApplication.class.getResourceAsStream("/static/vendor/"+file)) {
            if(module==null)throw new IOException("Prepared browser adapter module absent.");byte[] bytes=module.readNBytes(size+1);
            if(bytes.length!=size||!HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes)).equals(hash))throw new IOException("Prepared browser adapter module identity differs.");
        }
    }
}
