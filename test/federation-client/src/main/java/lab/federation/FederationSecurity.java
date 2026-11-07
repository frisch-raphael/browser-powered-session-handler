package lab.federation;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.List;
import javax.net.ssl.SSLContext;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.http.HttpMethod;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/** Maintained resource-token validation shared by the future HTTP roles and isolated consumer controls. */
public final class FederationSecurity {
    private FederationSecurity() {}

    /** Creates a bearer-only resource chain; no form login, cookie session or Basic authentication can satisfy it. */
    static SecurityFilterChain resourceChain(HttpSecurity http, JwtDecoder decoder, FederationApplication.Settings settings) throws Exception {
        var cors = new CorsConfiguration(); cors.setAllowedOrigins(List.of(settings.clientOrigin().toString()));
        cors.setAllowedMethods(List.of("GET")); cors.setAllowedHeaders(List.of("Authorization")); cors.setAllowCredentials(false);
        var corsSource = new UrlBasedCorsConfigurationSource(); corsSource.registerCorsConfiguration("/api/me", cors);
        org.springframework.security.web.AuthenticationEntryPoint denied = (request, response, error) -> {
            response.setStatus(401); response.setContentType("application/json"); response.getWriter().write("{\"error\":\"access_token_rejected\"}");
        };
        http.csrf(c -> c.disable()).cors(c -> c.configurationSource(corsSource))
                .sessionManagement(c -> c.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .formLogin(c -> c.disable()).httpBasic(c -> c.disable())
                .authorizeHttpRequests(c -> c.requestMatchers(HttpMethod.GET, "/api/me").authenticated().anyRequest().denyAll())
                .exceptionHandling(c -> c.authenticationEntryPoint(denied))
                .oauth2ResourceServer(c -> c.jwt(j -> j.decoder(decoder)).authenticationEntryPoint(denied));
        return http.build();
    }

    /**
     * Builds the real provider decoder with explicit signature algorithm and scoped CA trust.
     * No JVM trust store, browser policy or hostname verifier is changed.
     *
     * @param issuer Exact prepared downstream issuer.
     * @param dedicatedTrust Trust context containing the prepared lab CA.
     * @return Lazily fetched provider-key decoder; construction alone proves no provider access.
     */
    public static NimbusJwtDecoder providerDecoder(URI issuer, SSLContext dedicatedTrust) {
        requireIssuer(issuer);
        var client = HttpClient.newBuilder().sslContext(java.util.Objects.requireNonNull(dedicatedTrust))
                .proxy(new java.net.ProxySelector() {
                    @Override public List<java.net.Proxy> select(URI uri) { return List.of(java.net.Proxy.NO_PROXY); }
                    @Override public void connectFailed(URI uri, java.net.SocketAddress address, java.io.IOException error) { }
                })
                .followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(2)).build();
        var requests = new JdkClientHttpRequestFactory(client); requests.setReadTimeout(Duration.ofSeconds(5));
        var decoder = NimbusJwtDecoder.withJwkSetUri(issuer + "/protocol/openid-connect/certs")
                .jwsAlgorithm(SignatureAlgorithm.RS256).restOperations(new RestTemplate(requests)).build();
        return configureAccessDecoder(decoder, issuer);
    }

    /** Retains original claim absence instead of accepting the converter's synthesized issued-at value. */
    static NimbusJwtDecoder configureAccessDecoder(NimbusJwtDecoder decoder, URI issuer) {
        requireIssuer(issuer);
        var standardClaims = MappedJwtClaimSetConverter.withDefaults(java.util.Map.of());
        decoder.setClaimSetConverter(claims -> {
            var converted = standardClaims.convert(claims);
            if (!claims.containsKey("iat")) converted.remove("iat");
            return converted;
        });
        decoder.setJwtValidator(accessTokenValidator(issuer));
        return decoder;
    }

    /**
     * Requires signature-verified Keycloak access tokens for this API, with no expiry grace period.
     * The JWT header's type alone cannot distinguish an ID token from a Keycloak access token.
     *
     * @param issuer Exact configured downstream issuer.
     * @return Claim validators applied after the maintained decoder verifies the signature.
     */
    public static OAuth2TokenValidator<Jwt> accessTokenValidator(URI issuer) {
        requireIssuer(issuer);
        OAuth2TokenValidator<Jwt> required = token -> {
            var audiences = token.getAudience();
            boolean accepted = token.getExpiresAt() != null && token.getIssuedAt() != null
                    && token.getSubject() != null && !token.getSubject().isBlank()
                    && audiences != null && audiences.contains("authlab-api")
                    && "Bearer".equals(token.getClaims().get("typ"));
            return accepted ? OAuth2TokenValidatorResult.success() : OAuth2TokenValidatorResult.failure(
                    new OAuth2Error("invalid_token", "A valid access token for this resource is required.", null));
        };
        return new DelegatingOAuth2TokenValidator<>(List.of(new JwtTimestampValidator(Duration.ZERO),
                new JwtIssuerValidator(issuer.toString()), JwtTypeValidator.jwt(), required));
    }

    /** Rejects alternate hosts, userinfo and ambiguous issuer URLs before any key fetch. */
    private static void requireIssuer(URI issuer) {
        if (issuer == null || !"https".equals(issuer.getScheme()) || !"idp.federation.test".equals(issuer.getHost())
                || issuer.getPort() < 40000 || issuer.getPort() > 49999 || issuer.getRawUserInfo() != null
                || issuer.getRawQuery() != null || issuer.getRawFragment() != null
                || !"/realms/authlab-downstream".equals(issuer.getRawPath()))
            throw new IllegalArgumentException("Use the prepared downstream HTTPS issuer.");
    }
}
