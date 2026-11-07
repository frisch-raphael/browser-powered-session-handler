package lab.federation;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.SSLContext;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.endpoint.*;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.oidc.authentication.*;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.*;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.web.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.*;

/** Maintained backend OIDC client. No authorization-code, state, nonce or PKCE implementation is duplicated. */
final class FederationOAuth {
    private FederationOAuth() {}

    /** The fixed Keycloak endpoints avoid discovery through an unrelated/default JVM trust context. */
    static ClientRegistrationRepository registrations(FederationApplication.Settings settings,FederationProtocol protocol) {
        String issuer=settings.issuer().toString();
        var registration=ClientRegistration.withRegistrationId("backend").clientId("backend-client").clientSecret(settings.backendClientSecret())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(settings.clientOrigin()+"/login/oauth2/code/backend").scope("openid","profile")
                .authorizationUri(issuer+"/protocol/openid-connect/auth").tokenUri(issuer+"/protocol/openid-connect/token")
                .jwkSetUri(issuer+"/protocol/openid-connect/certs").userInfoUri(issuer+"/protocol/openid-connect/userinfo")
                .userNameAttributeName(IdTokenClaimNames.SUB).issuerUri(issuer).clientName("Lab backend").build();
        return id -> !id.equals("backend")?null:protocol.simulatedExpiry()?ClientRegistration.withClientRegistration(registration)
                .tokenUri(settings.clientOrigin()+"/cases/"+settings.caseId()+"/oauth/token-error").build():registration;
    }

    /** All backchannel calls retain normal hostname verification with this run's dedicated CA. */
    static JdkClientHttpRequestFactory requests(SSLContext trust) {
        var client=HttpClient.newBuilder().sslContext(trust).followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(2))
                .proxy(new java.net.ProxySelector(){
                    @Override public List<java.net.Proxy> select(java.net.URI uri){return List.of(java.net.Proxy.NO_PROXY);}
                    @Override public void connectFailed(java.net.URI uri,java.net.SocketAddress address,java.io.IOException error){}
                }).build();
        var factory=new JdkClientHttpRequestFactory(client);factory.setReadTimeout(Duration.ofSeconds(5));return factory;
    }

    /** Spring performs code exchange/error parsing; fixture controls will decorate this same client. */
    static OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> tokenClient(SSLContext trust,FederationProtocol protocol) {
        var client=new RestClientAuthorizationCodeTokenResponseClient();
        client.setRestClient(RestClient.builder().requestFactory(requests(trust))
                .configureMessageConverters(builder->builder.disableDefaults().addCustomConverter(new FormHttpMessageConverter())
                        .addCustomConverter(new OAuth2AccessTokenResponseHttpMessageConverter()))
                .defaultStatusHandler(new OAuth2ErrorResponseErrorHandler()).build());
        return request->{
            try{protocol.checkpoint("before-token-exchange");}
            catch(FederationProtocol.Failure closed){throw new OAuth2AuthorizationException(new OAuth2Error("invalid_request","The fixture checkpoint is unavailable.",null));}
            if(protocol.simulatedExpiry())protocol.changedField();
            protocol.exchangeStarted();var result=client.getTokenResponse(request);protocol.exchangeAccepted();return result;
        };
    }

    /** Retains Spring's OIDC ID-token validator and claim conversion, with run-local HTTPS key retrieval. */
    static JwtDecoderFactory<ClientRegistration> idTokens(SSLContext trust) {
        var decoders=new ConcurrentHashMap<String,JwtDecoder>();
        return registration->decoders.computeIfAbsent(registration.getRegistrationId(),id->{
            var decoder=NimbusJwtDecoder.withJwkSetUri(registration.getProviderDetails().getJwkSetUri()).jwsAlgorithm(SignatureAlgorithm.RS256)
                    .restOperations(new RestTemplate(requests(trust))).build();
            decoder.setClaimSetConverter(OidcIdTokenDecoderFactory.createDefaultClaimTypeConverter());
            var claims=new OidcIdTokenValidator(registration);claims.setClockSkew(Duration.ofSeconds(2));
            decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(new JwtTimestampValidator(Duration.ofSeconds(2)),claims));return decoder;
        });
    }

    /** User-info handling stays in the maintained client and shares the same scoped trust. */
    static OidcUserService users(SSLContext trust) {
        var userInfo=new DefaultOAuth2UserService();userInfo.setRestOperations(new RestTemplate(requests(trust)));
        var users=new OidcUserService();users.setOauth2UserService(userInfo);return users;
    }

    /** Builds the application chain with S256 even for the confidential backend client. */
    static SecurityFilterChain security(HttpSecurity http,ClientRegistrationRepository registrations,JwtDecoder accessTokens,SSLContext trust,
                                       OAuth2AuthorizedClientRepository clients,FederationClientEndpoints endpoints,
                                       org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository samlRegistrations,
                                       FederationApplication.Settings settings,FederationProtocol protocol) throws Exception {
        var authorization=new DefaultOAuth2AuthorizationRequestResolver(registrations,"/oauth2/authorization");
        authorization.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce()
                .andThen(builder->builder.additionalParameters(parameters->parameters.put("response_mode","query"))));
        String expiredRoute="/cases/"+settings.caseId()+"/oauth/token-error";
        http.csrf(c->c.ignoringRequestMatchers("/session","/logout-client",expiredRoute))
                .sessionManagement(c->c.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .formLogin(c->c.disable()).httpBasic(c->c.disable())
                .exceptionHandling(c->c.authenticationEntryPoint((request,response,error)->endpoints.failure(response,401,"client_authentication_required"))
                        .accessDeniedHandler((request,response,error)->endpoints.failure(response,403,"client_request_rejected")))
                .authorizeHttpRequests(c->c.dispatcherTypeMatchers(jakarta.servlet.DispatcherType.ERROR).permitAll()
                        .requestMatchers(expiredRoute,"/spa","/spa/callback","/spa.js","/spa-config","/vendor/keycloak.js","/vendor/deprecations.js","/me","/logout-client","/combined","/backend-complete","/saml-complete",
                                "/saml2/authenticate/keycloak","/login/saml2/sso/keycloak","/saml2/metadata/keycloak","/oauth2/authorization/backend","/login/oauth2/code/backend").permitAll()
                        .requestMatchers(org.springframework.http.HttpMethod.POST,"/session").authenticated().anyRequest().denyAll())
                .oauth2ResourceServer(c->c.jwt(j->j.decoder(accessTokens)).authenticationEntryPoint((request,response,error)->endpoints.failure(response,401,"access_token_rejected")))
                .oauth2Login(c->c.clientRegistrationRepository(registrations).authorizedClientRepository(clients)
                        .authorizationEndpoint(a->a.authorizationRequestResolver(authorization))
                        .tokenEndpoint(t->t.accessTokenResponseClient(tokenClient(trust,protocol)))
                        .userInfoEndpoint(u->u.oidcUserService(users(trust)))
                        .successHandler((request,response,authentication)->endpoints.backendCompleted(request,response,authentication,clients))
                        .failureHandler((request,response,error)->endpoints.loginFailed(response,error)))
                .saml2Login(c->c.relyingPartyRegistrationRepository(samlRegistrations).authenticationRequestUriQuery("/saml2/authenticate/{registrationId}")
                        .authenticationRequestResolver(FederationSaml.requests(samlRegistrations))
                        .authenticationManager(FederationSaml.authentication())
                        .successHandler((request,response,authentication)->endpoints.samlCompleted(response,authentication))
                        .failureHandler((request,response,error)->endpoints.samlFailed(response,error)))
                .saml2Metadata(org.springframework.security.config.Customizer.withDefaults());
        return http.build();
    }
}
