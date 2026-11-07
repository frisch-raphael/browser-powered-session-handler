package lab.federation;

import java.io.*;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import javax.net.ssl.SSLContext;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml5AuthenticationProvider;
import org.springframework.security.saml2.provider.service.registration.*;

/** Real Keycloak metadata and Spring/OpenSAML validation; no synthetic identity provider lives here. */
final class FederationSaml {
    private FederationSaml() {}

    /** Resolves only this owned provider's metadata through scoped TLS before admitting client traffic. */
    static RelyingPartyRegistrationRepository registrations(FederationApplication.Settings settings,SSLContext trust) throws Exception {
        byte[] metadata;
        try(var client=HttpClient.newBuilder().sslContext(trust).connectTimeout(Duration.ofSeconds(2)).followRedirects(HttpClient.Redirect.NEVER)
                .proxy(new java.net.ProxySelector(){
                    @Override public java.util.List<java.net.Proxy> select(URI uri){return java.util.List.of(java.net.Proxy.NO_PROXY);}
                    @Override public void connectFailed(URI uri,java.net.SocketAddress address,IOException error){}
                }).build()) {
            var response=client.send(HttpRequest.newBuilder(URI.create(settings.issuer()+"/protocol/saml/descriptor")).timeout(Duration.ofSeconds(5)).GET().build(),HttpResponse.BodyHandlers.ofInputStream());
            try(var input=response.body()){metadata=input.readNBytes(1_048_577);}
            if(response.statusCode()!=200||metadata.length>1_048_576)throw new IOException("Owned SAML metadata unavailable or oversized.");
        }
        var registration=RelyingPartyRegistrations.fromMetadata(new ByteArrayInputStream(metadata)).registrationId("keycloak")
                .entityId(settings.clientOrigin()+"/saml/metadata")
                .assertionConsumerServiceLocation(settings.clientOrigin()+"/login/saml2/sso/keycloak")
                // The owned SP's actual imported client policy disables request signatures; realm metadata is general.
                .assertingPartyMetadata(provider->provider.wantAuthnRequestsSigned(false))
                .assertionConsumerServiceBinding(Saml2MessageBinding.POST).authnRequestsSigned(false).build();
        var provider=registration.getAssertingPartyMetadata();
        if(!settings.issuer().toString().equals(provider.getEntityId())||!(settings.issuer()+"/protocol/saml").equals(provider.getSingleSignOnServiceLocation())
                ||provider.getVerificationX509Credentials().isEmpty())throw new IOException("Owned SAML metadata identity differs.");
        for(var credential:provider.getVerificationX509Credentials())credential.getCertificate().checkValidity();
        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }

    /** Retains maintained signature, recipient, audience and correlation checks with the declared two-second skew. */
    static ProviderManager authentication() {
        var provider=new OpenSaml5AuthenticationProvider();
        provider.setAssertionValidator(OpenSaml5AuthenticationProvider.AssertionValidator.builder().clockSkew(Duration.ofSeconds(2)).build());
        return new ProviderManager(provider);
    }

    /** Pins the maintained resolver as well as the entry matcher; an absent request cannot become another login protocol. */
    static org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver requests(RelyingPartyRegistrationRepository registrations) {
        var matcher=org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher.withDefaults().matcher("/saml2/authenticate/{registrationId}");
        var resolver=new org.springframework.security.saml2.provider.service.web.authentication.OpenSaml5AuthenticationRequestResolver(registrations);resolver.setRequestMatcher(matcher);
        return new org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver(){
          @Override public <T extends org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest> T resolve(jakarta.servlet.http.HttpServletRequest request) {
            if(!matcher.matches(request))return null;
            try {
                T result=resolver.resolve(request);if(result==null)throw new IllegalStateException("Configured SAML entry produced no authentication request.");return result;
            }catch(RuntimeException error){
                var types=new java.util.ArrayList<String>();for(Throwable cause=error;cause!=null&&types.size()<8;cause=cause.getCause())types.add(cause.getClass().getName());
                System.err.println("SAML request generation failed; exception types: "+String.join(",",types));
                for(Throwable cause=error;cause!=null;cause=cause.getCause())for(var frame:java.util.Arrays.stream(cause.getStackTrace()).limit(6).toList())
                    System.err.println("SAML request failure frame: "+frame.getClassName()+"."+frame.getMethodName()+":"+frame.getLineNumber());
                throw error;
            }
          }
        };
    }
}
