package bpsh.burp.http;

import bpsh.authentication.http.*;
import bpsh.browser.AuthTrafficGuard;
import bpsh.journey.*;
import bpsh.support.IntegrationFixtures;
import java.net.URI;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import static org.junit.jupiter.api.Assertions.*;

class GuardedHttpTransportFactoryTest {
    @ParameterizedTest @EnumSource(value=HttpTransportFactory.Purpose.class,names={"DIRECT","TEST"})
    void routingChangesOnlyOwnershipHeadersAndPreservesBothAuthenticationPolicies(HttpTransportFactory.Purpose purpose) throws Exception {
        var observed=new AtomicReference<HttpAuthenticationService.Request>();var allocator=new HttpMessageBody.Allocator(1024);
        var delegate=new HttpTransportFactory(){
            public HttpMessageBody.Allocator bodies(){return allocator;}public void close(){}
            public CompletableFuture<HttpAuthenticationService> open(ScopeSpec spec,SecretStore.Values values,long deadline){
                return CompletableFuture.completedFuture(new HttpAuthenticationService(){
                    public boolean isOpen(){return true;}public void close(){}
                    public Delivery admit(long end){return IntegrationFixtures.httpDelivery(request->{
                        observed.set(request);return CompletableFuture.completedFuture(new Response(200,List.of(),IntegrationFixtures.httpBody(new byte[0]),
                            new HttpAuthenticationEvidence(null,HttpAuthenticationEvidence.Status.UNCONFIRMED)));
                    });}
                });
            }
        };
        var origin=URI.create("http://example.test");
        var setup=new BrowserSetup(origin,new JourneyDefinition.Browser(true,new JourneyDefinition.Proxy(URI.create("http://127.0.0.1:8080")),30000,3000),null,
                new HttpAuthentication(HttpAuthentication.Protocol.NTLM_V2,"user-a","LAB","",Set.of(origin)));
        var spec=new HttpTransportFactory.ScopeSpec(UUID.randomUUID(),purpose,new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT,UUID.randomUUID(),1),0,setup,false);
        try(var guard=new AuthTrafficGuard();var factory=new GuardedHttpTransportFactory(delegate,guard);var values=new SecretStore.Values(null,java.util.Map.of());
            var scope=factory.open(spec,values,System.nanoTime()+5_000_000_000L).get();var lease=scope.admit(System.nanoTime()+5_000_000_000L);
            var body=IntegrationFixtures.httpBody(new byte[0])) {
            var request=new HttpAuthenticationService.Request(origin,"POST",List.of(new HttpAuthenticationService.Header("User-Agent","application-agent")),body,
                    HttpAuthenticationService.AuthorizationPolicy.PRESERVE_APPLICATION,HttpAuthenticationService.ChallengePolicy.ESTABLISHED_ONLY);
            try(var response=lease.exchange(request).get()) {assertEquals(200,response.status());}
            assertEquals(request.authorizationPolicy(),observed.get().authorizationPolicy());assertEquals(request.challengePolicy(),observed.get().challengePolicy());
            assertSame(body,observed.get().body());assertEquals(origin,observed.get().uri());
            var agent=observed.get().headers().stream().filter(h->h.name().equals("User-Agent")).findFirst().orElseThrow().value();
            assertEquals(AuthTrafficGuard.Classification.OWNED,guard.classify(agent,AuthTrafficGuard.Family.GLOBAL,1).classification());
        }
    }
}
