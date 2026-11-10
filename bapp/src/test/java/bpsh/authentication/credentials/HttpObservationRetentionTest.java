package bpsh.authentication.credentials;

import bpsh.authentication.http.HttpAuthenticationEvidence;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.JourneyCatalog;
import bpsh.journey.HttpAuthentication;
import java.net.URI;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class HttpObservationRetentionTest {
    @Test void compatibleCaptureRemappingPreservesTheObservedIdentityAndTime() throws Exception {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.lifecycle.observation-remap");
        var id=new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT,UUID.randomUUID(),1);
        var next=new JourneyDefinition.Identity(id.scope(),id.journeyId(),2);
        var origin=URI.create("https://example.test");var observed=Instant.ofEpochSecond(2000000000);
        var evidence=new HttpAuthenticationEvidence(HttpAuthentication.Protocol.NTLM_V2,HttpAuthenticationEvidence.Status.ACCEPTED,origin,id,4,observed,200,false);
        var source=new JourneyDefinition.JsonExtraction(origin,"/token","access_token");
        var old=new JourneyDefinition.CombinedExtraction(List.of(new JourneyDefinition.NamedExtraction("old",source)));
        var replacement=new JourneyDefinition.CombinedExtraction(List.of(new JourneyDefinition.NamedExtraction("new",source)));
        var lifetime=TokenLifetime.acquire("opaque",new JourneyDefinition.Cache(1800,10),observed,10);
        var snapshot=new TokenSnapshot(id,1,"opaque",lifetime,Map.of(),Map.of("old","opaque"),old,HttpAuthentication.Protocol.NTLM_V2,List.of(evidence));
        var remapped=snapshot.reconfigure(next,old,replacement);
        assertNotNull(remapped);assertEquals(next,remapped.identity());
        assertEquals(List.of(evidence),remapped.httpObservations());assertEquals(id,remapped.httpObservations().getFirst().observedIdentity());
        assertEquals(observed,remapped.httpObservations().getFirst().observedAt());assertEquals(lifetime,remapped.lifetime());
        var cleared=remapped.withoutHttpObservations();assertTrue(cleared.httpObservations().isEmpty());assertNull(cleared.httpProtocol());
        assertEquals("opaque",cleared.value());assertEquals(lifetime,cleared.lifetime());
            proof.put("currentGeneration",remapped.identity().generation());proof.put("observedGeneration",remapped.httpObservations().getFirst().observedIdentity().generation());proof.put("epoch",remapped.httpObservations().getFirst().epoch());proof.put("observedSecond",remapped.httpObservations().getFirst().observedAt().getEpochSecond());proof.put("cleared",cleared.httpObservations().isEmpty());proof.put("tokenRetained",cleared.value().equals(snapshot.value()));
        proof.write();
    }
    @Test void credentialRevisionInvalidatesHttpCompatibilityWithoutExposingSecretValues() {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.lifecycle.secret-revision");
        var definition=bpsh.authentication.session.CoordinatorFixtures.journey("identity");
        var identity=new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT,definition.id(),1);
        var original=new JourneyCatalog.Entry(identity,definition,1);
        assertTrue(original.sameHttpAuthentication(new JourneyCatalog.Entry(identity,definition,1)));
        assertFalse(original.sameHttpAuthentication(new JourneyCatalog.Entry(identity,definition,2)));
            proof.put("compatible",original.sameHttpAuthentication(new JourneyCatalog.Entry(identity,definition,1)));proof.put("changed",original.sameHttpAuthentication(new JourneyCatalog.Entry(identity,definition,2)));
        proof.write();
    }
}
