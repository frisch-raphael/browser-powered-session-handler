package bpsh.authentication.http;

import bpsh.journey.*;
import java.net.URI;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class HttpAuthenticationActivityTest {
    @Test void routineConnectionReuseUpdatesInspectionWithoutLoggingEveryResponse() {
        var owner=entry(1,1);var current=new AtomicReference<>(snapshot(owner));var events=new ArrayList<HttpAuthenticationProgress>();
        try(var activity=new HttpAuthenticationActivity(current::get)) {
            activity.events((identity,event)->events.add(event));var source=activity.observe(spec(owner));
            source.accept(progress(HttpAuthenticationProgress.Stage.ACCEPTED,1));
            for(int i=2;i<=101;i++)source.accept(new HttpAuthenticationProgress(HttpAuthenticationProgress.Stage.CONNECTION_REUSED,
                    HttpAuthentication.Protocol.NTLM_V2,ORIGIN,Instant.ofEpochSecond(i),i%2==0?302:200));
            assertEquals(List.of(HttpAuthenticationProgress.Stage.ACCEPTED),events.stream().map(HttpAuthenticationProgress::stage).toList());
            var latest=activity.snapshot(owner.identity()).getFirst();assertEquals(HttpAuthenticationProgress.Stage.CONNECTION_REUSED,latest.stage());
            assertEquals(200,latest.httpStatus());assertEquals(Instant.ofEpochSecond(101),latest.time());
            source.accept(progress(HttpAuthenticationProgress.Stage.REJECTED,102));
            assertEquals(List.of(HttpAuthenticationProgress.Stage.ACCEPTED,HttpAuthenticationProgress.Stage.REJECTED),events.stream().map(HttpAuthenticationProgress::stage).toList());
        }
    }
    @Test void recordingAnUnfinishedJourneyRetainsItsValidatedHttpIdentityAndProgress() {
        var executable=entry(1,1);
        var draft=JourneyDraft.capture(Map.of("url",ORIGIN.toString()),Map.of("httpAuthentication",true),JourneyDefinition.SlotKind.INDEX,"",List.of(),List.of());
        var owner=new JourneyCatalog.Entry(executable.identity(),draft.definition(id,"NTLM user","ntlm-user",false),1);
        var current=new AtomicReference<>(snapshot(owner));
        try(var activity=new HttpAuthenticationActivity(current::get)) {
            var recording=new HttpTransportFactory.ScopeSpec(UUID.randomUUID(),HttpTransportFactory.Purpose.RECORDING,owner.identity(),0,
                    BrowserSetup.from(executable.definition()),false);
            var source=activity.observe(recording);source.accept(progress(HttpAuthenticationProgress.Stage.ACCEPTED,1));
            assertEquals(executable.definition().httpAuthentication(),activity.settings(owner.identity()));
            assertEquals(HttpAuthenticationProgress.Stage.ACCEPTED,activity.snapshot(owner.identity()).getFirst().stage());
            current.set(snapshot(entry(2,1)));source.accept(progress(HttpAuthenticationProgress.Stage.ACCEPTED,2));
            assertTrue(activity.snapshot(owner.identity()).isEmpty());assertNull(activity.settings(owner.identity()));
        }
    }
    private static final URI ORIGIN=URI.create("https://example.test");
    private final UUID id=UUID.randomUUID();
    private JourneyCatalog.Entry entry(long generation,long secretRevision) {
        var definition=new JourneyDefinition(id,"NTLM user","ntlm-user",ORIGIN,false,List.of(),
                new JourneyDefinition.Browser(true,null,10000,1000),null,JourneyDefinition.Injection.perToken(List.of()),
                new JourneyDefinition.Cache(60,5),null,
                new HttpAuthentication(HttpAuthentication.Protocol.NTLM_V2,"user-a","LAB","",Set.of(ORIGIN)),null);
        return new JourneyCatalog.Entry(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT,id,generation),definition,secretRevision);
    }
    private static JourneyCatalog.Snapshot snapshot(JourneyCatalog.Entry entry) {
        return new JourneyCatalog.Snapshot(Map.of(entry.identity().key(),entry),Map.of("ntlm-user",List.of(entry.identity().key())),Set.of());
    }
    private static HttpTransportFactory.ScopeSpec spec(JourneyCatalog.Entry entry) {
        return new HttpTransportFactory.ScopeSpec(UUID.randomUUID(),HttpTransportFactory.Purpose.RECORDING,entry.identity(),0,BrowserSetup.from(entry.definition()),false);
    }
    private static HttpAuthenticationProgress progress(HttpAuthenticationProgress.Stage stage,int second) {
        return new HttpAuthenticationProgress(stage,HttpAuthentication.Protocol.NTLM_V2,ORIGIN,Instant.ofEpochSecond(second),stage==HttpAuthenticationProgress.Stage.ACCEPTED?200:0);
    }

    @Test void clearFencesLateScopesAndNewWorkCanPublishWithoutRestoringAnOldResult() {
        var owner=entry(1,1);var current=new AtomicReference<>(snapshot(owner));var events=new ArrayList<String>();
        try(var activity=new HttpAuthenticationActivity(current::get)) {
            activity.events((identity,event)->events.add(event.message()));
            var old=activity.observe(spec(owner));old.accept(progress(HttpAuthenticationProgress.Stage.ACCEPTED,1));
            assertEquals(HttpAuthenticationProgress.Stage.ACCEPTED,activity.snapshot(owner.identity()).getFirst().stage());
            activity.clear(owner.identity());old.accept(progress(HttpAuthenticationProgress.Stage.ACCEPTED,2));
            assertTrue(activity.snapshot(owner.identity()).isEmpty());assertEquals(1,events.size());
            var fresh=activity.observe(spec(owner));fresh.accept(progress(HttpAuthenticationProgress.Stage.REJECTED,3));
            old.accept(progress(HttpAuthenticationProgress.Stage.ACCEPTED,4));
            assertEquals(HttpAuthenticationProgress.Stage.REJECTED,activity.snapshot(owner.identity()).getFirst().stage());
            assertEquals(2,events.size());
            fresh.accept(progress(HttpAuthenticationProgress.Stage.NEGOTIATE_SENT,2));
            assertEquals(HttpAuthenticationProgress.Stage.REJECTED,activity.snapshot(owner.identity()).getFirst().stage());
            assertEquals(3,events.size());
            activity.close();fresh.accept(progress(HttpAuthenticationProgress.Stage.ACCEPTED,5));
            assertTrue(activity.snapshot(owner.identity()).isEmpty());assertEquals(3,events.size());
        }
    }
    @Test void generationSecretRevisionUnavailableScopeAndForeignOriginCannotDiscloseOrRestoreObservations() {
        var owner=entry(1,1);var current=new AtomicReference<>(snapshot(owner));var events=new ArrayList<String>();
        try(var activity=new HttpAuthenticationActivity(current::get)) {
            activity.events((identity,event)->events.add(event.message()));var source=activity.observe(spec(owner));
            source.accept(new HttpAuthenticationProgress(HttpAuthenticationProgress.Stage.ACCEPTED,HttpAuthentication.Protocol.NTLM_V2,
                    URI.create("https://foreign.test/secret-path?token=secret"),Instant.now(),200));
            assertTrue(activity.snapshot(owner.identity()).isEmpty());assertTrue(events.isEmpty());
            source.accept(progress(HttpAuthenticationProgress.Stage.ACCEPTED,1));
            current.set(snapshot(entry(1,2)));assertTrue(activity.snapshot(owner.identity()).isEmpty());
            source.accept(progress(HttpAuthenticationProgress.Stage.ACCEPTED,2));assertEquals(1,events.size());
            var newOwner=entry(2,2);current.set(snapshot(newOwner));
            var fresh=activity.observe(spec(newOwner));fresh.accept(progress(HttpAuthenticationProgress.Stage.ACCEPTED,3));
            assertTrue(activity.snapshot(owner.identity()).isEmpty());assertEquals(1,activity.snapshot(newOwner.identity()).size());
            current.set(new JourneyCatalog.Snapshot(Map.of(newOwner.identity().key(),newOwner),Map.of(),Set.of(JourneyDefinition.Scope.PROJECT)));
            fresh.accept(progress(HttpAuthenticationProgress.Stage.REJECTED,4));assertTrue(activity.snapshot(newOwner.identity()).isEmpty());
            assertEquals(2,events.size());
        }
    }
    @Test void failureMessagesClassifyCausesWithoutVendorTextOrAuthenticationData() {
        String secret="secret-password NTLM U0VDUkVU Authorization /private?token=hidden";
        var cases=Map.<Throwable,HttpAuthenticationProgress.Stage>of(
                new java.util.concurrent.CompletionException(new javax.net.ssl.SSLHandshakeException(secret)),HttpAuthenticationProgress.Stage.TLS_FAILED,
                new java.net.ConnectException(secret),HttpAuthenticationProgress.Stage.CONNECTION_FAILED,
                new java.util.concurrent.TimeoutException(secret),HttpAuthenticationProgress.Stage.TIMED_OUT,
                new java.util.concurrent.CancellationException(secret),HttpAuthenticationProgress.Stage.CANCELLED,
                new java.util.concurrent.RejectedExecutionException(secret),HttpAuthenticationProgress.Stage.CAPACITY);
        cases.forEach((failure,expected)->{
            var event=progress(HttpAuthenticationProgress.failureStage(failure,false),1);
            assertEquals(expected,event.stage());assertFalse(event.message().contains(secret));assertFalse(event.toString().contains(secret));
        });
    }
}
