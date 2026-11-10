package bpsh.support;

import bpsh.browser.BrowserSessionLauncher;
import bpsh.journey.*;
import bpsh.authentication.http.*;
import bpsh.transport.httpauth.HttpTransportRuntime;
import lab.auth.LabObservationCapture;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

/** Real Chromium policy scenarios using the existing launcher, fixture and process witness. */
public final class HttpAuthenticationBrowserPolicies {
    private HttpAuthenticationBrowserPolicies() { }
    private static long deadline() {return System.nanoTime()+TimeUnit.SECONDS.toNanos(30);}
    private static JourneyDefinition.Identity identity() {return new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT,UUID.randomUUID(),1);}
    private static BrowserSetup setup(java.net.URI url,HttpAuthentication.Protocol protocol,boolean consent) {
        return new BrowserSetup(url,new JourneyDefinition.Browser(true,null,10000,3000,consent),null,
                new HttpAuthentication(protocol,"user-a","LAB","",Set.of(bpsh.journey.JourneyOrigins.authenticationOrigin(url))));
    }
    public static void authorization(BrowserSessionLauncher launcher,HttpAuthentication.Protocol protocol,boolean reused) throws Exception {
        long began=System.nanoTime();var proof=new LinkedHashMap<String,Object>();
        var lab=IntegrationFixtures.httpAuthentication(protocol.name(),null);
        try(var processes=new BrowserProcessWitness()) {
            try(lab;var values=new SecretStore.Values(null,Map.of(),"alpha-password".toCharArray());
                var session=launcher.open(identity(),setup(lab.url(reused?"/application-page":"/anonymous-page"),protocol,false),values,
                        BrowserSessionLauncher.Visibility.HEADLESS,false,deadline(),()->false,ignored->{})) {
                var page=session.context().newPage();page.setDefaultTimeout(10000);
                page.navigate(lab.url(reused?"/application-page":"/anonymous-page").toString());
                int before=lab.requests.size(), handshakes=lab.handshakes.get();
                int status=((Number)page.evaluate("async()=>{const r=await fetch('/whoami',{headers:{Authorization:'Bearer application'}});await r.arrayBuffer();return r.status;}" )).intValue();
                boolean accepted=reused && protocol!=HttpAuthentication.Protocol.BASIC;
                assertEquals(accepted?200:401,status);assertEquals(1,lab.applicationAuthorizations.get());
                assertEquals(0,lab.unexpectedBasicCredentials.get(),"Browser must not fall back to its local proxy credentials.");
                assertEquals(1,lab.requests.size()-before,"The browser must not attempt another authentication scheme.");
                assertEquals(handshakes,lab.handshakes.get());
                var evidence=session.httpAuthentication();assertNotNull(evidence);
                assertEquals(accepted?HttpAuthenticationEvidence.Status.ACCEPTED:HttpAuthenticationEvidence.Status.REJECTED,evidence.status());
                assertEquals(!accepted,evidence.applicationAuthorizationConflict());
                boolean serverAccepted=lab.observations.stream().anyMatch(o->o.path().equals("/whoami")&&o.user().equals("user-a")&&o.protocol().name().equals(protocol.name()));
                assertEquals(accepted,serverAccepted);
                proof.putAll(Map.of("status",status,"applicationHeaders",lab.applicationAuthorizations.get(),"unexpectedCredentials",lab.unexpectedBasicCredentials.get(),
                        "wireDelta",lab.requests.size()-before,"handshakeDelta",lab.handshakes.get()-handshakes,"serverAccepted",serverAccepted,
                        "conflict",evidence.applicationAuthorizationConflict(),"observedProtocol",evidence.protocol()==null?"NONE":evidence.protocol().name()));
            }
            processes.close();processes.requireObserved(1);
            proof.put("drivers",processes.drivers());proof.put("processes",processes.processes());proof.put("alive",processes.alive());proof.put("fixtureClosed",lab.isClosed());
            LabObservationCapture.write("HTTP.auth.browser-authorization."+(reused?"reused-":"fresh-")+protocol.name().toLowerCase(Locale.ROOT).replace('_','-'),
                    proof,Map.of("startupMs",0L,"caseMs",TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-began),"cleanupMs",0L));
        }
    }
    public static void trust(BrowserSessionLauncher launcher,HttpTransportRuntime transport,Path directory) throws Exception {
        long began=System.nanoTime();var proof=new LinkedHashMap<String,Object>();
        var ca=lab.auth.LabTls.prepare(directory.resolve("ca"));var material=lab.auth.LabTls.createServer(ca,directory.resolve("server"));
        var fixture=IntegrationFixtures.httpAuthentication("NTLM_V2",material.serverContext());
        try(var processes=new BrowserProcessWitness()) {
            try(fixture;var values=new SecretStore.Values(null,Map.of(),"alpha-password".toCharArray())) {
                var statuses=new ArrayList<Integer>();
                for(boolean consent:new boolean[]{true,false})try(var session=launcher.open(identity(),setup(fixture.url("/whoami"),HttpAuthentication.Protocol.NTLM_V2,consent),values,
                        BrowserSessionLauncher.Visibility.HEADLESS,false,deadline(),()->false,ignored->{})) {
                    int status=session.context().newPage().navigate(fixture.url("/whoami").toString()).status();statuses.add(status);
                    assertEquals(consent?200:502,status);
                    if(!consent)assertEquals(bpsh.authentication.AuthenticationFailure.Cause.TRUST,session.transportFailure().reason());
                }
                var spec=new HttpTransportFactory.ScopeSpec(UUID.randomUUID(),HttpTransportFactory.Purpose.TEST,identity(),0,
                        setup(fixture.url("/whoami"),HttpAuthentication.Protocol.NTLM_V2,true),false);
                try(var scope=transport.open(spec,values,deadline()).get(10,TimeUnit.SECONDS);
                    var lease=scope.admit(deadline());var builder=transport.bodies().builder(0);var body=builder.finish()) {
                    assertThrows(java.util.concurrent.ExecutionException.class,()->lease.exchange(new HttpAuthenticationService.Request(fixture.url("/whoami"),"GET",List.of(),body)).get(10,TimeUnit.SECONDS));
                    proof.put("directTrustRejected",scope.failure()!=null && scope.failure().reason()==bpsh.authentication.AuthenticationFailure.Cause.TRUST);
                }
                proof.put("statuses",statuses);proof.put("handshakes",fixture.handshakes.get());assertEquals(1,fixture.handshakes.get());
            }
            processes.close();processes.requireObserved(2);
            proof.put("drivers",processes.drivers());proof.put("processes",processes.processes());proof.put("alive",processes.alive());proof.put("fixtureClosed",fixture.isClosed());
            LabObservationCapture.write("HTTP.auth.browser-trust.scoped",proof,Map.of("startupMs",0L,"caseMs",TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-began),"cleanupMs",0L));
        }
    }
}
