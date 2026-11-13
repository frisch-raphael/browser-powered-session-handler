package bpsh.transport.httpauth;

import bpsh.authentication.http.HttpAuthenticationEvidence;
import bpsh.authentication.http.HttpAuthenticationService;
import bpsh.journey.HttpAuthentication;
import bpsh.support.IntegrationFixtures;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import javax.net.ssl.SSLContext;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

class HttpClientAuthenticationTransportTest {
    @TempDir Path temporary;
    @ParameterizedTest(name="established-only-{0}") @EnumSource(HttpAuthentication.Protocol.class)
    void cachedOnlyRequestsNeverNegotiateOrReplayTheOriginalPost(HttpAuthentication.Protocol protocol) throws Exception {
        try(var lab=IntegrationFixtures.httpAuthentication(protocol.name(),null);
            var workers=Executors.newFixedThreadPool(2);var deadlines=Executors.newSingleThreadScheduledExecutor();
            var service=transport(protocol,"user-a","alpha-password",lab.url("/"),SSLContext.getDefault(),workers,deadlines);
            var body=IntegrationFixtures.httpBody("payload".getBytes(StandardCharsets.UTF_8))) {
            var post=new HttpAuthenticationService.Request(lab.url("/perform"),"POST",List.of(),body,
                    HttpAuthenticationService.AuthorizationPolicy.REPLACE_SELECTED,HttpAuthenticationService.ChallengePolicy.ESTABLISHED_ONLY);
            int before=lab.requests.size();
            try(var cold=IntegrationFixtures.httpExchange(service,post,deadline()).get(5,TimeUnit.SECONDS)) {
                assertEquals(401,cold.status());assertEquals(1,lab.requests.size()-before);assertEquals(0,lab.applicationPosts.get());
            }
            try(var warm=await(service,lab.url("/whoami"))){assertEquals(200,warm.status());}
            int handshakes=lab.handshakes.get();before=lab.requests.size();
            try(var cached=IntegrationFixtures.httpExchange(service,post,deadline()).get(5,TimeUnit.SECONDS)) {
                assertEquals(200,cached.status());assertEquals(HttpAuthenticationEvidence.Status.ACCEPTED,cached.authentication().status());
                assertEquals(1,lab.requests.size()-before);assertEquals(1,lab.applicationPosts.get());if(protocol!=HttpAuthentication.Protocol.BASIC)assertEquals(handshakes,lab.handshakes.get());
            }
            try(var closing=await(service,lab.url("/close"))){assertEquals(200,closing.status());}
            handshakes=lab.handshakes.get();before=lab.requests.size();
            try(var next=IntegrationFixtures.httpExchange(service,post,deadline()).get(5,TimeUnit.SECONDS)) {
                assertEquals(protocol==HttpAuthentication.Protocol.BASIC?200:401,next.status());
                assertEquals(1,lab.requests.size()-before);if(protocol!=HttpAuthentication.Protocol.BASIC)assertEquals(handshakes,lab.handshakes.get());
            }
        }
    }
    @ParameterizedTest(name="response-headers-{0}") @EnumSource(HttpAuthentication.Protocol.class)
    void boundsHeadersBeforeIntermediateAuthenticationOrFinalResponse(HttpAuthentication.Protocol protocol) throws Exception {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.resources.response-headers-"+protocol.name().toLowerCase(java.util.Locale.ROOT).replace('_','-'));
        var transmissions=new java.util.ArrayList<Integer>();
        try(var lab=IntegrationFixtures.httpAuthentication(protocol.name(),null);
            var workers=Executors.newFixedThreadPool(2);var deadlines=Executors.newSingleThreadScheduledExecutor()) {
            for(String path:List.of("/large-header-challenge","/large-header-final"))try(var service=transport(protocol,"user-a","alpha-password",lab.url("/"),SSLContext.getDefault(),workers,deadlines)) {
                int before=lab.requests.size();
                assertThrows(java.util.concurrent.ExecutionException.class,()->await(service,lab.url(path)));
                int sent=lab.requests.size()-before;transmissions.add(sent);
                assertTrue(sent<=4);if(path.endsWith("challenge"))assertEquals(1,sent);
            }
            assertEquals(1,lab.observations.size());assertEquals(0,lab.applicationPosts.get());proof.put("transmissions",transmissions);proof.put("accepted",lab.observations.size());proof.put("posts",lab.applicationPosts.get());
        }
        proof.write();
    }

    @ParameterizedTest(name="identity-{0}") @EnumSource(HttpAuthentication.Protocol.class)
    void switchingAccountsAndConcurrentRequestsKeepIdentitiesAndReuseNtlmConnections(HttpAuthentication.Protocol protocol) throws Exception {
        long began=System.nanoTime();
        var lab=IntegrationFixtures.httpAuthentication(protocol.name(),null);
        java.util.Map<String,Object> observed;
        try (lab;
             var workers=Executors.newFixedThreadPool(8); var deadlines=Executors.newSingleThreadScheduledExecutor();
             var a=transport(protocol,"user-a","alpha-password",lab.url("/"),SSLContext.getDefault(),workers,deadlines);
             var b=transport(protocol,"user-b","bravo-password",lab.url("/"),SSLContext.getDefault(),workers,deadlines)) {
            var first=await(a,lab.url("/whoami")); assertUser(first,"user-a",protocol);
            assertUser(await(b,lab.url("/whoami")),"user-b",protocol);
            assertUser(await(a,lab.url("/whoami")),"user-a",protocol);
            assertEquals("user-a",lab.observations.get(0).user());
            assertEquals("user-b",lab.observations.get(1).user());
            assertEquals(lab.observations.get(0).connection(),lab.observations.get(2).connection());
            assertNotEquals(lab.observations.get(0).connection(),lab.observations.get(1).connection());
            if(protocol!=HttpAuthentication.Protocol.BASIC)assertEquals(2,lab.handshakes.get());
            var one=bpsh.support.IntegrationFixtures.httpExchange(a,request(lab.url("/slow")),deadline());
            var two=bpsh.support.IntegrationFixtures.httpExchange(b,request(lab.url("/whoami")),deadline());
            assertUser(two.get(5,TimeUnit.SECONDS),"user-b",protocol);
            assertUser(one.get(5,TimeUnit.SECONDS),"user-a",protocol);
            if(protocol!=HttpAuthentication.Protocol.BASIC)assertEquals(2,lab.handshakes.get());
            assertEquals(0,lab.leakedDirectives.get());
            int beforeReconnect=lab.handshakes.get();
            assertUser(await(a,lab.url("/close")),"user-a",protocol);
            assertUser(await(a,lab.url("/whoami")),"user-a",protocol);
            assertNotEquals(lab.observations.get(5).connection(),lab.observations.get(6).connection());
            if(protocol!=HttpAuthentication.Protocol.BASIC)assertEquals(3,lab.handshakes.get());
            observed=bpsh.support.HttpAuthenticationCapture.observed(lab);
            observed.put("handshakesBeforeReconnect",beforeReconnect);
        }
        bpsh.support.HttpAuthenticationCapture.record(protocol.name(),"identity",lab,observed,began);
    }

    @ParameterizedTest @EnumSource(HttpAuthentication.Protocol.class)
    void freshOrRejectedAuthenticationCannotReportSuccess(HttpAuthentication.Protocol protocol) throws Exception {
        try(var lab=IntegrationFixtures.httpAuthentication(protocol.name(),null);
            var workers=Executors.newFixedThreadPool(4);var deadlines=Executors.newSingleThreadScheduledExecutor();
            var valid=transport(protocol,"user-a","alpha-password",lab.url("/"),SSLContext.getDefault(),workers,deadlines);
            var wrong=transport(protocol,"user-a","wrong",lab.url("/"),SSLContext.getDefault(),workers,deadlines)) {
            assertEquals(HttpAuthenticationEvidence.Status.UNCONFIRMED,await(valid,lab.url("/anonymous")).authentication().status());
            assertEquals(HttpAuthenticationEvidence.Status.REJECTED,await(wrong,lab.url("/whoami")).authentication().status());
            assertUser(await(valid,lab.url("/close")),"user-a",protocol);
            assertEquals(HttpAuthenticationEvidence.Status.UNCONFIRMED,await(valid,lab.url("/anonymous")).authentication().status());
            assertUser(await(valid,lab.url("/whoami")),"user-a",protocol);
            assertEquals(2,lab.handshakes.get());
            assertEquals(protocol==HttpAuthentication.Protocol.BASIC?HttpAuthenticationEvidence.Status.UNCONFIRMED:HttpAuthenticationEvidence.Status.ACCEPTED,await(valid,lab.url("/forbidden")).authentication().status());
        }
    }

    @ParameterizedTest @EnumSource(HttpAuthentication.Protocol.class)
    void overridesAllAuthorizationAndNeverRetriesAnExecutedPost(HttpAuthentication.Protocol protocol) throws Exception {
        try(var lab=IntegrationFixtures.httpAuthentication(protocol.name(),null);
            var workers=Executors.newFixedThreadPool(4);var deadlines=Executors.newSingleThreadScheduledExecutor();
            var service=transport(protocol,"user-b","bravo-password",lab.url("/"),SSLContext.getDefault(),workers,deadlines)) {
            List<HttpAuthenticationService.Header> headers=List.of(new HttpAuthenticationService.Header("Authorization","Basic dXNlci1hOmFscGhhLXBhc3N3b3Jk"),
                    new HttpAuthenticationService.Header("authorization","Bearer discarded"),new HttpAuthenticationService.Header("BPSP-HTTP-AUTHENT","<@user-b/>"));
            var request=new HttpAuthenticationService.Request(lab.url("/perform"),"POST",headers,bpsh.support.IntegrationFixtures.httpBody("payload".getBytes(StandardCharsets.UTF_8)));
            assertUser(bpsh.support.IntegrationFixtures.httpExchange(service,request,deadline()).get(5,TimeUnit.SECONDS),"user-b",protocol);
            assertEquals(1,lab.applicationPosts.get());assertEquals(7,lab.observations.get(0).bodyBytes());
            assertEquals(0,lab.leakedDirectives.get());
            assertThrows(java.util.concurrent.ExecutionException.class,()->bpsh.support.IntegrationFixtures.httpExchange(service,new HttpAuthenticationService.Request(lab.url("/drop"),"POST",headers,bpsh.support.IntegrationFixtures.httpBody(new byte[]{1})),deadline()).get(5,TimeUnit.SECONDS));
            assertEquals(2,lab.applicationPosts.get());
        }
    }

    @Test void boundsResponsesDeadlinesAndScopeRetirement() throws Exception {
        try(var lab=IntegrationFixtures.httpAuthentication("NTLM_V2",null);
            var workers=Executors.newFixedThreadPool(4);var deadlines=Executors.newSingleThreadScheduledExecutor();
            var service=transport(HttpAuthentication.Protocol.NTLM_V2,"user-a","alpha-password",lab.url("/"),SSLContext.getDefault(),workers,deadlines)) {
            assertThrows(java.util.concurrent.ExecutionException.class,()->await(service,lab.url("/large")));
            var timed=bpsh.support.IntegrationFixtures.httpExchange(service,request(lab.url("/slow")),System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(100));
            var timeout=assertThrows(java.util.concurrent.ExecutionException.class,()->timed.get(3,TimeUnit.SECONDS));
            assertInstanceOf(java.util.concurrent.TimeoutException.class,timeout.getCause());
            var pending=bpsh.support.IntegrationFixtures.httpExchange(service,request(lab.url("/slow")),deadline());service.close();
            assertThrows(java.util.concurrent.ExecutionException.class,()->pending.get(3,TimeUnit.SECONDS));
            assertThrows(java.util.concurrent.ExecutionException.class,()->await(service,lab.url("/whoami")));
        }
    }

    @ParameterizedTest @EnumSource(HttpAuthentication.Protocol.class)
    void challengePostsRepeatOnTheWireButExecuteOnceAndFinalRejectionStops(HttpAuthentication.Protocol protocol) throws Exception {
        try(var lab=IntegrationFixtures.httpAuthentication(protocol.name(),null);
            var workers=Executors.newFixedThreadPool(2);var deadlines=Executors.newSingleThreadScheduledExecutor();
            var service=transport(protocol,"user-a","alpha-password",lab.url("/"),SSLContext.getDefault(),workers,deadlines)) {
            var post=new HttpAuthenticationService.Request(lab.url("/perform"),"POST",List.of(),bpsh.support.IntegrationFixtures.httpBody(new byte[]{1,2,3}));
            assertUser(bpsh.support.IntegrationFixtures.httpExchange(service,post,deadline()).get(5,TimeUnit.SECONDS),"user-a",protocol);
            int exchanges=protocol==HttpAuthentication.Protocol.BASIC?2:3;
            assertEquals(exchanges,lab.requests.size());
            assertTrue(lab.requests.stream().allMatch(r->r.method().equals("POST") && r.bodyBytes()==3));
            assertEquals(1,lab.applicationPosts.get());
            int before=lab.requests.size();
            var rejected=bpsh.support.IntegrationFixtures.httpExchange(service,new HttpAuthenticationService.Request(lab.url("/reject"),"POST",List.of(),bpsh.support.IntegrationFixtures.httpBody(new byte[]{4})),deadline()).get(5,TimeUnit.SECONDS);
            assertEquals(401,rejected.status());
            assertEquals(HttpAuthenticationEvidence.Status.REJECTED,rejected.authentication().status());
            assertEquals(exchanges,lab.requests.size()-before);
            assertEquals(1,lab.applicationPosts.get());
        }
    }

    @ParameterizedTest @EnumSource(value=HttpAuthentication.Protocol.class,names={"NTLM_V1","NTLM_V2"})
    void renewedChallengeAuthenticatesAgainOnTheSameConnection(HttpAuthentication.Protocol protocol) throws Exception {
        try(var lab=IntegrationFixtures.httpAuthentication(protocol.name(),null);
            var workers=Executors.newFixedThreadPool(2);var deadlines=Executors.newSingleThreadScheduledExecutor();
            var service=transport(protocol,"user-a","alpha-password",lab.url("/"),SSLContext.getDefault(),workers,deadlines)) {
            assertUser(await(service,lab.url("/whoami")),"user-a",protocol);
            var post=new HttpAuthenticationService.Request(lab.url("/rechallenge"),"POST",List.of(),bpsh.support.IntegrationFixtures.httpBody(new byte[]{1}));
            assertUser(bpsh.support.IntegrationFixtures.httpExchange(service,post,deadline()).get(5,TimeUnit.SECONDS),"user-a",protocol);
            assertEquals(2,lab.handshakes.get());
            assertEquals(1,lab.applicationPosts.get());
            assertEquals(1,lab.requests.stream().map(r->r.connection()).distinct().count());
            assertEquals(6,lab.requests.size());
        }
    }

    @ParameterizedTest @EnumSource(HttpAuthentication.Protocol.class)
    void oversizedIntermediateChallengesAbortBeforeSendingCredentials(HttpAuthentication.Protocol protocol) throws Exception {
        for(String path:List.of("/large-challenge-fixed","/large-challenge-chunked")) {
            try(var lab=IntegrationFixtures.httpAuthentication(protocol.name(),null);
                var workers=Executors.newFixedThreadPool(2);var deadlines=Executors.newSingleThreadScheduledExecutor();
                var service=transport(protocol,"user-a","alpha-password",lab.url("/"),SSLContext.getDefault(),workers,deadlines)) {
                var failure=assertThrows(java.util.concurrent.ExecutionException.class,()->await(service,lab.url(path)));
                assertTrue(causes(failure).contains("16 MiB"),causes(failure));
                assertEquals(1,lab.requests.size());
                assertEquals(0,lab.handshakes.get());
            }
        }
    }

    @ParameterizedTest @EnumSource(HttpAuthentication.Protocol.class)
    void incompletePostResponseIsUncertainAndNeverRetried(HttpAuthentication.Protocol protocol) throws Exception {
        for(String path:List.of("/drop","/truncated")) {
            try(var lab=IntegrationFixtures.httpAuthentication(protocol.name(),null);
                var workers=Executors.newFixedThreadPool(2);var deadlines=Executors.newSingleThreadScheduledExecutor();
                var service=transport(protocol,"user-a","alpha-password",lab.url("/"),SSLContext.getDefault(),workers,deadlines)) {
                var post=new HttpAuthenticationService.Request(lab.url(path),"POST",List.of(),bpsh.support.IntegrationFixtures.httpBody(new byte[]{1}));
                var failure=assertThrows(java.util.concurrent.ExecutionException.class,()->bpsh.support.IntegrationFixtures.httpExchange(service,post,deadline()).get(5,TimeUnit.SECONDS));
                assertTrue(causes(failure).contains("may have reached"),causes(failure));
                assertEquals(1,lab.applicationPosts.get());
                assertEquals(protocol==HttpAuthentication.Protocol.BASIC?2:3,lab.requests.size());
            }
        }
    }

    @ParameterizedTest @EnumSource(HttpAuthentication.Protocol.class)
    void aServerThatActsBefore401DoesNotHaveAnExecuteOnceGuarantee(HttpAuthentication.Protocol protocol) throws Exception {
        try(var lab=IntegrationFixtures.httpAuthentication(protocol.name(),null);
            var workers=Executors.newFixedThreadPool(2);var deadlines=Executors.newSingleThreadScheduledExecutor();
            var service=transport(protocol,"user-a","alpha-password",lab.url("/"),SSLContext.getDefault(),workers,deadlines)) {
            var post=new HttpAuthenticationService.Request(lab.url("/action-before-auth"),"POST",List.of(),bpsh.support.IntegrationFixtures.httpBody(new byte[]{1}));
            assertUser(bpsh.support.IntegrationFixtures.httpExchange(service,post,deadline()).get(5,TimeUnit.SECONDS),"user-a",protocol);
            assertEquals(protocol==HttpAuthentication.Protocol.BASIC?2:3,lab.applicationPosts.get());
        }
    }

    @Test void traceIsRejectedWithoutSendingToTheDestination() throws Exception {
        try(var lab=IntegrationFixtures.httpAuthentication("BASIC",null);
            var workers=Executors.newFixedThreadPool(2);var deadlines=Executors.newSingleThreadScheduledExecutor();
            var service=transport(HttpAuthentication.Protocol.BASIC,"user-a","alpha-password",lab.url("/"),SSLContext.getDefault(),workers,deadlines)) {
            var trace=new HttpAuthenticationService.Request(lab.url("/whoami"),"TRACE",List.of(),bpsh.support.IntegrationFixtures.httpBody(new byte[0]));
            var failure=assertThrows(java.util.concurrent.ExecutionException.class,()->bpsh.support.IntegrationFixtures.httpExchange(service,trace,deadline()).get(5,TimeUnit.SECONDS));
            assertTrue(causes(failure).contains("TRACE"),causes(failure));
            assertEquals(0,lab.requests.size());
        }
    }

    @ParameterizedTest @EnumSource(HttpAuthentication.Protocol.class)
    void browserApplicationAuthorizationIsNeverReplacedOrChallenged(HttpAuthentication.Protocol protocol) throws Exception {
        try(var lab=IntegrationFixtures.httpAuthentication(protocol.name(),null);
            var workers=Executors.newFixedThreadPool(2);var deadlines=Executors.newSingleThreadScheduledExecutor();
            var service=transport(protocol,"user-a","alpha-password",lab.url("/"),SSLContext.getDefault(),workers,deadlines)) {
            var bearer=new HttpAuthenticationService.Request(lab.url("/whoami"),"GET",
                    List.of(new HttpAuthenticationService.Header("Authorization","Bearer application")),bpsh.support.IntegrationFixtures.httpBody(new byte[0]),
                    HttpAuthenticationService.AuthorizationPolicy.PRESERVE_APPLICATION);
            assertEquals(401,bpsh.support.IntegrationFixtures.httpExchange(service,bearer,deadline()).get(5,TimeUnit.SECONDS).status());
            assertEquals(1,lab.requests.size());assertEquals(0,lab.handshakes.get());
            assertUser(await(service,lab.url("/whoami")),"user-a",protocol);
            int before=lab.requests.size();
            var response=bpsh.support.IntegrationFixtures.httpExchange(service,bearer,deadline()).get(5,TimeUnit.SECONDS);
            assertEquals(protocol==HttpAuthentication.Protocol.BASIC?401:200,response.status());
            assertEquals(before+1,lab.requests.size());
            if(protocol!=HttpAuthentication.Protocol.BASIC)assertEquals(HttpAuthenticationEvidence.Status.ACCEPTED,response.authentication().status());
            var duplicate=new HttpAuthenticationService.Request(lab.url("/whoami"),"GET",
                    List.of(new HttpAuthenticationService.Header("Authorization","Bearer a"),new HttpAuthenticationService.Header("authorization","Bearer b")),bpsh.support.IntegrationFixtures.httpBody(new byte[0]),HttpAuthenticationService.AuthorizationPolicy.PRESERVE_APPLICATION);
            before=lab.requests.size();
            assertThrows(java.util.concurrent.ExecutionException.class,()->bpsh.support.IntegrationFixtures.httpExchange(service,duplicate,deadline()).get(5,TimeUnit.SECONDS));
            assertEquals(before,lab.requests.size());
        }
    }

    private static String causes(Throwable error) {
        StringBuilder result=new StringBuilder();
        for(Throwable next=error;next!=null;next=next.getCause())result.append(next.getMessage()).append('\n');
        return result.toString();
    }

    @Test void ntlmv2ProvesDestinationTlsChannelBindingAndStillVerifiesServerTrust() throws Exception {
        var ca=lab.auth.LabTls.prepare(temporary.resolve("ca"));
        var tls=lab.auth.LabTls.createServer(ca,temporary.resolve("server"));
        try(var lab=IntegrationFixtures.httpAuthentication("NTLM_V2",tls.serverContext());
            var workers=Executors.newFixedThreadPool(4);var deadlines=Executors.newSingleThreadScheduledExecutor();
            var service=transport(HttpAuthentication.Protocol.NTLM_V2,"user-a","alpha-password",lab.url("/"),tls.clientContext(),workers,deadlines);
            var untrusted=transport(HttpAuthentication.Protocol.NTLM_V2,"user-a","alpha-password",lab.url("/"),SSLContext.getDefault(),workers,deadlines)) {
            assertUser(await(service,lab.url("/whoami")),"user-a",HttpAuthentication.Protocol.NTLM_V2);
            assertEquals(1,lab.handshakes.get());
            assertThrows(java.util.concurrent.ExecutionException.class,()->await(untrusted,lab.url("/whoami")));
            assertEquals(1,lab.handshakes.get());
            URI other=URI.create(lab.url("/whoami").toString().replace("127.0.0.1","localhost"));
            assertThrows(java.util.concurrent.ExecutionException.class,()->await(service,other));
        }
    }

    @Test void selectedProtocolNeverFallsBackToADifferentServerChallenge() throws Exception {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.protocol.no-downgrade");
        var statuses=new java.util.ArrayList<Integer>();int accepted=0,handshakes=0;
        for(var selected:HttpAuthentication.Protocol.values())for(var offered:HttpAuthentication.Protocol.values())if(selected!=offered) {
            try(var lab=IntegrationFixtures.httpAuthentication(offered.name(),null);
                var workers=Executors.newFixedThreadPool(2);var deadlines=Executors.newSingleThreadScheduledExecutor();
                var service=transport(selected,"user-a","alpha-password",lab.url("/"),SSLContext.getDefault(),workers,deadlines);
                var response=await(service,lab.url("/whoami"))) {
                assertEquals(401,response.status(),selected+" against "+offered);
                assertNotEquals(HttpAuthenticationEvidence.Status.ACCEPTED,response.authentication().status());
                assertEquals(0,lab.handshakes.get());assertTrue(lab.observations.isEmpty());
                assertTrue(lab.requests.size()<=4);
            statuses.add(response.status());accepted+=lab.observations.size();handshakes+=lab.handshakes.get();proof.put("statuses",statuses);proof.put("accepted",accepted);proof.put("handshakes",handshakes);
            }
        }
        proof.write();
    }

    private static HttpClientAuthenticationTransport transport(HttpAuthentication.Protocol protocol,String user,String password,URI origin,SSLContext tls,
            java.util.concurrent.ExecutorService workers,java.util.concurrent.ScheduledExecutorService deadlines) {
        return new HttpClientAuthenticationTransport(new HttpAuthentication(protocol,user,"LAB","",Set.of(origin)),password.toCharArray(),tls,workers,deadlines);
    }
    private static HttpAuthenticationService.Request request(URI uri) {return new HttpAuthenticationService.Request(uri,"GET",List.of(),bpsh.support.IntegrationFixtures.httpBody(new byte[0]));}
    private static long deadline() {return System.nanoTime()+TimeUnit.SECONDS.toNanos(8);}
    private static HttpAuthenticationService.Response await(HttpAuthenticationService service,URI uri) throws Exception {return bpsh.support.IntegrationFixtures.httpExchange(service,request(uri),deadline()).get(10,TimeUnit.SECONDS);}
    private static void assertUser(HttpAuthenticationService.Response response,String user,HttpAuthentication.Protocol protocol) {
        assertEquals(200,response.status());assertTrue(new String(bpsh.support.IntegrationFixtures.httpBytes(response),StandardCharsets.UTF_8).contains("\"user\":\""+user+"\""));
        assertEquals(protocol,response.authentication().protocol());assertEquals(HttpAuthenticationEvidence.Status.ACCEPTED,response.authentication().status());
    }
}
