package lab.auth;

import com.sun.net.httpserver.*;
import javax.net.ssl.*;
import java.io.IOException;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.Predicate;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.*;
import org.littleshoot.proxy.*;
import org.littleshoot.proxy.impl.DefaultHttpProxyServer;
import org.littleshoot.proxy.impl.ThreadPoolConfiguration;

/** Shared transport applications used by native checks and foreground serving. No extension logic lives here. */
public final class TransportFixtures {
    private TransportFixtures() {}
    public static final Set<String> SERVABLE=Set.of("TLS.proxy.direct","TLS.proxy.http-proxy","TLS.proxy.connect","TLS.proxy.proxy-unavailable","TLS.proxy.no-direct-fallback",
            "TLS.mtls.expected-fingerprint","TLS.mtls.same-CN-pair","TLS.mtls.missing-certificate","TLS.mtls.token-unavailable","TLS.mtls.allowed-redirect","TLS.mtls.disallowed-origin",
            "TLS.mtls.resource-without-mtls","TLS.trust.untrusted-origin","TLS.trust.wrong-host");

    /** Explicitly prepared software material. Loading this record never opens a token or submits a PIN. */
    public record Material(Path root,Path module,Map<String,String> fingerprints) {
        public Material { fingerprints=Map.copyOf(fingerprints); }
        public static Material load(Path workspace,Path manifest) throws Exception {
            Path prepared=workspace.resolve("test/authentication-lab/build/prepared/pkcs11").toRealPath();
            Path file=manifest.toRealPath(),root=file.getParent();
            if(!file.getFileName().toString().equals("fixture.json")||!root.getParent().equals(prepared))throw new IllegalArgumentException("Expected owned software fixture.");
            UUID.fromString(root.getFileName().toString());
            var data=ScenarioCatalog.parseJson(Files.readAllBytes(file)).getAsJsonObject();
            var marker=ScenarioCatalog.parseJson(Files.readAllBytes(root.resolve(".fixture-owned.json"))).getAsJsonObject();
            if(data.get("formatVersion").getAsInt()!=1||!LabRun.text(marker,"purpose").equals("isolated-bpsh-tests")||
                    !LabRun.text(marker,"fixtureId").equals(LabRun.text(data,"fixtureId"))||!Path.of(LabRun.text(data,"root")).toRealPath().equals(root))throw new IllegalArgumentException("Unproven software fixture.");
            Path module=Path.of(LabRun.text(data,"module")).toRealPath();
            if(!module.getFileName().toString().equalsIgnoreCase("softhsm2-x64.dll"))throw new IllegalArgumentException("Expected the prepared software module.");
            var configuration=Files.readAllLines(root.resolve("softhsm2.conf"));
            if(!configuration.equals(List.of("directories.tokendir = "+root.resolve("tokens").toString().replace('\\','/'),"objectstore.backend = file","log.level = ERROR"))||!root.resolve("tokens").toRealPath().getParent().equals(root))throw new IllegalArgumentException("Unexpected software-token configuration.");
            var fingerprints=new LinkedHashMap<String,String>();
            for(String role:List.of("employee","admin")) {
                String expected=LabRun.text(data.getAsJsonObject("fingerprints"),role);
                try(var input=Files.newInputStream(root.resolve(role+".crt"))) {
                    var certificate=CertificateFactory.getInstance("X.509").generateCertificate(input);
                    if(!expected.matches("[0-9a-f]{64}")||!expected.equals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()))))throw new IllegalArgumentException("Fixture certificate changed.");
                }
                fingerprints.put(role,expected);
            }
            if(new HashSet<>(fingerprints.values()).size()!=2)throw new IllegalArgumentException("Expected distinct identities.");
            return new Material(root,module,fingerprints);
        }
        void claim(UUID invocation,UUID run) throws IOException {
            Path claim=root.resolve(".authlab-claimed.json");
            Files.writeString(claim,LabRun.JSON.toJson(Map.of("invocationId",invocation.toString(),"runId",run.toString(),"taskPath",":authLabServe","softwareOnly",true)),StandardOpenOption.CREATE_NEW);
            LabRun.restrict(claim);
        }
    }

    /** One active transport case; the case's normal clock, revocation and fault controls remain authoritative. */
    public static final class Serving implements AutoCloseable {
        private final LabRun.CaseLease lease;
        private final Material material;
        private final List<AutoCloseable> owned=new ArrayList<>();
        private final List<ControlledApplication.Origin> origins=new ArrayList<>();
        private CertificateIssuer identity;
        private ControlledApplication.Origin issuer,redirector,unlisted,wrongHost,resource;
        private UnauthenticatedProxy proxy;
        private Socket unavailable;
        private volatile boolean closed;
        public Serving(LabRun.CaseLease lease,Material material) throws Exception {
            this.lease=lease;this.material=material;
            if(!SERVABLE.contains(lease.id()))throw new IllegalArgumentException("Use the existing operational owner for this transport case.");
            try {
                identity=own(new CertificateIssuer(Map.of(material.fingerprints().get("employee"),new CertificateIdentity("employee","user"),material.fingerprints().get("admin"),new CertificateIdentity("admin","admin")),lease.identities,0,false));
                issuer=origin(https(material.root(),false,ClientAuth.REQUIRED));
                redirector=origin(https(material.root(),false,ClientAuth.REQUIRED));
                unlisted=origin(https(material.root(),false,ClientAuth.OPTIONAL));
                wrongHost=origin(https(material.root(),true,ClientAuth.REQUIRED));
                resource=origin(ControlledApplication.Origin.http("127.0.0.1"));
                issuer.route("/",exchange->handle(exchange,identity::issuer));
                wrongHost.route("/",exchange->handle(exchange,identity::issuer));
                redirector.route("/",exchange->handle(exchange,e->identity.redirect(e,version(lease.id().equals("TLS.mtls.disallowed-origin")?unlisted.url("/"):issuer.url("/")))));
                unlisted.route("/",exchange->handle(exchange,e->{
                    boolean present;try{((HttpsExchange)e).getSSLSession().getPeerCertificates();present=true;}catch(SSLPeerUnverifiedException absent){present=false;}
                    synchronized(lease){lease.event(LabRun.Phase.LOGIN,present?"unlisted-certificate-present":"unlisted-certificate-absent",List.of());}
                    ControlledApplication.Origin.reply(e,403,"application/json","{\"error\":\"unlisted_authentication_server\"}");
                }));
                resource.route("/protected",exchange->handle(exchange,e->{if(identity.resource(e,true)&&e.getRequestMethod().equals("POST"))lease.actions.incrementAndGet();}));
                origins.forEach(ControlledApplication.Origin::start);
                Set<Integer> allowed=new HashSet<>();origins.forEach(origin->allowed.add(origin.url("/").getPort()));allowed.add(lease.endpoint("start").getPort());
                proxy=own(new UnauthenticatedProxy(null,uri->allowed.contains(uri.getPort())));
                unavailable=own(new Socket());unavailable.bind(new InetSocketAddress("127.0.0.1",0));
            }catch(Exception failure){try{close();}catch(Exception cleanup){failure.addSuppressed(cleanup);}throw failure;}
        }
        private <T extends AutoCloseable>T own(T value){owned.add(value);return value;}
        private ControlledApplication.Origin origin(ControlledApplication.Origin value){origins.add(value);return own(value);}
        private URI version(URI uri){return URI.create(uri+(uri.getRawQuery()==null?"?":"&")+"generation="+lease.generation());}
        private void handle(HttpExchange exchange,HttpHandler handler) throws IOException {
            boolean entered=false;
            try {
                if(closed)throw LabRun.error(410,"RETIRED");
                if(ControlledApplication.generation(exchange)!=lease.generation())throw LabRun.error(409,"GENERATION_CONFLICT");
                lease.enter();entered=true;lease.routed.incrementAndGet();
                var phase=exchange.getRequestURI().getPath().equals("/protected")?LabRun.Phase.PROTECTED:exchange.getRequestURI().getPath().equals("/token")?LabRun.Phase.TOKEN_EXCHANGE:LabRun.Phase.LOGIN;
                if(ControlledApplication.faults(exchange,lease.hit(phase)))handler.handle(exchange);
            }catch(LabRun.ControlException failure){ControlledApplication.Origin.reply(exchange,failure.status(),"application/json",LabRun.JSON.toJson(Map.of("error",failure.code())));}
            finally{if(entered)lease.leave();exchange.close();}
        }
        public URI startUri(){
            if(Set.of("TLS.proxy.direct","TLS.proxy.http-proxy","TLS.proxy.no-direct-fallback").contains(lease.id()))return lease.endpoint("start");
            var origin=lease.id().equals("TLS.mtls.allowed-redirect")||lease.id().equals("TLS.mtls.disallowed-origin")?redirector:lease.id().equals("TLS.trust.wrong-host")?wrongHost:issuer;
            return version(origin.url("/login?identity=employee"));
        }
        public Map<String,Object> targets(){
            var result=new LinkedHashMap<String,Object>();result.put("caseId",lease.id());result.put("caseGeneration",lease.generation());
            result.put("issuerOrigin",issuer.url("").toString());result.put("redirectOrigin",redirector.url("").toString());result.put("unlistedOrigin",unlisted.url("").toString());
            result.put("wrongHostOrigin",wrongHost.url("").toString());result.put("resourceUri",version(resource.url("/protected")).toString());
            result.put("proxyUri",proxy.url().toString());result.put("unavailableProxyUri","http://127.0.0.1:"+unavailable.getLocalPort());
            result.put("modulePath",material.module().toString());result.put("configurationPath",material.root().resolve("softhsm2.conf").toString());
            result.put("trustedCaPath",material.root().resolve("ca.crt").toString());result.put("fingerprints",material.fingerprints());result.put("softwareOnly",true);return result;
        }
        public Map<String,Object> observations(){return Map.of("certificate",identity.metrics(),"issuanceIds",identity.issuanceLabels(),"proxyRequests",proxy.requestCounter().get(),"configuredProxyCredentialHeaders",proxy.credentialHeaders());}
        @Override public void close() throws Exception {
            closed=true;Exception failure=null;
            for(int index=owned.size()-1;index>=0;index--)try{owned.get(index).close();}catch(Exception cleanup){if(failure==null)failure=cleanup;else failure.addSuppressed(cleanup);}
            if(failure!=null)throw failure;
        }
    }

    public record ProxyDecision(boolean forward,String userAgent) {}
    @FunctionalInterface public interface RequestPolicy {ProxyDecision observe(String method,String path,String userAgent,long requestId);}
    /** The inspected HTTP/CONNECT proxy, with no authentication interface and only owned local destinations. */
    public static final class UnauthenticatedProxy implements AutoCloseable {
        private final HttpProxyServer server;
        private final AtomicLong requests=new AtomicLong(),credentialHeaders=new AtomicLong();
        public UnauthenticatedProxy(RequestPolicy observer,Predicate<URI> destination) {
            server=DefaultHttpProxyServer.bootstrap().withName("authlab-unauthenticated-proxy").withAddress(new InetSocketAddress("127.0.0.1",0))
                    .withAllowLocalOnly(true).withThreadPoolConfiguration(new ThreadPoolConfiguration().withAcceptorThreads(1).withClientToProxyWorkerThreads(2).withProxyToServerWorkerThreads(2))
                    .withFiltersSource(new HttpFiltersSourceAdapter(){
                        @Override public HttpFilters filterRequest(HttpRequest request,ChannelHandlerContext context){return new HttpFiltersAdapter(request,context){
                            @Override public HttpResponse clientToProxyRequest(HttpObject object) {
                                if(object instanceof HttpRequest incoming) {
                                    // Presence only: detect extension-owned attempt credentials before a proxy can strip them.
                                    if(incoming.headers().contains("Proxy-Authorization"))credentialHeaders.incrementAndGet();
                                    try {
                                        String raw=incoming.uri();URI uri=URI.create(incoming.method().equals(HttpMethod.CONNECT)?"http://"+raw:raw.startsWith("/")?"http://"+incoming.headers().get("Host")+raw:raw);
                                        if(uri.getUserInfo()!=null||uri.getFragment()!=null||!Set.of("localhost","127.0.0.1","::1","[::1]").contains(uri.getHost())||!destination.test(uri))return rejected(HttpResponseStatus.FORBIDDEN);
                                    }catch(RuntimeException malformed){return rejected(HttpResponseStatus.BAD_REQUEST);}
                                }
                                return null;
                            }
                            @Override public HttpResponse proxyToServerRequest(HttpObject object) {
                                if(object instanceof HttpRequest outgoing) {
                                    long id=requests.incrementAndGet();String path;
                                    try{path=URI.create(outgoing.uri()).getRawPath();}catch(RuntimeException malformed){path="CONNECT";}
                                    var decision=observer==null?new ProxyDecision(true,outgoing.headers().get("User-Agent")):observer.observe(outgoing.method().name(),path,outgoing.headers().get("User-Agent"),id);
                                    if(!decision.forward())return rejected(HttpResponseStatus.BAD_REQUEST);
                                    if(decision.userAgent()!=null)outgoing.headers().set("User-Agent",decision.userAgent());
                                    outgoing.headers().remove("Proxy-Authorization");
                                }
                                return null;
                            }
                        };}
                    }).start();
        }
        private static HttpResponse rejected(HttpResponseStatus status){var response=new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,status);response.headers().set("Content-Length",0);return response;}
        public HttpProxyServer server(){return server;}
        public URI url(){return URI.create("http://127.0.0.1:"+server.getListenAddress().getPort());}
        public AtomicLong requestCounter(){return requests;}
        public long credentialHeaders(){return credentialHeaders.get();}
        @Override public void close(){server.abort();}
    }

    /** Reuses the inspected strict TLS fixture with the canonical listener owner. */
    public enum ClientAuth { NONE, OPTIONAL, REQUIRED }
    public static ControlledApplication.Origin https(Path root,boolean wrongHost,boolean clientAuth) throws Exception {return https(root,wrongHost,clientAuth?ClientAuth.REQUIRED:ClientAuth.NONE);}
    public static ControlledApplication.Origin https(Path root,boolean wrongHost,ClientAuth clientAuth) throws Exception {
        KeyStore store=KeyStore.getInstance("JKS");store.load(null,null);
        String pem=Files.readString(root.resolve("server.key")).replace("-----BEGIN PRIVATE KEY-----","").replace("-----END PRIVATE KEY-----","");
        var key=KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(pem)));
        var certificates=CertificateFactory.getInstance("X.509");java.security.cert.Certificate certificate,ca;
        try(var input=Files.newInputStream(root.resolve(wrongHost?"wrong-host.crt":"server.crt"))){certificate=certificates.generateCertificate(input);}
        try(var input=Files.newInputStream(root.resolve("ca.crt"))){ca=certificates.generateCertificate(input);}
        char[] password="disposable-fixture-key".toCharArray();var keys=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        try{store.setKeyEntry("fixture-server",key,password,new java.security.cert.Certificate[]{certificate,ca});keys.init(store,password);}finally{Arrays.fill(password,'\0');}
        var trusted=KeyStore.getInstance("JKS");trusted.load(null,null);trusted.setCertificateEntry("fixture-ca",ca);
        var trust=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());trust.init(trusted);
        var context=SSLContext.getInstance("TLS");context.init(keys.getKeyManagers(),trust.getTrustManagers(),null);
        var server=HttpsServer.create(new InetSocketAddress("127.0.0.1",0),128);
        server.setHttpsConfigurator(new HttpsConfigurator(context){
            @Override public void configure(HttpsParameters parameters){var ssl=context.getDefaultSSLParameters();if(clientAuth==ClientAuth.OPTIONAL)ssl.setWantClientAuth(true);else ssl.setNeedClientAuth(clientAuth==ClientAuth.REQUIRED);parameters.setSSLParameters(ssl);}
        });
        return new ControlledApplication.Origin(server,"https","localhost");
    }

    public record CertificateIdentity(String role,String account) {}
    public record IdentityMetrics(int tlsRequests,boolean allCertificatesMatched,int proxyCredentialHeaders,
                                  Set<String> certificateRoles,Set<String> redirectedRoles,Set<String> protectedRoles,boolean sessionReusedAcrossReconnect) {}

    /** The certificate chooses the account; the shared identity store issues and accepts the credential. */
    public static final class CertificateIssuer implements AutoCloseable {
        private final Map<String,CertificateIdentity> identities;
        private final Map<String,String> rolesByAccount;
        private final Map<String,CertificateIdentity> certificateIssuances=new ConcurrentHashMap<>();
        private final FixtureIdentityStore store;
        private final boolean ownsStore;
        private final int repetitions;
        private final AtomicInteger tlsRequests=new AtomicInteger(),proxyHeaders=new AtomicInteger();
        private final AtomicBoolean matched=new AtomicBoolean(true);
        private final Set<String> certificateRoles=ConcurrentHashMap.newKeySet(),redirectedRoles=ConcurrentHashMap.newKeySet(),protectedRoles=ConcurrentHashMap.newKeySet();
        private final Map<String,Set<Integer>> sessions=new ConcurrentHashMap<>();
        private volatile boolean closed;
        public CertificateIssuer(Map<String,CertificateIdentity> identities,int repetitions){this(identities,new FixtureIdentityStore(),repetitions,true);}
        CertificateIssuer(Map<String,CertificateIdentity> identities,FixtureIdentityStore store,int repetitions,boolean ownsStore) {
            this.identities=Map.copyOf(identities);this.store=store;this.ownsStore=ownsStore;this.repetitions=repetitions;
            if(identities.size()!=2||repetitions<0||repetitions>100)throw new IllegalArgumentException("Expected two owned identities and a bounded request count.");
            var accounts=new HashMap<String,String>();
            for(var entry:identities.entrySet()) {
                if(!entry.getKey().matches("[0-9a-f]{64}")||!Set.of("employee","admin").contains(entry.getValue().role())||!Set.of("user","admin").contains(entry.getValue().account())||accounts.put(entry.getValue().account(),entry.getValue().role())!=null)throw new IllegalArgumentException("Invalid owned certificate identity.");
            }
            rolesByAccount=Map.copyOf(accounts);
        }
        private CertificateIdentity peer(HttpExchange exchange) throws Exception {
            if(closed)throw new IllegalStateException("Certificate issuer retired.");
            var https=(HttpsExchange)exchange;var certificate=(X509Certificate)https.getSSLSession().getPeerCertificates()[0];
            String fingerprint=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
            var identity=identities.get(fingerprint);tlsRequests.incrementAndGet();
            if(exchange.getRequestHeaders().getFirst("Proxy-Authorization")!=null)proxyHeaders.incrementAndGet();
            String requested=ControlledApplication.parameters(exchange.getRequestURI().getRawQuery()).get("identity");
            if(identity==null||requested!=null&&!requested.equals(identity.role())){matched.set(false);return null;}
            certificateRoles.add(identity.role());sessions.computeIfAbsent(identity.role()+":"+https.getSSLSession().getCreationTime(),ignored->ConcurrentHashMap.newKeySet()).add(exchange.getRemoteAddress().getPort());
            return identity;
        }
        public void issuer(HttpExchange exchange) throws IOException {
            try {
                var identity=peer(exchange);if(identity==null){ControlledApplication.Origin.reply(exchange,403,"text/plain","wrong certificate");return;}
                switch(exchange.getRequestURI().getPath()) {
                    case "/login" -> ControlledApplication.Origin.reply(exchange,200,"text/html","<script>(async()=>{const query=new URLSearchParams(location.search);query.set('identity','"+identity.role()+"');for(let i=0;i<"+repetitions+";i++)await fetch((i>=35?'/rotate':'/check')+'?'+query);await fetch('/token?'+query);})();</script>");
                    case "/token" -> {
                        var issued=store.issueVerified(identity.account());
                        certificateIssuances.put(issued.id(),identity);
                        json(exchange,200,Map.of("access_token",issued.credential(FixtureIdentityStore.Role.B).reveal(),"issuanceId",issued.id(),"expires_in",60));
                    }
                    default -> {if(exchange.getRequestURI().getPath().equals("/rotate"))exchange.getResponseHeaders().set("Connection","close");ControlledApplication.Origin.reply(exchange,200,"text/plain",identity.role());}
                }
            }catch(SSLPeerUnverifiedException absent){json(exchange,401,Map.of("error","client_certificate_absent"));}
            catch(IOException error){throw error;}catch(Exception failure){exchange.close();}
        }
        public void redirect(HttpExchange exchange,URI issuerOrigin) throws IOException {
            try {
                var identity=peer(exchange);if(identity==null){ControlledApplication.Origin.reply(exchange,403,"text/plain","wrong certificate");return;}
                redirectedRoles.add(identity.role());String query=issuerOrigin.getRawQuery();exchange.getResponseHeaders().set("Location",issuerOrigin.resolve("/login").toString()+"?identity="+identity.role()+(query==null?"":"&"+query));ControlledApplication.Origin.reply(exchange,302,"text/plain","Redirect");
            }catch(IOException error){throw error;}catch(Exception failure){exchange.close();}
        }
        public boolean resource(HttpExchange exchange,boolean json) throws IOException {
            String authorization=exchange.getRequestHeaders().getFirst("Authorization");
            var accepted=closed||authorization==null||!authorization.startsWith("Bearer ")?null:store.accept(Map.of(FixtureIdentityStore.Role.B,authorization.substring(7)),false);
            if(accepted==null){ControlledApplication.Origin.reply(exchange,401,"text/plain","unauthorized");return false;}
            var identity=certificateIssuances.get(accepted.issuanceIds().getFirst());
            if(identity==null||!identity.account().equals(accepted.accountId())){ControlledApplication.Origin.reply(exchange,401,"text/plain","unauthorized");return false;}
            String role=rolesByAccount.get(accepted.accountId());protectedRoles.add(role);
            if(json)json(exchange,200,Map.of("accountId",accepted.accountId(),"certificateIdentity",role,"issuanceId",accepted.issuanceIds().getFirst()));
            else ControlledApplication.Origin.reply(exchange,200,"text/plain",role);
            return true;
        }
        private static void json(HttpExchange exchange,int status,Object body) throws IOException {ControlledApplication.Origin.reply(exchange,status,"application/json; charset=utf-8",LabRun.JSON.toJson(body));}
        public IdentityMetrics metrics(){return new IdentityMetrics(tlsRequests.get(),matched.get(),proxyHeaders.get(),Set.copyOf(certificateRoles),Set.copyOf(redirectedRoles),Set.copyOf(protectedRoles),sessions.values().stream().anyMatch(ports->ports.size()>1));}
        public List<String> issuanceLabels(){return certificateIssuances.keySet().stream().sorted().toList();}
        @Override public void close(){closed=true;certificateIssuances.clear();if(ownsStore)store.clear();}
    }
}
