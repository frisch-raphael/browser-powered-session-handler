package lab.auth;

import com.google.gson.*;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

/** Run-owned federation infrastructure. Provider bootstrap is separate from client/protocol acceptance. */
public final class FederationEnvironment implements AutoCloseable {
    public record Spec(Path providerLock, Path downstreamTemplate, LabTls.PreparedCa ca,Path upstreamTemplate) {
        public Spec { Objects.requireNonNull(providerLock); Objects.requireNonNull(downstreamTemplate); Objects.requireNonNull(ca); }
        public Spec(Path providerLock,Path downstreamTemplate,LabTls.PreparedCa ca){this(providerLock,downstreamTemplate,ca,null);}
    }
    public record Ports(int client, int resource, int downstream,int upstream) {
        public Ports(int client,int resource,int downstream){this(client,resource,downstream,0);}
        public Ports {
            if (List.of(client,resource,downstream).stream().anyMatch(p->p<40000||p>49999) || new HashSet<>(List.of(client,resource,downstream)).size()!=3)
                throw new IllegalArgumentException("Use a distinct leased federation port tuple.");
            if(upstream!=0&&(upstream<40000||upstream>49999||List.of(client,resource,downstream).contains(upstream)))throw new IllegalArgumentException("Use a distinct leased upstream port.");
        }
        public URI clientOrigin() { return URI.create("https://app.authlab.test:"+client); }
        public URI resourceOrigin() { return URI.create("https://api.authlab.test:"+resource); }
        public URI issuer() { return URI.create("https://idp.federation.test:"+downstream+"/realms/authlab-downstream"); }
        public URI upstreamIssuer(){if(upstream==0)throw new IllegalStateException("No upstream is prepared.");return URI.create("https://idp.upstream-sso.test:"+upstream+"/realms/authlab-upstream");}
    }
    private static final Set<String> CLIENTS=Set.of("browser-client","backend-client","cookie-verifier","wrong-client-control","wrong-audience-client","authlab-api","authlab-sp");
    private final LabRun owner;
    private final Spec spec;
    private final Path directory;
    private final String createdAt=Instant.now().toString();
    private final AtomicBoolean closed=new AtomicBoolean();
    private final ReentrantLock launch=new ReentrantLock();
    private final List<Map<String,Object>> dockerResources=new CopyOnWriteArrayList<>();
    private final Map<String,FixtureIdentityStore.Secret> clientSecrets=new LinkedHashMap<>();
    private final FixtureIdentityStore.Secret adminSecret=FixtureIdentityStore.randomSecret();
    private HttpClient providerHttp;
    private JsonObject realmSeed;
    private JsonObject upstreamSeed;
    private volatile FederationApplications applications;
    private PortLease lease;
    private volatile boolean complete;
    private String networkId;
    private volatile boolean unknownCreatedId;

    private FederationEnvironment(LabRun owner, Spec spec) throws IOException {
        this.owner=owner;this.spec=spec;
        directory=Files.createDirectory(owner.directory().resolve("federation-"+UUID.randomUUID()));LabRun.restrict(directory);
        for(String id:List.of("backend-client","wrong-client-control","wrong-audience-client"))clientSecrets.put(id,FixtureIdentityStore.randomSecret());
    }

    /** Starts only a prepared pinned provider, with readiness and ownership proof. Does not claim client login support. */
    public static FederationEnvironment startProvider(LabRun owner, Spec spec) throws Exception {
        var environment=new FederationEnvironment(owner,spec);owner.attachFederation(environment);
        try { environment.startProvider();owner.federationReady(environment);return environment; }
        catch(Exception error) {
            try { environment.close(); } catch(Exception cleanup) { error.addSuppressed(cleanup); }
            owner.federationFailed();throw error;
        }
    }
    public Ports ports() { if(lease==null)throw new IllegalStateException("Provider ports are not leased.");return lease.ports; }
    public Path directory() { return directory; }
    public boolean providerReady() { return complete&&!closed.get(); }
    public HttpClient.Builder clientBuilder() { if(!providerReady())throw new IllegalStateException("Provider is not ready.");return ControlledApplication.localClientBuilder().sslContext(providerHttp.sslContext()); }
    public FixtureIdentityStore.Secret clientSecret(String id) { var result=clientSecrets.get(id);if(result==null)throw new IllegalArgumentException("Unknown private client.");return result; }
    LabTls.PreparedCa ca() { return spec.ca(); }
    void handoff(int port) throws IOException { if(closed.get())throw new IOException("Provider environment retired.");lease.handoff(port); }
    /** A fixed origin tuple serves one case at a time; reset closes the previous pair before new admission. */
    public FederationApplications startApplications(LabRun.CaseLease target,Path runtimeManifest) throws Exception {
        if(owner.find(target.id(),target.generation())!=target)throw LabRun.error(409,"STATE_CONFLICT");
        var prepared=new FederationApplications(owner,target,this,runtimeManifest);
        synchronized(this) {
            if(!providerReady()||applications!=null&&!applications.closed())throw LabRun.error(409,"STATE_CONFLICT");
            target.attachFederationApplications(prepared);applications=prepared;
        }
        prepared.start();owner.federationChanged();return prepared;
    }
    @Override public String toString() { return "FederationEnvironment[runId="+owner.runId()+", ready="+providerReady()+"]"; }
    /** Independent read-only observation after cleanup; only previously owned immutable IDs may be supplied. */
    public static void confirmResourceAbsent(String kind,String id) throws Exception {
        if(!Set.of("CONTAINER","NETWORK").contains(kind)||!id.matches("[a-f0-9]{64}"))throw new IllegalArgumentException("Invalid owned resource identity.");
        var process=new ProcessBuilder("docker",kind.equals("CONTAINER")?"container":"network","inspect","--format","{{.Id}}",id).redirectErrorStream(true).start();
        try(var reader=Executors.newVirtualThreadPerTaskExecutor()) {
            var output=reader.submit(()->new String(process.getInputStream().readNBytes(4097),StandardCharsets.UTF_8));
            try {
                if(!process.waitFor(5,TimeUnit.SECONDS))throw new IOException("Owned resource absence deadline.");
                String text=output.get(1,TimeUnit.SECONDS);
                if(process.exitValue()==0||!(text.contains("No such object: "+id)||text.contains("No such container: "+id)||text.contains("No such network: "+id)
                        ||kind.equals("NETWORK")&&text.contains("network "+id+" not found")))throw new IOException("Owned resource absence was not established.");
            }finally{if(process.isAlive())process.destroyForcibly();output.cancel(true);}
        }
    }

    /** Returns observed owned IDs only; command environments and imported secrets never enter the descriptor. */
    List<Map<String,Object>> resources() {
        var resources=new ArrayList<Map<String,Object>>();
        resources.add(Map.of("kind","DIRECTORY","id",directory.toString(),"ownerRunId",owner.runId().toString(),"createdAt",createdAt,
                "proof",Map.of("resolvedPath",directory.toString())));
        resources.addAll(dockerResources);var apps=applications;if(apps!=null)resources.addAll(apps.resources());return List.copyOf(resources);
    }

    /** Uses only the prepared image; Docker is forbidden from implicitly pulling another artifact. */
    private void startProvider() throws Exception {
        var lock=ScenarioCatalog.parseJson(Files.readAllBytes(spec.providerLock())).getAsJsonObject().getAsJsonObject("provider");
        String image=LabRun.text(lock,"image"),imageId=LabRun.text(lock,"platformImageId");
        if(!image.matches("quay\\.io/keycloak/keycloak:26\\.8\\.1@sha256:[a-f0-9]{64}")||!imageId.matches("sha256:[a-f0-9]{64}")
                ||!"linux/amd64".equals(LabRun.text(lock,"platform")))throw new IOException("Unprepared provider image pin.");
        var prepared=inspect("image",image);
        if(!imageId.equals(LabRun.text(prepared,"Id"))||!"linux".equals(LabRun.text(prepared,"Os"))||!"amd64".equals(LabRun.text(prepared,"Architecture")))
            throw new IOException("Prepared provider image identity differs.");
        lease=PortLease.reserve(owner.spec().environmentRoot().resolve("port-leases"),owner.runId(),spec.upstreamTemplate()!=null);
        Path env=directory.resolve("provider.env");
        Files.writeString(env,"KC_BOOTSTRAP_ADMIN_USERNAME=authlab-admin\nKC_BOOTSTRAP_ADMIN_PASSWORD="+adminSecret.reveal()+"\n");LabRun.restrict(env);
        createResource("NETWORK",List.of("network","create","--label","authlab.run="+owner.runId(),"--label","authlab.invocation="+owner.spec().invocationId(),"authlab-"+owner.runId()));
        networkId=dockerResources.getLast().get("id").toString();
        if(spec.upstreamTemplate()!=null) {
            upstreamSeed=renderUpstream(ScenarioCatalog.parseJson(Files.readAllBytes(spec.upstreamTemplate())).getAsJsonObject());
            var upstream=launchProvider("upstream","idp.upstream-sso.test",ports().upstream(),upstreamSeed,env,image,imageId);
            providerHttp=ControlledApplication.localClientBuilder().sslContext(upstream.tls().clientContext()).connectTimeout(Duration.ofSeconds(2)).build();
            awaitProvider(ports().upstreamIssuer(),upstream.id());
        }
        realmSeed=renderRealm(ScenarioCatalog.parseJson(Files.readAllBytes(spec.downstreamTemplate())).getAsJsonObject(),ports(),clientSecrets);
        var downstream=launchProvider("downstream","idp.federation.test",ports().downstream(),realmSeed,env,image,imageId);
        if(providerHttp==null)providerHttp=ControlledApplication.localClientBuilder().sslContext(downstream.tls().clientContext()).connectTimeout(Duration.ofSeconds(2)).build();
        awaitProvider(ports().issuer(),downstream.id());
        qualifySettings(System.nanoTime()+TimeUnit.SECONDS.toNanos(10));
        if(upstreamSeed!=null)configureBroker(true,System.nanoTime()+TimeUnit.SECONDS.toNanos(10));
        complete=true;
    }
    private record ProviderLaunch(LabTls.Material tls,String id) {}
    private ProviderLaunch launchProvider(String role,String host,int port,JsonObject realm,Path env,String image,String imageId) throws Exception {
        Path imports=Files.createDirectory(directory.resolve(role+"-import"));LabRun.restrict(imports);
        Path seed=imports.resolve("realm.json");Files.writeString(seed,LabRun.JSON.toJson(realm));LabRun.restrict(seed);
        var tls=LabTls.createServer(spec.ca(),directory.resolve(role+"-tls"),List.of(host));tls.exportServerPem();
        Files.copy(spec.ca().directory().resolve("ca.crt"),tls.keyStore().getParent().resolve("ca.crt"));
        lease.handoff(port);
        createResource("CONTAINER",List.of("run","--detach","--pull=never","--platform=linux/amd64","--name","authlab-"+owner.runId()+"-"+role,
                "--label","authlab.run="+owner.runId(),"--label","authlab.invocation="+owner.spec().invocationId(),
                "--network",networkId,"--network-alias",host,"--publish","127.0.0.1:"+port+":"+port,"--env-file",env.toString(),
                "--mount","type=bind,source="+imports.toRealPath()+",target=/opt/keycloak/data/import,readonly",
                "--mount","type=bind,source="+tls.keyStore().getParent()+",target=/opt/keycloak/conf/authlab-tls,readonly",image,
                "start-dev","--import-realm","--http-enabled=false","--https-port="+port,"--hostname=https://"+host+":"+port,
                "--https-certificate-file=/opt/keycloak/conf/authlab-tls/server-chain.pem","--https-certificate-key-file=/opt/keycloak/conf/authlab-tls/server-key.pem",
                "--truststore-paths=/opt/keycloak/conf/authlab-tls/ca.crt"));
        String id=dockerResources.getLast().get("id").toString();var actual=inspect("container",id);
        var binding=actual.getAsJsonObject("HostConfig").getAsJsonObject("PortBindings").getAsJsonArray(port+"/tcp");
        if(!imageId.equals(LabRun.text(actual,"Image"))||binding==null||binding.size()!=1||!"127.0.0.1".equals(LabRun.text(binding.get(0).getAsJsonObject(),"HostIp")))
            throw new IOException("Provider binding or image identity differs.");
        return new ProviderLaunch(tls,id);
    }
    private void awaitProvider(URI issuer,String containerId) throws Exception {
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(45);
        while(!closed.get()&&System.nanoTime()<deadline) {
            HttpResponse<InputStream> response=null;
            try{response=providerHttp.send(HttpRequest.newBuilder(URI.create(issuer+"/.well-known/openid-configuration")).timeout(Duration.ofSeconds(2)).GET().build(),HttpResponse.BodyHandlers.ofInputStream());}
            catch(IOException starting){}
            if(response!=null)try(var body=response.body()) {
                byte[] bytes=body.readNBytes(131_073);if(bytes.length>131_072)throw new IOException("Provider discovery output limit.");
                if(response.statusCode()==200) {
                    var discovery=ScenarioCatalog.parseJson(bytes).getAsJsonObject();
                    for(var entry:Map.of("issuer",issuer.toString(),"authorization_endpoint",issuer+"/protocol/openid-connect/auth",
                            "token_endpoint",issuer+"/protocol/openid-connect/token","jwks_uri",issuer+"/protocol/openid-connect/certs").entrySet())
                        if(!entry.getValue().equals(LabRun.text(discovery,entry.getKey())))throw new IOException("Provider published a different protocol origin.");
                    return;
                }
            }
            if(!inspect("container",containerId).getAsJsonObject("State").get("Running").getAsBoolean())throw new IOException("Owned provider exited before readiness.");
            Thread.sleep(100);
        }
        throw new IOException(closed.get()?"Provider startup was retired.":"Provider readiness deadline.");
    }
    private JsonObject renderUpstream(JsonObject template) throws IOException {
        var realm=template.deepCopy();if(!"authlab-upstream".equals(LabRun.text(realm,"realm")))throw new IOException("Unexpected upstream realm.");
        for(var item:realm.getAsJsonArray("clients")) {
            var client=item.getAsJsonObject();String id=LabRun.text(client,"clientId");
            if(id.equals("downstream-broker")) {
                client.addProperty("clientId",ports().issuer().toString());
                String callback=ports().issuer()+"/broker/upstream-saml/endpoint";client.add("redirectUris",strings(callback));
                client.getAsJsonObject("attributes").addProperty("saml_assertion_consumer_url_post",callback);
            }else if(id.equals("cookie-verifier")) {
                client.add("redirectUris",strings(ports().clientOrigin()+"/spa/callback"));client.add("webOrigins",strings(ports().clientOrigin().toString()));
            }else throw new IOException("Unexpected upstream client.");
        }
        return realm;
    }
    /** Uses Keycloak's metadata importer solely to wire the real upstream; no protocol validator test is added. */
    private void configureBroker(boolean initial,long deadline) throws Exception {
        String token=administrator(deadline);
        byte[] request=LabRun.JSON.toJson(Map.of("providerId","saml","fromUrl",ports().upstreamIssuer()+"/protocol/saml/descriptor")).getBytes(StandardCharsets.UTF_8);
        var imported=admin("POST","/admin/realms/authlab-downstream/identity-provider/import-config",request,token,deadline);
        if(imported.status()!=200)throw new IOException("Upstream metadata configuration unavailable.");
        var config=ScenarioCatalog.parseJson(imported.bytes()).getAsJsonObject();
        config.addProperty("entityId",ports().issuer().toString());config.addProperty("validateSignature","true");
        // The seeded links use the upstream username, so request that same stable subject format.
        config.addProperty("nameIDPolicyFormat","urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");config.addProperty("principalType","SUBJECT");
        config.addProperty("wantAuthnRequestsSigned","false");config.addProperty("postBindingAuthnRequest","true");config.addProperty("postBindingResponse","true");
        var idp=new JsonObject();idp.addProperty("alias","upstream-saml");idp.addProperty("providerId","saml");idp.addProperty("enabled",true);
        idp.addProperty("trustEmail",true);idp.addProperty("storeToken",false);idp.addProperty("firstBrokerLoginFlowAlias","first broker login");idp.add("config",config);
        var result=admin(initial?"POST":"PUT","/admin/realms/authlab-downstream/identity-provider/instances"+(initial?"":"/upstream-saml"),LabRun.JSON.toJson(idp).getBytes(StandardCharsets.UTF_8),token,deadline);
        if(result.status()!=(initial?201:204))throw new IOException("Owned upstream broker configuration failed.");
        var providers=new JsonArray();providers.add(idp);realmSeed.add("identityProviders",providers);
        for(var item:realmSeed.getAsJsonArray("users")) {
            var user=item.getAsJsonObject();String username=LabRun.text(user,"username");
            var link=new JsonObject();link.addProperty("identityProvider","upstream-saml");link.addProperty("userId",username);link.addProperty("userName",username);
            if(initial&&admin("POST","/admin/realms/authlab-downstream/users/"+LabRun.text(user,"id")+"/federated-identity/upstream-saml",LabRun.JSON.toJson(link).getBytes(StandardCharsets.UTF_8),token,deadline).status()!=204)
                throw new IOException("Owned broker account linking failed.");
            var links=new JsonArray();links.add(link);user.add("federatedIdentities",links);
        }
    }

    /** Recreates the owned realm explicitly, preserving ports but discarding its sessions, codes and signing keys. */
    void resetProvider(long deadline) throws Exception {
        if(!providerReady())throw new IOException("Provider reset requires a ready owned environment.");complete=false;
        if(upstreamSeed!=null) {
            String upstreamToken=administrator(true,deadline);
            if(admin(true,"DELETE","/admin/realms/authlab-upstream",null,upstreamToken,deadline).status()!=204
                    ||admin(true,"POST","/admin/realms",LabRun.JSON.toJson(upstreamSeed).getBytes(StandardCharsets.UTF_8),upstreamToken,deadline).status()!=201)
                throw new IOException("Upstream reset failed.");
        }
        String token=administrator(deadline);
        if(admin("DELETE","/admin/realms/authlab-downstream",null,token,deadline).status()!=204)throw new IOException("Provider realm removal was rejected.");
        if(admin("POST","/admin/realms",LabRun.JSON.toJson(realmSeed).getBytes(StandardCharsets.UTF_8),token,deadline).status()!=201)throw new IOException("Provider realm import was rejected.");
        qualifySettings(deadline);if(upstreamSeed!=null)configureBroker(false,deadline);complete=true;
    }
    /** Safe public key identifiers provide an independent reset witness without exposing any credential. */
    public Set<String> signingKeyIds() throws Exception {
        if(!providerReady())throw new IOException("Provider is not ready.");
        var response=call(HttpRequest.newBuilder(URI.create(ports().issuer()+"/protocol/openid-connect/certs")).GET(),System.nanoTime()+TimeUnit.SECONDS.toNanos(5));
        if(response.status()!=200)throw new IOException("Provider key metadata unavailable.");
        var ids=new HashSet<String>();for(var key:ScenarioCatalog.parseJson(response.bytes()).getAsJsonObject().getAsJsonArray("keys")) {
            var value=key.getAsJsonObject();if(value.has("use")&&value.get("use").getAsString().equals("sig"))ids.add(LabRun.text(value,"kid"));
        }
        if(ids.isEmpty())throw new IOException("Provider signing keys absent.");return Set.copyOf(ids);
    }
    private record Reply(int status,byte[] bytes) {}
    /** Bounds all administration response bytes and shares the caller's operation deadline. */
    private Reply call(HttpRequest.Builder request,long deadline) throws Exception {
        long remaining=deadline-System.nanoTime();if(remaining<=0)throw LabRun.error(504,"DEADLINE");
        var response=providerHttp.send(request.timeout(Duration.ofNanos(Math.min(remaining,TimeUnit.SECONDS.toNanos(5)))).build(),HttpResponse.BodyHandlers.ofInputStream());
        try(var input=response.body()) {byte[] bytes=input.readNBytes(1_048_577);if(bytes.length>1_048_576)throw new IOException("Provider administration response limit.");return new Reply(response.statusCode(),bytes);}
    }
    /** Administration is private fixture control, separate from every browser/client authentication journey. */
    private String administrator(long deadline) throws Exception {return administrator(false,deadline);}
    private String administrator(boolean upstream,long deadline) throws Exception {
        String body="grant_type=password&client_id=admin-cli&username=authlab-admin&password="+URLEncoder.encode(adminSecret.reveal(),StandardCharsets.UTF_8);
        var response=call(HttpRequest.newBuilder(URI.create(providerOrigin(upstream)+"/realms/master/protocol/openid-connect/token"))
                .header("Content-Type","application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(body)),deadline);
        if(response.status()!=200)throw new IOException("Provider fixture administration was denied.");
        return LabRun.text(ScenarioCatalog.parseJson(response.bytes()).getAsJsonObject(),"access_token");
    }
    private Reply admin(String method,String path,byte[] body,String token,long deadline) throws Exception {return admin(false,method,path,body,token,deadline);}
    private URI providerOrigin(boolean upstream){return URI.create(upstream?"https://idp.upstream-sso.test:"+ports().upstream():"https://idp.federation.test:"+ports().downstream());}
    private Reply admin(boolean upstream,String method,String path,byte[] body,String token,long deadline) throws Exception {
        if(!path.startsWith("/admin/realms"))throw new IOException("Unsupported provider control path.");
        var request=HttpRequest.newBuilder(URI.create(providerOrigin(upstream)+path)).header("Authorization","Bearer "+token);
        request.method(method,body==null?HttpRequest.BodyPublishers.noBody():HttpRequest.BodyPublishers.ofByteArray(body));
        if(body!=null)request.header("Content-Type","application/json");return call(request,deadline);
    }
    /** Checks imported settings at the actual provider instead of inferring them from the seed file. */
    private void qualifySettings(long deadline) throws Exception {
        String token=administrator(deadline);var response=admin("GET","/admin/realms/authlab-downstream",null,token,deadline);
        if(response.status()!=200)throw new IOException("Imported provider realm unavailable.");
        var realm=ScenarioCatalog.parseJson(response.bytes()).getAsJsonObject();
        for(String field:List.of("accessTokenLifespan","accessCodeLifespan","ssoSessionIdleTimeout","ssoSessionMaxLifespan","clientSessionIdleTimeout"))
            if(realm.get(field)==null||realm.get(field).getAsLong()!=realmSeed.get(field).getAsLong())throw new IOException("Imported provider lifetime differs: "+field+".");
        for(var item:realmSeed.getAsJsonArray("clients")) {
            var expected=item.getAsJsonObject();String id=LabRun.text(expected,"clientId");
            var found=admin("GET","/admin/realms/authlab-downstream/clients?clientId="+URLEncoder.encode(id,StandardCharsets.UTF_8),null,token,deadline);
            if(found.status()!=200)throw new IOException("Provider client inspection denied.");
            var clients=ScenarioCatalog.parseJson(found.bytes()).getAsJsonArray();if(clients.size()!=1)throw new IOException("Imported client identity differs.");
            var actual=clients.get(0).getAsJsonObject();
            for(String field:List.of("protocol","publicClient","standardFlowEnabled","implicitFlowEnabled","directAccessGrantsEnabled"))
                if(expected.has(field)&&!expected.get(field).equals(actual.get(field)))throw new IOException("Imported client configuration differs: "+field+".");
            // Keycloak stores URI collections as sets; ordering does not change the accepted callbacks.
            for(String field:List.of("redirectUris","webOrigins"))if(expected.has(field)) {
                var wanted=expected.getAsJsonArray(field).asList().stream().map(JsonElement::getAsString).sorted().toList();
                if(!actual.has(field)||!wanted.equals(actual.getAsJsonArray(field).asList().stream().map(JsonElement::getAsString).sorted().toList()))
                    throw new IOException("Imported client configuration differs: "+field+".");
            }
            if("openid-connect".equals(LabRun.text(expected,"protocol"))&&!id.equals("authlab-api")
                    &&!"S256".equals(LabRun.text(actual.getAsJsonObject("attributes"),"pkce.code.challenge.method")))throw new IOException("Provider PKCE requirement differs.");
            if("saml".equals(LabRun.text(expected,"protocol")))for(String field:List.of("saml.force.post.binding","saml.server.signature","saml.assertion.signature",
                    "saml.client.signature","saml.authnstatement","saml_name_id_format","saml_assertion_consumer_url_post"))
                if(!Objects.equals(expected.getAsJsonObject("attributes").get(field),actual.getAsJsonObject("attributes").get(field)))throw new IOException("Provider SAML configuration differs: "+field+".");
            if(clientSecrets.containsKey(id)) {
                var secret=admin("GET","/admin/realms/authlab-downstream/clients/"+LabRun.text(actual,"id")+"/client-secret",null,token,deadline);
                if(secret.status()!=200||!java.security.MessageDigest.isEqual(clientSecrets.get(id).reveal().getBytes(StandardCharsets.UTF_8),
                        LabRun.text(ScenarioCatalog.parseJson(secret.bytes()).getAsJsonObject(),"value").getBytes(StandardCharsets.UTF_8)))throw new IOException("Provider confidential-client identity differs.");
            }
        }
    }

    /** Renders known seed fields only; no arbitrary substitution expression or wildcard callback is accepted. */
    static JsonObject renderRealm(JsonObject template,Ports ports,Map<String,FixtureIdentityStore.Secret> secrets) throws IOException {
        var realm=template.deepCopy();if(!"authlab-downstream".equals(LabRun.text(realm,"realm")))throw new IOException("Unexpected provider realm.");
        var ids=new HashSet<String>();
        for(var item:realm.getAsJsonArray("clients")) {
            var client=item.getAsJsonObject();String id=LabRun.text(client,"clientId");if(!CLIENTS.contains(id)||!ids.add(id))throw new IOException("Unexpected provider client inventory.");
            if(id.equals("authlab-api"))continue;
            String origin=ports.clientOrigin().toString();
            if(id.equals("authlab-sp")) {
                client.addProperty("clientId",origin+"/saml/metadata");client.add("redirectUris",strings(origin+"/login/saml2/sso/keycloak"));
                client.getAsJsonObject("attributes").addProperty("saml_assertion_consumer_url_post",origin+"/login/saml2/sso/keycloak");continue;
            }
            client.add("webOrigins",strings(origin));
            client.add("redirectUris",switch(id) {
                case "backend-client","wrong-client-control"->strings(origin+"/login/oauth2/code/backend",origin+"/login/oauth2/code/backend-control");
                case "wrong-audience-client"->strings(origin+"/login/oauth2/code/backend-audience-control");
                default->strings(origin+"/spa/callback");
            });
            if(!client.get("publicClient").getAsBoolean()) {
                var secret=secrets.get(id);if(secret==null)throw new IOException("Prepared client secret absent.");client.addProperty("secret",secret.reveal());
            }
            var audience=new JsonObject();audience.addProperty("name","authlab-api-audience");audience.addProperty("protocol","openid-connect");audience.addProperty("protocolMapper","oidc-audience-mapper");
            var config=new JsonObject();config.addProperty("included.custom.audience",id.equals("wrong-audience-client")?"authlab-other-api":"authlab-api");
            config.addProperty("access.token.claim","true");config.addProperty("id.token.claim","false");audience.add("config",config);
            var mappers=new JsonArray();mappers.add(audience);client.add("protocolMappers",mappers);
        }
        if(!ids.equals(CLIENTS))throw new IOException("Incomplete provider client inventory.");return realm;
    }
    private static JsonArray strings(String... values) { var array=new JsonArray();for(var value:values)array.add(value);return array; }

    /** Serializes creation with cleanup and persists immutable IDs immediately after inspecting exact ownership. */
    private void createResource(String kind,List<String> arguments) throws Exception {
        launch.lockInterruptibly();
        try {
            if(closed.get())throw new IOException("Provider environment retired.");
            unknownCreatedId=true;
            Files.writeString(directory.resolve("creation-intent.json"),LabRun.JSON.toJson(Map.of("kind",kind,"runId",owner.runId().toString(),"invocationId",owner.spec().invocationId().toString(),"time",Instant.now().toString())));
            String id=docker(arguments).lines().filter(s->!s.isBlank()).reduce((first,last)->last).orElse("").trim();
            if(!id.matches("[a-f0-9]{64}"))throw new IOException("Docker did not return an immutable owned resource ID.");
            var pending=Map.<String,Object>of("kind",kind,"id",id,"ownerRunId",owner.runId().toString(),"createdAt",Instant.now().toString(),
                    "proof",Map.of("id",id,"verified",false));
            dockerResources.add(pending);unknownCreatedId=false;
            // Persist the returned ID before inspection, without taking the parent monitor under the launch lock.
            Files.writeString(directory.resolve("created-"+id+".json"),LabRun.JSON.toJson(pending));
            var observed=inspect(kind.equals("NETWORK")?"network":"container",id);verifyOwner(observed,id);
            dockerResources.set(dockerResources.indexOf(pending),Map.of("kind",kind,"id",id,"ownerRunId",owner.runId().toString(),"createdAt",LabRun.text(observed,"Created"),
                    "proof",Map.of("id",id,"verified",true,"labels",Map.of("authlab.run",owner.runId().toString(),"authlab.invocation",owner.spec().invocationId().toString()))));
        } finally { launch.unlock();owner.federationChanged(); }
    }
    private JsonObject inspect(String kind,String id) throws Exception {
        var value=ScenarioCatalog.parseJson(docker(List.of(kind,"inspect",id)).getBytes(StandardCharsets.UTF_8)).getAsJsonArray();
        if(value.size()!=1)throw new IOException("Ambiguous Docker ownership inspection.");return value.get(0).getAsJsonObject();
    }
    /** Labels alone are insufficient: the retained immutable ID must also match the actual object. */
    private void verifyOwner(JsonObject observed,String id) throws IOException {
        var labels=observed.has("bpsh.config.Config")?observed.getAsJsonObject("bpsh.config.Config").getAsJsonObject("Labels"):observed.getAsJsonObject("Labels");
        if(!id.equals(LabRun.text(observed,"Id"))||labels==null||!owner.runId().toString().equals(LabRun.text(labels,"authlab.run"))
                ||!owner.spec().invocationId().toString().equals(LabRun.text(labels,"authlab.invocation")))throw new IOException("Docker resource ownership differs; it was not removed.");
    }
    /** Invokes Docker without a shell; failures never echo captured environment/seed contents. */
    private static String docker(List<String> arguments) throws Exception {
        var command=new ArrayList<>(List.of("docker"));command.addAll(arguments);
        var process=new ProcessBuilder(command).redirectErrorStream(true).start();
        try(var readers=Executors.newVirtualThreadPerTaskExecutor()) {
            var output=readers.submit(()->{try(var stream=process.getInputStream()){byte[] bytes=stream.readNBytes(1_048_577);if(bytes.length>1_048_576)throw new IOException("Docker output limit.");return new String(bytes,StandardCharsets.UTF_8);}});
            try {
                if(!process.waitFor(15,TimeUnit.SECONDS)||process.exitValue()!=0)throw new IOException("Owned provider operation failed: "+arguments.getFirst()+".");
                return output.get(2,TimeUnit.SECONDS);
            } finally {if(process.isAlive())process.destroyForcibly();output.cancel(true);}
        }
    }

    /** Inspects IDs/labels/creation time before touching resources; a failed cleanup remains visible to the parent. */
    @Override public void close() throws Exception {
        closed.set(true);complete=false;
        Exception failure=null;var apps=applications;if(apps!=null)try{apps.close();}catch(Exception error){failure=error;}
        if(!launch.tryLock(15,TimeUnit.SECONDS))throw new IOException("Provider cleanup could not settle launch ownership.");
        try {
            for(var resource:new ArrayList<>(dockerResources).reversed()) {
                try {
                    String id=resource.get("id").toString(),kind=resource.get("kind").toString();
                    var observed=inspect(kind.equals("NETWORK")?"network":"container",id);verifyOwner(observed,id);
                    if(Boolean.TRUE.equals(((Map<?,?>)resource.get("proof")).get("verified"))&&!resource.get("createdAt").equals(LabRun.text(observed,"Created")))throw new IOException("Resource creation proof differs.");
                    if(kind.equals("CONTAINER")){docker(List.of("stop","--time","5",id));docker(List.of("rm",id));}
                    else docker(List.of("network","rm",id));
                    dockerResources.remove(resource);owner.federationChanged();
                } catch(Exception error){if(failure==null)failure=error;else failure.addSuppressed(error);}
            }
            if(unknownCreatedId){var unresolved=new IOException("Provider creation returned no verifiable resource ID; explicit review is required.");if(failure==null)failure=unresolved;else failure.addSuppressed(unresolved);}
        } finally {
            launch.unlock();if(lease!=null&&dockerResources.isEmpty()&&!unknownCreatedId)lease.close();
            if(providerHttp!=null){providerHttp.shutdownNow();if(!providerHttp.awaitTermination(Duration.ofSeconds(3)))throw new IOException("Provider control transport did not close.");}
        }
        if(failure!=null)throw failure;owner.detachFederation(this);
    }

    /** Full-tuple cross-process lease. Socket handoff retains its exclusive file lock until environment cleanup. */
    static final class PortLease implements AutoCloseable {
        private record Reservation(ServerSocket socket,FileChannel channel,FileLock lock) {}
        private final Map<Integer,Reservation> reservations;
        final Ports ports;
        private PortLease(Map<Integer,Reservation> reservations) { this.reservations=reservations;var values=new ArrayList<>(reservations.keySet());ports=new Ports(values.get(0),values.get(1),values.get(2),values.size()==4?values.get(3):0); }
        static PortLease reserve(Path root,UUID runId) throws IOException {
            return reserve(root,runId,false);
        }
        static PortLease reserve(Path root,UUID runId,boolean upstream) throws IOException {
            Files.createDirectories(root);root=root.toRealPath();var held=new LinkedHashMap<Integer,Reservation>();
            try {
                int required=upstream?4:3;
                for(int attempts=0;held.size()<required&&attempts<128;attempts++) {
                    int port=ThreadLocalRandom.current().nextInt(40000,50000);if(held.containsKey(port))continue;
                    Path file=root.resolve("port-"+port+".lock");
                    var channel=FileChannel.open(file,StandardOpenOption.CREATE,StandardOpenOption.READ,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS);
                    FileLock lock=null;var socket=new ServerSocket();
                    try {
                        try {lock=channel.tryLock();}catch(OverlappingFileLockException occupied){}
                        if(lock==null)continue;
                        socket.bind(new InetSocketAddress("127.0.0.1",port));channel.truncate(0);
                        channel.write(ByteBuffer.wrap(("authlab-port-v1 "+runId+"\n").getBytes(StandardCharsets.UTF_8)));channel.force(false);
                        held.put(port,new Reservation(socket,channel,lock));socket=null;channel=null;lock=null;
                    } catch(BindException occupied) { }
                    finally {if(socket!=null)socket.close();if(lock!=null)lock.close();if(channel!=null)channel.close();}
                }
                if(held.size()!=required)throw new IOException("No exclusive federation port tuple available.");return new PortLease(held);
            } catch(IOException|RuntimeException error) {for(var value:held.values()){value.socket().close();value.lock().close();value.channel().close();}throw error;}
        }
        void handoff(int port) throws IOException {var value=reservations.get(port);if(value==null)throw new IOException("Port is outside this owned tuple.");value.socket().close();}
        @Override public void close() throws IOException {for(var value:reservations.values()){value.socket().close();if(value.lock().isValid())value.lock().close();value.channel().close();}}
    }
}
