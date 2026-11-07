package lab.federation;

import java.net.URI;
import java.time.Instant;
import java.util.*;
import java.util.stream.Stream;
import java.nio.file.*;
import java.net.http.*;
import java.time.Duration;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.boot.SpringApplication;
import org.junit.jupiter.api.*;
import org.springframework.security.oauth2.jwt.*;
import static org.junit.jupiter.api.Assertions.*;

/** Isolated maintained-consumer checks; no provider/browser/OS trust preparation is claimed. */
class FederationConfigurationTest {
    @TempDir Path root;
    /** Starts at the validated-JWT boundary: equal identity/session claims cannot substitute different token bytes. */
    @Test void combinedClientSessionRequiresItsExactTokenEvenWhenEveryIdentityClaimMatches() throws Exception {
        var settings=new FederationApplication.Settings(UUID.randomUUID(),UUID.randomUUID(),"FED.outputs.client-cookie-plus-bearer",1,"client",
                URI.create("https://app.authlab.test:41001"),URI.create("https://api.authlab.test:41002"),ISSUER,root.resolve("unused.p12"),"CANARY_PASSWORD",
                root.resolve("unused.crt"),"a".repeat(43),"CANARY_BACKEND_SECRET",null,root);
        Instant now=Instant.now();
        Jwt first=Jwt.withTokenValue("CANARY_TOKEN_ONE").header("alg","RS256").subject("fixture-user").issuedAt(now).expiresAt(now.plusSeconds(60)).claim("sid","same-session").claim("jti","same-id").build();
        Jwt second=Jwt.withTokenValue("CANARY_TOKEN_TWO").header("alg","RS256").subject("fixture-user").issuedAt(now).expiresAt(now.plusSeconds(60)).claim("sid","same-session").claim("jti","same-id").build();
        assertEquals(first.getClaims(),second.getClaims());
        try(var endpoints=new FederationClientEndpoints(settings,token->{throw new AssertionError("This control starts after JWT validation.");},javax.net.ssl.SSLContext.getDefault(),new FederationProtocol(settings))) {
            var established=new ServletCapture();endpoints.establish(first,established.response());assertEquals(200,established.status);
            var cookie=java.net.HttpCookie.parse(established.headers.get("Set-Cookie")).getFirst().getValue();
            var request=(jakarta.servlet.http.HttpServletRequest)java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(),new Class<?>[]{jakarta.servlet.http.HttpServletRequest.class},
                    (proxy,method,args)->method.getName().equals("getCookies")?new jakarta.servlet.http.Cookie[]{new jakarta.servlet.http.Cookie("LAB_CLIENT",cookie)}:null);
            var accepted=new ServletCapture();endpoints.combined(request,accepted.response(),first);assertEquals(200,accepted.status);
            var rejected=new ServletCapture();endpoints.combined(request,rejected.response(),second);assertEquals(401,rejected.status);
            assertTrue(rejected.output.toString(java.nio.charset.StandardCharsets.UTF_8).contains("credential_pair_rejected"));
            var logout=new ServletCapture();endpoints.logoutClient(request,logout.response());assertEquals(204,logout.status);
            var retired=new ServletCapture();endpoints.me(request,retired.response());assertEquals(401,retired.status);
        }
    }
    /** Minimal servlet boundary capture; neither a second authentication implementation nor another HTTP server. */
    private static final class ServletCapture {
        int status=200;final Map<String,String> headers=new HashMap<>();final java.io.ByteArrayOutputStream output=new java.io.ByteArrayOutputStream();
        jakarta.servlet.http.HttpServletResponse response() {
            var stream=new jakarta.servlet.ServletOutputStream(){
                @Override public boolean isReady(){return true;}
                @Override public void setWriteListener(jakarta.servlet.WriteListener listener){}
                @Override public void write(int value){output.write(value);}
            };
            return (jakarta.servlet.http.HttpServletResponse)java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(),new Class<?>[]{jakarta.servlet.http.HttpServletResponse.class},
                    (proxy,method,args)->{switch(method.getName()){
                        case "setStatus"->status=(int)args[0];case "addHeader"->headers.put((String)args[0],(String)args[1]);case "getOutputStream"->{return stream;}
                    }return null;});
        }
    }
    private static final URI ISSUER = URI.create("https://idp.federation.test:41003/realms/authlab-downstream");

    @TestFactory Stream<DynamicTest> privateProtocolControlsValidateCaseOwnershipAndReleaseOnlyObservedCheckpoints() {
        return Arrays.stream(FederationProtocol.Variant.values()).map(variant->DynamicTest.dynamicTest(variant.label,()-> {
            Path directory=Files.createDirectory(root.resolve(variant.label));var settings=protocolSettings(directory,variant);
            try(var context=new GenericApplicationContext()) {
                context.registerBean(FederationProtocol.class,()->new FederationProtocol(settings));context.refresh();
                try(var control=new FederationControl(settings,context);var http=lab.auth.ControlledApplication.localClientBuilder().build()) {
                    control.onApplicationEvent(new ApplicationReadyEvent(new SpringApplication(FederationApplication.class),new String[0],context,Duration.ZERO));
                    var ready=FederationApplication.JSON.readTree(Files.readAllBytes(directory.resolve("ready-client.json")));URI base=URI.create(ready.get("controlUri").asString());
                    String route="/cases/"+settings.caseId();
                    assertEquals(400,request(http,base,settings,route+"/federation-control","{\"generation\":1,\"variant\":\"CANARY_SECRET\",\"checkpoint\":\"bad\"}").statusCode());
                    String body=FederationApplication.JSON.writeValueAsString(Map.of("generation",1,"variant",variant.label,"checkpoint",variant.checkpoint));
                    assertEquals(200,request(http,base,settings,route+"/federation-control",body).statusCode());
                    assertEquals(409,request(http,base,settings,route+"/federation-control",body).statusCode());
                    assertEquals(409,request(http,base,settings,route+"/gates/"+variant.checkpoint+"/release","{\"generation\":1}").statusCode());
                    var protocol=context.getBean(FederationProtocol.class);
                    try(var worker=java.util.concurrent.Executors.newSingleThreadExecutor()) {
                        var held=worker.submit(()->protocol.checkpoint(variant.checkpoint));awaitGate(protocol);
                        assertFalse(held.isDone());
                        var snapshot=request(http,base,settings,route+"/snapshot?generation=1",null);assertEquals(200,snapshot.statusCode());assertFalse(snapshot.body().contains("CANARY_SECRET"));
                        assertEquals(409,request(http,base,settings,route+"/gates/"+variant.checkpoint+"/release","{\"generation\":2}").statusCode());
                        assertEquals(200,request(http,base,settings,route+"/gates/"+variant.checkpoint+"/release","{\"generation\":1}").statusCode());
                        held.get(1,java.util.concurrent.TimeUnit.SECONDS);
                        assertEquals(409,request(http,base,settings,route+"/gates/"+variant.checkpoint+"/release","{\"generation\":1}").statusCode());
                    }
                }
            }
        }));
    }

    @Test void contextRetirementReleasesHeldProtocolWorkWithoutWaitingForItsDeadline() throws Exception {
        var settings=protocolSettings(root,FederationProtocol.Variant.EXPIRED);
        try(var context=new GenericApplicationContext();var worker=java.util.concurrent.Executors.newSingleThreadExecutor()) {
            context.registerBean(FederationProtocol.class,()->new FederationProtocol(settings));context.refresh();var protocol=context.getBean(FederationProtocol.class);
            protocol.arm("code-expired","before-token-exchange");var held=worker.submit(()->protocol.checkpoint("before-token-exchange"));awaitGate(protocol);
            context.close();var failed=assertThrows(java.util.concurrent.ExecutionException.class,()->held.get(1,java.util.concurrent.TimeUnit.SECONDS));
            assertEquals("RETIRED",assertInstanceOf(FederationProtocol.Failure.class,failed.getCause()).code);
        }
    }
    private static void awaitGate(FederationProtocol protocol) throws Exception {
        long deadline=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(1);
        while(System.nanoTime()<deadline) {
            if(protocol.checkpoints().stream().anyMatch(c->c.get("state").equals("WAITING")))return;
            Thread.sleep(5);
        }
        fail("The owned protocol worker did not reach its checkpoint.");
    }
    private static FederationApplication.Settings protocolSettings(Path directory,FederationProtocol.Variant variant) {
        return new FederationApplication.Settings(UUID.randomUUID(),UUID.randomUUID(),variant==FederationProtocol.Variant.EXPIRED?"FED.negative.code-expired":"FED.broker.cancelled",1,"client",
                URI.create("https://app.authlab.test:41001"),URI.create("https://api.authlab.test:41002"),ISSUER,directory.resolve("unused.p12"),"CANARY_PASSWORD",directory.resolve("unused.crt"),"a".repeat(43),"CANARY_BACKEND_SECRET",null,directory);
    }

    /** Invalid launch material must fail safely before a listener or provider request is created. */
    @TestFactory Stream<DynamicTest> childSettingsRejectAmbiguousOrUnpreparedLaunchInputs() {
        return Stream.of("unknown-field", "duplicate-field", "trailing-json", "wrong-role", "zero-generation", "overflow-generation",
                "external-origin", "http-origin", "duplicate-port", "path-escape", "missing-password", "missing-client-secret", "oversized")
                .map(variant -> DynamicTest.dynamicTest(variant, () -> {
                    Path directory = Files.createDirectory(root.resolve(variant));
                    var input = launchSettings(directory);
                    Path path = directory.resolve("settings.json"); Files.write(path,FederationApplication.JSON.writeValueAsBytes(input));
                    var valid = FederationApplication.readSettings(path);
                    assertEquals("resource",valid.role()); assertFalse(valid.toString().contains("CANARY_PRIVATE_PASSWORD")); assertFalse(valid.toString().contains(valid.controlKey()));
                    assertFalse(valid.toString().contains("CANARY_BACKEND_SECRET"));
                    switch(variant) {
                        case "unknown-field" -> input.put("extra","CANARY_PRIVATE_PASSWORD");
                        case "wrong-role" -> input.put("role","other");
                        case "zero-generation" -> input.put("generation",0);
                        case "overflow-generation" -> input.put("generation",new java.math.BigInteger("9223372036854775808"));
                        case "external-origin" -> input.put("clientOrigin","https://external.invalid:41001");
                        case "http-origin" -> input.put("clientOrigin","http://app.authlab.test:41001");
                        case "duplicate-port" -> input.put("resourceOrigin","https://api.authlab.test:41001");
                        case "path-escape" -> input.put("keyStore","../outside.p12");
                        case "missing-password" -> input.put("keyStorePassword","");
                        case "missing-client-secret" -> input.put("role","client");
                    }
                    String json = FederationApplication.JSON.writeValueAsString(input);
                    if(variant.equals("duplicate-field"))json=json.substring(0,json.length()-1)+",\"role\":\"client\"}";
                    if(variant.equals("trailing-json"))json+=" {}";
                    if(variant.equals("oversized"))json=" ".repeat(65_537);
                    Files.writeString(path,json);
                    var error=assertThrows(java.io.IOException.class,()->FederationApplication.readSettings(path));
                    assertEquals("Invalid private federation settings.",error.getMessage()); assertNull(error.getCause());
                }));
    }

    /** Exercises the real independent child listener, private bootstrap and terminal record without an IdP. */
    @Test void childControlsEnforcePrivateKeyVersionsClosedFieldsAndSafeTerminalState() throws Exception {
        var input=launchSettings(root); Path path=root.resolve("settings.json"); Files.write(path,FederationApplication.JSON.writeValueAsBytes(input));
        var settings=FederationApplication.readSettings(path);
        try(var context=new GenericApplicationContext();var control=new FederationControl(settings,context);var http=lab.auth.ControlledApplication.localClientBuilder().build()) {
            context.refresh(); control.onApplicationEvent(new ApplicationReadyEvent(new SpringApplication(),new String[0],context,Duration.ZERO));
            Path readiness=root.resolve("ready-resource.json"); var ready=FederationApplication.JSON.readTree(Files.readAllBytes(readiness));
            URI base=URI.create(ready.get("controlUri").asString());
            var unauthorized=http.send(HttpRequest.newBuilder(URI.create(base+"/cases/"+settings.caseId()+"/snapshot?generation=1")).GET().build(),HttpResponse.BodyHandlers.ofString());
            assertEquals(401,unauthorized.statusCode()); assertFalse(unauthorized.body().contains(settings.controlKey()));
            String snapshot="/cases/"+settings.caseId()+"/snapshot?generation=";
            assertEquals(200,request(http,base,settings,snapshot+"1",null).statusCode());
            assertEquals(409,request(http,base,settings,snapshot+"2",null).statusCode());
            assertEquals(400,request(http,base,settings,snapshot+"bad",null).statusCode());
            for(String body:List.of("", "null", "[]", "{\"generation\":\"1\"}", "{\"generation\":1,\"extra\":\"CANARY_PRIVATE_PASSWORD\"}", "{\"generation\":1,\"generation\":2}")) {
                var response=request(http,base,settings,"/stop",body); assertEquals(400,response.statusCode());
                assertFalse(response.body().contains("CANARY_PRIVATE_PASSWORD")); assertFalse(response.body().contains(settings.controlKey()));
            }
            assertEquals(409,request(http,base,settings,"/stop","{\"generation\":2}").statusCode());
            assertEquals(413,request(http,base,settings,"/stop"," ".repeat(65_537)).statusCode());
            assertThrows(java.io.IOException.class,()->new FederationControl(settings,context),"A second child must not replace this private readiness record.");
            control.close(); control.close();
            var terminal=FederationApplication.JSON.readTree(Files.readAllBytes(readiness));assertEquals("CLOSED",terminal.get("state").asString());
            assertFalse(Files.exists(root.resolve("ready-resource.pending")));
        }
    }

    /** Checks real HTTPS/child-process wiring once; the token-validation matrix stays in its lower-layer owner. */
    @Test @Timeout(30) void resourceChildBecomesReadyOnlyWithHttpsAndStopsThroughItsPrivateListener() throws Exception {
        var ca=lab.auth.LabTls.prepare(root.resolve("resource-child"));
        var leaf=lab.auth.LabTls.createServer(ca,ca.directory().resolve("leaf"),List.of("api.authlab.test"));
        var input=launchSettings(ca.directory());var ports=availablePorts();
        input.put("clientOrigin","https://app.authlab.test:"+ports.get(0));input.put("resourceOrigin","https://api.authlab.test:"+ports.get(1));
        input.put("issuer","https://idp.federation.test:"+ports.get(2)+"/realms/authlab-downstream");
        input.put("keyStore","leaf/server.p12");input.put("keyStorePassword",leaf.password().reveal());
        Path path=ca.directory().resolve("settings.json");Files.write(path,FederationApplication.JSON.writeValueAsBytes(input));
        Path log=ca.directory().resolve("child.log");
        String javaExecutable=Path.of(System.getProperty("java.home"),"bin",System.getProperty("os.name").startsWith("Windows")?"java.exe":"java").toString();
        var child=new ProcessBuilder(javaExecutable,"-cp",System.getProperty("federation.childClasspath"),FederationApplication.class.getName(),"--settings",path.toString())
                .directory(ca.directory().toFile()).redirectErrorStream(true).redirectOutput(log.toFile()).start();
        try(var watcher=FileSystems.getDefault().newWatchService();var http=lab.auth.ControlledApplication.localClientBuilder().build()) {
            ca.directory().register(watcher,StandardWatchEventKinds.ENTRY_CREATE,StandardWatchEventKinds.ENTRY_MODIFY);
            Path readiness=ca.directory().resolve("ready-resource.json");long deadline=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(15);
            while(!Files.isRegularFile(readiness) && child.isAlive() && System.nanoTime()<deadline) {
                var changed=watcher.poll(250,java.util.concurrent.TimeUnit.MILLISECONDS);if(changed!=null)changed.reset();
            }
            assertTrue(Files.isRegularFile(readiness),"The owned resource child did not publish readiness.");
            var ready=FederationApplication.JSON.readTree(Files.readAllBytes(readiness));assertEquals(child.pid(),ready.get("pid").asLong());
            assertEquals("READY",ready.get("state").asString());assertEquals(input.get("runId"),ready.get("runId").asString());
            String response=resourceRequest(leaf,ports.get(1),"/api/me");
            assertTrue(response.startsWith("HTTP/1.1 401"));assertTrue(response.contains("access_token_rejected"));assertFalse(response.contains("Set-Cookie:"));
            String applicationControl=resourceRequest(leaf,ports.get(1),"/control/v1/runs/"+input.get("runId")+"/stop");
            assertTrue(applicationControl.contains("access_token_rejected"));assertFalse(applicationControl.contains("UNAUTHORIZED"));
            var settings=FederationApplication.readSettings(path);URI control=URI.create(ready.get("controlUri").asString());
            assertEquals(202,request(http,control,settings,"/stop","{\"generation\":1}").statusCode());
            assertTrue(child.waitFor(5,java.util.concurrent.TimeUnit.SECONDS),"The owned child did not exit after acknowledged stop.");assertEquals(0,child.exitValue());
            assertEquals("CLOSED",FederationApplication.JSON.readTree(Files.readAllBytes(readiness)).get("state").asString());
            String output=Files.readString(log);assertFalse(output.contains(leaf.password().reveal()));assertFalse(output.contains(settings.controlKey()));
        } finally {
            if(child.isAlive()){child.destroy();if(!child.waitFor(3,java.util.concurrent.TimeUnit.SECONDS)){child.destroyForcibly();assertTrue(child.waitFor(3,java.util.concurrent.TimeUnit.SECONDS));}}
        }
    }

    /** Chooses a short-lived independent wiring-test tuple; full provider environments own persistent port leases. */
    private static List<Integer> availablePorts() throws Exception {
        var listeners=new ArrayList<java.net.ServerSocket>();
        try {
            for(int attempt=0;listeners.size()<3&&attempt<32;attempt++) {
                var socket=new java.net.ServerSocket();
                try {socket.bind(new java.net.InetSocketAddress("127.0.0.1",java.util.concurrent.ThreadLocalRandom.current().nextInt(40000,50000)));listeners.add(socket);}
                catch(java.io.IOException occupied){socket.close();}
            }
            if(listeners.size()!=3)throw new java.io.IOException("No wiring-test port tuple available.");
            return listeners.stream().map(java.net.ServerSocket::getLocalPort).toList();
        } finally {for(var listener:listeners)listener.close();}
    }

    /** Scoped trust plus an explicit peer hostname avoids any dependency on Windows hosts/trust in default tests. */
    private static String resourceRequest(lab.auth.LabTls.Material leaf,int port,String route) throws Exception {
        try(var plain=new java.net.Socket()) {
            plain.connect(new java.net.InetSocketAddress("127.0.0.1",port),2000);
            try(var socket=(javax.net.ssl.SSLSocket)leaf.clientContext().getSocketFactory().createSocket(plain,"api.authlab.test",port,true)) {
                socket.setSoTimeout(3000);var parameters=socket.getSSLParameters();parameters.setEndpointIdentificationAlgorithm("HTTPS");socket.setSSLParameters(parameters);socket.startHandshake();
                socket.getOutputStream().write(("GET "+route+" HTTP/1.1\r\nHost: api.authlab.test:"+port+"\r\nConnection: close\r\n\r\n").getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                return new String(socket.getInputStream().readNBytes(65_536),java.nio.charset.StandardCharsets.UTF_8);
            }
        }
    }

    /** Shared launch fixture has only local placeholder files; configuration checks perform no TLS/network access. */
    private static Map<String,Object> launchSettings(Path directory) throws Exception {
        if(!Files.exists(directory.resolve("leaf.p12")))Files.writeString(directory.resolve("leaf.p12"),"fixture launch input");
        if(!Files.exists(directory.resolve("ca.crt")))Files.writeString(directory.resolve("ca.crt"),"fixture launch input");
        var input=new LinkedHashMap<String,Object>(); input.put("settingsVersion",2);input.put("invocationId",UUID.randomUUID().toString());input.put("runId",UUID.randomUUID().toString());
        input.put("caseId","FED.flow.oidc");input.put("generation",1);input.put("role","resource");input.put("clientOrigin","https://app.authlab.test:41001");
        input.put("resourceOrigin","https://api.authlab.test:41002");input.put("issuer",ISSUER.toString());input.put("keyStore","leaf.p12");input.put("keyStorePassword","CANARY_PRIVATE_PASSWORD");
        input.put("caCertificate","ca.crt");input.put("controlKey","a".repeat(43));input.put("backendClientSecret",null);input.put("upstreamIssuer",null);return input;
    }
    /** Sends exact private protocol inputs; response assertions never include the private request/key. */
    private static HttpResponse<String> request(HttpClient http,URI base,FederationApplication.Settings settings,String route,String body) throws Exception {
        var request=HttpRequest.newBuilder(URI.create(base+route)).timeout(Duration.ofSeconds(3)).header("Authorization","Bearer "+settings.controlKey());
        if(body==null)request.GET();else request.header("Content-Type","application/json").POST(HttpRequest.BodyPublishers.ofString(body));
        return http.send(request.build(),HttpResponse.BodyHandlers.ofString());
    }

    /** Qualifies only our API-specific audience/type rules; signature/time validation belongs to Spring/Nimbus. */
    @Test void resourceOracleDistinguishesItsAccessTokenFromOtherAudienceAndIdToken() {
        Instant now=Instant.now();
        java.util.function.BiFunction<String,String,Jwt> token=(audience,kind)->Jwt.withTokenValue("CANARY_VALIDATED_TOKEN")
                .header("alg","RS256").header("typ","JWT").issuer(ISSUER.toString()).subject("fixture-user")
                .issuedAt(now.minusSeconds(5)).expiresAt(now.plusSeconds(120)).audience(List.of(audience)).claim("typ",kind).build();
        var validator=FederationSecurity.accessTokenValidator(ISSUER);
        assertFalse(validator.validate(token.apply("authlab-api","Bearer")).hasErrors());
        assertTrue(validator.validate(token.apply("other-api","Bearer")).hasErrors());
        assertTrue(validator.validate(token.apply("authlab-api","ID")).hasErrors());
    }

    @TestFactory Stream<DynamicTest> decoderRefusesUnpreparedIssuerBeforeAnyNetworkRequest() {
        return Stream.of("http://idp.federation.test:41003/realms/authlab-downstream",
                "https://external.example:41003/realms/authlab-downstream",
                "https://idp.federation.test:443/realms/authlab-downstream",
                "https://user:secret@idp.federation.test:41003/realms/authlab-downstream",
                "https://idp.federation.test:41003/realms/authlab-downstream?secret=value",
                "https://idp.federation.test:41003/realms/authlab-downstream#fragment",
                "https://idp.federation.test:41003/realms/authlab-upstream").map(value -> DynamicTest.dynamicTest(
                        "unprepared-issuer-" + Integer.toHexString(value.hashCode()), () ->
                                assertThrows(IllegalArgumentException.class, () -> FederationSecurity.accessTokenValidator(URI.create(value)))));
    }

}
