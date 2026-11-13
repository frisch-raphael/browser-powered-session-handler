package bpsh.support;

import bpsh.authentication.credentials.TokenExtractor;
import bpsh.journey.ConfigurationException;
import bpsh.journey.JourneyDefinition;
import com.fasterxml.jackson.databind.JsonNode;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;

/** Exports real native definitions for an already running owned lab. Never logs in or runs a journey. */
public final class ProductionLabExamples {
    private ProductionLabExamples() {}
    private static String stage="verify the owned live run";
    public static void main(String[] args) {
        try{export();}
        catch(ConfigurationException invalid){System.err.println("Could not build a native journey export: "+invalid.getMessage());System.exit(3);}
        catch(Exception|AssertionError failure){System.err.println("Could not "+stage+". Keep the owned serve run READY, use its printed run ID, and export again after preparing current cases.");System.exit(3);}
    }
    private static void export() throws Exception {
        var plan=AuthLabSupport.JSON.readTree(Files.readAllBytes(Path.of(System.getProperty("authlab.plan"))));
        String exportMode=plan.path("mode").asText("");
        if(!Set.of("","HOST").contains(exportMode))throw new IllegalArgumentException("Unknown export mode.");
        boolean hostMode=exportMode.equals("HOST");
        String hostPrefix=plan.path("hostAliasPrefix").asText("host");
        if(!Set.of("host","host_failure").contains(hostPrefix)||!hostMode&&plan.has("hostAliasPrefix"))throw new IllegalArgumentException("Invalid host alias prefix.");
        UUID runId=UUID.fromString(plan.path("liveRunId").asText());Path root=Path.of(plan.path("liveRunsRoot").asText()).toRealPath();
        Path descriptor=null;
        try(var invocations=Files.list(root)) {
            for(Path invocation:invocations.filter(p->Files.isDirectory(p,LinkOption.NOFOLLOW_LINKS)).toList()) {
                try{UUID.fromString(invocation.getFileName().toString());}catch(IllegalArgumentException unrelated){continue;}
                Path candidate=invocation.resolve(runId.toString()).resolve("run.json");
                if(Files.isRegularFile(candidate,LinkOption.NOFOLLOW_LINKS)&&candidate.toRealPath().startsWith(root)) {
                    if(descriptor!=null)throw new IllegalArgumentException("Ambiguous owned run.");descriptor=candidate.toRealPath();
                }
            }
        }
        if(descriptor==null)throw new IllegalArgumentException("Owned run not found.");
        var owner=AuthLabSupport.JSON.readTree(Files.readAllBytes(descriptor));
        if(owner.path("descriptorVersion").asInt()!=1||!owner.path("state").asText().equals("READY")||!owner.path("runId").asText().equals(runId.toString())||
                !owner.path("invocationId").asText().equals(descriptor.getParent().getParent().getFileName().toString())||
                !Path.of(owner.path("environmentRoot").asText()).toRealPath().equals(root))throw new IllegalArgumentException("Invalid owned descriptor.");
        boolean proven=false;
        for(var resource:owner.path("resources"))if(resource.path("kind").asText().equals("DIRECTORY")&&resource.path("ownerRunId").asText().equals(runId.toString())&&
                resource.path("proof").path("resolvedPath").asText().equals(descriptor.getParent().toString()))proven=true;
        if(!proven)throw new IllegalArgumentException("Missing ownership proof.");
        URI control=URI.create(owner.path("controlUri").asText());
        if(!control.getScheme().equals("http")||!"127.0.0.1".equals(control.getHost())||control.getPort()<=0||control.getUserInfo()!=null||control.getQuery()!=null||control.getFragment()!=null||
                !control.getPath().equals("/control/v1/runs/"+runId))throw new IllegalArgumentException("Invalid owned control address.");
        long generation=owner.path("generation").asLong();
        try(var http=lab.auth.ControlledApplication.localClientBuilder().connectTimeout(Duration.ofSeconds(2)).build()) {
            stage="read the current live target inventory";
            var targets=targets(http,control,owner.path("controlKey").asText(),generation);
            if(!targets.path("runId").asText().equals(runId.toString())||targets.path("generation").asLong()!=generation)throw new IllegalArgumentException("Foreign live targets.");
            URI application=origin(targets.path("applicationOrigin").asText()),alternate=origin(targets.path("alternateOrigin").asText());
            var exports=new LinkedHashMap<String,String>();var references=new ArrayList<Map<String,Object>>();
            stage="build the native journey definitions";
            for(var target:targets.path("cases")) {
                String id=target.path("caseId").asText();String mode=federationMode(id);List<String> roles=roles(id);if(roles==null&&mode==null&&!lab.auth.TransportFixtures.SERVABLE.contains(id))continue;
                long version=target.path("generation").asLong();if(version<=0)throw new IllegalArgumentException("Invalid live case version.");
                if(hostMode) {
                    if(id.equals("BROW.basic.json"))for(String suffix:List.of("a","b")) {
                        String alias=hostPrefix+"_"+suffix;
                        var definition=ProductionLabAdapter.hostLoginDefinition(new ProductionLabAdapter.LoginTarget(id,version,application,alternate),suffix.equals("a")?"user":"user2",alias).journey();
                        exports.put(alias,ProductionLabAdapter.export(definition));
                        references.add(Map.of("file",alias+".json","caseId",id,"caseGeneration",version,"alias",alias));
                    }
                    continue;
                }
                if(id.startsWith("TLS.")) {
                    var topology=targets.path("transport");
                    if(!topology.path("caseId").asText().equals(id)||topology.path("caseGeneration").asLong()!=version||!topology.path("softwareOnly").asBoolean())throw new IllegalArgumentException("Invalid live transport case.");
                    String alias="lab_"+id.replaceAll("[^A-Za-z0-9_]","_").toLowerCase(Locale.ROOT);
                    if(Set.of("TLS.proxy.direct","TLS.proxy.http-proxy","TLS.proxy.no-direct-fallback").contains(id)) {
                        var built=ProductionLabAdapter.loginDefinition(new ProductionLabAdapter.LoginTarget(id,version,application,alternate),List.of("B"),"user2",alias).journey();
                        URI proxy=id.equals("TLS.proxy.direct")?null:origin(topology.path(id.equals("TLS.proxy.http-proxy")?"proxyUri":"unavailableProxyUri").asText());
                        var journey=IntegrationFixtures.configured(built,built.authenticationUrl(),new JourneyDefinition.Browser(true,proxy==null?null:new JourneyDefinition.Proxy(proxy),5_000,1_500),built.extraction(),null);
                        exports.put(id,ProductionLabAdapter.export(journey));references.add(Map.of("file",id+".json","caseId",id,"caseGeneration",version,"alias",alias));
                    }else {
                        for(String role:id.equals("TLS.mtls.same-CN-pair")?List.of("employee","admin"):List.of("employee")) {
                            String name=id+"."+role;URI start=localHttps(target.path("startUri").asText());
                            if(role.equals("admin"))start=URI.create(start.toString().replace("identity=employee","identity=admin"));
                            URI issuer=TokenExtractor.origin(localHttps(topology.path(id.equals("TLS.trust.wrong-host")?"wrongHostOrigin":"issuerOrigin").asText()));
                            var origins=new ArrayList<URI>();origins.add(TokenExtractor.origin(start));if(id.equals("TLS.mtls.allowed-redirect"))origins.add(issuer);
                            String module=topology.path("modulePath").asText(),ca=topology.path("trustedCaPath").asText();
                            if(id.equals("TLS.mtls.token-unavailable"))module=Path.of(topology.path("configurationPath").asText()).getParent().resolve("absent-middleware.dll").toString();
                            String fingerprint=id.equals("TLS.mtls.missing-certificate")?"0".repeat(64):topology.path("fingerprints").path(role).asText();
                            var mtls=new JourneyDefinition.Mtls(module,new JourneyDefinition.Slot(JourneyDefinition.SlotKind.INDEX,0),fingerprint,origins,id.equals("TLS.trust.untrusted-origin")?null:ca);
                            URI proxy=id.equals("TLS.proxy.connect")?origin(topology.path("proxyUri").asText()):id.equals("TLS.proxy.proxy-unavailable")?origin(topology.path("unavailableProxyUri").asText()):null;
                            var journey=ProductionLabAdapter.certificateDefinition(start,issuer,mtls,proxy,alias+"_"+role);
                            exports.put(name,ProductionLabAdapter.export(journey));references.add(Map.of("file",name+".json","caseId",id,"caseGeneration",version,"alias",journey.alias()));
                        }
                    }
                    continue;
                }
                if(mode!=null) {
                    var topology=targets.path("federation");String alias="lab_"+id.replaceAll("[^A-Za-z0-9_]","_").toLowerCase(Locale.ROOT);
                    var definition=ProductionLabAdapter.federationDefinition(named(topology.path("clientOrigin").asText(),"app.authlab.test",""),
                            named(topology.path("issuer").asText(),"idp.federation.test","/realms/authlab-downstream"),
                            mode.equals("broker")?named(topology.path("upstreamIssuer").asText(),"idp.upstream-sso.test","/realms/authlab-upstream"):null,
                            mode,"user2","#login-complete",alias);
                    if(!definition.journey().authenticationUrl().toString().equals(target.path("startUri").asText()))throw new IllegalArgumentException("Federation start target differs.");
                    exports.put(id,ProductionLabAdapter.export(definition.journey()));references.add(Map.of("file",id+".json","caseId",id,"caseGeneration",version,"alias",alias));continue;
                }
                var input=new ProductionLabAdapter.LoginTarget(id,version,application,alternate);
                add(exports,references,input,roles,id,"lab_"+id.replaceAll("[^A-Za-z0-9_]","_").toLowerCase(Locale.ROOT));
                if(id.equals("BROW.basic.json"))add(exports,references,input,List.of("B","C1","C2"),id+".combined","lab_combined");
            }
            if(hostMode) {
                if(!exports.keySet().equals(Set.of(hostPrefix+"_a",hostPrefix+"_b")))throw new IllegalArgumentException("Missing current host form case.");
                var protocols=new HashSet<String>();
                for(var target:targets.path("httpAuthentication")) {
                    String protocol=target.path("protocol").asText();
                    if(!Set.of("BASIC","NTLM_V1","NTLM_V2").contains(protocol)||!protocols.add(protocol))throw new IllegalArgumentException("Invalid HTTP fixture inventory.");
                    URI httpOrigin=origin(target.path("origin").asText()),request=URI.create(target.path("request").asText());
                    if(!TokenExtractor.origin(request).equals(TokenExtractor.origin(httpOrigin))||!"/whoami".equals(request.getPath())
                            ||request.getRawUserInfo()!=null||request.getRawQuery()!=null||request.getRawFragment()!=null)throw new IllegalArgumentException("Foreign HTTP fixture target.");
                    for(String suffix:List.of("a","b")) {
                        String alias=hostPrefix+"_"+protocol.toLowerCase(Locale.ROOT)+"_"+suffix;
                        var definition=ProductionLabAdapter.hostHttpDefinition(request,bpsh.journey.HttpAuthentication.Protocol.valueOf(protocol),"user-"+suffix,alias);
                        exports.put(alias,ProductionLabAdapter.export(definition));
                        references.add(Map.of("file",alias+".json","protocol",protocol,"alias",alias));
                    }
                }
                if(!protocols.equals(Set.of("BASIC","NTLM_V1","NTLM_V2")))throw new IllegalArgumentException("Missing HTTP fixture inventory.");
            }
            if(exports.isEmpty())throw new IllegalArgumentException("No supported live browser examples.");
            stage="confirm that the live targets have not changed";
            if(!targets.equals(targets(http,control,owner.path("controlKey").asText(),generation)))throw new IllegalArgumentException("Live targets changed while exporting.");
            stage="write the generated native files";
            Path report=Path.of(plan.path("reportDirectory").asText()).toRealPath(),directory=Files.createDirectory(report.resolve("native-examples"));
            for(var entry:exports.entrySet())Files.writeString(directory.resolve(entry.getKey()+".json"),entry.getValue(),StandardCharsets.UTF_8,StandardOpenOption.CREATE_NEW);
            Files.writeString(directory.resolve("README.txt"),hostMode ? "Host examples generated by the captured native serializer for run "+runId+", generation "+generation+".\nTwo form accounts capture B,C1 with a maximum cache age of 3500 seconds and a skew of 10 seconds. Host form browsers use the normal native 30000 ms navigation/startup and 3000 ms token-observation settings, with headless execution; unchanged attempt and outer deadlines still apply. Host fixture issuance lasts 3600 seconds; dedicated expiry fixtures retain their normal lifetime. Three HTTP authentication protocols each have A/B identities. Enter synthetic fixture secrets through the private GUI input; this export contains no passwords, runtime credentials or control keys. Authentication was not executed.\n" : "Generated by the actual captured extension serializer for live run "+runId+", generation "+generation+".\nImport individual JSON files in the extension. Each alias is distinct. Ordinary fixture forms use user2/pass2; enter pass2 in the secure input. No password, PIN, runtime token or control key is exported.\nThe controlled combined example captures bearer AND both cookies from one journey. Browser OIDC captures bearer/client/selected IdP cookie; backend OIDC and SAML capture the client cookie available to the browser; the broker captures bearer/client/selected upstream cookie. These are prepared definitions, not authentication results. Use the matching protected endpoint and inspect its account/issuance result.\nTransport examples use the active transport inventory's resourceUri. Employee must return account user; admin must return account admin. The same-CN pair has two distinct fingerprint selections. Negative examples must fail without yielding a usable credential. Software certificate examples require a fresh Burp process inheriting the private SOFTHSM2_CONF path from the inventory and the disposable PIN from its owned fixture.json; never use a real token PIN or an existing process with an unknown store. No global environment change is required.\nKeep authLabServe running. Controlled URLs carry case generations and are rejected after retirement. Federation named origins can be reused after reset; regenerate the matching example whenever the active case changes. Stop closes the services.\n",StandardCharsets.UTF_8,StandardOpenOption.CREATE_NEW);
            Files.writeString(report.resolve("native-examples-completion.json"),AuthLabSupport.JSON.writeValueAsString(Map.of("runId",runId.toString(),"generation",generation,"files",references,"authenticationExecuted",false)),StandardCharsets.UTF_8,StandardOpenOption.CREATE_NEW);
            System.out.println("Native examples prepared: "+exports.size()+"; authentication was not executed. Output: "+directory);
        }
    }
    private static URI origin(String value) {
        URI uri=URI.create(value);
        if(!uri.getScheme().equals("http")||!"127.0.0.1".equals(uri.getHost())||uri.getPort()<=0||uri.getUserInfo()!=null||uri.getQuery()!=null||uri.getFragment()!=null||!Set.of("","/").contains(uri.getPath()))throw new IllegalArgumentException("Invalid controlled origin.");
        return uri;
    }
    private static URI localHttps(String value) {
        URI uri=URI.create(value);
        if(!uri.getScheme().equals("https")||!"localhost".equals(uri.getHost())||uri.getPort()<=0||uri.getUserInfo()!=null||uri.getFragment()!=null)throw new IllegalArgumentException("Invalid owned TLS endpoint.");
        return uri;
    }
    private static URI named(String value,String host,String path) {
        URI uri=URI.create(value);
        if(!uri.getScheme().equals("https")||!host.equals(uri.getHost())||uri.getPort()<40000||uri.getPort()>49999||uri.getUserInfo()!=null||uri.getQuery()!=null||uri.getFragment()!=null||!path.equals(uri.getPath()))throw new IllegalArgumentException("Invalid owned federation endpoint.");
        return uri;
    }
    private static String federationMode(String id) {
        return switch(id) {
            case "FED.flow.browser-oidc","FED.outputs.api-token","FED.outputs.idp-cookie","FED.outputs.client-cookie-plus-bearer" -> "browser";
            case "FED.flow.backend-oidc","FED.outputs.client-cookie" -> "backend";
            case "FED.flow.saml-sp" -> "saml";
            case "FED.broker.success","FED.broker.combined-outputs" -> "broker";
            default -> null;
        };
    }
    private static JsonNode targets(HttpClient client,URI control,String key,long generation) throws Exception {
        var response=client.send(HttpRequest.newBuilder(URI.create(control+"/targets?generation="+generation)).timeout(Duration.ofSeconds(3)).header("Authorization","Bearer "+key).GET().build(),HttpResponse.BodyHandlers.ofByteArray());
        if(response.statusCode()!=200||response.body().length>1_048_576)throw new IllegalArgumentException("Owned live target query rejected.");
        return AuthLabSupport.JSON.readTree(response.body());
    }
    private static List<String> roles(String id) {
        if(id.equals("BROW.basic.cookie-one"))return List.of("C1");if(id.equals("BROW.basic.cookie-two"))return List.of("C1","C2");
        if(Set.of("BROW.basic.json","BROW.basic.two-page","BROW.basic.csrf-cookie","BROW.basic.javascript","BROW.basic.interstitial",
                "BROW.redirect.cookie-each-hop","BROW.redirect.cross-origin","BROW.redirect.post-303","BROW.redirect.post-307","BROW.redirect.deep-link",
                "BROW.surfaces.popup","BROW.surfaces.frame","BROW.surfaces.service-worker","BROW.surfaces.cors-fetch").contains(id))return List.of("B");
        return null;
    }
    private static void add(Map<String,String> exports,List<Map<String,Object>> references,ProductionLabAdapter.LoginTarget target,List<String> roles,String name,String alias) throws Exception {
        var built=ProductionLabAdapter.loginDefinition(target,roles,"user2",alias);var j=built.journey();
        exports.put(name,ProductionLabAdapter.export(j));references.add(Map.of("file",name+".json","caseId",target.id(),"caseGeneration",target.generation(),"alias",alias));
    }
}
