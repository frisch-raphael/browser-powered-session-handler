package lab.auth;

import com.google.gson.JsonObject;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Reads observations from existing native owners. Contains no authentication or test runner. */
final class LabTransportEvidence {
    private LabTransportEvidence() {}
    record Capture(JsonObject observed, JsonObject timings) {}
    record Input(String label, int drivers, String task) {}
    static final Set<String> PREPARATION_FILES=Set.of("fixture.json",".fixture-owned.json","softhsm2.conf","ca.crt","server.key","server.crt","wrong-host.crt");
    static boolean preparationCurrent(JsonObject plan) throws IOException {
        Path root=Path.of(s(plan,"pkcs11OwnedRoot")).toRealPath();UUID.fromString(root.getFileName().toString());
        var hashes=plan.getAsJsonObject("pkcs11InputHashes");if(!hashes.keySet().equals(PREPARATION_FILES))return false;
        for(String name:PREPARATION_FILES) {
            Path path=root.resolve(name);
            if(!path.toRealPath().startsWith(root)||!s(hashes,name).equals(LabEvidence.sha256(Files.readAllBytes(path))))return false;
        }
        var claim=readOwned(root,root.resolve(".authlab-claimed.json"));
        if(!claim.keySet().equals(Set.of("invocationId","task"))||!s(claim,"invocationId").equals(s(plan,"invocationId"))||!s(claim,"task").equals("authLabTransportTest"))return false;
        Path module=Path.of(s(plan,"pkcs11Module"));
        return s(plan,"pkcs11ModuleSha256").equals(LabEvidence.sha256(Files.readAllBytes(module)));
    }
    static Input input(String id) {
        String label; int drivers;
        switch(id) {
            case "TLS.proxy.direct" -> {label="direct-route";drivers=2;}
            case "TLS.proxy.http-proxy" -> {label="http-proxy";drivers=1;}
            case "TLS.proxy.no-direct-fallback" -> {label="ordinary-no-direct-fallback";drivers=1;}
            case "TLS.proxy.connect" -> {label="available-upstream";drivers=1;}
            case "TLS.proxy.proxy-unavailable" -> {label="unavailable-unauthenticated-route";drivers=1;}
            case "TLS.mtls.missing-certificate" -> {label="missing-fingerprint";drivers=0;}
            case "TLS.mtls.ambiguous-certificate", "TLS.mtls.token-unavailable" -> {label="native-picker";drivers=0;}
            case "TLS.mtls.internal-proxy-credentials" -> {label="local-mtls-proxy";drivers=0;}
            case "TLS.trust.untrusted-origin" -> {label="trust-mode-0";drivers=1;}
            case "TLS.trust.wrong-host" -> {label="trust-mode-1";drivers=1;}
            case "TLS.mtls.disallowed-origin" -> {label="unlisted-origin";drivers=2;}
            case "TLS.trust.unlisted-proxy-key" -> {label="unlisted-proxy-key";drivers=1;}
            case "TLS.mtls.expected-fingerprint", "TLS.mtls.same-CN-pair", "TLS.mtls.allowed-redirect",
                    "TLS.mtls.resource-without-mtls", "TLS.mtls.pool-cleanup", "TLS.trust.listed-proxy-key" -> {label="selected-identities";drivers=2;}
            default -> throw new IllegalArgumentException("Uninspected transport requirement.");
        }
        return new Input(label,drivers,Set.of("direct-route","http-proxy","ordinary-no-direct-fallback").contains(label)?":authLabBrowserTest":":authLabTransportTest");
    }
    static Capture read(Path directory, ScenarioCatalog.Requirement row, JsonObject context) throws IOException {
        var binding=row.binding();var spec=input(row.id());
        String key=binding.parameterKey()==null?binding.methodSignature().replaceFirst("\\(\\)$", ""):binding.parameterKey();
        Path processFile=directory.resolve("process-observations/"+LabEvidence.sha256(key.getBytes(StandardCharsets.UTF_8))+".json");
        Path factsFile=directory.resolve("transport-observations/"+spec.label()+".json");
        if(!Files.isRegularFile(processFile))return null;
        var process=readOwned(directory,processFile);
        if(!validProcess(process,key,spec,context))return null;
        if(spec.task().equals(":authLabTransportTest")) {
            Path providers=directory.resolve("process-observations/providers.json");
            if(!Files.isRegularFile(providers)||!validProcess(readOwned(directory,providers),"Pkcs11JourneyIntegrationTest.providers",new Input("providers",0,spec.task()),context))return null;
        }
        JsonObject observed=null;
        if(Files.isRegularFile(factsFile)) {
            var facts=readOwned(directory,factsFile);
            if(valid(process,facts,key,spec,context))observed=facts.getAsJsonObject("observed");
        }
        return new Capture(observed,process.getAsJsonObject("timings"));
    }
    private static JsonObject readOwned(Path root,Path file) throws IOException {
        if(!file.toRealPath().startsWith(root.toRealPath())||Files.size(file)>1_048_576)throw new IOException("Invalid transport observation location or size.");
        return ScenarioCatalog.parseJson(Files.readAllBytes(file)).getAsJsonObject();
    }
    static boolean valid(JsonObject process,JsonObject facts,String input,Input spec,JsonObject context) {
        try {
            return validProcess(process,input,spec,context)&&facts.keySet().equals(Set.of("version","input","invocationId","taskPath","productionRevision","configurationHash","observed","label"))&&
                    sameInput(facts,input,spec,context)&&s(facts,"label").equals(spec.label())&&shape(spec.label(),facts.getAsJsonObject("observed"));
        }catch(RuntimeException invalid){return false;}
    }
    private static boolean sameInput(JsonObject value,String input,Input spec,JsonObject context) {
        if(n(value,"version")!=1||!s(value,"input").equals(input)||!s(value,"taskPath").equals(spec.task()))return false;
        for(String field:List.of("invocationId","taskPath","productionRevision","configurationHash"))if(!s(value,field).equals(s(context,field)))return false;
        return true;
    }
    private static boolean validProcess(JsonObject process,String input,Input spec,JsonObject context) {
        try {
            if(!process.keySet().equals(Set.of("version","input","invocationId","taskPath","productionRevision","configurationHash","observed","cleanup","timings"))||
                    !sameInput(process,input,spec,context)||!s(process,"cleanup").equals("COMPLETE"))return false;
            var observed=process.getAsJsonObject("observed");
            if(!observed.keySet().equals(Set.of("drivers","processes","alive"))||n(observed,"drivers")!=spec.drivers()||n(observed,"alive")!=0||
                    (spec.drivers()==0?(spec.label().equals("providers")?n(observed,"processes")<1:n(observed,"processes")!=0):n(observed,"processes")<2L*spec.drivers()))return false;
            var timings=process.getAsJsonObject("timings");if(!timings.keySet().equals(Set.of("startupMs","caseMs","cleanupMs")))return false;
            for(String field:timings.keySet())n(timings,field);
            return true;
        }catch(RuntimeException invalid){return false;}
    }
    private static boolean shape(String label,JsonObject value) {
        String numbers="",booleans="",strings="";
        switch(label) {
            case "direct-route" -> {numbers="primeProxyRequests directProxyRequests tokenRequests expectedOutputsReturned";booleans="directHadMarker";}
            case "http-proxy" -> {numbers="proxyRequests ownershipPathsObserved";booleans="allRequestsOwned cleanAgentPreserved expectedOutputReturned";}
            case "ordinary-no-direct-fallback" -> {numbers="originRequests";booleans="retryable credentialReturned configuredProxyHadCredentials";strings="phase cause";}
            case "available-upstream" -> {numbers="upstreamConnections configuredProxyCredentialHeaders";booleans="expectedOutputReturned attemptCredentialsStrippedBeforeOrigin";}
            case "unavailable-unauthenticated-route" -> {numbers="originRequests";booleans="retryable configuredProxyHadCredentials";strings="phase cause";}
            case "missing-fingerprint" -> {numbers="originRequests";booleans="retryable";strings="cause";}
            case "native-picker" -> {numbers="explicitSelectionDialogs sameSubjectChoices distinctFingerprints";booleans="explicitFingerprintSelected cancelPreservedSelection missingModuleReported moduleMessageCoherent";}
            case "local-mtls-proxy" -> {numbers="targetConnections ownedListenersClosed";booleans="missingAttemptCredentialsRejected incorrectAttemptCredentialsRejected otherAttemptCredentialsRejected";}
            case "trust-mode-0", "trust-mode-1" -> {numbers="originRequests";booleans="retryable";strings="phase cause";}
            case "unlisted-origin" -> booleans="positiveExpectedFingerprintObserved unlistedOriginClientCertificateAbsent credentialReturnedForUnlistedOrigin";
            case "unlisted-proxy-key" -> {booleans="actualBrowserRejectedUnlistedKey peerlessTlsEngineRejected";strings="safeBrowserCode";}
            case "selected-identities" -> {numbers="protectedAccountsVerified allowedRedirectAccountsVerified tlsRequestsObserved proxyCredentialsAtOrigin";booleans="allCertificatesMatched tlsSessionReusedAcrossReconnect";}
            default -> {return false;}
        }
        var keys=new HashSet<String>();
        for(String field:words(numbers)){keys.add(field);n(value,field);}
        for(String field:words(booleans)){keys.add(field);if(!value.get(field).getAsJsonPrimitive().isBoolean())return false;}
        for(String field:words(strings)) {
            keys.add(field);String actual=s(value,field);
            if(field.equals("safeBrowserCode")){if(!actual.equals("ERR_CERT_AUTHORITY_INVALID"))return false;}
            else if(!actual.matches("[A-Z][A-Z_]{0,40}"))return false;
        }
        return value.keySet().equals(keys);
    }
    private static List<String> words(String value){return value.isEmpty()?List.of():List.of(value.split(" "));}
    private static String s(JsonObject value,String key){return LabRun.text(value,key);}
    private static long n(JsonObject value,String key){return LabRun.number(value,key,true);}
    private static boolean b(JsonObject value,String key){return value.get(key).getAsBoolean();}
    static List<ScenarioCatalog.Fact> facts(String id,JsonObject a) {
        String outcome=null;
        switch(id) {
            case "TLS.proxy.direct" -> {if(n(a,"primeProxyRequests")>0&&n(a,"directProxyRequests")==0&&n(a,"tokenRequests")==2&&n(a,"expectedOutputsReturned")==2&&!b(a,"directHadMarker"))outcome="actual-network-route-matches-selected-transport";}
            case "TLS.proxy.http-proxy" -> {if(n(a,"proxyRequests")>0&&n(a,"ownershipPathsObserved")>=8&&b(a,"allRequestsOwned")&&b(a,"cleanAgentPreserved")&&b(a,"expectedOutputReturned"))outcome="actual-network-route-matches-selected-transport";}
            case "TLS.proxy.connect" -> {if(n(a,"upstreamConnections")>0&&n(a,"configuredProxyCredentialHeaders")==0&&b(a,"expectedOutputReturned")&&b(a,"attemptCredentialsStrippedBeforeOrigin"))outcome="unauthenticated-configured-tunnel-returns-expected-output-with-clean-proxy-and-origin-headers";}
            case "TLS.proxy.proxy-unavailable" -> {if(s(a,"phase").equals("PROXY")&&s(a,"cause").equals("TRANSPORT")&&b(a,"retryable")&&n(a,"originRequests")==0&&!b(a,"configuredProxyHadCredentials"))outcome="unavailable-route-returns-retryable-connection-failure-without-direct-bypass";}
            case "TLS.proxy.no-direct-fallback" -> {if(n(a,"originRequests")==0&&!b(a,"credentialReturned")&&!b(a,"configuredProxyHadCredentials"))outcome="failed-selected-route-never-reaches-origin-directly";}
            case "TLS.mtls.missing-certificate" -> {if(s(a,"cause").equals("CERTIFICATE")&&!b(a,"retryable")&&n(a,"originRequests")==0)outcome="missing-selected-fingerprint-fails-before-browser-or-origin-use";}
            case "TLS.mtls.ambiguous-certificate" -> {if(n(a,"explicitSelectionDialogs")==2&&n(a,"sameSubjectChoices")==2&&n(a,"distinctFingerprints")==2&&b(a,"explicitFingerprintSelected")&&b(a,"cancelPreservedSelection"))outcome="same-subject-picker-requires-explicit-fingerprint-and-cancel-preserves-selection";}
            case "TLS.mtls.token-unavailable" -> {if(n(a,"explicitSelectionDialogs")==2&&b(a,"missingModuleReported")&&b(a,"moduleMessageCoherent"))outcome="missing-software-module-reports-module-failure-without-another-selection-dialog";}
            case "TLS.mtls.internal-proxy-credentials" -> {if(b(a,"missingAttemptCredentialsRejected")&&b(a,"incorrectAttemptCredentialsRejected")&&b(a,"otherAttemptCredentialsRejected")&&n(a,"targetConnections")==0&&n(a,"ownedListenersClosed")==2)outcome="owned-local-mtls-proxy-rejects-absent-wrong-and-other-attempt-credentials-before-target-contact";}
            case "TLS.mtls.disallowed-origin" -> {if(b(a,"positiveExpectedFingerprintObserved")&&b(a,"unlistedOriginClientCertificateAbsent")&&!b(a,"credentialReturnedForUnlistedOrigin"))outcome="unlisted-origin-receives-no-client-certificate-and-returns-no-credential";}
            case "TLS.trust.untrusted-origin", "TLS.trust.wrong-host" -> {if(n(a,"originRequests")==0&&!b(a,"retryable")&&!s(a,"cause").equals("PIN_REJECTED"))outcome=id.endsWith("wrong-host")?"wrong-upstream-certificate-hostname-is-rejected-before-origin-application-use":"untrusted-upstream-ca-is-rejected-before-origin-application-use";}
            case "TLS.trust.unlisted-proxy-key" -> {if(b(a,"actualBrowserRejectedUnlistedKey")&&b(a,"peerlessTlsEngineRejected")&&s(a,"safeBrowserCode").equals("ERR_CERT_AUTHORITY_INVALID"))outcome="browser-rejects-extension-owned-local-proxy-certificate-without-its-key-exception";}
            default -> {
                boolean accounts=n(a,"protectedAccountsVerified")==2&&b(a,"allCertificatesMatched")&&n(a,"proxyCredentialsAtOrigin")==0;
                outcome=switch(id) {
                    case "TLS.mtls.expected-fingerprint" -> accounts?"configured-certificate-authenticates-expected-account-with-clean-origin-headers":null;
                    case "TLS.mtls.same-CN-pair" -> accounts?"same-subject-certificates-retain-distinct-fingerprints-and-protected-identities":null;
                    case "TLS.mtls.allowed-redirect" -> accounts&&n(a,"allowedRedirectAccountsVerified")==2?"configured-identity-authenticates-at-each-exact-allowed-redirect-origin":null;
                    case "TLS.mtls.resource-without-mtls" -> accounts?"captured-bearer-authenticates-expected-account-at-non-mtls-resource":null;
                    case "TLS.mtls.pool-cleanup" -> accounts&&n(a,"tlsRequestsObserved")>=80&&b(a,"tlsSessionReusedAcrossReconnect")?"identity-pools-reuse-only-own-tls-sessions-and-close-owned-browser-processes":null;
                    case "TLS.trust.listed-proxy-key" -> accounts?"managed-browser-accepts-owned-local-proxy-key":null;
                    default -> throw new IllegalArgumentException("Uninspected transport fact.");
                };
            }
        }
        return outcome==null?List.of():List.of(new ScenarioCatalog.Fact("outcome",outcome));
    }
}
