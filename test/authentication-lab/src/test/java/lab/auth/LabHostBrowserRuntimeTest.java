package lab.auth;

import com.google.gson.*;
import java.io.IOException;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class LabHostBrowserRuntimeTest {
    static final String SHA="a".repeat(64),PATH="C:\\bpsh\\browser-powered-session-handler-dev.jar";
    @Test void windowsPathCasingDoesNotChangeTheSelectedArtifact() {
        var current=receipt();setPaths(current,PATH.replace("\\bpsh\\","\\BPSH\\"));
        assertDoesNotThrow(()->validate(current));
        for(String foreign:List.of("D:\\bpsh\\browser-powered-session-handler-dev.jar","C:\\other\\browser-powered-session-handler-dev.jar",PATH+".old")) {
            var changed=current.deepCopy();changed.addProperty("loadedPath",foreign);assertThrows(IOException.class,()->validate(changed));
        }
    }
    @Test void linuxArtifactPathsRemainCaseSensitive() {
        String path="/home/tester/bpsh/active.jar";var current=receipt();current.addProperty("platform","linux");current.getAsJsonObject("memory").addProperty("platform","linux");setPaths(current,path);
        assertDoesNotThrow(()->LabHostBrowserRuntime.validate(current,SHA,path));
        current.addProperty("loadedPath","/HOME/tester/bpsh/active.jar");assertThrows(IOException.class,()->LabHostBrowserRuntime.validate(current,SHA,path));
        current.addProperty("loadedPath",path);current.getAsJsonArray("cycles").get(0).getAsJsonObject().addProperty("loadedPath","/HOME/tester/bpsh/active.jar");
        assertThrows(IOException.class,()->LabHostBrowserRuntime.validate(current,SHA,path));
    }
    private static void setPaths(JsonObject value,String path) {
        value.addProperty("loadedPath",path);for(var cycle:value.getAsJsonArray("cycles"))cycle.getAsJsonObject().addProperty("loadedPath",path);
    }
    @Test void fiveCyclesRequireSamePidAndExactArtifact() throws Exception {
        var current=receipt();assertDoesNotThrow(()->validate(current));
        for(String key:List.of("pid","startedEpochMs")) {var changed=current.deepCopy();changed.getAsJsonArray("cycles").get(2).getAsJsonObject().addProperty(key,999);assertThrows(IOException.class,()->validate(changed));}
        var four=current.deepCopy();four.getAsJsonArray("cycles").remove(4);assertThrows(IOException.class,()->validate(four));
        var heap=current.deepCopy();heap.addProperty("heapBytes",3L<<30);assertThrows(IOException.class,()->validate(heap));
        var same=current.deepCopy();same.getAsJsonArray("cycles").get(2).getAsJsonObject().addProperty("unloadSequence",1);assertThrows(IOException.class,()->validate(same));
    }
    @Test void staleStableCopyCannotPass() {
        var old=receipt();old.addProperty("productSha256","f".repeat(64));assertThrows(IOException.class,()->validate(old));
        var path=receipt();path.addProperty("loadedPath","C:\\obsolete.jar");assertThrows(IOException.class,()->validate(path));
        var cycle=receipt();cycle.getAsJsonArray("cycles").get(4).getAsJsonObject().addProperty("productSha256","f".repeat(64));assertThrows(IOException.class,()->validate(cycle));
    }
    @Test void missingRssIntervalOrLoadingErrorFailsQualification() {
        for(String key:List.of("complete","overflow")) {var receipt=receipt();receipt.getAsJsonObject("memory").addProperty(key,!key.equals("complete"));assertThrows(IOException.class,()->validate(receipt));}
        var cadence=receipt();cadence.getAsJsonObject("memory").addProperty("intervalMs",250);assertThrows(IOException.class,()->validate(cadence));
        var gap=receipt();gap.getAsJsonObject("memory").addProperty("maxSampleGapMs",LabHostMemory.MAX_GAP_MS+1);assertThrows(IOException.class,()->validate(gap));
        var ending=receipt();ending.getAsJsonObject("memory").addProperty("lastSampleEpochMs",1100);assertThrows(IOException.class,()->validate(ending));
        var gc=receipt();gc.getAsJsonObject("memory").getAsJsonObject("gc").addProperty("complete",false);assertThrows(IOException.class,()->validate(gc));
        var loader=receipt();loader.addProperty("nativeLoadingErrors",1);assertThrows(IOException.class,()->validate(loader));
        var cleanup=receipt();cleanup.addProperty("cleanup","INCOMPLETE");assertThrows(IOException.class,()->validate(cleanup));
    }
    @Test void loginNeedsIndependentAccountAndRecordingEvidence() {
        var account=receipt();account.getAsJsonObject("login").getAsJsonObject("proof").addProperty("account","wrong-user");assertThrows(IOException.class,()->validate(account));
        var reused=receipt();reused.getAsJsonObject("recording").getAsJsonObject("replayProof").addProperty("issuance","s2");assertThrows(IOException.class,()->validate(reused));
        for(String key:List.of("initialStepsCleared","nativeStart","nativeStop","reviewReplaced","replayUiConfirmed")) {var changed=receipt();changed.getAsJsonObject("recording").addProperty(key,false);assertThrows(IOException.class,()->validate(changed));}
        var missing=receipt();missing.getAsJsonObject("recording").remove("replayProof");assertThrows(IOException.class,()->validate(missing));
    }
    @Test void settingsNeedsBothNativeThemesSizesAndActualLocatedFocus() {
        var partial=receipt();partial.getAsJsonArray("settings").remove(3);assertThrows(IOException.class,()->validate(partial));
        for(String key:List.of("inlineError","focused","noPopup","literalPath","controlsVisible")) {var changed=receipt();changed.getAsJsonArray("settings").get(0).getAsJsonObject().addProperty(key,false);assertThrows(IOException.class,()->validate(changed));}
    }
    @Test void foreignMemoryAndContradictorySamplingCannotPass() {
        for(String key:List.of("invocationId","platform","runNonce","productSha256","helperSha256")) {
            var foreign=receipt();foreign.getAsJsonObject("memory").addProperty(key,"foreign");assertThrows(IOException.class,()->validate(foreign));
        }
        var sparse=receipt();sparse.getAsJsonObject("memory").addProperty("samples",3);assertThrows(IOException.class,()->validate(sparse));
        var unknown=receipt();unknown.getAsJsonObject("memory").addProperty("ignored",true);assertThrows(IOException.class,()->validate(unknown));
        var duplicateRoles=receipt();duplicateRoles.getAsJsonObject("login").getAsJsonObject("proof").add("roles",LabJson.JSON.toJsonTree(List.of("B","C1","B")));
        assertThrows(IOException.class,()->validate(duplicateRoles));
    }
    @Test void lastReloadMustFollowRealBrowserUseAndRetainActualProductProvenance() {
        var missing=receipt();missing.remove("preReloadLogin");assertThrows(IOException.class,()->validate(missing));
        var late=receipt();late.getAsJsonObject("preReloadLogin").addProperty("endedEpochMs",1500);assertThrows(IOException.class,()->validate(late));
        var reused=receipt();reused.getAsJsonObject("preReloadLogin").getAsJsonObject("proof").addProperty("issuance","s2");assertThrows(IOException.class,()->validate(reused));
        var stale=receipt();stale.getAsJsonArray("cycles").get(4).getAsJsonObject().addProperty("productSourceMatched",false);assertThrows(IOException.class,()->validate(stale));
    }
    @Test void scopedRuntimeStageCannotClaimHostCatalogPass() {
        String[] base={"host-qualify","--workspace",".","--report-directory",".","--artifact",".","--vm-config",".","--plan",".","--stage","browser-runtime"};
        assertEquals("browser-runtime",LabHostInputs.options(base).stage());base[0]="host-test";assertThrows(IllegalArgumentException.class,()->LabHostInputs.options(base));
        var wrong=receipt();wrong.addProperty("taskPath",":authLabHostTest");assertThrows(IOException.class,()->validate(wrong));
        var result=new LabHostCoordinator.PlatformResult("windows",LabHostCoordinator.Outcome.PASS,"BROWSER_RUNTIME_QUALIFIED",LabHostCoordinator.Cleanup.COMPLETE,true,Map.of());
        assertFalse(LabHostCoordinator.complete(List.of("windows"),List.of(result),"scenarios"));
    }
    static void validate(JsonObject value) throws IOException {LabHostBrowserRuntime.validate(value,SHA,PATH);}
    static JsonObject proof(String issuance){return LabJson.JSON.toJsonTree(Map.of("status",200,"account","user2","issuance",issuance,"roles",List.of("B","C1"))).getAsJsonObject();}
    static JsonObject receipt() {
        var root=LabJson.JSON.toJsonTree(Map.of("version",1,"invocationId",UUID.randomUUID(),"platform","windows","runNonce",UUID.randomUUID(),"productSha256",SHA,"helperSha256","b".repeat(64))).getAsJsonObject();
        root.addProperty("stage","BROWSER_RUNTIME");root.addProperty("taskPath",":authLabHostQualify");root.addProperty("loadedPath",PATH);root.addProperty("browserVersion","156.0.8078.48");
        root.addProperty("burpPid",321);root.addProperty("burpStartedEpochMs",100);root.addProperty("heapBytes",2L<<30);root.addProperty("startedEpochMs",1000);root.addProperty("endedEpochMs",3000);root.addProperty("nativeLoadingErrors",0);root.addProperty("cleanup","COMPLETE");
        var cycles=new JsonArray();for(int i=0;i<5;i++){var c=new JsonObject();c.addProperty("cycle",i+1);c.addProperty("pid",321);c.addProperty("startedEpochMs",100);c.addProperty("productSha256",SHA);c.addProperty("loadedPath",PATH);
            c.addProperty("beganEpochMs",1000+i*100);c.addProperty("endedEpochMs",1040+i*100);c.addProperty("unloadSequence",1+i*2);c.addProperty("loadSequence",2+i*2);c.addProperty("unloaded",true);c.addProperty("loaded",true);c.addProperty("productSourceMatched",true);cycles.add(c);}root.add("cycles",cycles);
        var memory=new JsonObject();for(String key:List.of("version","invocationId","platform","runNonce","productSha256","helperSha256"))memory.add(key,root.get(key).deepCopy());memory.addProperty("pid",321);memory.addProperty("startedEpochMs",100);memory.addProperty("intervalMs",200);memory.addProperty("peakRssBytes",300L<<20);memory.addProperty("samples",12);memory.addProperty("overflow",false);memory.addProperty("complete",true);memory.addProperty("firstSampleEpochMs",900);memory.addProperty("lastSampleEpochMs",3100);memory.addProperty("maxSampleGapMs",200);
        var gc=new JsonObject();gc.addProperty("complete",true);for(String key:List.of("objectObservations","gcObservations","maxObservedObjectBytes","peakObservedHumongousBytes"))gc.addProperty(key,0);memory.add("gc",gc);root.add("memory",memory);
        var login=new JsonObject();login.addProperty("testUiConfirmed",true);login.add("proof",proof("s2"));root.add("login",login);
        var prior=new JsonObject();prior.addProperty("testUiConfirmed",true);prior.addProperty("endedEpochMs",1370);prior.add("proof",proof("s1"));root.add("preReloadLogin",prior);
        var recording=new JsonObject();for(String key:List.of("initialStepsCleared","nativeStart","nativeStop","reviewReplaced","replayUiConfirmed"))recording.addProperty(key,true);recording.addProperty("recordedAccount","user2");recording.addProperty("recordedIssuance","s3");recording.add("replayProof",proof("s4"));root.add("recording",recording);
        var settings=new JsonArray();for(String theme:List.of("Light","Dark"))for(String size:List.of("compact","wide")){var v=new JsonObject();v.addProperty("theme",theme);v.addProperty("size",size);v.addProperty("width",size.equals("compact")?1000:1400);for(String key:List.of("inlineError","focused","noPopup","literalPath","controlsVisible"))v.addProperty(key,true);settings.add(v);}root.add("settings",settings);return root;
    }
}
