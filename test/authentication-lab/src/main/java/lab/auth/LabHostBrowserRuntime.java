package lab.auth;

import com.google.gson.*;
import java.io.IOException;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static lab.auth.LabJson.*;

/** Qualification receipt for the exact browser-runtime build; cannot grant HOST catalog acceptance. */
public final class LabHostBrowserRuntime {
    private LabHostBrowserRuntime() {}
    static void validateNativeEvidence(JsonObject evidence,Path report) throws IOException {
        try {
            var environment=read(report.resolve("environment.json"),65536);
            for(String key:List.of("burpPid","burpStartedEpochMs"))require(evidence.get(key).equals(environment.get(key)),"RUNTIME_NATIVE_PROCESS");
            require(evidence.get("heapBytes").equals(environment.get("actualMaxHeapBytes")),"RUNTIME_NATIVE_HEAP");
            require(evidence.get("memory").equals(read(report.resolve("memory.json"),65536)),"RUNTIME_NATIVE_MEMORY");
            var session=new LabHostGuiProtocol.Session(uuid(evidence.get("invocationId")),text(evidence,"platform"),uuid(evidence.get("runNonce")),
                    hash(evidence.get("productSha256")),hash(evidence.get("helperSha256")),report);
            var journal=new TreeMap<Long,JsonObject>();
            try(var files=Files.list(report)) {
                var nativeFiles=files.filter(path->path.getFileName().toString().matches("gui-[0-9]{3,6}\\.json")).limit(LabHostGuest.EVIDENCE_INDEX_LIMIT+1).toList();
                require(nativeFiles.size()<=LabHostGuest.EVIDENCE_INDEX_LIMIT,"RUNTIME_NATIVE_JOURNAL_SIZE");
                for(Path path:nativeFiles) {
                    var receipt=LabHostGuiProtocol.validateRetainedReceipt(read(owned(report,path.getFileName().toString()),65536),session);
                    long sequence=positive(receipt.get("sequence"));require(path.getFileName().toString().equals(String.format(Locale.ROOT,"gui-%03d.json",sequence))
                            &&journal.put(sequence,receipt)==null&&text(receipt,"outcome").equals("PASS"),"RUNTIME_NATIVE_JOURNAL");
                }
            }
            for(var item:evidence.getAsJsonArray("cycles")) {
                var cycle=item.getAsJsonObject();
                for(boolean enabled:List.of(false,true)) {
                    long sequence=positive(cycle.get(enabled?"loadSequence":"unloadSequence"));
                    var nativeReceipt=LabHostGuiProtocol.validateRetainedReceipt(read(owned(report,String.format(Locale.ROOT,"gui-%03d.json",sequence)),65536),session);
                    require(positive(nativeReceipt.get("sequence"))==sequence&&text(nativeReceipt,"operation").equals("SET_PRODUCT_LOADED")
                            &&text(nativeReceipt,"outcome").equals("PASS"),"RUNTIME_NATIVE_RELOAD");
                    require(flag(nativeReceipt.getAsJsonObject("intent"),"enabled")==enabled&&flag(nativeReceipt.getAsJsonObject("observed"),"enabled")==enabled,"RUNTIME_NATIVE_RELOAD");
                    if(enabled)require(flag(nativeReceipt.getAsJsonObject("observed"),"productSourceMatched"),"RUNTIME_NATIVE_SOURCE");
                    require(positive(nativeReceipt.get("startedEpochMs"))>=positive(cycle.get("beganEpochMs"))
                            &&positive(nativeReceipt.get("endedEpochMs"))<=positive(cycle.get("endedEpochMs")),"RUNTIME_NATIVE_ORDER");
                }
            }
            var tests=nativeOperations(journal,"TEST_BROWSER_LOGIN",3);var starts=nativeOperations(journal,"RECORD_BROWSER_LOGIN",1);
            var stops=nativeOperations(journal,"FINISH_BROWSER_RECORDING",1);var settings=nativeOperations(journal,"BROWSER_SETTINGS",4);
            var cycles=evidence.getAsJsonArray("cycles");long fourth=positive(cycles.get(3).getAsJsonObject().get("loadSequence")),fifth=positive(cycles.get(4).getAsJsonObject().get("unloadSequence"));
            require(positive(tests.get(0).get("sequence"))>fourth&&positive(tests.get(0).get("sequence"))<fifth
                    &&positive(tests.get(0).get("endedEpochMs"))<=positive(evidence.getAsJsonObject("preReloadLogin").get("endedEpochMs")),"RUNTIME_NATIVE_USED_RELOAD");
            long after=positive(cycles.get(4).getAsJsonObject().get("loadSequence"));
            for(var receipt:List.of(tests.get(1),starts.getFirst(),stops.getFirst(),tests.get(2))) {
                long sequence=positive(receipt.get("sequence"));require(sequence>after,"RUNTIME_NATIVE_FLOW_ORDER");after=sequence;
            }
            for(var receipt:tests)require(flag(receipt.getAsJsonObject("observed"),"testUiConfirmed"),"RUNTIME_NATIVE_LOGIN");
            var started=starts.getFirst().getAsJsonObject("observed");var stopped=stops.getFirst().getAsJsonObject("observed");
            for(String key:List.of("nativeStart","initialStepsCleared","loginTyped"))require(flag(started,key),"RUNTIME_NATIVE_RECORDING");
            for(String key:List.of("nativeStop","reviewReplaced"))require(flag(stopped,key),"RUNTIME_NATIVE_RECORDING");
            require(evidence.get("browserVersion").equals(started.get("browserVersion")),"RUNTIME_NATIVE_BROWSER_VERSION");
            for(int i=0;i<settings.size();i++) {
                var receipt=settings.get(i);require(positive(receipt.get("sequence"))>after,"RUNTIME_NATIVE_SETTINGS_ORDER");after=positive(receipt.get("sequence"));
                require(receipt.get("observed").equals(evidence.getAsJsonArray("settings").get(i)),"RUNTIME_NATIVE_SETTINGS");
                for(String key:List.of("theme","size"))require(receipt.getAsJsonObject("intent").get(key).equals(receipt.getAsJsonObject("observed").get(key)),"RUNTIME_NATIVE_SETTINGS_INTENT");
            }
        }catch(RuntimeException invalid){throw new IOException("HOST_NATIVE_RUNTIME_EVIDENCE");}
    }
    private static List<JsonObject> nativeOperations(SortedMap<Long,JsonObject> journal,String operation,int count) {
        var receipts=journal.values().stream().filter(receipt->text(receipt,"operation").equals(operation)).toList();
        require(receipts.size()==count,"RUNTIME_NATIVE_OPERATION_COUNT");
        for(var receipt:receipts)require(text(receipt.getAsJsonObject("intent"),"alias").equals("host_b"),"RUNTIME_NATIVE_JOURNEY");
        return receipts;
    }
    public static void validate(JsonObject evidence,String expectedProductSha256,String expectedLoadedPath) throws IOException {
        try {
            var value=object(evidence,"version","invocationId","platform","runNonce","productSha256","helperSha256","stage","taskPath",
                    "loadedPath","browserVersion","burpPid","burpStartedEpochMs","heapBytes","startedEpochMs","endedEpochMs",
                    "cycles","memory","nativeLoadingErrors","preReloadLogin","login","recording","settings","cleanup");
            require(positive(value.get("version"))==1,"RUNTIME_VERSION");uuid(value.get("invocationId"));uuid(value.get("runNonce"));hash(value.get("helperSha256"));
            String platform=member(value.get("platform"),"windows","linux");
            require(text(value,"stage").equals("BROWSER_RUNTIME")&&text(value,"taskPath").equals(":authLabHostQualify"),"RUNTIME_SCOPE");
            require(hash(value.get("productSha256")).equals(expectedProductSha256)&&sameLoadedPath(platform,text(value,"loadedPath"),expectedLoadedPath),"RUNTIME_ARTIFACT");
            require(text(value,"browserVersion").matches("[0-9]{1,9}(?:\\.[0-9]{1,9}){2,3}"),"RUNTIME_BROWSER_VERSION");
            long pid=positive(value.get("burpPid")),born=positive(value.get("burpStartedEpochMs"));
            long begin=positive(value.get("startedEpochMs")),end=positive(value.get("endedEpochMs"));
            require(begin>=born&&end>=begin&&positive(value.get("heapBytes"))==(2L<<30),"RUNTIME_PROCESS");
            require(number(value.get("nativeLoadingErrors"))==0&&text(value,"cleanup").equals("COMPLETE"),"RUNTIME_CLEANUP");
            var cycles=value.getAsJsonArray("cycles");require(cycles.size()==5,"RUNTIME_CYCLES");long previous=begin,sequence=0;
            for(int i=0;i<cycles.size();i++) {
                var cycle=object(cycles.get(i),"cycle","pid","startedEpochMs","productSha256","loadedPath","beganEpochMs","endedEpochMs","unloadSequence","loadSequence","unloaded","loaded","productSourceMatched");
                require(positive(cycle.get("cycle"))==i+1&&positive(cycle.get("pid"))==pid&&positive(cycle.get("startedEpochMs"))==born,"RUNTIME_CYCLE_PROCESS");
                require(hash(cycle.get("productSha256")).equals(expectedProductSha256)&&sameLoadedPath(platform,text(cycle,"loadedPath"),expectedLoadedPath),"RUNTIME_CYCLE_ARTIFACT");
                long began=positive(cycle.get("beganEpochMs")),ended=positive(cycle.get("endedEpochMs"));
                long unloaded=positive(cycle.get("unloadSequence")),loaded=positive(cycle.get("loadSequence"));
                require(began>=previous&&ended>=began&&ended<=end&&unloaded>sequence&&loaded>unloaded,"RUNTIME_CYCLE_ORDER");
                require(flag(cycle,"unloaded")&&flag(cycle,"loaded")&&flag(cycle,"productSourceMatched"),"RUNTIME_NATIVE_CYCLE");previous=ended;sequence=loaded;
            }
            var memory=object(value.get("memory"),"version","invocationId","platform","runNonce","productSha256","helperSha256",
                    "pid","startedEpochMs","intervalMs","peakRssBytes","samples","overflow","firstSampleEpochMs","lastSampleEpochMs","maxSampleGapMs","complete","gc");
            for(String key:List.of("version","invocationId","platform","runNonce","productSha256","helperSha256"))
                require(value.get(key).equals(memory.get(key)),"RUNTIME_MEMORY_IDENTITY");
            require(positive(memory.get("pid"))==pid&&positive(memory.get("startedEpochMs"))==born&&positive(memory.get("intervalMs"))==200,"RUNTIME_MEMORY_OWNER");
            require(flag(memory,"complete")&&!flag(memory,"overflow")&&positive(memory.get("samples"))>=3&&positive(memory.get("peakRssBytes"))>0,"RUNTIME_MEMORY");
            long first=positive(memory.get("firstSampleEpochMs")),last=positive(memory.get("lastSampleEpochMs")),gap=number(memory.get("maxSampleGapMs"));
            require(first>=born&&first<=begin+1000&&last>=first&&last+1000>=end&&gap<=LabHostMemory.MAX_GAP_MS,"RUNTIME_MEMORY_COVERAGE");
            require(last-first<=Math.multiplyExact(positive(memory.get("samples"))-1,gap),"RUNTIME_MEMORY_DENSITY");
            var gc=object(memory.get("gc"),"complete","objectObservations","gcObservations","maxObservedObjectBytes","peakObservedHumongousBytes");require(flag(gc,"complete"),"RUNTIME_GC");
            for(String key:List.of("objectObservations","gcObservations","maxObservedObjectBytes","peakObservedHumongousBytes"))number(gc.get(key));
            var login=object(value.get("login"),"testUiConfirmed","proof");require(flag(login,"testUiConfirmed"),"RUNTIME_LOGIN_UI");String firstIssuance=proof(object(login.get("proof")));
            var prior=object(value.get("preReloadLogin"),"testUiConfirmed","endedEpochMs","proof");
            require(flag(prior,"testUiConfirmed"),"RUNTIME_PRE_RELOAD_UI");String priorIssuance=proof(object(prior.get("proof")));
            long used=positive(prior.get("endedEpochMs"));
            require(used>=positive(cycles.get(3).getAsJsonObject().get("endedEpochMs"))&&used<=positive(cycles.get(4).getAsJsonObject().get("beganEpochMs"))
                    &&!priorIssuance.equals(firstIssuance),"RUNTIME_USED_RELOAD");
            var recording=object(value.get("recording"),"initialStepsCleared","nativeStart","nativeStop","reviewReplaced","replayUiConfirmed","recordedAccount","recordedIssuance","replayProof");
            for(String key:List.of("initialStepsCleared","nativeStart","nativeStop","reviewReplaced","replayUiConfirmed"))require(flag(recording,key),"RUNTIME_RECORDING_UI");
            require(text(recording,"recordedAccount").equals("user2"),"RUNTIME_RECORDING_ACCOUNT");
            String recorded=text(recording,"recordedIssuance"),replayed=proof(object(recording.get("replayProof")));
            require(recorded.matches("s[0-9]+")&&!recorded.equals(firstIssuance)&&!replayed.equals(recorded)&&!replayed.equals(firstIssuance)&&!recorded.equals(priorIssuance)&&!replayed.equals(priorIssuance),"RUNTIME_FRESH_LOGINS");
            var variants=value.getAsJsonArray("settings");require(variants.size()==4,"RUNTIME_SETTINGS_VARIANTS");var seen=new HashSet<String>();
            for(var entry:variants) {
                var variant=object(entry,"theme","size","width","inlineError","focused","noPopup","literalPath","controlsVisible");
                String theme=member(variant.get("theme"),"Light","Dark"),size=member(variant.get("size"),"compact","wide");
                long width=positive(variant.get("width"));require(size.equals("compact")?width<=1100:width>=1200,"RUNTIME_SETTINGS_SIZE");
                require(seen.add(theme+":"+size),"RUNTIME_SETTINGS_DUPLICATE");
                for(String key:List.of("inlineError","focused","noPopup","literalPath","controlsVisible"))require(flag(variant,key),"RUNTIME_SETTINGS_UI");
            }
        }catch(RuntimeException invalid){throw new IOException("HOST_BROWSER_RUNTIME_EVIDENCE");}
    }
    /** Reads only fixed error signatures from bounded owned logs; no private text leaves this method. */
    static int loadingErrors(Path root) throws IOException {
        Path owner=root.toRealPath();int errors=0;
        var signature=java.util.regex.Pattern.compile("UnsatisfiedLinkError|already loaded in another classloader|Error loading extension|LinkageError",java.util.regex.Pattern.CASE_INSENSITIVE);
        for(String name:List.of("burp-private-out.txt","burp-private-error.txt")) {
            Path log=owner.resolve(name);
            if(!Files.isRegularFile(log,LinkOption.NOFOLLOW_LINKS)||!log.toRealPath().getParent().equals(owner)||Files.size(log)>8L*1024*1024)
                throw new IOException("HOST_NATIVE_LOADING_OBSERVATION");
            try(var input=Files.newInputStream(log)) {
                byte[] bytes=input.readNBytes(8*1024*1024+1);if(bytes.length>8*1024*1024)throw new IOException("HOST_NATIVE_LOADING_OBSERVATION");
                errors=Math.addExact(errors,(int)new String(bytes,StandardCharsets.UTF_8).lines().filter(line->signature.matcher(line).find()).count());
            }
        }
        return errors;
    }
    private static boolean sameLoadedPath(String platform,String actual,String expected) {
        return platform.equals("windows")?actual.equalsIgnoreCase(expected):actual.equals(expected);
    }
    private static String proof(JsonObject proof) {
        object(proof,"status","account","issuance","roles");require(positive(proof.get("status"))==200&&text(proof,"account").equals("user2"),"RUNTIME_ACCOUNT");
        var roles=strings(proof.get("roles"));require(roles.size()==2&&new HashSet<>(roles).equals(Set.of("B","C1")),"RUNTIME_ROLES");String issuance=text(proof,"issuance");require(issuance.matches("s[0-9]+"),"RUNTIME_ISSUANCE");return issuance;
    }
    private static boolean flag(JsonObject value,String key){var field=value.get(key);require(field!=null&&field.isJsonPrimitive()&&field.getAsJsonPrimitive().isBoolean(),"RUNTIME_BOOLEAN");return field.getAsBoolean();}
    private static long number(JsonElement value){require(value!=null&&value.isJsonPrimitive()&&value.getAsJsonPrimitive().isNumber(),"RUNTIME_NUMBER");long n=value.getAsBigDecimal().longValueExact();require(n>=0,"RUNTIME_NUMBER");return n;}
}
