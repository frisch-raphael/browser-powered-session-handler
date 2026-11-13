package lab.auth;

import com.google.gson.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import static lab.auth.LabJson.*;

/** Private, bounded GUI command channel. A claimed input is never blindly repeated. */
public final class LabHostGuiProtocol {
    private LabHostGuiProtocol() {}
    public static final Set<String> SAFE_LABELS=Set.of("Proxy","Repeater","Extensions","Browser Powered Session Handler",
            "Test login","Next","Start Burp","Journeys","Session handling","Settings","Import journeys...","Loaded","Extension loaded",
            "Intercept","HTTP history","Intercept is on","Intercept is off","Intercept on","Intercept off","Forward","Drop","Send","Raw","Pretty","Hex");
    public enum Operation { READY, IMPORT_JOURNEY, ENTER_SECRET, EDIT_RULES, OPEN_TOOL, COPY_TO_REPEATER,
        SET_REPEATER_REQUEST, SET_REPEATER_NONCE, SEND_REPEATER, ASSERT_REPEATER_RESPONSE, TEST_LOGIN, TEST_BROWSER_LOGIN, RECORD_BROWSER_LOGIN, FINISH_BROWSER_RECORDING, BROWSER_SETTINGS, SET_INTERCEPT, EDIT_INTERCEPTED_REQUEST,
        FORWARD_INTERCEPTED_REQUEST, SET_PRODUCT_LOADED, CAPTURE_PROBE, ASSERT_UI, CLOSE }
    public enum ClaimState { NEW, COMPLETED, AMBIGUOUS }
    public record Session(UUID invocationId, String platform, UUID runNonce, String productSha256,
                          String helperSha256, Path root) {}
    public record Command(long sequence, UUID operationId, Operation operation, long deadlineEpochMs, JsonObject arguments) {
        public Command { arguments = arguments.deepCopy(); }
        @Override public JsonObject arguments() { return arguments.deepCopy(); }
    }
    public record Claim(ClaimState state, Path claim, Path receipt) {}

    public static Session session(Path root) throws IOException {
        root = root.toRealPath();
        var json = object(read(root.resolve("gui-session.json"), 64 * 1024), "version", "invocationId", "platform",
                "runNonce", "productSha256", "helperSha256", "root");
        require(positive(json.get("version")) == 1, "GUI_VERSION");
        require(Path.of(text(json,"root")).toRealPath().equals(root), "GUI_ROOT");
        return new Session(uuid(json.get("invocationId")), member(json.get("platform"), "windows", "linux"),
                uuid(json.get("runNonce")), hash(json.get("productSha256")), hash(json.get("helperSha256")), root);
    }
    public static Command command(JsonObject json, Session session) throws IOException {
        object(json, "version", "invocationId", "platform", "runNonce", "productSha256", "helperSha256",
                "sequence", "operationId", "operation", "deadlineEpochMs", "arguments");
        require(positive(json.get("version")) == 1, "GUI_VERSION");
        require(uuid(json.get("invocationId")).equals(session.invocationId()) && text(json,"platform").equals(session.platform())
                && uuid(json.get("runNonce")).equals(session.runNonce()) && hash(json.get("productSha256")).equals(session.productSha256())
                && hash(json.get("helperSha256")).equals(session.helperSha256()), "GUI_FOREIGN_COMMAND");
        Operation operation;
        try { operation = Operation.valueOf(text(json,"operation")); }
        catch (IllegalArgumentException ex) { throw invalid("GUI_OPERATION"); }
        var args = object(json.get("arguments")); validateArguments(operation, args, session.root());
        return new Command(positive(json.get("sequence")), uuid(json.get("operationId")), operation,
                positive(json.get("deadlineEpochMs")), args);
    }
    public static JsonObject encode(Session session, Command command) {
        var json = identity(session); json.addProperty("sequence",command.sequence()); json.addProperty("operationId",command.operationId().toString());
        json.addProperty("operation",command.operation().name()); json.addProperty("deadlineEpochMs",command.deadlineEpochMs());
        json.add("arguments",command.arguments()); return json;
    }
    public static JsonObject identity(Session session) {
        var json = new JsonObject(); json.addProperty("version",1); json.addProperty("invocationId",session.invocationId().toString());
        json.addProperty("platform",session.platform()); json.addProperty("runNonce",session.runNonce().toString());
        json.addProperty("productSha256",session.productSha256()); json.addProperty("helperSha256",session.helperSha256()); return json;
    }
    public static JsonObject receipt(Session session, Command command, long began, long ended, String outcome, String code, JsonObject observed) {
        require(Set.of("PASS","FAIL","BLOCKED","CANCELLED").contains(outcome), "GUI_OUTCOME");
        require(code.matches("[A-Z][A-Z0-9_]{0,79}") && began > 0 && ended >= began, "GUI_RECEIPT");
        var json = identity(session); json.addProperty("sequence",command.sequence()); json.addProperty("operationId",command.operationId().toString());
        json.addProperty("operation",command.operation().name()); json.addProperty("startedEpochMs",began); json.addProperty("endedEpochMs",ended);
        json.addProperty("outcome",outcome); json.addProperty("code",code); json.add("observed", observed.deepCopy()); return json;
    }
    public static Claim claim(Session session, Command command, long expectedSequence, long now) throws IOException {
        Path directory = session.root().resolve("gui/claims"); Files.createDirectories(directory);
        Path claim = owned(session.root(),"gui/claims/"+command.operationId()+".json");
        Path receipt = owned(session.root(),"gui/receipts/"+command.operationId()+".json");
        String digest = digest(JSON.toJson(encode(session,command)).getBytes(StandardCharsets.UTF_8));
        if (Files.exists(claim, LinkOption.NOFOLLOW_LINKS)) {
            var retained = object(read(claim,4096),"sha256","sequence");
            require(hash(retained.get("sha256")).equals(digest) && positive(retained.get("sequence")) == command.sequence(), "GUI_REUSED_ID");
            if(Files.isRegularFile(receipt))validateReceipt(read(receipt,65536),session,command);
            return new Claim(Files.isRegularFile(receipt) ? ClaimState.COMPLETED : ClaimState.AMBIGUOUS, claim, receipt);
        }
        require(command.sequence() == expectedSequence, "GUI_SEQUENCE");
        require(now < command.deadlineEpochMs(), "GUI_DEADLINE");
        try { writeNew(claim, Map.of("sha256",digest,"sequence",command.sequence())); }
        catch (FileAlreadyExistsException conflict) { return claim(session, command, expectedSequence, now); }
        return new Claim(ClaimState.NEW,claim,receipt);
    }
    public static JsonObject validateReceipt(JsonObject value,Session session,Command command) {
        object(value,"version","invocationId","platform","runNonce","productSha256","helperSha256","sequence","operationId",
                "operation","startedEpochMs","endedEpochMs","outcome","code","observed");
        require(positive(value.get("version"))==1&&uuid(value.get("invocationId")).equals(session.invocationId())
                &&text(value,"platform").equals(session.platform())&&uuid(value.get("runNonce")).equals(session.runNonce())
                &&hash(value.get("productSha256")).equals(session.productSha256())&&hash(value.get("helperSha256")).equals(session.helperSha256())
                &&positive(value.get("sequence"))==command.sequence()&&uuid(value.get("operationId")).equals(command.operationId())
                &&text(value,"operation").equals(command.operation().name()),"GUI_FOREIGN_RECEIPT");
        long began=positive(value.get("startedEpochMs")),ended=positive(value.get("endedEpochMs"));
        require(ended>=began&&(!text(value,"outcome").equals("PASS")||ended<=command.deadlineEpochMs()),"GUI_RECEIPT_TIME");
        member(value.get("outcome"),"PASS","FAIL","BLOCKED","CANCELLED");require(text(value,"code").matches("[A-Z][A-Z0-9_]{0,79}"),"GUI_RECEIPT_CODE");
        var observed=object(value.get("observed"));
        require(Set.of("ready","tool","enabled","imported","nonce","length","status","submitted","copied","forwarded","edited","closeRequested","counts","labels","secretEntered","loginResult","httpProtocol","rulesConfigured","validationRejected","captureCompleted","assertionObserved","assertionCode","testUiConfirmed","nativeStart","loginTyped","initialStepsCleared","nativeStop","reviewReplaced","browserVersion","theme","size","width","inlineError","focused","noPopup","literalPath","controlsVisible","productSourceMatched").containsAll(observed.keySet()),"GUI_OBSERVED_FIELDS");
        for(var entry:observed.entrySet()) {
            String key=entry.getKey();JsonElement fact=entry.getValue();
            switch(key) {
                case "nonce" -> require(text(fact).matches("h[0-9a-f]{16}"),"GUI_OBSERVED_NONCE");
                case "tool" -> member(fact,"PROXY","REPEATER","EXTENSIONS");
                case "loginResult" -> member(fact,"HTTP_AUTHENTICATED");
                case "httpProtocol" -> member(fact,"BASIC","NTLM_V1","NTLM_V2");
                case "assertionCode" -> member(fact,"URL_REGEX_INVALID","RECOVERY_PAUSED","LOGIN_FAILED","ORDINARY_UNCHANGED");
                case "browserVersion" -> require(text(fact).matches("[0-9]{1,9}(?:\\.[0-9]{1,9}){2,3}"),"GUI_BROWSER_VERSION");
                case "theme" -> member(fact,"Light","Dark");
                case "size" -> member(fact,"compact","wide");
                case "width","length" -> positive(fact);
                case "status" -> require(positive(fact)>=100&&positive(fact)<=599,"GUI_OBSERVED_STATUS");
                case "counts" -> {var counts=object(fact);require(Set.of("password","text","button","table","tabs","other").containsAll(counts.keySet()),"GUI_OBSERVED_COUNTS");counts.entrySet().forEach(e->positive(e.getValue()));}
                case "labels" -> require(SAFE_LABELS.containsAll(strings(fact)),"GUI_OBSERVED_LABELS");
                default -> require(fact.isJsonPrimitive()&&fact.getAsJsonPrimitive().isBoolean(),"GUI_OBSERVED_BOOLEAN");
            }
        }
        return value;
    }
    /** Public proof retains fixed intent and input hashes, never file paths or secret values. */
    public static JsonObject retainedReceipt(JsonObject receipt,Session session,Command command) throws IOException {
        validateReceipt(receipt,session,command);validateArguments(command.operation(),command.arguments(),session.root());
        var intent=command.arguments();
        if(intent.has("path")) {
            var path=owned(session.root(),relative(intent.remove("path")));
            if(command.operation()!=Operation.CAPTURE_PROBE||text(intent,"phase").equals("RESET")) {
                require(Files.isRegularFile(path)&&Files.size(path)<=65536,"GUI_INPUT_FILE");
                intent.addProperty("inputSha256",sha256(path));
            }
        }
        if(intent.has("secret"))intent.add("secretRef",intent.remove("secret"));
        var retained=receipt.deepCopy();retained.addProperty("deadlineEpochMs",command.deadlineEpochMs());retained.add("intent",intent);
        return validateRetainedReceipt(retained,session);
    }
    public static JsonObject validateRetainedReceipt(JsonObject value,Session session) {
        object(value,"version","invocationId","platform","runNonce","productSha256","helperSha256","sequence","operationId",
                "operation","startedEpochMs","endedEpochMs","outcome","code","observed","deadlineEpochMs","intent");
        Operation operation;
        try{operation=Operation.valueOf(text(value,"operation"));}catch(IllegalArgumentException unknown){throw invalid("GUI_OPERATION");}
        var intent=object(value.get("intent"));validateIntent(operation,intent);
        long deadline=positive(value.get("deadlineEpochMs"));
        var command=new Command(positive(value.get("sequence")),uuid(value.get("operationId")),operation,deadline,new JsonObject());
        var original=value.deepCopy();original.remove("deadlineEpochMs");original.remove("intent");validateReceipt(original,session,command);
        return value;
    }
    private static void validateIntent(Operation operation,JsonObject intent) {
        switch(operation) {
            case READY,CLOSE -> object(intent);
            case IMPORT_JOURNEY -> {object(intent,"alias","inputSha256");alias(intent);hash(intent.get("inputSha256"));}
            case ENTER_SECRET -> {object(intent,"alias","secretRef");alias(intent);member(intent.get("secretRef"),"FORM_A","FORM_B","HTTP_A","HTTP_B");}
            case EDIT_RULES -> {object(intent,"inputSha256");hash(intent.get("inputSha256"));}
            case OPEN_TOOL -> {object(intent,"tool");member(intent.get("tool"),"PROXY","REPEATER","EXTENSIONS");}
            case COPY_TO_REPEATER,SEND_REPEATER,FORWARD_INTERCEPTED_REQUEST -> {object(intent,"nonce");nonce(intent);}
            case SET_REPEATER_NONCE -> {
                object(intent,"previousNonce","nonce");nonce(intent);
                require(text(intent,"previousNonce").matches("h[0-9a-f]{16}")&&!text(intent,"previousNonce").equals(text(intent,"nonce")),"GUI_PREVIOUS_NONCE");
            }
            case ASSERT_REPEATER_RESPONSE -> {object(intent,"nonce","status");nonce(intent);require(positive(intent.get("status"))>=100&&positive(intent.get("status"))<=599,"GUI_RESPONSE_STATUS");}
            case SET_REPEATER_REQUEST,EDIT_INTERCEPTED_REQUEST -> {object(intent,"nonce","inputSha256");nonce(intent);hash(intent.get("inputSha256"));}
            case TEST_LOGIN,TEST_BROWSER_LOGIN,FINISH_BROWSER_RECORDING -> {object(intent,"alias");alias(intent);}
            case RECORD_BROWSER_LOGIN -> {object(intent,"alias","secretRef");alias(intent);member(intent.get("secretRef"),"FORM_B");}
            case BROWSER_SETTINGS -> {object(intent,"alias","theme","size");alias(intent);member(intent.get("theme"),"Light","Dark");member(intent.get("size"),"compact","wide");}
            case SET_INTERCEPT,SET_PRODUCT_LOADED -> {object(intent,"enabled");require(intent.get("enabled").isJsonPrimitive()&&intent.getAsJsonPrimitive("enabled").isBoolean(),"GUI_BOOLEAN");}
            case CAPTURE_PROBE -> {
                String phase=member(intent.get("phase"),"RESET","EXPORT");
                if(phase.equals("RESET")){object(intent,"phase","inputSha256");hash(intent.get("inputSha256"));}else object(intent,"phase");
            }
            case ASSERT_UI -> {
                String code=member(intent.get("code"),"URL_REGEX_INVALID","RECOVERY_PAUSED","LOGIN_FAILED","ORDINARY_UNCHANGED");
                if(code.equals("ORDINARY_UNCHANGED")){object(intent,"alias","code","nonce");nonce(intent);}else object(intent,"alias","code");alias(intent);
            }
        }
    }
    private static String digest(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA256_UNAVAILABLE"); }
    }
    private static void validateArguments(Operation operation, JsonObject args, Path root) throws IOException {
        switch (operation) {
            case READY, CLOSE -> object(args);
            case IMPORT_JOURNEY -> { object(args,"path","alias"); inputPath(args,root); alias(args); }
            case ENTER_SECRET -> { object(args,"alias","secret"); alias(args); member(args.get("secret"),"FORM_A","FORM_B","HTTP_A","HTTP_B"); }
            case EDIT_RULES -> { object(args,"path"); inputPath(args,root); }
            case OPEN_TOOL -> { object(args,"tool"); member(args.get("tool"),"PROXY","REPEATER","EXTENSIONS"); }
            case COPY_TO_REPEATER, SEND_REPEATER, FORWARD_INTERCEPTED_REQUEST -> { object(args,"nonce"); nonce(args); }
            case SET_REPEATER_NONCE -> {object(args,"previousNonce","nonce");nonce(args);
                require(text(args,"previousNonce").matches("h[0-9a-f]{16}")&&!text(args,"previousNonce").equals(text(args,"nonce")),"GUI_PREVIOUS_NONCE");}
            case ASSERT_REPEATER_RESPONSE -> {object(args,"nonce","status");nonce(args);require(positive(args.get("status"))>=100&&positive(args.get("status"))<=599,"GUI_RESPONSE_STATUS");}
            case SET_REPEATER_REQUEST, EDIT_INTERCEPTED_REQUEST -> { object(args,"nonce","path"); nonce(args); inputPath(args,root); }
            case TEST_LOGIN,TEST_BROWSER_LOGIN,FINISH_BROWSER_RECORDING -> { object(args,"alias"); alias(args); }
            case RECORD_BROWSER_LOGIN -> {object(args,"alias","secret");alias(args);member(args.get("secret"),"FORM_B");}
            case BROWSER_SETTINGS -> {object(args,"alias","theme","size");alias(args);member(args.get("theme"),"Light","Dark");member(args.get("size"),"compact","wide");}
            case SET_INTERCEPT, SET_PRODUCT_LOADED -> {
                object(args,"enabled"); require(args.get("enabled").isJsonPrimitive() && args.get("enabled").getAsJsonPrimitive().isBoolean(),"GUI_BOOLEAN");
            }
            case CAPTURE_PROBE -> {
                object(args,"phase","path"); member(args.get("phase"),"RESET","EXPORT");
                owned(root,relative(args.get("path")));
            }
            case ASSERT_UI -> {
                String code=member(args.get("code"),"URL_REGEX_INVALID","RECOVERY_PAUSED","LOGIN_FAILED","ORDINARY_UNCHANGED");
                if(code.equals("ORDINARY_UNCHANGED")){object(args,"alias","code","nonce");nonce(args);}
                else object(args,"alias","code");
                alias(args);
            }
        }
        if (operation == Operation.READY || operation == Operation.CLOSE) require(args.isEmpty(),"GUI_ARGUMENTS");
    }
    private static void inputPath(JsonObject args, Path root) throws IOException {
        require(Files.isRegularFile(owned(root,relative(args.get("path")))), "GUI_INPUT_FILE");
    }
    private static void alias(JsonObject args) { require(text(args,"alias").matches("[a-z][a-z0-9_]{0,63}"),"GUI_ALIAS"); }
    private static void nonce(JsonObject args) { require(text(args,"nonce").matches("h[0-9a-f]{16}"),"GUI_NONCE"); }
}
