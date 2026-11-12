package lab.auth;

import com.google.gson.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class LabHostInputsTest {
    @TempDir Path directory;
    @Test void commandsRejectUnknownDuplicateMissingAndAcceptanceFiltersWithoutEchoingValues() {
        for(var arguments:List.of(new String[]{"host-test","--password","SECRET_SENTINEL"},
                new String[]{"host-guest","--plan","a","--plan","b"},
                new String[]{"host-guest","--plan","a"},new String[]{"host-test","--platform","linux"})) {
            var output=new ByteArrayOutputStream();
            assertEquals(2,LabMain.run(arguments,new PrintStream(output),new PrintStream(output)));
            assertFalse(output.toString(StandardCharsets.UTF_8).contains("SECRET_SENTINEL"));
        }
        assertEquals("host-guest",LabHostInputs.options(new String[]{"host-guest","--plan","a","--report-directory","b"}).command());
    }
    @Test void sharedParserRejectsDuplicateKeysBadUtf8DepthAndTrailingData() {
        for(byte[] bad:List.of("{\"a\":1,\"a\":2}".getBytes(StandardCharsets.UTF_8),new byte[]{(byte)0xc3,0x28},
                "{} {}".getBytes(StandardCharsets.UTF_8),("[".repeat(65)+"0"+"]".repeat(65)).getBytes(StandardCharsets.UTF_8)))
            assertThrows(IllegalArgumentException.class,()->LabJson.parse(bad));
        assertEquals(1,LabJson.parse("{\"a\":1}".getBytes(StandardCharsets.UTF_8)).getAsJsonObject().get("a").getAsInt());
        assertThrows(ScenarioCatalog.CatalogException.class,()->ScenarioCatalog.parseJson("{\"a\":1,\"a\":2}".getBytes(StandardCharsets.UTF_8)));
    }
    @Test void planVerifiesOwnedArtifactBytesAndAuditIdentity() throws Exception {
        Path path=fixture(directory,LabHostInputs.Mode.QUALIFICATION);
        var plan=LabHostInputs.plan(path); assertEquals(12,LabHostInputs.inventory(LabJson.read(plan.scenarios().path(),65536)).size());
        Files.writeString(plan.product().path(),"changed");
        assertThrows(IllegalArgumentException.class,()->LabHostInputs.plan(path));
    }
    @Test void acceptanceCannotDropAPlatformAndPlansRejectUnknownFieldsAndForeignAudit() throws Exception {
        Path path=fixture(directory,LabHostInputs.Mode.ACCEPTANCE); var original=LabJson.read(path,1_048_576);
        var changed=original.deepCopy(); var platforms=new JsonArray();platforms.add("linux");changed.add("platforms",platforms);
        replace(path,changed); assertThrows(IllegalArgumentException.class,()->LabHostInputs.plan(path));
        changed=original.deepCopy();changed.addProperty("password","SECRET_SENTINEL");replace(path,changed);
        assertThrows(IllegalArgumentException.class,()->LabHostInputs.plan(path));
        changed=original.deepCopy();changed.addProperty("sourceRevision","f".repeat(64));replace(path,changed);
        assertThrows(IllegalArgumentException.class,()->LabHostInputs.plan(path));
    }
    @Test void vmConfigurationRejectsRootAndPrerequisiteOverlapAndNeverReadsCredentials() throws Exception {
        var helpers=new HashMap<String,Path>();var config=new JsonObject();config.addProperty("version",1);
        for(String platform:LabHostInputs.PLATFORMS) {
            var helper=Files.writeString(directory.resolve(platform+".py"),"# fake helper, never executed");helpers.put(platform,helper);
            var vm=new JsonObject();vm.addProperty("helper",helper.toString());vm.addProperty("guestRoot",platform.equals("windows")?"C:/bpsh/host-tests":"/home/tester/host-tests");
            vm.addProperty("java",platform.equals("windows")?"C:/Program Files/BurpSuite/jre/bin/java.exe":"/opt/burp/jre/bin/java");
            vm.addProperty("labJava",platform.equals("windows")?"C:/bpsh/provision/jdk/bin/java.exe":"/usr/bin/java");
            vm.addProperty("burpJar",platform.equals("windows")?"C:/Program Files/BurpSuite/burp.jar":"/opt/burp/burp.jar");
            vm.addProperty("approvedPreferences",platform.equals("windows")?"C:/bpsh/setup/preferences.json":"/home/tester/setup/preferences.json");
            if(platform.equals("linux"))vm.addProperty("display",":0");config.add(platform,vm);
        }
        Path file=directory.resolve("vms.json");replace(file,config);var parsed=LabHostInputs.vmConfig(file,helpers);assertEquals(2,parsed.size());
        assertEquals("C:\\bpsh\\host-tests",parsed.get("windows").guestRoot());
        assertEquals("C:\\Program Files\\BurpSuite\\jre\\bin\\java.exe",parsed.get("windows").java());
        assertEquals("C:\\bpsh\\provision\\jdk\\bin\\java.exe",parsed.get("windows").labJava());
        config.getAsJsonObject("linux").addProperty("guestRoot","/");replace(file,config);
        assertThrows(IllegalArgumentException.class,()->LabHostInputs.vmConfig(file,helpers));
        config.getAsJsonObject("linux").addProperty("guestRoot","/opt/burp");replace(file,config);
        assertThrows(IllegalArgumentException.class,()->LabHostInputs.vmConfig(file,helpers));
    }
    @Test void boundedReadsAndRelativePathsRejectEscapes() throws Exception {
        Path file=Files.writeString(directory.resolve("large.json")," ".repeat(101));
        assertThrows(IllegalArgumentException.class,()->LabJson.read(file,100));
        for(String path:List.of("../escape","/absolute","a/../b","C:/other","a\\b","a//b"))
            assertThrows(IllegalArgumentException.class,()->LabJson.owned(directory,path));
    }
    static Path fixture(Path base,LabHostInputs.Mode mode) throws Exception {
        UUID invocation=UUID.randomUUID();Path capture=Files.createDirectories(base.resolve(invocation.toString()).resolve("capture"));
        var sources=Map.of("bapp/src/main/java/example.java","a".repeat(64));
        var audit=artifact(capture,"audit.json",LabJson.JSON.toJson(Map.of("boundaryHash","b".repeat(64),"head","c".repeat(40),"files",sources)),null);
        var product=artifact(capture,"product.jar","product fixture bytes",null);
        var helper=artifact(capture,"helper.jar","helper fixture bytes",null);
        // The fixture models the coordinator's explicit source-inventory input, not classpath discovery.
        Path workspace=Path.of(System.getProperty("user.dir")).toAbsolutePath();
        while(workspace!=null&&!Files.isRegularFile(workspace.resolve("test/authentication-lab/src/main/resources/host-scenarios.json")))workspace=workspace.getParent();
        assertNotNull(workspace,"Host scenario source inventory is required.");
        String inventory=Files.readString(workspace.resolve("test/authentication-lab/src/main/resources/host-scenarios.json"));
        var scenarios=artifact(capture,"scenarios.json",inventory,null);
        var runtime=List.of(artifact(capture,"lab.jar","lab fixture bytes","LAB"),artifact(capture,"exporter.jar","exporter fixture bytes","EXPORTER"));
        var plan=new LinkedHashMap<String,Object>();plan.put("version",1);plan.put("invocationId",invocation);plan.put("mode",mode);
        plan.put("platforms",LabHostInputs.PLATFORMS);plan.put("taskPath",mode==LabHostInputs.Mode.ACCEPTANCE?":authLabHostTest":":authLabHostQualify");
        plan.put("configurationHash","d".repeat(64));plan.put("catalogRevision","e".repeat(64));plan.put("sourceRevision","b".repeat(64));
        plan.put("head","c".repeat(40));plan.put("sourceHashes",sources);plan.put("audit",audit);plan.put("product",product);plan.put("helper",helper);
        plan.put("runtime",runtime);plan.put("scenarios",scenarios);plan.put("captureDirectory",capture.toString());
        Path file=capture.getParent().resolve("plan.json");LabJson.writeNew(file,plan);return file;
    }
    private static JsonObject artifact(Path root,String name,String text,String role) throws Exception {
        Path file=Files.writeString(root.resolve(name),text);return new LabHostInputs.Artifact(file,LabJson.sha256(file),Files.size(file),role).json(file.toString());
    }
    static void replace(Path path,JsonObject json) throws IOException {Files.writeString(path,LabJson.JSON.toJson(json));}
}
