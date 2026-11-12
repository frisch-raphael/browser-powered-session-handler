package lab.auth;

import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

class LabHostArtifactCacheTest {
    @TempDir Path directory;
    private LabHostInputs.Vm vm(String platform) {
        return new LabHostInputs.Vm(platform,directory.resolve("helper.py"),platform.equals("windows")?"C:\\bpsh\\host-tests":"/home/tester/bpsh/host-tests",
                "java","lab-java","burp.jar","prefs",platform.equals("linux")?":0":null);
    }
    private LabHostInputs.Artifact artifact() throws Exception {
        Path path=directory.resolve("captured.jar");Files.writeString(path,"current captured bytes");
        return new LabHostInputs.Artifact(path,LabJson.sha256(path),Files.size(path),null);
    }
    @ParameterizedTest @ValueSource(strings={"windows","linux"})
    void aVerifiedCacheHitSkipsUploadAndAMissUploadsBeforeRechecking(String platform) throws Exception {
        var artifact=artifact();var replies=new ArrayDeque<>(List.of(false,true));var operations=new ArrayList<String>();
        var transport=new LabHostVmTransport((args,budget)->{
            operations.add(args.get(2));
            if(args.get(2).equals("get"))Files.writeString(Path.of(args.getLast()),"{\"reused\":"+replies.removeFirst()+"}");
        });
        var vm=vm(platform);String root=LabHostVmTransport.joinGuest(vm.guestRoot(),"owned-run",platform);
        String destination=LabHostVmTransport.joinGuest(root,"assets/"+artifact.sha256()+".jar",platform);
        var cache=new LabHostArtifactCache(transport);
        cache.place(vm,artifact,root,destination,directory,"product.jar",Duration.ofSeconds(30));
        assertEquals(List.of("run","get","put","run","get"),operations);assertTrue(replies.isEmpty());
        operations.clear();replies.add(true);
        cache.place(vm,artifact,root,destination,directory,"product.jar",Duration.ofSeconds(30));
        assertEquals(List.of("run","get"),operations);
    }
    @Test void changedCaptureIsRejectedBeforeAnyGuestMutation() throws Exception {
        var artifact=artifact();Files.writeString(artifact.path(),"changed captured bytes");var calls=new ArrayList<String>();
        var cache=new LabHostArtifactCache(new LabHostVmTransport((args,budget)->calls.add(args.get(2))));
        assertThrows(IllegalArgumentException.class,()->cache.place(vm("linux"),artifact,"/owned","/owned/assets/file.jar",directory,"product.jar",Duration.ofSeconds(30)));
        assertTrue(calls.isEmpty());
    }
    @Test void failedPostUploadVerificationAndUnboundedMetadataCannotCountAsDeployment() throws Exception {
        var artifact=artifact();var transport=new LabHostVmTransport((args,budget)->{
            if(args.get(2).equals("get"))Files.writeString(Path.of(args.getLast()),"{\"reused\":false}");
        });
        var failed=assertThrows(LabHostVmTransport.Failure.class,()->new LabHostArtifactCache(transport).place(vm("linux"),artifact,
                "/home/tester/bpsh/host-tests/run","/home/tester/bpsh/host-tests/run/assets/file.jar",directory,"large-runtime.jar",Duration.ofSeconds(30)));
        assertEquals("HOST_CACHE_VERIFICATION",failed.code());
        var invalid=new LabHostVmTransport((args,budget)->{
            if(args.get(2).equals("get"))Files.writeString(Path.of(args.getLast()),"{\"reused\":true,\"password\":\"PRIVATE_SENTINEL\"}");
        });
        assertThrows(IllegalArgumentException.class,()->new LabHostArtifactCache(invalid).place(vm("linux"),artifact,
                "/home/tester/bpsh/host-tests/run","/home/tester/bpsh/host-tests/run/assets/file.jar",directory,"product.jar",Duration.ofSeconds(30)));
    }
}
