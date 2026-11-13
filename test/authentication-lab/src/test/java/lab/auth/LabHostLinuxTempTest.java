package lab.auth;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.*;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class LabHostLinuxTempTest {
    @TempDir Path directory;

    @Test void shortPathContractAcceptsOnlyOnePrivateRandomLinuxTmpLeaf() {
        assertTrue(LabHostLinuxTemp.validPath("/tmp/bpsh-0123456789abc"));
        assertEquals(23,"/tmp/bpsh-0123456789abc".length());
        for(String invalid:List.of("/tmp/bpsh-0123456789ab","/tmp/bpsh-0123456789abcd","/tmp/bpsh-0123456789abC",
                "/tmp/bpsh-0123456789abc/child","/tmp/../tmp/bpsh-0123456789abc","/var/tmp/bpsh-0123456789abc",
                "/tmp/bpsh-0123456789abc\n","/tmp/bpsh-0123456789ab/","C:/tmp/bpsh-0123456789abc"))
            assertFalse(LabHostLinuxTemp.validPath(invalid),invalid);
        assertFalse(LabHostLinuxTemp.validPath(null));
    }

    @Test void ownerRejectsRelativeTraversalAndMissingNativeProcessIdentity() {
        var invocation=UUID.randomUUID();var nonce=UUID.randomUUID();
        assertDoesNotThrow(()->new LabHostLinuxTemp.Owner("/home/tester/owned-run",invocation,nonce,1,1000));
        for(String root:List.of("relative","/tmp/../foreign","/tmp/./foreign","/tmp/owned/"))
            assertThrows(IllegalArgumentException.class,()->new LabHostLinuxTemp.Owner(root,invocation,nonce,1,1000));
        assertThrows(IllegalArgumentException.class,()->new LabHostLinuxTemp.Owner("/tmp/owned",invocation,nonce,0,1000));
        assertThrows(IllegalArgumentException.class,()->new LabHostLinuxTemp.Owner("/tmp/owned",invocation,nonce,1,0));
    }

    private final class Fixture implements AutoCloseable {
        final UUID invocation=UUID.randomUUID(),nonce=UUID.randomUUID();
        final Path root,temporary;final byte[] descriptor;
        Fixture() throws Exception {
            root=Files.createDirectory(directory.resolve(invocation+"-"+nonce.toString().substring(0,8))).toRealPath();
            Files.setPosixFilePermissions(root,PosixFilePermissions.fromString("rwx------"));
            Files.createDirectory(root.resolve("report"));
            LabJson.writeNew(root.resolve("owner.json"),Map.of("version",1,"invocationId",invocation,"platform","linux","runNonce",nonce,"guestRoot",root.toString()));
            start(ProcessHandle.current().pid(),ProcessHandle.current().info().startInstant().orElseThrow().toEpochMilli());
            temporary=LabHostLinuxTemp.create(root,invocation,nonce);descriptor=Files.readAllBytes(root.resolve(LabHostLinuxTemp.DESCRIPTOR));
        }
        void start(long pid,long began) throws Exception {
            Files.writeString(root.resolve("report/started.json"),LabJson.JSON.toJson(Map.of("version",1,"invocationId",invocation,"runNonce",nonce,
                    "pid",pid,"startedEpochMs",began,"executable",ProcessHandle.current().info().command().orElseThrow())));
        }
        void restore() throws Exception {
            Files.write(root.resolve(LabHostLinuxTemp.DESCRIPTOR),descriptor);
            Files.setPosixFilePermissions(root.resolve(LabHostLinuxTemp.DESCRIPTOR),PosixFilePermissions.fromString("rw-------"));
            if(Files.isDirectory(temporary,LinkOption.NOFOLLOW_LINKS)) {
                Files.setPosixFilePermissions(temporary,PosixFilePermissions.fromString("rwx------"));
                Files.write(temporary.resolve("owner.json"),descriptor);
                Files.setPosixFilePermissions(temporary.resolve("owner.json"),PosixFilePermissions.fromString("rw-------"));
            }
            start(ProcessHandle.current().pid(),ProcessHandle.current().info().startInstant().orElseThrow().toEpochMilli());
        }
        @Override public void close() throws Exception {
            if(Files.exists(root)){restore();LabHostLinuxTemp.cleanup(root,invocation,nonce);}
        }
    }

    @Test @EnabledOnOs(OS.LINUX) void guestAllocationIsPrivateBoundedExclusiveAndCleanupIsIdempotent() throws Exception {
        try(var fixture=new Fixture()) {
            assertTrue(LabHostLinuxTemp.validPath(fixture.temporary.toString()));
            assertEquals(PosixFilePermissions.fromString("rwx------"),Files.getPosixFilePermissions(fixture.temporary));
            assertEquals(PosixFilePermissions.fromString("rw-------"),Files.getPosixFilePermissions(fixture.root.resolve(LabHostLinuxTemp.DESCRIPTOR)));
            assertEquals(PosixFilePermissions.fromString("rw-------"),Files.getPosixFilePermissions(fixture.temporary.resolve("owner.json")));
            assertThrows(IOException.class,()->LabHostLinuxTemp.create(fixture.root,fixture.invocation,fixture.nonce));
            Files.createDirectories(fixture.temporary.resolve("nested/content"));Files.writeString(fixture.temporary.resolve("nested/content/owned"),"OWNED");
            LabHostLinuxTemp.cleanup(fixture.root,fixture.invocation,fixture.nonce);
            assertFalse(Files.exists(fixture.temporary));assertTrue(Files.isDirectory(fixture.root));
            assertDoesNotThrow(()->LabHostLinuxTemp.cleanup(fixture.root,fixture.invocation,fixture.nonce));
        }
    }

    @Test @EnabledOnOs(OS.LINUX) void changedDescriptorOrExternalMarkerNeverDeletesEitherRoot() throws Exception {
        try(var fixture=new Fixture()) {
            var original=LabJson.read(fixture.root.resolve(LabHostLinuxTemp.DESCRIPTOR),4096);
            for(String field:List.of("version","invocationId","runNonce","guestRoot","guestPid","guestStartedEpochMs","uid","path","allocationId","unknown")) {
                var changed=original.deepCopy();
                switch(field) {
                    case "version" -> changed.addProperty(field,true);
                    case "guestPid","guestStartedEpochMs","uid" -> changed.addProperty(field,changed.get(field).getAsLong()+1);
                    case "path" -> changed.addProperty(field,"/tmp/foreign");
                    case "guestRoot" -> changed.addProperty(field,"/tmp/foreign-root");
                    default -> changed.addProperty(field,UUID.randomUUID().toString());
                }
                Files.writeString(fixture.root.resolve(LabHostLinuxTemp.DESCRIPTOR),LabJson.JSON.toJson(changed));
                assertThrows(IOException.class,()->LabHostLinuxTemp.cleanup(fixture.root,fixture.invocation,fixture.nonce),field);
                assertTrue(Files.isDirectory(fixture.root));assertTrue(Files.isDirectory(fixture.temporary));fixture.restore();
            }
            Files.writeString(fixture.temporary.resolve("owner.json"),"{}");
            assertThrows(IOException.class,()->LabHostLinuxTemp.cleanup(fixture.root,fixture.invocation,fixture.nonce));
            assertTrue(Files.exists(fixture.temporary));
        }
    }

    @Test @EnabledOnOs(OS.LINUX) void symlinkAndHardlinkTreesRefuseCleanupWithoutTouchingTheirTargets() throws Exception {
        try(var fixture=new Fixture()) {
            Path sentinel=Files.writeString(directory.resolve("unrelated"),"PRIVATE_SENTINEL");Path link=fixture.temporary.resolve("link");
            Files.createSymbolicLink(link,sentinel);
            try{assertThrows(IOException.class,()->LabHostLinuxTemp.cleanup(fixture.root,fixture.invocation,fixture.nonce));}
            finally{Files.delete(link);}
            Files.createLink(link,sentinel);
            try{assertThrows(IOException.class,()->LabHostLinuxTemp.cleanup(fixture.root,fixture.invocation,fixture.nonce));}
            finally{Files.delete(link);}
            assertEquals("PRIVATE_SENTINEL",Files.readString(sentinel));assertTrue(Files.exists(fixture.temporary));
        }
    }

    @Test @EnabledOnOs(OS.LINUX) void missingMarkerAndNonprivatePermissionsRemainIncompleteAndRecoverAfterRepair() throws Exception {
        try(var fixture=new Fixture()) {
            Files.delete(fixture.temporary.resolve("owner.json"));
            assertThrows(IOException.class,()->LabHostLinuxTemp.cleanup(fixture.root,fixture.invocation,fixture.nonce));fixture.restore();
            Files.setPosixFilePermissions(fixture.temporary,PosixFilePermissions.fromString("rwxr-xr-x"));
            assertThrows(IOException.class,()->LabHostLinuxTemp.cleanup(fixture.root,fixture.invocation,fixture.nonce));fixture.restore();
            Files.setPosixFilePermissions(fixture.root.resolve(LabHostLinuxTemp.DESCRIPTOR),PosixFilePermissions.fromString("rw-r--r--"));
            assertThrows(IOException.class,()->LabHostLinuxTemp.cleanup(fixture.root,fixture.invocation,fixture.nonce));fixture.restore();
            Files.writeString(fixture.root.resolve(LabHostLinuxTemp.DESCRIPTOR),"x".repeat(4097));
            assertThrows(IOException.class,()->LabHostLinuxTemp.cleanup(fixture.root,fixture.invocation,fixture.nonce));
            fixture.restore();
            Files.writeString(fixture.root.resolve(LabHostLinuxTemp.DESCRIPTOR),new String(fixture.descriptor,java.nio.charset.StandardCharsets.UTF_8).replace("\"version\":1","\"version\":1,\"version\":1"));
            assertThrows(IOException.class,()->LabHostLinuxTemp.cleanup(fixture.root,fixture.invocation,fixture.nonce));
            assertTrue(Files.isDirectory(fixture.temporary));
        }
    }

    @Test @EnabledOnOs(OS.LINUX) void descriptorAndTemporaryRootLinksAreNeverFollowed() throws Exception {
        try(var fixture=new Fixture()) {
            Path descriptor=fixture.root.resolve(LabHostLinuxTemp.DESCRIPTOR),saved=fixture.root.resolve("descriptor-target");
            Files.move(descriptor,saved);Files.createSymbolicLink(descriptor,saved);
            try{assertThrows(IOException.class,()->LabHostLinuxTemp.cleanup(fixture.root,fixture.invocation,fixture.nonce));}
            finally{Files.delete(descriptor);Files.move(saved,descriptor);}
            Path moved=fixture.temporary.resolveSibling(fixture.temporary.getFileName()+"-target");
            Files.move(fixture.temporary,moved);Files.createSymbolicLink(fixture.temporary,moved);
            try{assertThrows(IOException.class,()->LabHostLinuxTemp.cleanup(fixture.root,fixture.invocation,fixture.nonce));assertTrue(Files.exists(moved.resolve("owner.json")));}
            finally{Files.delete(fixture.temporary);Files.move(moved,fixture.temporary);}
        }
    }

    @Test @EnabledOnOs(OS.LINUX) void allocatorCollisionNeverReusesOrDeletesAnExistingTemporaryDirectory() throws Exception {
        try(var fixture=new Fixture()) {
            LabHostLinuxTemp.cleanup(fixture.root,fixture.invocation,fixture.nonce);Files.delete(fixture.root.resolve(LabHostLinuxTemp.DESCRIPTOR));
            String token=UUID.randomUUID().toString().replace("-","").substring(0,13);Path foreign=Files.createDirectory(Path.of("/tmp/bpsh-"+token));
            Path sentinel=Files.writeString(foreign.resolve("unrelated"),"PRIVATE_SENTINEL");
            try {
                var process=ProcessHandle.current();var owner=new LabHostLinuxTemp.Owner(fixture.root.toString(),fixture.invocation,fixture.nonce,
                        process.pid(),process.info().startInstant().orElseThrow().toEpochMilli());
                String allocation="import secrets\nsecrets.token_hex=lambda length:'"+token+"'\n"+LabHostLinuxTemp.allocationScript(owner);
                assertNotEquals(0,execute(allocation,true));assertEquals("PRIVATE_SENTINEL",Files.readString(sentinel));
                assertTrue(Files.exists(fixture.root.resolve(LabHostLinuxTemp.DESCRIPTOR)));
                assertThrows(IOException.class,()->LabHostLinuxTemp.cleanup(fixture.root,fixture.invocation,fixture.nonce));
            }finally{Files.delete(sentinel);Files.delete(foreign);}
        }
    }

    @Test @EnabledOnOs(OS.LINUX) void ownedBurpPidMustHaveExitedEvenIfItsStartIdentityIsDifferent() throws Exception {
        try(var fixture=new Fixture()) {
            Path burp=fixture.root.resolve("burp-owner.json");
            LabJson.writeNew(burp,Map.of("pid",ProcessHandle.current().pid(),"nonce",fixture.nonce,"executable","java","startedEpochMs",1));
            try{assertThrows(IOException.class,()->LabHostLinuxTemp.cleanup(fixture.root,fixture.invocation,fixture.nonce));assertTrue(Files.exists(fixture.temporary));}
            finally{Files.delete(burp);}
        }
    }

    private static void stop(Process process) throws Exception {
        process.destroy();if(!process.waitFor(2,TimeUnit.SECONDS)){process.destroyForcibly();assertTrue(process.waitFor(5,TimeUnit.SECONDS));}
    }
    @Test @EnabledOnOs(OS.LINUX) void aLiveReadOnlyMonitorMentioningPrivatePathsDoesNotOwnTheirResources() throws Exception {
        try(var fixture=new Fixture()) {
            String script="import time; paths="+LabJson.JSON.toJson(List.of(fixture.root.toString(),fixture.temporary.toString()))+"; time.sleep(30)";
            var monitor=new ProcessBuilder("/usr/bin/python3","-c",script).redirectError(ProcessBuilder.Redirect.DISCARD).start();
            try {
                assertTrue(monitor.isAlive());LabHostLinuxTemp.cleanup(fixture.root,fixture.invocation,fixture.nonce);
                assertFalse(Files.exists(fixture.temporary));assertTrue(monitor.isAlive());
            }finally{stop(monitor);}
        }
    }

    @Test @EnabledOnOs(OS.LINUX) void actualPrivateExecutablesNonceWorkersAndRecognizedTempArgumentsBlockCleanup() throws Exception {
        try(var fixture=new Fixture()) {
            Path executable=Files.copy(Path.of("/usr/bin/sleep"),fixture.root.resolve("owned-worker"));
            Files.setPosixFilePermissions(executable,PosixFilePermissions.fromString("rwx------"));
            var commands=List.of(List.of(executable.toString(),"30"),
                    List.of("/usr/bin/python3","-c","import time; time.sleep(30)","-Dlab.host.burpNonce="+fixture.nonce),
                    List.of("/usr/bin/python3","-c","import time; time.sleep(30)","-Djava.io.tmpdir="+fixture.temporary),
                    List.of("/usr/bin/python3","-c","import time; time.sleep(30)","--user-data-dir="+fixture.temporary.resolve("profile")));
            for(var command:commands) {
                var worker=new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.DISCARD).start();
                try {
                    assertTrue(worker.isAlive());assertThrows(IOException.class,()->LabHostLinuxTemp.cleanup(fixture.root,fixture.invocation,fixture.nonce));
                    assertTrue(Files.exists(fixture.temporary));assertTrue(worker.isAlive());
                }finally{stop(worker);}
            }
        }
    }

    private static int execute(String script) throws Exception {
        return execute(script,false);
    }
    private static int execute(String script,boolean python) throws Exception {
        var process=new ProcessBuilder(python?"/usr/bin/python3":"/bin/bash","-c",script).redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        try{assertTrue(process.waitFor(15,TimeUnit.SECONDS));return process.exitValue();}finally{if(process.isAlive())process.destroyForcibly();}
    }
    private static void exitedOwner(Fixture fixture) throws Exception {
        var descriptor=LabJson.read(fixture.root.resolve(LabHostLinuxTemp.DESCRIPTOR),4096);
        descriptor.addProperty("guestPid",99999999);descriptor.addProperty("guestStartedEpochMs",1000);
        Files.writeString(fixture.root.resolve(LabHostLinuxTemp.DESCRIPTOR),LabJson.JSON.toJson(descriptor));
        Files.writeString(fixture.temporary.resolve("owner.json"),LabJson.JSON.toJson(descriptor));fixture.start(99999999,1000);
    }
    private LabHostInputs.Vm vm(Fixture fixture) {return new LabHostInputs.Vm("linux",directory.resolve("helper"),fixture.root.getParent().toString(),"/java","/java","/burp","/prefs",":0");}

    @Test @EnabledOnOs(OS.LINUX) void coordinatorRecoversAnInterruptedExitedRunAndRemovesTempBeforeMainRoot() throws Exception {
        try(var fixture=new Fixture()) {
            exitedOwner(fixture);Files.writeString(fixture.temporary.resolve("interrupted"),"OWNED");
            Path sentinel=Files.writeString(directory.resolve("unrelated"),"PRIVATE_SENTINEL");
            assertEquals(0,execute(LabHostCoordinator.ownedRootCleanupScript(vm(fixture),fixture.root.toString(),fixture.invocation,fixture.nonce.toString(),99999999,1000)));
            assertFalse(Files.exists(fixture.temporary));assertFalse(Files.exists(fixture.root));assertEquals("PRIVATE_SENTINEL",Files.readString(sentinel));
        }
    }

    @Test @EnabledOnOs(OS.LINUX) void coordinatorPreservesMainRootWhenTemporaryOwnershipCannotBeProven() throws Exception {
        try(var fixture=new Fixture()) {
            exitedOwner(fixture);Files.writeString(fixture.temporary.resolve("owner.json"),"{}");
            assertNotEquals(0,execute(LabHostCoordinator.ownedRootCleanupScript(vm(fixture),fixture.root.toString(),fixture.invocation,fixture.nonce.toString(),99999999,1000)));
            assertTrue(Files.isDirectory(fixture.root));assertTrue(Files.isDirectory(fixture.temporary));
        }
    }

    @Test @EnabledOnOs(OS.LINUX) void recoveryRefusesALiveOrReusedGuestPidAndAMissingDescriptorAfterBurpStarted() throws Exception {
        try(var fixture=new Fixture()) {
            var process=ProcessHandle.current();var descriptor=LabJson.read(fixture.root.resolve(LabHostLinuxTemp.DESCRIPTOR),4096);
            descriptor.addProperty("guestStartedEpochMs",1);Files.writeString(fixture.root.resolve(LabHostLinuxTemp.DESCRIPTOR),LabJson.JSON.toJson(descriptor));
            Files.writeString(fixture.temporary.resolve("owner.json"),LabJson.JSON.toJson(descriptor));fixture.start(process.pid(),1);
            String action=LabHostLinuxTemp.pythonFunctions()+"\ncleanup_temp("+LabJson.JSON.toJson(fixture.root.toString())+","+
                    LabJson.JSON.toJson(fixture.invocation.toString())+","+LabJson.JSON.toJson(fixture.nonce.toString())+","+process.pid()+",1,True)\n";
            assertNotEquals(0,execute(action,true));assertTrue(Files.exists(fixture.temporary));fixture.restore();
            exitedOwner(fixture);Files.delete(fixture.root.resolve(LabHostLinuxTemp.DESCRIPTOR));
            LabJson.writeNew(fixture.root.resolve("burp-owner.json"),Map.of("pid",99999998,"nonce",fixture.nonce,"executable","java","startedEpochMs",1000));
            assertNotEquals(0,execute(LabHostCoordinator.ownedRootCleanupScript(vm(fixture),fixture.root.toString(),fixture.invocation,fixture.nonce.toString(),99999999,1000)));
            assertTrue(Files.exists(fixture.root));assertTrue(Files.exists(fixture.temporary));
        }
    }
}
