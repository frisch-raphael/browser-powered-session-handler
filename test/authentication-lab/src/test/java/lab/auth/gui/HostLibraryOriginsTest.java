package lab.auth.gui;

import com.google.gson.Gson;
import java.io.*;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.jar.*;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class HostLibraryOriginsTest {
    @TempDir Path directory;

    private record Snapshots(Instrumentation instrumentation, AtomicInteger loadedCalls, AtomicInteger initiatedCalls) {}

    private Snapshots snapshots(Class<?>[] loaded, Function<ClassLoader, Class<?>[]> initiated) {
        var loadedCalls = new AtomicInteger(); var initiatedCalls = new AtomicInteger();
        var api = (Instrumentation) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{Instrumentation.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "getAllLoadedClasses" -> { loadedCalls.incrementAndGet(); yield loaded; }
                    case "getInitiatedClasses" -> { initiatedCalls.incrementAndGet(); yield initiated.apply((ClassLoader) args[0]); }
                    default -> throw new AssertionError("No other instrumentation operation is permitted");
                });
        return new Snapshots(api, loadedCalls, initiatedCalls);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> row(Map<String, Object> result, String scope, String type) {
        return ((List<Map<String, Object>>) result.get(scope)).stream().filter(r -> type.equals(r.get("class"))).findFirst().orElseThrow();
    }

    private Path source(Class<?> type) throws Exception { return Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()); }

    @Test void duplicateDefinitionsAreDistinguishedAndUnknownNamesAndPathsAreNeverReturned() throws Exception {
        Path original = source(Gson.class), copied = directory.resolve("PRIVATE_PRODUCT_PATH.jar");
        Files.copy(original, copied);
        try (var loader = new URLClassLoader(new URL[]{copied.toUri().toURL()}, null)) {
            Class<?> duplicate = loader.loadClass("com.google.gson.Gson");
            assertNotSame(Gson.class, duplicate);
            var calls = snapshots(new Class<?>[]{Gson.class, duplicate, Gson.class, HostLibraryOriginsTest.class, String.class},
                    unused -> { throw new AssertionError("No product Playwright was observed"); });
            var result = new HostLibraryOrigins(calls.instrumentation(), Map.of(
                    HostLibraryOrigins.Origin.HOST, original, HostLibraryOrigins.Origin.PRODUCT, copied)).capture();
            assertEquals(true, result.get("available"));
            assertEquals(2, row(result, "loaded", "com.google.gson.Gson").get("definitions"));
            assertEquals(Map.of("HOST", 1, "PRODUCT", 1), row(result, "loaded", "com.google.gson.Gson").get("origins"));
            assertEquals("NOT_OBSERVED", result.get("productPlaywrightLoader"));
            assertEquals(1, calls.loadedCalls().get()); assertEquals(0, calls.initiatedCalls().get());
            assertFalse(result.toString().contains("PRIVATE_"));
            assertFalse(result.toString().contains("HostLibraryOriginsTest"));
            assertFalse(result.toString().contains(original.toString()));
            assertFalse(result.toString().contains(directory.toString()));
        }
    }

    @Test void absentClassesAreNotLoadedToImproveTheSnapshotAndUnknownSourcesStayOther() throws Exception {
        var empty = snapshots(new Class<?>[0], unused -> { throw new AssertionError("Absent Playwright cannot select a loader"); });
        var result = new HostLibraryOrigins(empty.instrumentation(), Map.of()).capture();
        assertEquals(true, result.get("available"));
        assertEquals(0, row(result, "loaded", "com.google.gson.Gson").get("definitions"), "Available test class must not be added to a snapshot that did not contain it");
        assertEquals(Map.of(), row(result, "loaded", "com.microsoft.playwright.Playwright").get("origins"));
        assertEquals("NOT_OBSERVED", result.get("productPlaywrightLoader"));
        assertEquals(1, empty.loadedCalls().get()); assertEquals(0, empty.initiatedCalls().get());
        var unknown = snapshots(new Class<?>[]{Gson.class}, unused -> null);
        var other = new HostLibraryOrigins(unknown.instrumentation(), Map.of()).capture();
        assertEquals(Map.of("OTHER", 1), row(other, "loaded", "com.google.gson.Gson").get("origins"));
        var conflicting = new HostLibraryOrigins(unknown.instrumentation(), Map.of(
                HostLibraryOrigins.Origin.HOST, source(Gson.class), HostLibraryOrigins.Origin.HELPER, source(Gson.class))).capture();
        assertEquals(Map.of("UNAVAILABLE", 1), row(conflicting, "loaded", "com.google.gson.Gson").get("origins"));
    }

    @Test void onlyAnUnambiguousProductPlaywrightLoaderCanRevealInitiatedGsonOriginWithoutInitialization() throws Exception {
        String property = "lab.auth.origins.initialized." + UUID.randomUUID();
        Path jar = publicLibraryFixture(property);
        try (var loader = new URLClassLoader(new URL[]{jar.toUri().toURL()}, null)) {
            Class<?> playwright = loader.loadClass("com.microsoft.playwright.Playwright");
            Class<?> jna = loader.loadClass("com.sun.jna.Native");
            assertNull(System.getProperty(property));
            var calls = snapshots(new Class<?>[]{playwright, jna, Gson.class}, expected -> {
                assertSame(loader, expected); return new Class<?>[]{Gson.class, jna, HostLibraryOriginsTest.class};
            });
            var result = new HostLibraryOrigins(calls.instrumentation(), Map.of(
                    HostLibraryOrigins.Origin.PRODUCT, jar, HostLibraryOrigins.Origin.HELPER, source(Gson.class))).capture();
            assertEquals("IDENTIFIED", result.get("productPlaywrightLoader"));
            assertEquals(Map.of("HELPER", 1), row(result, "initiated", "com.google.gson.Gson").get("origins"));
            assertEquals(Map.of("PRODUCT", 1), row(result, "initiated", "com.sun.jna.Native").get("origins"));
            assertEquals(1, calls.loadedCalls().get()); assertEquals(1, calls.initiatedCalls().get());
            assertNull(System.getProperty(property), "Public class metadata must not run library initializers");
            assertFalse(result.toString().contains("PRIVATE_")); assertFalse(result.toString().contains(directory.toString()));
        } finally { System.clearProperty(property); }
    }

    @Test void duplicateProductPlaywrightLoadersAndUnavailableInitiationDoNotGuess() throws Exception {
        Path jar = publicLibraryFixture("lab.auth.origins.unused." + UUID.randomUUID());
        try (var a = new URLClassLoader(new URL[]{jar.toUri().toURL()}, null); var b = new URLClassLoader(new URL[]{jar.toUri().toURL()}, null)) {
            Class<?> first = a.loadClass("com.microsoft.playwright.Playwright"), second = b.loadClass("com.microsoft.playwright.Playwright");
            var foreign = snapshots(new Class<?>[]{first}, unused -> { throw new AssertionError("A host Playwright cannot identify the product loader"); });
            var foreignResult = new HostLibraryOrigins(foreign.instrumentation(), Map.of(HostLibraryOrigins.Origin.HOST, jar)).capture();
            assertEquals("NOT_OBSERVED", foreignResult.get("productPlaywrightLoader")); assertEquals(0, foreign.initiatedCalls().get());
            var ambiguous = snapshots(new Class<?>[]{first, second}, unused -> { throw new AssertionError("Do not choose between duplicate product loaders"); });
            var result = new HostLibraryOrigins(ambiguous.instrumentation(), Map.of(HostLibraryOrigins.Origin.PRODUCT, jar)).capture();
            assertEquals("AMBIGUOUS", result.get("productPlaywrightLoader")); assertEquals(List.of(), result.get("initiated"));
            assertEquals(0, ambiguous.initiatedCalls().get());
            var unavailable = snapshots(new Class<?>[]{first}, unused -> { throw new SecurityException("PRIVATE_PATH PRIVATE_SECRET"); });
            var missing = new HostLibraryOrigins(unavailable.instrumentation(), Map.of(HostLibraryOrigins.Origin.PRODUCT, jar)).capture();
            assertEquals(true, missing.get("available")); assertEquals("UNAVAILABLE", missing.get("productPlaywrightLoader"));
            assertFalse(missing.toString().contains("PRIVATE_"));
        }
    }

    @Test void absentInstrumentationEdtAndOversizedSnapshotsRemainOptionalAndDoNotQueryFurther() {
        assertEquals(false, new HostLibraryOrigins(null, Map.of()).capture().get("available"));
        var calls = snapshots(new Class<?>[]{Gson.class}, unused -> null);
        var collector = new HostLibraryOrigins(calls.instrumentation(), Map.of());
        HostGuiSelectors.edt(() -> { assertEquals(false, collector.capture().get("available")); return true; });
        assertEquals(0, calls.loadedCalls().get());
        var oversized = snapshots(new Class<?>[200_001], unused -> { throw new AssertionError("No second query after bounds fail"); });
        assertEquals(false, new HostLibraryOrigins(oversized.instrumentation(), Map.of()).capture().get("available"));
        assertEquals(1, oversized.loadedCalls().get()); assertEquals(0, oversized.initiatedCalls().get());
        var failing = (Instrumentation) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{Instrumentation.class},
                (proxy, method, args) -> { throw new SecurityException("PRIVATE_PATH PRIVATE_SECRET"); });
        var failed = new HostLibraryOrigins(failing, Map.of()).capture();
        assertEquals(false, failed.get("available")); assertFalse(failed.toString().contains("PRIVATE_"));
    }

    @Test void loadedProductEntryNeedsTheSelectedSourceAndCannotBorrowAForeignDefinition() throws Exception {
        String property="lab.auth.origins.entry."+UUID.randomUUID();Path jar=publicLibraryFixture(property),foreignJar=directory.resolve("FOREIGN_PRODUCT.jar");Files.copy(jar,foreignJar);
        try(var first=new URLClassLoader(new URL[]{jar.toUri().toURL()},null);var reloaded=new URLClassLoader(new URL[]{jar.toUri().toURL()},null);var foreign=new URLClassLoader(new URL[]{foreignJar.toUri().toURL()},null)) {
            Class<?> a=first.loadClass("bpsh.Extension"),b=reloaded.loadClass("bpsh.Extension"),c=foreign.loadClass("bpsh.Extension");
            var expected=Map.of(HostLibraryOrigins.Origin.PRODUCT,jar);String sha=lab.auth.LabJson.sha256(jar);Path ownedTemporary=Files.createDirectory(directory.resolve("entry-owned-temp"));
            assertTrue(new HostLibraryOrigins(snapshots(new Class<?>[]{a,b},unused->null).instrumentation(),expected).productEntryArtifactMatches(ownedTemporary,sha));
            assertFalse(new HostLibraryOrigins(snapshots(new Class<?>[]{a,c},unused->null).instrumentation(),expected).productEntryArtifactMatches(ownedTemporary,sha));
            assertFalse(new HostLibraryOrigins(snapshots(new Class<?>[]{c},unused->null).instrumentation(),expected).productEntryArtifactMatches(ownedTemporary,sha));
            assertFalse(new HostLibraryOrigins(snapshots(new Class<?>[0],unused->null).instrumentation(),expected).productEntryArtifactMatches(ownedTemporary,sha));
            assertFalse(new HostLibraryOrigins(null,expected).productEntryArtifactMatches(ownedTemporary,sha));
            assertNull(System.getProperty(property),"Observing the entry's source must not initialize it.");
        }finally{System.clearProperty(property);}
    }
    @Test void loadedEntrySourceAlsoRequiresTheCapturedFileHash() throws Exception {
        Path jar=publicLibraryFixture("lab.auth.origins.hash."+UUID.randomUUID()),assets=Files.createDirectory(directory.resolve("assets"));
        String sha=lab.auth.LabJson.sha256(jar);Path exact=assets.resolve(sha+".jar"),wrong=assets.resolve("c".repeat(64)+".jar");Files.copy(jar,exact);Files.copy(jar,wrong);
        try(var a=new URLClassLoader(new URL[]{exact.toUri().toURL()},null);var b=new URLClassLoader(new URL[]{wrong.toUri().toURL()},null)) {
            var session=new lab.auth.LabHostGuiProtocol.Session(UUID.randomUUID(),"windows",UUID.randomUUID(),sha,"b".repeat(64),directory);
            HostGuiDiagnostics.configureLibraryOrigins(snapshots(new Class<?>[]{a.loadClass("bpsh.Extension")},unused->null).instrumentation(),session);
            assertTrue(HostGuiDiagnostics.productSourceMatched());
            var mismatched=new lab.auth.LabHostGuiProtocol.Session(session.invocationId(),"windows",session.runNonce(),"c".repeat(64),session.helperSha256(),directory);
            HostGuiDiagnostics.configureLibraryOrigins(snapshots(new Class<?>[]{b.loadClass("bpsh.Extension")},unused->null).instrumentation(),mismatched);
            assertFalse(HostGuiDiagnostics.productSourceMatched(),"A matching location does not prove matching product bytes.");
        }
    }
    @Test void entrySourceDiagnosisSeparatesMissingDomainsFromForeignFilesWithoutReturningPaths() throws Exception {
        Path jar=publicLibraryFixture("lab.auth.origins.diagnosis."+UUID.randomUUID());
        try(var loader=new URLClassLoader(new URL[]{jar.toUri().toURL()},null);var archive=new JarFile(jar.toFile())) {
            Class<?> sourced=loader.loadClass("bpsh.Extension");byte[] bytes;
            try(var input=archive.getInputStream(archive.getJarEntry("bpsh/Extension.class"))){bytes=input.readAllBytes();}
            class MemoryLoader extends ClassLoader {MemoryLoader(){super(null);}Class<?> entry(){return defineClass("bpsh.Extension",bytes,0,bytes.length);}}
            Class<?> memory=new MemoryLoader().entry();
            var observer=new HostLibraryOrigins(snapshots(new Class<?>[]{sourced,memory},unused->null).instrumentation(),Map.of(HostLibraryOrigins.Origin.PRODUCT,jar));
            var result=observer.productEntrySources();
            assertTrue(result.has("available"),"The diagnostic must retain availability even when no code source is exposed.");
            assertTrue(result.get("available").getAsBoolean());assertEquals(2,result.get("definitions").getAsInt());
            assertEquals(1,result.get("missingSources").getAsInt());assertEquals(1,result.getAsJsonObject("origins").get("PRODUCT").getAsInt());
            assertEquals(1,result.getAsJsonObject("origins").get("UNAVAILABLE").getAsInt());
            assertFalse(result.toString().contains(directory.toString()));assertFalse(result.toString().contains("PRIVATE_"));
            assertFalse(observer.productEntryArtifactMatches(directory,lab.auth.LabJson.sha256(jar)),"Missing protection-domain sources cannot silently qualify.");
        }
    }
    @Test void entryLocationDiagnosisHashesOnlyBoundedOwnedFilesAndDetectsChangedShadowBytes() throws Exception {
        Path fixture=publicLibraryFixture("lab.auth.origins.location."+UUID.randomUUID());
        Path run=Files.createDirectory(directory.resolve("run")),temp=Files.createDirectory(directory.resolve("temporary"));
        Path expected=Files.copy(fixture,run.resolve("product.jar")),shadow=Files.copy(fixture,temp.resolve("shadow.jar")),outside=Files.copy(fixture,directory.resolve("outside.jar"));
        try(var a=new URLClassLoader(new URL[]{expected.toUri().toURL()},null);var b=new URLClassLoader(new URL[]{shadow.toUri().toURL()},null);var c=new URLClassLoader(new URL[]{outside.toUri().toURL()},null)) {
            var observer=new HostLibraryOrigins(snapshots(new Class<?>[]{a.loadClass("bpsh.Extension"),b.loadClass("bpsh.Extension"),c.loadClass("bpsh.Extension")},unused->null).instrumentation(),Map.of(HostLibraryOrigins.Origin.PRODUCT,expected));
            String sha=lab.auth.LabJson.sha256(expected);var result=observer.productEntryLocations(run,temp,sha);
            assertTrue(result.has("sameArtifactFiles"));assertEquals(2,result.get("sameArtifactFiles").getAsInt());
            assertEquals(1,result.get("outsideOwnedFiles").getAsInt());assertEquals(1,result.get("ownedTemporaryFiles").getAsInt());
            assertFalse(result.toString().contains(directory.toString()));
            Files.writeString(shadow,"wrong bytes");var changed=observer.productEntryLocations(run,temp,sha);
            assertEquals(1,changed.get("sameArtifactFiles").getAsInt());assertEquals(1,changed.get("differentArtifactFiles").getAsInt());
        }
    }
    @Test void verifiedOwnedShadowDefinitionsSurviveTheirDeletedFilesWithoutTrustingAnUnobservedMissingDefinition() throws Exception {
        String property="lab.auth.origins.shadow."+UUID.randomUUID();Path fixture=publicLibraryFixture(property);
        Path temporary=Files.createDirectory(directory.resolve("owned-tmp")),aPath=Files.copy(fixture,temporary.resolve("a.jar")),bPath=Files.copy(fixture,temporary.resolve("b.jar"));
        Class<?>[] loaded=new Class<?>[3];
        try(var a=new URLClassLoader(new URL[]{aPath.toUri().toURL()},null);var b=new URLClassLoader(new URL[]{bPath.toUri().toURL()},null);var c=new URLClassLoader(new URL[]{aPath.toUri().toURL()},null)) {
            loaded[0]=a.loadClass("bpsh.Extension");var observer=new HostLibraryOrigins(snapshots(loaded,unused->null).instrumentation(),Map.of(HostLibraryOrigins.Origin.PRODUCT,fixture));
            Class<?> unobserved=c.loadClass("bpsh.Extension");
            String sha=lab.auth.LabJson.sha256(fixture);
            assertTrue(observer.productEntryArtifactMatches(temporary,sha));
            a.close();c.close();Files.delete(aPath);
            assertFalse(observer.productEntryArtifactMatches(temporary,sha),"A deleted historical copy alone cannot establish a current loaded artifact.");
            loaded[1]=b.loadClass("bpsh.Extension");
            assertTrue(observer.productEntryArtifactMatches(temporary,sha),"A previous definition must be bound before its owned copy is deleted.");
            loaded[2]=unobserved;
            assertFalse(observer.productEntryArtifactMatches(temporary,sha),"Missing unverified bytes cannot borrow another definition's proof.");
            assertNull(System.getProperty(property));
        }finally{System.clearProperty(property);}
    }
    @Test void shadowProofRejectsChangedBytesForeignLocationsAndWrongArtifactIdentity() throws Exception {
        Path fixture=publicLibraryFixture("lab.auth.origins.foreign."+UUID.randomUUID());Path temporary=Files.createDirectory(directory.resolve("private-tmp"));
        Path shadow=Files.copy(fixture,temporary.resolve("shadow.jar")),foreign=Files.copy(fixture,directory.resolve("foreign.jar")),other=Files.copy(fixture,temporary.resolve("other.jar"));
        try(var a=new URLClassLoader(new URL[]{shadow.toUri().toURL()},null);var b=new URLClassLoader(new URL[]{foreign.toUri().toURL()},null);var c=new URLClassLoader(new URL[]{other.toUri().toURL()},null)) {
            Class<?> entry=a.loadClass("bpsh.Extension");var expected=Map.of(HostLibraryOrigins.Origin.PRODUCT,fixture);String sha=lab.auth.LabJson.sha256(fixture);
            var observer=new HostLibraryOrigins(snapshots(new Class<?>[]{entry,c.loadClass("bpsh.Extension")},unused->null).instrumentation(),expected);
            assertTrue(observer.productEntryArtifactMatches(temporary,sha));assertFalse(observer.productEntryArtifactMatches(temporary,"0".repeat(64)));
            assertTrue(observer.productEntryArtifactMatches(temporary,sha));
            a.close();Files.writeString(shadow,"different bytes");assertFalse(observer.productEntryArtifactMatches(temporary,sha),"A cached proof cannot hide a changed existing file.");
            Files.delete(shadow);assertFalse(observer.productEntryArtifactMatches(temporary,sha),"Deleting bytes observed to be wrong cannot restore an obsolete proof.");
            var outside=new HostLibraryOrigins(snapshots(new Class<?>[]{b.loadClass("bpsh.Extension")},unused->null).instrumentation(),expected);
            assertFalse(outside.productEntryArtifactMatches(temporary,sha),"Identical bytes outside the owned temporary directory cannot qualify.");
        }
    }
    /** Metadata-only synthetic public library classes; their static initializer must never run. */
    private Path publicLibraryFixture(String property) throws Exception {
        Path fixture = Files.createTempDirectory(directory, "PRIVATE_LIBRARY_PATH"), sources = fixture.resolve("source"), classes = fixture.resolve("classes");
        Files.createDirectories(sources.resolve("bpsh")); Files.createDirectories(sources.resolve("com/microsoft/playwright")); Files.createDirectories(sources.resolve("com/sun/jna")); Files.createDirectories(classes);
        Path playwright = sources.resolve("com/microsoft/playwright/Playwright.java"), jna = sources.resolve("com/sun/jna/Native.java");
        Files.writeString(playwright, "package com.microsoft.playwright; public class Playwright { static { System.setProperty(\"" + property + "\",\"PRIVATE_INITIALIZER\"); } }");
        Files.writeString(jna, "package com.sun.jna; public class Native {} ");
        Path entry=sources.resolve("bpsh/Extension.java");
        Files.writeString(entry,"package bpsh; public class Extension { static { System.setProperty(\""+property+"\",\"PRIVATE_INITIALIZER\"); } }");
        var compiler = ToolProvider.getSystemJavaCompiler(); assertNotNull(compiler);
        assertEquals(0, compiler.run(null, OutputStream.nullOutputStream(), OutputStream.nullOutputStream(), "-d", classes.toString(), playwright.toString(), jna.toString(), entry.toString()));
        Path jar = fixture.resolve("public-library.jar");
        try (var stream = new JarOutputStream(Files.newOutputStream(jar)); var files = Files.walk(classes)) {
            for (Path file : files.filter(Files::isRegularFile).toList()) {
                stream.putNextEntry(new JarEntry(classes.relativize(file).toString().replace('\\', '/'))); Files.copy(file, stream); stream.closeEntry();
            }
        }
        return jar;
    }
}
