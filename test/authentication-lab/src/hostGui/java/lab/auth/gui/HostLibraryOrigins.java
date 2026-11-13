package lab.auth.gui;

import java.awt.EventQueue;
import java.lang.instrument.Instrumentation;
import java.nio.file.Path;
import java.util.*;

/** Optional public-JDK metadata about already loaded public library classes; never loads or calls them. */
final class HostLibraryOrigins {
    enum Origin { HOST, HELPER, PRODUCT, OTHER, UNAVAILABLE }
    private static final int MAX_CLASSES = 200_000;
    private static final String PLAYWRIGHT = "com.microsoft.playwright.Playwright";
    private static final List<String> PUBLIC_CLASSES = List.of(
            "com.google.gson.Gson", "com.google.gson.JsonParser",
            "com.fasterxml.jackson.databind.ObjectMapper", "com.sun.jna.Native", PLAYWRIGHT,
            "org.apache.commons.compress.archivers.zip.ZipFile",
            "org.apache.hc.client5.http.classic.HttpClient", "org.tukaani.xz.XZInputStream", "io.netty.channel.Channel");
    private final Instrumentation instrumentation;
    private final Map<Origin, Path> sources;
    private record VerifiedSource(Path path,String sha256) {}
    // Weak keys are essential: qualification must not keep an unloaded extension/classloader alive.
    private final Map<Class<?>,VerifiedSource> verifiedEntries=new WeakHashMap<>();
    synchronized boolean productEntryArtifactMatches(Path temporary,String expectedSha) {
        if(instrumentation==null||EventQueue.isDispatchThread()||expectedSha==null||!expectedSha.matches("[0-9a-f]{64}"))return false;
        try {
            Path expected=sources.get(Origin.PRODUCT),temp=temporary.toAbsolutePath().normalize();
            if(expected==null||!temp.equals(temp.toRealPath())||!java.nio.file.Files.isDirectory(temp,java.nio.file.LinkOption.NOFOLLOW_LINKS))return false;
            Class<?>[] loaded=instrumentation.getAllLoadedClasses();if(loaded==null||loaded.length>MAX_CLASSES)return false;
            boolean found=false,current=false;var hashes=new HashMap<Path,Boolean>();
            for(Class<?> type:distinct(loaded))if(type.getName().equals("bpsh.Extension")) {
                found=true;var domain=type.getProtectionDomain();var source=domain==null?null:domain.getCodeSource();var location=source==null?null:source.getLocation();
                if(location==null||!location.getProtocol().equals("file"))return false;
                Path actual=Path.of(location.toURI()).toAbsolutePath().normalize();boolean original=actual.equals(expected);
                if(!original&&(!actual.startsWith(temp)||actual.equals(temp)))return false;
                if(!safeOwnedPath(actual,original?expected.getParent():temp))return false;
                if(!java.nio.file.Files.exists(actual,java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                    var previous=verifiedEntries.get(type);
                    if(original||previous==null||!previous.path().equals(actual)||!previous.sha256().equals(expectedSha))return false;
                    continue;
                }
                if(!hashes.containsKey(actual)) {
                    if(hashes.size()>=4)return false;hashes.put(actual,boundedHashMatches(actual,expectedSha));
                }
                if(!hashes.get(actual)) {
                    verifiedEntries.values().removeIf(proof->proof.path().equals(actual));return false;
                }
                if(!verifiedEntries.containsKey(type)&&verifiedEntries.size()>=64)return false;
                verifiedEntries.put(type,new VerifiedSource(actual,expectedSha));current=true;
            }
            return found&&current;
        }catch(Exception|LinkageError unavailable){return false;}
    }

    /** Keeps only the captured expected locations internally; locations never enter the result. */
    HostLibraryOrigins(Instrumentation instrumentation, Map<Origin, Path> expectedSources) {
        this.instrumentation = instrumentation;
        var known = new EnumMap<Origin, Path>(Origin.class);
        for (var origin : List.of(Origin.HOST, Origin.HELPER, Origin.PRODUCT)) {
            Path source = expectedSources.get(origin);
            if (source != null) try { known.put(origin, source.toAbsolutePath().normalize()); }
            catch (RuntimeException unavailable) { /* An unrepresentable expected source cannot establish its origin. */ }
        }
        sources = Map.copyOf(known);
    }

    /** One bounded off-EDT snapshot. Missing/ambiguous evidence never implies a particular dependency origin. */
    Map<String, Object> capture() {
        if (instrumentation == null || EventQueue.isDispatchThread()) return unavailable();
        try {
            Class<?>[] loaded = instrumentation.getAllLoadedClasses();
            if (loaded == null || loaded.length > MAX_CLASSES) return unavailable();
            var observed = observe(loaded);
            var productLoaders = Collections.newSetFromMap(new IdentityHashMap<ClassLoader, Boolean>());
            int productPlaywrightDefinitions = 0;
            for (Class<?> type : distinct(loaded)) if (PLAYWRIGHT.equals(type.getName()) && origin(type) == Origin.PRODUCT) {
                productPlaywrightDefinitions++;
                ClassLoader loader = type.getClassLoader();
                if (loader != null) productLoaders.add(loader);
            }
            String loaderState = productPlaywrightDefinitions == 0 ? "NOT_OBSERVED" : "AMBIGUOUS";
            List<Map<String, Object>> initiated = List.of();
            if (productPlaywrightDefinitions == 1 && productLoaders.size() == 1) {
                loaderState = "UNAVAILABLE";
                try {
                    Class<?>[] classes = instrumentation.getInitiatedClasses(productLoaders.iterator().next());
                    if (classes != null && classes.length <= MAX_CLASSES) {
                        initiated = observe(classes); loaderState = "IDENTIFIED";
                    }
                } catch (RuntimeException | LinkageError unavailable) { /* Retain all-loaded proof independently. */ }
            }
            return Map.of("available", true, "loaded", observed,
                    "productPlaywrightLoader", loaderState, "initiated", initiated);
        } catch (RuntimeException | LinkageError unavailable) { return unavailable(); }
    }

    com.google.gson.JsonObject productEntrySources() {
        var result=new com.google.gson.JsonObject();result.addProperty("available",false);result.addProperty("definitions",0);
        result.addProperty("missingSources",0);result.addProperty("fileSources",0);result.addProperty("otherProtocols",0);result.add("origins",new com.google.gson.JsonObject());
        if(instrumentation==null||EventQueue.isDispatchThread())return result;
        try {
            Class<?>[] loaded=instrumentation.getAllLoadedClasses();if(loaded==null||loaded.length>MAX_CLASSES)return result;
            int definitions=0,missing=0,files=0,other=0;var origins=new com.google.gson.JsonObject();
            for(Class<?> type:distinct(loaded))if(type.getName().equals("bpsh.Extension")) {
                definitions++;String origin=origin(type).name();origins.addProperty(origin,origins.has(origin)?origins.get(origin).getAsInt()+1:1);
                try {
                    var domain=type.getProtectionDomain();var source=domain==null?null:domain.getCodeSource();var location=source==null?null:source.getLocation();
                    if(location==null)missing++;else if(location.getProtocol().equals("file"))files++;else other++;
                }catch(RuntimeException|LinkageError unavailable){missing++;}
            }
            result.addProperty("available",true);result.addProperty("definitions",definitions);result.addProperty("missingSources",missing);
            result.addProperty("fileSources",files);result.addProperty("otherProtocols",other);result.add("origins",origins);
        }catch(RuntimeException|LinkageError unavailable){/* Fixed unavailable marker, never raw source or exception text. */}
        return result;
    }
    com.google.gson.JsonObject productEntryLocations(Path runRoot,Path temporary,String expectedSha) {
        var result=new com.google.gson.JsonObject();result.addProperty("available",false);
        for(String key:List.of("definitions","sameArtifactFiles","differentArtifactFiles","ownedRootFiles","ownedTemporaryFiles","outsideOwnedFiles","missingOwnedFiles","ownedDirectories","unsafeOwnedFiles","readBudgetExceeded"))result.addProperty(key,0);
        if(instrumentation==null||EventQueue.isDispatchThread())return result;
        try {
            Path root=runRoot.toRealPath(),temp=temporary.toRealPath();Class<?>[] loaded=instrumentation.getAllLoadedClasses();
            if(loaded==null||loaded.length>MAX_CLASSES||!expectedSha.matches("[0-9a-f]{64}"))return result;
            var hashes=new HashMap<Path,Boolean>();
            for(Class<?> type:distinct(loaded))if(type.getName().equals("bpsh.Extension")) {
                increment(result,"definitions");
                var domain=type.getProtectionDomain();var source=domain==null?null:domain.getCodeSource();var location=source==null?null:source.getLocation();
                if(location==null||!location.getProtocol().equals("file"))continue;
                Path actual=Path.of(location.toURI()).toAbsolutePath().normalize();Path boundary;
                if(actual.startsWith(root)){increment(result,"ownedRootFiles");boundary=root;}
                else if(actual.startsWith(temp)){increment(result,"ownedTemporaryFiles");boundary=temp;}
                else {increment(result,"outsideOwnedFiles");continue;}
                if(!safeOwnedPath(actual,boundary)){increment(result,"unsafeOwnedFiles");continue;}
                if(!java.nio.file.Files.exists(actual,java.nio.file.LinkOption.NOFOLLOW_LINKS)){increment(result,"missingOwnedFiles");continue;}
                if(java.nio.file.Files.isDirectory(actual,java.nio.file.LinkOption.NOFOLLOW_LINKS)){increment(result,"ownedDirectories");continue;}
                if(!hashes.containsKey(actual)) {
                    if(hashes.size()>=4){increment(result,"readBudgetExceeded");continue;}
                    hashes.put(actual,boundedHashMatches(actual,expectedSha));
                }
                increment(result,hashes.get(actual)?"sameArtifactFiles":"differentArtifactFiles");
            }
            result.addProperty("available",true);
        }catch(Exception|LinkageError unavailable){/* No arbitrary source path or exception text leaves this diagnostic. */}
        return result;
    }
    private static boolean safeOwnedPath(Path actual,Path boundary) throws java.io.IOException {
        if(!actual.startsWith(boundary))return false;
        var root=java.nio.file.Files.readAttributes(boundary,java.nio.file.attribute.BasicFileAttributes.class,java.nio.file.LinkOption.NOFOLLOW_LINKS);
        if(!root.isDirectory()||root.isSymbolicLink()||root.isOther())return false;
        Path part=boundary;
        for(Path segment:boundary.relativize(actual)) {
            part=part.resolve(segment);
            if(!java.nio.file.Files.exists(part,java.nio.file.LinkOption.NOFOLLOW_LINKS))return true;
            var attributes=java.nio.file.Files.readAttributes(part,java.nio.file.attribute.BasicFileAttributes.class,java.nio.file.LinkOption.NOFOLLOW_LINKS);
            if(attributes.isSymbolicLink()||attributes.isOther())return false;
        }
        return true;
    }
    private static void increment(com.google.gson.JsonObject result,String key){result.addProperty(key,result.get(key).getAsInt()+1);}
    private static boolean boundedHashMatches(Path path,String expected) throws Exception {
        var before=java.nio.file.Files.readAttributes(path,java.nio.file.attribute.BasicFileAttributes.class,java.nio.file.LinkOption.NOFOLLOW_LINKS);
        long limit=134217728L;if(!before.isRegularFile()||before.size()<1||before.size()>=limit)return false;
        var digest=java.security.MessageDigest.getInstance("SHA-256");long bytes=0;
        try(var input=java.nio.file.Files.newInputStream(path)) {
            byte[] buffer=new byte[65536];int count;
            while((count=input.read(buffer))!=-1){bytes+=count;if(bytes>=limit)return false;digest.update(buffer,0,count);}
        }
        var after=java.nio.file.Files.readAttributes(path,java.nio.file.attribute.BasicFileAttributes.class,java.nio.file.LinkOption.NOFOLLOW_LINKS);
        return bytes==before.size()&&after.isRegularFile()&&after.size()==before.size()&&Objects.equals(before.fileKey(),after.fileKey())
                &&before.lastModifiedTime().equals(after.lastModifiedTime())&&HexFormat.of().formatHex(digest.digest()).equals(expected);
    }

    private static Map<String, Object> unavailable() {
        return Map.of("available", false, "loaded", List.of(), "productPlaywrightLoader", "UNAVAILABLE", "initiated", List.of());
    }

    /** Deduplicates only Class identities, preserving distinct definitions with the same public name. */
    private static Set<Class<?>> distinct(Class<?>[] classes) {
        Set<Class<?>> result = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Class<?> type : classes) if (type != null) result.add(type);
        return result;
    }

    private List<Map<String, Object>> observe(Class<?>[] classes) {
        var counts = new LinkedHashMap<String, EnumMap<Origin, Integer>>();
        PUBLIC_CLASSES.forEach(name -> counts.put(name, new EnumMap<>(Origin.class)));
        for (Class<?> type : distinct(classes)) {
            var row = counts.get(type.getName());
            if (row != null) row.merge(origin(type), 1, Integer::sum);
        }
        var result = new ArrayList<Map<String, Object>>();
        counts.forEach((name, row) -> {
            var origins = new LinkedHashMap<String, Integer>();
            row.forEach((origin, count) -> origins.put(origin.name(), count));
            result.add(Map.of("class", name, "definitions", row.values().stream().mapToInt(Integer::intValue).sum(),
                    "origins", Collections.unmodifiableMap(origins)));
        });
        return List.copyOf(result);
    }

    /** Reads public metadata only for a fixed approved library name; no package, loader or URI text is emitted. */
    private Origin origin(Class<?> type) {
        try {
            var domain = type.getProtectionDomain();
            var source = domain == null ? null : domain.getCodeSource();
            var location = source == null ? null : source.getLocation();
            if (location == null || !location.getProtocol().equals("file")) return Origin.UNAVAILABLE;
            // Compare the captured location lexically; never open an arbitrary library source or follow a network path.
            Path actual = Path.of(location.toURI()).toAbsolutePath().normalize();
            var matches = sources.entrySet().stream().filter(entry -> entry.getValue().equals(actual)).map(Map.Entry::getKey).toList();
            return matches.size() == 1 ? matches.getFirst() : matches.isEmpty() ? Origin.OTHER : Origin.UNAVAILABLE;
        } catch (Exception | LinkageError unavailable) { return Origin.UNAVAILABLE; }
    }
}
