package bpsh.mtls;

import bpsh.model.AuthenticationFailure;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Runs discovery in the bundled Java runtime, isolating its native bridge from host classloaders/libraries. */
final class Pkcs11DiscoveryProcess {
    private static final ObjectMapper JSON = new ObjectMapper();

    /** @param module Canonical module path. @return Initialized tokens, without ever accepting a PIN. @throws Exception On helper startup, timeout, malformed result or native failure. */
    List<Pkcs11IdentityManager.TokenInfo> tokens(Path module) throws Exception {
        Path result = Files.createTempFile("bpsh-device-discovery-", ".json"); Process child = null;
        try {
            String executable = System.getProperty("os.name", "").startsWith("Windows") ? "javaw.exe" : "java";
            Path java = Path.of(System.getProperty("java.home"), "bin", executable);
            child = new ProcessBuilder(java.toString(), "--enable-native-access=ALL-UNNAMED", "-Djava.awt.headless=true",
                    "-cp", classpath(), Pkcs11DiscoveryMain.class.getName(), module.toString(), result.toString())
                    .redirectInput(ProcessBuilder.Redirect.PIPE).redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
            child.getOutputStream().close();
            if (!child.waitFor(45, TimeUnit.SECONDS))
                throw problem("Security-device discovery timed out in the middleware.", "Check the device and middleware before choosing the certificate again.");
            long size = Files.size(result);
            if (child.exitValue() != 0 || size == 0 || size > 262_144)
                throw problem("The security-device discovery helper did not return a valid result.", "Check the Java runtime and the installed middleware.");
            var document = JSON.readTree(Files.readString(result));
            if (document.has("problem") && document.path("problem").isTextual() && document.path("recovery").isTextual())
                throw problem(document.path("problem").textValue(), document.path("recovery").textValue());
            var tokens = document.path("tokens");
            if (!tokens.isArray() || tokens.size() > 256) throw problem("The discovery helper returned an invalid device list.", "");
            var found = new ArrayList<Pkcs11IdentityManager.TokenInfo>();
            for (var token : tokens) {
                if (!token.path("slotId").canConvertToLong() || token.path("slotId").longValue() < 0
                        || !token.path("label").isTextual() || !token.path("manufacturer").isTextual()
                        || !token.path("model").isTextual() || !token.path("serial").isTextual())
                    throw problem("The discovery helper returned invalid device metadata.", "");
                found.add(new Pkcs11IdentityManager.TokenInfo(token.path("slotId").longValue(), token.path("label").textValue(),
                        token.path("manufacturer").textValue(), token.path("model").textValue(), token.path("serial").textValue()));
            }
            return List.copyOf(found);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new AuthenticationFailure(AuthenticationFailure.Phase.PROVIDER, AuthenticationFailure.Cause.CANCELLED, "Security-device discovery was interrupted.");
        } catch (AuthenticationFailure error) { throw error; }
        catch (Exception | LinkageError error) {
            throw problem("The security-device discovery helper could not be started or read.", "Check Burp's Java runtime and temporary-file access.");
        } finally {
            if (child != null && child.isAlive()) child.destroyForcibly();
            try { Files.deleteIfExists(result); } catch (java.io.IOException | SecurityException ignored) { /* result contains public device metadata only */ }
        }
    }

    /** @return Packaged JAR in production; explicit code sources also support the existing compiled-class integration tests. @throws Exception On unavailable runtime sources. */
    private static String classpath() throws Exception {
        var paths = new LinkedHashSet<String>();
        for (Class<?> type : List.of(Pkcs11DiscoveryMain.class, com.sun.jna.Native.class, ObjectMapper.class,
                com.fasterxml.jackson.core.JsonFactory.class, com.fasterxml.jackson.annotation.JsonInclude.class))
            paths.add(Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString());
        return String.join(File.pathSeparator, paths);
    }

    /** @param text Controlled helper observation. @param recovery Supported next action. @return Failure without native output or raw exceptions. */
    private static AuthenticationFailure problem(String text, String recovery) { return new AuthenticationFailure(AuthenticationFailure.Phase.PROVIDER, AuthenticationFailure.Cause.CONFIGURATION, text, recovery); }
}
