package bpsh.browser.runtime;

import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/** Closed native-loader observations; vendor strings are inspected briefly but never returned. */
enum NativeLoadReason {
    VERSION_MISMATCH("The loaded JNA native library is incompatible with its Java library.", "Check native-library overrides in Burp's Java launch configuration."),
    CLASSLOADER_CONFLICT("The native library is already loaded by another Java classloader.", "Restart Burp completely; reloading only the extension does not unload every shared native library."),
    TEMP_DIRECTORY("JNA could not create or access its temporary native-library file.", "Check Burp's temporary-directory permissions, availability and free space."),
    RESOURCE_MISSING("The JNA support DLL was not found in the native loader's resources.", "Verify the extension JAR's published checksum and check native-library overrides."),
    POLICY_BLOCKED("Windows rejected loading the native library under its application or signature policy.", "Ask your administrator to review the native-library approval on this machine."),
    ACCESS_DENIED("Windows denied access while loading the native library.", "Check the native file's access permissions and the machine's application-control policy."),
    IMAGE_FORMAT("Windows rejected the native library's format or architecture.", "Use 64-bit Burp Java and verify the extension JAR's published checksum."),
    MODULE_MISSING("Windows could not find a native module required for loading.", "Check that the support DLL and its Windows dependencies are available."),
    DLL_INITIALIZATION("Windows could not initialize the native DLL.", "Ask your administrator to review the Windows DLL-initialization failure."),
    JNI_ENTRYPOINT("The native library does not provide a required JNA entry point.", "Check that the loaded JNA Java classes and native library are compatible."),
    CLASSPATH_DISABLED("Native loading failed while JNA classpath resources are disabled by jna.noclasspath.", "Check this Java launch setting with the administrator of the Burp installation."),
    UNPACK_DISABLED("Native loading failed while JNA resource extraction is disabled by jna.nounpack.", "Check the approved native-library location and this Java launch setting."),
    UNKNOWN("A native library required by the browser runtime could not load.", "Check native-library loading restrictions and Java launch settings on this machine.");

    final String problem;
    final String recovery;
    private static final Pattern WINDOWS_ERROR = Pattern.compile("(?:\\berror(?:\\s+code)?\\s*[=:]?\\s*|\\bwin32\\s*[=:]?\\s*)(1260|1114|577|193|126|5)\\b");

    NativeLoadReason(String problem, String recovery) { this.problem = problem; this.recovery = recovery; }

    /** Known non-secret flags, read without modifying the JVM or exposing property values. */
    record Settings(boolean classpathDisabled, boolean unpackDisabled) {
        static Settings current() { return new Settings(enabled("jna.noclasspath"), enabled("jna.nounpack")); }
        private static boolean enabled(String key) {
            try { return Boolean.getBoolean(key); } catch (SecurityException unavailable) { return false; }
        }
    }

    /** @param error Borrowed loader error. @return Whether JNA's explicit ABI-check error was observed. */
    static boolean incompatibleVersionError(Throwable error) {
        return error.getClass() == Error.class && text(error).contains("there is an incompatible jna native library installed on this system");
    }

    /** @param chain Bounded borrowed cause list. @param settings Observed flags. @return Fixed reason; never raw vendor data. */
    static NativeLoadReason observe(List<Throwable> chain, Settings settings) {
        for (Throwable error : chain) {
            String text = text(error);
            if (text.contains("there is an incompatible jna native library installed on this system")) return VERSION_MISMATCH;
            if (text.contains("already loaded in another classloader")) return CLASSLOADER_CONFLICT;
            if (text.contains("jna temporary directory") || text.contains("failed to create temporary file for")) return TEMP_DIRECTORY;
            if (text.contains("jnidispatch") && text.contains("not found in resource path")) return RESOURCE_MISSING;
            if (text.contains("blocked by group policy") || text.contains("bloqué par une stratégie de groupe") || text.contains("digital signature") || text.contains("signature numérique")) return POLICY_BLOCKED;
            if (text.contains("access is denied") || text.contains("accès refusé") || text.contains("accès est refusé")) return ACCESS_DENIED;
            if (text.contains("not a valid win32 application") || text.contains("n’est pas une application win32 valide") || text.contains("n'est pas une application win32 valide")) return IMAGE_FORMAT;
            if (text.contains("can't find dependent libraries") || text.contains("specified module could not be found") || text.contains("module spécifié est introuvable")) return MODULE_MISSING;
            if (text.contains("dll initialization routine failed") || ((text.contains("routine d'initialisation") || text.contains("routine d’initialisation")) && text.contains("échoué"))) return DLL_INITIALIZATION;
            var code = WINDOWS_ERROR.matcher(text);
            if (code.find()) return switch (code.group(1)) {
                case "5" -> ACCESS_DENIED; case "126" -> MODULE_MISSING; case "193" -> IMAGE_FORMAT;
                case "577", "1260" -> POLICY_BLOCKED; case "1114" -> DLL_INITIALIZATION;
                default -> UNKNOWN;
            };
            if (text.contains("com.sun.jna.native.") || text.contains("error looking up function")) return JNI_ENTRYPOINT;
        }
        if (settings.classpathDisabled()) return CLASSPATH_DISABLED;
        if (settings.unpackDisabled()) return UNPACK_DISABLED;
        return UNKNOWN;
    }

    /** @param error Borrowed error. @return Bounded transient text for closed matching only. */
    private static String text(Throwable error) {
        String message = error.getMessage();
        return message == null ? "" : message.substring(0, Math.min(8192, message.length())).toLowerCase(Locale.ROOT);
    }
}
