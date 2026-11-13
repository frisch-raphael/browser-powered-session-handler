package bpsh.browser.runtime;

import bpsh.authentication.AuthenticationFailure;
import java.lang.reflect.InaccessibleObjectException;
import java.util.ArrayList;
import java.util.List;

/** Classifies startup evidence without retaining vendor messages, paths or exception graphs. */
final class DriverStartupFailures {
    /** Last operation entered, rather than an inferred failing component. */
    enum Stage { NATIVE_SUPPORT, DRIVER_PROCESS, PLAYWRIGHT_PROTOCOL, BROWSER_SESSION }

    private DriverStartupFailures() {}

    /**
     * Returns a classified loading failure, or null for the existing process/I/O classifier.
     * @param error Borrowed throwable whose text and graph must not escape.
     * @param stage Last operation entered by the owner.
     * @return Independent safe failure, or null for an unclassified error.
     */
    static AuthenticationFailure classify(Throwable error, Stage stage) {
        List<Throwable> chain = new ArrayList<>();
        for (Throwable next = error; next != null && chain.size() < 12; next = next.getCause()) {
            boolean repeated = false;
            for (Throwable seen : chain) if (seen == next) { repeated = true; break; }
            if (repeated) break;
            chain.add(next);
        }
        for (Throwable item : chain) if (item instanceof WindowsBrowserJob.Failure known) {
            String code = "WINDOWS_JOB_" + known.operation.name();
            if (known.nativeCode != null) code += "; Windows error " + known.nativeCode;
            if (known.waitResult != null) code += "; wait result " + known.waitResult;
            return failure(stage, code, "Windows could not establish or close the driver's owned process group.", "");
        }
        if (contains(chain, UnsupportedClassVersionError.class))
            return failure(stage, "JAVA_VERSION", "The browser runtime contains classes incompatible with Burp's Java version.",
                    "Use Burp's bundled Java runtime and the complete published extension JAR.");
        if (stage == Stage.NATIVE_SUPPORT && contains(chain, IllegalCallerException.class))
            return failure(stage, "NATIVE_ACCESS", "Burp's Java runtime refused access while initializing Windows native support.",
                    "Check the native-access configuration of the Java runtime used to launch Burp.");
        if (stage == Stage.NATIVE_SUPPORT && (contains(chain, UnsatisfiedLinkError.class)
                || chain.stream().anyMatch(NativeLoadReason::incompatibleVersionError))) {
            var detail = NativeLoadReason.observe(chain, NativeLoadReason.Settings.current());
            return failure(stage, "NATIVE_LIBRARY" + (detail == NativeLoadReason.UNKNOWN ? "" : "_" + detail.name()), detail.problem, detail.recovery);
        }
        if (contains(chain, UnsatisfiedLinkError.class))
            return failure(stage, "NATIVE_LIBRARY", "A native library required by the browser runtime could not load.",
                    "Check native-library loading restrictions and Java launch settings on this machine.");
        if (contains(chain, IllegalAccessError.class) || contains(chain, IllegalAccessException.class) || contains(chain, InaccessibleObjectException.class))
            return failure(stage, "JAVA_ACCESS", "Java denied access while initializing the browser runtime.", "");
        if (contains(chain, IncompatibleClassChangeError.class) && !contains(chain, NoClassDefFoundError.class))
            return failure(stage, "LIBRARY_VERSION", "The browser runtime encountered incompatible Java libraries.",
                    "Check for Java-library overrides in Burp's launch configuration and verify the installed extension JAR's checksum.");
        if (contains(chain, ExceptionInInitializerError.class) || chain.stream().anyMatch(item ->
                item instanceof NoClassDefFoundError && item.getMessage() != null && item.getMessage().startsWith("Could not initialize class ")))
            return failure(stage, "CLASS_INITIALIZATION", "A Java class required by the browser runtime failed to initialize.",
                    "Restart Burp completely; reloading the extension alone may retain the failed initialization state.");
        if (contains(chain, NoClassDefFoundError.class) || contains(chain, ClassNotFoundException.class))
            return failure(stage, "CLASS_MISSING", "A required browser-runtime Java class could not load.",
                    "Verify the installed extension JAR's checksum against the published release.");
        if (contains(chain, NoSuchMethodException.class) || contains(chain, NoSuchFieldException.class))
            return failure(stage, "DRIVER_API", "The browser driver's Java API does not match the extension's pinned runtime.",
                    "Verify the installed extension JAR's checksum against the published release.");
        if (contains(chain, LinkageError.class))
            return failure(stage, "JAVA_LINKAGE", "The browser runtime's Java libraries could not link.", "");
        return null;
    }

    /** @param chain Bounded borrowed cause list. @param type Known Java failure family. @return Whether that family was observed. */
    private static boolean contains(List<Throwable> chain, Class<? extends Throwable> type) {
        return chain.stream().anyMatch(type::isInstance);
    }

    /** @param stage Observed operation. @param code Authored category and bounded native numbers. @param problem Authored explanation. @param recovery Evidence-based guidance. @return Failure with no raw cause. */
    private static AuthenticationFailure failure(Stage stage, String code, String problem, String recovery) {
        return new AuthenticationFailure(AuthenticationFailure.Phase.SETUP, AuthenticationFailure.Cause.CONFIGURATION,
                problem + " Diagnostic: " + stage.name() + "/" + code + ".", recovery);
    }
}
