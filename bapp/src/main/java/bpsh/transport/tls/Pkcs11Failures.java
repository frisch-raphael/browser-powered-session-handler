package bpsh.transport.tls;

import bpsh.authentication.AuthenticationFailure;
import java.nio.file.AccessDeniedException;
import java.nio.file.InvalidPathException;
import java.nio.file.NoSuchFileException;
import java.security.ProviderException;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** Converts device-boundary failures into safe operation-specific explanations; raw causes are never retained. */
public final class Pkcs11Failures {
    /** Last operation entered, so a later certificate-read failure is never described as initialization. */
    public enum Operation { MODULE, DISCOVERY, INITIALIZE, LOGIN, CERTIFICATES }

    /** Fixed descriptions of known PKCS#11 outcomes; configured values and vendor messages are excluded. */
    private record Issue(String problem, String recovery) {}
    private static final Map<String, Issue> ISSUES = Map.ofEntries(
            Map.entry("CKR_SLOT_ID_INVALID", new Issue("The saved security device is not available to this middleware instance.", "Use Choose certificate to detect available devices. If your device is missing, check the middleware configuration available to Burp.")),
            Map.entry("CKR_TOKEN_NOT_PRESENT", new Issue("No token is present in the selected slot.", "Connect the token before retrying.")),
            Map.entry("CKR_TOKEN_NOT_RECOGNIZED", new Issue("The middleware does not recognize the token.", "Check that the selected middleware supports this token.")),
            Map.entry("CKR_TOKEN_NOT_INITIALIZED", new Issue("The selected token is not initialized.", "Ask the token administrator to prepare it before retrying.")),
            Map.entry("CKR_USER_PIN_NOT_INITIALIZED", new Issue("The token has no initialized user PIN.", "Ask the token administrator to prepare it before retrying.")),
            Map.entry("CKR_DEVICE_REMOVED", new Issue("The security device was disconnected.", "Reconnect the device before retrying.")),
            Map.entry("CKR_DEVICE_ERROR", new Issue("The security device reported a device error.", "Check the device in its middleware application before retrying.")),
            Map.entry("CKR_DEVICE_MEMORY", new Issue("The security device has insufficient memory for this operation.", "Check the device in its middleware application.")),
            Map.entry("CKR_HOST_MEMORY", new Issue("The middleware could not allocate memory.", "")),
            Map.entry("CKR_GENERAL_ERROR", new Issue("The middleware reported an unspecified error.", "Check the middleware configuration and its own diagnostics.")),
            Map.entry("CKR_FUNCTION_FAILED", new Issue("The middleware could not complete the operation.", "Check the middleware's own diagnostics.")),
            Map.entry("CKR_ARGUMENTS_BAD", new Issue("The middleware rejected the operation's parameters.", "Check that the middleware is compatible with Burp's Java runtime.")),
            Map.entry("CKR_CRYPTOKI_NOT_INITIALIZED", new Issue("The middleware is no longer initialized.", "Reload the extension before retrying.")),
            Map.entry("CKR_CRYPTOKI_ALREADY_INITIALIZED", new Issue("The middleware rejected initialization because it is already initialized.", "Check for another application or extension using the same middleware.")),
            Map.entry("CKR_LIBRARY_LOAD_FAILED", new Issue("The PKCS#11 native library could not be loaded.", "Check the library's architecture, dependencies, and file permissions.")),
            Map.entry("CKR_CANT_LOCK", new Issue("The middleware could not initialize its locking support.", "Check that the middleware supports multithreaded Java applications.")),
            Map.entry("CKR_SESSION_CLOSED", new Issue("The token session was closed.", "Retry certificate listing to establish a new session.")),
            Map.entry("CKR_SESSION_HANDLE_INVALID", new Issue("The token session is no longer valid.", "Retry certificate listing to establish a new session.")),
            Map.entry("CKR_SESSION_COUNT", new Issue("The token has no free sessions.", "Close unused token sessions in other applications before retrying.")),
            Map.entry("CKR_USER_NOT_LOGGED_IN", new Issue("The token requires a new login.", "Retry certificate listing when the device is ready.")),
            Map.entry("CKR_FUNCTION_NOT_SUPPORTED", new Issue("The middleware does not support the requested operation.", "Check the middleware's compatibility and supported operations.")),
            Map.entry("CKR_MECHANISM_INVALID", new Issue("The token does not support the requested cryptographic operation.", "Choose a compatible certificate and middleware.")),
            Map.entry("CKR_KEY_HANDLE_INVALID", new Issue("The token's private-key reference is no longer valid.", "Choose the certificate again from the current token.")),
            Map.entry("CKR_KEY_TYPE_INCONSISTENT", new Issue("The private key is incompatible with the requested operation.", "Choose a compatible client certificate.")),
            Map.entry("CKR_KEY_FUNCTION_NOT_PERMITTED", new Issue("The token does not permit the requested private-key operation.", "Check the key's permitted uses with the token administrator.")),
            Map.entry("CKR_PIN_INCORRECT", new Issue("The security device rejected the PIN as incorrect.", "Check the PIN before explicitly retrying.")),
            Map.entry("CKR_PIN_INVALID", new Issue("The security device rejected the PIN format.", "Check the device's PIN requirements before explicitly retrying.")),
            Map.entry("CKR_PIN_LEN_RANGE", new Issue("The security device rejected the PIN length.", "Check the device's PIN requirements before explicitly retrying.")),
            Map.entry("CKR_PIN_LOCKED", new Issue("The security device's PIN is locked.", "Contact the token administrator to unlock it before retrying.")),
            Map.entry("CKR_PIN_EXPIRED", new Issue("The security device's PIN has expired.", "Update it using the token's own software before retrying.")),
            Map.entry("CKR_FUNCTION_CANCELED", new Issue("The device operation was cancelled.", "")),
            Map.entry("CKR_CANCEL", new Issue("The device operation was cancelled.", ""))
    );
    private static final Set<String> PIN_REJECTIONS = Set.of("CKR_PIN_INCORRECT", "CKR_PIN_INVALID", "CKR_PIN_LEN_RANGE", "CKR_PIN_LOCKED", "CKR_PIN_EXPIRED");
    private static final Pattern CODE = Pattern.compile("(?<![A-Z0-9_])CKR_[A-Z0-9_]+(?![A-Z0-9_])");
    private static final Pattern SLOT_INDEX = Pattern.compile("slotListIndex is -?\\d+ but token only has \\d+ slots");

    /** Shared classifier only. */
    private Pkcs11Failures() {}

    /**
     * Classifies a bounded cause chain without storing any native text, PIN, path or raw exception.
     * @param operation Last entered boundary; LOGIN means the PIN may have reached the device.
     * @param error Observed failure, inspected transiently.
     * @return Safe terminal failure. Uncertain login outcomes always retain PIN suppression.
     */
    public static AuthenticationFailure from(Operation operation, Throwable error) {
        var failure = classify(operation, error);
        if (failure.input() != null) return failure;
        return switch (operation) {
            case MODULE -> failure.atInput(AuthenticationFailure.Input.MIDDLEWARE);
            case DISCOVERY -> failure.atInput(AuthenticationFailure.Input.SECURITY_DEVICE);
            case LOGIN -> failure.atInput(failure.reason() == AuthenticationFailure.Cause.PIN_REJECTED
                    ? AuthenticationFailure.Input.MTLS_PIN : AuthenticationFailure.Input.SECURITY_DEVICE);
            case CERTIFICATES -> failure.atInput(AuthenticationFailure.Input.CERTIFICATE);
            case INITIALIZE -> failure;
        };
    }
    /** @param operation Observed boundary. @param error Transient vendor error. @return Redacted failure with precise input attribution where established. */
    private static AuthenticationFailure classify(Operation operation, Throwable error) {
        var seen = Collections.newSetFromMap(new IdentityHashMap<Throwable, Boolean>());
        String code = null; boolean index = false, providerMissing = false, denied = false, missing = false, invalidPath = false;
        boolean linkage = false, invalidConfig = false, unsupported = false;
        for (Throwable cause = error; cause != null && seen.size() < 16 && seen.add(cause); cause = cause.getCause()) {
            String message = cause.getMessage();
            if (message != null) {
                var matcher = CODE.matcher(message);
                while (matcher.find()) {
                    String candidate = matcher.group();
                    if (ISSUES.containsKey(candidate) && (code == null || PIN_REJECTIONS.contains(candidate))) code = candidate;
                }
                index |= cause instanceof ProviderException && SLOT_INDEX.matcher(message).matches();
                providerMissing |= message.equals("Cryptoki unavailable.");
            }
            denied |= cause instanceof AccessDeniedException || cause instanceof SecurityException;
            missing |= cause instanceof NoSuchFileException;
            invalidPath |= cause instanceof InvalidPathException;
            linkage |= cause instanceof LinkageError;
            invalidConfig |= cause instanceof java.security.InvalidParameterException;
            unsupported |= cause instanceof java.security.NoSuchAlgorithmException || cause instanceof java.security.NoSuchProviderException;
        }
        Issue issue = code == null ? null : ISSUES.get(code);
        String detail = issue == null ? "" : " " + issue.problem() + " (" + code + ")";
        if (operation == Operation.LOGIN) {
            if (PIN_REJECTIONS.contains(code == null ? "" : code))
                return failure(AuthenticationFailure.Phase.PIN, AuthenticationFailure.Cause.PIN_REJECTED,
                        issue.problem() + " (" + code + ")", "Automatic PIN attempts are paused. " + issue.recovery());
            return failure(AuthenticationFailure.Phase.PIN, AuthenticationFailure.Cause.PIN_INDETERMINATE,
                    "The security device did not report whether it accepted the PIN." + detail,
                    "Automatic PIN attempts are paused. Check the device before explicitly choosing Retry certificate listing.");
        }
        if (operation == Operation.CERTIFICATES)
            return failure(AuthenticationFailure.Phase.PROVIDER, AuthenticationFailure.Cause.CERTIFICATE,
                    "The token login completed, but its certificates and private-key entries could not be prepared." + detail,
                    issue == null ? "Check the token's certificates and key access in its middleware application." : issue.recovery());
        if (issue != null) {
            var result = failure(AuthenticationFailure.Phase.PROVIDER, AuthenticationFailure.Cause.CONFIGURATION,
                    issue.problem() + " (" + code + ")", issue.recovery());
            if (Set.of("CKR_SLOT_ID_INVALID", "CKR_TOKEN_NOT_PRESENT", "CKR_TOKEN_NOT_RECOGNIZED", "CKR_TOKEN_NOT_INITIALIZED", "CKR_DEVICE_REMOVED", "CKR_DEVICE_ERROR").contains(code))
                return result.atInput(AuthenticationFailure.Input.SECURITY_DEVICE);
            return code.equals("CKR_LIBRARY_LOAD_FAILED") ? result.atInput(AuthenticationFailure.Input.MIDDLEWARE) : result;
        }
        if (index) return failure(AuthenticationFailure.Phase.PROVIDER, AuthenticationFailure.Cause.CONFIGURATION,
                "The saved security-device selection is no longer available.",
                "Refresh the security devices and select a certificate again.").atInput(AuthenticationFailure.Input.SECURITY_DEVICE);
        if (providerMissing || unsupported) return failure(AuthenticationFailure.Phase.PROVIDER, AuthenticationFailure.Cause.CONFIGURATION,
                "Burp's Java runtime has no available SunPKCS11 provider service.", "Use a Java runtime with SunPKCS11 support.");
        if (denied) return failure(AuthenticationFailure.Phase.PROVIDER, AuthenticationFailure.Cause.CONFIGURATION,
                "Access to the PKCS#11 middleware or its configuration was denied.", "Check file permissions and Java provider access for Burp.").atInput(AuthenticationFailure.Input.MIDDLEWARE);
        if (missing || invalidPath) return failure(AuthenticationFailure.Phase.PROVIDER, AuthenticationFailure.Cause.CONFIGURATION,
                operation == Operation.MODULE ? "The configured PKCS#11 middleware file was not found or its path is invalid." : "A file needed to initialize the PKCS#11 provider was not found.",
                operation == Operation.MODULE ? "Choose an existing middleware file using an absolute path." : "Check the middleware installation and Burp's temporary-file access.");
        if (linkage) return failure(AuthenticationFailure.Phase.PROVIDER, AuthenticationFailure.Cause.CONFIGURATION,
                "Java could not load or link the PKCS#11 native library.", "Check that the library matches Burp's architecture and that its native dependencies are installed.").atInput(AuthenticationFailure.Input.MIDDLEWARE);
        if (invalidConfig) return failure(AuthenticationFailure.Phase.PROVIDER, AuthenticationFailure.Cause.CONFIGURATION,
                "Java rejected the PKCS#11 provider configuration.", "Check the middleware file, then choose the certificate again.");
        return failure(AuthenticationFailure.Phase.PROVIDER, AuthenticationFailure.Cause.CONFIGURATION,
                operation == Operation.MODULE ? "The configured PKCS#11 middleware file could not be opened." : operation == Operation.DISCOVERY
                        ? "Security-device discovery failed; the middleware supplied no recognized cause." : "The PKCS#11 provider failed during initialization; the middleware supplied no recognized cause.", "");
    }

    /** @param phase Observed boundary. @param cause Safe disposition. @param problem Safe text. @param recovery Evidence-based action. @return Failure with no raw cause. */
    private static AuthenticationFailure failure(AuthenticationFailure.Phase phase, AuthenticationFailure.Cause cause, String problem, String recovery) {
        return new AuthenticationFailure(phase, cause, problem, recovery);
    }
}
