package bpsh.burp.ui;

import bpsh.journey.CredentialNames;
import bpsh.journey.JourneyDraft;
import java.awt.*;
import java.util.List;
import javax.swing.*;

/** Sanitized field-path guidance shared by editor validation and execution failures. */
final class JourneyValidationMessages {
    private JourneyValidationMessages() {}
    /**
     * Presents validated field paths as short user-facing captions without echoing input values.
     * @param message Redacted codec field path and reason.
     * @return Human-readable field/row guidance.
     */
    static String validationMessage(String message) {
        var step = java.util.regex.Pattern.compile("^steps\\[(\\d+)]\\.([^:]+):\\s*(.*)$").matcher(message);
        if (step.matches()) {
            String label = switch (step.group(2)) { case "selector" -> "Selector"; case "urlPattern" -> "URL pattern"; case "durationMs" -> "Duration"; case "value" -> "Text value"; case "state" -> "Condition"; case "checked" -> "State"; case "values" -> "Dropdown options"; case "key" -> "Enter key"; case "pageRef" -> "Page"; case "triggerStepId" -> "Opening step"; case "context" -> "Frame"; default -> "Setting"; };
            return "Step " + (Integer.parseInt(step.group(1)) + 1) + ", " + label + ": " + step.group(3);
        }
        if (message.startsWith("controls.requestWaitTimeoutMs") || message.startsWith("requestWaitTimeoutMs")) return "Request wait must be between 1 and 600 seconds.";
        if (message.startsWith("controls.attemptTimeoutMs") || message.startsWith("attemptTimeoutMs")) return "Login attempt timeout must be between 1 and 300 seconds.";
        if (message.startsWith("controls.cycleTimeoutMs") || message.startsWith("cycleTimeoutMs")) return "Total login timeout must cover the request wait and login attempt timeout, up to 1800 seconds.";
        int colon = message.indexOf(':'); if (colon < 0) return message;
        String path = message.substring(0, colon), label = path;
        String leaf = path.substring(path.lastIndexOf('.') + 1);
        if (leaf.equals("navigationTimeoutMs")) return "Browser action timeout must be between 1 and 300 seconds.";
        if (leaf.equals("tokenWaitTimeoutMs")) return "Final capture wait must be between 0.001 and 300 seconds.";
        if (leaf.equals("certificateSha256")) return "Choose a client certificate before running this journey.";
        label = switch (leaf) {
            case "navTimeout" -> "Browser action timeout (seconds)";
            case "tokenWait" -> "Final capture wait (seconds)";
            case "maxAge", "maxAgeSeconds" -> "Maximum cache age (seconds)";
            case "skew", "refreshSkewSeconds" -> "Refresh before expiry (seconds)";
            case "recoveryStatus", "statusCode" -> "Failure status";
            case "displayName" -> "Display name"; case "alias" -> "Tag alias"; case "authenticationUrl" -> "Login URL";
            case "modulePath" -> "Middleware file"; case "slot" -> "Security device";
            case "origins" -> "Additional authentication servers";
            case "trustedCaBundlePath" -> "Trusted CA";
            case "maxWaitingRequestsGlobal", "global" -> "Global limit";
            case "maxWaitingRequestsPerJourney", "per" -> "Per-journey limit";
            case "request" -> "Request wait (seconds)"; case "attempt" -> "Login attempt timeout (seconds)";
            case "cycle" -> "Total login timeout (seconds)";
            case "urlPrefix" -> "URL prefix";
            default -> label;
        };
        if (path.startsWith("browser.proxy")) label = "Proxy URL";
        if (path.equals("recovery.pattern")) label = "RE2 expression";
        var row = java.util.regex.Pattern.compile("extraction\\.tokens\\[(\\d+)\\]").matcher(path);
        String prefix = row.find() ? "Token " + (Integer.parseInt(row.group(1)) + 1) + ", " : "";
        if (path.startsWith("extraction")) {
            if (path.endsWith("jsonPath")) label = "JSON path";
            else if (path.endsWith("startRegex")) label = "Start regex";
            else if (path.endsWith("endRegex")) label = "End regex";
            else if (path.endsWith("responseOrigin")) label = "Response origin";
            else if (path.endsWith("originUrl")) label = "Capture URL";
            else if (path.endsWith("pathSubstring")) label = "Path contains";
            else if (path.endsWith("domain")) label = "Cookie domain";
            else if (path.endsWith("path")) label = "Cookie path";
            else if (path.endsWith("name")) label = path.matches("extraction\\.tokens\\[\\d+]\\.name") ? "Credential name" : "Cookie name";
            else label = "Token selection";
            label = prefix + label;
        } else if (path.startsWith("injection")) label = "Inject into";
        return label + message.substring(colon);
    }
    /** @param message Redacted indexed field error. @param inputs Its exact configuration snapshot. @return Row/name context using only bounded valid credential names, never captured values or selectors. */
    static String validationMessage(String message, List<JourneyDraft.CredentialInput> inputs) {
        String guidance = validationMessage(message);
        var row = java.util.regex.Pattern.compile("^extraction\\.tokens\\[(\\d+)]").matcher(message);
        if (!row.find()) return guidance;
        int index = Integer.parseInt(row.group(1)); if (index >= inputs.size()) return guidance;
        String name = inputs.get(index).name().trim();
        String identity = "Credential " + (index + 1) + (CredentialNames.problem(name) == null ? " \"" + name + "\"" : "");
        if (message.startsWith("extraction.tokens[" + index + "].name:")) return identity + ": " + message.substring(message.indexOf(':') + 1).stripLeading();
        String prefix = "Token " + (index + 1) + ", ";
        return identity + ", " + (guidance.startsWith(prefix) ? guidance.substring(prefix.length()) : guidance);
    }
}
