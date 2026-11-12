package bpsh.authentication.credentials;

import bpsh.authentication.AuthenticationFailure;
import bpsh.pattern.BoundedRegex;
import com.google.re2j.Pattern;

/** Bounded RE2 session-detection grammar, independent of HTTP callbacks and recovery state. */
public final class RecoveryPattern {
    private RecoveryPattern() {}
    /**
     * Validates source and compiled-program bounds with safe position guidance on unsupported syntax.
     * @param source Configured expression, never included in diagnostic output.
     * @return DOTALL/find-style RE2 pattern; callers invoke matcher.find rather than matches.
     * @throws AuthenticationFailure If empty, oversized, unsupported or above 10,000 instructions.
     */
    public static Pattern compile(String source) throws AuthenticationFailure {
        try {
            return BoundedRegex.compile(source, Pattern.DOTALL);
        } catch (BoundedRegex.Failure ex) {
            throw invalidPattern(switch (ex.reason()) {
                case SOURCE -> "The recovery expression must contain 1-4096 UTF-8 bytes.";
                case COMPLEXITY -> "The session-detection expression is too complex.";
                case SYNTAX -> "The recovery expression uses unsupported or invalid RE2 syntax"
                        + (ex.syntaxIndex() >= 0 ? " at position " + ex.syntaxIndex() + "." : ".");
            });
        }
    }
    /**
     * Explains a regex constraint or unsupported syntax without echoing pattern or response contents.
     *
     * @param problem Safe regex constraint/position.
     * @return Terminal correction without echoing expression or response data.
     */
    private static AuthenticationFailure invalidPattern(String problem) { return new AuthenticationFailure(AuthenticationFailure.Phase.SETUP, AuthenticationFailure.Cause.CONFIGURATION, problem,
            "Correct the session-detection expression using supported RE2 syntax."); }
}
