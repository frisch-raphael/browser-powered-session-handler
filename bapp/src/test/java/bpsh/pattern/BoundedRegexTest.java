package bpsh.pattern;

import bpsh.authentication.AuthenticationFailure;
import bpsh.authentication.credentials.RecoveryPattern;
import com.google.re2j.Pattern;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Checks actual RE2 bounds, matching flags and safe recovery diagnostics. */
class BoundedRegexTest {
    @Test void boundedCompilationPreservesFlagsAndRedactsFailures() throws Exception {
        utf8SourceLimitAndProgramLimitAreIndependent();
        unsupportedSyntaxNeverLeaksExpressionOrOriginalException();
        assertTrue(BoundedRegex.compile("login", 0).matcher("https://example.test/login?x=1").find());
        assertFalse(BoundedRegex.compile("login", 0).matcher("/LOGIN").find());
        assertTrue(BoundedRegex.compile("(?i)login", 0).matcher("/LOGIN").find());
        assertFalse(BoundedRegex.compile("a.b", 0).matcher("a\nb").find());
        assertTrue(BoundedRegex.compile("a.b", Pattern.DOTALL).matcher("a\nb").find());
        assertTrue(RecoveryPattern.compile("a.b").matcher("a\nb").find());
    }

    private void utf8SourceLimitAndProgramLimitAreIndependent() throws Exception {
        assertNotNull(BoundedRegex.compile("a".repeat(4096), 0));
        assertNotNull(BoundedRegex.compile("é".repeat(2048), 0));
        for (String source : new String[] {"", "  ", "a".repeat(4097), "é".repeat(2049)})
            assertEquals(BoundedRegex.Reason.SOURCE, assertThrows(BoundedRegex.Failure.class,
                    () -> BoundedRegex.compile(source, 0)).reason());
        assertEquals(BoundedRegex.Reason.SOURCE, assertThrows(BoundedRegex.Failure.class,
                () -> BoundedRegex.compile(null, 0)).reason());
        assertEquals(BoundedRegex.Reason.COMPLEXITY, assertThrows(BoundedRegex.Failure.class,
                () -> BoundedRegex.compile("(a{100}){100}", 0)).reason());
    }

    private void unsupportedSyntaxNeverLeaksExpressionOrOriginalException() {
        String source = "private-secret(?=x)";
        var failure = assertThrows(BoundedRegex.Failure.class, () -> BoundedRegex.compile(source, 0));
        assertEquals(BoundedRegex.Reason.SYNTAX, failure.reason());
        assertNull(failure.getCause());
        assertFalse(failure.toString().contains("private-secret"));
        var recovery = assertThrows(AuthenticationFailure.class, () -> RecoveryPattern.compile(source));
        assertNull(recovery.getCause());
        assertFalse(recovery.getMessage().contains("private-secret"));
        assertTrue(recovery.getMessage().startsWith("The recovery expression uses unsupported or invalid RE2 syntax"));
        assertEquals("The recovery expression must contain 1-4096 UTF-8 bytes.",
                assertThrows(AuthenticationFailure.class, () -> RecoveryPattern.compile(" ")).problem());
        assertEquals("The session-detection expression is too complex.",
                assertThrows(AuthenticationFailure.class, () -> RecoveryPattern.compile("(a{100}){100}")).problem());
    }
}
