package bpsh.pattern;

import com.google.re2j.Pattern;
import com.google.re2j.PatternSyntaxException;
import java.nio.charset.StandardCharsets;

/** Shared bounded RE2 compilation without retaining expressions in failure diagnostics. */
public final class BoundedRegex {
    /** Prevents construction of this stateless compiler. */
    private BoundedRegex() {}

    /** Safe categories that callers translate into context-specific guidance. */
    public enum Reason { SOURCE, SYNTAX, COMPLEXITY }

    /** Carries only a safe reason and optional syntax position, never the original exception. */
    public static final class Failure extends Exception {
        private final Reason reason;
        private final int syntaxIndex;

        /** @param reason Safe failure category. @param syntaxIndex Position, or -1 when unavailable. */
        private Failure(Reason reason, int syntaxIndex) {
            super("Bounded regex compilation failed: " + reason);
            this.reason = reason;
            this.syntaxIndex = syntaxIndex;
        }

        /** @return Safe failure category. */
        public Reason reason() { return reason; }

        /** @return Syntax position, or -1 when unavailable. */
        public int syntaxIndex() { return syntaxIndex; }
    }

    /**
     * Compiles nonblank expressions within fixed source and program limits.
     * @param source Expression limited to 4096 UTF-8 bytes.
     * @param flags RE2 compilation flags chosen by the owning caller.
     * @return Pattern limited to 10,000 compiled instructions; callers choose find or matches.
     * @throws Failure For invalid source, unsupported syntax or excessive program size.
     */
    public static Pattern compile(String source, int flags) throws Failure {
        if (source == null || source.isBlank() || source.getBytes(StandardCharsets.UTF_8).length > 4096)
            throw new Failure(Reason.SOURCE, -1);
        try {
            Pattern compiled = Pattern.compile(source, flags);
            if (compiled.programSize() > 10_000) throw new Failure(Reason.COMPLEXITY, -1);
            return compiled;
        } catch (PatternSyntaxException ex) {
            throw new Failure(Reason.SYNTAX, ex.getIndex());
        }
    }
}
