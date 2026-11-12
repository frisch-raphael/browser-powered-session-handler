package bpsh.authentication;

/** Attempts every owned cleanup without retaining potentially sensitive third-party exception text. */
public final class ServiceCleanup {
    private ServiceCleanup() {}
    /** Reports incomplete cleanup only after all actions have been attempted. */
    public static void close(Runnable... actions) {
        boolean failed = false;
        for (Runnable action : actions) try { action.run(); }
        catch (RuntimeException | LinkageError failure) { failed = true; }
        if (failed) throw new IllegalStateException("One or more owned resources did not finish cleanup.");
    }
}
