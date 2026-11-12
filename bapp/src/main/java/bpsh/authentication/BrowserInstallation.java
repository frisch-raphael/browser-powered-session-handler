package bpsh.authentication;

import java.nio.file.Path;
import java.util.function.BooleanSupplier;

/** Application boundary for user-local browser selection; exposes no driver or UI implementation. */
public interface BrowserInstallation {
    /** Presentation-safe location of an installed executable.
     * @param executable Resolved installed executable. @param explicit Whether the user selected it explicitly.
     */
    record Selection(Path executable, boolean explicit) {}
    /** @return Raw user-local executable selection, or empty for automatic discovery. */
    String executableOverride();
    /** @param value Raw user selection, retained even while invalid. */
    void setExecutableOverride(String value);
    /** Resolves installation metadata on a worker without starting a browser.
     * @param deadlineNanos Original monotonic budget. @param cancelled Discovery cancellation.
     * @return Resolved presentation metadata. @throws AuthenticationFailure On an observed prerequisite failure.
     */
    Selection discover(long deadlineNanos, BooleanSupplier cancelled) throws AuthenticationFailure;
}
