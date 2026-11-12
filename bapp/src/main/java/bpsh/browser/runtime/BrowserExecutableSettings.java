package bpsh.browser.runtime;

/** Thread-safe per-user executable selection; empty selects automatic discovery. */
public final class BrowserExecutableSettings {
    private volatile String override = "";
    /** @return Raw selected path, including invalid input retained for correction. */
    public String executableOverride() { return override; }
    /** @param value Raw path or empty for automatic selection. */
    public void setExecutableOverride(String value) { override = java.util.Objects.requireNonNull(value); }
}
