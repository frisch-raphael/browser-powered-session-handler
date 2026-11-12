package bpsh.burp.ui;

import bpsh.authentication.BrowserInstallation;
import burp.api.montoya.persistence.Preferences;

/** User-local browser selection, separate from project and journey persistence. */
public final class BrowserRuntimePreferences {
    private static final String KEY = "bpsh.browser.executable";
    private final Preferences preferences;
    private final BrowserInstallation settings;
    /** @param preferences Host user preferences or null in a local fixture. @param settings Runtime selection. */
    public BrowserRuntimePreferences(Preferences preferences, BrowserInstallation settings) {
        this.preferences = preferences; this.settings = java.util.Objects.requireNonNull(settings);
        if (preferences != null) try {
            String saved = preferences.getString(KEY); if (saved != null) settings.setExecutableOverride(saved);
        } catch (RuntimeException ignored) { /* Host preference availability must not prevent editing. */ }
    }
    /** @param value Raw executable selection or empty for automatic detection. */
    public void select(String value) {
        settings.setExecutableOverride(value);
        if (preferences != null) try { if (value.isEmpty()) preferences.deleteString(KEY); else preferences.setString(KEY, value); }
        catch (RuntimeException error) { throw new IllegalStateException("This browser selection applies for this session but could not be saved. Select it again after reloading the extension."); }
    }
}
