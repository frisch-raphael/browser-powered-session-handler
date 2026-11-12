package bpsh.burp.ui;

import bpsh.browser.runtime.BrowserExecutableSettings;
import burp.api.montoya.persistence.Preferences;
import java.lang.reflect.Proxy;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class BrowserRuntimePreferencesTest {
    static Preferences preferences(Map<String, String> values) {
        return (Preferences) Proxy.newProxyInstance(Preferences.class.getClassLoader(), new Class<?>[]{Preferences.class}, (proxy, method, args) -> {
            return switch (method.getName()) {
                case "getString" -> values.get(args[0]);
                case "setString" -> { values.put((String) args[0], (String) args[1]); yield null; }
                case "deleteString" -> { values.remove(args[0]); yield null; }
                default -> null;
            };
        });
    }
    static bpsh.authentication.BrowserInstallation installation(BrowserExecutableSettings settings, bpsh.browser.runtime.BurpBrowserResolver resolver) {
        return new bpsh.authentication.BrowserInstallation() {
            @Override public String executableOverride() { return settings.executableOverride(); }
            @Override public void setExecutableOverride(String value) { settings.setExecutableOverride(value); }
            @Override public Selection discover(long deadline, java.util.function.BooleanSupplier cancelled) throws bpsh.authentication.AuthenticationFailure {
                if (resolver == null) throw new AssertionError("Unexpected discovery");
                var result = resolver.resolve(deadline, cancelled);
                return new Selection(result.executable(), result.source() == bpsh.browser.runtime.BurpBrowserResolver.Source.EXPLICIT);
            }
        };
    }
    @Test void invalidOverrideIsUserLocalAndRetainedAcrossReloadUntilAutomaticIsSelected() {
        var values = new HashMap<String, String>(); var settings = new BrowserExecutableSettings();
        var preferences = preferences(values); var runtime = new BrowserRuntimePreferences(preferences, installation(settings, null));
        runtime.select(" invalid literal <browser> "); assertEquals(" invalid literal <browser> ", settings.executableOverride());
        assertEquals(Map.of("bpsh.browser.executable", " invalid literal <browser> "), values);
        var reloaded = new BrowserExecutableSettings(); new BrowserRuntimePreferences(preferences, installation(reloaded, null));
        assertEquals(" invalid literal <browser> ", reloaded.executableOverride());
        runtime.select(""); assertTrue(values.isEmpty()); assertEquals("", settings.executableOverride());
    }
}
