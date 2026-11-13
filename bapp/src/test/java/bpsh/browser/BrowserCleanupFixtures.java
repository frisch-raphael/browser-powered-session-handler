package bpsh.browser;

import bpsh.authentication.AuthenticationFailure;
import com.microsoft.playwright.Browser;
import java.lang.reflect.Proxy;
import java.time.Clock;

/** Injects an external protocol-close failure while retaining the real session's cleanup policy. */
public final class BrowserCleanupFixtures {
    private BrowserCleanupFixtures() {}

    public static BrowserSessionLauncher.Session failingSession() throws Exception {
        var launcher = new BrowserSessionLauncher(null, null, new AuthTrafficGuard(), Clock.systemUTC());
        var sessionConstructor = BrowserSessionLauncher.Session.class.getDeclaredConstructor(BrowserSessionLauncher.class);
        sessionConstructor.setAccessible(true);
        var session = sessionConstructor.newInstance(launcher);
        var browser = (Browser) Proxy.newProxyInstance(Browser.class.getClassLoader(), new Class<?>[]{Browser.class}, (proxy, method, args) -> {
            if (method.getName().equals("close")) throw new IllegalStateException("PRIVATE_CLOSE_CANARY");
            if (method.getName().equals("isConnected")) return true;
            throw new UnsupportedOperationException(method.getName());
        });
        var field = BrowserSessionLauncher.Session.class.getDeclaredField("browser"); field.setAccessible(true);
        var constructor = field.getType().getDeclaredConstructors()[0]; constructor.setAccessible(true);
        field.set(session, constructor.newInstance(launcher, browser, null));
        return session;
    }

    public static AuthenticationFailure failedLaunch(AuthenticationFailure primary) throws Exception {
        var close = BrowserSessionLauncher.class.getDeclaredMethod("closeAfterFailure", BrowserSessionLauncher.Session.class, AuthenticationFailure.class);
        close.setAccessible(true); close.invoke(null, failingSession(), primary);
        return primary;
    }
}
