package bpsh.browser;

import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.AuthStep;
import bpsh.journey.AuthStepSequence;
import bpsh.journey.SecretStore;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.ElementHandle;
import com.microsoft.playwright.Frame;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.TimeoutError;
import com.microsoft.playwright.options.LoadState;
import com.microsoft.playwright.options.WaitForSelectorState;
import java.util.Arrays;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/** Executes a validated sequence with explicit current page/frame and opener-owned popup expectations. */
final class BrowserStepExecutor implements AutoCloseable {
    private final BrowserContext context;
    private final Map<String, Page> pages = new HashMap<>();
    private final Map<Page, Pending> openers = new IdentityHashMap<>();
    private final Map<String, Pending> expected = new HashMap<>();
    private final Consumer<Page> pageListener = this::opened;
    private Page page;
    private Frame frame;
    private AuthenticationFailure callbackFailure;

    private static final class Pending {
        final AuthStep.Popup declaration;
        boolean armed;
        long expires;
        int arrivals;
        Pending(AuthStep.Popup declaration) { this.declaration = declaration; }
    }

    /** Installs popup observation before the initial page navigates. */
    BrowserStepExecutor(BrowserContext context, Page main, java.util.List<AuthStep.Definition> steps) {
        AuthStepSequence.validate(steps);
        this.context = context; page = main; frame = main.mainFrame(); pages.put("main", main);
        context.onPage(pageListener);
    }

    private void opened(Page child) {
        Page opener = child.opener();
        Pending pending = openers.get(opener);
        if (pending == null || !pending.armed) return;
        if (++pending.arrivals > 1) {
            callbackFailure = failure(AuthenticationFailure.Cause.POPUP_AMBIGUOUS,
                    "Several popups opened from the expected page. Keep only the popup needed for this login.");
            return;
        }
        if (System.nanoTime() - pending.expires > 0) return;
        pages.put(pending.declaration.pageRef(), child);
    }

    /** Runs one action with the original attempt budget and separately owned secret values. */
    void execute(AuthStep.Definition step, SecretStore.Values values, int actionTimeoutMs,
            long deadline, BooleanSupplier cancelled) throws AuthenticationFailure {
        check(deadline, cancelled);
        double timeout = AuthenticationFailure.remainingMs(actionTimeoutMs, deadline, cancelled);
        if (step.type() == AuthStep.Type.SWITCH_PAGE) {
            String name = ((AuthStep.PageTarget) step.operation()).pageRef();
            await(name, deadline, cancelled);
            page = pages.get(name); frame = page == null ? null : page.mainFrame();
        }
        active(step.type() == AuthStep.Type.SWITCH_PAGE || step.type() == AuthStep.Type.MAIN_FRAME || step.type() == AuthStep.Type.CLOSE_PAGE);
        page.setDefaultTimeout(timeout); page.setDefaultNavigationTimeout(timeout);
        Pending pending = openers.get(page);
        if (pending != null && pending.declaration.triggerStepId().equals(step.id())) {
            pending.armed = true;
            pending.expires = Math.min(deadline, System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(actionTimeoutMs));
        }
        try {
        switch (step.type()) {
            case CLICK -> frame.locator(step.selector()).click();
            case INPUT -> frame.locator(step.selector()).fill(step.value());
            case SECURE_INPUT -> {
                char[] value = values.stepValue(step.id());
                if (value == null) throw failure(AuthenticationFailure.Cause.MISSING_SECRET, "Enter the secret for this step.");
                try { frame.locator(step.selector()).fill(new String(value)); } finally { Arrays.fill(value, '\0'); }
            }
            case SET_CHECKED -> {
                var locator = frame.locator(step.selector()); boolean checked = ((AuthStep.Checked) step.operation()).checked();
                if (!checked && Boolean.TRUE.equals(locator.evaluate("e => e instanceof HTMLInputElement && e.type === 'radio'")))
                    throw failure(AuthenticationFailure.Cause.CONFIGURATION, "Radio buttons can only be selected. Choose Checked for this step.");
                locator.setChecked(checked);
            }
            case SELECT_OPTIONS -> {
                var locator = frame.locator(step.selector()); var options = ((AuthStep.Options) step.operation()).values();
                if (options.size() != 1 && !Boolean.TRUE.equals(locator.evaluate("e => e instanceof HTMLSelectElement && e.multiple")))
                    throw failure(AuthenticationFailure.Cause.CONFIGURATION, "This dropdown requires one option value. Only a multi-select dropdown accepts several values or an empty list.");
                locator.selectOption(options.toArray(String[]::new));
            }
            case PRESS_KEY -> frame.locator(step.selector()).press(((AuthStep.Key) step.operation()).key());
            case EXPECT_POPUP -> {
                if (pending != null && !pages.containsKey(pending.declaration.pageRef()))
                    throw failure(AuthenticationFailure.Cause.POPUP_AMBIGUOUS, "The previous expected popup has not opened. Switch to it before expecting another popup from this page.");
                var next = new Pending((AuthStep.Popup) step.operation()); openers.put(page, next); expected.put(next.declaration.pageRef(), next);
            }
            case SWITCH_PAGE -> { }
            case ENTER_FRAME -> enterFrame(step.selector(), timeout, deadline, cancelled);
            case PARENT_FRAME -> {
                Frame parent = frame.parentFrame();
                if (parent == null) throw failure(AuthenticationFailure.Cause.FRAME_DETACHED, "There is no outer frame. Use Leave all frames to return to the page.");
                frame = parent;
            }
            case MAIN_FRAME -> frame = page.mainFrame();
            case CLOSE_PAGE -> { page.close(); page = null; frame = null; }
            case WAIT_LOAD_STATE -> frame.waitForLoadState(switch (step.state() == null ? "load" : step.state()) {
                case "domcontentloaded" -> LoadState.DOMCONTENTLOADED; case "networkidle" -> LoadState.NETWORKIDLE; default -> LoadState.LOAD;
            });
            case WAIT_URL -> { if ("exact".equals(step.state())) frame.waitForURL(url -> url.equals(step.urlPattern())); else frame.waitForURL(step.urlPattern()); }
            case WAIT_SELECTOR -> frame.locator(step.selector()).waitFor(new com.microsoft.playwright.Locator.WaitForOptions().setState(
                    switch (step.state() == null ? "visible" : step.state()) {
                        case "hidden" -> WaitForSelectorState.HIDDEN; case "attached" -> WaitForSelectorState.ATTACHED;
                        case "detached" -> WaitForSelectorState.DETACHED; default -> WaitForSelectorState.VISIBLE;
                    }));
            case WAIT_TIME -> {
                long end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(step.durationMs());
                while (end - System.nanoTime() > 0) { check(deadline, cancelled); pump(Math.min(50, Math.max(0.001, (end - System.nanoTime()) / 1_000_000.0))); }
            }
        }
        } catch (com.microsoft.playwright.PlaywrightException error) {
            AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.STEP, deadline, cancelled);
            active(false); throw error;
        }
        check(deadline, cancelled);
    }

    private void enterFrame(String selector, double timeout, long deadline, BooleanSupplier cancelled) throws AuthenticationFailure {
        long end = Math.min(deadline, System.nanoTime() + TimeUnit.MILLISECONDS.toNanos((long) timeout));
        do {
            check(deadline, cancelled);
            page.setDefaultTimeout(Math.max(1, (end - System.nanoTime()) / 1_000_000.0));
            ElementHandle element = frame.locator(selector).elementHandle();
            try {
                if (!Boolean.TRUE.equals(element.evaluate("e => e instanceof HTMLIFrameElement || e instanceof HTMLFrameElement")))
                    throw failure(AuthenticationFailure.Cause.CONFIGURATION, "Choose an embedded frame element for Enter frame.");
                Frame child = element.contentFrame();
                if (child != null && child.parentFrame() == frame) { frame = child; return; }
            } finally { element.dispose(); }
            pump(10);
        } while (end - System.nanoTime() > 0);
        throw failure(AuthenticationFailure.Cause.FRAME_DETACHED, "The embedded frame is unavailable. Review its selector or record the login again.");
    }

    private void active(boolean resetFrame) throws AuthenticationFailure {
        if (page == null || page.isClosed()) throw failure(AuthenticationFailure.Cause.PAGE_CLOSED, "The selected page is closed. Choose an open page with Switch page.");
        if (!resetFrame && (frame == null || frame.isDetached()))
            throw failure(AuthenticationFailure.Cause.FRAME_DETACHED, "The selected frame is no longer available. Use Leave all frames, then enter the frame again.");
    }

    private void await(String name, long deadline, BooleanSupplier cancelled) throws AuthenticationFailure {
        Pending pending = expected.get(name);
        while (!pages.containsKey(name)) {
            check(deadline, cancelled);
            if (pending == null || !pending.armed || pending.expires - System.nanoTime() <= 0)
                throw failure(AuthenticationFailure.Cause.POPUP_TIMEOUT, "The expected popup did not open. Review its opening step and test again.");
            pump(Math.min(50, Math.max(0.001, (pending.expires - System.nanoTime()) / 1_000_000.0)));
        }
    }

    /** Waits for unresolved popup declarations only while credentials have not completed the run. */
    void finish(long deadline, BooleanSupplier cancelled, BooleanSupplier completed) throws AuthenticationFailure {
        for (var entry : expected.entrySet()) {
            while (!completed.getAsBoolean() && !pages.containsKey(entry.getKey())) {
                check(deadline, cancelled); pump(25);
            }
        }
        if (!completed.getAsBoolean()) check(deadline, cancelled);
    }

    private void check(long deadline, BooleanSupplier cancelled) throws AuthenticationFailure {
        AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.STEP, deadline, cancelled);
        if (callbackFailure != null) throw callbackFailure;
        for (var pending : expected.values()) if (pending.armed && !pages.containsKey(pending.declaration.pageRef()) && System.nanoTime() - pending.expires >= 0)
            throw failure(AuthenticationFailure.Cause.POPUP_TIMEOUT, "The expected popup did not open. Review its opening step and test again.");
    }

    /** Pumps context events even when the initial page has closed. */
    void pump(double milliseconds) {
        try { context.waitForCondition(() -> false, new BrowserContext.WaitForConditionOptions().setTimeout(milliseconds)); }
        catch (TimeoutError ignored) { /* one bounded event-pump slice */ }
    }

    private static AuthenticationFailure failure(AuthenticationFailure.Cause cause, String message) {
        return new AuthenticationFailure(AuthenticationFailure.Phase.STEP, cause, message);
    }

    @Override public void close() { context.offPage(pageListener); }
}
