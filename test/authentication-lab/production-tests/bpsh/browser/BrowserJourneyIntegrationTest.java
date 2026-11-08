package bpsh.browser;

import lab.auth.LoginFlows;

import bpsh.request.RequestSettings;
import bpsh.journey.editing.JourneyWorkspace;
import bpsh.authentication.credentials.AuthenticationResult;
import bpsh.burp.http.NativeTagResolver;
import bpsh.burp.http.SessionRecovery;
import bpsh.journey.AuthStep;
import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.JourneyDefinition;
import bpsh.browser.mtls.Pkcs11IdentityManager;
import bpsh.browser.runtime.BrowserRuntimeManager;
import bpsh.browser.runtime.PlaywrightDriverAdapter;
import bpsh.journey.SecretStore;
import bpsh.authentication.session.AuthenticationCoordinator;
import bpsh.authentication.session.CoordinatorFixtures;
import bpsh.support.AuthLabSupport;
import bpsh.support.IntegrationFixtures;
import bpsh.support.ProductionLabAdapter;
import bpsh.burp.ui.DiagnosticsTest;
import com.microsoft.playwright.BrowserType;
import java.lang.reflect.Field;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises production browser ownership/extraction with actual bundled Chromium and local origins. */
public class BrowserJourneyIntegrationTest {
    public static BrowserRuntimeManager runtime;
    public static Pkcs11IdentityManager identities;
    public static AuthTrafficGuard guard;
    public static BrowserFlowRunner runner;
    public static final java.util.concurrent.CopyOnWriteArrayList<BrowserFlowRunner.Lifecycle> resourceEvents = new java.util.concurrent.CopyOnWriteArrayList<>();
    public static AuthLabSupport controlledTargets;
    public static AuthLabSupport targets() throws Exception {
        if (controlledTargets == null) controlledTargets = new AuthLabSupport();
        return controlledTargets;
    }

    /** Fails if pinned assets are missing; this explicit suite never skips browser prerequisites. */
    public @BeforeAll static void setup() throws Exception {
        runtime = new BrowserRuntimeManager(); runtime.acquire(System.nanoTime() + TimeUnit.MINUTES.toNanos(5), () -> false);
        identities = new Pkcs11IdentityManager(); guard = new AuthTrafficGuard(); runner = new BrowserFlowRunner(runtime, identities, guard, Clock.systemUTC(), resourceEvents::add);
    }
    /** Releases only suite-owned services; the verified immutable browser cache remains reusable. */
    public @AfterAll static void shutdown() throws Exception {
        try { if (controlledTargets != null) controlledTargets.close(); }
        finally { if (runtime != null) runtime.close(); if (identities != null) identities.close(); if (guard != null) guard.close(); }
    }
    /** @param j Current fixture definition. @param values Session snapshot. @return Production-runner outcome under a finite attempt deadline. */
    public static AuthenticationResult run(JourneyDefinition j, SecretStore.Values values) throws Exception {
        return runner.run(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, j.id(), 1), j, values, false,
                System.nanoTime() + TimeUnit.SECONDS.toNanos(25), () -> false);
    }
    /** @param type Retained step kind. @param selector Optional selector. @param value Optional ordinary input/state/pattern. @return Stable-ID immutable fixture step. */
    public static AuthStep.Definition step(AuthStep.Type type, String selector, String value) {
        return new AuthStep.Definition(UUID.randomUUID(), type, selector, type == AuthStep.Type.INPUT ? value : null,
                type == AuthStep.Type.WAIT_LOAD_STATE ? value : null, type == AuthStep.Type.WAIT_URL ? value : null,
                type == AuthStep.Type.WAIT_TIME ? Integer.parseInt(value) : null);
    }

    private static AuthStep.Definition operation(AuthStep.Type type, String selector, AuthStep.Operation payload) {
        return new AuthStep.Definition(UUID.randomUUID(), type, selector, null, null, null, null, payload);
    }

    public @Test void explicitControlsNestedCrossOriginFramesAndPopupReplayProduceVerifiedOutput() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http(); var values = SecretStore.Values.empty()) {
            var observed = LoginFlows.journeyControls(origin.owner, cross.owner); cross.start(); origin.start();
            var open = step(AuthStep.Type.CLICK, "#open", null);
            var steps = List.of(
                    operation(AuthStep.Type.SET_CHECKED, "#check", new AuthStep.Checked(true)),
                    operation(AuthStep.Type.SET_CHECKED, "#check", new AuthStep.Checked(false)),
                    operation(AuthStep.Type.SET_CHECKED, "#radio", new AuthStep.Checked(true)),
                    operation(AuthStep.Type.SELECT_OPTIONS, "#single", new AuthStep.Options(List.of("admin"))),
                    operation(AuthStep.Type.SELECT_OPTIONS, "#multi", new AuthStep.Options(List.of())),
                    operation(AuthStep.Type.SELECT_OPTIONS, "#multi", new AuthStep.Options(List.of("", "blue,green"))),
                    operation(AuthStep.Type.PRESS_KEY, "#enter", new AuthStep.Key("Control+Enter")),
                    operation(AuthStep.Type.ENTER_FRAME, "#outer", new AuthStep.Context()),
                    operation(AuthStep.Type.ENTER_FRAME, "#inner", new AuthStep.Context()),
                    step(AuthStep.Type.INPUT, "#nested", "nested value"), step(AuthStep.Type.CLICK, "#framebutton", null),
                    new AuthStep.Definition(UUID.randomUUID(), AuthStep.Type.WAIT_URL, null, null, "exact", origin.url("/controls/inner?done").toString(), null),
                    step(AuthStep.Type.WAIT_SELECTOR, "#frame-done", null),
                    operation(AuthStep.Type.PARENT_FRAME, null, new AuthStep.Context()), step(AuthStep.Type.WAIT_SELECTOR, "#outer-marker", null),
                    operation(AuthStep.Type.MAIN_FRAME, null, new AuthStep.Context()),
                    operation(AuthStep.Type.EXPECT_POPUP, null, new AuthStep.Popup("popup-1", open.id())), open,
                    operation(AuthStep.Type.SWITCH_PAGE, null, new AuthStep.PageTarget("popup-1")),
                    step(AuthStep.Type.INPUT, "#popup-text", "popup value"), operation(AuthStep.Type.PRESS_KEY, "#popup-text", new AuthStep.Key("Enter")),
                    step(AuthStep.Type.WAIT_SELECTOR, "#submitted", null), operation(AuthStep.Type.CLOSE_PAGE, null, new AuthStep.Context()),
                    operation(AuthStep.Type.SWITCH_PAGE, null, new AuthStep.PageTarget("main")), step(AuthStep.Type.CLICK, "#finish", null));
            var result = run(IntegrationFixtures.journey(origin, steps), values);
            assertEquals("controls-token", result.token()); assertEquals("nested value", observed.nested.get());
            assertEquals("popup value", observed.popup.get()); assertEquals(1, observed.completed.get());
        }
    }

    public @Test void competingClosedAndMissingPopupsFailWithoutChoosingAnotherPage() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http(); var values = SecretStore.Values.empty()) {
            LoginFlows.journeyControls(origin.owner, cross.owner); cross.start(); origin.start();
            for (String scenario : List.of("double", "closed", "missing")) {
                var trigger = step(AuthStep.Type.CLICK, scenario.equals("missing") ? "#enter" : "#" + scenario, null);
                var steps = List.of(operation(AuthStep.Type.EXPECT_POPUP, null, new AuthStep.Popup("popup-1", trigger.id())), trigger,
                        step(AuthStep.Type.WAIT_TIME, null, scenario.equals("missing") ? "0" : "400"),
                        operation(AuthStep.Type.SWITCH_PAGE, null, new AuthStep.PageTarget("popup-1")));
                var base = IntegrationFixtures.journey(origin, steps);
                var journey = new JourneyDefinition(base.id(), base.displayName(), base.alias(), base.authenticationUrl(), false, steps,
                        new JourneyDefinition.Browser(true, null, 1000, 100), base.extraction(), base.injection(), base.cache(), null);
                var failure = assertThrows(AuthenticationFailure.class, () -> run(journey, values), scenario);
                assertEquals(scenario.equals("double") ? AuthenticationFailure.Cause.POPUP_AMBIGUOUS
                        : scenario.equals("closed") ? AuthenticationFailure.Cause.PAGE_CLOSED : AuthenticationFailure.Cause.POPUP_TIMEOUT, failure.reason(), scenario);
                assertFalse(failure.getMessage().contains(origin.url("/login").toString()));
            }
        }
    }

    public @Test void radioClearingAndMultipleValuesOnSingleSelectGiveActionableErrors() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http(); var values = SecretStore.Values.empty()) {
            LoginFlows.journeyControls(origin.owner, cross.owner); cross.start(); origin.start();
            for (var action : List.of(operation(AuthStep.Type.SET_CHECKED, "#radio", new AuthStep.Checked(false)),
                    operation(AuthStep.Type.SELECT_OPTIONS, "#single", new AuthStep.Options(List.of("guest", "admin"))))) {
                var failure = assertThrows(AuthenticationFailure.class, () -> run(IntegrationFixtures.journey(origin, List.of(action)), values));
                assertEquals(AuthenticationFailure.Cause.CONFIGURATION, failure.reason()); assertEquals(action.id(), failure.step().id());
                assertTrue(failure.getMessage().contains(action.type() == AuthStep.Type.SET_CHECKED ? "Radio buttons can only be selected" : "requires one option value"));
                assertFalse(failure.getMessage().contains(action.selector()));
            }
        }
    }

    public @Test void detachedFrameRequiresExplicitRecoveryAndWrongOpenerCannotSatisfyPopup() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http(); var values = SecretStore.Values.empty()) {
            LoginFlows.journeyControls(origin.owner, cross.owner); cross.start(); origin.start();
            var base = IntegrationFixtures.journey(origin, List.of());
            var identity = new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, base.id(), 1);
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(25);
            var launcher = new BrowserSessionLauncher(runtime, identities, guard, Clock.systemUTC());
            try (var session = launcher.open(identity, bpsh.journey.BrowserSetup.from(base), values, BrowserSessionLauncher.Visibility.HEADLESS,
                    false, deadline, () -> false, ignored -> {})) {
                var context = session.context(); var main = context.newPage();
                try (var executor = new BrowserStepExecutor(context, main, List.of())) {
                    main.navigate(origin.url("/login").toString());
                    executor.execute(operation(AuthStep.Type.ENTER_FRAME, "#outer", new AuthStep.Context()), values, 2000, deadline, () -> false);
                    executor.execute(operation(AuthStep.Type.ENTER_FRAME, "#inner", new AuthStep.Context()), values, 2000, deadline, () -> false);
                    main.evaluate("document.querySelector('#outer').remove()");
                    var detached = assertThrows(AuthenticationFailure.class, () -> executor.execute(step(AuthStep.Type.INPUT, "#nested", "must not reach main"), values, 1000, deadline, () -> false));
                    assertEquals(AuthenticationFailure.Cause.FRAME_DETACHED, detached.reason());
                    executor.execute(operation(AuthStep.Type.MAIN_FRAME, null, new AuthStep.Context()), values, 1000, deadline, () -> false);
                    var trigger = step(AuthStep.Type.CLICK, "#enter", null);
                    executor.execute(operation(AuthStep.Type.EXPECT_POPUP, null, new AuthStep.Popup("popup-1", trigger.id())), values, 2000, deadline, () -> false);
                    executor.execute(trigger, values, 2000, deadline, () -> false);
                    var other = context.newPage(); other.navigate(origin.url("/login").toString()); other.locator("#open").click();
                    var wrong = assertThrows(AuthenticationFailure.class, () -> executor.execute(operation(AuthStep.Type.SWITCH_PAGE, null,
                            new AuthStep.PageTarget("popup-1")), values, 2000, deadline, () -> false));
                    assertEquals(AuthenticationFailure.Cause.POPUP_TIMEOUT, wrong.reason());
                    assertFalse(main.isClosed());
                }
            }
        }
    }

    public @Test void pinnedPrivateRecorderReceivesStructuredUpdatesAndFlushesFinalValue() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http(); var values = SecretStore.Values.empty()) {
            LoginFlows.journeyControls(origin.owner, cross.owner); cross.start(); origin.start();
            var base = IntegrationFixtures.journey(origin, List.of()); long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(25);
            var launcher = new BrowserSessionLauncher(runtime, identities, guard, Clock.systemUTC());
            try (var session = launcher.open(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, base.id(), 1), bpsh.journey.BrowserSetup.from(base),
                    values, BrowserSessionLauncher.Visibility.HEADLESS, false, deadline, () -> false, ignored -> {});
                 var adapter = session.driver().recorder(session.context())) {
                adapter.start(5000); var page = session.context().newPage(); page.navigate(origin.url("/login").toString());
                page.waitForCondition(() -> Boolean.TRUE.equals(page.evaluate("async () => typeof window.__pw_recorderState === 'function' && (await window.__pw_recorderState()).mode === 'recording'")),
                        new com.microsoft.playwright.Page.WaitForConditionOptions().setTimeout(5000));
                page.locator("#enter").fill("first value"); page.locator("#enter").fill("final value");
                page.locator("#check").check(); page.locator("#single").selectOption("admin");
                page.locator("#enter").fill("tail draft"); page.locator("#enter").fill("last without blur");
                adapter.stop(5000); assertNull(adapter.failure());
                var names = new java.util.ArrayList<String>(); boolean updated = false; String lastFill = null;
                bpsh.browser.runtime.PlaywrightRecorderAdapter.Event event;
                while ((event = adapter.poll()) != null) {
                    try {
                        names.add(event.action().name());
                        if (event.action().name().equals("fill")) {
                            char[] text = event.action().value(); try { lastFill = new String(text); } finally { java.util.Arrays.fill(text, '\0'); }
                        }
                        updated |= event.kind() == bpsh.browser.runtime.PlaywrightRecorderAdapter.Kind.UPDATED;
                    } finally { event.close(); }
                }
                assertTrue(names.containsAll(List.of("fill", "check", "select"))); assertTrue(updated); assertEquals("last without blur", lastFill);
                page.locator("#enter").fill("after stop"); page.waitForTimeout(100); assertNull(adapter.poll());
            }
        }
    }

    public @Test void maintainedMetadataTracksPasswordHistoryAndActualNestedFrameSources() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http(); var values = SecretStore.Values.empty()) {
            LoginFlows.recording(origin.owner, cross.owner); cross.start(); origin.start();
            var base = IntegrationFixtures.journey(origin.url("/recording"), List.of());
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(40);
            var launcher = new BrowserSessionLauncher(runtime, identities, guard, Clock.systemUTC());
            try (var session = launcher.open(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, base.id(), 1), bpsh.journey.BrowserSetup.from(base),
                    values, BrowserSessionLauncher.Visibility.HEADLESS, false, deadline, () -> false, ignored -> {})) {
                var context = session.context(); var sources = new java.util.HashMap<String, com.microsoft.playwright.Frame>();
                bpsh.browser.runtime.PlaywrightRecorderAdapter.installMetadata(context, (source, args) -> {
                    assertSame(context, source.context()); assertEquals(1, args.length); sources.put((String) args[0], source.frame()); return null;
                });
                try (var adapter = session.driver().recorder(context)) {
                    adapter.start(5000); var page = context.newPage(); page.navigate(base.authenticationUrl().toString());
                    page.waitForCondition(() -> Boolean.TRUE.equals(page.evaluate("async () => typeof window.__pw_recorderState === 'function' && (await window.__pw_recorderState()).mode === 'recording'")),
                            new com.microsoft.playwright.Page.WaitForConditionOptions().setTimeout(5000));
                    page.locator("#username").fill("ordinary-first"); page.locator("#password").fill("secret-first");
                    page.locator("#show").click(); page.locator("#password").fill("secret-revealed");
                    page.locator("#replace-same").click(); page.locator("#password").fill("replacement-needs-logical-protection");
                    page.locator("#add-text").click(); page.locator("#later-text").fill("unknown-new-target");
                    page.locator("#username").fill("ordinary-existing");
                    page.locator("#reveal-before-fill").click(); page.locator("#reveal-first").fill("secret-before-first-fill");
                    page.locator("#add-shadow").click(); page.locator("#shadow-password").fill("secret-shadow");
                    page.locator("#shadow-text").fill("unknown-late-shadow");
                    var nested = page.frameLocator("#outer").frameLocator("#inner").locator("#nested");
                    nested.fill("nested-final-source");
                    for (var frame : List.copyOf(page.frames())) {
                        var status = bpsh.browser.runtime.PlaywrightRecorderAdapter.metadataStatus(frame, true);
                        assertTrue(status.available()); assertFalse(status.failed()); assertEquals(0, status.pending());
                    }
                    adapter.stop(5000); assertNull(adapter.failure());
                    var classifications = new java.util.HashMap<String, bpsh.browser.runtime.PlaywrightRecorderAdapter.Classification>();
                    boolean nestedSource = false;
                    bpsh.browser.runtime.PlaywrightRecorderAdapter.Event event;
                    while ((event = adapter.poll()) != null) {
                        try {
                            if (!event.action().name().equals("fill")) continue;
                            char[] text = event.action().value();
                            try {
                                String value = new String(text); classifications.put(value, event.action().metadata().classification());
                                var actual = sources.get(event.action().metadata().sourceKey()); assertNotNull(actual);
                                if (value.equals("nested-final-source")) {
                                    var target = BrowserTargets.resolve(event.action().selector(), actual);
                                    assertEquals(2, target.frames().size()); assertFalse(target.anyFrame()); nestedSource = true;
                                }
                            } finally { java.util.Arrays.fill(text, '\0'); }
                        } finally { event.close(); }
                    }
                    for (String value : List.of("secret-first", "secret-revealed", "secret-before-first-fill", "secret-shadow"))
                        assertEquals(bpsh.browser.runtime.PlaywrightRecorderAdapter.Classification.SECRET, classifications.get(value));
                    for (String value : List.of("ordinary-first", "ordinary-existing", "nested-final-source"))
                        assertEquals(bpsh.browser.runtime.PlaywrightRecorderAdapter.Classification.ORDINARY, classifications.get(value));
                    for (String value : List.of("replacement-needs-logical-protection", "unknown-new-target", "unknown-late-shadow"))
                        assertEquals(bpsh.browser.runtime.PlaywrightRecorderAdapter.Classification.UNKNOWN, classifications.get(value));
                    assertTrue(nestedSource);
                }
            }
        }
    }

    private static bpsh.journey.JourneyRecording.Request recordingRequest(JourneyDefinition base) {
        var identity = new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, base.id(), 1);
        return new bpsh.journey.JourneyRecording.Request(identity,
                new bpsh.journey.JourneyRecording.Stamp(identity.key(), 1, UUID.randomUUID()), bpsh.journey.BrowserSetup.from(base));
    }

    private static java.util.function.Consumer<bpsh.journey.JourneyRecording.Event> recordingResult(
            java.util.concurrent.CompletableFuture<bpsh.journey.JourneyRecording.Result> result) {
        return event -> {
            if (event.state() == bpsh.journey.JourneyRecording.State.REVIEW) result.complete(event.result());
            if (event.state() == bpsh.journey.JourneyRecording.State.CLOSED) result.completeExceptionally(new AssertionError(event.problem() == null ? "Recording closed without review" : event.problem().message()));
        };
    }

    public @Test void recordingWorkerProtectsReplacementTargetsAndStopsAfterTheFinalNestedFill() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http()) {
            LoginFlows.recording(origin.owner, cross.owner); cross.start(); origin.start();
            var base = IntegrationFixtures.journey(origin.url("/recording"), List.of());
            var lifecycle = new java.util.concurrent.CopyOnWriteArrayList<BrowserSessionLauncher.Lifecycle>();
            var launcher = new BrowserSessionLauncher(runtime, identities, guard, Clock.systemUTC(), lifecycle::add);
            try (var recorder = new BrowserJourneyRecorder(launcher, BrowserSessionLauncher.Visibility.HEADLESS, (context, control) -> {
                var page = context.pages().getFirst();
                page.locator("#username").fill("record-user"); page.locator("#password").fill("first-secret");
                page.locator("#show").click(); page.locator("#password").fill("revealed-secret");
                page.locator("#replace-same").click(); page.locator("#password").fill("replacement-secret");
                page.frameLocator("#outer").frameLocator("#inner").locator("#nested").fill("last nested value"); control.stop();
            })) {
                var frozen = new java.util.concurrent.CompletableFuture<bpsh.journey.JourneyRecording.Result>(); var setup = SecretStore.Values.empty();
                recorder.start(recordingRequest(base), setup, recordingResult(frozen));
                try (var result = frozen.get(45, TimeUnit.SECONDS); var values = result.copySecrets()) {
                    assertTrue(result.complete(), () -> result.problems().toString()); assertThrows(IllegalStateException.class, setup::pin);
                    var secrets = result.candidates().stream().filter(c -> c.step().type() == AuthStep.Type.SECURE_INPUT).toList();
                    assertEquals(3, secrets.size()); assertTrue(secrets.stream().noneMatch(bpsh.journey.JourneyRecording.Candidate::passwordUnclassified));
                    assertEquals(3, values.stepIds().size()); var captured = new java.util.HashSet<String>();
                    for (var step : secrets) {
                        char[] value = values.stepValue(step.step().id()); try { captured.add(new String(value)); } finally { java.util.Arrays.fill(value, '\0'); }
                    }
                    assertEquals(Set.of("first-secret", "revealed-secret", "replacement-secret"), captured);
                    assertTrue(result.candidates().stream().anyMatch(c -> c.step().type() == AuthStep.Type.INPUT && "last nested value".equals(c.step().value())));
                    bpsh.journey.AuthStepSequence.validate(result.candidates().stream().map(bpsh.journey.JourneyRecording.Candidate::step).toList());
                    assertEquals(BrowserSessionLauncher.ResourceEvent.BROWSER_CLOSED, lifecycle.getLast().event());
                    var rejected = SecretStore.Values.empty();
                    assertThrows(IllegalStateException.class, () -> recorder.start(recordingRequest(base), rejected, ignored -> {}));
                    assertThrows(IllegalStateException.class, rejected::pin);
                }
            }
        }
    }

    public @Test void rapidSubmitRecordingReplaysWithTheRetainedPasswordInAFreshContext() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http()) {
            var observed = LoginFlows.recording(origin.owner, cross.owner); cross.start(); origin.start();
            var base = IntegrationFixtures.journey(origin.url("/recording"), List.of());
            try (var recorder = new BrowserJourneyRecorder(new BrowserSessionLauncher(runtime, identities, guard, Clock.systemUTC()), BrowserSessionLauncher.Visibility.HEADLESS, (context, control) -> {
                var page = context.pages().getFirst(); page.locator("#username").fill("record-user"); page.locator("#password").fill("record-secret");
                page.locator("#submit").click(); control.stop();
            })) {
                var frozen = new java.util.concurrent.CompletableFuture<bpsh.journey.JourneyRecording.Result>();
                recorder.start(recordingRequest(base), SecretStore.Values.empty(), recordingResult(frozen));
                try (var result = frozen.get(45, TimeUnit.SECONDS); var values = result.copySecrets()) {
                    assertTrue(result.complete(), () -> result.problems().toString()); var steps = result.candidates().stream().map(bpsh.journey.JourneyRecording.Candidate::step).toList();
                    assertEquals(List.of(AuthStep.Type.INPUT, AuthStep.Type.SECURE_INPUT, AuthStep.Type.CLICK), steps.stream().map(AuthStep.Definition::type).toList());
                    var replay = new JourneyDefinition(base.id(), base.displayName(), base.alias(), base.authenticationUrl(), false, steps, base.browser(),
                            new JourneyDefinition.JsonExtraction(base.extraction() instanceof JourneyDefinition.JsonExtraction json ? json.responseOrigin() : origin.url("/"), "/recording-submit", "access_token"),
                            base.injection(), base.cache(), null);
                    observed.recordedSubmission.set(null); assertEquals("recording-token", run(replay, values).token());
                    String body = java.net.URLDecoder.decode(observed.recordedSubmission.get(), java.nio.charset.StandardCharsets.UTF_8);
                    assertTrue(body.contains("username=record-user")); assertTrue(body.contains("password=record-secret"));
                }
            }
        }
    }

    public @Test void recordedControlsFramesAndPopupReplayInAFreshContext() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http(); var proxy = new IntegrationFixtures.ForwardProxy(guard)) {
            var observed = LoginFlows.journeyControls(origin.owner, cross.owner); cross.start(); origin.start();
            var initial = IntegrationFixtures.journey(origin, List.of());
            var base = IntegrationFixtures.configured(initial, initial.authenticationUrl(), new JourneyDefinition.Browser(true,
                    new JourneyDefinition.Proxy(proxy.url()), 5000, 1000), initial.extraction(), null);
            try (var recorder = new BrowserJourneyRecorder(new BrowserSessionLauncher(runtime, identities, guard, Clock.systemUTC()), BrowserSessionLauncher.Visibility.HEADLESS, (context, control) -> {
                var page = context.pages().getFirst();
                page.locator("#check").check(); page.locator("#check").uncheck(); page.locator("#radio").check();
                page.locator("#single").selectOption("admin"); page.locator("#multi").selectOption(new String[0]);
                page.locator("#multi").selectOption(new String[]{"", "blue,green"}); page.locator("#enter").press("Control+Enter");
                var nested = page.frameLocator("#outer").frameLocator("#inner");
                nested.locator("#nested").fill("nested value"); nested.locator("#framebutton").click(); nested.locator("#frame-done").waitFor();
                var popup = page.waitForPopup(() -> page.locator("#open").click());
                popup.waitForCondition(() -> Boolean.TRUE.equals(popup.evaluate("async () => typeof window.__pw_recorderState === 'function' && (await window.__pw_recorderState()).mode === 'recording'")));
                popup.locator("#popup-text").fill("popup value"); popup.locator("#popup-text").press("Enter"); popup.locator("#submitted").waitFor();
                popup.close(); page.locator("#finish").click();
                page.waitForCondition(() -> observed.completed.get() == 1); control.stop();
            })) {
                var frozen = new java.util.concurrent.CompletableFuture<bpsh.journey.JourneyRecording.Result>();
                recorder.start(recordingRequest(base), SecretStore.Values.empty(), recordingResult(frozen));
                try (var result = frozen.get(45, TimeUnit.SECONDS); var values = result.copySecrets()) {
                    assertTrue(result.complete(), () -> result.problems().toString()); assertEquals(1, result.popups().size());
                    var popup = result.popups().getFirst();
                    var opening = result.candidates().stream().filter(c -> popup.openingSteps().contains(c.step().id())
                            && c.step().type() == AuthStep.Type.CLICK && c.frames().isEmpty()).toList();
                    assertEquals(1, opening.size(), "The actual opener must remain eligible for explicit review");
                    var raw = result.candidates().stream().map(c -> bpsh.journey.JourneyDraft.StepInput.fromDefinition(c.step())).toList();
                    var corrected = bpsh.journey.editing.JourneyDraftCompiler.placePopup(raw, popup.declarationId(), popup.pageRef(), opening.getFirst().step().id());
                    var steps = bpsh.journey.editing.JourneyDraftCompiler.executableSteps(corrected);
                    assertEquals(List.of(List.of(), List.of("", "blue,green")), steps.stream().filter(s -> s.type() == AuthStep.Type.SELECT_OPTIONS
                            && ((AuthStep.Options) s.operation()).values().size() != 1).map(s -> ((AuthStep.Options) s.operation()).values()).toList());
                    assertTrue(steps.stream().anyMatch(s -> s.type() == AuthStep.Type.CLOSE_PAGE));
                    var replay = new JourneyDefinition(base.id(), base.displayName(), base.alias(), base.authenticationUrl(), false, steps,
                            base.browser(), base.extraction(), base.injection(), base.cache(), null);
                    assertEquals(1, observed.popupSubmissions.get(), "One Enter gesture submits exactly once during recording");
                    assertEquals("controls-token", run(replay, values).token()); assertEquals(2, observed.completed.get());
                    assertEquals(2, observed.popupSubmissions.get(), "Replay must not duplicate Enter's implicit submit click");
                    assertTrue(proxy.seen.stream().map(IntegrationFixtures.Seen::path).toList().containsAll(List.of("/login", "/controls/outer", "/controls/inner", "/controls/popup")));
                    assertTrue(proxy.seen.stream().allMatch(s -> s.classification() == AuthTrafficGuard.Classification.OWNED));
                    assertTrue(proxy.seen.stream().allMatch(s -> s.agent().startsWith("Mozilla/") && !s.agent().contains("BPSHAuth/")));
                }
            }
        }
    }

    public @Test void closingAPopupImmediatelyAfterTypingRetainsTheFinalValueAndCloseOrder() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http()) {
            LoginFlows.journeyControls(origin.owner, cross.owner); cross.start(); origin.start();
            var base = IntegrationFixtures.journey(origin, List.of());
            try (var recorder = new BrowserJourneyRecorder(new BrowserSessionLauncher(runtime, identities, guard, Clock.systemUTC()), BrowserSessionLauncher.Visibility.HEADLESS, (context, control) -> {
                var page = context.pages().getFirst(); var popup = page.waitForPopup(() -> page.locator("#open").click());
                popup.waitForCondition(() -> Boolean.TRUE.equals(popup.evaluate("async () => typeof window.__pw_recorderState === 'function' && (await window.__pw_recorderState()).mode === 'recording'")));
                popup.locator("#popup-text").fill("last popup value"); popup.close(); control.stop();
            })) {
                var frozen = new java.util.concurrent.CompletableFuture<bpsh.journey.JourneyRecording.Result>();
                recorder.start(recordingRequest(base), SecretStore.Values.empty(), recordingResult(frozen));
                try (var result = frozen.get(45, TimeUnit.SECONDS); var values = result.copySecrets()) {
                    assertTrue(result.complete(), () -> result.problems().toString());
                    var steps = result.candidates().stream().map(bpsh.journey.JourneyRecording.Candidate::step).toList();
                    int fill = java.util.stream.IntStream.range(0, steps.size()).filter(i -> steps.get(i).type().requiresInputValue()).findFirst().orElseThrow();
                    var input = steps.get(fill); char[] captured = input.type() == AuthStep.Type.SECURE_INPUT ? values.stepValue(input.id()) : input.value().toCharArray();
                    try { assertArrayEquals("last popup value".toCharArray(), captured); } finally { java.util.Arrays.fill(captured, '\0'); }
                    assertEquals(AuthStep.Type.CLOSE_PAGE, steps.get(fill + 1).type()); assertEquals(1, result.popups().size());
                }
            }
        }
    }

    public @Test void recordingCancellationClosesItsWorkerWithoutPublishingAReview() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http()) {
            LoginFlows.recording(origin.owner, cross.owner); cross.start(); origin.start();
            var base = IntegrationFixtures.journey(origin.url("/recording"), List.of());
            var recorder = new BrowserJourneyRecorder(new BrowserSessionLauncher(runtime, identities, guard, Clock.systemUTC()), BrowserSessionLauncher.Visibility.HEADLESS, (context, control) -> control.cancel());
            try (recorder) {
                var finished = new java.util.concurrent.CompletableFuture<bpsh.journey.JourneyRecording.Event>(); var setup = SecretStore.Values.empty();
                recorder.start(recordingRequest(base), setup, event -> {
                    if (event.state() == bpsh.journey.JourneyRecording.State.REVIEW || event.state() == bpsh.journey.JourneyRecording.State.CLOSED) finished.complete(event);
                });
                var event = finished.get(30, TimeUnit.SECONDS); assertEquals(bpsh.journey.JourneyRecording.State.CLOSED, event.state());
                assertNull(event.result()); assertNull(event.problem()); assertThrows(IllegalStateException.class, setup::pin);
            }
            assertTrue(recorder.awaitClosed(5000));
        }
    }

    public @Test void sessionLossRecoveryUsesThreeSequentialFreshBrowsersAndReplaysEightActualRequestsOnce() throws Exception {
        long caseBegan=System.nanoTime();var processes=new ProductionLabAdapter.BrowserProcesses();Map<String,Object> observed;
        try {
        var lifecycle = new java.util.concurrent.CopyOnWriteArrayList<BrowserFlowRunner.Lifecycle>();
        try (var origin = IntegrationFixtures.http(); var secrets = new SecretStore()) {
            var fixture = LoginFlows.recovery(origin.owner);
            var loginAttempts = fixture.loginAttempts; var issuances = fixture.issuances; var protectedIngress = fixture.protectedIngress; var acceptedActions = fixture.acceptedActions;
            var acceptedToken = fixture.acceptedToken; origin.start(); var definition = IntegrationFixtures.journey(origin, List.of()); var registry = new JourneyWorkspace(secrets); CoordinatorFixtures.load(registry, List.of(definition));
            var observedRunner = new BrowserFlowRunner(runtime, identities, guard, Clock.systemUTC(), lifecycle::add);
            var clock = new CoordinatorFixtures.ManualRuntime(); clock.now = System.nanoTime(); clock.wall = java.time.Instant.now();
            // Advance only coordinator scheduling. Actual Chromium keeps its real monotonic deadline and cleanup.
            try (var coordinator = new AuthenticationCoordinator(registry, RequestSettings.Controls.defaults(), clock, (entry, recover, deadline, cancelled) -> {
                long remaining = deadline - clock.nanos(); long began = System.nanoTime();
                try (var values = SecretStore.Values.empty()) {
                    return observedRunner.run(entry.identity(), entry.definition(), values, recover, began + remaining, cancelled);
                } finally { clock.advance(java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - began)); }
            }, entry -> null); var recovery = new SessionRecovery(coordinator, clock::nanos)) {
                var entry = registry.snapshot().resolve(definition.alias()); var initialTicket = coordinator.acquire(List.of(entry)); clock.runWorker(); initialTicket.future().join();
                var initial = coordinator.peek(entry.identity()); var client = java.net.http.HttpClient.newHttpClient();
                var proof = client.send(java.net.http.HttpRequest.newBuilder(origin.url("/protected")).header("Authorization", "Bearer " + initial.value()).build(), java.net.http.HttpResponse.BodyHandlers.ofString());
                assertEquals(200, proof.statusCode()); assertEquals("fixture-account", proof.body()); acceptedToken.set(null);
                var resolver = new NativeTagResolver(registry, coordinator); var rule = new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null);
                var observations = new java.util.ArrayList<Integer>();
                for (int i = 0; i < 8; i++) {
                    String raw = "POST /protected HTTP/1.1\r\nHost: " + origin.url("/").getAuthority() + "\r\nAuthorization: Bearer stale\r\nX-Trace: original-" + i + "\r\nContent-Length: 9\r\n\r\nbody=data";
                    try (var operation = resolver.resolveAutomatic(raw.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1), List.of(new NativeTagResolver.Automatic(entry, rule)))) {
                        var resolved = operation.future().join(); String wire = new String(resolved.commit(), java.nio.charset.StandardCharsets.ISO_8859_1);
                        assertTrue(wire.contains("Bearer " + initial.value()));
                        recovery.record(100 + i, resolved.uses(), false, resolved.replayTemplate(raw.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1)));
                        var response = client.send(java.net.http.HttpRequest.newBuilder(origin.url("/protected")).header("Authorization", "Bearer " + initial.value()).POST(java.net.http.HttpRequest.BodyPublishers.ofString("body=data")).build(), java.net.http.HttpResponse.BodyHandlers.ofString());
                        observations.add(response.statusCode()); assertEquals(401, response.statusCode());
                    }
                }
                var decisions = new java.util.ArrayList<SessionRecovery.Decision>();
                for (int i = 0; i < 8; i++) decisions.add(recovery.receivedPlan(100 + i, observations.get(i), () -> null, false, true));
                assertEquals(1, clock.workers.size()); clock.runWorker(); clock.advance(5000); clock.runWorker(); clock.advance(15_000); clock.runWorker();
                for (int i = 0; i < 8; i++) try (var plan = decisions.get(i).replay().get(60, TimeUnit.SECONDS)) {
                    String wire = new String(plan.claim(), java.nio.charset.StandardCharsets.ISO_8859_1);
                    assertTrue(wire.contains("X-Trace: original-" + i)); assertTrue(wire.endsWith("body=data"));
                    String authorization = wire.lines().filter(line -> line.startsWith("Authorization:")).findFirst().orElseThrow().substring("Authorization:".length()).trim();
                    var response = client.send(java.net.http.HttpRequest.newBuilder(origin.url("/protected")).header("Authorization", authorization).header("X-Trace", "original-" + i)
                            .POST(java.net.http.HttpRequest.BodyPublishers.ofString("body=data")).build(), java.net.http.HttpResponse.BodyHandlers.ofString());
                    assertEquals(200, response.statusCode()); assertEquals("fixture-account", response.body());
                    recovery.record(200 + i, plan.uses(), false); assertNull(recovery.receivedPlan(200 + i, response.statusCode(), () -> null, false, true).replay());
                    assertThrows(AuthenticationFailure.class, plan::claim);
                }
                assertEquals(4, loginAttempts.get()); assertEquals(2, issuances.get()); assertEquals(17, protectedIngress.get()); assertEquals(9, acceptedActions.get());
                assertEquals(3, coordinator.status(entry.identity()).attempts()); assertTrue(coordinator.status(entry.identity()).acceptedUse());
                int browsers = 0, contexts = 0; var seen = new java.util.HashSet<Long>(); int opens = 0;
                for (var event : lifecycle) switch (event.event()) {
                    case BROWSER_OPEN -> { assertEquals(0, browsers); browsers++; opens++; assertTrue(seen.add(event.resourceId())); }
                    case CONTEXT_OPEN -> { assertEquals(0, contexts); contexts++; assertTrue(seen.add(event.resourceId())); }
                    case CONTEXT_CLOSED -> { assertEquals(1, contexts); contexts--; }
                    case BROWSER_CLOSED -> { assertEquals(0, contexts); assertEquals(1, browsers); browsers--; }
                }
                assertEquals(4, opens); assertEquals(0, browsers); assertEquals(0, contexts);
                observed=new java.util.LinkedHashMap<>();observed.put("loginRequests",loginAttempts.get());observed.put("issuedCredentials",issuances.get());observed.put("protectedIngress",protectedIngress.get());observed.put("acceptedRequests",acceptedActions.get());
                observed.put("recoveryAttempts",coordinator.status(entry.identity()).attempts());observed.put("originals",observations.size());observed.put("replays",decisions.size());observed.put("acceptedUse",coordinator.status(entry.identity()).acceptedUse());
                observed.put("browsersOpened",opens);observed.put("browsersClosed",lifecycle.stream().filter(event->event.event()==BrowserFlowRunner.ResourceEvent.BROWSER_CLOSED).count());
                observed.put("contextsOpened",lifecycle.stream().filter(event->event.event()==BrowserFlowRunner.ResourceEvent.CONTEXT_OPEN).count());observed.put("contextsClosed",lifecycle.stream().filter(event->event.event()==BrowserFlowRunner.ResourceEvent.CONTEXT_CLOSED).count());
                observed.put("distinctResources",seen.size());
                observed.put("events",lifecycle.stream().map(event->Map.of("event",event.event().name(),"resource",event.resourceId(),"parent",event.parentId())).toList());
            }
        }
        }finally{processes.close();}
        processes.requireObserved(4);observed.put("drivers",processes.drivers());observed.put("processes",processes.processes());observed.put("alive",processes.alive());
        AuthLabSupport.component("RUN.recovery.network-third-succeeds",observed,Map.of("startupMs",0L,"caseMs",TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-caseBegan),"cleanupMs",0L));
    }

    public @Test void retainedStepsAndSecureInputProduceNormalizedToken() throws Exception {
        var secure = step(AuthStep.Type.SECURE_INPUT, "#password", null);
        try (var origin = IntegrationFixtures.http()) {
            var posted = LoginFlows.normalizedForm(origin.owner); origin.start();
            var steps = List.of(step(AuthStep.Type.WAIT_LOAD_STATE, null, "load"), step(AuthStep.Type.INPUT, "#name", "fixture-user"), secure,
                    step(AuthStep.Type.WAIT_SELECTOR, "#submit", null), step(AuthStep.Type.WAIT_TIME, null, "10"), step(AuthStep.Type.CLICK, "#submit", null),
                    step(AuthStep.Type.WAIT_URL, null, "**/done"), step(AuthStep.Type.WAIT_LOAD_STATE, null, "domcontentloaded"),
                    step(AuthStep.Type.WAIT_LOAD_STATE, null, "networkidle"), step(AuthStep.Type.WAIT_SELECTOR, "#done", null));
            JourneyDefinition j = IntegrationFixtures.journey(origin, steps);
            j = IntegrationFixtures.configured(j, j.authenticationUrl(), new JourneyDefinition.Browser(true, null, 5000, 3000), j.extraction(), null);
            try (var values = new SecretStore.Values(null, Map.of(secure.id(), "fixture-password".toCharArray()))) {
                var result = run(j, values); assertEquals("fixture-token", result.token()); assertEquals(1, posted.get()); assertFalse(result.toString().contains("fixture-token"));
            }
        }
    }
    public @Test void namedJsonAndSeveralCookiesAreAcquiredTogether() throws Exception {
        try (var origin = IntegrationFixtures.http(); var values = SecretStore.Values.empty()) {
            LoginFlows.combinedOutputs(origin.owner, true, false).start();
            var base = IntegrationFixtures.journey(origin, List.of());
            var selection = new JourneyDefinition.CombinedExtraction(List.of(
                    new JourneyDefinition.NamedExtraction("access", base.extraction()),
                    new JourneyDefinition.NamedExtraction("session", new JourneyDefinition.CookieExtraction(origin.url("/"), "sid", null, "/")),
                    new JourneyDefinition.NamedExtraction("tenant", new JourneyDefinition.CookieExtraction(origin.url("/"), "tenant", null, "/"))));
            var journey = IntegrationFixtures.configured(base, base.authenticationUrl(), base.browser(), selection, null);
            var result = run(journey, values);
            assertEquals(Map.of("access", "access-value", "session", "session-value", "tenant", "tenant-value"), result.namedTokens());
            assertEquals(Map.of("sid", "session-value", "tenant", "tenant-value"), result.cookies());
            assertEquals("access-value", result.token()); assertFalse(result.toString().contains("access-value"));
        }
        var roles = List.of("B", "C1", "C2");
        try (var target = targets().prepare("BROW.basic.json");
             var prepared = ProductionLabAdapter.login(targets(), target, roles, "admin", "adminpass")) {
            ProductionLabAdapter.automaticAndTaggedProofs(targets(), target, prepared, "admin");
        }
    }

    public @org.junit.jupiter.api.TestFactory
    java.util.stream.Stream<org.junit.jupiter.api.DynamicTest> controlledJavaLoginAuthenticatesExpectedAccount() {
        return List.of("cookie-one", "cookie-two", "two-page", "csrf-cookie", "javascript", "interstitial", "invalid-credentials").stream().map(variant ->
                org.junit.jupiter.api.DynamicTest.dynamicTest("[case=BROW.basic." + variant + "]", () -> {
                    var roles = variant.equals("cookie-one") ? List.of("C1") : variant.equals("cookie-two") ? List.of("C1","C2") : List.of("B");
                    try (var target = targets().prepare("BROW.basic." + variant);
                         var prepared = ProductionLabAdapter.login(targets(), target, roles, "user2", variant.equals("invalid-credentials") ? "incorrect" : "pass2")) {
                        if (variant.equals("invalid-credentials")) {
                            var failure = assertThrows(AuthenticationFailure.class, () -> ProductionLabAdapter.run(targets(), target, prepared));
                            target.failure(failure, "AUTH_REJECTED");
                            assertTrue(target.snapshot().path("events").toString().contains("login-rejected-http-401"));
                            assertEquals(AuthenticationFailure.Cause.AUTH_REJECTED, failure.reason());
                            assertFalse(target.snapshot().path("events").toString().contains("login-completed"));
                        } else {
                            var result = ProductionLabAdapter.run(targets(), target, prepared);
                            target.prove(roles.stream().map(String::toLowerCase).collect(java.util.stream.Collectors.joining("_")), ProductionLabAdapter.credentials(result, roles), "user2");
                        }
                    }
                }));
    }

    public @org.junit.jupiter.api.TestFactory
    java.util.stream.Stream<org.junit.jupiter.api.DynamicTest> controlledRedirectsAuthenticateWithoutChangingMethodsOrLosingCookies() {
        return List.of("zero", "one", "multi", "cross-origin", "cookie-each-hop", "deep-link", "post-303", "post-307").stream().map(variant ->
                org.junit.jupiter.api.DynamicTest.dynamicTest("[case=BROW.redirect." + variant + "]", () -> {
                    try (var target = targets().prepare("BROW.redirect." + variant);
                         var prepared = ProductionLabAdapter.login(targets(), target, List.of("B"), "user2", "pass2")) {
                        var result = ProductionLabAdapter.run(targets(), target, prepared);
                        target.prove("b", ProductionLabAdapter.credentials(result, List.of("B")), "user2");
                        var hops = new ArrayList<String>(); target.snapshot().path("events").forEach(e -> { if (e.path("name").asText().startsWith("hop-")) hops.add(e.path("name").asText()); });
                        assertEquals(variant.equals("zero") ? 0 : variant.equals("one") || variant.startsWith("post-") ? 1 : 3, hops.size());
                        for (int i = 0; i < hops.size(); i++) assertEquals("hop-" + i + (variant.equals("post-307") ? "-POST" : "-GET"), hops.get(i));
                    }
                }));
    }

    public @org.junit.jupiter.api.TestFactory
    java.util.stream.Stream<org.junit.jupiter.api.DynamicTest> controlledCookieSelectionUsesTheCurrentApplicableCredential() {
        return List.of("idp-client-decoy", "early-cookie-rotated", "same-name-paths", "deleted-mid-flow", "ambiguous").stream().map(variant ->
                org.junit.jupiter.api.DynamicTest.dynamicTest("[case=BROW.cookie-selection." + variant + "]", () -> {
                    try (var target = targets().prepare("BROW.cookie-selection." + variant);
                         var prepared = ProductionLabAdapter.login(targets(), target, List.of("C1"), "user2", "pass2")) {
                        if (variant.equals("deleted-mid-flow") || variant.equals("ambiguous")) {
                            var failure = assertThrows(AuthenticationFailure.class, () -> ProductionLabAdapter.run(targets(), target, prepared));
                            target.failure(failure, "EXTRACTION");
                            assertEquals(AuthenticationFailure.Cause.EXTRACTION, failure.reason());
                            assertFalse(failure.problem().toLowerCase().contains("connection"));
                            if (variant.equals("ambiguous")) assertTrue(failure.problem().toLowerCase().contains("more than one cookie"));
                        } else {
                            var result = ProductionLabAdapter.run(targets(), target, prepared);
                            target.prove("c1", ProductionLabAdapter.credentials(result, List.of("C1")), "user2");
                            String control=variant.equals("idp-client-decoy")?"decoy-cookie-set":variant.equals("early-cookie-rotated")?"selected-cookie-rotated":"competing-path-cookie-set";
                            assertTrue(java.util.stream.StreamSupport.stream(target.snapshot().path("events").spliterator(),false).anyMatch(event->event.path("name").asText().equals(control)),"The competing or rotated cookie must actually be emitted before selection can qualify.");
                        }
                    }
                }));
    }
    public @org.junit.jupiter.api.TestFactory
    java.util.stream.Stream<org.junit.jupiter.api.DynamicTest> controlledResponseSurfacesProduceUsableCredentials() {
        return List.of("early-response", "late-response", "nested-json", "popup", "frame", "cors-fetch", "service-worker").stream().map(variant ->
                org.junit.jupiter.api.DynamicTest.dynamicTest("[case=BROW.surfaces." + variant + "]", () -> {
                    try (var target = targets().prepare("BROW.surfaces." + variant);
                         var prepared = ProductionLabAdapter.login(targets(), target, List.of("B"), "user2", "pass2")) {
                        var result = variant.equals("late-response") ? ProductionLabAdapter.runAtCheckpoint(targets(), target, prepared, "late-token", false)
                                : ProductionLabAdapter.run(targets(), target, prepared);
                        target.prove("b", ProductionLabAdapter.credentials(result, List.of("B")), "user2");
                        String kind = switch (variant) { case "early-response" -> "early"; case "late-response" -> "late"; case "nested-json" -> "nested"; case "cors-fetch" -> "cors"; case "service-worker" -> "worker"; default -> variant; };
                        assertTrue(java.util.stream.StreamSupport.stream(target.snapshot().path("events").spliterator(), false).anyMatch(event ->
                                event.path("name").asText().equals("token-emitted") && event.path("safeIds").toString().contains("\"value\":\"" + kind + "\"")));
                        // Close acknowledged in-flight target work before inspecting the final retained page observations.
                        target.close();
                        var state = target.snapshot(); assertFalse(state.path("truncated").asBoolean(), "Missing page observations cannot establish a pass.");
                        var required = switch (variant) {
                            case "early-response" -> List.of("page-early-ready");
                            case "late-response" -> List.of("page-late-ready", "late-token-requested");
                            case "nested-json" -> List.of("page-nested-ready");
                            case "popup" -> List.of("page-popup-parent-ready", "page-popup-parent-done");
                            case "frame" -> List.of("page-frame-parent-ready", "page-frame-parent-done");
                            case "cors-fetch" -> List.of("page-cors-ready", "page-cors-done", "cors-probe-requested", "page-cors-denied");
                            case "service-worker" -> List.of("page-worker-controlled", "page-worker-ready");
                            default -> throw new IllegalArgumentException();
                        };
                        var names = new java.util.HashSet<String>(); state.path("events").forEach(event -> names.add(event.path("name").asText()));
                        var missing = required.stream().filter(name -> !names.contains(name)).toList(); target.surfaceObservation(state, required, missing);
                        assertTrue(missing.isEmpty(), "The production browser ended without required application page observations: " + missing);
                        assertFalse(names.contains("page-cors-unexpected"), "The browser must deny JavaScript access to the unpermitted CORS response.");
                        assertTrue(names.stream().noneMatch(name -> name.endsWith("fixture-stage-failed")), "The application reported a JavaScript stage failure.");
                        if (variant.equals("early-response")) {
                            long tokenSequence = Long.MAX_VALUE, readySequence = -1;
                            for (var event : state.path("events")) {
                                if (event.path("name").asText().equals("token-emitted")) tokenSequence = Math.min(tokenSequence, event.path("sequence").asLong());
                                if (event.path("name").asText().equals("page-early-ready")) readySequence = event.path("sequence").asLong();
                            }
                            assertTrue(tokenSequence < readySequence, "Early response must precede the actual page-ready marker.");
                        }
                    }
                }));
    }

    public @org.junit.jupiter.api.TestFactory
    java.util.stream.Stream<org.junit.jupiter.api.DynamicTest> controlledRepeatedAttemptsDoNotReuseBrowserCookiesOrStorage() {
        return List.of("cookies", "local-storage", "session-storage", "service-worker").stream().map(kind ->
                org.junit.jupiter.api.DynamicTest.dynamicTest("[case=BROW.fresh." + kind + "]", () -> {
                    long started = System.nanoTime(), ready, checked; Map<String, Object> facts;
                    try (var target = targets().prepare("BROW.fresh." + kind);
                         var prepared = ProductionLabAdapter.login(targets(), target, List.of("B"), "user2", "pass2")) {
                        ready = System.nanoTime();
                        String definitionHash = ProductionLabAdapter.savedDefinitionHash(prepared);
                        assertEquals(target.url("fresh/" + kind + "/start"), prepared.definition.authenticationUrl());
                        target.freshPhase("PRIME");
                        var first = ProductionLabAdapter.run(targets(), target, prepared);
                        var firstProof = target.prove("b", ProductionLabAdapter.credentials(first, List.of("B")), "user2");
                        long primeSequence = freshEvent(target.snapshot(), kind, "PRIME", "present");
                        assertEquals(definitionHash, ProductionLabAdapter.savedDefinitionHash(prepared));
                        target.freshPhase("PROBE");
                        var second = ProductionLabAdapter.run(targets(), target, prepared);
                        var secondProof = target.prove("b", ProductionLabAdapter.credentials(second, List.of("B")), "user2");
                        assertEquals(first.identity(), second.identity(), "Both attempts must use the same saved identity/generation.");
                        assertEquals(definitionHash, ProductionLabAdapter.savedDefinitionHash(prepared));
                        assertNotEquals(firstProof.path("issuanceId").asText(), secondProof.path("issuanceId").asText(), "Each actual attempt must complete a new login.");
                        assertFalse(first.token().equals(second.token()), "The second proof must not reuse the first attempt's credential.");
                        target.close(); var state = target.snapshot(); long probeSequence = freshEvent(state, kind, "PROBE", "absent");
                        var logins = new ArrayList<Long>(); state.path("events").forEach(event -> { if (event.path("name").asText().equals("login-completed")) logins.add(event.path("sequence").asLong()); });
                        assertEquals(2, logins.size()); assertTrue(primeSequence < logins.getFirst());
                        assertTrue(logins.getFirst() < probeSequence && probeSequence < logins.getLast(), "The second attempt observes state before any second login/output issuance.");
                        var contexts = resourceEvents.stream().filter(event -> event.identity().journeyId().equals(prepared.definition.id()) && !event.bootstrap()
                                && event.event() == BrowserFlowRunner.ResourceEvent.CONTEXT_OPEN).toList();
                        assertEquals(2, contexts.size()); assertNotEquals(contexts.getFirst().resourceId(), contexts.getLast().resourceId());
                        for (var context : contexts) assertEquals(1, resourceEvents.stream().filter(event -> event.resourceId() == context.resourceId()
                                && event.event() == BrowserFlowRunner.ResourceEvent.CONTEXT_CLOSED).count());
                        int firstClose = java.util.stream.IntStream.range(0, resourceEvents.size()).filter(i -> resourceEvents.get(i).resourceId() == contexts.getFirst().resourceId()
                                && resourceEvents.get(i).event() == BrowserFlowRunner.ResourceEvent.CONTEXT_CLOSED).findFirst().orElseThrow();
                        assertTrue(firstClose < resourceEvents.indexOf(contexts.getLast()), "The first actual context must close before the second opens.");
                        target.freshObservation(definitionHash, firstProof, secondProof, primeSequence, probeSequence, logins.getLast(), state,
                                contexts.getFirst().resourceId(), contexts.getLast().resourceId());
                        var owned = ProductionLabAdapter.resources(target.id); assertEquals(2, owned.size());
                        assertEquals(contexts.getFirst().resourceId(), owned.getFirst().contextId()); assertEquals(contexts.getLast().resourceId(), owned.getLast().contextId());
                        var captured = new java.util.LinkedHashMap<String, Object>();
                        captured.put("sameDefinition", definitionHash.equals(ProductionLabAdapter.savedDefinitionHash(prepared)));
                        captured.put("firstAccount", firstProof.path("accountId").asText()); captured.put("secondAccount", secondProof.path("accountId").asText());
                        captured.put("differentIssuance", !firstProof.path("issuanceId").asText().equals(secondProof.path("issuanceId").asText()));
                        captured.put("differentToken", !first.token().equals(second.token()));
                        captured.put("primeSequence", primeSequence); captured.put("firstLoginSequence", logins.getFirst()); captured.put("probeSequence", probeSequence); captured.put("secondLoginSequence", logins.getLast());
                        captured.put("firstContext", owned.getFirst().contextId()); captured.put("secondContext", owned.getLast().contextId()); captured.put("firstClosedBeforeSecond", firstClose < resourceEvents.indexOf(contexts.getLast()));
                        captured.put("closedContexts", owned.stream().mapToInt(ProductionLabAdapter.AttemptResources::contextsClosed).sum());
                        captured.put("openedBrowsers", owned.stream().mapToInt(ProductionLabAdapter.AttemptResources::browsersOpened).sum()); captured.put("closedBrowsers", owned.stream().mapToInt(ProductionLabAdapter.AttemptResources::browsersClosed).sum());
                        captured.put("drivers", owned.stream().mapToInt(ProductionLabAdapter.AttemptResources::drivers).sum()); captured.put("processes", owned.stream().mapToInt(ProductionLabAdapter.AttemptResources::observedProcesses).sum());
                        captured.put("alive", owned.stream().mapToLong(ProductionLabAdapter.AttemptResources::alive).sum()); facts = Map.copyOf(captured); checked = System.nanoTime();
                    }
                    AuthLabSupport.component("BROW.fresh." + kind, facts, Map.of("startupMs", TimeUnit.NANOSECONDS.toMillis(ready - started),
                            "caseMs", TimeUnit.NANOSECONDS.toMillis(checked - ready), "cleanupMs", TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - checked)));
                }));
    }
    /** Requires the actual browser observation, including the positive prime control; fixture defaults cannot pass. */
    public static long freshEvent(com.fasterxml.jackson.databind.JsonNode state, String kind, String phase, String presence) {
        assertFalse(state.path("truncated").asBoolean()); var sequences = new ArrayList<Long>();
        state.path("events").forEach(event -> {
            if (!event.path("name").asText().equals(phase.equals("PRIME") ? "fresh-prime-observed" : "fresh-probe-observed")) return;
            var labels = new java.util.HashMap<String, String>(); event.path("safeIds").forEach(label -> labels.put(label.path("kind").asText(), label.path("value").asText()));
            assertEquals(Map.of("variant", kind, "phase", phase, "presence", presence), labels, "Actual stored/probed state must match the selected variant and phase.");
            sequences.add(event.path("sequence").asLong());
        });
        assertEquals(1, sequences.size(), "Require exactly one current browser state observation per attempt."); return sequences.getFirst();
    }
    public @org.junit.jupiter.api.TestFactory
    java.util.stream.Stream<org.junit.jupiter.api.DynamicTest> controlledRedirectFailuresPublishNoCredentialAndCloseTheirProcesses() {
        return List.of("missing-callback", "wrong-return", "missing-state", "loop", "unreachable-hop", "cancel-before-callback").stream().map(variant ->
                org.junit.jupiter.api.DynamicTest.dynamicTest("[case=BROW.redirect-failure." + variant + "]", () -> {
                    try (var target = targets().prepare("BROW.redirect-failure." + variant);
                         var prepared = ProductionLabAdapter.login(targets(), target, List.of("B"), "user2", "pass2")) {
                        var failure = assertThrows(AuthenticationFailure.class, () -> {
                            if (variant.equals("cancel-before-callback")) ProductionLabAdapter.runAtCheckpoint(targets(), target, prepared, "cancel-before-callback", true);
                            else ProductionLabAdapter.run(targets(), target, prepared);
                        });
                        String expected = variant.equals("unreachable-hop") ? "TRANSPORT" : variant.equals("cancel-before-callback") ? "CANCELLED" : "FINITE_NO_OUTPUT";
                        target.failure(failure, expected);
                        if (!expected.equals("FINITE_NO_OUTPUT")) assertEquals(expected, failure.reason().name());
                        var snapshot = target.snapshot(); assertFalse(snapshot.path("truncated").asBoolean());
                        assertTrue(java.util.stream.StreamSupport.stream(snapshot.path("events").spliterator(), false).anyMatch(event -> event.path("phase").asText().equals("HOP")));
                        assertFalse(snapshot.path("events").toString().contains("login-completed")); assertEquals(0, snapshot.path("counters").path("actions").asInt());
                    }
                }));
    }
    public @Test void earlyJsonAndCookieAttemptsStartWithFreshContextState() throws Exception {
        try (var origin = IntegrationFixtures.http(); var empty = SecretStore.Values.empty()) {
            var observation = LoginFlows.freshCookie(origin.owner); origin.start();
            JourneyDefinition j = IntegrationFixtures.journey(origin, List.of()); assertEquals("early-token", run(j, empty).token());
            JourneyDefinition cookie = IntegrationFixtures.configured(j, j.authenticationUrl(), j.browser(), new JourneyDefinition.CookieExtraction(origin.url("/"), "session", null, "/"), null);
            cookie = new JourneyDefinition(cookie.id(), cookie.displayName(), cookie.alias(), cookie.authenticationUrl(), false,
                    List.of(step(AuthStep.Type.CLICK, "#CANARY_SELECTOR", null), step(AuthStep.Type.WAIT_SELECTOR, "#CANARY_SELECTOR", null)), cookie.browser(), cookie.extraction(), cookie.injection(), cookie.cache(), null);
            var first = run(cookie, empty); var second = run(cookie, empty);
            assertEquals("fresh-2", first.token()); assertEquals("fresh-3", second.token()); assertEquals(0, observation.oldCookies());
            assertEquals(2, first.skippedSteps()); assertEquals(2, second.skippedSteps());
        }
    }
    public @Test void responseBodyRegexJsonAndCookiesCompleteOneBrowserLogin() throws Exception {
        try (var origin = IntegrationFixtures.http(); var values = SecretStore.Values.empty()) {
            LoginFlows.combinedOutputs(origin.owner, false, true).start();
            var base = IntegrationFixtures.journey(origin, List.of());
            var selection = new JourneyDefinition.CombinedExtraction(List.of(
                    new JourneyDefinition.NamedExtraction("access", base.extraction()),
                    new JourneyDefinition.NamedExtraction("csrf", new JourneyDefinition.RegexExtraction(origin.url(""), "/login", "name='csrf' content='", "'")),
                    new JourneyDefinition.NamedExtraction("session", new JourneyDefinition.CookieExtraction(origin.url("/"), "sid", null, "/"))));
            var journey = IntegrationFixtures.configured(base, base.authenticationUrl(), base.browser(), selection, null);
            var result = run(journey, values);
            assertEquals(Map.of("access", "access-value", "csrf", "csrf-value", "session", "session-value"), result.namedTokens());
            assertEquals(Map.of("sid", "session-value"), result.cookies());
            assertFalse(result.toString().contains("csrf-value"));
        }
    }
    public @Test void productionCoordinatorPublishesOwnedBrowserResultWithOriginalAcquisitionClocks() throws Exception {
        var providers = java.util.Arrays.stream(java.security.Security.getProviders()).map(java.security.Provider::getName).toList();
        try (var origin = IntegrationFixtures.http(); var secrets = new SecretStore()) {
            LoginFlows.tokenFetch(origin.owner, "coordinator-token", LoginFlows.TokenResponse.SUCCESS).start();
            var registry = new JourneyWorkspace(secrets); var journey = IntegrationFixtures.journey(origin, List.of()); CoordinatorFixtures.load(registry, List.of(journey));
            try (var coordinator = BrowserAuthentication.coordinator(registry, secrets, runner, identities, RequestSettings.Controls.defaults())) {
                var entry = registry.snapshot().resolve(journey.alias()); var ticket = coordinator.acquire(List.of(entry));
                var snapshot = ticket.future().get(25, TimeUnit.SECONDS).get(entry.identity());
                assertEquals("coordinator-token", snapshot.value()); assertSame(snapshot, coordinator.peek(entry.identity()));
                assertTrue(snapshot.lifetime().acquiredNanos() - System.nanoTime() <= 0); assertEquals(AuthenticationCoordinator.Phase.READY, coordinator.status(entry.identity()).phase());
                assertEquals(0, coordinator.capacity().waitingRequests());
            }
        }
        assertEquals(providers, java.util.Arrays.stream(java.security.Security.getProviders()).map(java.security.Provider::getName).toList(), "ordinary journeys must never initialize a native provider");
    }
    public @Test void relevantStatusesAndMalformedResponsesHaveDistinctDispositions() throws Exception {
        for (int status : List.of(503, 401, 200)) try (var origin = IntegrationFixtures.http(); var empty = SecretStore.Values.empty()) {
            LoginFlows.tokenFetch(origin.owner, "unused", status == 503 ? LoginFlows.TokenResponse.TEMPORARY_SERVICE : status == 401 ? LoginFlows.TokenResponse.AUTH_REJECTED : LoginFlows.TokenResponse.MISSING_OUTPUT).start();
            var ex = assertThrows(AuthenticationFailure.class, () -> run(IntegrationFixtures.journey(origin, List.of()), empty));
            assertEquals(status == 503 ? AuthenticationFailure.Cause.TEMPORARY_SERVICE : status == 401 ? AuthenticationFailure.Cause.AUTH_REJECTED : AuthenticationFailure.Cause.EXTRACTION, ex.reason());
            assertEquals(status == 503, ex.retryable()); if (status == 503) assertNotNull(ex.retryAfter());
        }
        actualStepFailuresKeepTheirOwnIdentityAndSafeMessage();
    }
    /** Actual Chromium failures complement the fast mapper/presentation cases without repeating the complete UI matrix. */
    private static void actualStepFailuresKeepTheirOwnIdentityAndSafeMessage() throws Exception {
        var variants = new ArrayList<String>();
        for (var type : AuthStep.Type.values()) if (type != AuthStep.Type.WAIT_TIME) variants.add("step-timeout-" + type.name());
        variants.addAll(List.of("step-timeout-hidden-WAIT_SELECTOR", "step-timeout-attached-WAIT_SELECTOR",
                "step-timeout-detached-WAIT_SELECTOR", "step-timeout-exact-WAIT_URL"));
        variants.addAll(List.of("step-ambiguous-CLICK", "step-missing-secret-SECURE_INPUT"));
        for (String variant : variants) {
            try (var origin = IntegrationFixtures.http()) {
                var held = LoginFlows.stepFailure(origin.owner, variant.contains("-hidden-") || variant.contains("-detached-")); origin.start(); var actions = new ArrayList<>(DiagnosticsTest.presentationSteps(variant));
                String waitMode = variant.contains("-hidden-") ? "hidden" : variant.contains("-attached-") ? "attached"
                        : variant.contains("-detached-") ? "detached" : variant.contains("-exact-") ? "exact" : null;
                if (waitMode != null) {
                    var action = actions.get(1);
                    actions.set(1, new AuthStep.Definition(action.id(), action.type(), action.selector(), action.value(), waitMode, action.urlPattern(), action.durationMs()));
                }
                if (actions.get(1).type() == AuthStep.Type.WAIT_LOAD_STATE) actions.set(0, step(AuthStep.Type.CLICK, "#begin-busy", null));
                if (variant.startsWith("step-ambiguous")) {
                    var original = actions.get(1); actions.set(1, new AuthStep.Definition(original.id(), original.type(), "input[data-private='CANARY_SELECTOR'], input", null, null, null, null));
                }
                var base = IntegrationFixtures.journey(origin, actions);
                var journey = IntegrationFixtures.configured(base, base.authenticationUrl(), new JourneyDefinition.Browser(true, null, 2000, 50), base.extraction(), null);
                try (var values = new SecretStore.Values(null, variant.startsWith("step-missing-secret") || actions.get(1).type() != AuthStep.Type.SECURE_INPUT ? Map.of() : Map.of(actions.get(1).id(), "CANARY_SECURE_SECRET".toCharArray()))) {
                    var failure = assertThrows(AuthenticationFailure.class, () -> run(journey, values));
                    assertEquals(variant.startsWith("step-missing-secret") ? AuthenticationFailure.Phase.SETUP : AuthenticationFailure.Phase.STEP, failure.phase(), () -> variant + ": " + failure.problem());
                    assertEquals(variant.startsWith("step-missing-secret") ? AuthenticationFailure.Cause.MISSING_SECRET : variant.startsWith("step-ambiguous") ? AuthenticationFailure.Cause.UNKNOWN : AuthenticationFailure.Cause.STEP_TIMEOUT, failure.reason());
                    assertNotNull(failure.step()); assertEquals(actions.get(1).id(), failure.step().id()); assertEquals(2, failure.step().number()); assertEquals(actions.get(1).type(), failure.step().type());
                    assertTrue(failure.problem().contains("Step 2")); assertTrue(failure.problem().contains(DiagnosticsTest.stepLabel(actions.get(1).type())));
                    for (String secret : List.of("CANARY_SELECTOR", "CANARY_PLAIN_SECRET", "CANARY_SECURE_SECRET", "CANARY_URL_SECRET", origin.url("/").toString())) assertFalse(failure.getMessage().contains(secret));
                    assertNull(failure.getCause(), "The safe failure must not retain the SDK's raw exception text.");
                    if (variant.equals("step-timeout-CLICK")) {
                        var presentation = new DiagnosticsTest(); presentation.temporary = Files.createTempDirectory(Path.of(System.getProperty("java.io.tmpdir")), "step-presentation-");
                        presentation.checkPresentation(variant, failure, journey);
                    }
                    var plan = AuthLabSupport.JSON.readTree(Files.readAllBytes(Path.of(System.getProperty("authlab.plan"))));
                    Files.writeString(Path.of(plan.path("reportDirectory").asText()).resolve("step-error-observations.jsonl"), AuthLabSupport.JSON.writeValueAsString(Map.of(
                            "variant", variant, "stepNumber", failure.step().number(), "stepType", failure.step().type().name(), "stepIdentityMatched", true,
                            "phase", failure.phase().name(), "cause", failure.reason().name(), "redacted", true, "presentationChecked", variant.equals("step-timeout-CLICK"))) + "\n",
                            java.nio.charset.StandardCharsets.UTF_8, java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
                } finally { held.release(); }
            }
        }
    }
    public @Test void unconfiguredSubresource503DoesNotBecomeAnAuthenticationRetry() throws Exception {
        long began=System.nanoTime();var processes=new ProductionLabAdapter.BrowserProcesses();int first=resourceEvents.size();var logins=new AtomicInteger();var assets=new AtomicInteger();AuthenticationFailure failure;
        try(var origin=IntegrationFixtures.http();var empty=SecretStore.Values.empty()) {
            LoginFlows.unrelatedFailure(origin.owner, logins::incrementAndGet, assets::incrementAndGet); origin.start();
            var initial=IntegrationFixtures.journey(origin,List.of(step(AuthStep.Type.WAIT_SELECTOR,"#asset-observed",null)));
            var journey=IntegrationFixtures.configured(initial,initial.authenticationUrl(),new JourneyDefinition.Browser(true,null,10_000,100),initial.extraction(),null);
            failure=assertThrows(AuthenticationFailure.class,()->run(journey,empty));assertEquals(AuthenticationFailure.Cause.EXTRACTION,failure.reason());assertFalse(failure.retryable());assertEquals(1,assets.get());assertEquals(1,logins.get());
        } finally {processes.close();}
        processes.requireObserved(1);var events=List.copyOf(resourceEvents.subList(first,resourceEvents.size()));
        boolean ordered=events.size()==4&&events.stream().map(BrowserFlowRunner.Lifecycle::event).toList().equals(List.of(BrowserFlowRunner.ResourceEvent.BROWSER_OPEN,BrowserFlowRunner.ResourceEvent.CONTEXT_OPEN,BrowserFlowRunner.ResourceEvent.CONTEXT_CLOSED,BrowserFlowRunner.ResourceEvent.BROWSER_CLOSED))
            &&events.get(0).resourceId()==events.get(3).resourceId()&&events.get(1).resourceId()==events.get(2).resourceId()&&events.get(0).resourceId()!=events.get(1).resourceId()&&events.get(1).parentId()==events.get(0).resourceId();assertTrue(ordered);
        var observed=new java.util.LinkedHashMap<String,Object>();observed.put("attempts",logins.get());observed.put("assetRequests",assets.get());observed.put("cause",failure.reason().name());observed.put("retryable",failure.retryable());observed.put("orderedCleanup",ordered);
        observed.put("resources",events.stream().map(BrowserFlowRunner.Lifecycle::resourceId).distinct().count());observed.put("drivers",processes.drivers());observed.put("processes",processes.processes());observed.put("alive",processes.alive());
        AuthLabSupport.component("CORE.retry.subresource-error",observed,Map.of("startupMs",0L,"caseMs",TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-began),"cleanupMs",0L));
    }
    public @Test void elapsedAttemptPreservesRelevantServiceAndAuthenticationErrors() throws Exception {
        for (int status : List.of(503, 401)) try (var origin = IntegrationFixtures.http(); var empty = SecretStore.Values.empty()) {
            LoginFlows.tokenFetch(origin.owner, "unused", status == 503 ? LoginFlows.TokenResponse.TEMPORARY_SERVICE : LoginFlows.TokenResponse.AUTH_REJECTED).start();
            var j = IntegrationFixtures.journey(origin, List.of(step(AuthStep.Type.WAIT_SELECTOR, "#never-present", null)));
            j = IntegrationFixtures.configured(j, j.authenticationUrl(), new JourneyDefinition.Browser(true, null, 1000, 10_000), j.extraction(), null);
            JourneyDefinition journey = j;
            var ex = assertThrows(AuthenticationFailure.class, () -> runner.run(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, journey.id(), 1),
                    journey, empty, false, System.nanoTime() + TimeUnit.SECONDS.toNanos(4), () -> false));
            assertEquals(status == 503 ? AuthenticationFailure.Cause.TEMPORARY_SERVICE : AuthenticationFailure.Cause.AUTH_REJECTED, ex.reason());
            assertNull(ex.step(), "An observed server failure must not be relabelled as the later selector timeout.");
        }
    }
    public @org.junit.jupiter.api.TestFactory
    java.util.stream.Stream<org.junit.jupiter.api.DynamicTest> actualUserAgentMarkerCoversRedirectsPopupsFramesFetchWorkersAndWebsocketHandshake() {
        return java.util.stream.Stream.of(
                ProductionLabAdapter.processCase("TLS.proxy.http-proxy",1,BrowserJourneyIntegrationTest::ordinaryProxyCoversOwnedBrowserSurfaces),
                ProductionLabAdapter.processCase("TLS.proxy.direct",2,BrowserJourneyIntegrationTest::ordinaryDirectJourneyDoesNotReuseThePreviousProxy),
                ProductionLabAdapter.processCase("TLS.proxy.no-direct-fallback",1,BrowserJourneyIntegrationTest::unavailableOrdinaryProxyDoesNotFallBackToTheOrigin));
    }
    private static void ordinaryProxyCoversOwnedBrowserSurfaces() throws Exception {
        try (var origin = IntegrationFixtures.http(); var cross = IntegrationFixtures.http(); var proxy = new IntegrationFixtures.ForwardProxy(guard); var empty = SecretStore.Values.empty()) {
            var surfaces = LoginFlows.ownedBrowserSurfaces(origin.owner, cross.owner, exchange -> {
                var decision = guard.classify(exchange.getRequestHeaders().getFirst("User-Agent"), AuthTrafficGuard.Family.GLOBAL, 9_000_000);
                proxy.seen.add(new IntegrationFixtures.Seen("/ws", decision.userAgent(), decision.classification()));
            });
            var requiredPaths = surfaces.requiredPaths(); var reachedPaths = surfaces.reachedPaths();
            cross.start(); origin.start();
            JourneyDefinition j = IntegrationFixtures.journey(origin, List.of());
            j = IntegrationFixtures.configured(j, j.authenticationUrl(), new JourneyDefinition.Browser(true, new JourneyDefinition.Proxy(proxy.url()), 10_000, 5000), j.extraction(), null);
            try{assertTrue("marked-token".equals(run(j,empty).token()),"The configured proxy must return the expected output.");}
            catch(AuthenticationFailure failure){retainOrdinaryProxyFacts(proxy,false);var missing=new HashSet<>(requiredPaths);missing.removeAll(reachedPaths);if(!missing.isEmpty())throw new AssertionError("Owned browser fixture did not observe required paths: "+missing+"; observed proxy paths: "+proxy.seen.stream().map(IntegrationFixtures.Seen::path).distinct().toList(),failure);throw failure;}
            Set<String> paths = new HashSet<>(); proxy.seen.forEach(s -> paths.add(s.path()));
            assertTrue(paths.containsAll(requiredPaths), "Required ownership paths: " + paths);
            assertTrue(proxy.seen.stream().allMatch(s -> s.classification() == AuthTrafficGuard.Classification.OWNED));
            String base = proxy.seen.getFirst().agent(); assertTrue(base.startsWith("Mozilla/"));
            for (var seen : proxy.seen) assertEquals(base, seen.agent(), "Clean User-Agent on " + seen.path());
            assertFalse(base.contains("BPSHAuth/"));
            retainOrdinaryProxyFacts(proxy,true);
        }
    }
    private static void retainOrdinaryProxyFacts(IntegrationFixtures.ForwardProxy proxy,boolean outputReturned) throws Exception {
        var observed=List.copyOf(proxy.seen);String agent=observed.isEmpty()?"":observed.getFirst().agent();
        ProductionLabAdapter.retainProcessFacts("http-proxy",Map.of("proxyRequests",proxy.accepted.get(),"ownershipPathsObserved",observed.stream().map(IntegrationFixtures.Seen::path).distinct().count(),
                "allRequestsOwned",!observed.isEmpty()&&observed.stream().allMatch(seen->seen.classification()==AuthTrafficGuard.Classification.OWNED),
                "cleanAgentPreserved",agent!=null&&agent.startsWith("Mozilla/")&&!agent.contains("BPSHAuth/")&&observed.stream().allMatch(seen->java.util.Objects.equals(agent,seen.agent())),"expectedOutputReturned",outputReturned));
    }
    private static void ordinaryDirectJourneyDoesNotReuseThePreviousProxy() throws Exception {
        var requests=new AtomicInteger();var directHadMarker=new java.util.concurrent.atomic.AtomicBoolean();
        try(var origin=IntegrationFixtures.http();var proxy=new IntegrationFixtures.ForwardProxy(guard);var values=SecretStore.Values.empty()) {
            LoginFlows.tokenFetch(origin.owner, "direct-route-proof", LoginFlows.TokenResponse.SUCCESS, exchange -> {
                requests.incrementAndGet();
                if (requests.get() > 1 && java.util.Objects.toString(exchange.getRequestHeaders().getFirst("User-Agent"), "").contains("BPSHAuth/")) directHadMarker.set(true);
            }).start();
            var first=IntegrationFixtures.journey(origin,List.of());first=IntegrationFixtures.configured(first,first.authenticationUrl(),new JourneyDefinition.Browser(true,new JourneyDefinition.Proxy(proxy.url()),10000,3000),first.extraction(),null);
            assertTrue("direct-route-proof".equals(run(first,values).token()),"The proxy comparison must return the expected output.");long before=proxy.accepted.get();assertTrue(before>0);
            var direct=IntegrationFixtures.journey(origin,List.of());direct=IntegrationFixtures.configured(direct,direct.authenticationUrl(),new JourneyDefinition.Browser(true,null,10000,3000),direct.extraction(),null);
            assertTrue("direct-route-proof".equals(run(direct,values).token()),"The direct request must return the expected output.");assertEquals(2,requests.get());assertEquals(before,proxy.accepted.get());assertFalse(directHadMarker.get());
            ProductionLabAdapter.retainProcessFacts("direct-route",Map.of("primeProxyRequests",before,"directProxyRequests",proxy.accepted.get()-before,
                    "tokenRequests",requests.get(),"expectedOutputsReturned",2,"directHadMarker",directHadMarker.get()));
        }
    }
    private static void unavailableOrdinaryProxyDoesNotFallBackToTheOrigin() throws Exception {
        var reached=new AtomicInteger();
        try(var origin=IntegrationFixtures.http();var proxy=new IntegrationFixtures.ForwardProxy(null);var values=SecretStore.Values.empty()) {
            lab.auth.TransportFixtures.countingTarget(origin.owner, reached::incrementAndGet).start();
            var unavailable=proxy.url();proxy.close();var initial=IntegrationFixtures.journey(origin,List.of());
            var journey=IntegrationFixtures.configured(initial,initial.authenticationUrl(),new JourneyDefinition.Browser(true,new JourneyDefinition.Proxy(unavailable),5000,500),initial.extraction(),null);
            var failure=assertThrows(AuthenticationFailure.class,()->run(journey,values));assertEquals(0,reached.get());
            // The lower mapper owner already establishes generic browser-proxy error disposition.
            ProductionLabAdapter.retainProcessFacts("ordinary-no-direct-fallback",Map.of("phase",failure.phase().name(),"cause",failure.reason().name(),
                    "retryable",failure.retryable(),"originRequests",reached.get(),"credentialReturned",false,"configuredProxyHadCredentials",false));
        }
    }
    public @Test void cancellationKillsOnlyTheOwnedDriverAndReturnsTypedCancellation() throws Exception {
        AtomicInteger requests = new AtomicInteger(); java.util.concurrent.atomic.AtomicBoolean cancel = new java.util.concurrent.atomic.AtomicBoolean();
        try (var origin = IntegrationFixtures.http(); var empty = SecretStore.Values.empty(); var timer = java.util.concurrent.Executors.newSingleThreadScheduledExecutor()) {
            LoginFlows.noOutput(origin.owner, () -> { requests.incrementAndGet(); cancel.set(true); }).start();
            JourneyDefinition j = IntegrationFixtures.journey(origin, List.of(step(AuthStep.Type.WAIT_SELECTOR, "#never", null)));
            var ex = assertThrows(AuthenticationFailure.class, () -> runner.run(new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, j.id(), 1), j, empty, false,
                    System.nanoTime() + TimeUnit.SECONDS.toNanos(20), cancel::get));
            assertEquals(AuthenticationFailure.Cause.CANCELLED, ex.reason()); assertEquals(1, requests.get());
        }
    }


    public @Test void coldAndUpgradeProbesUseNormalBudgets() throws Exception {
        IntegrationFixtures.verifyColdAndUpgrade();
    }

    public @Test void packagedClassloaderUsesExactResourcesWithoutSharedDriverCacheOrJvmMutation() throws Exception {
        Path jar = IntegrationFixtures.packagedJar();
        try (var origin = LoginFlows.probeForm(lab.auth.ControlledApplication.Origin.http("localhost"), "packaged-owned-token", "packaged-owned-cookie").start();
             var loader = new URLClassLoader(new java.net.URL[]{jar.toUri().toURL(), Path.of("build/classes/java/test").toUri().toURL()}, ClassLoader.getPlatformClassLoader())) {
            loader.loadClass("bpsh.browser.BrowserJourneyIntegrationTest$PackagedProbe").getMethod("exercise", String.class).invoke(null, origin.url("/login").toString());
            assertThrows(ClassNotFoundException.class, () -> loader.loadClass("lab.auth.ControlledApplication"));
        }
    }

    /** Runs only against the candidate JAR, this test probe and JDK platform modules. */
    public static class PackagedProbe {
        /** Verifies actual scoped resources, pinned versions, form/JSON/cookies and fresh contexts. */
        public static void exercise(String loginUrl) throws Exception {
            ClassLoader loader = PlaywrightDriverAdapter.class.getClassLoader();
            String scope = "META-INF/bpsh/" + BrowserRuntimeManager.hostPlatform() + "/";
            if (loader.getResource(scope + "browser-assets.json") == null || loader.getResource(scope + "browser-assets.zip") == null)
                throw new AssertionError("Host payload resources missing.");
            for (String name : List.of("driver/package/cli.js", "driver/win32_x64/node.exe", "driver/linux/node", "driver/mac/node"))
                if (loader.getResource(name) != null) throw new AssertionError("Duplicate driver execution resources remain.");
            var json = new com.fasterxml.jackson.databind.ObjectMapper();
            com.fasterxml.jackson.databind.JsonNode metadata;
            try (var in = loader.getResourceAsStream(scope + "browser-assets.json")) { metadata = json.readTree(in); }
            Class<?> driver = loader.loadClass("com.microsoft.playwright.impl.driver.Driver"); Field instance = driver.getDeclaredField("instance"); instance.setAccessible(true); Object before = instance.get(null);
            Map<Object, Object> properties = new java.util.HashMap<>(System.getProperties());
            try (var runtime = new BrowserRuntimeManager()) {
                var ready = runtime.acquire(System.nanoTime() + TimeUnit.MINUTES.toNanos(5), () -> false);
                if (!Files.isRegularFile(ready.nodeExecutable()) || !Files.isRegularFile(ready.driverEntryPoint()) || !Files.isRegularFile(ready.browserExecutable()))
                    throw new AssertionError("Verified host selectors are missing.");
                var versionBuilder = new ProcessBuilder(ready.nodeExecutable().toString(), "--version").redirectError(ProcessBuilder.Redirect.DISCARD);
                versionBuilder.environment().clear(); versionBuilder.environment().putAll(PlaywrightDriverAdapter.environment(ready));
                Process node = versionBuilder.start();
                try {
                    if (!node.waitFor(10, TimeUnit.SECONDS) || node.exitValue() != 0) throw new AssertionError("Pinned Node version check failed.");
                    byte[] output = node.getInputStream().readNBytes(129);
                    if (output.length > 128 || !new String(output, java.nio.charset.StandardCharsets.UTF_8).trim().equals("v" + metadata.path("nodeVersion").asText()))
                        throw new AssertionError("Pinned Node version differs.");
                } finally { if (node.isAlive()) node.destroyForcibly(); }
                try (var session = PlaywrightDriverAdapter.open(ready, System.nanoTime() + TimeUnit.SECONDS.toNanos(30), () -> false);
                     var browser = session.playwright().chromium().launch(new BrowserType.LaunchOptions().setHeadless(true).setTimeout(20000).setExecutablePath(ready.browserExecutable()).setArgs(List.of("--no-proxy-server")));
                     var context = browser.newContext()) {
                    if (!browser.version().equals(metadata.path("browserVersion").asText())) throw new AssertionError("Pinned Chromium version differs.");
                    var page = context.newPage(); page.navigate(loginUrl);
                    page.fill("#user", "fixture"); page.click("#submit");
                    if (!page.textContent("body").contains("packaged-owned-token")) throw new AssertionError("Packaged form/JSON flow failed.");
                    if (context.cookies().stream().noneMatch(cookie -> cookie.name.equals("session") && cookie.value.equals("packaged-owned-cookie")))
                        throw new AssertionError("Packaged cookie capture failed.");
                    try (var fresh = browser.newContext()) { if (!fresh.cookies().isEmpty()) throw new AssertionError("Browser contexts shared cookies."); }
                }
            }
            if (instance.get(null) != before || !properties.equals(new java.util.HashMap<>(System.getProperties()))) throw new AssertionError("Driver singleton or JVM properties changed.");
        }
    }
}
