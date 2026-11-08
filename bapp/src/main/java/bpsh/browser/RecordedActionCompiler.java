package bpsh.browser;

import bpsh.browser.runtime.PlaywrightRecorderAdapter;
import bpsh.journey.AuthStep;
import bpsh.journey.JourneyRecording;
import bpsh.journey.SecretStore;
import java.nio.CharBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.IntSupplier;
import static bpsh.journey.JourneyRecording.Limits.*;

/** Converts native action lifecycle into bounded steps, explicit contexts and separately owned secret values. */
final class RecordedActionCompiler implements AutoCloseable {
    /** Browser-owned identities are assigned from actual binding sources, never page-claimed frame IDs. */
    record Target(String pageGuid, long frameIdentity, long generation, List<String> frames, String selector,
            boolean trusted, boolean resetFrame, long interactionOrder) {
        Target { frames = List.copyOf(frames); }
        @Override public String toString() { return "RecordingTarget[depth=" + frames.size() + "]"; }
    }
    private record Document(long frameIdentity, long generation) {}
    private record Last(String name, String page, String selector, int index) {}
    private record Raw(AuthStep.Definition step, Target target, String page, String field, boolean knownPassword,
            boolean warning, int bytes) {}
    private static final class Page {
        final String name, opener;
        final UUID declarationId = UUID.randomUUID();
        final long created, cutoff;
        long navigation, lastPopup;
        int firstUse = Integer.MAX_VALUE;
        boolean closed, capturedClose;
        Page(String name, String opener, long created, long cutoff) { this.name = name; this.opener = opener; this.created = created; this.cutoff = cutoff; }
    }

    private final String initialGuid, loginUrl;
    private final Map<String, Page> pages = new LinkedHashMap<>();
    private final Map<String, String> popupSignals = new HashMap<>();
    private final List<Raw> actions = new ArrayList<>();
    private final Map<UUID, char[]> values = new HashMap<>();
    private final Map<Document, Set<String>> protectedTargets = new HashMap<>();
    private final Set<Document> saturated = new HashSet<>();
    private final List<String> problems = new ArrayList<>();
    private IntSupplier queuedBytes = () -> 0;
    private Last last;
    private int retained, metadataBytes, nextPopup, sourceActions;
    private boolean initialNavigation, overflow, closed;

    RecordedActionCompiler(String initialGuid, String loginUrl) {
        this.initialGuid = initialGuid; this.loginUrl = loginUrl; pages.put(initialGuid, new Page("main", null, 0, 0));
    }

    void queuedBytes(IntSupplier queued) { queuedBytes = queued; }
    int remainingBytes() { return Math.max(0, RETAINED_BYTES - retained - metadataBytes); }
    void incomplete(String safeGuidance) { problem(safeGuidance); }

    void pageOpened(String guid, String openerGuid, long order) {
        if (closed || pages.containsKey(guid)) return;
        if (pages.size() >= PAGES) { limit("The recording contains more than 16 pages."); return; }
        var opener = pages.get(openerGuid);
        if (opener == null) { problem("A new tab had no supported opening page. Record the login without opening an independent tab."); return; }
        pages.put(guid, new Page("popup-" + (++nextPopup), opener.name, order, Math.max(opener.navigation, opener.lastPopup)));
        opener.lastPopup = order;
    }

    void pageClosed(String guid) {
        var page = pages.get(guid); if (page == null || closed) return; page.closed = true;
        if (guid.equals(initialGuid)) problem("The initial tab closed before recording finished. Record the login again.");
    }

    void navigated(String pageGuid, long frameIdentity, boolean mainFrame, long order) {
        forgetFrame(frameIdentity);
        if (mainFrame && pages.containsKey(pageGuid)) pages.get(pageGuid).navigation = order;
    }

    void forgetFrame(long frameIdentity) {
        for (var key : new ArrayList<>(protectedTargets.keySet())) if (key.frameIdentity() == frameIdentity) {
            for (var selector : protectedTargets.remove(key)) metadataBytes -= utf8Length(selector) + 32;
            saturated.remove(key);
        }
    }

    /** Borrows an event; its owner always closes it after conversion. */
    void accept(PlaywrightRecorderAdapter.Event event, Target target) {
        if (closed || overflow) return;
        var action = event.action(); var page = pages.get(event.pageGuid());
        if (page == null) { problem("An action's page could not be identified. Record the login again."); return; }
        if (event.kind() == PlaywrightRecorderAdapter.Kind.SIGNAL) {
            switch (action.name()) {
                case "navigation" -> { /* attached observations never create URL steps with session material */ }
                case "popup" -> {
                    if (action.popupPageGuid() == null) problem("A popup's opening page could not be identified. Record the login again.");
                    else popupSignals.put(action.popupPageGuid(), event.pageGuid());
                }
                default -> problem("A browser interaction (" + describe(action) + ") was not added as a step: this interaction is not supported.");
            }
            return;
        }
        int previous = -1;
        if (event.kind() == PlaywrightRecorderAdapter.Kind.UPDATED) {
            if (last == null || !last.name().equals("fill") || !action.name().equals("fill") || !last.page().equals(event.pageGuid())
                    || !java.util.Objects.equals(last.selector(), action.selector())) {
                problem("A recorded input update could not be associated with its field. Record the login again."); return;
            }
            previous = last.index();
        }
        last = new Last(action.name(), event.pageGuid(), action.selector(), -1);
        if (action.name().equals("openPage")) return;
        if (action.name().equals("navigate")) {
            if (!initialNavigation && event.pageGuid().equals(initialGuid) && loginUrl.equals(action.url())) initialNavigation = true;
            else problem("Opening another URL directly is not supported in this recording. Record the login using page buttons and links.");
            return;
        }
        if (action.name().equals("closePage")) {
            if (event.kind() == PlaywrightRecorderAdapter.Kind.ADDED) sourceActions++;
            if (event.pageGuid().equals(initialGuid)) return;
            if (page.capturedClose) return; page.capturedClose = true;
            var context = new Target(event.pageGuid(), 0, 0, List.of(), null, false, false, 0);
            store(new Raw(definition(UUID.randomUUID(), AuthStep.Type.CLOSE_PAGE, null, null, new AuthStep.Context()), context, page.name, "", false, false, 256), -1);
            page.firstUse = Math.min(page.firstUse, actions.size() - 1); return;
        }
        if (event.kind() == PlaywrightRecorderAdapter.Kind.ADDED) sourceActions++;
        if (target == null || !target.pageGuid().equals(event.pageGuid()) || target.selector() == null || target.selector().isBlank()) {
            unsupported(action, "the page or frame could not be resolved"); return;
        }
        Raw prior = previous < 0 ? null : actions.get(previous);
        boolean same = prior != null && sameField(prior, target, action.metadata().fieldId());
        if (!same) previous = -1;
        UUID id = same ? prior.step().id() : UUID.randomUUID();
        AuthStep.Definition step; boolean known = false, warning = false; int valueBytes = 0; char[] captured = null;
        try {
            switch (action.name()) {
                case "fill" -> {
                    captured = action.value();
                    if (captured == null) { unsupported(action, "the input value was missing"); return; }
                    valueBytes = utf8Length(CharBuffer.wrap(captured));
                    var document = new Document(target.frameIdentity(), target.generation());
                    boolean owned = target.trusted() && target.frameIdentity() > 0;
                    boolean classified = owned && !action.metadata().fieldId().isEmpty() && !action.metadata().documentId().isEmpty();
                    boolean inherited = owned && protectedTargets.getOrDefault(document, Set.of()).contains(target.selector());
                    known = classified && action.metadata().classification() == PlaywrightRecorderAdapter.Classification.SECRET || inherited || same && prior.knownPassword();
                    boolean ordinary = classified && !saturated.contains(document) && action.metadata().classification() == PlaywrightRecorderAdapter.Classification.ORDINARY;
                    boolean secret = known || !ordinary || same && prior.warning(); warning = secret && !known;
                    step = definition(id, secret ? AuthStep.Type.SECURE_INPUT : AuthStep.Type.INPUT, target.selector(), secret ? null : new String(captured), null);
                    if (known) protect(document, target.selector());
                }
                case "check", "uncheck" -> step = definition(id, AuthStep.Type.SET_CHECKED, target.selector(), null, new AuthStep.Checked(action.name().equals("check")));
                case "select" -> step = definition(id, AuthStep.Type.SELECT_OPTIONS, target.selector(), null, new AuthStep.Options(action.options()));
                case "click" -> {
                    if (!action.button().equals("left") || action.clickCount() != 1 || action.modifiers() != 0 || action.position()) {
                        unsupported(action, "only a single left click without modifiers or coordinates is supported"); return;
                    }
                    step = definition(id, AuthStep.Type.CLICK, target.selector(), null, null);
                }
                case "press" -> {
                    String key = action.key().equals("Enter") && (action.modifiers() == 0 || action.modifiers() == 2)
                            ? action.modifiers() == 2 ? "Control+Enter" : "Enter"
                            : action.key().equals("Tab") && (action.modifiers() == 0 || action.modifiers() == 8)
                            ? action.modifiers() == 8 ? "Shift+Tab" : "Tab" : null;
                    if (key == null) { unsupported(action, "supported keys are Enter, Ctrl+Enter, Tab and Shift+Tab"); return; }
                    step = definition(id, AuthStep.Type.PRESS_KEY, target.selector(), null, new AuthStep.Key(key));
                }
                default -> { unsupported(action, "this interaction is not supported"); return; }
            }
            int size = 256 + utf8Length(target.selector()) + valueBytes + utf8Length(action.metadata().fieldId());
            for (String frame : target.frames()) size += utf8Length(frame) + 16;
            for (String option : action.options()) size += utf8Length(option) + 8;
            var raw = new Raw(step, target, page.name, action.metadata().fieldId(), known, warning, size);
            int index = store(raw, previous);
            if (index >= 0) {
                if (step.type() == AuthStep.Type.SECURE_INPUT) {
                    char[] old = values.put(id, captured.clone()); if (old != null) Arrays.fill(old, '\0');
                }
                last = new Last(action.name(), event.pageGuid(), action.selector(), index);
                page.firstUse = Math.min(page.firstUse, index);
            }
        } finally { if (captured != null) Arrays.fill(captured, '\0'); }
    }

    private static boolean sameField(Raw prior, Target target, String field) {
        return target.trusted() && prior.target().trusted() && !field.isEmpty() && prior.field().equals(field)
                && prior.target().frameIdentity() == target.frameIdentity() && prior.target().generation() == target.generation();
    }

    private int store(Raw raw, int replace) {
        int removed = replace < 0 ? 0 : actions.get(replace).bytes();
        if (replace < 0 && actions.size() >= STEPS || retained - removed + raw.bytes() + metadataBytes + queuedBytes.getAsInt() > RETAINED_BYTES) {
            limit("The recording exceeds its step or data limit. Record a shorter login."); return -1;
        }
        retained += raw.bytes() - removed;
        if (replace < 0) { actions.add(raw); return actions.size() - 1; }
        actions.set(replace, raw); return replace;
    }

    private void protect(Document document, String selector) {
        var targets = protectedTargets.computeIfAbsent(document, ignored -> new HashSet<>());
        if (targets.contains(selector)) return;
        int bytes = utf8Length(selector) + 32;
        if (targets.size() >= METADATA_FIELDS || retained + metadataBytes + bytes + queuedBytes.getAsInt() > RETAINED_BYTES) { saturated.add(document); return; }
        targets.add(selector); metadataBytes += bytes;
    }

    /** Freezes complete or partial review with provisional popup relationships for editing before execution. */
    JourneyRecording.Result freeze(JourneyRecording.Stamp stamp, Runnable released) {
        var candidates = new ArrayList<JourneyRecording.Candidate>(); var popups = new ArrayList<JourneyRecording.Popup>();
        String currentPage = "main"; List<String> path = List.of();
        for (var raw : actions) {
            if (!raw.page().equals(currentPage)) {
                candidates.add(candidate(definition(UUID.randomUUID(), AuthStep.Type.SWITCH_PAGE, null, null, new AuthStep.PageTarget(raw.page())), raw.page(), List.of(), false));
                currentPage = raw.page(); path = List.of();
            }
            if (raw.step().type() != AuthStep.Type.CLOSE_PAGE) {
                if (raw.target().resetFrame() && !path.isEmpty()) {
                    candidates.add(candidate(definition(UUID.randomUUID(), AuthStep.Type.MAIN_FRAME, null, null, new AuthStep.Context()), currentPage, List.of(), false)); path = List.of();
                }
                int common = BrowserTargets.commonPrefix(path, raw.target().frames());
                for (int i = path.size(); i > common; i--)
                    candidates.add(candidate(definition(UUID.randomUUID(), AuthStep.Type.PARENT_FRAME, null, null, new AuthStep.Context()), currentPage, path.subList(0, i - 1), false));
                for (int i = common; i < raw.target().frames().size(); i++)
                    candidates.add(candidate(definition(UUID.randomUUID(), AuthStep.Type.ENTER_FRAME, raw.target().frames().get(i), null, new AuthStep.Context()), currentPage, raw.target().frames().subList(0, i + 1), false));
                path = raw.target().frames();
            }
            candidates.add(candidate(raw.step(), raw.page(), raw.target().frames(), raw.warning()));
            if (raw.step().type() == AuthStep.Type.CLOSE_PAGE) { currentPage = ""; path = List.of(); }
        }
        for (var entry : pages.entrySet()) {
            var page = entry.getValue(); if (page.opener == null) continue;
            if (page.closed && !page.capturedClose) problem("A popup closed without a recorded close action. Record the login again.");
            var eligible = new ArrayList<UUID>(); var suggestions = new ArrayList<UUID>();
            for (int i = 0; i < actions.size() && i < page.firstUse; i++) {
                var action = actions.get(i);
                if (action.page().equals(page.opener) && Set.of(AuthStep.Type.CLICK, AuthStep.Type.PRESS_KEY).contains(action.step().type())) {
                    eligible.add(action.step().id());
                    if (action.target().interactionOrder() > page.cutoff && action.target().interactionOrder() < page.created) suggestions.add(action.step().id());
                }
            }
            UUID suggested = suggestions.size() == 1 ? suggestions.getFirst() : null;
            popups.add(new JourneyRecording.Popup(page.declarationId, page.name, page.opener, eligible, suggested));
            if (eligible.isEmpty()) problem("A popup has no supported earlier opening step. Record the login again.");
            int insertion = suggested == null ? firstPageUse(candidates, page.name) : stepIndex(candidates, suggested);
            if (insertion < 0) insertion = candidates.size();
            var expectation = definition(page.declarationId, AuthStep.Type.EXPECT_POPUP, null, null, new AuthStep.Popup(page.name, suggested == null ? page.declarationId : suggested));
            List<String> frames = insertion < candidates.size() && suggested != null ? candidates.get(insertion).frames() : List.of();
            candidates.add(insertion, candidate(expectation, page.opener, frames, false));
        }
        for (var signal : popupSignals.entrySet()) {
            var popup = pages.get(signal.getKey()); var opener = pages.get(signal.getValue());
            if (popup == null || opener == null || !java.util.Objects.equals(popup.opener, opener.name))
                problem("A popup signal did not match its observed opening page. Record the login again.");
        }
        if (candidates.size() > STEPS) limit("The recording exceeds 256 steps after page and frame changes. Record a shorter login.");
        var secrets = overflow ? SecretStore.Values.empty() : new SecretStore.Values(null, values);
        var result = new JourneyRecording.Result(stamp, overflow ? List.of() : candidates, popups, problems, secrets, released);
        close(); return result;
    }

    private static int stepIndex(List<JourneyRecording.Candidate> candidates, UUID id) {
        for (int i = 0; i < candidates.size(); i++) if (candidates.get(i).step().id().equals(id)) return i; return -1;
    }
    private static int firstPageUse(List<JourneyRecording.Candidate> candidates, String name) {
        for (int i = 0; i < candidates.size(); i++) if (candidates.get(i).pageRef().equals(name)) return i; return -1;
    }
    private static AuthStep.Definition definition(UUID id, AuthStep.Type type, String selector, String value, AuthStep.Operation operation) {
        return new AuthStep.Definition(id, type, selector, value, null, null, null, operation);
    }
    private static JourneyRecording.Candidate candidate(AuthStep.Definition step, String page, List<String> frames, boolean warning) {
        return new JourneyRecording.Candidate(step, page, frames, warning);
    }
    /** Describes omitted browser interactions using symbolic action/key names, never selectors or entered text. */
    private void unsupported(PlaywrightRecorderAdapter.Action action, String reason) {
        problem("Browser interaction " + Math.max(1, sourceActions) + " (" + describe(action) + ") was not added as a step: " + reason + ".");
    }
    private static String describe(PlaywrightRecorderAdapter.Action action) {
        return switch (action.name()) {
            case "press" -> {
                String key = action.key();
                if (key == null || (action.modifiers() & ~15) != 0 || !Set.of("Enter", "Tab", "Escape", "Backspace", "Delete", "Insert", "Home", "End", "PageUp", "PageDown", "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "Space").contains(key)
                        && !key.matches("F(?:[1-9]|1[0-2])")) yield "pressed a key or shortcut";
                yield "pressed " + modifiers(action.modifiers()) + key;
            }
            case "click" -> (action.clickCount() == 2 ? "double-" : action.clickCount() > 2 ? "multiple " : "")
                    + modifiers(action.modifiers()) + (action.button().equals("right") ? "right-click" : action.button().equals("middle") ? "middle-click" : "click")
                    + (action.position() ? " at specific coordinates" : "");
            case "fill" -> "filled a field"; case "check" -> "checked a control"; case "uncheck" -> "unchecked a control";
            case "select" -> "selected dropdown options"; case "download" -> "downloaded a file"; case "dialog" -> "opened a browser dialog";
            case "setInputFiles" -> "selected files for upload"; case "assertText", "assertVisible", "assertValue", "assertChecked", "assertSnapshot" -> "added an assertion";
            default -> "unsupported browser action";
        };
    }
    /** Playwright's modifier mask carries only symbolic modifier keys. */
    private static String modifiers(int value) {
        return ((value & 2) != 0 ? "Ctrl+" : "") + ((value & 1) != 0 ? "Alt+" : "")
                + ((value & 8) != 0 ? "Shift+" : "") + ((value & 4) != 0 ? "Meta+" : "");
    }
    private void problem(String message) { if (problems.size() < STEPS && !problems.contains(message)) problems.add(message); else if (problems.size() == STEPS) overflow = true; }
    private void limit(String message) { problem(message); overflow = true; }
    @Override public void close() {
        if (closed) return; closed = true; values.values().forEach(value -> Arrays.fill(value, '\0')); values.clear();
        protectedTargets.clear(); saturated.clear(); actions.clear(); retained = metadataBytes = 0;
    }
}
