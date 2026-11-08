package bpsh.browser;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.playwright.ElementHandle;
import com.microsoft.playwright.Frame;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/** Pinned recorder-selector boundaries and browser-owned frame ancestry; never generates CSS. */
final class BrowserTargets {
    private static final ObjectMapper JSON = new ObjectMapper().enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private static final Set<String> ENGINES = Set.of("css", "css:light", "xpath", "id", "text", "nth", "visible",
            "internal:role", "internal:text", "internal:label", "internal:attr", "internal:testid", "internal:has-text", "internal:has-not-text");
    private static final Set<String> NESTED = Set.of("internal:has", "internal:has-not", "internal:and", "internal:or", "internal:chain");
    private BrowserTargets() {}

    /** Retains native leaf text and explicit immediate-child frame selectors. */
    record Target(List<String> frames, String selector, boolean anyFrame) {
        Target { frames = List.copyOf(frames); }
        @Override public String toString() { return "Target[frameDepth=" + frames.size() + ", unresolvedAncestry=" + anyFrame + "]"; }
    }
    private record Component(String source, String engine, String body) {}

    /** Parses only the supported recording subset; manually saved selectors keep their existing runtime semantics. */
    static Target parse(String selector) {
        var components = components(selector, 0, new int[]{0}, true);
        var frames = new ArrayList<String>(); var chunk = new ArrayList<String>(); boolean anyFrame = false;
        for (int i = 0; i < components.size(); i++) {
            var component = components.get(i);
            if (!component.engine().equals("internal:control")) {
                if (chunk.isEmpty() && NESTED.contains(component.engine())) throw invalid();
                chunk.add(component.source()); continue;
            }
            if (component.body().equals("any-frame") && i == 0) { anyFrame = true; continue; }
            if (anyFrame || !component.body().equals("enter-frame") || chunk.isEmpty()) throw invalid();
            frames.add(String.join(" >> ", chunk)); chunk.clear();
            if (frames.size() > 16) throw invalid();
        }
        if (chunk.isEmpty()) throw invalid();
        return new Target(frames, String.join(" >> ", chunk), anyFrame);
    }

    private static List<Component> components(String selector, int depth, int[] count, boolean controls) {
        if (selector == null || selector.getBytes(StandardCharsets.UTF_8).length > 4096 || depth > 16) throw invalid();
        var parts = new ArrayList<Component>(); int start = 0; char quote = 0;
        for (int i = 0; i < selector.length(); i++) {
            char c = selector.charAt(i);
            if (c == '\\') { if (++i >= selector.length()) throw invalid(); continue; }
            if (c == quote) { quote = 0; continue; }
            if (quote == 0 && (c == '\'' || c == '"' || c == '`')
                    && !selector.substring(start, i).matches("(?s)\\s*text\\s*=.+")) { quote = c; continue; }
            if (quote == 0 && c == '>' && i + 1 < selector.length() && selector.charAt(i + 1) == '>') {
                parts.add(component(selector.substring(start, i), depth, count, controls, parts.isEmpty())); start = ++i + 1;
            }
        }
        if (quote != 0) throw invalid();
        parts.add(component(selector.substring(start), depth, count, controls, parts.isEmpty())); return parts;
    }

    private static Component component(String source, int depth, int[] count, boolean controls, boolean first) {
        source = source.trim(); if (source.isEmpty() || ++count[0] > 256) throw invalid();
        String engine, body; int equals = source.indexOf('=');
        if (equals >= 0 && source.substring(0, equals).trim().matches("[a-zA-Z_0-9-+:*]+")) {
            engine = source.substring(0, equals).trim(); body = source.substring(equals + 1);
        } else {
            engine = source.length() > 1 && (source.startsWith("\"") && source.endsWith("\"") || source.startsWith("'") && source.endsWith("'"))
                    ? "text" : source.matches("(?s)^\\(*//.*") || source.startsWith("..") ? "xpath" : "css";
            body = source;
        }
        if (engine.startsWith("*") || body.isEmpty()) throw invalid();
        if (engine.equals("internal:control")) {
            if (!controls || !Set.of("enter-frame", "any-frame").contains(body)) throw invalid();
        } else if (NESTED.contains(engine)) {
            if (first) throw invalid();
            try {
                var nested = JSON.readTree(body); if (nested == null || !nested.isTextual()) throw invalid();
                components(nested.textValue(), depth + 1, count, false);
            } catch (java.io.IOException error) { throw invalid(); }
        } else if (!ENGINES.contains(engine)) throw invalid();
        return new Component(source, engine, body);
    }

    /** Resolves native any-frame shorthand using the actual binding source, including cross-origin ancestors. */
    static Target resolve(String selector, Frame source) {
        Target parsed = parse(selector); if (!parsed.anyFrame()) return parsed;
        if (source == null || source.isDetached()) throw invalid();
        var path = new ArrayList<String>(); Frame child = source;
        try {
            while (child.parentFrame() != null) {
                if (path.size() == 16 || child.isDetached()) throw invalid();
                Frame parent = child.parentFrame(); ElementHandle owner = child.frameElement();
                try {
                    Object generated = parent.evaluate("element => window.playwright.selector(element)", owner);
                    if (!(generated instanceof String text)) throw invalid();
                    Target target = parse(text); if (target.anyFrame() || !target.frames().isEmpty()) throw invalid();
                    path.add(target.selector());
                } finally { owner.dispose(); }
                child = parent;
            }
        } catch (RuntimeException error) { throw invalid(); }
        if (child != source.page().mainFrame()) throw invalid();
        Collections.reverse(path); return new Target(path, parsed.selector(), false);
    }

    /** @return Exact common ancestry; textually different selectors are never assumed equivalent. */
    static int commonPrefix(List<String> previous, List<String> next) {
        int count = 0; while (count < previous.size() && count < next.size() && previous.get(count).equals(next.get(count))) count++;
        return count;
    }

    private static IllegalArgumentException invalid() { return new IllegalArgumentException("The recorded target could not be resolved safely. Record the login again."); }
}
