package bpsh.burp.http;

import bpsh.authentication.AuthenticationFailure;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Parses only bounded native references/wrappers; token output is data and is never parsed again. */
public final class NativeTagParser {
    static final int MAX_NODES = 256, MAX_REFERENCES = 16, MAX_TEXT_BYTES = 1 << 20, MAX_OUTPUT_BYTES = 4 << 20, MAX_DEPTH = 8;

    /** Prevents instances of the native grammar namespace. */
    private NativeTagParser() {}

    /** Immutable source nodes; literals may contain arbitrary ordinary text but no executable tag syntax. */
    sealed interface Node permits Literal, Reference, Wrapper {}
    /** Literal text retained exactly within one supported request region. */
    record Literal(String value) implements Node {}
    /** Canonical alias reference resolved once from a consistent registry snapshot. */
    record Reference(String alias, String tokenName) implements Node {}
    /** Explicit inner-to-outer encoding of the complete resolved child content. */
    record Wrapper(String mode, List<Node> children) implements Node {
        /** Defensively copies the validated replacement tree. */
        Wrapper { children = List.copyOf(children); }
    }

    /** Accumulates limits across all marked fields in a single HTTP request. */
    static final class Budget {
        int nodes, textBytes;
        final Set<String> aliases = new LinkedHashSet<>();
        /**
         * Counts complete marked source regions in their original wire encoding.
         * @param bytes Source region bytes before any decoding.
         * @throws AuthenticationFailure If the shared 1 MiB input ceiling is exceeded.
         */
        void text(int bytes) throws AuthenticationFailure { if (bytes > MAX_TEXT_BYTES - textBytes) throw syntax("Tagged text exceeds 1 MiB.", "Reduce the amount of request text containing authentication tags, then resend."); textBytes += bytes; }
        /**
         * Counts references and wrapper nodes; literal runs do not consume tag-node slots.
         * @throws AuthenticationFailure If more than 256 tag nodes are present.
         */
        void node() throws AuthenticationFailure { if (++nodes > MAX_NODES) throw syntax("The request contains more than 256 authentication or encoding tags.", "Reduce the number of tags in the request, then resend."); }
        /**
         * Adds one case-folded reference without multiplying work for repeated aliases.
         * @param alias Validated readable alias.
         * @throws AuthenticationFailure If more than 16 distinct references are requested.
         */
        void reference(String alias) throws AuthenticationFailure { aliases.add(alias.toLowerCase(Locale.ROOT)); if (aliases.size() > MAX_REFERENCES) throw syntax("A request references more than 16 distinct journeys.", "Reduce the number of journey references in the request, then resend."); }
    }

    /** Holds one validated region's replacement tree, never substituted source text. */
    static final class Tree {
        final List<Node> nodes;
        /**
         * Captures a validated immutable replacement tree for one supported request field.
         *
         * @param nodes Complete immutable grammar tree for a single field.
         */
        Tree(List<Node> nodes) { this.nodes = List.copyOf(nodes); }
        /**
         * Resolves data values inside explicit wrappers without reinterpreting them as grammar.
         * @param tokens Canonical aliases mapped to deliberate normalized token values.
         * @return Completely rendered text for one region.
         * @throws AuthenticationFailure If a token is absent or intermediate output exceeds its ceiling.
         */
        String render(Map<String, String> tokens) throws AuthenticationFailure { return renderNodes(nodes, tokens); }
    }

    /**
     * Detects reserved namespace prefixes with ASCII case folding directly in wire bytes.
     * @param bytes Source bytes, including an opaque body when needed.
     * @param start Inclusive scan offset.
     * @param end Exclusive scan offset.
     * @return Whether native-looking syntax is present; decoding/body allocation is unnecessary.
     */
    public static boolean contains(byte[] bytes, int start, int end) {
        for (int i = start; i < end; i++) if (prefix(bytes, i, end)) return true;
        return false;
    }

    /**
     * Recognizes malformed/case-mistaken native prefixes without claiming other tag namespaces.
     * @param bytes Raw message bytes.
     * @param at Candidate less-than offset.
     * @param end Exclusive region boundary.
     * @return True for a reserved native-looking opening or closing delimiter.
     */
    private static boolean prefix(byte[] bytes, int at, int end) {
        int i = at;
        if (i + 2 > end || bytes[i++] != '<') return false;
        if (i < end && bytes[i] == '/') i++;
        if (i >= end || bytes[i++] != '@') return false;
        return true;
    }

    /**
     * Detects percent-encoded native notation in a target without treating it as executable source.
     * @param bytes Raw request bytes.
     * @param start Inclusive target offset.
     * @param end Exclusive target offset.
     * @return Whether a mixed/fully percent-encoded reserved prefix requires raw-editor guidance.
     */
    static boolean encodedPrefix(byte[] bytes, int start, int end) {
        byte[] candidate = new byte[9];
        for (int at = start; at < end; at++) if (bytes[at] == '%' || bytes[at] == '<') {
            int i = at, count = 0; boolean encoded = false;
            while (i < end && count < candidate.length) {
                int value = bytes[i++] & 255;
                if (value == '%' && i + 1 < end) {
                    int a = Character.digit((char) bytes[i], 16), b = Character.digit((char) bytes[i + 1], 16);
                    if (a >= 0 && b >= 0) { value = (a << 4) | b; i += 2; encoded = true; }
                }
                candidate[count++] = (byte) value;
            }
            if (encoded && prefix(candidate, 0, count)) return true;
        }
        return false;
    }

    /**
     * Parses one marked field with the request's shared node/reference/input budget.
     * @param source Strictly decoded supported region.
     * @param bytes Original byte length of that region.
     * @param budget Shared limits for the whole request.
     * @return Fully validated tree; no authentication is started during parsing.
     * @throws AuthenticationFailure On malformed tags, unsupported grammar or a breached limit.
     */
    static Tree parse(String source, int bytes, Budget budget) throws AuthenticationFailure {
        budget.text(bytes); Cursor cursor = new Cursor(source, budget);
        return new Tree(cursor.children(null, 0));
    }

    /** Tracks a bounded source cursor; recursive descent is limited to eight encoding wrappers. */
    private static final class Cursor {
        final String text; final Budget budget; int at;
        /**
         * Starts bounded recursive descent over one region with the whole request's shared limits.
         *
         * @param text One strictly decoded region.
         * @param budget Whole-request limits.
         */
        Cursor(String text, Budget budget) { this.text = text; this.budget = budget; }
        /**
         * Reads a complete root or matching wrapper body without regex-based delimiter guessing.
         * @param closing Expected lowercase wrapper name, or null at the root.
         * @param depth Currently open wrapper depth.
         * @return Ordered immutable-ready source nodes.
         * @throws AuthenticationFailure If a closing delimiter, alias or wrapper violates the grammar.
         */
        List<Node> children(String closing, int depth) throws AuthenticationFailure {
            List<Node> nodes = new ArrayList<>(); int literal = at;
            while (at < text.length()) {
                if (!nativeAt(text, at)) { at++; continue; }
                if (at > literal) nodes.add(new Literal(text.substring(literal, at)));
                boolean ending = text.startsWith("</@", at);
                String canonical = ending ? "</@" : "<@";
                if (!text.startsWith(canonical, at)) throw syntax("Use literal tag delimiters in the raw request editor.");
                int end = text.indexOf('>', at + canonical.length());
                if (end < 0 || end - at > 160) throw syntax("An authentication tag is incomplete or too long.");
                String name = text.substring(at + canonical.length(), end); boolean self = name.endsWith("/");
                if (self) name = name.substring(0, name.length() - 1);
                String tokenName = null;
                int attribute = name.indexOf(" token=\"");
                if (attribute >= 0 && self && name.endsWith("\"")) {
                    tokenName = name.substring(attribute + 8, name.length() - 1); name = name.substring(0, attribute);
                    if (!validAlias(tokenName)) throw syntax("Use a valid token name in token=\"name\".");
                    tokenName = tokenName.toLowerCase(Locale.ROOT);
                }
                if (!validAlias(name)) throw syntax("Use <@journey/> or <@journey token=\"name\"/>.");
                at = end + 1;
                if (ending) {
                    if (self || closing == null || !closing.equals(name)) throw syntax("An encoding wrapper has a missing or mismatched end tag.");
                    return nodes;
                }
                budget.node();
                if (self) { String alias = name.toLowerCase(Locale.ROOT); budget.reference(alias); nodes.add(new Reference(alias, tokenName)); }
                else {
                    if (!Set.of("url", "form", "json").contains(name)) throw syntax("Only url, form and json have paired encoding-wrapper tags.");
                    if (depth >= MAX_DEPTH) throw syntax("Encoding tags are nested more than eight levels deep.", "Remove unnecessary nested encoding tags, then resend.");
                    nodes.add(new Wrapper(name, children(name, depth + 1)));
                }
                literal = at;
            }
            if (closing != null) throw syntax("An encoding wrapper is missing its end tag.");
            if (at > literal) nodes.add(new Literal(text.substring(literal, at)));
            return nodes;
        }
    }

    /**
     * Detects the same reserved prefix in decoded text while preserving all ordinary source characters.
     * @param text Strict decoded field.
     * @param at Candidate delimiter offset.
     * @return Whether grammar validation must handle this native-looking prefix.
     */
    private static boolean nativeAt(String text, int at) {
        if (text.charAt(at) != '<') return false;
        int i = at + 1; if (i < text.length() && text.charAt(i) == '/') i++;
        return i < text.length() && text.charAt(i) == '@';
    }

    /**
     * Validates the fixed ASCII alias grammar without a general-purpose expression engine.
     * @param value Alias spelling between native delimiters.
     * @return Whether the 1-64 character alias is valid.
     */
    private static boolean validAlias(String value) {
        if (value.isEmpty() || value.length() > 64 || !alphanumeric(value.charAt(0))) return false;
        for (int i = 1; i < value.length(); i++) if (!alphanumeric(value.charAt(i)) && value.charAt(i) != '-' && value.charAt(i) != '_') return false;
        return true;
    }
    /**
     * Checks the fixed ASCII alias alphabet without locale-dependent character folding.
     *
     * @param c Candidate ASCII character.
     * @return Whether it is an ASCII letter or digit.
     */
    private static boolean alphanumeric(char c) { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'; }
    /**
     * Folds an ASCII byte for prefix recognition without decoding an opaque response or request body.
     *
     * @param value Raw ASCII-compatible byte.
     * @return ASCII case-folded byte without locale dependence.
     */
    private static int lower(byte value) { int c = value & 255; return c >= 'A' && c <= 'Z' ? c + 32 : c; }

    /**
     * Renders a complete node list under the expansion ceiling, evaluating nested wrappers inside out.
     * @param nodes Validated immutable nodes.
     * @param tokens Deliberate normalized values keyed by canonical alias.
     * @return Rendered text; source-looking token values remain literal data.
     * @throws AuthenticationFailure If a value is unavailable or output is too large.
     */
    private static String renderNodes(List<Node> nodes, Map<String, String> tokens) throws AuthenticationFailure {
        StringBuilder output = new StringBuilder();
        for (Node node : nodes) {
            String value;
            if (node instanceof Literal literal) value = literal.value();
            else if (node instanceof Reference reference) {
                value = tokens.get(reference.alias() + (reference.tokenName() == null ? "" : "\0" + reference.tokenName()));
                if (value == null) throw syntax(reference.tokenName() == null ? "This journey has several tokens. Select one with token=\"name\"." : "The selected token name is unavailable. Choose a saved token from Add authentication token.");
            } else { Wrapper wrapper = (Wrapper) node; value = encode(wrapper.mode(), renderNodes(wrapper.children(), tokens)); }
            if (value.length() > MAX_OUTPUT_BYTES - output.length()) throw syntax("The text produced by expanding authentication tags exceeds 4 MiB.", "Reduce repeated tags or nested encoding layers, then resend.");
            output.append(value);
        }
        return output.toString();
    }

    /**
     * Encodes whole wrapper content explicitly; no location guessing or authentication prefix is added.
     * @param mode Exact lowercase url, form or json wrapper name.
     * @param value Completely rendered inner content.
     * @return URL-component/form bytes as ASCII text, or JSON string content without surrounding quotes.
     * @throws AuthenticationFailure If intermediate expansion exceeds its ceiling.
     */
    private static String encode(String mode, String value) throws AuthenticationFailure {
        String result;
        if (mode.equals("form")) result = java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
        else if (mode.equals("url")) {
            var out = new StringBuilder(); final String hex = "0123456789ABCDEF";
            for (byte b : value.getBytes(java.nio.charset.StandardCharsets.UTF_8)) {
                int c = b & 255;
                if (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || "-._~".indexOf(c) >= 0) out.append((char) c);
                else out.append('%').append(hex.charAt(c >> 4)).append(hex.charAt(c & 15));
                if (out.length() > MAX_OUTPUT_BYTES) throw syntax("The text produced by encoding authentication tags exceeds 4 MiB.", "Reduce repeated tags or nested encoding layers, then resend.");
            }
            result = out.toString();
        } else {
            var out = new StringBuilder();
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                switch (c) {
                    case '"' -> out.append("\\\""); case '\\' -> out.append("\\\\");
                    case '\b' -> out.append("\\b"); case '\f' -> out.append("\\f"); case '\n' -> out.append("\\n");
                    case '\r' -> out.append("\\r"); case '\t' -> out.append("\\t");
                    default -> { if (c < 32) out.append(String.format(Locale.ROOT, "\\u%04x", (int) c)); else out.append(c); }
                }
                if (out.length() > MAX_OUTPUT_BYTES) throw syntax("The text produced by encoding authentication tags exceeds 4 MiB.", "Reduce repeated tags or nested encoding layers, then resend.");
            }
            result = out.toString();
        }
        if (result.length() > MAX_OUTPUT_BYTES) throw syntax("The text produced by encoding authentication tags exceeds 4 MiB.", "Reduce repeated tags or nested encoding layers, then resend."); return result;
    }

    /**
     * Reports the known grammar or format failure without assuming a remedy.
     * @param problem Safe grammar or limit explanation.
     * @return Terminal configuration result for a tagged request that must not be sent.
     */
    static AuthenticationFailure syntax(String problem) { return new AuthenticationFailure(AuthenticationFailure.Phase.STEP, AuthenticationFailure.Cause.CONFIGURATION, problem); }

    /** @param problem Safe grammar or limit explanation. @param recovery Action specific to this failure. @return Tagged-request configuration error. */
    private static AuthenticationFailure syntax(String problem, String recovery) {
        return new AuthenticationFailure(AuthenticationFailure.Phase.STEP, AuthenticationFailure.Cause.CONFIGURATION, problem, recovery);
    }
}
