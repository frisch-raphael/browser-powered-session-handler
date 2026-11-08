package bpsh.authentication.credentials;

import bpsh.journey.ConfigurationException;

/** The bounded JSON-selector grammar shared by configuration and extraction. */
public final class JsonPathSelector {
    private JsonPathSelector() {}
    /**
     * Validates the limited dotted-key/numeric-index grammar without evaluating it.
     *
     * Keys begin with an ASCII letter/underscore and may contain digits/hyphens. Numeric segments
     * and bracket indices have no leading zeros and fit signed 32-bit range. Wildcards, quoted keys,
     * recursive descent and dollar-root syntax are unsupported. Iterative scanning avoids recursive
     * regex matching on long configured paths.
     *
     * @param path Extraction selector such as data.tokens[0].value or data.tokens.0.value.
     * @throws bpsh.journey.ConfigurationException If segment syntax, delimiters or an index bound is invalid.
     */
    public static void validate(String path) {
        if (path == null || path.isEmpty()) throw invalid("extraction.jsonPath", "requires a key or index");
        int i = 0;
        while (i < path.length()) {
            boolean bracket = path.charAt(i) == '[';
            if (bracket) i++;
            if (i == path.length()) throw invalid("extraction.jsonPath", "missing index");
            char first = path.charAt(i);
            if (first >= '0' && first <= '9') {
                int start = i; long index = 0;
                while (i < path.length() && path.charAt(i) >= '0' && path.charAt(i) <= '9') {
                    index = index * 10 + path.charAt(i++) - '0';
                    if (index > Integer.MAX_VALUE) throw invalid("extraction.jsonPath", "array indices must fit a signed 32-bit integer");
                }
                if (first == '0' && i - start > 1) throw invalid("extraction.jsonPath", "indices cannot contain leading zeros");
            } else if (!bracket && keyStart(first)) {
                i++;
                while (i < path.length() && (keyStart(path.charAt(i)) || (path.charAt(i) >= '0' && path.charAt(i) <= '9') || path.charAt(i) == '-')) i++;
            } else throw invalid("extraction.jsonPath", "use dotted keys or numeric indices only");
            if (bracket) {
                if (i == path.length() || path.charAt(i++) != ']') throw invalid("extraction.jsonPath", "missing closing bracket");
            }
            if (i == path.length()) return;
            if (path.charAt(i) == '[') continue;
            if (path.charAt(i++) != '.' || i == path.length() || path.charAt(i) == '[')
                throw invalid("extraction.jsonPath", "use dotted keys or numeric indices only");
        }
    }
    /**
     * Recognizes the ASCII first-character rule shared by JSON-path key segments.
     *
     * @param c Candidate first character; Unicode letters are intentionally not accepted.
     * @return True for an ASCII letter or underscore.
     */
    private static boolean keyStart(char c) { return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }
    private static ConfigurationException invalid(String path, String reason) { return new ConfigurationException(path + ": " + reason + "."); }
}
