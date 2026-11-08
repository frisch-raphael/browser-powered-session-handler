package bpsh.journey;

import java.text.Normalizer;
import java.util.Locale;

/** Derives portable request-tag names from journey display names without choosing a collision winner. */
public final class JourneyNames {
    /** @return Unchanged portable ASCII alias; throws a safe configuration error otherwise. */
    public static String validateAlias(String value) {
        if (!value.matches("[A-Za-z0-9][A-Za-z0-9_-]{0,63}")) throw new ConfigurationException("alias: use 1-64 ASCII letters, digits, underscores or hyphens, starting with a letter or digit.");
        return value;
    }
    /** Prevents instances of the naming utility. */
    private JourneyNames() {}

    /**
     * Normalizes accents/case, replaces separators with hyphens and bounds the tag to the codec's 64-character limit.
     * Names without ASCII letters/digits receive a deterministic fallback; active duplicates are still rejected by the registry.
     * @param name User-entered journey name.
     * @return Derived ASCII alias, or empty while the name is blank.
     */
    public static String alias(String name) {
        if (name.isBlank()) return "";
        String value = Normalizer.normalize(name, Normalizer.Form.NFKD).replaceAll("\\p{M}+", "").toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9_-]+", "-").replaceAll("[-_]{2,}", "-").replaceAll("^[^a-z0-9]+|[-_]+$", "");
        if (value.isEmpty()) return "journey-" + Integer.toUnsignedString(name.hashCode(), 36);
        return value.substring(0, Math.min(64, value.length())).replaceAll("[-_]+$", "");
    }
}
