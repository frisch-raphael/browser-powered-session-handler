/** Shared naming rules for captured credentials and their request references. */
final class CredentialNames {
    static final String DUPLICATE = "Use a unique name; uppercase and lowercase count as the same.";
    private static final int MAX_LENGTH = 64;

    /** Shared utility only. */
    private CredentialNames() {}

    /** @param name Candidate name, with editor whitespace already trimmed. @return Safe guidance, or null for a valid name. */
    static String problem(String name) {
        if (name.isEmpty()) return "Enter a credential name.";
        if (name.length() > MAX_LENGTH) return "Use 64 characters or fewer.";
        if (!name.matches("[A-Za-z0-9_-]+")) return "Use only A-Z, a-z, 0-9, underscores or hyphens.";
        if (name.charAt(0) == '_' || name.charAt(0) == '-') return "Start with a letter or digit.";
        return null;
    }
}
