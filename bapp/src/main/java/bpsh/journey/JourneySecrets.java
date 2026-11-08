package bpsh.journey;
import java.util.*;
/** Validates typed secret ownership and explicit complete-secret requirements without serialization. */
public final class JourneySecrets {
    private JourneySecrets() {}
    private static ConfigurationException invalid(String path, String reason) { return new ConfigurationException(path + ": " + reason + "."); }
    /**
     * Checks typed secret ownership without creating JSON strings for unremembered values.
     *
     * Temporary PIN copies are wiped; step validation needs only IDs. Missing required
     * runtime values remain permitted at this configuration-validation stage.
     *
     * @param journey Validated definition owning the candidate values.
     * @param values Open caller-owned snapshot; neither consumed nor modified.
     * @throws bpsh.journey.ConfigurationException If values refer to absent mTLS configuration or nonsecure steps.
     * @throws IllegalStateException If the snapshot is closed.
     */
    public static void validateSecretOwnership(JourneyDefinition journey, SecretStore.Values values) {
        char[] pin = values.pin();
        try {
            if (pin != null && journey.mtls() == null) throw invalid("secrets.mtlsPin", "requires mTLS configuration");
            Set<UUID> secure = new HashSet<>();
            journey.steps().stream().filter(s -> s.type() == AuthStep.Type.SECURE_INPUT).forEach(s -> secure.add(s.id()));
            if (!secure.containsAll(values.stepIds())) throw invalid("secrets.stepValues", "value must belong to a secure step in this journey");
        } finally {
            if (pin != null) Arrays.fill(pin, '\0');
        }
    }
    /**
     * Requires every configured secret when an explicit complete-secret export is requested.
     *
     * Errors identify the journey and secure-step position with remediation, never a supplied value.
     * Returned accessor copies are wiped after checking presence; empty supplied arrays are present.
     *
     * @param journey Definition whose mTLS and secure-input requirements must be satisfied.
     * @param values Open session snapshot to inspect without consuming it.
     * @throws bpsh.journey.ConfigurationException If a required value is absent.
     * @throws IllegalStateException If the snapshot is closed.
     */
    public static void requireCompleteSecrets(JourneyDefinition journey, SecretStore.Values values) {
        String owner = "journey " + JourneyNames.validateAlias(journey.alias()) + ".secrets";
        if (journey.mtls() != null) requireSecret(values.pin(), "mTLS PIN", owner);
        for (int i = 0; i < journey.steps().size(); i++) {
            AuthStep.Definition step = journey.steps().get(i);
            if (step.type() == AuthStep.Type.SECURE_INPUT) requireSecret(values.stepValue(step.id()), "secure-input value at step " + (i + 1), owner);
        }
    }
    /**
     * Checks presence and wipes an accessor copy without logging its content.
     *
     * @param value Caller-owned temporary buffer to wipe, or null when missing.
     * @param field Safe human-readable field description, optionally including a step position.
     * @param owner Validated journey/field label for actionable diagnostics.
     * @throws bpsh.journey.ConfigurationException If value is null, with guidance to enter it or omit secret inclusion.
     */
    private static void requireSecret(char[] value, String field, String owner) {
        if (value == null) throw invalid(owner, "missing " + field + "; enter it in the journey configuration or export without Include secrets");
        Arrays.fill(value, '\0');
    }
}
