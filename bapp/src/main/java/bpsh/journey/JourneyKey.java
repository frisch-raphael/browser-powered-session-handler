package bpsh.journey;

import java.util.Objects;
import java.util.UUID;

/**
 * Identifies a secret owner across managed scopes.
 *
 * Generation is excluded deliberately: changing values advances the registry generation while
 * replacing secrets under this stable journey key.
 *
 * @param scope Project or library container owning the journey.
 * @param journeyId Stable internal journey UUID.
 */
public record JourneyKey(JourneyDefinition.Scope scope, UUID journeyId) {
    /**
     * Rejects null components before an ownership key can enter the store.
     */
    public JourneyKey { Objects.requireNonNull(scope); Objects.requireNonNull(journeyId); }
}
