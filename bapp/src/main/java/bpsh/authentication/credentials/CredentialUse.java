package bpsh.authentication.credentials;

import bpsh.journey.JourneyDefinition;

/** Token-free provenance captured at successful request commit, not from the UI's current selection. */
public record CredentialUse(JourneyDefinition.Identity identity, long version, JourneyDefinition.Recovery rule, long validationEpisode, boolean replay) {
    public CredentialUse(JourneyDefinition.Identity identity, long version, JourneyDefinition.Recovery rule) { this(identity, version, rule, 0, false); }
}
