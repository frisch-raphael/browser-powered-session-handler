# Journey domain

## Overview

Defines a saved or unfinished journey, scoped identity, secret ownership and the read-only catalog contract.

## Interface

- [AuthStep](./AuthStep.java): Defines native step kinds and stable-ID immutable configuration, without secret values.
- [AuthStepSequence](./AuthStepSequence.java): Shared indexed validation of page references, popup triggers and explicit frame transitions.
- [BrowserSetup](./BrowserSetup.java): Validated browser/certificate settings independent of steps and credential capture, with no live handles or secrets.
- [ConfigurationException](./ConfigurationException.java): Reports native format failures using safe field paths and reasons, without raw secret values.
- [CredentialNames](./CredentialNames.java): Shared naming rules for captured credentials and their request references.
- [JourneyCatalog](./JourneyCatalog.java): Read-only journey publication boundary used by authentication and request handling.
- [JourneyDefinition](./JourneyDefinition.java): Describes a native authentication journey without secret values or live browser/token state.
- [JourneyDraft](./JourneyDraft.java): Nonsecret unfinished settings, preserved literally until the user executes the journey.
- [JourneyKey](./JourneyKey.java): Identifies a secret owner across managed scopes.
- [JourneyNames](./JourneyNames.java): Derives portable request-tag names from journey display names without choosing a collision winner.
- [JourneyRecording](./JourneyRecording.java): Framework-free recording lifecycle, bounded candidates and separately owned result secrets.
- [JourneyOrigins](./JourneyOrigins.java): Exact authentication-server identity shared by authoring and native configuration.
- [JourneySecrets](./JourneySecrets.java): Validates typed secret ownership and explicit complete-secret requirements without serialization.
- [SecretStore](./SecretStore.java): Owns mutable session secrets separately from journey definitions and tokens.
- [editing](./editing/README.md): child boundary.
- [persistence](./persistence/README.md): child boundary.

## Invariants

JourneyCatalog.java:Snapshot preserves all alias candidates and rejects unavailable or ambiguous selections. JourneySecrets.java validates ownership without JSON or host APIs.

## Side Effects

SecretStore.java replaces and wipes owned in-memory buffers; the other domain values do not perform I/O.

## Verification

From the repository root: `.\bapp\gradlew.bat -p bapp check verifyNativeDocumentation --offline`. Browser/native integration uses explicit tasks in [the build guide](../../../../../README.md).
