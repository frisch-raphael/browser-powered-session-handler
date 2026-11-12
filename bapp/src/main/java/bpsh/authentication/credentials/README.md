# Credential acquisition values

## Overview

Captures and validates response/cookie observations and computes immutable credential lifetimes.

## Interface

- [AuthenticationResult](./AuthenticationResult.java): Carries a deliberate token result without making diagnostic output disclose it.
- [CapturedCookie](./CapturedCookie.java): Browser-independent observation of one cookie applicable to the requested URL.
- [CredentialUse](./CredentialUse.java): Token-free provenance captured at successful request commit, not from the UI's current selection.
- [JsonPathSelector](./JsonPathSelector.java): The bounded JSON-selector grammar shared by configuration and extraction.
- [RecoveryPattern](./RecoveryPattern.java): Bounded RE2 session-detection grammar, independent of HTTP callbacks and recovery state.
- [TokenExtractor](./TokenExtractor.java): Collects the first valid token on its browser worker, retaining safe failures for a final result.
- [TokenLifetime](./TokenLifetime.java): Computes finite token lifetime from monotonic age and optional, untrusted JWT expiry metadata.
- [TokenSnapshot](./TokenSnapshot.java): Holds one immutable, versioned credential; diagnostic representations never disclose its value.

## Invariants

RecoveryPattern delegates source and program bounds to [the shared compiler](../../pattern/README.md), preserving recovery messages and DOTALL/find semantics. TokenExtractor.java requires complete combined capture and bounded token/body data. CapturedCookie.java carries plain observations rather than Playwright types; its diagnostic string excludes values. TokenLifetime.java checks both wall and monotonic expiry.

## Side Effects

Updates attempt-local candidates and invokes the supplied cookie-observation reader. No browser or host object is owned here.

## Verification

From the repository root: `.\bapp\gradlew.bat -p bapp check verifyNativeDocumentation --offline`. Browser/native integration uses explicit tasks in [the build guide](../../../../../../README.md).
