# Burp request handling

## Overview

Adapts global/Proxy hooks to credential acquisition, tag expansion, automatic injection and attributed recovery replay.

## Interface

- [Diagnostics](./Diagnostics.java): Produces actionable request outcomes while suppressing repeated safe cycle warnings for five seconds.
- [HttpSessionHandler](./HttpSessionHandler.java): Applies one native request pipeline globally and exempts only verified owned traffic from Proxy interception.
- [NativeTagParser](./NativeTagParser.java): Parses only bounded native references/wrappers; token output is data and is never parsed again.
- [NativeTagResolver](./NativeTagResolver.java): Builds atomic byte-preserving request replacements before any Burp hook commits or records provenance.
- [SessionRecovery](./SessionRecovery.java): Coordinates attributed, single-use recovery replays with bounded retention and linear-time RE2 matching.

## Invariants

NativeTagResolver.java:Resolved.commit rechecks publication before insertion. SessionRecovery.java consumes attribution once and never replays a replay. Diagnostics.java accepts already sanitized failures.

## Side Effects

Replaces/annotates outgoing requests, retains bounded replay templates and sends authorized replays through the injected transport.

## Verification

From the repository root: `.\bapp\gradlew.bat -p bapp check verifyNativeDocumentation --offline`. Browser/native integration uses explicit tasks in [the build guide](../../../../../../README.md).
