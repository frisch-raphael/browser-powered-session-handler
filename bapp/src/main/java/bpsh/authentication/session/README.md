# Authentication sessions

## Overview

Owns shared acquisition cycles, waiters, publication, recovery pauses and bounded event history.

## Interface

- [AuthenticationCoordinator](./AuthenticationCoordinator.java): Shares bounded background authentication without moving browser work into HTTP callbacks.
- [ExecutorAuthenticationRuntime](./ExecutorAuthenticationRuntime.java): Owns one scheduling thread and exactly two bounded daemon browser workers.
- [JourneyEventLog](./JourneyEventLog.java): Bounded session-only history keyed by stable journey identity; accepts sanitized metadata, never credentials or requests.

## Invariants

AuthenticationCoordinator.java consumes JourneyCatalog and AuthenticationPolicy only. Publication rechecks the current generation and lifetime; ordered waiters retain one deadline.
JourneyEventLog groups retained identical warnings/errors by stable journey, severity, message and saved step. Immutable snapshots preserve first/last occurrence times and counts; clearing or eviction releases that aggregation state. Normal tokenless HTTP/mTLS routing never requests a captured credential.

## Side Effects

Schedules owned workers/timers, publishes/invalidates credentials, completes tickets and retains bounded in-memory events.

## Verification

From the repository root: `.\bapp\gradlew.bat -p bapp check verifyNativeDocumentation --offline`. Browser/native integration uses explicit tasks in [the build guide](../../../../../../README.md).
