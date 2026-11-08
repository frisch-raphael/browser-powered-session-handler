# Authentication sessions

## Overview

Owns shared acquisition cycles, waiters, publication, recovery pauses and bounded event history.

## Interface

- [AuthenticationCoordinator](./AuthenticationCoordinator.java): Shares bounded background authentication without moving browser work into HTTP callbacks.
- [ExecutorAuthenticationRuntime](./ExecutorAuthenticationRuntime.java): Owns one scheduling thread and exactly two bounded daemon browser workers.
- [JourneyEventLog](./JourneyEventLog.java): Bounded session-only history keyed by stable journey identity; accepts sanitized metadata, never credentials or requests.

## Invariants

AuthenticationCoordinator.java consumes JourneyCatalog and AuthenticationPolicy only. Publication rechecks the current generation and lifetime; ordered waiters retain one deadline.

## Side Effects

Schedules owned workers/timers, publishes/invalidates credentials, completes tickets and retains bounded in-memory events.

## Verification

From the repository root: `.\bapp\gradlew.bat -p bapp check verifyNativeDocumentation --offline`. Browser/native integration uses explicit tasks in [the build guide](../../../../../../README.md).
