# Authentication contracts

## Overview

Defines safe failures, setup progress and the scheduling policy port.

## Interface

- [AuthenticationFailure](./AuthenticationFailure.java): Carries an observed authentication outcome without retaining secret-bearing vendor exceptions.
- [AuthenticationPolicy](./AuthenticationPolicy.java): Scheduling/admission input port.
- [AuthenticationStage](./AuthenticationStage.java): Fixed local preparation states; none contains browser or credential output.
- [credentials](./credentials/README.md): child boundary.
- [session](./session/README.md): child boundary.

## Invariants

AuthenticationFailure.java requires typed safe messages; AuthenticationPolicy.java exposes only deadlines and admission limits, without request rules or host tools.

## Side Effects

AuthenticationFailure.java:checkpoint observes cancellation/deadlines; no host, browser or storage operations occur.

## Verification

From the repository root: `.\bapp\gradlew.bat -p bapp check verifyNativeDocumentation --offline`. Browser/native integration uses explicit tasks in [the build guide](../../../../../README.md).
