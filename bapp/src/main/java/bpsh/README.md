# Extension composition

## Overview

Wires one shared service graph and owns host registration and ordered unload.

## Interface

- [Extension](./Extension.java): Composes one native service graph and owns the entire UI/hook/browser/storage unload sequence.
- [authentication](./authentication/README.md): child boundary.
- [browser](./browser/README.md): child boundary.
- [burp](./burp/README.md): child boundary.
- [journey](./journey/README.md): child boundary.
- [platform](./platform/README.md): child boundary.
- [request](./request/README.md): child boundary.

## Invariants

Extension.java:initialize checks capabilities before registering hooks; Services.close is idempotent.

## Side Effects

Registers host hooks/UI and closes owned services.

## Verification

From the repository root: `.\bapp\gradlew.bat -p bapp check verifyNativeDocumentation --offline`. Browser/native integration uses explicit tasks in [the build guide](../../../../README.md).
