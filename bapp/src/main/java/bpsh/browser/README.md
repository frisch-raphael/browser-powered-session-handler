# Browser execution

## Overview

Adapts the authentication attempt port to real browser execution and guards owned browser traffic.

## Interface

- [AuthTrafficGuard](./AuthTrafficGuard.java): Marks owned proxied browser attempts and keeps global/Proxy response provenance independent.
- [BrowserAuthentication](./BrowserAuthentication.java): Wires the real browser and native PIN gate to the independently testable session policy.
- [BrowserFailureClassifier](./BrowserFailureClassifier.java): Safe browser failure attribution and retry metadata, independent of browser lifecycle.
- [BrowserJourneyRecorder](./BrowserJourneyRecorder.java): Independent browser worker with bounded Stop/Cancel, source ownership and unsaved secret-backed review.
- [RecordedActionCompiler](./RecordedActionCompiler.java): Converts native updates and page/frame observations into typed candidates with sticky secret protection.
- [BrowserFlowRunner](./BrowserFlowRunner.java): Executes a fresh browser/context on its calling worker, with listeners installed before navigation.
- [BrowserSessionLauncher](./BrowserSessionLauncher.java): Shares browser setup, certificate/PIN selection, traffic routing and worker-owned cleanup without requiring login steps or capture rules.
- [BrowserStepExecutor](./BrowserStepExecutor.java): Replays controls and explicit page/frame operations with bounded popup ownership.
- [BrowserTargets](./BrowserTargets.java): Validates pinned recording selector boundaries and resolves actual frame ancestry.
- [mtls](./mtls/README.md): child boundary.
- [runtime](./runtime/README.md): child boundary.

## Invariants

BrowserFlowRunner.java shares the original deadline across setup, actions and capture, converts browser cookies to CapturedCookie and closes attempt resources.

## Side Effects

Starts browser/driver/context/native proxy resources, navigates configured servers and observes credentials.

## Verification

From the repository root: `.\bapp\gradlew.bat -p bapp check verifyNativeDocumentation --offline`. Browser/native integration uses explicit tasks in [the build guide](../../../../../README.md).
