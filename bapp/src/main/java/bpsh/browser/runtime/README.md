# Verified drivers and installed browser

## Overview

Verifies bundled platform assets and owns extraction, immutable cache publication and Playwright driver processes.

## Interface

- [BurpBrowserResolver](./BurpBrowserResolver.java): Resolves installed Burp Browser from bounded current-process/installation hints or an authoritative per-user selection; never reads live browser profiles.
- [BrowserExecutableSettings](./BrowserExecutableSettings.java): Publishes the raw user-local executable selection atomically; an empty selection uses automatic discovery.
- [BrowserManifestCodec](./BrowserManifestCodec.java): Bounded manifest parsing, archive metadata and path validation; performs no cache publication.
- [BrowserArchiveCodec](./BrowserArchiveCodec.java): Streams the selected format-3 driver-only XZ resource to an exact-size ZIP with compressed SHA-256, a 128 MiB decoder ceiling and the original attempt checkpoints; owns the source stream only.
- [BrowserRuntimeManager](./BrowserRuntimeManager.java): Verifies and extracts only the JAR's bundled driver assets, with no network/install fallback.
- [InvalidAsset](./InvalidAsset.java): Distinguishes a proved asset invariant failure from unrelated filesystem I/O.
- [EarlyBrowserTargets](./EarlyBrowserTargets.java): Pauses only attempt-owned Chromium page/frame targets while installing response interception before their first scripts; uses the pinned public CDP target channels, never a live user browser.
- [BoundedTokenResponses](./BoundedTokenResponses.java): Streams selected decoded Chromium responses under the 1 MiB extraction ceiling.
- [PlaywrightDriverAdapter](./PlaywrightDriverAdapter.java): Isolates the exact Playwright 1.64.0 pipe bootstrap from browser workflow code.
- [DriverStartupFailures](./DriverStartupFailures.java): Reports the observed startup component and bounded Java/native failure category without vendor messages or raw causes.
- [WindowsBrowserJob](./WindowsBrowserJob.java): Owns the Windows driver and its descendants as one native job, verifies group termination and closes its noninherited handle before profile removal.
- [PlaywrightRecorderAdapter](./PlaywrightRecorderAdapter.java): Pins private structured recording commands/events and drops generated source before Java dispatch.

## Invariants

BrowserRuntimeManager.java verifies manifests and members before publication. PlaywrightDriverAdapter.java confines sessions to their creating thread and terminates only owned processes.

Windows containment failures retain only a closed operation, unsigned native
error/wait result and deadline flag. A session attaches at most its first
observation failure and first close failure to its existing lifecycle error;
vendor messages, causes and suppression graphs are discarded. These diagnostics
do not weaken termination checks or extend cleanup budgets.

## Side Effects

Reads packaged resources, writes private caches/locks/temp files and starts the bundled Node driver.

## Verification

From the repository root: `.\bapp\gradlew.bat -p bapp check verifyNativeDocumentation --offline`. Browser/native integration uses explicit tasks in [the build guide](../../../../../../README.md).

Origin-only response capture uses the bounded Network response stream so an unrelated large page, script or download still reaches the browser. Collection stops per oversized response at 1 MiB while other token responses remain observable. Explicit path-filtered responses keep response-stage Fetch interception; service-worker responses share passive bounded collection. Neither mode reads a whole unbounded response into Java.

Passive collection starts broad streams at request observation. If Chromium has already completed a small response, collection may retrieve it only after observing a positive decoded byte count within the limit and completion of an uncached, non-range response. The returned UTF-8 or base64 body is independently bounded before extraction; a header alone never authorizes retrieval. One context shares a 4 MiB collected-payload budget and 128 response records across its target sessions, with 1 MiB per response. Old unfinished collection is retired to admit newer candidates; ordinary response delivery continues. Retirement is identity-checked so a reentrant protocol reply cannot resurrect an evicted buffer. Temporary decoding/result copies remain individually bounded.
