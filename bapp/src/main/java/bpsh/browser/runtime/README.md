# Bundled browser runtime

## Overview

Verifies bundled platform assets and owns extraction, immutable cache publication and Playwright driver processes.

## Interface

- [BrowserManifestCodec](./BrowserManifestCodec.java): Bounded manifest parsing, archive metadata and path validation; performs no cache publication.
- [BrowserRuntimeManager](./BrowserRuntimeManager.java): Verifies and extracts only the JAR's bundled browser assets, with no network/install fallback.
- [InvalidAsset](./InvalidAsset.java): Distinguishes a proved asset invariant failure from unrelated filesystem I/O.
- [BoundedTokenResponses](./BoundedTokenResponses.java): Streams selected decoded Chromium responses under the 1 MiB extraction ceiling.
- [PlaywrightDriverAdapter](./PlaywrightDriverAdapter.java): Isolates the exact Playwright 1.64.0 pipe bootstrap from browser workflow code.
- [PlaywrightRecorderAdapter](./PlaywrightRecorderAdapter.java): Pins private structured recording commands/events and drops generated source before Java dispatch.

## Invariants

BrowserRuntimeManager.java verifies manifests and members before publication. PlaywrightDriverAdapter.java confines sessions to their creating thread and terminates only owned processes.

## Side Effects

Reads packaged resources, writes private caches/locks/temp files and starts the bundled Node driver.

## Verification

From the repository root: `.\bapp\gradlew.bat -p bapp check verifyNativeDocumentation --offline`. Browser/native integration uses explicit tasks in [the build guide](../../../../../../README.md).
