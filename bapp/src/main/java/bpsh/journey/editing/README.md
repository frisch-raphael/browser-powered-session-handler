# Journey editing

## Overview

Coordinates complete edits, draft compilation, import/export, publication and captured storage revisions.

## Interface

- [BrowserSetupCompiler](./BrowserSetupCompiler.java): Compiles setup for recording without requiring valid unrelated journey fields; shares strict codec validation with full journey compilation.
- [JourneyDraftCompiler](./JourneyDraftCompiler.java): Compiles nonsecret editor snapshots through the strict native codec, independently of Swing.
- [JourneyStorage](./JourneyStorage.java): Owns storage revisions and external-load epochs independently of the Swing editor.
- [JourneyTransfer](./JourneyTransfer.java): Transfers native journeys without treating managed or legacy files as imports.
- [JourneyWorkspace](./JourneyWorkspace.java): Publishes immutable, secret-free snapshots of the active project and user library.

## Invariants

JourneyWorkspace.java:prepareEdit validates before writing; JourneyStorage.java:checkEpoch rejects drafts from an earlier external load.

## Side Effects

JourneyStorage.java invokes revision-checked stores and the library watcher. JourneyWorkspace.java publishes generations and updates owned secrets.

## Verification

From the repository root: `.\bapp\gradlew.bat -p bapp check verifyNativeDocumentation --offline`. Browser/native integration uses explicit tasks in [the build guide](../../../../../../README.md).
