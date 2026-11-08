# Journey persistence and format

## Overview

Owns the native JSON format and concrete project, user-library and transfer-file storage.

## Interface

- [JourneyDocument](./JourneyDocument.java): Owned journey storage/transfer envelope, independent of the project persistence implementation.
- [JourneyJson](./JourneyJson.java): Strict JSON boundary shared by storage, authoring and native transfer.
- [NativeDocumentCodec](./NativeDocumentCodec.java): Strict native JSON codec.
- [NativeJourneyCodec](./NativeJourneyCodec.java): Native journey, credential and secret encoding, independent of project persistence.
- [NativeJourneyFiles](./NativeJourneyFiles.java): Bounded native transfer I/O; presentation and explicit overwrite decisions remain in the UI.
- [NativeJson](./NativeJson.java): Exact field readers and bounded scalar validation shared by the native codecs.
- [ProjectStore](./ProjectStore.java): Validates and persists only the native project/journey formats, leaving previous stored data untouched.
- [UserLibraryStore](./UserLibraryStore.java): Persists the native user library with locked compare-and-swap saves and atomic replacement.

## Invariants

JourneyJson.java is the strict shared format boundary. ProjectStore.java:saveNativeProject and UserLibraryStore.java:save reject conflicting revisions. JourneyDocument.java owns attached secret snapshots.

## Side Effects

Reads/writes Burp project data and private user-library/export files; library observation is explicitly started and closed.

## Verification

From the repository root: `.\bapp\gradlew.bat -p bapp check verifyNativeDocumentation --offline`. Browser/native integration uses explicit tasks in [the build guide](../../../../../../README.md).
