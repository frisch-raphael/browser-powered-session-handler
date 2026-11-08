# Restricted filesystem creation

## Overview

Provides OS-specific private-file creation attributes shared by browser setup and journey persistence.

## Interface

- [PrivateFiles](./PrivateFiles.java): Shared local ownership checks; independent of browser installation and library storage.

## Invariants

PrivateFiles.java:creationAttributes requires a supported restrictive POSIX/ACL view; Windows identity comes from the native account rather than user.name.

## Side Effects

Queries filesystem/native account services; callers create the files with returned attributes.

## Verification

From the repository root: `.\bapp\gradlew.bat -p bapp check verifyNativeDocumentation --offline`. Browser/native integration uses explicit tasks in [the build guide](../../../../../../README.md).
