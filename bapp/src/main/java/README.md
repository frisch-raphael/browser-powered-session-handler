# Production Java

## Overview

The production extension uses named packages beneath `bpsh`.

## Interface

- [bpsh](./bpsh/README.md): composition root and feature contracts.

## Invariants

[verifyArchitecture](../../../gradle/architecture.gradle.kts) enforces package paths, permitted dependencies, framework exclusions and absence of cycles.

## Side Effects

Owned by the concrete integrations indexed in the child contracts.

## Verification

From the repository root: `.\bapp\gradlew.bat -p bapp check verifyNativeDocumentation --offline`.
