# Main source set

## Overview

Production Java and native schema resources are assembled by the extension build.

## Subdirectories & Boundaries

- [java](./java/README.md): feature packages and extension entry point.

## Interface

The Java entry point is [bpsh.Extension](./java/bpsh/Extension.java). Resource packaging is configured in [build.gradle.kts](../../build.gradle.kts).

## Invariants

Java compilation targets version 21 (`tasks.withType<JavaCompile>` in [build.gradle.kts](../../build.gradle.kts)).

## Side Effects

Runtime effects belong to the [Java contracts](./java/README.md); this source-set container adds none.

## Verification

From the repository root: `.\bapp\gradlew.bat -p bapp check --offline`.
