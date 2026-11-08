# Extension source sets

## Overview

Production code and native regression tests use matching feature package names.

## Subdirectories & Boundaries

- [main](./main/README.md): production Java and resources.
- `test`: test-only source set; excluded from contract bootstrapping.

## Interface

[Extension.initialize](./main/java/bpsh/Extension.java) is the host entry point.

## Invariants

[build.gradle.kts:tasks.test](../build.gradle.kts) excludes the explicit browser and PKCS#11 integration classes from default tests.

## Side Effects

See [main](./main/README.md) for runtime ownership. Explicit integration tasks can start browsers and native fixtures.

## Verification

From the repository root: `.\bapp\gradlew.bat -p bapp check --offline`.
