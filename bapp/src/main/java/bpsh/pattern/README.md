# Bounded regular expressions

## Overview

Shares bounded RE2 compilation between session detection and request URL rules.

## Interface

- [BoundedRegex](./BoundedRegex.java): Compiles expressions with caller-selected flags; failures expose only a reason and optional syntax position.

## Invariants

Source must be nonblank and at most 4096 UTF-8 bytes. Compiled programs contain at most 10,000 instructions. Failure diagnostics retain neither the source nor a chained pattern-bearing exception. Callers own matching semantics and context-specific messages.

## Side Effects

None. This leaf has no application or host dependencies and retains no cache.

## Verification

From the repository root: `.\bapp\gradlew.bat -p bapp :test --tests bpsh.pattern.BoundedRegexTest --tests bpsh.burp.http.SessionRecoveryTest :verifyArchitecture :verifyNativeDocumentation --offline`.
