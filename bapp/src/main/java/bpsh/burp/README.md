# Burp adapters

## Overview

Concrete integration boundaries; domain policy does not import these packages.

## Interface

- [http](./http/README.md)
- [ui](./ui/README.md)

## Invariants

Child contracts own their invariants; the package graph is enforced by `verifyArchitecture`.

## Side Effects

Delegated to the concrete child adapters.

## Verification

From the repository root: `.\bapp\gradlew.bat -p bapp verifyArchitecture --offline`.
