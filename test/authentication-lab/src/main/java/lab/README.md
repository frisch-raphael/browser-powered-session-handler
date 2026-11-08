# lab source blueprint

## Overview

Groups the documented source branches below; this directory defines no additional runtime API.

## Interface

- [auth](./auth/README.md): source boundary and contract.

## Invariants

- Child contracts preserve the owning runtime boundary. [`LabRun.java:LabRun.start`](./auth/LabRun.java)

## Side Effects

- Run startup opens local listeners and retains private evidence. [`LabRun.java:LabRun.start`](./auth/LabRun.java)

## Verification

From the repository root, with Java 21:

```powershell
.\bapp\gradlew.bat -p bapp :auth-lab:test --offline
```
