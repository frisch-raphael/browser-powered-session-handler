# lab source blueprint

## Overview

Groups the documented source branches below; this directory defines no additional runtime API.

## Interface

- [federation](./federation/README.md): source boundary and contract.

## Invariants

- Child contracts preserve the owning runtime boundary. [`FederationApplication.java:FederationApplication.main`](./federation/FederationApplication.java)

## Side Effects

- Role startup opens HTTPS and private control listeners. [`FederationApplication.java:FederationApplication.main`](./federation/FederationApplication.java)

## Verification

From the repository root, with Java 21:

```powershell
.\bapp\gradlew.bat -p bapp :federation-client:test --offline
```
