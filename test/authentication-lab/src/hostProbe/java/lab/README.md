# lab source blueprint

## Overview

Groups the documented source branches below; this directory defines no additional runtime API.

## Interface

- [auth](./auth/README.md): source boundary and contract.

## Invariants

- Only explicit local request dispatch is exposed through the manual probe. [`HostProbeExtension.java:HostProbeExtension.dispatch`](./auth/HostProbeExtension.java)

## Side Effects

- Registers Swing UI, reads the selected file and retains safe probe metadata. [`HostProbeExtension.java:HostProbeExtension.initialize`](./auth/HostProbeExtension.java); [`HostProbeExtension.java:HostProbeExtension.retain`](./auth/HostProbeExtension.java)

## Verification

From the repository root, with Java 21:

```powershell
.\bapp\gradlew.bat -p bapp :auth-lab:compileHostProbeJava --offline
```
