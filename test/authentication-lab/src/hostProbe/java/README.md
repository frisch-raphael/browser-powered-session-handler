# java source blueprint

## Overview

Groups the documented source branches below; this directory defines no additional runtime API.

## Interface

- [lab](./lab/README.md): source boundary and contract.

## Invariants

- Only explicit local request dispatch is exposed through the manual probe. [`HostProbeExtension.java:HostProbeExtension.dispatch`](./lab/auth/HostProbeExtension.java)

## Side Effects

- Registers Swing UI, reads the selected file and retains safe probe metadata. [`HostProbeExtension.java:HostProbeExtension.initialize`](./lab/auth/HostProbeExtension.java); [`HostProbeExtension.java:HostProbeExtension.retain`](./lab/auth/HostProbeExtension.java)

## Verification

From the repository root, with Java 21:

```powershell
.\bapp\gradlew.bat -p bapp :auth-lab:compileHostProbeJava --offline
```
