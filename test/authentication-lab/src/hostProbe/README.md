# hostProbe source blueprint

## Overview

Groups the documented source branches below; this directory defines no additional runtime API.

## Interface

- [java](./java/README.md): source boundary and contract.

## Invariants

- The Send once tab performs explicit local request dispatch. The Observe callbacks tab passively records only explicitly selected literal loopback fixture origins and never dispatches requests. [`HostProbeExtension.java:HostProbeExtension.dispatch`](./java/lab/auth/HostProbeExtension.java)

## Side Effects

- Registers Swing UI, reads the selected file and retains safe probe metadata. [`HostProbeExtension.java:HostProbeExtension.initialize`](./java/lab/auth/HostProbeExtension.java); [`HostProbeExtension.java:HostProbeExtension.retain`](./java/lab/auth/HostProbeExtension.java)

Observation is opt-in. Choose comma-separated local HTTP(S) origins and a safe case label, enable observation, then generate traffic through the product. Clear capture between cases and export from the local tab. Each capture retains at most 1,000 events; overflow is incomplete evidence. Family-qualified IDs are recorded independently and are never joined across callbacks. No URL targets, request bodies or credential values enter the capture. See [the package contract](java/lab/auth/README.md).

## Verification

From the repository root, with Java 21:

```powershell
.\bapp\gradlew.bat -p bapp :auth-lab:hostProbeJar --offline
```

The JAR also includes the test-only [native GUI driver](../hostGui/java/lab/auth/gui/README.md)
and shared strict JSON/protocol utilities. No authentication engine is bundled.
