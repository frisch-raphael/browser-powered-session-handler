# Manual Burp host probe

## Overview

Separate Montoya extension source for a manual Extensions-origin request checkpoint.

## Interface

- [`HostProbeExtension.java:HostProbeExtension.initialize`](./HostProbeExtension.java): registers the Auth lab probe tab and unload cleanup; the operator selects a raw request and sends once.

## Invariants

- Only HTTP(S) origins whose resolved addresses are loopback are admitted; input size is 1 byte to 4 MiB and captured-credential roles are distinct B/C1/C2. [`HostProbeExtension.java:HostProbeExtension.dispatch`](./HostProbeExtension.java)
- Captured-credential proof requires HTTP 200, expected account/roles and an issuance identifier. HTTP-authentication proof instead requires the expected server-reported account and BASIC/NTLM_V1/NTLM_V2 type. Result metadata excludes raw credentials. [`HostProbeExtension.java:HostProbeExtension.dispatch`](./HostProbeExtension.java); [`HostProbeExtension.java:HostProbeExtension.shape`](./HostProbeExtension.java)

## Side Effects

- Creates Swing UI and a single daemon worker, reads the selected file and calls Montoya sendRequest once per dispatch. [`HostProbeExtension.java:HostProbeExtension.initialize`](./HostProbeExtension.java); [`HostProbeExtension.java:HostProbeExtension.dispatch`](./HostProbeExtension.java)
- Writes a CREATE_NEW safe .probe.json record beside the selected request; unloading shuts down the worker. [`HostProbeExtension.java:HostProbeExtension.retain`](./HostProbeExtension.java); [`HostProbeExtension.java:HostProbeExtension.initialize`](./HostProbeExtension.java)

## Verification

From the repository root, with Java 21:

```powershell
.\bapp\gradlew.bat -p bapp :auth-lab:compileHostProbeJava --offline
```
