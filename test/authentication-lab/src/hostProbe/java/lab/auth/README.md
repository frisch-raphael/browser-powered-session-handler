# Burp host observation helper

## Overview

Separate Montoya extension for a manual Extensions-origin request checkpoint and opt-in passive callback observations.
The same developer JAR packages the [public JDK GUI driver](../../../../hostGui/java/lab/auth/gui/README.md)
and pinned Gson. The GUI worker drives genuine native Burp controls; the passive
probe never authenticates or forwards intercepted requests itself.

## Interface

- [`HostProbeExtension.java:HostProbeExtension.initialize`](./HostProbeExtension.java): registers the Auth lab probe tab and unload cleanup; the operator selects a raw request and sends once.
  In an owned GUI invocation it also writes safe Burp/JVM identity to the private
  run directory. It registers no product control endpoint or bytecode transformer.

## Invariants

- Only HTTP(S) origins whose resolved addresses are loopback are admitted; input size is 1 byte to 4 MiB and captured-credential roles are distinct B/C1/C2. [`HostProbeExtension.java:HostProbeExtension.dispatch`](./HostProbeExtension.java)
- Captured-credential proof requires HTTP 200, expected account/roles and an issuance identifier. HTTP-authentication proof instead requires the expected server-reported account and BASIC/NTLM_V1/NTLM_V2 type. Result metadata excludes raw credentials. [`HostProbeExtension.java:HostProbeExtension.dispatch`](./HostProbeExtension.java); [`HostProbeExtension.java:HostProbeExtension.shape`](./HostProbeExtension.java)

## Callback observation

The Observe callbacks tab accepts explicit HTTP(S) origins using localhost, 127.0.0.1 or [::1]. It compares the actual request service without resolving addresses, inferring a listener or modifying a request. Its case label is local metadata and is never added to traffic.

Capture fields are sequence, case, callback family, family-local ID, phase, tool, actual incoming listener (Proxy only), HTTP version, status and presence of the HTTP-authentication directive. Proxy and global IDs remain separate; no annotation or content bridge is assumed. No URL targets, header values, request bodies or credential values are retained. The 1,000-event bound marks overflow as incomplete. Clear and export are local tab actions; there is no remote-control service.

Observers return unchanged continuation actions and perform no authentication or application dispatch. Callback traces establish host observations, not server-side receipt or account acceptance; use independent fixture observations for those claims. The Send once operation retains its existing single-dispatch behavior. Unload deregisters callbacks, clears captures and stops the owned worker.

## Side Effects

- Creates Swing UI and a single daemon worker, reads the selected file and calls Montoya sendRequest once per dispatch. [`HostProbeExtension.java:HostProbeExtension.initialize`](./HostProbeExtension.java); [`HostProbeExtension.java:HostProbeExtension.dispatch`](./HostProbeExtension.java)
- Writes a CREATE_NEW safe .probe.json record beside the selected request; unloading shuts down the worker. [`HostProbeExtension.java:HostProbeExtension.retain`](./HostProbeExtension.java); [`HostProbeExtension.java:HostProbeExtension.initialize`](./HostProbeExtension.java)

## Verification

From the repository root, with Java 21:

```powershell
.\bapp\gradlew.bat -p bapp :auth-lab:compileHostProbeJava --offline
```
