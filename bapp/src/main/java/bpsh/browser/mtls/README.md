# Browser client-certificate transport

## Overview

Owns PIN-free PKCS#11 discovery, selected device material and attempt TLS routing.

## Interface

- [JourneyTlsProxy](./JourneyTlsProxy.java): Owns a fresh authenticated loopback LittleProxy endpoint and immutable TLS identity per attempt.
- [Pkcs11Discovery](./Pkcs11Discovery.java): PIN-free PKCS#11 discovery through the standard function table; no session, login or finalization calls.
- [Pkcs11DiscoveryMain](./Pkcs11DiscoveryMain.java): Owned PIN-free helper entry point; native vendor output is never used as a UI protocol.
- [Pkcs11DiscoveryProcess](./Pkcs11DiscoveryProcess.java): Runs discovery in the bundled Java runtime, isolating its native bridge from host classloaders/libraries.
- [Pkcs11Failures](./Pkcs11Failures.java): Converts device-boundary failures into safe operation-specific explanations; raw causes are never retained.
- [Pkcs11IdentityManager](./Pkcs11IdentityManager.java): Owns shared PKCS#11 providers/login state and slot-level PIN suppression inside the extension.
- [ProxyCertificateFactory](./ProxyCertificateFactory.java): Creates ephemeral host-appropriate browser-facing certificates for one owned mTLS proxy key.

## Invariants

Pkcs11IdentityManager.java pins selection to an exact certificate fingerprint. JourneyTlsProxy.java restricts identity use to configured HTTPS origins and keeps upstream certificate/hostname verification.

## Side Effects

Loads vendor middleware, starts discovery helpers and local TLS listeners, retains shared native material and closes only owned resources.

## Verification

From the repository root: `.\bapp\gradlew.bat -p bapp check verifyNativeDocumentation --offline`. Browser/native integration uses explicit tasks in [the build guide](../../../../../../README.md).
