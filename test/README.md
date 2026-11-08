# Authentication verification tools

## Overview

Maintained Java lab applications and the disposable SoftHSM fixture helper support extension verification. Generated captures and reports belong under ignored build directories.

## Interface

- [authentication-lab](./authentication-lab/README.md): controlled authentication, evidence collection and production acceptance.
- [federation-client](./federation-client/README.md): controlled OAuth and SAML applications.
- [pkcs11_fixture.py:prepare](./pkcs11_fixture.py) creates a new SoftHSM store and writes `fixture.json` with two distinct certificate fingerprints.
- [pkcs11_fixture.py:main](./pkcs11_fixture.py) exposes `--output`, `--module`, `--utility`, `--pkcs-tool` and `--openssl` developer arguments.

## Invariants

- [pkcs11_fixture.py:prepare](./pkcs11_fixture.py) refuses an existing output directory, missing tool files and middleware whose filename does not contain `softhsm`.
- For completed nonzero exits, [pkcs11_fixture.py:run](./pkcs11_fixture.py) reports only the tool name and exit code. Subprocess timeout exceptions propagate; this helper does not guarantee redaction of every exception path.

## Side Effects

- [pkcs11_fixture.py:prepare](./pkcs11_fixture.py) writes a private fixture directory, SoftHSM configuration, test certificates, CA/server private keys and a PIN-bearing manifest. It invokes SoftHSM, OpenSC, OpenSSL and Windows `icacls` where applicable; no existing token store is reset.
- The Java lab's process, listener and evidence lifecycles are documented in its child contracts.

## Verification

From the repository root: `.\bapp\gradlew.bat -p bapp test --offline`.
For helper argument discovery: `python test/pkcs11_fixture.py --help` (does not initialize a fixture). Native acceptance requires an explicitly prepared fresh fixture; see the extension build's `pkcs11IntegrationTest` task.
