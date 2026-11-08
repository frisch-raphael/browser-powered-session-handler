# Authentication test lab

The maintained Java lab owns controlled login applications, protected credential checks, production acceptance overlays, real federation clients and transport fixtures. Commands and prerequisites are in [the lab guide](../../test/authentication-lab/README.md). [Case definitions](authentication-test-lab-cases.md), [data/execution contracts](authentication-test-lab-contracts.md) and [terms](authentication-test-lab-terms.md) specify the finite checks.

## Architecture and ownership

`test/authentication-lab` is a separate Gradle Java module. `ControlledApplication`, `LoginFlows` and `LabRun` own the purpose-specific HTTP/HTTPS servers and lifecycle. `TransportFixtures` owns shared HTTP/CONNECT and mTLS mechanics. Native test facades delegate common behavior to these owners while retaining their test-specific callbacks.

`test/federation-client` has its own locked Spring/Security/OpenSAML graph and pinned provider/browser-adapter assets. It implements the application, client and resource roles needed for real OAuth, SAML and brokered login journeys. These dependencies never enter the extension's runtime JAR.

Production acceptance overlays live under `production-tests/bpsh` and run only in isolated captures. Ordinary native tests remain under `bapp/src/test/java/bpsh`. Reuse existing assertions, fixtures and policy seams; do not add a second authentication engine, browser lab or generic server implementation.

## Catalog and execution

`src/main/resources/catalog/catalog.json` indexes nine data files and exact named profiles. Expanded requirement rows, expected facts, prerequisites, evidence layers and callable bindings are explicit data. The validator rejects ambiguous JSON, unknown fields, invalid domains and stale or inconsistent bindings. A binding establishes ownership, not a passing result.

Each profile selects a finite union of requirement IDs and deduplicates shared execution owners. Fixture-only checks do not count as product acceptance. Out-of-scope entries remain explicit exclusions and cannot run or earn passing coverage. Manual host and capability assessments require their own actual observations.

The extension is the product under test. Keycloak, Spring Security and OpenSAML supply infrastructure; their general protocol-validator behavior is not extension coverage. Harness checks are justified only when needed to trust an extension result. Configured upstream proxy authentication remains outside product scope; credentials on the extension-owned mTLS proxy have separate ownership.

## Controlled applications and independent proof

Prepared case URLs include their generation. Typed private controls own faults, held responses, releases, revocation, fixture-clock advances, snapshots, reset and stop. Application traffic cannot invoke those controls. A stale URL or lease cannot mutate a replacement case. Cleanup is bounded and reported explicitly.

Successful login issues a fresh account/issuance-bound bearer and cookies. Protected requests validate the selected credential roles independently, including malformed, missing, expired and mismatched combinations. Strict combinations require a common issuance; the independent-cookie route separately tests matching-account cookies from distinct logins.

Browser cases exercise real form actions, redirects, cookies, JSON/regex output, popup/frame/CORS/service-worker surfaces, fresh context state and protected credential use. Test output must identify the expected account, actual completed issuance and selected roles. HTTP 200 or captured credentials alone cannot establish successful application authentication.

Time-dependent tests use gates and fixture clock controls where available, keeping measured product deadlines distinct from simulated server time. Real browser creation/closure and OS process cleanup require their own observations; the application cannot pretend to observe those boundaries.

## Production captures and evidence

Each production invocation captures the current checkout, exact selected sources, overlays, build/configuration inputs and resolved artifacts. The capture audit, generated plan, JUnit reports, protected proofs and safe resource observations must agree before a result passes. Source changes require a new invocation. Missing/empty discovery, skips, changed XML, stale fingerprints or contradictory observations prevent acceptance.

Configuration inputs are shared through `configuration-inputs.json`. Intentional binding changes use `:auth-lab:refreshBindings`; review the diff, then run acceptance in a separate invocation against rebuilt catalog resources. Refreshing fingerprints grants no passing coverage.

Generated run material stays in ignored build directories with private ownership. Reports omit tokens, raw private requests/responses, browser profiles, PINs and control keys. Examples use the production serializer/parser and contain no acquired credentials. Export live examples from the running case generation and regenerate them after reset.

## Recovery, transport and host boundaries

Component owners verify admission, coalescing, lifetime, retries, publication generations, cancellation, pause/rearm, recovery and atomic request mutation. Browser owners establish actual runner/resource/credential behavior. The [authentication contract](bapp-owned-authentication.md) owns the production policy, including three-attempt cycles and one separately sent replay per eligible original.

Software-token transport checks use explicit installed middleware tools and a fresh disposable SoftHSM store. `test/pkcs11_fixture.py` is an optional developer utility that prepares new owned material; the operational applications and tests run in Java. No existing user or physical-token store is reset. Software-token results do not qualify a physical device.

Federation uses dedicated named HTTPS origins and exact client/provider configuration. Asset preparation and hosts/trust installation are explicit prerequisites, separate from normal tests and actual journey acceptance. [Windows setup](../../test/authentication-lab/Windows-Federation-Setup.md) describes current preparation and removal.

The Burp matrix uses the exact loaded artifact, actual tool origins and protected identities. The separate host-probe extension supplies the Extensions-origin action without adding a product control endpoint. Preserve ordinary interception and keep host results separate from lower-layer proofs. [Capability recipes](capability-assessments.md) define the remaining manual assessments without implying support.

## Verification

Use the existing root/native, lab fixture and selected production-profile tasks described in the lab guide. Select the smallest current owner set that proves the change, then complete required aggregate checks. A source method, passing subset, prepared provider or packaged payload cannot stand in for another evidence layer.
