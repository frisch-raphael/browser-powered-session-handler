# Authentication lab Java package

## Overview

Canonical Java fixture applications, resource ownership and evidence collectors. Production authentication is exercised through captured BApp builds; these fixtures do not reimplement its runner.

## Interface

- [`ScenarioCatalog.java:ScenarioCatalog`](./ScenarioCatalog.java): `load, select, requirements, profiles, requirement`. Loads the exact catalog inventory, validates requirements/bindings, and selects deduplicated profile members.
- [`LabMain.java:LabMain`](./LabMain.java): `main, run`. Dispatches metadata, serving, owned lifecycle operations and evidence collection; returns status 0, 2 or 3.
- [`LabJson.java:LabJson`](./LabJson.java): bounded strict UTF-8 JSON, closed fields, owned paths and streamed artifact hashes shared with the GUI helper. `ScenarioCatalog.parseJson` retains its catalog exception interface.
- [`LabHostInputs.java:LabHostInputs`](./LabHostInputs.java): validates host CLI, private VM configuration, captured invocation artifacts and the fixed host scenario inventory.
- [`LabHostCoordinator.java:LabHostCoordinator`](./LabHostCoordinator.java): concurrent Windows/Linux jobs from one capture, isolated platform reports, finite private VM transport and cancellation. One platform failure does not cancel the other; aggregate results retain Windows/Linux order. Acceptance requires independently validated evidence and current automated bindings.
- [`LabHostVmTransport.java:LabHostVmTransport`](./LabHostVmTransport.java): invokes existing helpers with bounded subprocesses, hidden Windows execution and suppressed private output/errors.
- [`LabHostArtifactCache.java:LabHostArtifactCache`](./LabHostArtifactCache.java): keeps two replaceable current-byte slots under each dedicated guest root. Every fresh deployment checks the captured source and cached/copy SHA-256; a missing or mismatched slot is overwritten from the current capture. No prior report grants coverage.
- [`LabHostGuiProtocol.java:LabHostGuiProtocol`](./LabHostGuiProtocol.java): private session/command/receipt schema and a claim journal that prevents resending ambiguous GUI actions.
- [`LabHostGuest.java:LabHostGuest`](./LabHostGuest.java): guest-local lab/Burp ownership, checksum/prerequisite checks, GUI primitive qualification and process cleanup. Full scenario acceptance is still under implementation.
- [`LabHostMemory.java:LabHostMemory`](./LabHostMemory.java): bounded 200 ms target RSS sampling of one owned Burp PID/start identity, independent observer cleanup and numeric GC summaries. Missing, truncated, rotated or incomplete observations cannot qualify the memory check; raw logs stay private.
- [`LabHostScenarios.java:LabHostScenarios`](./LabHostScenarios.java): nine fixed real-Burp recipes using shared fixture owners, real GUI operations and independent server/probe joins. Qualification is separate from catalog acceptance.
- [`LabHostEvidence.java:LabHostEvidence`](./LabHostEvidence.java): validates captured inputs, exact source inventories, both platforms, all fixed recipes, GUI deadlines, receiving applications, memory and cleanup. Only its validated `VerifiedRun` can prove a current HOST binding. `collectResult` returns a typed outcome and writes normalized evidence; manual rows remain unperformed.
- [`LabHostObservations.java:LabHostObservations`](./LabHostObservations.java): bounded independent receiver journal. Records synthetic correlation, credential presence, response status and accepted identity; never retains credential, header or body values. Pending, invalid correlation and truncated captures cannot qualify complete evidence.
- [`LabRun.java:LabRun`](./LabRun.java): `start, prepareCase, reset, close, CaseLease`. Owns a run, versioned case leases, faults, checkpoints, snapshots and private control listener.
- [`ControlledApplication.java:ControlledApplication`](./ControlledApplication.java): `localClientBuilder, Origin`. Provides direct local HTTP clients and owned listeners; routes canonical login and protected-use traffic.
- [`FixtureIdentityStore.java:FixtureIdentityStore`](./FixtureIdentityStore.java): `Role, Secret, Issuance, Accepted, login, accept, rotate, revoke, advance`. Issues private role credentials and verifies account, issuance, role, expiry and revocation.
- [`LoginFlows.java:LoginFlows`](./LoginFlows.java): `handle`. Serves forms, JSON/JWT login, redirect chains, cookie selection, fresh-state and response-surface fixtures.
- [`IngressSentinel.java:IngressSentinel`](./IngressSentinel.java): `Snapshot, address, snapshot, await, close`. Counts observed connections, completed TLS handshakes and decrypted application bytes.
- [`LabTls.java:LabTls`](./LabTls.java): `PreparedCa, Material, prepare, loadPrepared, loadServer, createServer`. Creates and validates dedicated CA/leaf material and scoped TLS contexts.
- [`FederationEnvironment.java:FederationEnvironment`](./FederationEnvironment.java): `Spec, Ports, startProvider, startApplications, signingKeyIds, confirmResourceAbsent, close`. Owns prepared provider containers/network/port leases and the single active client/API pair.
- [`FederationApplications.java:FederationApplications`](./FederationApplications.java): `clientOrigin, resourceOrigin, runtimeIdentity, clientSnapshot, armProtocol, releaseProtocol, awaitProtocolCheckpoint, close`. Validates frozen artifacts, launches owned child JVMs and authenticates control/readiness/cleanup.
- [`TransportFixtures.java:TransportFixtures`](./TransportFixtures.java): `Material, Serving, UnauthenticatedProxy, https, CertificateIssuer`. Shares software-token material validation, HTTP/CONNECT proxies, TLS targets and certificate-bound issuance fixtures.
- [`LabEvidence.java:LabEvidence`](./LabEvidence.java): `captureFixture, collectFixtures, catalogFingerprint, configurationFingerprint, fixtureBindingsCurrent`. Joins current fixture JUnit XML, safe HTTP observations and source/configuration/artifact identities.
- [`LabProductionEvidence.java:LabProductionEvidence`](./LabProductionEvidence.java): `configurationFingerprint, federationInputs, collect, collectProfiles, collectTransportProfile`. Checks captured production contexts and scoped observations before writing normalized results.
- [`RefreshBindings.java:RefreshBindings`](./RefreshBindings.java): `main`. Explicit maintenance entry point for reviewed source/configuration fingerprints; runs no acceptance.
- [`LabBuildInputs.java:LabBuildInputs`](./LabBuildInputs.java): `configurationFiles`. Package-private shared closed-field configuration inventory validation.
- [`LabBrowserEvidence.java:LabBrowserEvidence`](./LabBrowserEvidence.java): `supports, valid, facts`. Checks browser proofs, page events and owned resource observations.
- [`LabConfigurationEvidence.java:LabConfigurationEvidence`](./LabConfigurationEvidence.java): `supports, valid, facts`. Checks registry/editor/storage observations.
- [`LabEncodingEvidence.java:LabEncodingEvidence`](./LabEncodingEvidence.java): `supports, valid, facts`. Checks independent native byte comparisons without implementing encoders.
- [`LabInjectionEvidence.java:LabInjectionEvidence`](./LabInjectionEvidence.java): `supports, valid, facts`. Checks wire and protected-service injection observations.
- [`LabLifetimeEvidence.java:LabLifetimeEvidence`](./LabLifetimeEvidence.java): `supports, valid, facts`. Checks existing lifetime/coordinator observations and supplies shared typed-field checks.
- [`LabLimitEvidence.java:LabLimitEvidence`](./LabLimitEvidence.java): `LIMITS, supports, valid, facts`. Checks declared parser/extractor boundary observations.
- [`LabOutputEvidence.java:LabOutputEvidence`](./LabOutputEvidence.java): `supports, valid, facts`. Checks complete publication and retired-generation observations.
- [`LabRecoveryBrowserEvidence.java:LabRecoveryBrowserEvidence`](./LabRecoveryBrowserEvidence.java): `ID, valid, facts`. Checks ordered real-browser recovery lifecycle and protected-response observations.
- [`LabResourceEvidence.java:LabResourceEvidence`](./LabResourceEvidence.java): `supports, valid, facts`. Checks bounded coordinator ownership and released reservations.
- [`LabRetryEvidence.java:LabRetryEvidence`](./LabRetryEvidence.java): `supports, valid, facts`. Checks existing retry-owner counts, causes and terminal state.
- [`LabTagFailureEvidence.java:LabTagFailureEvidence`](./LabTagFailureEvidence.java): `supports, valid, facts`. Checks whole-request rejection and safe unresolved-tag diagnostics.
- [`LabTagSelectionEvidence.java:LabTagSelectionEvidence`](./LabTagSelectionEvidence.java): `supports, valid, facts`. Checks exact intended outputs and independent journey observations.
- [`LabTransportEvidence.java:LabTransportEvidence`](./LabTransportEvidence.java): `input, read, preparationCurrent, facts`. Joins transport captures and process observations with explicit owned preparation.

- [`HttpAuthenticationFixture.java:HttpAuthenticationFixture`](./HttpAuthenticationFixture.java): owns multi-user Basic, strict NTLMv1 and NTLMv2 applications and safe account/connection observations.
- [`NtlmChallengeVerifier.java:NtlmChallengeVerifier`](./NtlmChallengeVerifier.java): independently verifies the selected NTLM response using lab-only primitives.
- [`LabHttpAuthenticationEvidence.java:LabHttpAuthenticationEvidence`](./LabHttpAuthenticationEvidence.java): validates the separate HTTP profile's actual server and adapter facts.
- [`LabObservationCapture.java:LabObservationCapture.write`](./LabObservationCapture.java): writes safe facts inside the existing isolated invocation envelope; ordinary native runs write no acceptance capture.

## Invariants

- Catalog loading is metadata only; exact file inventory, profile membership, closed fields, duplicate JSON keys and binding witnesses are validated. [`ScenarioCatalog.java:ScenarioCatalog.loadResources`](./ScenarioCatalog.java); [`ScenarioCatalog.java:ScenarioCatalog.parseJson`](./ScenarioCatalog.java)
- Run and case generations are checked before mutation; reset retires old cases and close releases gates before draining owned work. [`LabRun.java:LabRun.prepareCase`](./LabRun.java); [`LabRun.java:LabRun.reset`](./LabRun.java); [`LabRun.java:LabRun.CaseLease.close`](./LabRun.java)
- Protected routes require exactly the selected B/C1/C2 roles; ordinary combinations share one issuance, while independent-cookies permits same-account distinct issuances. [`ControlledApplication.java:ControlledApplication.protectedRoute`](./ControlledApplication.java); [`FixtureIdentityStore.java:FixtureIdentityStore.accept`](./FixtureIdentityStore.java)
- Fixture and production passes require matching current context, binding, XML and observed facts; incomplete execution remains blocked. [`LabEvidence.java:LabEvidence.collectFixtures`](./LabEvidence.java); [`LabProductionEvidence.java:LabProductionEvidence.collect`](./LabProductionEvidence.java)
- Provider operations validate pinned artifacts and owned resource identities; client/API origins serve one case at a time. [`FederationEnvironment.java:FederationEnvironment.startProvider`](./FederationEnvironment.java); [`FederationEnvironment.java:FederationEnvironment.startApplications`](./FederationEnvironment.java); [`FederationApplications.java:FederationApplications.validateReadiness`](./FederationApplications.java)

## Side Effects

- Creates loopback listeners, virtual-thread executors, private descriptors and JSONL evidence. [`LabRun.java:LabRun.start`](./LabRun.java); [`LabEvidence.java:LabEvidence.write`](./LabEvidence.java)
- Explicit federation setup launches Docker and child JVM processes, writes private launch/TLS material, and removes verified owned resources during cleanup. [`FederationEnvironment.java:FederationEnvironment.createResource`](./FederationEnvironment.java); [`FederationApplications.java:FederationApplications.start`](./FederationApplications.java); [`LabTls.java:LabTls.keytool`](./LabTls.java)
- Transport serving reads prepared software material, claims it once and starts local TLS/proxy listeners. [`TransportFixtures.java:TransportFixtures.Material.claim`](./TransportFixtures.java); [`TransportFixtures.java:TransportFixtures.Serving`](./TransportFixtures.java)
- Explicit refresh rewrites catalog fingerprints. Federation input enumeration includes every regular file under federation-client/src/main, including documentation. [`RefreshBindings.java:RefreshBindings.refresh`](./RefreshBindings.java); [`LabProductionEvidence.java:LabProductionEvidence.federationInputs`](./LabProductionEvidence.java)

## Verification

From the repository root, with Java 21:

```powershell
.\bapp\gradlew.bat -p bapp :auth-lab:test --offline
```
