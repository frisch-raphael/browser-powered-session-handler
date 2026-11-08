# Federation client

This Java 21 module has its own locked dependency graph: Spring Boot 4.1.2, Spring Security 7.1.2, OpenSAML 5.2.3 and the explicit JUnit 6.1.3 test override. It has no dependency on BApp production classes; canonical lab support is test-only. The additional Shibboleth repository is restricted to its required OpenSAML/Shibboleth groups. The shared verification metadata retains all preceding checksums. Its 346 new entries match published primary-repository checksums or independently fetched primary artifact bytes; the detailed preparation record is `build/p3/preparation/checksum-verification.json`.

Prepare and check the isolated module from the repository root:

```powershell
.\bapp\gradlew.bat -p bapp :federation-client:prepareFederationDependencies
.\bapp\gradlew.bat -p bapp :federation-client:test --offline
```

The fixture decoder uses maintained Spring/Nimbus validation, scoped TLS trust and bounded key fetching. One local check qualifies our API-specific audience/type configuration using already validated claims. Library signature, algorithm and time validation do not add extension coverage. Review each selected test for a concrete extension failure or a necessary harness purpose.

Additional harness checks cover bounded private launch settings, redaction, control authentication/versioning, one actual resource child JVM, and exact cookie/token-byte association even when every identity claim matches. That child serves HTTPS, rejects unauthenticated access, keeps controls on a separate listener, and retains CLOSED before exiting after Stop. Default checks use scoped Java trust and explicit peer hostnames, so they do not depend on Windows hosts/root installation. Both client and resource roles are executable. The client uses Spring's maintained confidential OIDC exchange, the locally pinned official browser adapter and Spring/OpenSAML for real SAML login.

The isolated checks qualify only the harness: private settings, resource proof boundaries, HTTPS/control wiring and retirement of the one backend-failure checkpoint. They do not establish extension coverage or test the IdP's protocol correctness. The explicit `federationContractTest` reuses its prior infrastructure owner to check our parent controls, child startup, reset and stale-generation rejection. Redundant issuer/asset/protocol bootstrap assertions were removed. It never creates an alternate IdP or signed-message validator suite.

The product scope is actual production-runner OAuth/SAML login, usable captured credentials for the expected account, fresh attempts, selected IdP-cookie SSO verification, accurate failure reporting and cleanup. Provider protocol-validator checks are excluded from product acceptance. Review the complete selected suite for duplicate and irrelevant coverage before claiming completion.

Explicit operational entry points, after [Windows preparation](../authentication-lab/Windows-Federation-Setup.md) and local image/adapter preparation:

```powershell
.\bapp\gradlew.bat -p bapp :federation-client:prepareFederationBrowserAdapter --offline
.\bapp\gradlew.bat -p bapp :federation-client:federationContractTest --offline
.\bapp\gradlew.bat -p bapp authLabFederationTest --offline
.\bapp\gradlew.bat -p bapp authLab -PlabProfiles=federation --offline
```

The native task runs the actual captured BApp journey runner against the real provider and client/API roles. Seven owners cover browser outputs, fresh/repeated accounts, backend-cookie login, real SAML-cookie login, truthful feedback after one immediately simulated backend rejection, and broker success/rejection/cancellation. Seventeen catalog requirements share those seven executions. Selected IdP-cookie verification is separate from production attempts and never seeds them. Client/API acceptance proves that the credentials captured by the extension work for the expected account; library validator correctness is not product coverage.

The profile command additionally requires a complete normalized report: seventeen active requirements pass, fourteen provider-validation entries remain excluded, and cleanup is complete. The collector joins the exact JUnit owners, observed output use and lifecycle facts to the invocation, captured source and immutable runtime. A filtered `authLabFederationTest -PlabTests=...` run can pass its selected checks while the full catalog report remains incomplete; it does not accept the whole profile.

The broker captures the upstream IdP cookie, client cookie and access token in one journey. Both providers use the same cookie wire name, which the native configuration currently refuses to select twice even at different domains (L01). The downstream cookie is proved in ordinary OIDC; this limitation is recorded rather than bypassed by renaming cookies or composing separate journeys.

For applications that stay available while you configure a journey in Burp:

```powershell
.\bapp\gradlew.bat -p bapp authLabServe -PlabProfiles=federation '-PlabCase=FED.flow.browser-oidc' --offline
```

Wait for the printed `Federation login` URL and run ID. The public target index links to the actual named client URL; it contains no control key or obtained credential. Use the printed fixture accounts. The same run also prepares the upstream provider, so you can switch to a broker case after reset. One client/API case runs at a time.

Generate the matching native journey from another terminal with `.\bapp\gradlew.bat -p bapp authLabExamples "-PlabRun=RUN_ID" --offline`. Import the printed JSON file and enter fixture password `pass2` in its secure input. The exporter uses the same definition builder and actual native serializer as the real journey tests. Browser OAuth selects bearer/client/IdP-cookie outputs, backend OAuth and SAML select the available client cookie, and the broker selects bearer/client/upstream-cookie outputs. Passwords and acquired credentials are omitted. Exporting performs no authentication. Regenerate after changing the active case; named origins can be reused across reset.

From another terminal, use the printed run ID:

```powershell
.\bapp\gradlew.bat -p bapp authLabReset -PlabRun=RUN_ID --offline
.\bapp\gradlew.bat -p bapp authLabPrepareCase -PlabRun=RUN_ID '-PlabCase=FED.broker.combined-outputs' --offline
.\bapp\gradlew.bat -p bapp authLabStop -PlabRun=RUN_ID --offline
```

Reset retires the old client/API pair and provider login state. Preparation starts a new owned pair before acknowledging readiness. The index displays the new case generation. Parent control routes forward snapshots and the two supported federation checkpoints to the owned client. Generic fixture-clock/fault/revocation controls do not pretend to change real provider sessions. Startup/reset timeouts are upper bounds; successful operations return immediately. The foreground owner retains its own lab runtime, and child services use the frozen federation runtime, so concurrent builds do not replace code loaded by the running environment. Hosting these applications is not a passing test run.

`prepareFederationRuntime` freezes all 105 local runtime JARs in a directory identified by their hashes. Each child validates the manifest and every artifact before launch. This prevents a parallel rebuild from changing a live server. Client/API settings, control keys and launch files stay private in the owning run directory. OS process identity, authenticated readiness, graceful Stop and terminal CLOSED are checked; case reset retires the previous pair before recreating provider state. Ordinary tests never install trust, pull images or download the browser adapter.

The pinned provider image and official browser adapter are recorded in `provider-assets.lock.json`. Their preparation records are under `build/p3/preparation/`. Use the [Windows hosts/trust setup](../authentication-lab/Windows-Federation-Setup.md) to prepare and qualify dedicated material for this checkout. Normal tests never install trust or alter hosts. Preparation alone does not establish successful provider login.

The complete ESM import set is verified, including the official adapter's `deprecations.js`. SAML requests follow the actual owned client policy; provider responses/assertions retain maintained signature validation. The seed explicitly includes the provider session statement. Unknown client routes return an error, and transaction sessions use cookies only, so errors cannot silently initiate a different login protocol or put session IDs in URLs.

## Source contract

### Overview

Source contracts below supplement the operational guidance above. Test-only trees are outside this contract index.

### Interface

- [Source tree](./src/README.md): Java, browser resources.

### Invariants

- Private validated settings select distinct named HTTPS client/resource roles. [`FederationApplication.java:FederationApplication.main`](./src/main/java/lab/federation/FederationApplication.java)

### Side Effects

- Role startup opens HTTPS and private control listeners. [`FederationApplication.java:FederationApplication.main`](./src/main/java/lab/federation/FederationApplication.java)

### Verification

From the repository root, with Java 21:

```powershell
.\bapp\gradlew.bat -p bapp :federation-client:test --offline
```

The evidence inventory includes every regular file under `src/main`, including these contracts. Adding or editing one changes the federation configuration fingerprint used by future acceptance; existing reviewed bindings must be intentionally refreshed and reviewed before a new acceptance invocation. Ordinary compilation has no such evidence gate. See [`LabProductionEvidence.java:federationInputs`](../authentication-lab/src/main/java/lab/auth/LabProductionEvidence.java) and [`LabProductionEvidence.java:collect`](../authentication-lab/src/main/java/lab/auth/LabProductionEvidence.java).
