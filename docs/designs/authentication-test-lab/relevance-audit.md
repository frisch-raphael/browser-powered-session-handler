# Test-suite relevance audit

The A8 inventory and execution records below remain historical. The subsequent integrated-main source audit, reuse decisions and full automated fix qualification are recorded in [findings fix verification](findings-fix-verification.md), with its current 363-declaration inventory in p2-predecessor-audit.json. The current ownership ledger records 912 automated PASS; its archived predecessor (historical reference) preserves the A8 results described below. Manual host observations and sixteen capability assessments remain separate.

2026-11-06. Code review complete; the full custom-verifier matrix is retained after user review. Automated post-audit qualification is recorded below; actual Burp/manual work remains outstanding.

The subject is the extension's behavior, especially whether returned credentials authenticate the intended account and login session. A verification service is the protected URL used to establish that: for example, accepting the extension's bearer and cookie together as user2, while rejecting a duplicated cookie or a credential from another login. Checks of that service are harness qualification, not product coverage.

The refreshed review uses immutable A8 production boundary 4057a832e087b96e25a819d9b8b027e8ece19c89e2f69aaadf603c097c7e52df and the current test overlays. The qualification records below distinguish the historical A7 runs from the completed A8 runs. The compiler-parsed owner inventory (historical reference) now covers 477 annotated declarations: 249 selected predecessor/overlay owners, 109 harness declarations, 118 unselected declarations and one installation owner reused externally. Every selected class has an explicit purpose. Unselected upstream declarations remain outside the execution allowlist; copying a helper-containing source file does not mean all its tests run. The decision ledger (historical reference) records 28 exclusions and the 504 fixture cases restored after user review, with previous binding hashes where available.

## Decisions

| Area | Decision | Why and retained evidence |
| --- | --- | --- |
| Test-application credential matrix | Retain all 511 combinations and twelve explicit controls as harness validation. | A verifier that incorrectly accepts missing credentials, mixed accounts or mixed login issuances could create a false extension pass. The full matrix checks our custom matching rules through actual HTTP responses and independent input expectations. Positive cases also prevent a correct extension result from being rejected by a broken verifier, so it guards false failures as well as false passes. The proposed 504-case retirement was reversed after user review. None of these 523 checks earns extension coverage; actual extension outputs are proven separately. |
| Chromium cookie-policy matrix | Exclude ten unimplemented BROW.cookie-rules entries. | These would test Chromium's Domain/Path/Secure/HttpOnly/SameSite implementation. Retain actual production cookie applicability/selection, redirect-hop cookies, HttpOnly extraction, HTTPS cookie use and real OIDC/SAML/broker flows. General cross-site-cookie-policy conformance is not qualified. |
| Repeated real-browser recovery matrix | Exclude three higher-layer copies. | Coordinator/recovery owners establish three attempts, persistent pause, cancellation and one replay per original. The existing native recipe proves one initial login plus three sequential recovery attempts and eight one-time replays. Native negative/cancellation cases establish per-attempt process cleanup. |
| Unlisted local-proxy SPKI browser probe | Remove the selected owner and exclude its requirement. | It supplied Chromium launch arguments itself, so it could pass even if production built them incorrectly. Retain actual production-runner positive trust, wrong-chain/wrong-host, allowed-origin and selected-certificate proofs. |
| PrivateKey.getEncoded() == null | Remove the assertion. | This checks the software provider's export behavior, not extension behavior. Selected-key use remains proven by TLS and the expected server-observed certificate fingerprint. Physical-device interoperability remains unqualified. |
| Independent-cookie verification-service test | Restore as harness validation. | This is a deliberately retained legacy verifier route. Its custom same-account/different-issuance rule and honest issuance reporting need their own control, so a fixture defect cannot mislead testing. This earns no extension coverage and does not permit automatic composition of credentials from separate journeys. |
| Static IdP seed settings | Remove copied lifespan, PKCE/grant and audience-constant assertions. | The renderer does not implement these protocols. Retain owned-port/callback rewriting, distinct private-client secrets, identity/client uniqueness and invalid-template rejection. Actual provider-backed extension flows remain. |
| Configured upstream proxy authentication | Keep excluded; remove unused fixture support. | The A7 audit already excluded these owners. The copied authenticated ForwardProxy branch was unused and is now removed. Extension-owned internal mTLS proxy credentials remain in scope. |
| Signed-message/provider validation | Keep the prior fourteen exclusions. | Do not retest IdP, Spring/Nimbus, SAML signature or cryptographic-library conformance. One custom resource audience/token-kind control prevents the verification endpoint from accepting the wrong artifact. |

The slow-form/held-token resource entries share the independent-caller timeout execution. This is a component proof: the coordinator cannot observe whether an admitted acquisition is waiting for a form or a token. It proves the caller's independent deadline and released reservation, not another browser/form execution. Native timeout/cancellation checks supply browser evidence.

The removed SPKI probe also contained an extension-owned assertion that a TLS engine without a target peer is rejected. That assertion was moved into the existing local mTLS proxy owner, so removing the Chromium probe loses no extension guard.

The existing same-level tag and recovery interaction matrices remain. They exercise actual parser/resolver/coordinator/recovery combinations, exact transformations, shared publications and protected-request outcomes. They are inexpensive component checks and are not duplicated as browser matrices.

## Retained ownership

- Acquisition/classification: actual extractors and failure mapping; controlled inputs replace network/device boundaries where the claim permits it.
- Tags/injection/recovery: complete bytes, publication identity/version, account/issuance acceptance, duplicate rejection and actual action/replay counts.
- Diagnostics: actual event rows/details/current editor state and applicable request feedback. Success clears active errors; history may retain them. An unresolved alias has request/log feedback without inventing a saved journey.
- Browser/federation: actual production runner and maintained provider clients; usable received credentials, fresh contexts and observed process cleanup. Infrastructure protocol validation earns no product coverage.
- Harness: custom fixture/control/lifecycle and report guards preventing concrete false passes, stale/foreign evidence, credential leaks or unobserved live resources. These remain separate from product coverage.

No production source, sibling-worktree source, or preserved legacy application/certificate asset is removed. Unselected predecessor UI tests, including a fixed-delay draft/status test, were not adopted. The retained native step smoke has distinct actual browser-action/network-idle/post-step-listener coverage; its bounded delayed response is not simulated backoff or a thirty-second failure test.

## Counts and limits

The catalog retains 980 historical IDs:

| Disposition | Requirements |
| --- | ---: |
| Active product behavior | 389 |
| Active verification-service checks | 523 |
| Manual Burp checkpoints | 24 |
| Manual capability assessments | 16 |
| Excluded, never counted as passes | 28 |

All 912 active automated requirements have callable bindings, sharing 851 executions. A binding is an inspected link to a test, not a passing result. Source/configuration fingerprints and actual observations still control acceptance.

The rollback component check proves preservation of old data and absence of automatic imports. It does not claim a previous extension binary has been loaded successfully. Actual Burp/offline/unload-reload checks and physical-device interoperability remain separate.

F02, F04, F05 and F06 remain confirmed against A8. This review removes no failing product expectation. Automated module/component/browser/federation/transport results are recorded below; actual host work and the failing product gates still prevent final qualification or legacy cutover.

## Recorded qualification

After restoring the matrix, invocation `0618490c-ac67-4875-a480-85fc8b9904f2` passes all 523 fixture requirements (42 accepted / 469 rejected matrix inputs plus twelve controls), all 720 module checks and the 27 federation-client checks. Its component task passes 520/523 checks, with only the existing F02/F04 failures; normalized results are 312 PASS / one F02 FAIL and complete cleanup. Browser invocation `011d89c6-2d59-478a-81a9-dbfc25ded653`, completed just before the matrix metadata restoration, passes 50/51 checks with the existing F06 failure, no blocked/skipped results and complete cleanup. These are A7 results. Native transport invocation `717ee8bc-8515-4346-885f-60034d2a004b` records 16 PASS / two known F05/F06 FAIL / one EXCLUDED, no blocked entries and complete cleanup. The same invocation passes all seven federation owners and seventeen requirements, with fourteen provider checks excluded and complete cleanup. The completed A8 qualification is recorded in the following section. Actual host work is still pending; no fixture check counts as extension acceptance.

The live-source refresh adds nine supplied component owners for field-specific runtime/validation feedback, each within the existing diagnostics scope. They cover all action types, observed network/extraction failures, exact multi-output rows, missing middleware/PIN, CA reading and retained dock choice. They use production mappings/UI and bounded controlled inputs; no duplicate browser/error engine is added. Four newly supplied declarations remain outside this lab: a repeated secure-input example, general settings-validation matrix and two widget-only log checks. They remain available in normal product regression. Only two existing overlay bodies change when merging the new predecessor tests: the native certificate picker gains loaded-certificate-state checks, and the recovery owner checks that persistent pause retains the identified input. The compiler-parsed method comparison confirms all other overlaid bodies are preserved.

## A8 qualification and final fixture correction

All 912 active automated requirement bindings now have exact matching results in the ownership ledger: **909 PASS / three FAIL**, with 28 EXCLUDED, 24 manual host checks not performed and sixteen capability assessments unresolved. This is 523 test-application requirements plus 389 extension requirements. The three failing catalog rows are F02, F05 and F06; F04 remains represented by two additional failing component reproducer inputs, so the product task still fails on it. No existing product failure was removed.

A8 invocation `49e3ecae-dcf3-4c2f-95e2-8866eacd42c9` passes 562/565 component checks and 50/51 browser checks. All 42 newly adopted field-feedback inputs pass. The normalized component/browser results are 312 PASS / one F02 FAIL and 43 PASS / one F06 FAIL, respectively, with complete cleanup. The fixture follow-up `07ace3ab-6bb1-48d4-8ede-5b2444f12654` passes all 523 fixture requirements and **721 module checks**, including the restored independent-cookie route contract. The declaration inventory consequently contains 470 entries: 250 selected product/overlay, 102 harness and 118 outside the lab allowlists.

A8 transport invocation `3c62501c-6138-45b8-b622-abf8f71d2759` records 16 PASS / two known F05/F06 FAIL / one EXCLUDED, with complete cleanup. Federation in that invocation never started: Docker returned an internal server error during image inspection. Its seventeen BLOCKED rows are retained as failed preparation, not product failures or passes. Docker Desktop's normal Restart recovered it without a WSL shutdown or settings change. Federation invocation `1ad0532a-722a-4f30-ab8d-d1dc75fb1fca` then passes seven actual owners and seventeen requirements, fourteen provider exclusions and complete cleanup. This later successful preparation/execution supplies the current matching evidence.

The separate development host-probe JAR compiles and packages only its own classes, using the existing compile-only Montoya API. That build earns no H01 host pass and changes no production artifact or automated binding. Actual host qualification is still outstanding.

## Profile execution and host follow-up

The focused profile commands reuse the existing production owners; they introduce no new authentication case, provider check or browser action. Seven new harness declarations qualify owner selection and aggregation: required IDs cannot disappear, overlapping profiles share methods, unreviewed methods cannot enter, incomplete/duplicated streams cannot pass, failed JUnit evidence cannot be relabeled PASS, and incomplete scope cleanup cannot be reported complete. Their synthetic report inputs are harness qualification only. Both new source files were parsed with the existing Java compiler inventory utility; all 728 module checks pass after the cleanup-label correction.

The actual `credentials` command proves 179 requirements with 239 existing JUnit cases. Combined `baseline,recovery,diagnostics` executes the browser and component tasks once each and reports 134 unique requirements: 130 PASS, one known F02 FAIL, three EXCLUDED, complete cleanup. A subsequent `credentials,diagnostics` run after the cleanup-label correction reports 196 PASS and the same F02 FAIL, no blocked/skipped requirements and complete cleanup. These source-specific profile records do not replace the earlier full A8 qualification or turn its other known failures into passes.

Actual host observations are now separate in [P4 findings](p4-findings.md) and the checkpoint ledger (historical reference): fourteen PASS, three FAIL, two PARTIAL, two specification conflicts, two unavailable Scanner checks and one offline-installation result reused from `install`. No lab/provider validation is counted as Burp acceptance. F02/F04/F05/F06/F07/F08 remain six open production findings; no production fix or newer-source acceptance is inferred.

Following the user's correction, [installation evidence reuse](installation-evidence-reuse.md) replaces the proposed duplicate offline check. The delivered universal JAR's hash and sanitized Windows cold/cache protected proofs were verified read-only. The already-existing packaged-classloader helper had no catalog binding and is removed from the lab's browser allowlist, with its source preserved and its installation ownership recorded. Cold/cache/upgrade/rollback remain with `install`. No authentication catalog row or failing expectation is removed.
