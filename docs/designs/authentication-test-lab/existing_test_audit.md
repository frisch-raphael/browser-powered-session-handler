# Authentication test lab: existing-test reuse audit

* **Author:** rfrisch
* **Date:** 2026-11-04
* **Status:** Preliminary historical snapshot only. The author requires a fresh audit at P2, against the actual predecessor implementation being integrated, before production tests or bindings are added/changed.
* **Scope:** Read-only source audit of the active `java-playwright` worktree, not a test run or a claim that those tests pass.
* **Source root:** `C:/Users/Rapha/orca/workspaces/browser-powered-session-handler/java-playwright/bapp/src/test/java`.
* **Result:** 14 test classes (166 annotated method declarations, including parameterized declarations) and two shared helper files were found. Method declarations are not JUnit invocation or coverage counts. Substantial lower-layer coverage must be reused; new assertions are limited to the gaps below.

The sibling has uncommitted/untracked test work and is still being developed. Hashes below identify only the individual source bytes inspected, not a final branch commit or an atomic repository snapshot. The inventory covers the then-present 16 files; detailed assertion inspection focused on named examples. The dispositions, method names, counts and gaps below are provisional and must not drive edits without the fresh P2 audit. No code was copied, merged, built or executed by this audit.

## Mandatory fresh audit at P2

1. Once the predecessor is available, identify the actual revision selected for integration, including hashes of any accepted uncommitted work.
2. Re-inventory its complete production test tree, shared fixtures, relevant production entry points and Gradle selection/reporting. Do not limit the audit to the 16 files or gaps captured here.
3. Recheck actual assertions and input/parameter witnesses against the current lab requirements. The earlier four-attempt observation or missing protected-use checks may already have been fixed; do not alter current tests solely because this snapshot recorded them.
4. Publish a new reuse/extend/new/blocked mapping and compute unique existing/new executions. Only then add or change production tests, adapters or catalog bindings.
5. If the audited implementation changes before those edits, refresh affected mappings; repeat the complete inventory if the source boundary changed materially.

This gate is scheduled for P2, not another rolling audit during design. Independent review of this design may proceed using the historical snapshot and the explicit gate.

## Required changes to the plan

1. Treat the catalog as **requirements and test bindings**, not an instruction to create a fresh test for every entry. A passing existing method can cover several requirements only when its actual assertions and inputs establish them. Do not assign coverage from a method name alone.
2. Reuse the existing production suites, `CoordinatorFixtures.ManualRuntime`, host doubles and HTTP/TLS/proxy helpers. Fill missing vectors in their owning tests; avoid parallel parser/coordinator/fixture implementations.
3. Update changed production expectations **in place**. In particular, the captured retry test asserts four attempts. It is not reusable unchanged for the agreed three-total-attempt contract. Existing response-invalidation tests likewise do not establish the new replay/pause behavior.
4. Extend the browser tests with actual protected identity where absent. Existing mTLS tests already verify server fingerprints and subsequent protected identity; most ordinary browser tests only assert extraction. These are different gaps, not a reason to rerun every known encoder/cache case through the browser.
5. Remove the proposed extra `TransportFixtureTest` and `PackagedDeploymentTest` suites. Add genuinely missing oracle or artifact assertions to their existing owners. Standalone fixture extraction, if needed, moves shared behavior once rather than keeping another generic server/proxy implementation.
6. Exclude all configured upstream proxy-authentication assertions, including rejection/challenge checks. A mixed existing method must be split before selecting its unauthenticated availability assertions. Internal credentials on the extension-owned mTLS proxy remain in scope. Existing application Basic/Digest capability assessments are unrelated to upstream proxy authentication.

## Requirement-to-existing-test ledger

“Reuse” below describes matching source assertions; it is not a PASS result. “Extend” retains those assertions and adds only the identified gap. “New/blocked” means the source does not establish the new contract. Actual browser/process/wire evidence remains separate from simulated hooks and fake runners.

| Requirement group | Disposition | Existing source evidence | Implementation action |
| --- | --- | --- | --- |
| FIX.matrix / FIX.extra | New fixture assertions | Existing mTLS issuer/resource checks are not the bearer-plus-two-cookies acceptance oracle. | Build the bounded independent 511-input oracle and missing negative controls. Do not claim this proves production request selection. |
| BROW.basic | Extend existing browser tests | BrowserJourneyIntegrationTest.retainedStepsAndSecureInputProduceNormalizedToken checks real steps/secure input and normalized output. | Add protected identity verification to the owning test; add only absent two-page/CSRF/interstitial flows. |
| BROW.redirect | Partial reuse | BrowserJourneyIntegrationTest.actualUserAgentMarkerCoversRedirectsPopupsFramesFetchWorkersAndWebsocketHandshake observes redirect paths. | Reuse navigation/carrier assertions. Add required-cookie-per-hop, method/deep-link and absent exact redirect variants; do not repeat the carrier matrix. |
| BROW.redirect-failure | Partial reuse / gaps | BrowserJourneyIntegrationTest.cancellationKillsOnlyTheOwnedDriverAndReturnsTypedCancellation checks typed cancellation. | Keep that assertion; add missing loop/callback/unreachable outcomes and direct resource-completion evidence. |
| BROW.cookie-selection | Reuse unit selection; extend browser proof | TokenExtractorTest.cookieSelectionRequiresApplicabilityAndUnambiguousIdentity covers exact selectors, ambiguity and expired candidate cookies. | Do not repeat selector mechanics in a new unit suite. Add only real-browser issuance/rotation and protected-use assertions. |
| BROW.cookie-rules | Mostly new browser behavior | Selection of supplied Cookie objects does not establish Chromium Domain/Path/Secure/HttpOnly/SameSite behavior. | Run the actual-browser attribute/cross-site cases; avoid claiming a duplicate of the selector unit test. |
| BROW.surfaces | Partial reuse | BrowserJourneyIntegrationTest already checks early responses, nested extraction paths and owned traffic on frame/popup/fetch/workers. | Reuse those exact assertions. Its marker test extracts a main-page token; token extraction from a popup/frame is a distinct remaining claim. |
| BROW.fresh | Reuse cookies; extend missing state | BrowserJourneyIntegrationTest.earlyJsonAndCookieAttemptsStartWithFreshContextState checks absent prior Cookie headers and fresh values. | Keep the cookie assertion once; add protected-use and local/session-storage/worker isolation only where absent. |
| CORE.outputs | New contract, blocked | Existing Outcome/TokenSnapshot fixtures provide one token. | Add complete-set publication/order/expiry assertions only after the multi-output amendment. No second coordinator implementation. |
| CORE.tag-matrix | Reuse and fill exact-vector gaps | NativeTagPipelineTest already covers raw headers, text bodies, wrappers and snapshots. | Bind matching vectors to existing tests. Parameterize missing location/mode/reference-count combinations in the same owning suite, not a second 48-case pipeline harness. |
| CORE.tag-selection | Partial reuse | NativeTagPipelineTest.rawReferencesPreserveEveryOtherByteAndDoNotApplyAutomaticCredentials and lateGenerationAndVersionChangesPreventCommitAndReservationsAlwaysRelease cover aliases/identities/snapshots. | Add absent three-slot/multi-output combinations after the contract exists; retain repeated-reference acquisition checks from the coordinator. |
| CORE.tag-failure | Mostly reused; revised gaps | NativeTagPipelineTest covers unknown/mixed/malformed references, atomicity, unsupported bodies and output-not-reparsed. | Reuse those assertions. Add only paused-journey and revised output-selector failures. |
| CORE.encoding | Mostly reused | NativeTagPipelineTest wrappersEncodeWholeContentInsideOutAndSelfClosingWrapperNamesRemainAliases, UTF-8/body-length and invalid-target tests assert concrete bytes. | Bind existing assertions for matching inputs. Add only absent exact literals/vectors; do not restate all encoders in a new suite. |
| CORE.limits | Reuse covered limits; fill boundary gaps | NativeTagPipelineTest, TokenExtractorTest and SessionRecoveryTest assert request/wrapper/extraction/regex bounds. | Map each exact below/at/above witness first; add missing nearest-boundary values only. |
| CORE.injection | Reuse baseline; combined gap | NativeTagPipelineTest.ordinaryCookieInjectionReplacesNamedCookieOnceWithoutChangingOthersOrSharedState and ProductionHooks cover baseline mutation/precedence. | Retain once; add combined bearer-plus-cookie and missing settings vectors after the amendment. |
| CORE.tool-policy | Partial reuse | NativeTagPipelineTest.explicitGlobalHookResolvesOutOfScopeWithAutomaticDisabledBeforeAnyUrlHelper exercises the production hook using a host double. | Reuse its metadata path. Fill absent tool/URL/enabled vectors in that suite; do not create another fake-host scaffold. |
| CORE.lifetime | Reuse baseline; revised-use gaps | TokenLifetimeTest's three methods plus coordinator proactive-refresh/version tests cover opaque/JWT bounds and clocks. | Keep these owners. Add only server-revocation/revised combined-output lifetime semantics not already asserted. |
| CORE.recovery | Reuse provenance; new replay/pause policy | SessionRecoveryTest asserts attributed versions, independent captured rules, bounded decoding and regex. | Keep those assertions. Current tests cover invalidation for future demand, not automatic replay; extend the existing suite with new replay/pause behavior after the amendment. |
| CORE.retry | Revise existing expectation | AuthenticationCoordinatorTest.positivelyTemporaryFailuresHaveExactlyThreeRetriesAndReleaseWorkerDuringBackoff asserts four attempts and permits later demand after cooldown. | Update this test in place with the three-total-attempt/shared-pause contract when production changes. Do not count the old test as satisfying the new limit or add a contradictory parallel retry suite. |
| CORE.resources | Reuse baseline; revised pause gaps | AuthenticationCoordinatorTest covers shared 100/200 callers, reservation limits, per-caller cancellation, queue/backoff/unload and stale results. | Reuse CoordinatorFixtures.ManualRuntime and existing assertions. Add only changed pause/replay ownership and missing resource witnesses. |
| CORE.registry | Mostly reused | JourneyRegistryTest covers collisions, alias retirement/reassignment, generation changes, session secrets and edit/load behavior. | Bind existing lower-layer assertions rather than add them to browser apps. Exclude upstream proxy-authentication checks from lab selection. |
| CORE.storage | Reuse preservation; new-format gaps | UserLibraryStoreTest and JourneyRegistryTest already cover v1 roundtrips, unknown versions, atomic-write failure, secret redaction and external edits. | Keep baseline checks. Extend only the future multi-output format transition/rollback contract; do not rerun all v1 storage tests as a new lab suite. |
| RUN.recovery | New representative operational evidence | Existing coordinator tests use a fake runner; browser cancellation checks do not directly count the OS process tree. | Keep deterministic rules below; add only selected real-runner/shared-recovery cases with actual resource observations. |
| FED.flow | New real-provider cases | No Keycloak/OIDC/SAML client suite is present in the inspected test tree. | Add the real protocol clients and production-runner proof; controlled redirect tests cannot satisfy it. |
| FED.outputs | New real-provider proof | Existing fixed token extraction is not accepting-service proof for IdP/client/API outputs. | Add the selected-output checks, conditional on schema and single-cookie qualification. |
| FED.negative | New provider/client oracle controls | Existing parser/normalization tests do not validate real codes/state/PKCE/audiences. | Add only the provider/client contract controls; label their evidence layer. |
| FED.sso | New proof plus reused fresh-cookie assertion | The existing fresh-context cookie assertion is reusable; explicit IdP-cookie acceptance is absent. | Reuse the former once and add the qualified no-password SSO proof/controls. |
| FED.saml | New provider/client controls | No real SAML relying-party fixture exists in these tests. | Add maintained-client correlation/negative controls; do not build a custom provider. |
| FED.broker | New real chain | The current carrier redirect fixture is not a brokered OIDC-to-SAML flow. | Add the two-provider chain and selected outputs without repeating simple lower-layer navigation checks. |
| TLS.proxy | Reuse route; split mixed method | Pkcs11JourneyIntegrationTest.explicitUpstreamUrlTunnelWorksWithoutLeakingAttemptCredentials and rejectedOrUnavailableUpstreamNeverFallsBackToDirectOrigin include applicable routing evidence. | Reuse the unauthenticated tunnel assertions. Split the mixed method to select only unavailable unauthenticated routing; assert failure/zero origin reach without its PROXY_AUTH classification or challenge/authentication assertions. |
| TLS.mtls | Substantial existing integration proof | Pkcs11JourneyIntegrationTest checks actual same-CN fingerprints, repeated connections, protected identity, local internal credentials and stripping. | Reuse those cases. Add only absent allowed/disallowed-origin or missing-certificate exact witnesses; no second mTLS fixture/test family for the same claims. |
| TLS.trust | Mostly reused | Pkcs11JourneyIntegrationTest checks wrong chain/hostname/origin and actual Chromium rejection of an unlisted local SPKI; ProxyCertificateFactoryTest checks leaves/SANs/SPKI. | Reuse these owners; qualify any missing listed-key positive/ordinary-browser trust witness rather than recreate the matrix. |
| H01 | Retain actual-host gap | NativeTagPipelineTest.ProductionHooks uses an explicitly installed Montoya factory double, not a Burp process. | Do not duplicate the unit assertions. Keep the small actual-tool dispatch and wire-output representatives. |
| H02 | Retain wire non-delivery gap | The existing hook test asserts DROP on a double and unchanged ordinary bytes. | Reuse that policy assertion. Actual zero ingress and actual host forward remain distinct H02 facts. |
| H03 | New host replay/pause gap | No current source test establishes automatic application replay in actual Burp. | Keep two host representatives after the production amendment, not the full lower-layer retry matrix. |
| H04 | Reuse guard/carrier units; retain real-host gap | AuthTrafficGuardTest and the existing real-browser marker test already exercise carrier/ledger behavior. | Retain only actual Burp interception/tunnel ordering and non-recursion; no repeat of every marker input. |
| H05 | Reuse editor/diagnostic units; retain actual UI gap | JourneyRegistryTest has editor/layout tests and DiagnosticsTest has warning/annotation/rate-limit tests. | Reuse them once; extend only changed Save/Test/dirty/pause assertions below. The offscreen layout test explicitly does not establish a real Burp UI result. |
| H06 | Reuse packaged probe; extend only missing facts | BrowserJourneyIntegrationTest.packagedClassloaderUsesExactResourcesWithoutSharedDriverCacheOrJvmMutation already loads an actual JAR and launches Chromium through its isolated probe. | Reuse/parameterize this probe for the selected artifact and add lab-dependency exclusion checks there. Do not add PackagedDeploymentTest as a parallel bootstrap suite. Actual offline Burp load/unload remains manual. |
| CAP.assessment | Retain explicit assessments | The marker test covers a WebSocket opening carrier, not WebSocket frames or actual-host hook delivery; challenge/grant support is not established by unit tests. | Reference applicable prior evidence and assess only the remaining capability question; do not infer unattended support. |
| Shared helpers / diagnostics / assets | Reuse, not new feature suites | CoordinatorFixtures, IntegrationFixtures, BrowserAssetsTest, DiagnosticsTest, AuthTrafficGuardTest, Pkcs11IdentityManagerTest and ProxyCertificateFactoryTest already implement relevant support/assertions. | Do not invent a second manual scheduler, generic proxy fixture, asset bootstrap, PIN-state model or warning test suite. Extract common fixture code only when standalone serving needs it, preserving one owner. |

## Execution binding and deduplication

For each requirement, record an owning class/method and relevant parameter/assertion witness, captured contract revision, `reuse/extend/new/blocked/manual` disposition and any missing assertion. Keep requirement ID separate from the shared execution ID. A binding is valid only for the actual supported inputs/evidence, not merely a similarly named test.

Run a bound existing method/parameter **once** per relevant artifact/backend/configuration within a lab invocation, even when several requirements/profiles reference it. Map its JUnit result back to those requirements. A skipped, missing or failed binding cannot become passing coverage; a partially covered requirement stays incomplete until its missing assertion runs. Existing baseline tests that still have valid assertions remain owners when revised tests are added.

Use scoped method/parameter selection for lab component and browser/native tasks, rather than making every profile depend on an unfiltered whole predecessor suite. This also prevents selecting existing upstream proxy-authentication assertions. Keep unrelated normal project regression commands separate from the lab's selected scope. Default test ownership is preserved; no existing test is deleted merely because it is not selected by this lab.

The amended catalog contains **962 requirements/assessments (922 automated requirements, 24 host-manual, 16 capability assessments)**. This audit deliberately does not subtract whole partially covered groups or claim an exact number of new JUnit invocations. Resolve each binding's inputs/remaining assertions first; `authLabMatrix` reports covered requirements, unique reused executions and new gap executions separately.

## Source inventory

All hashes are SHA-256 of the bytes read. Existing source remains in its worktree. The method counts include all selected annotation declarations, not parameter expansions.

| File under source root | Annotated methods | SHA-256 |
| --- | --- | --- |
| `AuthenticationCoordinatorTest.java` | 24 | `D8169CE340486A85E7F3C92DC3BE12F4005214E3979FFA355FB20AE0B07B1827` |
| `AuthTrafficGuardTest.java` | 5 | `C0072F680B5957F54BD8D9362874E884AAB5C9AF87F89F515B2006982DC5BF78` |
| `BrowserAssetsTest.java` | 15 | `DBE7CAAACE7B1C81C00A738DF365A512A5116B111484F910E704CCD3F2ABA55E` |
| `BrowserJourneyIntegrationTest.java` | 9 | `EA7D07020CE234D9DB63E298D77CC9104C208602BB360A65FBF22F9AF8BCE557` |
| `DiagnosticsTest.java` | 4 | `B586D60CE79D1120225AB9E56A3CB09C955AA6635F8FA45C3ADE0A40A2CCC46A` |
| `JourneyRegistryTest.java` | 40 | `B7A3F3E891D8223ECF3373300B2ED0AB42CDA3F5575C52D7B1043F53E12E885B` |
| `NativeTagPipelineTest.java` | 24 | `F1500793B7661F5D1DCE684FA08CA373345B0FE99142D482143088BA3124460C` |
| `Pkcs11IdentityManagerTest.java` | 5 | `BB6C514A7E45E90966712D433C3214BACBD440E002F31EE8805D76A3E2E08C8F` |
| `Pkcs11JourneyIntegrationTest.java` | 7 | `339B49F8224FDA9EA87369CEA92F24E25272C25CC2B7E0FAE5706B51E8C72612` |
| `ProxyCertificateFactoryTest.java` | 1 | `CBE3144D5A5966EBC1227B6D36FE7A15E30DE36A02FC7D378EB12C676B496820` |
| `SessionRecoveryTest.java` | 8 | `91C42AA63813C42AE72D52C1308BD4CBA779E446B904468E1B6A638468D42E75` |
| `TokenExtractorTest.java` | 10 | `8E589C878273972C6DDFA6EB0614018E0A39C0198CE07110C126410BFDF7668A` |
| `TokenLifetimeTest.java` | 3 | `BACB5860208BB6063018D9EFB7E524E028694812C778144FF8D3958CF6A4D909` |
| `UserLibraryStoreTest.java` | 11 | `185096F541A61A866AC41E5E53C111B3E2C4C960F2AA173467DB65AB69CF442C` |
| `IntegrationFixtures.java` | helper | `0D94655418E9F5BC9F41522FF494738D3E5BDF5004A84B7BDAC9BE41728C8439` |
| `CoordinatorFixtures.java` | helper | `09F722C8CAAF03E953E06DA278757540E4389D585D233035B7852E90F463533A` |

## Qualification limits

* NativeTagPipelineTest's `ProductionHooks` installs a small SDK factory double and invokes the actual handler. It is useful unit/boundary coverage, never proof of actual host dispatch or network non-delivery.
* The browser cancellation test returns typed cancellation, but its captured body does not explicitly assert the owned OS process tree is empty. Preserve that distinction when claiming cleanup evidence.
* The actual-JAR browser probe already checks packaged resource lookup/driver bootstrap. Extend its artifact input and exclusion assertions instead of recreating them; it still does not prove an offline Burp load.
* Keep the existing disposable native-fixture manifest/setup workflow. Java execution can consume a prepared fixture without invoking Python. The optional existing `test/pkcs11_fixture.py` setup utility is not a new production/lab runtime dependency and should not be reimplemented merely to port the applications.
* No new production source was inspected as implemented support for multiple outputs/replay. Those outcomes remain conditional on their reviewed amendment, irrespective of old tests passing.

*Prepared with EGM.*
