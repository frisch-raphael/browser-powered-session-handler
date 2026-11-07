# Required final test relevance audit

Status: code review recorded in the [relevance audit](relevance-audit.md); current integrated-main qualification is recorded in [fix verification](findings-fix-verification.md). Host/manual gaps remain. This file preserves the original checklist and evidence inventory; its named review items are not a new request to restore removed executions. Refresh the selected production-source comparison before claims about later live code. The author requested this audit after provider/library checks were added without a sufficient extension-testing justification.

For every retained product execution, record the extension failure it detects, the actual production entry point it exercises, the observable assertion, and the existing lower-layer owner considered for reuse. A catalog alias is not a separate execution. Remove an execution if an existing lower owner establishes the same behavior with the same relevant inputs. Preserve necessary checks of custom test infrastructure separately and exclude them from product coverage totals.

## Decisions already made

| Tests or controls | Decision and reason |
| --- | --- |
| Generated signed SAML invalid/time/recipient/replay controls | Removed before execution. They would test Spring/OpenSAML validation rather than extension behavior. |
| Standalone IdP state/PKCE/client/callback/code-reuse/token-kind/audience scenarios | Removed from product execution. Nine former negative catalog entries and five former SAML entries remain explicitly excluded as historical records. |
| Real SAML browser journey and protected client-cookie proof | Retain for final review: exercises the extension through a real form POST/redirect journey and verifies the obtained credential. No SAML-validator mutation matrix. |
| Real OAuth and brokered browser journeys | Retain for final review: exercises extension navigation, selected outputs and expected-account access through maintained clients. |
| One immediate simulated backend exchange rejection | Retain for final review: checks that the extension returns no credential and reports the missing cookie without inventing a connection error or unseen server-side cause. |
| Federation catalog aliases | Share seven actual native owners for seventeen requirements. Do not create a login execution per catalog entry. |
| Previous standalone provider bootstrap assertions | Removed redundant issuer/asset/PKCE/SAML-request/key-rotation assertions. Reused that existing owner for our previously uncovered parent-control serving/reset lifecycle; its results qualify the harness only. Verification is tracked with the serving implementation. |
| Federation resource signed-token mutation matrix | Reduced fourteen decoder executions to one custom-oracle check: a valid API access token is accepted; an otherwise matching wrong-audience token and ID token are rejected. Removed signature, algorithm, timestamp, issuer, malformed-token and missing-claim permutations. The replacement starts with already validated claims and does not generate signed messages or test Nimbus/Spring cryptography. The revised default federation suite passes 27 checks, zero failures/skips, in invocation `28843dd9-680c-4ba0-bd5a-983a4a8e09ed`. |

## Concrete remaining audit items

| Area | Required review |
| --- | --- |
| `FederationConfigurationTest.resourceOracleDistinguishesItsAccessTokenFromOtherAudienceAndIdToken` | Confirm the reduced check qualifies our custom resource audience/type configuration only. It is harness assurance, never extension acceptance. Removed library mutation cases must not be restored as product coverage. |
| `FederationContractTest.servingControlsCreateOneOwnedCaseAndRejectStaleWorkAfterReset` | Confirm that the reduced owner only qualifies our parent-control forwarding, child startup, reset and stale-generation behavior. Do not restore removed provider/bootstrap assertions or count it as extension acceptance. |
| `FixtureContractTest` matrix | Review the 523 fixture requirements as oracle qualification, separately from extension acceptance. Explain whether the full matrix adds confidence over representative custom matching/issuance checks; do not present it as 523 extension scenarios. |
| Component overlays | Repeat comparison with the current Java-playwright worktree. Retain predecessor owners; add only missing parameter inputs or stronger assertions. Check for duplicate tag, injection, recovery, diagnostics and storage executions. |
| Browser versus component tests | Require a browser only for behavior the lower owner cannot establish, such as actual redirects, cookie applicability, response observation, native failures and browser/process closure. Do not repeat encoding or tag parser matrices in a browser. |
| `Pkcs11JourneyIntegrationTest.unlistedLocalProxySpkiIsRejectedByActualChromium` | It exercises the actual extension-owned TLS proxy/certificate with a real browser, but constructs its own launch arguments. Identify the concrete proxy/certificate regression it catches; do not claim it verifies the production runner's argument selection or retain it merely to retest Chromium's documented flag behavior. |
| Burp integration | Keep only behaviors requiring the real host: hook wiring, tools, project/scope integration and user-visible host state. Reuse lower-layer correctness evidence. |
| Harness evidence/lifecycle checks | Verify that each protects against a plausible false pass, leak or stale/foreign result. Remove parser/getter mirrors and repeated combinations that add no new failure detection. |
| Provider seed configuration assertions in `LabLifecycleTest` | Separate necessary isolation/topology/private-input checks from assertions that merely repeat fixed seed fields or provider protocol policies. Do not count seed preparation as IdP correctness or extension authentication coverage. |
| Live native exports | Reuse the operational definition builder and actual serializer/parser. The seventeen exported files are prepared examples, not seventeen new authentication executions. Lifecycle/current-generation checks belong to existing harness owners. |

An observed example is invocation `fd0858bc-839a-4175-8e9c-80e0b9d325db`: all seven native owners passed, but cancellation lacked graceful SDK close notifications after the watchdog had killed the actual owned process tree. The report rejected that one case. The revised contract distinguishes forced process closure from graceful notification delivery and preserves the actual zero counts. A remaining live owned process still rejects the result. This is a harness-evidence correction, not a new extension defect or permission to infer unobserved cleanup.

The final report must list retained, reused, reduced and removed execution owners, distinguish product results from harness qualification, and identify unresolved coverage gaps. The audit is a completion gate; passing test totals alone do not satisfy it.
