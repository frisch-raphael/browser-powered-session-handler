# Authentication findings: fixes and verification

2026-11-06. Production fixes are directly in `main`, starting from `fbb1d72f5722fe1642da05223114751642990878`. At the time of these checks, the separate `test-suite` checkout owned the controlled applications, acceptance overlays and broader evidence. The suite is now integrated into main; this record preserves the original artifact and run identities. The mTLS fixture changes are included in the follow-up main delivery.

The verified universal development candidate is `bapp/build/libs/browser-powered-session-handler-fixes-candidate.jar`, SHA-256 `679a1ba4a2384139bb25e753ffe12cee09eb194871da21e39d5017aa23d821fc` (739,900,322 bytes). These changes do not alter the bundled browser resources or installation contract.

## Corrections

| Finding | Resulting behavior | Owner and verification |
| --- | --- | --- |
| F02: missing cookie unnamed | Feedback identifies the selected cookie, for example `The selected cookie LAB_C1 was not received.`, and its capture field. It contains no cookie value. | `TokenExtractor`; existing extractor and diagnostic owners. |
| F04: combined capture hides the actual failure | An incomplete combined result preserves the strongest observed navigation, step or collector failure and its attribution. A complete valid credential set still succeeds. | `TokenExtractor`; combined extraction and diagnostic regressions, including partial and empty captures. |
| F05: unavailable mTLS upstream is terminal authentication failure | Positively identified temporary socket failures become retryable TRANSPORT failures. Unknown errors remain terminal; configured routing never falls back to a direct connection. | `JourneyTlsProxy`; typed failure/redaction checks and the existing unauthenticated-upstream native owner. |
| F06: popup frame metadata aborts capture | Unavailable frame metadata is handled by the frame guard already present in integrated main. Unexpected final event-pump failures retain a safe lifecycle cause instead of becoming missing output. | `BrowserFlowRunner`; frame boundary and actual browser-surface owners. |
| F07: HTTP success implies verified authentication | Events report the actual HTTP status, including non-200 successful statuses. The journey summary says protected access remains unverified. | `AuthenticationCoordinator`, `SessionRecovery`, `UiController`; event/UI/recovery regressions and actual Burp event observation. |
| F08: original/replay references disappear | The original response receives a durable original-request reference before its callback returns. Request and response callbacks identify the replay using that reference. The replay marker is explicitly added when `User-Agent` is absent. | `HttpSessionHandler`; actual hook regressions with and without an existing agent, successful/rejected replacements, and native Burp Logger exports. |

An original's reference is the durable common key. For example, original request 9 and its replay both identify original request 9. A later best-effort mutation of the original annotation is not required for correlation.

## Why the extra F08 fix was necessary

The first candidate fixed the original note but still lost replay identity for requests without `User-Agent`. A real Burp comparison established that `withUpdatedHeader` updates an existing header without adding an absent one. The replay's internal marker was therefore missing, so it re-entered the ordinary request path. An existing-agent control retained both references. The correction uses `withAddedHeader` for the absent-header case and preserves the original request's header shape on delivery.

This is distinct from browser-login ownership: login requests are exempt from ordinary authentication handling; an application replay remains an application request whose rejection must be observed. A replay marker identifies the already prepared replay and keeps its one-replay provenance.

## Regression checks and scope

The focused main regression run passes 233 tests with zero failures/errors/skips; `verifyNativeDocumentation` also passes. It covers extractor, diagnostics, event log, recovery, native hooks, coordinator, configuration and browser-failure presentation. Configured upstream authentication and mixed methods containing those assertions are excluded from this final run. Earlier broad selection accidentally included two mixed configuration/UI methods; those were identified, excluded and the affected selection rerun. No upstream authentication endpoint or challenge was exercised.

The hook regression now also enables automatic handling for every URL, including the login request's URL, and returns HTTP 401 to an owned login request. It requires zero authentication attempts, no queued worker and no waiting caller. Existing owners cover tagged login traffic being stopped, stale markers, shared concurrent acquisition, three total temporary-failure attempts, terminal pause, and a rejected replacement producing no second replay.

Acceptance uses the existing lab fixtures and controlled protected-resource proofs. No provider protocol-validation matrix or duplicate installation check was introduced. Final lab component invocation `7a0f06e5-686b-4810-a85f-95b63fb33fa2` passes 569 checks against source capture `cf523e3047ba13907ea7f2ac5a5bd4a166e9dd3852dfd1b4cc322d4baa33192f`. Invocation `8885b56b-778b-4e04-95a1-6f92813720d8` passes 50 browser and nine native transport checks against `0f9e2bbe2c68584bcb6fe4137e0ce3cc61540a5da67952d8ab5d425754349aa6`. Only the strengthened test source differs between those captures; production input hashes are identical. All runs have zero failures/skips. The 728 lab module checks also pass. These overlapping layers must not be summed as distinct scenarios.

## Actual Burp verification

Fresh Community 2026.10.1, PID 26476, loads the candidate successfully. Refresh unloads and reloads the existing extension entry. The lab case is `BROW.basic.json`, generation 7, run `3e3a5dcf-6d87-4cd9-9f63-347c83217017`.

With no `User-Agent` in the original input, a tagged request proves account `user2`, issuance `s10`, and roles B/C1/C2. Revoking that issuance produces original request 9 (401), one fresh login, and replay request 10 (200), proving `user2`, issuance `s11`, and all three roles. Both persisted Logger comments identify original request 9.

Revoking `s11` and rejecting its replacement produces original 11 (401), exactly one fresh login and replay 12 (401). Both comments identify original 11. The actual event explains persistent pause after one attempt; the earlier successful event neutrally reports HTTP 200. Ingress remains 47, completed logins 7 and protected acceptances 6 during the subsequent idle observation: no additional recovery/browser cycle appears.

The sanitized native Logger export, safe helper sidecars, callback-only numeric metadata and before/after lab counters are retained under `test-suite/test/authentication-lab/build/fixes`. Raw Request/Response export columns were removed immediately. The passive observer supplies no authentication, retry, replay or note-modification implementation; acceptance of persisted comments comes from the native Logger export.

These are focused fix checks. They do not claim every catalog requirement, provider, physical token or platform was requalified. Existing offline installation results retain their separate artifact identity.

## Delivered artifact and cleanup

The verified candidate is published to `bapp/build/libs/browser-powered-session-handler-dev.jar` with the SHA above. The disposable Burp process is closed, the owned Java lab run records CLOSED, and its listeners are absent. Existing earlier Burp windows remain open. All 26 preserved legacy test files remain unchanged in the lab worktree. These authentication fixes and the mTLS fixture changes are included in the follow-up main delivery after test-suite integration.
