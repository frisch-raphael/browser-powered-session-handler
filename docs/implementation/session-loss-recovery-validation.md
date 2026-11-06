# Production session-loss recovery validation

Date: 2026-11-05. This is focused production evidence; the sibling `test-suite` worktree still owns the full authentication lab and acceptance/stress matrix.

## Contract and predecessor audit

The implementation follows the recovery requirements in the sibling `test-suite/docs/designs/authentication-test-lab.md`. Its `docs/brainstorms/authentication-test-lab/p2-predecessor-audit.md` was read and rechecked against the current production sources, rather than treating its captured predecessor as current code.

| Previous observation | Recheck and disposition |
| --- | --- |
| Recovery only invalidates; no replay | Replaced in the production response path by captured-version shared reauthentication and single-use replay plans, delivered through Montoya. Existing invalidation/decoding tests remain. |
| Four total attempts and cooldown restarts | Three total sequential attempts, with 5/15-second temporary-failure backoff. Exhausted recovery remains paused across demand, timers and saved generations until successful explicit Test. |
| Rejected replacements can restart recovery | Replacement rejection pauses the exact owner. Includes replacements reused from an independently completed refresh; late older results cannot pause a newer publication/episode. |
| No independently observable browser/context closure seam | Metadata lifecycle events follow actual SDK open and successful close completion. The real Chromium test observes fresh resources and close-before-next-open order. OS-process termination is not independently established. |
| UI calls extraction Authenticated | Capture is reported as unverified. A separately observed accepted application response records accepted use once per publication. Pause history preserves cause, stage, attempt count and request policies. |
| Single-output baseline | Stale: named JSON/regex/cookie extraction and per-output injection already exist. No second output schema was added. |
| Manual Save/dirty-editor assumptions | Stale: current autosave and save-before-Test remain. Saving does not authenticate, clear pause or resend old requests. |
| Generic missing selected output name | Still a separate extraction diagnostic gap. This change does not claim to resolve the full lab diagnostic matrix. |

The production design amendment is in [bapp-owned-authentication.md](../designs/bapp-owned-authentication.md#production-session-loss-recovery-amendment-2026-11-05).

## Automated checks

The existing coordinator, response-recovery, native HTTP-hook, traffic-guard, event-history and Swing tests were extended/reused. No separate authentication lab, fixture matrix or recovery adapter was introduced. Existing `IntegrationFixtures` provides the controlled Java HTTP origin for the real runner check.

Final validation uses a disposable Gradle init script, build output and project cache under `%TEMP%/bpsh-recovery-validation-20261105`. Separate project-cache history is required as concurrent Gradle builds can otherwise remove each other's previous outputs. Production sources and the existing Gradle tasks are unchanged by that redirect:

```powershell
.\bapp\gradlew.bat -p bapp --project-cache-dir C:/Users/Rapha/AppData/Local/Temp/bpsh-recovery-validation-20261105/gradle-cache -I C:/Users/Rapha/AppData/Local/Temp/bpsh-recovery-validation-20261105/validation.gradle test verifyNativeDocumentation browserIntegrationTest --tests BrowserJourneyIntegrationTest.sessionLossRecoveryUsesThreeSequentialFreshBrowsersAndReplaysEightActualRequestsOnce --tests BrowserJourneyIntegrationTest.relevantStatusesAndMalformedResponsesHaveDistinctDispositions --tests BrowserJourneyIntegrationTest.unconfiguredSubresource503DoesNotBecomeAnAuthenticationRetry --tests BrowserJourneyIntegrationTest.elapsedAttemptPreservesRelevantServiceAndAuthenticationErrors --offline --console=plain
```

The recovery browser case proves an initial protected identity, revokes it, sends eight original requests, observes three recovery attempts (two HTTP 503 failures then success), sends eight one-use production replay plans, verifies protected identity again, and independently counts 17 protected ingresses and nine accepted actions. Lifecycle IDs prove four browser/context pairs including the initial acquisition and no overlap/leaked SDK resource at completion. The three companion cases preserve known service/authentication failure classification and ignore irrelevant subresource 503s.

Final isolated run passed: **586 unit/component tests**, **4 real-browser tests**, private-member native Javadoc doclint and platform JAR structure/archive-hash verification. Zero failures, errors or skips. All production/test source fingerprints remained unchanged throughout this final run and refresh.

Loaded artifact: `bapp/build/libs/browser-powered-session-handler-dev-windows-x64.jar`. SHA-256: `86651abf504a9fb6c5a9b7010551b92bbcc9f354b2ac5317d401a3911b6e4662`. Source-manifest SHA-256: `bf50bcdda2aba73931f9cf57b250f7c42bc1dd33584d117ce3c03f2047f0d9f9`. The full manifest and result counts are retained in ignored `bapp/build/recovery-validation-source-manifest.json`; detailed reports are in `%TEMP%/bpsh-recovery-validation-20261105/output/reports/tests/`.

Earlier broad runs encountered concurrent editor-test edits and shared Gradle output/history collisions. Those runs are not the final acceptance result; the separate output and project-cache run above passed against the frozen source manifest.

## Live Burp evidence

Burp Professional 2026.10.1, existing extension entry refreshed with Loaded off/on. Used the existing loopback UX fixture on port 28438 and one disposable project journey/rule. All credentials were synthetic. Evidence is independent of component host doubles.

* Initial ordinary Proxy request to `/protected` returned 200 using injected credentials.
* `/reject?run=recovery-live-1` returned its original 401. Logger showed separate original Proxy and replay Extensions rows, both 401, with BPSH comments. Fixture `/reject` ingress increased by exactly two. Login/token counts increased once for initial acquisition and once for shared recovery.
* Replacement rejection produced a persistent journey Error event: rejected replacement credentials, one recovery attempt, Test login guidance, ordinary unchanged forwarding and unresolved-tag stop effects.
* Three subsequent ordinary requests each returned 401 without another login. One tagged request produced no additional protected-origin ingress. Burp's client-side response to the supported DROP action is not a target acceptance result; origin counters establish suppression.
* Renaming/autosaving the journey retained the pause. Another ordinary request reached the fixture unchanged; login/token counters remained unchanged.
* Clicking Test login started exactly one new login. Before sending another request, `/reject` remained at two ingresses and protected ingress remained at five, proving Test did not resend old requests. The next protected request returned 200.

The numeric counter snapshots are retained locally in ignored `bapp/build/recovery-live-report.json`. Original and replay responses remain separate; a replay success does not replace the response delivered to the original caller. Runtime pause survives saves/configuration generations, not extension unload/restart. This check does not establish the full five-tool host matrix, Proxy interception-on ordering, every replay cancellation race, or independent OS process termination.

## Final refresh and cleanup

The final fingerprinted JAR was loaded with the existing entry's Loaded checkbox off/on. A second live run independently reconfirmed protected access (200), exactly one recovery replay (two `/reject` ingresses), replacement-rejection pause, ordinary unchanged forwarding without another login, and zero additional protected-origin ingress for the paused tagged request. The actual journey event log visibly distinguished Credentials captured from Application request accepted with these credentials, then showed the paused cause, attempt count and policy guidance. These snapshots are retained in ignored `bapp/build/recovery-final-live-report.json`.

Removed the disposable Recovery live check saved rule and journey through the UI. Verified only the original New journey and qa-combined journeys and their original two rules remain. The existing loopback fixture was reused and left running; this task did not create or stop it. The extension remains loaded with the final build. The sibling lab and its predecessor snapshot were not modified.
