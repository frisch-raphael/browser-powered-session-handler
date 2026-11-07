# P2 findings from the actual production runner

Current main fix verification: see [findings fix verification](findings-fix-verification.md). The reproductions and counts below describe historical artifacts; F02/F04/F05/F06/F07/F08 now have fixes and focused verification recorded separately.

Latest reviewed checkpoint (2026-11-06): A8 `4057a832e087b96e25a819d9b8b027e8ece19c89e2f69aaadf603c097c7e52df`, invocation `49e3ecae-dcf3-4c2f-95e2-8866eacd42c9`, passes **562/565 component checks** and **50/51 browser checks**, zero skips and complete cleanup. All 42 newly reused field-specific error-feedback inputs pass. F02 and both F04 inputs still fail; F06 remains observed in browser/proxy routing. A8 transport also reproduces F05/F06. No additional product defect was found in this refresh. Later live edits remain outside this immutable capture. Following checkpoints preserve earlier results.

2026-11-06 A7 checkpoint: captured boundary `085d10e2cc00a13ff422a0b9866f2b571329841c662c5285a562b7bf1d357f18`, full component invocation `e602f728-4c66-4c58-8245-72a8accb3e8d` passes **497/500**, zero skips. Only F02 and both F04 inputs fail. All complete-output, encoding and six then-bound tag-selection requirements pass. Two subsequent HTTP account/issuance inputs pass in `7b9912db-432e-4e69-b2db-424ae296f17d`; no additional product bug was found. The full browser/transport checkpoints still reproduce F06/F05, respectively. Later live Java-playwright edits remain outside this immutable capture.

2026-11-06 certificate/diagnostic refresh: captured boundary `1d3951a4f0556c5371ba44fb84d28bbc32e8ffe52e123676e2ecef86863c083f`, component invocation `5ea416d0-614b-4a16-93dc-25442f7a2dfe`, passes **485/488**, zero skipped. Only F02 and both F04 inputs fail. Eleven newly supplied focused test owners add fifteen invocations; all pass. The prior A5 invocation `55b8070d-3f2d-4ed0-aea5-430008b7534f` remains attributed to its own boundary and passed 470/473. Transport findings F05/F06 are recorded in [P3 findings](p3-findings.md). Later edits in the active Java-playwright worktree are outside the retained snapshot.

## F04: Combined outputs discard the observed failing step — historical reproduction; fixed in main

Severity: Medium. When a journey selects both a response token and a cookie, a real failed action can be replaced by `A configured token or cookie was not received.` The phase becomes EXTRACTION, the STEP_TIMEOUT cause is lost, and the step UUID/number/type becomes null. The user loses the actionable step-specific error. This is distinct from F02's missing cookie name.

The first real-provider browser run exposed this while the lab page had a missing JavaScript import. A direct diagnostic browser identified the fixture defect: the official adapter requested `/vendor/deprecations.js`, which the lab had not packaged. That fixture defect is corrected separately. The product's error selection is reproduced without a browser in the existing Diagnostics owner: create a real combined `TokenExtractor`, optionally supply the valid response token, observe the actual runner mapper's attributed WAIT_SELECTOR timeout, and complete extraction. Both no-output and bearer-only inputs return generic EXTRACTION and null step instead of the observed failure.

```powershell
.\bapp\gradlew.bat -p bapp authLabComponentTest "-PlabTests=DiagnosticsTest.combinedOutputsRetainObservedStepFailureBeforeReportingMissingCredentials" --offline
```

`TokenExtractor.result()` asks incomplete child collectors for their results before considering the combined collector's observed failure. The proposed production correction must preserve the relevant observed failure and its step attribution while retaining existing failure priority and later-valid-output behavior. The lab leaves the failing expectations intact and does not edit production code. No new catalog binding is inferred from these diagnostic checks.

Latest scoped refresh: boundary `a2eb67ad21c724a1063e91123de9f0a69922593d24e96a0782751c244add444c`, component invocation `13027ceb-26cd-493f-b379-6d556c17d993` (**470/471 pass**) and browser invocation `272eb29c-5003-45fa-9556-155970f005a2` (**49/49 pass**), zero skipped. F02 is still the only failure. All twelve native step observations pass, now including hidden/attached/detached element waits and exact URL matching. The refreshed 680 independent lab checks also pass. Standardized component/browser results retain 197 PASS plus one FAIL and four PASS respectively, with complete cleanup. Further live edits are outside this capture.

Checkpoint: 2026-11-05, invocation `aae080da-b7a7-4de5-93f9-90f31b170840`, captured `java-playwright` boundary `8b330b985d05a3812d52f0ac189fd382134f8e06f45087affd24bf28e430b3d5`. The run passed 680 lab checks, 465/466 component checks and 49/49 browser checks, with zero skips. Standardized results retain 523 fixture PASS, 197 component PASS, one component FAIL and four browser PASS; cleanup is COMPLETE. Later live app edits are outside this checkpoint. No production source is changed by this lab.

## F02: Missing-cookie feedback omits the selected cookie name — historical reproduction; fixed in main

Severity: Low. The actual production cookie selector for `LAB_C1` receives an empty cookie result. Its failure passes through Test login, the coordinator, event row/details, current editor state and tagged/ordinary request feedback. The cause correctly remains extraction and does not claim a connection failure. However, the message omits `LAB_C1`, leaving the user unable to identify the missing output when several are configured.

```powershell
.\bapp\gradlew.bat -p bapp authLabComponentTest "-PlabTests=DiagnosticsTest.*" --offline
```

This reproduction requires the audited source to match; refresh the audit after live changes. `missingCookieNamesTheSelectedOutputWithoutClaimingAConnectionFailure` remains failing. The proposed product correction is to retain the extraction cause and include the validated selected output name, while excluding its value, credentials and URL. The lab deliberately preserves the failing assertion.

## F01: Rejected login was misreported as missing output — resolved in this snapshot

Originally observed at boundary `25a11725062b25f2c88231e490de0850414eb407a1517cc4afb62e8107ca9fe0`. A real main-frame login POST returned HTTP 401, but the JSON journey selected a later `/outputs` response and reported EXTRACTION instead of the observed rejection. The current production source observes relevant main-frame authentication status independently of the selected extraction response.

The retained native browser owner now passes for invalid credentials. Unrelated subresource failures remain separately checked. These observations verify the current product correction; they do not reclassify the earlier failing runs.

## F03: Extraction success implied protected access — resolved in this snapshot

Originally observed at boundary `ab7ca893874c7d1b0611b0f951d41475e8f4e21718db64be04a35865ec65ff18`. The event log said login succeeded when only credentials had been captured. Current production displays neutral `Credentials captured.` feedback and emits a separate accepted-application-request event after actual successful use. Existing event-row/detail checks and recovery requests verify both stages. Extraction alone does not prove the protected service accepted a token.

## Step-specific error checks

The existing diagnostic factory checks all seven action types, ambiguous element matches, missing secure input, cancellation and unknown action failure. It verifies the actual step UUID, visible number/action label, safe cause, journey state, request feedback, event row and details. The step link opens the correct saved step and becomes disabled after the saved generation changes. Selector text, URLs and input values must not leak.

The existing native browser owner initially added eight actual runner observations: action timeouts, ambiguous click and secure-input preflight failure. The latest refresh adds four explicit wait-condition failures, for twelve observations. One real action failure also passes through the complete diagnostic presentation path. A separate server-rejection check requires no misleading step attribution. These extend existing owners rather than create a second diagnostic matrix; the remaining unbound diagnostic requirements remain unproven.

## Remaining acceptance limits

- Three total attempts, persistent pause and one replay now exist in production and are exercised by 80 component recovery inputs. Actual browser recovery has its own retained owner. This is not actual Burp host acceptance.
- Four fresh-state bindings now use real context identities and closure observations. The native cancellation-before-callback case still lacks an observed SDK context-close event, so its stronger lifecycle binding stays unbound.
- Production autosaves drafts before Test login. The lab's older saved-revision/dirty-editor assumption needs reconciliation before H05 acceptance.
- Provider/SAML, named-origin browser trust, physical PKCS11 and actual Burp observations remain outstanding.

## Resolved harness issues

Chromium's Windows temporary-path limit required a shorter owned test directory. Packaging checks retain OpenTest4j because it is an existing Playwright runtime dependency. Report validation runs after XML generation so failures retain detailed results.

Each production invocation now retains immutable lab runtime JAR copies. Previously a parallel lab rebuild could replace a shared JAR while its target JVM was using it, causing fixture HTTP 500 responses. Configuration fingerprints also use the same case-sensitive filename ordering in Java and Python on Windows. These were harness failures, not product authentication defects.

An isolated reset stress reproduction exposed intermittent Windows `AccessDeniedException` during atomic status-file replacement. Publication now retries only that exception within a bounded interval, retains atomic replacement/private permissions and propagates persistent failure or interruption. The 680 lab checks pass after this correction and binding-fingerprint refresh. This later harness check does not replace the retained production checkpoint above.
