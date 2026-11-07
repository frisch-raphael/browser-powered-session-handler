# P3 findings and capability limits

Current main fix verification: see [findings fix verification](findings-fix-verification.md). The reproductions and counts below describe historical artifacts; F02/F04/F05/F06/F07/F08 now have fixes and focused verification recorded separately.

Latest A8 checkpoint (2026-11-06), source `4057a832e087b96e25a819d9b8b027e8ece19c89e2f69aaadf603c097c7e52df`: transport invocation `3c62501c-6138-45b8-b622-abf8f71d2759` records **16 PASS / two existing F05/F06 FAIL / one EXCLUDED**, complete cleanup. Federation initially did not start because Docker returned an internal server error. After normal Docker Restart, invocation `1ad0532a-722a-4f30-ab8d-d1dc75fb1fca` passes all seven owners and seventeen requirements, fourteen provider exclusions and complete cleanup. The startup failure is infrastructure evidence, not another authentication bug. No provider-validation matrix was restored; the full custom-fixture credential matrix was retained separately to protect against misleading extension results.

Product acceptance concerns the extension's journeys, captured credentials, credential use, feedback and cleanup. Provider/library protocol validation is excluded. Existing product defects remain in [P2 findings](p2-findings.md).

## F05: An unavailable unauthenticated upstream is classified as terminal authentication failure — historical reproduction; fixed in main

Severity: Medium. Boundary `57d835d77e3c2e7ac29198ad9daa8526851b33e31c911be882a0272a7a099112`. Native transport invocation `8ad85cc5-2e21-4c65-978e-2c614c836d0d` passes six of seven selected owners, with zero skips. The existing route owner completes its valid unauthenticated tunnel comparison, then closes a separate unauthenticated proxy listener before running the real mTLS browser journey. No proxy username/password or authentication challenge is configured or tested.

The origin receives zero requests: direct fallback is correctly prevented. The extension returns phase PROXY with cause `PROXY_AUTH` instead of the expected retryable TRANSPORT category. `JourneyTlsProxy.connectionFailed()` unconditionally assigns that cause to a failed upstream connection. `AuthenticationFailure.retryable()` accepts only TRANSPORT and TEMPORARY_SERVICE, so this network failure is terminal and cannot use the approved automatic temporary-failure retries. The test leaves its expectation failing; production source is unchanged.

All seven owners' observed process records show zero surviving browser/driver processes, including both attempts in the failing route owner. The predecessor's mixed rejection/unavailability method is excluded and was removed from the lab overlay. This reproducer checks connection availability, failure classification and no fallback; it does not test upstream proxy authentication.

The existing owners now expose ten separate native inputs. Invocation `1278193d-cd8a-493f-b652-3f2521664aea` passes nine and reproduces F05, with zero skips and complete observed process cleanup. Nineteen transport catalog requirements now have explicit shared bindings across these ten native inputs and three ordinary-browser inputs. The aggregate remains failed: its ordinary HTTP proxy owner also exposes F06 below. The earlier picker failure in invocation `97d6e35f-a931-4dc9-a64f-d05066a76dd9` was a lab error (nested Swing dispatch), corrected and passed in the later run.

## F06: A popup response can abort authentication and be reported as a missing credential — historical reproduction; fixed in main

Severity: Medium. Same captured production boundary as F05. The retained browser traffic owner uses the real production runner, a local unauthenticated HTTP proxy and owned page/frame/popup/worker/service-worker/WebSocket routes. Its original fixed-delay fixture intermittently passed or returned a missing-output EXTRACTION failure. Sequential, explicit acknowledgments between the surfaces expose the same failure before all required requests arrive; neither a larger timeout nor retries are used to make it pass.

Diagnostic invocation `7aff7955-ad44-4aaa-985e-71d5de087eef` records the caught exception using a temporary JDK flight recording. The only distinct Playwright exception is `Frame for this navigation request is not available`, thrown at `BrowserFlowRunner.observeStatus:320`, reached from its response listener while `execute:244` pumps browser events. `observeStatus` calls `response.request().frame().parentFrame()` before its protected URL parsing block. The token-wait loop catches that Playwright exception and breaks without retaining the cause. `extractor.result()` then reports a missing token after about three seconds, despite a five-second configured token wait. The owned proxy saw `/popup`, but its follow-up request and later surfaces were not reached.

This is a navigation-response race in the extension, with misleading user feedback; no IdP or upstream proxy authentication is involved. Frame availability must be handled at the actual request boundary without aborting the event pump. Unexpected browser errors must retain an appropriate safe diagnostic instead of becoming an invented missing-output explanation. The fixture now uses explicit completion acknowledgments, retains its failing assertions and observes process closure. Temporary flight-recording code was removed; the private diagnostic artifact remains with that invocation. No production source was modified.

Complete transport invocation `744a9118-a93e-42b1-abb1-bfd316177b9c` retains seventeen requirements PASS and two FAIL (F05/F06), with thirteen actual cases, zero skips, complete cleanup and zero surviving observed browser/driver processes. Its normalized aggregate is `test/authentication-lab/build/authlab/744a9118-a93e-42b1-abb1-bfd316177b9c/report-transport.jsonl`. The failed profile is not acceptance.

The refreshed certificate/diagnostic capture `1d3951a4f0556c5371ba44fb84d28bbc32e8ffe52e123676e2ecef86863c083f` reproduces the same two transport findings in invocation `aee4cf00-43b1-4571-ae45-cb3392d8fec2`: seventeen requirements PASS, two FAIL, zero skips and complete cleanup. Its HTTPS-login-origin default is handled by the revised valid-config unlisted-redirect input, which passes. No fix for F05/F06 is inferred from the new device diagnostics.

## L01: Two selected cookies with the same wire name are not supported

Boundary: `57d835d77e3c2e7ac29198ad9daa8526851b33e31c911be882a0272a7a099112`.

The real broker fixture exposes `KEYCLOAK_IDENTITY` on both `idp.federation.test` and `idp.upstream-sso.test`. A native journey selecting both cookies under distinct output labels fails the production codec with `extraction.tokens: use distinct cookie names for automatic injection.` The domain/path selectors do not change that restriction. Invocation `dcda0f3f-3a13-4d88-b35a-bc34bec27faf` retains this result. Both services and client/API children reached readiness and closed normally; the browser journey did not run because its configuration was rejected.

This is a capability limit, not yet a contract-approved product defect. The lab does not bypass native validation, rename provider cookies or combine credentials from separate journeys. The broker journey instead selects the upstream SSO cookie, client cookie and access token together. Ordinary OIDC already verifies the downstream selected cookie. Simultaneous same-name cookie outputs remain unsupported and are not claimed by the broker result.

## Environment failures

Docker Desktop repeatedly returned engine HTTP 500 before fixture allocation after idle periods. Those initialization failures are retained separately and are not authentication findings. Normal restart restored it. Resource Saver was temporarily disabled for development and then restored to its original enabled value and 300-second idle timeout. The private record is `test/federation-client/build/p3/preparation/docker-resource-saver.json`; its restoration requirement is cleared. The same idle failure recurred with the original setting; no Docker update, purge or global WSL shutdown was performed in this stage.

## Required final audit

The author requires a whole-suite relevance/redundancy audit after implementation. It must distinguish actual extension regressions, necessary harness sanity checks, duplicated lower-layer assertions and third-party behavior. The code review and automated results are recorded in the [relevance audit](relevance-audit.md), including restoration of the full custom-verifier matrix after user review. Host/manual work and the remaining product failures still prevent full-suite qualification.
