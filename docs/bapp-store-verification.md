# BApp Store compliance audit

Re-audited and remediated on 2026-11-10. The [fix and qualification record](bapp-store-fix-plan.md)
tracks the implementation. The supplied [requirements](bapp-store-requirements.md)
remain an unchanged copy of the author's document.

**Submission readiness is not established.** Code fixes address the reproduced
security, allocation, capacity and native-lifecycle problems. Exact-artifact Burp
VM/load qualification, Linux/Intel macOS execution and physical middleware remain
separate evidence requirements. No Store reviewer exception has been obtained.

## Basis

The [current official criteria](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/bapp-store-acceptance-criteria)
were checked during the re-audit. Networking is a preference, current item 12
concerns AI providers, and lifecycle/large-project guidance is more specific than
the supplied checklist. Testing remains a local requirement. No AI feature exists.
This is not a complete dependency-CVE or license/source-obligation review.

Review covered composition/unload, callbacks, parsing/rewriting, authentication
coordination, HTTP/TLS routing, browser launch/recording, extraction, credential
presentation, persistence and packaging. It used production source, pinned
Montoya 2026.4 sources, the prepared Playwright driver, fresh tests and controlled
probes. Engineering priorities below are not a PortSwigger acceptance decision.

## Findings and implemented fixes

| ID | Priority | Finding | Current implementation |
| --- | --- | --- | --- |
| F1 | High | Chromium sandbox was disabled by default. | Shared login/recording launcher explicitly enables sandboxing and reports prerequisite failures. |
| F6 | High | First rendering of a recorded option could fetch an HTML image URL. | Plain-text policy is applied before the first text assignment in options and event renderers. |
| F5 | Medium | Automatic rewriting repeatedly copied whole uploads before retention admission. | Automatic resolution processes headers, body assembly uses host bytes, copy capacity is reserved before materialization and replay capture is lazy. |
| F3 | Medium | A noninterruptible native call and its PIN could outlive manager close. | PKCS#11 configuration, login and signing run in owned helpers; host PINs are wiped before awaiting results, helpers are terminated and cleanup completion is observed. |
| F2 | Medium | Intentional waits had Unlimited defaults and incomplete cancellation ownership. | Finite request admission covers the whole callback, and interrupted identity setup detaches its pending admission. The synchronous API constraint remains. |
| F4 | Medium | Authentication uses an explicit route independently of Burp globals. | Behavior is retained and explained; NTLM routing/no-fallback tests cover journey configuration. Burp listener/upstream qualification remains pending. |

### F1: Browser sandbox

[BrowserSessionLauncher](../bapp/src/main/java/bpsh/browser/BrowserSessionLauncher.java)
previously omitted `setChromiumSandbox(true)`. The prepared driver's
`driver/package/lib/coreBundle.js` adds `--no-sandbox` unless that option is true,
matching the [Playwright API](https://playwright.dev/java/docs/api/class-browsertype#browser-type-launch-option-chromium-sandbox).
No browser exploit was attempted. The shared launcher now sets it explicitly,
including recording, and offers no unsandboxed fallback. Windows execution and
other platform qualification must be reported separately.

### F6: Recorded values interpreted as HTML

[StepsPanel](../bapp/src/main/java/bpsh/burp/ui/StepsPanel.java) previously set
`html.disable` after superclass rendering. The recorder preserves exact dropdown
option values, allowing target-derived HTML to reach Swing first. A controlled
headless probe of the actual editor fetched an owned loopback image once on its
first render and zero times thereafter. This demonstrated network activity,
not JavaScript execution.

The property is now set before any rendering text assignment. The regression
checks first/subsequent renders and a fresh editor, zero network fetches and
preservation of the saved option value. Related event rendering uses the same
safe ordering; the credential-cache renderer already did so.

### F5: Allocation and replay admission

The baseline resolver probe processed an 8,388,677-byte warm-cache request under
Send immediately and allocated 42,400,704 bytes on its calling thread, excluding
fixture input and Burp objects. It constructed an additional full replay template
before the retention decision. That was allocation evidence, not an observed OOM
or peak retained-heap measurement.

[SessionRequestProcessor](../bapp/src/main/java/bpsh/burp/http/SessionRequestProcessor.java)
now materializes only the headers for automatic injection, preserving the body
through host byte arrays. Explicit directive/tag size checks precede full byte
reads. The shared renderer allocates output once. A production-hook regression
preserves an 8 MiB upload and untouched header formatting.

[RequestCapacity](../bapp/src/main/java/bpsh/burp/http/RequestCapacity.java)
reserves a conservative working-copy allowance before preparation. Its 512 MiB
aggregate budget charges four times message size plus 16 MiB for bounded header
expansion; automatic messages above 124 MiB therefore continue unchanged with a
capacity diagnostic. Automatic header expansion is bounded to 4 MiB. Explicit
messages retain their 4 MiB limit. These are documented behavior limits, not
proof of zero-copy Montoya internals or host peak-heap usage.

[SessionRecovery](../bapp/src/main/java/bpsh/burp/http/SessionRecovery.java)
checks enabled detection, 4 MiB individual and 32 MiB aggregate retention before
invoking the copying supplier. Without retention, shared recovery still runs
but the original needs a manual resend. Host memory/load measurement remains open.

### F3: Native isolation and teardown

A baseline fake native load ignored interrupts until released. Close released
its caller and removed the provider, while the worker and its owned nonzero PIN
remained until the call returned. This proved an in-process limitation, not a
hang in a particular vendor.

[Pkcs11ProcessAccess](../bapp/src/main/java/bpsh/transport/tls/Pkcs11ProcessAccess.java)
and [Pkcs11KeyMain](../bapp/src/main/java/bpsh/transport/tls/Pkcs11KeyMain.java)
now put provider setup, login, certificate/key access and signatures in a child.
The host retains public chains and opaque JCA signing references. Authenticated,
bounded binary IPC uses a capability passed through stdin; PINs are absent from
arguments, environment, files and logs. The host temporary PIN is wiped before
waiting for the child. There is no private-key export or object deserialization.

Helpers and owned descendants are force-terminated with bounded exit observation.
Explicit retry terminates its previous helper, invalidates old TLS scopes and
reopens the device deliberately. Unexpected helper loss pauses further use with
specific device-session guidance; it never authorizes an automatic PIN submission.
The stalled-helper regression checks process exit, caller release and host PIN
wiping. Packaged software-token tests exercise real signing, PIN suppression,
retry replacement and mTLS; vendor/other-platform claims remain unqualified.

[ServiceCleanup](../bapp/src/main/java/bpsh/authentication/ServiceCleanup.java)
attempts every cleanup action even after an individual failure. Transport
passwords are wiped in a finally block; worker/timer completion is observed off
the EDT. Native helpers close before transport teardown can wait on a signature.
A Burp-owned replay send may ignore interruption until its response timeout;
unload reports incomplete worker termination rather than claiming it completed.
Graceful browser/context close has a separate two-second deadline. Protocol-close
errors are discarded only after owned-process exit is confirmed; transport, file
cleanup and incomplete process termination errors remain failures. Windows
temporary-tree deletion retries transient filesystem errors for at most one
second, rechecking containment on each retry. Driver cancellation retains owned descendant handles and confirms their exit
before reporting browser-close completion when a protocol disconnect event is
missing. Repeated actual Burp unload still needs qualification.

### F2: Conditional waiting and finite admission

| Path | Behavior |
| --- | --- |
| Automatic Send immediately, missing cache | Starts/joins background login and forwards the original without a login wait. |
| Automatic usable cache | Adds ready credentials; preparation still consumes bounded resources. |
| Automatic Wait for login | Waits within the request deadline. |
| Explicit credential tags | Resolves credentials before sending; failure drops the request. |
| Direct HTTP-auth directive | Waits for captures, identity and the response needed for spoofing. |

[RequestSettings](../bapp/src/main/java/bpsh/request/RequestSettings.java)
defaults to finite numeric limits of 64 globally and 16 per journey. Automatic
handling remains off by default. Callback admission covers preparation through
direct response delivery; memory admission can refuse work earlier. Capacity
refusal forwards an ordinary original with a diagnostic and stops explicit
requests. Interruption during identity setup cancels the waiter and closes any
late delivery lease. Tests verify release and subsequent admission.

Pinned sources and current [global](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/http/handler/RequestToBeSentAction.html)
and [final Proxy](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/proxy/http/ProxyRequestToBeSentAction.html)
action interfaces return synchronously for this operation. Preserving the
original transaction while awaiting credentials/a spoofed response occupies its
callback. Finite admission mitigates accumulation; actual Burp worker-pool and
EDT impact remains unmeasured. The URL/port design's routing probe does not imply
asynchronous suspension. Proactive refresh and shared login already exist.

### F4: Explicit authentication routing

Ordinary requests with injected credentials continue through Burp; recovery uses
`api.http().sendRequest()`. Browser login/recording and direct Basic/NTLM use the
journey's optional proxy; empty means direct. Those authentication paths do not
automatically inherit Burp global upstream-proxy/TLS/session settings.

The user guide and Setup tooltip now make this explicit. Production factory tests
cover NTLMv1/v2 for direct, browser and recording scopes through the configured
proxy, and prove an unavailable proxy sends nothing directly to the origin.
Existing HTTPS CONNECT tests cover tunnel setup and connection reuse. Actual
Burp-listener/upstream routing, recursion and host TLS policy remain qualification
items. The technical rationale concerns per-origin identities, PKCS#11 and NTLM
connection ownership; replacing transports needs equivalent behavior evidence.

## Criteria assessment

| Supplied criterion | Assessment |
| --- | --- |
| 1. Unique function | Plausible differentiation through real-browser journeys and certificate-backed authentication. [ATOR](https://portswigger.net/bappstore/51327b097b354243b307b4ed87ba39eb) and [Auth Analyzer](https://portswigger.net/bappstore/7db49799266c4f85866f54d9eab82c89) overlap session capture/replacement/testing. Limited comparison does not guarantee acceptance. |
| 2. Name | Browser Powered Session Handler and its guide describe its purpose. |
| 3. Security | F1/F6 fixes and native isolation need the stated qualification. Existing origin isolation, authenticated loopback ingress, bounded extraction and verified assets remain positive controls. No blanket security pass. |
| 4. Dependencies | Java/browser/driver resources are bundled for three targets. Linux libraries/vendor middleware remain prerequisites; Intel macOS execution and Store distribution suitability remain open. |
| 5. Responsiveness | Background UI work, finite callback admission and copy budgets are implemented; host-load/EDT measurement remains pending. |
| 6. Unload | Exception-safe cleanup and terminable native ownership are implemented. Repeated Burp unload and host-call cancellation behavior remain pending. |
| 7. Burp networking | Ordinary injection/recovery use Burp; specialized authentication has the documented F4 route. |
| 8. Offline | Embedded verified assets and runtime download suppression support it. Cold-cache browser evidence is separate from a disconnected Burp VM check. |
| 9. Large projects | No whole-history/site-map scan found. Retention, request copies, callbacks, text matching and diagnostics have explicit bounds; host measurements remain pending. |
| 10. GUI parent | Inspected dialogs use the suite frame/parent, including recording. Fresh multi-monitor qualification remains pending. |
| 11. Montoya artifact | Compile-only pinned Maven API; packaging excludes host API classes. |
| 12. Testing | Native/component, lab, browser and software-token checks provide distinct evidence. Exact-artifact host/OS qualification remains separate. |
| Current AI criterion | Not applicable; no AI feature. |

## Delivered verification

Final working-tree verification completed successfully on 2026-11-10:

```powershell
.\gradlew.bat check verifyNativeDocumentation jar pkcs11IntegrationTest browserIntegrationTest '-Ppkcs11Fixture=build/pkcs11-fixtures/bapp-fixes-final-20261110/fixture.json' --offline --console=plain
```

| Suite | Passed | Skipped | Failed/error |
| --- | ---: | ---: | ---: |
| Native unit/component | 1,149 | 1 | 0 |
| Authentication lab unit | 735 | 0 | 0 |
| Federation client unit | 27 | 0 | 0 |
| Packaged Windows browser | 53 | 0 | 0 |
| Packaged Windows SoftHSM | 10 | 0 | 0 |
| Isolated HTTP-auth browser acceptance | 13 | 0 | 0 |
| Isolated HTTP-auth component acceptance | 34 | 0 | 0 |

The skip is POSIX executable/link extraction on Windows. Architecture checks
covered 123 production Java files in 17 packages with no cycles. Native Javadoc
and all 17 synthetic browser-asset producer cases passed. The final browser
suite includes the fresh-home/cache probes and forced protocol-cleanup regression.
An old artifact was not supplied, so update/rollback execution was explicitly
not run.

Binding refresh was reviewed before a separate
`authLab -PlabProfiles=http-auth --offline` invocation. All 47 selected acceptance
results were PASS, with no failures or skips. Evidence is under
`test/authentication-lab/build/authlab/58e6dd0f-279a-450b-a410-ff09c7e690c2/`;
the isolated capture hash is
`f3baa46a7a7dc1d4c301a357894a151027133336c93506a116a9a4aea46e40a7`.
This qualifies the selected profile, not every catalog requirement.

The delivered universal JAR is
`bapp/build/libs/browser-powered-session-handler-dev.jar` (740,737,948 bytes).
Its SHA-256 is
`f2b75e898ccc8e6a40bfa29a66a87fcd6c3558d80b327c38e6ce6952056fab09`.
All **429 freshly compiled production classes match its entries exactly**;
there are no duplicate ZIP entries or bundled host API classes. Packaging
verified all three embedded payload hashes. The production-tree SHA-256 is
`5dd9dc2b6acad898ea17ae44b18362e9fc34173c731fd4d2db3064e493fe878b`.

The complete manifest is
`bapp/build/reports/bapp-store-audit/fixes-evidence.json`; final build output is
`fixes-complete.log` and isolated acceptance output is `fixes-http-acceptance.log`
in that directory. Generated evidence and artifacts remain ignored.

No fresh Burp UI/VM, Linux VM, Intel macOS or physical-vendor middleware
qualification was performed. Windows browser and software-token execution do
not replace those remaining checks. The supplied requirements copy is unchanged.
