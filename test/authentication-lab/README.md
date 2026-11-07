# Authentication lab

The Java catalog, controlled login applications, protected credential checks and private lifecycle controls are implemented. Scoped component/browser tests exercise captured production code from integrated `main`; the applications and acceptance overlays are maintained here in main. Real federation journeys, software-token transport and foreground serving are implemented. All active automated requirements have bindings. The [main fix verification](../../docs/designs/authentication-test-lab/findings-fix-verification.md) distinguishes current passing fix checks from historical failures. The separate host ledger records artifact-specific Burp observations and remaining manual gaps.

Run these commands from the repository root, using Java 21:

```powershell
.\bapp\gradlew.bat -p bapp :auth-lab:test :federation-client:classes
.\bapp\gradlew.bat -p bapp authLabMatrix -PlabProfiles=baseline
.\bapp\gradlew.bat -p bapp authLabMatrix -PlabProfiles=browser,diagnostics
.\bapp\gradlew.bat -p bapp authLabMatrix -PlabProfiles=all
.\bapp\gradlew.bat -p bapp authLabDoctor -PlabProfiles=baseline
```

`matrix` lists historical requirement IDs, owning layers, expected observations and prerequisites. The catalog retains **41 groups / 980 entries**: **389 active product requirements, 523 verification-service checks, 28 excluded entries, 24 manual Burp entries and 16 capability assessments**. All 912 active automated requirements have bindings; they share 851 executions. The full credential matrix validates our custom test server and does not count as extension coverage. Bindings and passing results remain separate. See the [relevance audit](../../docs/designs/authentication-test-lab/relevance-audit.md).

`doctor` checks prerequisites without logging in. It currently qualifies Java 21 and current fixture bindings only; it does not qualify production-profile prerequisites. Use the actual profile commands below for production execution. The Java exit code for blocked work is 3, which Gradle reports as a failed command. This indicates a missing prerequisite or binding, not a failed login or network connection.

To execute the fixture checks with current-invocation evidence:

```powershell
.\bapp\gradlew.bat -p bapp authLab "-PlabProfiles=fixtures"
.\bapp\gradlew.bat -p bapp authLabDoctor "-PlabProfiles=fixtures"
```

This uses the existing `:auth-lab:test` task, with fresh JUnit XML, safe observed HTTP facts and an exact context record under `build/authlab/{invocationId}/{taskHash}/`. `report.jsonl` joins them to the inspected source witnesses and runtime artifact. Missing, skipped, duplicated, stale, mismatched or contradictory observations cannot establish a pass. Normal `:auth-lab:test` keeps its ordinary JUnit reports and establishes target contracts; `authLab` adds the scoped binding/evidence join. A bound case in `matrix` is not itself a passing result.

`authLab` implements selected-profile evidence collection for `fixtures`, `federation`, `transport`, `baseline`, `revised`, `credentials`, `diagnostics`, `browser` and `recovery`. The last six may be combined, for example `-PlabProfiles=baseline,recovery,diagnostics`: a shared existing method runs once per owning task, and the aggregate includes each selected requirement once. It runs no provider or middleware task for those six profiles. Explicit exclusions stay exclusions. A profile passes only when every selected result and its cleanup pass; a known product failure still fails the command. Partial `-PlabTests` filters belong to explicit scoped tasks and are rejected for profile acceptance. Other combinations, host/deployment and `all` remain gated.

Focused profiles write `build/authlab/{invocationId}/report-profiles.jsonl`, alongside their component/browser reports. Missing completion, duplicate or foreign requirements, stale sources/context, changed XML and passing labels contradicted by JUnit prevent acceptance. Existing explicit scoped production tasks remain available below. `LabMain` returns 2 for invalid arguments/catalogs, 3 for blocked/incomplete work and 0 for completed metadata/lifecycle operations. No empty selected test suite can pass.

Packaging and offline cold/cache/upgrade/rollback checks are maintained in main with the universal packaging design. The [installation reuse record](../../docs/designs/authentication-test-lab/installation-evidence-reuse.md) links its verified universal artifact and existing Windows/Linux evidence. This lab no longer selects its duplicate packaged-classloader helper. Installation smoke evidence is kept separate from broader authentication acceptance and the A8 artifact used by this lab's recorded product checks.

## Test the actual extension outside Burp

```powershell
.\bapp\gradlew.bat -p bapp authLabComponentTest --offline
.\bapp\gradlew.bat -p bapp authLabBrowserTest --offline
.\bapp\gradlew.bat -p bapp authLab -PlabProfiles=federation --offline
```

Component checks exercise the extension's real Java logic without launching a browser. The browser checks use its actual login engine: open the app, enter credentials, follow redirects, extract the selected output, then authenticate a protected request. The returned account and issuance must match the actual completed login, so a valid token from an older login for the same account cannot satisfy the proof. Combined automatic injection and one/two/three tags also send the production resolver's exact bytes, preventing an HTTP library from hiding duplicated headers/cookies.

The reviewed [production policy](src/main/resources/production-policy.json) selects component owners and explicit exclusions. Every production command captures the current checkout into `build/captures/{invocationId}/production`, records exact source hashes in `production-audit.json`, and rechecks inventory and bytes before publishing the capture. Its generated plan binds that audit by SHA-256. `-PlabPredecessor=PATH` explicitly selects another checkout; main is the default. Acceptance overlays live in `production-tests/` and are applied only in the isolated capture. The root Gradle `test` task runs main's native tests normally. Source edits require a new invocation; new test owners need an explicit policy review before selection. The source capture itself establishes no passing coverage. Binding `sourceRevision` preserves reviewed test provenance; the invocation audit, compiled outputs and observations bind the exact production revision. Reviewed source/configuration hashes remain strict and must be refreshed after intentional harness changes.

The current production artifact is universal: Windows x64, Linux x64 and Intel macOS. The browser/native executions recorded here run on Windows; bundled resources alone do not qualify execution on another platform. Prepare production's locked browser assets first. The lab can reuse all required source ZIPs from that cache only after checking their locked sizes and hashes; the offline command downloads no browser sources. Java 21 and the resolved/verified Gradle dependencies are also prerequisites. No Docker, provider or native token store is needed for these scoped component/browser checks.

Use `"-PlabTests=ClassName.methodName"` to investigate a particular owner, for example `"-PlabTests=DiagnosticsTest.*"`. This narrows the reviewed allowlist; it cannot select excluded upstream proxy-authentication methods. Such a subset is not full profile acceptance. The `labProfiles` property does not filter these explicit scoped tasks.

Each invocation retains a plan with source/test/helper/artifact hashes, resolved production/test dependency graphs, JUnit XML/HTML, safe component observations, protected identities, configured budgets and observed process cleanup under `build/authlab/{invocationId}/{taskHash}/`. The task hash is the full SHA-256 of its Gradle task path. Earlier scoped checkpoints remain under `build/p2/invocations/`. Missing methods, empty discovery, skips or failed assertions cannot yield a successful scoped task. Historical defects and their subsequent corrections retain separate evidence; see [main fix verification](../../docs/designs/authentication-test-lab/findings-fix-verification.md).

An early checkpoint, `aae080da-b7a7-4de5-93f9-90f31b170840`, had 198 component bindings and reported the then-failing missing-cookie feedback; its browser task passed 49 checks. Those counts are historical. The final fix checks pass 569 component, 50 browser and nine native transport tests with zero skips; the linked verification record supplies their exact source identities. Current binding/profile membership comes from the catalog, rather than those older counts. Later application edits receive a fresh source capture when production tasks run.

The diagnostic owners also check step numbers, action labels, causes, event details, journey state, request feedback, safe step navigation and redaction. Eight native browser observations cover real action failures and missing secure input. Server rejection must keep its own cause instead of being replaced by a later action timeout. These assertions extend existing owners; they do not claim the unbound diagnostic cases are complete.

Each tag input checks the original request and cached reuse, matching the selected journey identities and credential versions. Two/three-reference inputs exercise both distinct journeys and repeated references to one journey. Changing the acquisition fixture's next values cannot change the cached request or start another acquisition. New matrix vectors stay alphanumeric as designed; the existing literal-output owner separately checks complete request bytes and proves that tag-looking token text starts no second journey. This corrects the catalog's earlier combined publication label without dropping the separate literal-output requirement.

Browser surface checks also require actual page observations: early-token ordering before the ready marker, popup/frame completion messages, worker activation/control, and successful plus browser-denied CORS reads. Normal application telemetry reports only fixed stage names after creating the DOM marker. It cannot forward private controls. The test closes the owned target case before checking its retained observations and writes safe `surface-observations.jsonl` alongside the protected proofs. The late-token response retains its private hold/release gate, with the click remaining the last journey action; no extra page-completion step or expiry sleep is imposed on that recipe.

Four fresh-state operational cases run the same native journey twice at the same URL, case generation and configuration identity. Attempt A writes and reads back a cookie, local/session storage entry or service-worker registration, then completes a protected login. Attempt B observes it absent before logging in. Both new outputs authenticate the expected account. Actual context identities, closure ordering and owned-process cleanup are observed; all four have catalog bindings. The safe prime/probe observations remain in the invocation directory.

Diagnostic cases use real production extraction/network/cancellation failures, the actual Test login action and existing editor fixture, event rows and details, current coordinator state, and tagged/ordinary request feedback. The toolbar retains nonvisual state; its `getText()` is not treated as displayed output. The extraction-only success case reuses the existing coordinator/event-log owner. Safe detailed metrics stay in observation files; standardized facts use only catalog vocabulary. False semantic observations withhold the corresponding fact and cannot establish a pass.

Complete profile acceptance is not inferred from a passing source method or a subset run. Examples generated during operational tests retire with those servers. For manual testing, use the live export command below with a foreground serve run.

## Start and control the applications

```powershell
.\bapp\gradlew.bat -p bapp authLabServe "-PlabProfiles=browser"
```

Open the printed local address. Its index lists the prepared case URLs, including their generation. The process stays in the foreground; it starts no browser, Burp, Python application or provider container. Use `user/pass`, `user2/pass2` or `admin/adminpass` on the forms.

In another terminal, substitute the printed run ID:

```powershell
.\bapp\gradlew.bat -p bapp authLabExamples "-PlabRun=RUN_UUID" --offline
.\bapp\gradlew.bat -p bapp authLabReset "-PlabRun=RUN_UUID"
.\bapp\gradlew.bat -p bapp authLabPrepareCase "-PlabRun=RUN_UUID" "-PlabCase=BROW.basic.json"
.\bapp\gradlew.bat -p bapp authLabStop "-PlabRun=RUN_UUID"
```

Quote the complete Gradle properties in PowerShell, especially values containing dots. Reset retires old work and invalidates its generation; prepare the desired cases again afterward. Stop waits for cleanup acknowledgment. Commands read the private owned descriptor automatically and do not print its control key. They cannot kill or delete unrelated resources. Runtime files remain under `build/runs/{invocationId}/{runId}/`.

`authLabExamples` prints its generated `native-examples` directory. Import the individual JSON files in the extension and enter fixture password `pass2` in the secure input; username `user2` is already configured. The actual production serializer/parser generates and validates the files. A full browser serve run provides seventeen positive examples: ordinary forms, selected cookies, redirect variants, response surfaces and one combined bearer/two-cookie journey. Aliases are distinct within the export. No password, acquired token or control key is included. Generation prepares definitions and performs no authentication.

Keep the serving terminal running while using those examples. After Reset, prepare the desired cases and export again. Controlled example URLs carry case generations and reject earlier versions. Federation named origins can be reused, so regenerate the example matching the active mode. Retire previous imported samples before importing replacements with the same aliases. Closed runs cannot produce live exports. The same command exports the active supported federation case: browser OAuth, backend OAuth, SAML or broker. Software-token examples remain separate work.

The private control listener is separate from application traffic. It supports typed faults, bounded held responses, gate release, revocation, clock advances, phase selection, snapshots, reset and stop. Application URLs cannot forward control operations. Stale URLs, requests and typed leases cannot mutate a replacement case. Fixture time includes real elapsed time; explicit clock advances affect this server only. Expiry/revocation checks require no forced wait.

## What the targets provide

A successful JSON login is `POST /cases/{id}/login/json?generation=N` with exactly `username,password`. It returns a bearer and sets `LAB_C1`/`LAB_C2`, all from one new issuance. `/login/jwt` provides the explicit signed scheduling variant. `GET|POST .../protected/{subset}` accepts exactly the requested subset of `b,c1,c2`; success returns the actual account and issuance. Strict combinations require the same issuance. Duplicated, malformed or unrequired auth roles are rejected. `/protected/independent-cookies` separately preserves the legacy same-account/different-login behavior.

Use a fresh proof request carrying only the selected credential roles. An automatic cookie jar can otherwise add unrequired auth cookies to a bearer-only proof. The tests verify the returned identity and actual action counts, not just HTTP 200.

Prepared forms cover username/password, two pages, hidden-token plus cookie CSRF, JavaScript submission and consent. Ordinary form completion exposes a session-bound `/outputs` JSON response for the real response selector; it cannot restore a deliberately omitted output. Redirect chains cover zero/one/three hops, separate origins, cookies required between hops, exact POST preservation for 307, GET conversion for 303, deep links and deliberate failures. The deep-link fixture carries its bearer in `LAB_B` before landing on the exact protected URL; that ordinary navigation does not supply an Authorization header. Its bearer is proved separately through a correctly formed protected request.

Cookie targets expose rotation, deletion, tuple ambiguity, path attributes and an IdP/client decoy on distinct `localhost`/`127.0.0.1` hosts. The decoy cannot authenticate at the client endpoint. Response-surface pages expose early/late/nested JSON, popup, frame, CORS and service-worker responses. The late response uses the private `late-token` gate. A missing worker produces no fallback token response.

Fresh-state cases use the unchanged `/fresh/{kind}/start` entry, with PRIME/PROBE selected privately by the driver. Positive prime observation and A's login are required before PROBE; B observes state before login. The application does not pretend to observe production browser creation/closure. P2 must supply those real lifecycle witnesses and execute the page JavaScript through the production runner.

HTTP fixture checks validate target behavior and emitted headers. Actual browser tests separately establish the selected cookie, popup, worker and redirect behaviors. Prepared named-origin HTTPS and real federation flows have run on this machine; broader browser/platform compatibility is not inferred. `LabTls` creates dedicated material without installing global trust. The ingress sentinel observes connections, handshakes and decrypted bytes separately and closes with its owning case.

## Disposable software-token transport checks

The explicit native task reuses the inspected PKCS#11 tests and adds missing inputs in their existing owners. It requires installed SoftHSM/OpenSC/OpenSSL tools and a fresh private software-token store. From the repository root, the existing developer utility can prepare one:

```powershell
$productionRoot = (Get-Location).Path
$nativeRoot = Join-Path (Get-Location) ("test/authentication-lab/build/prepared/pkcs11/" + [Guid]::NewGuid())
python (Join-Path $productionRoot 'test/pkcs11_fixture.py') --output $nativeRoot
.\bapp\gradlew.bat -p bapp authLabTransportTest "-PlabPkcs11Fixture=$nativeRoot\fixture.json" --offline
# Or, instead of the scoped task, run all transport owners using this fresh store:
.\bapp\gradlew.bat -p bapp authLab "-PlabProfiles=transport" "-PlabPkcs11Fixture=$nativeRoot\fixture.json" --offline
```

That optional Python command only prepares local keys and a private SoftHSM store. The test applications and operational tests are Java. It refuses an existing directory; the native task validates and claims the new store for one invocation. A new invocation needs a fresh store. No user/physical token store is selected or reset.

The allowlist omits the old mixed upstream-authentication method entirely. Its unavailable-route input is tested with an unauthenticated listener. Internal per-attempt credentials on the extension-owned mTLS proxy remain in scope. Software-token results do not qualify physical devices. Eighteen active transport requirements share nine native inputs and three ordinary-browser routing inputs; one Chromium-only requirement is explicitly excluded. The profile command selects only those browser owners and still collects both scopes when an assertion fails; the combined report is `build/authlab/{invocationId}/report-transport.jsonl`. A private store is claimed by one invocation: prepare a fresh directory before another native command. The unavailable-upstream classification and browser-frame failures are corrected in main; historical P3 failures remain recorded separately. The scoped native task alone does not claim full transport acceptance.

For manual transport work, prepare a separate fresh store, then start the shared Java applications:

```powershell
.\bapp\gradlew.bat -p bapp authLabServe "-PlabProfiles=transport" "-PlabPkcs11Fixture=$nativeRoot\fixture.json" --offline
# In another terminal, use the printed run ID:
.\bapp\gradlew.bat -p bapp authLabExamples "-PlabRun=RUN-UUID" --offline
.\bapp\gradlew.bat -p bapp authLabReset "-PlabRun=RUN-UUID" --offline
.\bapp\gradlew.bat -p bapp authLabPrepareCase "-PlabProfiles=transport" "-PlabRun=RUN-UUID" "-PlabCase=TLS.mtls.same-CN-pair" --offline
.\bapp\gradlew.bat -p bapp authLabStop "-PlabRun=RUN-UUID" --offline
```

One case is active at a time; the default is `TLS.mtls.expected-fingerprint`. Fourteen cases have standalone examples: direct/HTTP/CONNECT/unavailable proxy routes, selected and missing certificate, missing middleware, the same-display-name certificate pair, allowed and unlisted redirects, a non-mTLS protected resource, and untrusted/wrong-host TLS. Internal proxy credentials, Chromium pinning, ambiguous selection and pool cleanup use their existing operational owners. Preparing one of those operational-only cases does not fabricate a standalone example.

The private authenticated `/targets` inventory supplies the current `resourceUri`, proxy addresses, public certificate fingerprints, CA path and private software-token configuration path. Exports omit the PIN. Start a **fresh Burp process** with that owned `SOFTHSM2_CONF` path inherited by that process only, then enter the disposable fixture PIN when prompted. An already running process may have initialized another token store; do not use it for this software-token check or change global environment settings. The employee credential must authenticate as account `user`; the admin credential must authenticate as `admin`. The same-CN case exports two separately selected fingerprints; they are separate journeys, not inputs composed into one automatic login.

Revocation and clock controls act on the same store that issued the certificate login's bearer. A snapshot supplies safe issuance IDs; `/revoke` rejects an old bearer and advancing the fixture clock by 60,001 milliseconds expires it immediately. No real-time expiry sleep is needed. Reset closes the owned listeners and retires their generation-bearing URLs; prepare a replacement case and regenerate its export afterward. Hosting, export generation and harness-control checks do not establish additional extension coverage.

## Catalog rules

The ten JSON files in `src/main/resources/catalog` implement the [approved contracts](../../docs/designs/authentication-test-lab-contracts.md). `catalog.json` explicitly indexes nine data files and the exact twelve profiles. Every expanded requirement is stored as data; runtime loading uses no expression language or native journey parser.

The Java validator rejects malformed/ambiguous JSON, unknown fields/capabilities, invalid bindings and missing/extra catalog members. The 912 inspected bindings are 523 fixture, 313 component-owned, 41 browser/recovery/subresource, seventeen federation and eighteen transport requirements, sharing 851 executions. No active automated requirement remains unbound. This is not a pass count: actual retained source/configuration-specific results still control acceptance. Excluded entries cannot execute or earn coverage. The [decision ledger](../../docs/designs/authentication-test-lab/relevance-retirements.csv) records the exclusions and the restored fixture checks.

Normalized axis labels are fixed in `ScenarioCatalog`: tag locations are `header,path,query,text-body`; tools are `scanner,proxy,repeater,extensions,intruder`; URL modes retain `burp_scope,all_requests,single_url`; boolean axes use `true,false`; limit dimensions use underscore-separated names. Named variant IDs and recipe labels retain the matrix's exact spelling, including `PIN-rejected` and `PIN-unknown`. H01 uses ordered `tool,mode` axes with `automatic-combined-injection,native-tags`. These are lab labels, not new production syntax.

Catalog budgets remain planning estimates. Actual invocation reports record measured startup/case/cleanup time; shared setup is not multiplied by requirement aliases. These values are not sleeps or substituted production timeouts. The simulated expired-code input requires no expiry wait.

## Build separation and dependency verification

The root build includes `:auth-lab` and `:federation-client` as separate Java modules under `test/`. The root `authLabRuntime` configuration never enters the extension runtime or release JAR. Maintained Spring/OpenSAML clients and the pinned official browser adapter drive real OIDC, SAML and brokered flows. Federation dependencies have their own locked graph; the clients have no production BApp dependency. Isolated fixture-validator checks qualify the harness only and remain subject to the final relevance audit.

The lab locks resolved dependency versions in `gradle.lockfile`. Its separate `hostProbe` source set has a compile-only Montoya dependency matching this checkout; building it establishes no Burp integration coverage. Narrow `.gitattributes` rules preserve LF bytes for the source/configuration files recorded in fixture bindings.

The lab uses Gson 2.13.2 and JUnit BOM 6.1.3. Gson's strict reader is combined with explicit duplicate-member and closed-field checks; [Gson's strictness guidance](https://github.com/google/gson/blob/main/Troubleshooting.md) explains why default parsing is insufficient. Gradle verifies the resolved artifacts through `bapp/gradle/verification-metadata.xml`. New dependency checksums were compared with published Maven Central SHA-256 values. Existing older root dependencies retain their checksums observed during resolution; not every older artifact publishes a separate SHA-256 file. See [Gradle dependency verification](https://docs.gradle.org/current/userguide/dependency_verification.html) before updating metadata. Do not disable verification or replace predecessor entries when integrating later work.

## Preserved legacy behavior

P0/P1 leave the old applications, examples, certificates and token assets intact. The current fixture sources provide these preservation requirements:

Preservation baseline: this checkout at `8accbeab2ba1beb216df3e447842f19ba130a9ff`, with 26 legacy files checked unchanged. SHA-256 of the sorted path-to-file-hash manifest: `c200c7a20b68ee03ca9f957e277477acfdd9da45ac41407f2b683fcf50a94c7c`. The local detailed manifest is `build/p0/preservation-before.json`. This identifies the older fixture assets, not the production revision to be integrated at P2.

| Existing source | Preserve or explicitly reconcile at cutover |
| --- | --- |
| `../mock-auth-app/app.py` | Accounts `user`, `user2`, `admin`; the login forms' `#user`, `#pass`, `#login` selectors; JSON/cookie/SSO routes and protected identity behavior. |
| `../mock-auth-app/saved_steps.json`, `saved_steps_cookie.json`, `saved_steps_cookie_2.json` | Recheck all three real saved-step files against their routes/selectors before replacing advertised examples. |
| `../mock-auth-app/README.md` | Its `button#cookie-login` example differs from the actual `button#login`; record the correction for later cutover rather than changing legacy behavior now. |
| `../integration_dual_cookie_tags.py` | Independent C1/C2 cookies may come from different issuances for the same account; keep this distinct from the strict common-issuance routes. |
| `../mTLS-app` | Preserve existing keys, certificates and token assets. Its static token example does not prove the new dynamic issuer/resource behavior. |

The initial P2 integration used `java-playwright`; production tasks now capture this checkout by default. Historical records retain their original source identity. The generated capture rechecks the complete selected source and Gradle inventory on every invocation. Configured upstream proxy-authentication tests remain excluded; internal mTLS-proxy credentials retain their separate scope.

## Next implementation stage

Each invocation records its exact production boundary in a generated capture audit. Reviewed catalog hashes describe the harness and selected test sources; changing those requires an intentional binding refresh. Profile commands, foreground browser/federation/transport serving and live native exports are implemented. The [current verification record](../../docs/designs/authentication-test-lab/findings-fix-verification.md) distinguishes corrected main behavior from historical P2/P3 failures. Remaining work includes the [sixteen capability assessments](../../docs/designs/authentication-test-lab/capability-assessment-recipes.md), unavailable or incomplete host checks and the legacy cutover gates. The [finalized design](../../docs/designs/authentication-test-lab.md) and [required relevance audit](../../docs/designs/authentication-test-lab/test-relevance-audit.md) define those gates.

Historical named-origin Windows hosts/current-user CA preparation and managed-browser trust probes apply to the original worktree material. Generated certificates and provider assets are not included in this integration; prepare and qualify this checkout before running federation. [Windows federation setup](Windows-Federation-Setup.md) documents preparation/removal for other machines; ordinary tests never install trust or edit hosts. The [federation module](../federation-client/README.md) documents the prepared image/adapter, complete profile command and foreground OIDC/SAML/broker serving commands.

## Manual Extensions-origin probe

Build the separate development helper with Java 21:

```powershell
.\test\authentication-lab\Build-HostProbe.ps1 -JdkHome 'C:\Program Files\Java\jdk-21'
```

The JAR is written to `test/authentication-lab/build/host-probe/authentication-lab-host-probe.jar`. Load it as a separate Java test extension in Burp. Its **Auth lab probe** tab loads a prepared raw HTTP request file, takes the current local lab origin, expected account and required roles, and calls the real Montoya request API once per explicit click. The loaded product handles authentication, injection and any authorized replay. The helper has no remote-control listener or authentication engine.

Use the protected request for the currently prepared controlled case. For automatic injection, leave credentials out of the request and select its journey in the product. For the native-tag checkpoint, put the saved alias references in the intended bearer/cookie slots. Match the role fields to the endpoint, for example `B,C1` for bearer plus one cookie. A retired case URL cannot qualify a new run. The helper records public account/issuance/role metadata and hashes, never raw requests, responses or credential values. It also records header counts, fixed role labels and tag presence before dispatch and in the request returned by Burp. The same safe JSON is retained beside the selected input as `<input>.<probe UUID>.probe.json`; a file-write failure remains visible in the UI. Its expected tool origin is explicitly labeled as an expectation; verify actual host policy wiring with the H01 procedure and Burp Logger. Its result is one manual checkpoint, not full profile acceptance.

The controlled fixture's credentials expire after 60 seconds. For manual host checks, clear expired cached credentials or use Test login immediately before sending. An expired response is not evidence that tag replacement failed. The product's 2xx-based acceptance message is also not independent authentication proof: qualify positive results using the protected response's expected account, common issuance and accepted roles. Current host observations and feedback findings are recorded in [P4 findings](../../docs/designs/authentication-test-lab/p4-findings.md); the [24-checkpoint ledger](../../docs/designs/authentication-test-lab/p4-host-checkpoints.csv) distinguishes passing, failing, partial and unavailable host checks.

When refreshing an extension already installed in Burp, toggle **Loaded** off before replacing its JAR and on afterward. Keep host/manual results separate from the automated catalog. The helper is absent from the production source set and release artifact.
