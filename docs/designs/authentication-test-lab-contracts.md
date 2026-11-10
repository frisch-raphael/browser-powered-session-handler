# Authentication test lab: implementation contracts

Current data/execution contracts for the [Java lab](authentication-test-lab.md) and [case matrix](authentication-test-lab-cases.md). Provider libraries are infrastructure, not the product under test. Explicit scope exclusions cannot execute or earn passing coverage.

## Reading guide and definitions

Here, **contract** means an agreement about exact data formats and behavior. For example: “When login succeeds, this endpoint returns these fields; when the cookie is missing, this test expects that error.” It does not mean a legal contract.

The six sections answer these practical questions:

1. How do we describe a check, connect it to a real test, control the test application and record the result?
2. Which checks run when you choose baseline, diagnostics or another named selection?
3. What exactly do the prepared applications return, including when we deliberately introduce a failure?
4. Which module owns shared server code, and how do native test facades delegate to it?
5. Which application issues each cookie/token, and how do we check that valid and deliberately invalid OAuth/SAML messages are handled correctly?
6. Which command examples and short explanations need correcting?

Start with the [complete missing-cookie example](authentication-test-lab-terms.md#start-with-one-complete-example). The [definitions with examples](authentication-test-lab-terms.md) explain the remaining terminology, grouped by topic. The precise fields and names below remain necessary for implementation, but you do not need to infer their meaning from the names alone.


## 1. Catalog, bindings, controls and evidence

In plain English: save a list of checks, identify the real code that runs each one, give the test driver a way to prepare/release/reset its applications, and record what happened. **Evidence** means actual observations, such as the account returned by a protected endpoint or the message produced by the extension; the list of planned checks alone is not evidence of a pass.

### Catalog records

A **catalog** is that saved list; a **record** is one entry in it. A **schema** says which fields and types an entry may contain. A **closed field set** rejects unknown fields, and an **enum** allows only a fixed list of labels. For example, `budgetMs` is a declared field, but an accidental `budgetMilliseconds` is rejected; an outcome labelled `PROBABLY_OK` is also rejected. See [data and selection terms](authentication-test-lab-terms.md#choosing-tests-and-understanding-their-data).

Use UTF-8 JSON, strict syntax and duplicate-member rejection. Every record below has a closed field set; reject unknown fields, invalid enum values and duplicate IDs. No implicit defaults, script expressions or native journey objects are accepted. Optional fields use explicit `null` or an empty array as specified; missing required fields are invalid.

`catalog.json` has exactly `labCatalogVersion` (integer 1), `dataFiles` (the existing ten relative JSON filenames, without traversal), and `profiles` (a map from the profile names in section 2 to arrays of requirement IDs). Each data file has exactly `labCatalogVersion` (1) and `requirements` (array of expanded requirement records). Store all 1030 expanded requirements explicitly; the Java catalog validator independently checks their domains/counts against the matrix. This avoids an embedded expansion language. `ScenarioCatalog` computes execution selections and checks that axis labels/IDs match their finite domains.

Each requirement record has these fields:

| Field | Type and rule |
| --- | --- |
| `id` | Unique string; named variants use `<group>.<variant>`. Axis variants use `<group>.<key>=<value>~...` with keys in the matrix's stated axis order. Values use lowercase ASCII letters, digits, `_` or `-`; no delimiter escaping is allowed. |
| `group` | One of the 41 exact group names in the matrix. |
| `revision` | Positive integer, initially 1. Change when inputs or expected behavior change. |
| `contract` | `LAB`, `BASELINE`, `REVISED`, `PROVIDER_CONTROL` or `ASSESSMENT`. |
| `layer` | `FIXTURE`, `COMPONENT`, `RUNNER`, `PROVIDER_CONTROL`, `TRANSPORT`, `HOST` or `ASSESSMENT`. |
| `axes` | Ordered array of `{name:string,value:string}`. Names/order/domains are those in the matrix. Empty for named variants. |
| `capabilities` | Array drawn from `FIXTURES`, `PRODUCTION`, `BROWSER`, `NATIVE_TAGS`, `WRAPPERS`, `LIMITS`, `INJECTION`, `MULTI_OUTPUT`, `REPLAY_PAUSE`, `PRESENTATION`, `NATIVE_STORAGE`, `HTTPS`, `CROSS_SITE`, `KEYCLOAK`, `BROKER`, `IDP_COOKIE_PROOF`, `PKCS11`, `SOFTHSM`, `PHYSICAL_TOKEN`, `BURP_HOST`, `PACKAGED_ARTIFACT`. Per-variant requirements, never blanket group skipping. |
| `roles` | Array drawn from `B`, `C1`, `C2`, `API_TOKEN`, `CLIENT_COOKIE`, `IDP_COOKIE`. Role is a lab expectation, not production selector syntax. |
| `recipe` | Exact named flow/variant from the matrix, or `null` for a component-only assertion. |
| `assignments` | Array of `{slot:string,value:string}`. Fixture slots are `account`, `issuance`, `required`, `B`, `C1`, `C2`, `method`, `body`, `return`, `selector`. Component axis slots use their exact matrix axis names. Additional slot names require an explicit case-contract revision, not silent acceptance. Raw credential values are prohibited. |
| `expected` | Array of `{fact:string,value:string}`. Allowed fact names: `outcome`, `httpStatus`, `account`, `issuance`, `role`, `publication`, `ingressBytes`, `actions`, `attempts`, `replays`, `state`, `stage`, `cause`, `requiredMessageFact`, `forbiddenMessageClaim`, `currentRevision`, `resources`, `redaction`, `capability`. Multiple message facts are allowed; contradictory duplicate facts are invalid. |
| `faults` | Ordered array of fault records defined below; empty when absent. |
| `evidence` | Required observation names from the same fact vocabulary, plus `browserLaunch`, `contextClose`, `processOwnership`, `hostCheckpoint` and `completion`. |
| `budgetMs` | `{startup:positive integer,case:positive integer,cleanup:positive integer}`. Real-runner case budget follows the configured production cycle deadline plus its declared cleanup allowance. Protocol-expiry controls have the explicit budgets in section 5. |
| `binding` | `null` before a callable owner is established, otherwise the binding record below. Null active bindings produce `BLOCKED`; excluded entries cannot bind or execute. |
| `disposition` | `NEW`, `REUSE`, `EXTEND`, `BLOCKED`, `MANUAL` or `EXCLUDED`. EXCLUDED is restricted to the author's fourteen retired provider-validation entries and requires the explicit outside-extension-scope outcome. It never means PASS. |

Fixture matrix axis order is `required`, then applicable roles in `b,c1,c2` order. Required values are `b`, `c1`, `c2`, `b_c1`, `b_c2`, `c1_c2`, `b_c1_c2`. Supplied role values are `s0` through `s5` or `none`; non-required roles are absent, not additional axes. For example: `FIX.matrix.required=b_c1~b=s0~c1=s1`. The tag axes are `location,mode,references`; tool-policy axes are `tool,urlMode,enabled,tagged`; recovery axes are `trigger,requestMode,outputs,originals`; limit axes are `dimension,point`. Their values are the matrix's declared labels, normalized once to the allowed ID characters. Validate every declared combination rather than infer coverage from row count alone. An **axis** is a choice that varies; its **domain** is the allowed choices. For example, 4 locations × 4 encodings × 3 reference counts gives 48 combinations, also called a Cartesian product.

Logical ownership (`layer`, `recipe` and expected assertion) must exist in P0. A physical production binding can remain null until P2; that is a declared blocked prerequisite, not an unowned assertion. P0 metadata commands must not load production classes to validate the catalog.

Use nested Java records in their already-listed owning files. `LabRun.start(RunSpec)` returns an AutoCloseable LabRun. RunSpec has `invocationId:UUID`, `profiles:List<String>`, `catalog:ScenarioCatalog`, `environmentRoot:Path`, `preparedArtifacts:List<ArtifactRecord>` and `cycleDeadlineMs:long`. Resolve required listeners/provider roles from selected capabilities rather than another independent configuration language. `prepareCase(String caseId)` returns a CaseLease with immutable run/case/generation identity and resolved endpoint URIs. Its typed operations are `armFault(FaultSpec)`, `awaitCheckpoint(String name, Duration timeout)`, `release(String name)`, `revoke(String issuanceId)`, `advanceFixtureClock(Duration delta)`, `selectFreshPhase(FreshPhase)`, `snapshot()` and `close()`. Await uses a monotonic deadline and returns the observed checkpoint snapshot or a sanitized deadline failure. Close is idempotent and uses the declared cleanup budget; a cleanup failure is recorded and propagated, not ignored. None of these types imports production credential or authentication classes.

### Existing-test binding

A **test binding** connects a requirement to the actual test and input that establish it. A **witness** identifies its relevant assertion; an assertion is the check inside the test. For example, the missing-cookie requirement needs a test that checks the actual missing-cookie message, not a test whose name happens to mention cookies. Recording those links gives the **witness ledger**. See [test definitions and examples](authentication-test-lab-terms.md#tests-and-what-they-prove). This meaning of binding differs from associating a cookie with a bearer token in section 5.

Each requirement has one binding and one owning layer. A binding is null before its callable owner is established, otherwise it has exactly `executionId`, `executor`, `className`, `methodSignature`, `parameterKey`, `witnesses`, `sourceRevision`, `sourceHashes`, `taskPath`, `configurationHash` and `xmlCaseName`. JUNIT owners require actual class/method identity, task/configuration and exact safe exported testcase name; unparameterized owners have parameterKey:null. FIXTURE/MANUAL owners have null className, methodSignature, xmlCaseName and taskPath; parameterKey stores their declared case/checkpoint key and configurationHash identifies the owned run/artifact configuration. No required-execution list, dependency graph or implicit AND across different test invocations is introduced.

The component requirement `CORE.diagnostics.missing-cookie` proves actual message formatting/state for a supplied missing-cookie outcome. The separate `BROW.cookie-selection.deleted-mid-flow` requirement proves the real runner reports the missing selected cookie after the fixture removes it. Likewise, CORE.diagnostics.connection-refused checks the component presentation, while BROW.redirect-failure.unreachable-hop owns actual connection-failure propagation from its declared hop. Record each expected stage/cause in its own requirement. Reuse other existing browser/transport requirements for their actual failure categories; do not add duplicate flow cases merely to join the report. The full selected suite establishes both facts; the diagnostics profile establishes only its declared component facts. A component pass is not reported as browser-propagation evidence.

`witnesses` is an array of `{requirementId,assertionId,sourcePath,sourceSymbol,inputKey}` identifying the audited assertion/input within that one owning invocation. `sourceHashes` maps paths to exact SHA-256. An execution may satisfy several requirements when its inspected assertions establish each separately; selecting several profiles still runs that identical execution once per artifact/backend/task configuration. Missing/stale bindings are BLOCKED; an actual failed invocation is FAIL, skipped or missing selected invocations cannot PASS. P2 supplies the actual method/parameter witnesses after the full fresh audit.

### Actual JUnit result matching

Use normal Gradle JUnit XML as observed execution evidence; XML is a structured report where each testcase entry describes an actual test outcome. Implement the join in the planned LabEvidence/AuthLabSupport classes and Gradle wiring. No replacement runner or extra test suite is required. Each explicit lab invocation/task uses a fresh directory under its owning project's build/authlab/{invocationId}/{taskKey}/, where taskKey is the full lowercase SHA-256 of the UTF-8 task path. Set that task's JUnit XML output to its junit-xml subdirectory. Disable cached/up-to-date success for these lab tasks.

The task writes report-context.json with exactly contextVersion:1, invocationId, taskPath, configurationHash, productionRevision, artifactSha256, catalogRevision and state. State starts as STARTED. A task finalizer records COMPLETED or FAILED only after the actual test task and report collection settle. Missing completion/cancellation is incomplete evidence. FAILED preserves passing and failing individual cases without turning the task into success. Reject foreign invocation/task/configuration context.

Match a binding to exactly one actual XML testcase by taskPath, configurationHash, classname and name, where classname equals className and name equals xmlCaseName. For a parameterized invocation, require exactly one safe [case=KEY] marker in that actual name and compare its parsed KEY to parameterKey; P2 adds that marker to an existing owner's display name only when an equivalent safely audited key is unavailable. If retaining an existing convention, record its exact deterministic key extraction at P2. Never match an ordinal or raw argument value. Verify current source hashes, artifact/catalog revision and the audited method/assertion mapping. A missing/duplicate/skipped/mismatched entry cannot PASS; a testcase failure/error is FAIL. The audited method signature is mapping data, not a claimed runtime XML field.

CASE_RESULT has a singular observedBinding object (or null when no matching execution exists). All its fields are strings except witnessIds (array of strings); outcome uses the existing outcome enum. Hash strings are 64 lowercase hexadecimal characters. observedParameterKey is null for an unparameterized JUnit invocation; taskPath and observedClassName/observedCaseName are null for non-JUnit owners, whose observedParameterKey is read from their actual case/checkpoint record. Its exact fields are executionId, executor, invocationId, taskPath, configurationHash, observedClassName, observedCaseName, observedParameterKey, bindingSha256, witnessIds, reportPath, reportSha256, contextSha256 and outcome. JUNIT observed names/keys come from the actual XML. The binding fingerprint and witness IDs describe the validated source mapping; do not invent them as runtime observations. Hash binding JSON with recursively sorted object keys, array order preserved and no insignificant whitespace. Paths stay within the owned invocation directory; report/context hashes fingerprint the retained bytes. Parse XML without external entities/DOCTYPE. Parameter labels and assertion output exclude credentials. PASS requires the matching successful result and required case evidence; null/missing observation never passes.

For MANUAL, taskPath and JUnit names are null; reportPath references the same run's actual operator/checkpoint record and contextSha256 identifies its run/artifact context. For a non-JUnit FIXTURE executor, those fields are also null and reportPath identifies the actual typed fixture result; it can prove FIXTURE facts only. Their actual invocation/case revision must match CASE_RESULT, and they cannot replace a production JUnit binding. Preserve unperformed manual results as NOT_RUN and unmet prerequisites as BLOCKED.

Representative valid requirement: `CORE.diagnostics.missing-cookie` with layer `COMPONENT`, required facts `stage=extraction` and `requiredMessageFact=selected-cookie-missing`, forbidden claim `connection-failed`, and an audited diagnostic owner. These are lab expectation labels mapped to actual production presentation, not new production error codes. Invalid records include unknown field `nativeJourney`, duplicate IDs, an axis outside its domain, a `REUSE` result without a current binding, or `PASS` from an unexecuted witness.

### Private descriptor and resource ownership

A **run** is one owned test environment. Its **descriptor** is the private file saying which servers, processes and containers belong to it. **Resource ownership** means we can prove which ones the test created before stopping them. For example, cleanup closes this run's browser; it must not close your unrelated Chrome window. A process ID alone cannot prove ownership because the operating system can reuse it.

For native cancellation, distinguish graceful SDK close notifications from forced termination of the owned driver/browser process tree. The watchdog may destroy the pipe before context/browser `close()` can emit notifications. Preserve their actual counts, including zero. Cancellation can establish resource closure only when the real context was observed, the owned driver and browser processes were observed with process identity, and none survives the bounded cleanup wait. Do not invent SDK events. Other successful/rejected federation journeys still require their actual graceful close events as well as process closure. An expected authentication exception must not absorb a separate cleanup assertion failure; report that case as failed/incomplete.

The owning process creates `test/authentication-lab/build/runs/{invocationId}/{runId}/`. IDs are random UUIDs. Its private `run.json` has exactly `descriptorVersion:1`, `invocationId`, `runId`, `generation`, `createdAt` (UTC ISO-8601), `environmentRoot` (resolved absolute path), `controlUri`, `controlKey` (256-bit random base64url), `resources`, and `state` (`STARTING`, `READY`, `STOPPING`, `CLOSED`, `INTERRUPTED`). Do not print the key or put it in process arguments, journeys or application URLs. Restrict the directory to the current user.

Resource records contain `kind` (`PROCESS`, `CONTAINER`, `NETWORK`, `VOLUME`, `DIRECTORY`), `id`, `ownerRunId`, `createdAt` and `proof`. Process proof records PID, OS creation time, canonical executable and the parent-owned launch ledger entry. Docker proof records immutable resource ID and labels `authlab.run`/`authlab.invocation`, checked by inspection. Directory proof records its resolved path beneath the recorded environment root. PID, port, name or label alone is insufficient. Unverifiable resources are reported for explicit cleanup; they must not be killed/deleted speculatively. Closing a run never removes user token stores, preserved certificates or unrelated resources.

### Control HTTP interface

This is a separate local address for the test driver to control the test application. For example, the login response can be deliberately held while the driver sends a release command through this separate address. The browser doing the login uses the application address, not this control address. A **listener** is a server waiting for connections; **loopback** means an address on this computer, such as 127.0.0.1. See [running and controlling a case](authentication-test-lab-terms.md#running-controlling-and-cleaning-up-a-case).

Base path: `/control/v1/runs/{runId}` on an independent loopback listener. Authenticate every call using `Authorization: Bearer <controlKey>`. Require JSON content type for nonempty request bodies; maximum 64 KiB. No control CORS grants or application-listener aliases.

| Method and relative path | Request body | Success |
| --- | --- | --- |
| `POST /cases` | `{caseId:string,runGeneration:positive integer}` | 201 `{runId,caseId,generation}`; compare the expected run generation before allocating a new monotonically increasing case generation. |
| `POST /cases/{caseId}/fresh-phase` | `{generation,phase}`; phase is `PRIME` or `PROBE`. | 200 `{generation,phase}` after the allowed phase selection. |
| `POST /cases/{caseId}/faults` | `{generation,fault}` | 200 `{generation,armed:true}`. |
| `POST /cases/{caseId}/gates/{name}/release` | `{generation}` | 200 `{generation,released:true}`; repeated release in the same active generation is idempotent. |
| `POST /cases/{caseId}/revoke` | `{generation,issuanceId}` | 200 `{generation,revoked:true}`. |
| `POST /cases/{caseId}/clock` | `{generation,advanceMs:nonnegative integer}` | 200 `{generation,fixtureTimeMs}`; fixture time only. |
| `POST /cases/{caseId}/federation-control` | `{generation,variant,checkpoint}`; `code-expired` at `before-token-exchange` only for `FED.negative.code-expired`, or `client-publication-hold` at `before-client-session` only for `FED.broker.cancelled`. | 200 `{generation,armed:true}`; arm the immediate backend failure input or hold client-cookie publication until the extension is cancelled. Neither changes provider validation. |
| `GET /cases/{caseId}/snapshot?generation=N` | Empty | 200 safe counters/events/checkpoint states; no credentials. |
| `GET /targets?generation=N` | Empty; current run generation. | 200 `{runId,generation,applicationOrigin,alternateOrigin,cases:[{caseId,generation,startUri}],federation,transport}` for active cases only. `federation` is null for ordinary runs; otherwise `{clientOrigin,resourceOrigin,issuer,upstreamIssuer}`, with null upstream when absent. `transport` is null without an active standalone transport case; otherwise it supplies the current case/version, owned issuer/redirect/unlisted/wrong-host origins, generation-bearing resource URI, unauthenticated proxy/held unavailable-proxy addresses, module/configuration/CA paths, public fingerprints and `softwareOnly:true`. Neither view contains a PIN, obtained credential or control key. Private control authentication is required; stale run versions return 409. This read-only view supports native examples without copying keys or scraping the public index. |

Foreground federation serving uses the same `LabRun`, provider and client/API owners as JUnit. Select `--profiles federation` and one active `--case` (default `FED.flow.browser-oidc`); mixed federation/controlled serving is rejected explicitly. The fixed named HTTPS origin tuple serves one client/API pair at a time. The public index links to that case's real named login URL and displays its generation. Preparing a federation case through the authenticated parent `/cases` route starts the owned pair before acknowledging readiness. Reset closes that pair and recreates provider state; a case must be prepared again. Parent snapshots and federation/gate controls delegate only to the current owned child, with private child keys kept inside the owner. Preserve the child's sanitized status/code on rejection. Fixture-clock, generic-fault, revocation-label and fresh-cookie-phase controls are rejected for federation cases rather than mutating an unrelated fixture store. Unobserved federation counters remain null.

The foreground Java command uses a retained copy of its lab runtime and a frozen federation runtime manifest, so a concurrent build cannot replace live service code. CLI preparation/reset bounds include actual child startup/provider reset and return as soon as the operation settles; those bounds are not fixed waits. Serving applications never establishes passing extension coverage.
| `DELETE /cases/{caseId}?generation=N` | Empty | 200 `{generation,closed:true}` after the case's work has stopped and resources have settled (quiescence); otherwise bounded failure. |
| `POST /reset` | `{generation}` | 200 `{generation:newRunGeneration}` after retiring all prior cases and settling their work. Provider state is recreated only when this run owns a selected provider environment. |
| `POST /stop` | `{generation}` | 202 `{state:"STOPPING"}`; terminal outcome is written to the result stream before process exit. |

Fault records have exactly `phase` (`LOGIN`, `HOP`, `EXTRACTION`, `TOKEN_EXCHANGE`, `PROTECTED`), `occurrence` (1–32), `kind` (`REJECT`, `CLOSE_BEFORE_RESPONSE`, `HTTP_ERROR`, `HOLD`, `OMIT_OUTPUT`, `ROTATE_OUTPUT`, `OMIT_HOP_COOKIE`, `REDIRECT_LOOP`, `REJECT_REPLACEMENT`), `role` (declared role or null), `status` (401/403/500/502/503/504 for HTTP_ERROR, otherwise null) and `checkpoint` (named gate or null). Reject incompatible fields. These inject observations; they do not decide production retry classification.

Errors use `{error:{code,message,runId,caseId,generation}}`, with null case fields for run errors. Codes/statuses: `BAD_INPUT` 400, `UNAUTHORIZED` 401, `NOT_FOUND` 404, `GENERATION_CONFLICT` 409, `STATE_CONFLICT` 409, `RETIRED` 410, `TOO_LARGE` 413, `DEADLINE` 504, `INTERNAL` 500. Messages are sanitized. A stale mutation never affects a new generation. Waiting for checkpoints uses bounded in-process conditions or repeated safe snapshots until the caller's deadline; no blocking control-handler wait consumes the release executor.

Only READY runs admit prepare/mutation requests. Preparing an already-active case ID returns 409 STATE_CONFLICT; reuse requires closing/resetting its prior generation first. Case generations increase monotonically within the run, and reset increases the run generation and retires every prior case before reopening admission. Snapshots may report a STOPPING run; no new mutation is admitted. Stop is idempotent for that run/generation. Child federation controls use the same field/error contract on their private listener, with the run owner forwarding approved operations using the private key; the application listener cannot forward control requests.

Case creation carries the caller's expected `runGeneration`, distinct from the allocated case `generation`. Missing or invalid `runGeneration` is 400 BAD_INPUT. A version mismatch is 409 GENERATION_CONFLICT and allocates nothing. Compare the version, check READY/admission and allocate the case atomically under the same lifecycle lock used by reset. Never replace the supplied version with the current version or retry automatically using a newer version. Reset commits the new run version to its in-process handle and private descriptor before reopening admission. Existing prepared-case operations retain their case-generation checks.

The typed `LabRun.prepareCase(String)` captures its expected run version on entry, before queuing or acquiring the lifecycle lock, and applies the same atomic comparison/allocation rule as HTTP. A typed conflict fails that call with GENERATION_CONFLICT rather than creating a case. A newly issued call after completed reset captures the new version. Do not read the version only after waiting for the lock, because that would admit old queued work.

Fresh-state cases begin UNARMED. Only BROW.fresh cases accept this operation; another case or an invalid phase is 400 BAD_INPUT. UNARMED to PRIME is allowed. PRIME to PROBE requires the fixture's positive prime observation and A's completed login; otherwise return 409 STATE_CONFLICT. Selecting the already selected PRIME or PROBE phase is idempotent. Reversal from PROBE to PRIME is 409 STATE_CONFLICT. Stale/retired case generations follow the existing conflict/retirement rules and cannot change phase.

The driver selects PRIME before attempt A. After A succeeds, the driver verifies closure of A's actual production context/resources using their lifecycle owner, then selects PROBE and starts B. The fixture checks its own prime/login observations; it does not claim to observe browser closure. Phase selection uses the private control address/key, never a journey action or a cookie/storage value. No target reset or browser-state clearing occurs between A and B.

Any other phase transition is 409 STATE_CONFLICT. `CaseLease.selectFreshPhase(FreshPhase)` uses the same generation guard and transition rules as HTTP; declare the PRIME/PROBE enum inside LabRun.java. Invalid lifecycle transitions use STATE_CONFLICT.

A snapshot has exactly `runId`, `caseId`, `generation`, `state` (`PREPARED`, `RUNNING`, `CLOSING`, `CLOSED`), `checkpoints` (array of `{name,state}` with WAITING/RELEASED/RETIRED), `counters` (`httpIngress`, `routed`, `actions`, `connections`, `tlsHandshakes`, `applicationBytes`), `events` (array of `{sequence,time,phase,name,safeIds}`), and `truncated` (boolean). `safeIds` is an array of `{kind,value}` using nonsecret case/account/issuance/role labels. A counter is a nonnegative integer or null when that listener cannot observe it; required null observations are incomplete evidence. Browser/process observations come from their actual lifecycle owner and the result collector, not guessed fixture counters. Protocol observations use these events for the selected variant, exchange count, safe outcome/error code and changed-field name; no raw codes/tokens/assertions leave private runtime state.

### Result and completion records

These are the recorded observations and final outcome. **JSON Lines** means one JSON record per line, so a run can leave useful partial results if interrupted. The **completion record** separately confirms that execution and cleanup finished. For example, a passed case followed by a process crash must not turn into an overall passed run just because that case's result was written.

Write safe UTF-8 JSON Lines to `report.jsonl` in the run directory; publish only that sanitized stream and normal JUnit results. Each envelope has `resultVersion:1`, `type`, `invocationId`, `runId`, `sequence` (increasing integer), `time` and `data`.

The type-specific `data` fields are closed records:

| Type | Exact data fields |
| --- | --- |
| `RUN_STARTED` | `productionRevision` (string or null for independent fixture work), `artifacts` (array of `{role,version,sha256}`), `dependencyPins` (array of `{coordinates,version,integrity}`), `profiles` (array of profile names), `selectedRequirementIds` (array of IDs). |
| `CASE_RESULT` | `requirementIds` (array of IDs), `executionId` (string), `observedBinding` (the singular observed-result record or null), `caseRevision` (integer), `layer` (catalog enum), `classification` (enum below), `outcome` (enum below), `expected`/`observed` (fact arrays), `missingEvidence` (observation-name array), `timings` (`startupMs`, `caseMs`, `cleanupMs`, nonnegative integers), `cleanup` (COMPLETE/FAILED/INCOMPLETE), `host` (null or `{operator,version,tool,platform,artifactSha256,checkpoints}`). Host fields are strings except its checkpoint-name array. |
| `RUN_COMPLETED` | `outcomes` (integer counters named PASS/FAIL/BLOCKED/NOT_RUN/INTERRUPTED/EXCLUDED), `cleanupOutcome` (COMPLETE/FAILED/INCOMPLETE), `remainingResources` (array of safe owned-resource IDs), `complete` (boolean, true only after required quiescence and evidence checks). |

Outcomes are PASS/FAIL/BLOCKED/NOT_RUN/INTERRUPTED/EXCLUDED. Classification is SUPPORTED/UNSUPPORTED/MANUAL/UNASSESSED/EXCLUDED, independently of execution outcome. EXCLUDED records intentional scope removal and cannot count as a test execution, pass or missing witness. Missing final completion, required active facts, matching witness or cleanup acknowledgment prevents a full pass. An empty explicitly selected executable suite fails. Event truncation is visible; atomic counters remain available after the 10,000-event cap. JUnit or fixture assertion failure yields FAIL; missing active prerequisites/bindings yield BLOCKED; requested but unperformed manual cases yield NOT_RUN; process termination before a final record yields INTERRUPTED. Preserve every outcome in the aggregate rather than replacing failed rows with the last exit status.

## 2. Exact profile selection and smoke budget

A **profile** is a named selection of checks, not a saved browser profile. The **baseline/smoke** selection is a small first check for obvious breakage. A **predicate** is simply the selection rule in the table, such as “all BROW cases.” Combining profiles takes their **union**: include each requirement once. **Deduplication** means the same actual test is not rerun merely because two selected profiles need it.

All active profile members are mandatory requirements. Explicit scope exclusions cannot execute or enter required-coverage counts. Missing active prerequisites produce BLOCKED; they are never silently filtered into a pass. Manual entries remain NOT_RUN until recorded. `all` can report its automated subset separately, with host/manual/assessment work still outstanding. Selecting several profiles takes the union and deduplicates execution IDs.

| Profile | Exact requirement predicate |
| --- | --- |
| `fixtures` | All `FIX.*`. |
| `baseline` | Exactly the 12 IDs listed below. |
| `revised` | All `CORE.outputs`, `CORE.recovery`, `CORE.retry`, `RUN.recovery`; plus `CORE.injection.combined`, `CORE.diagnostics.incomplete-output-set`, `CORE.diagnostics.attempts-exhausted`. |
| `credentials` | All `CORE.outputs`, `CORE.tag-matrix`, `CORE.tag-selection`, `CORE.tag-failure`, `CORE.encoding`, `CORE.limits`, `CORE.injection`, `CORE.tool-policy`, `CORE.lifetime`. |
| `diagnostics` | All CORE.diagnostics component requirements only. Separate BROW/TLS requirements own actual failure propagation; the complete selected suite reports their results separately. |
| `browser` | All `BROW.*`. |
| `federation` | All `FED.*`. |
| `recovery` | All `CORE.recovery`, `CORE.retry`, `CORE.resources`, `RUN.recovery`; plus `CORE.lifetime.server-revoked`, `CORE.lifetime.late-old-401`. |
| `transport` | All `TLS.*`; hardware-only evidence remains explicitly manual when selected. |
| `http-auth` | All twelve `HTTP.auth.*` cases, through the existing component/browser tasks; no PKCS#11 prerequisite. |
| `burp` | All `HOST.http-auth.*` and H01–H05 entries. |
| `deployment` | H06's two entries, with their linked automated package observations and mandatory actual-host checkpoints. Automated package checks alone cannot pass a host requirement. |
| `all` | All 1030 requirements/assessments, including `CORE.registry`, `CORE.storage` and CAP.assessment. |

Baseline IDs: `BROW.basic.json`, `BROW.basic.cookie-one`, `BROW.basic.two-page`, `BROW.redirect.cookie-each-hop`, `CORE.tag-selection.repeat-one-output`, `CORE.injection.bearer`, `CORE.injection.cookie`, `CORE.lifetime.fresh`, `CORE.lifetime.exact-expiry`, `CORE.registry.missing-secret`, `CORE.diagnostics.missing-cookie`, `CORE.diagnostics.connection-refused`.

This selects four real-runner requirements and eight component requirements; it requires neither Docker nor TLS/native middleware. Production/presentation prerequisites still apply. The two diagnostic IDs are component-only claims; broader browser profiles separately prove actual failure propagation. There are no hidden supporting-execution dependencies. No additional profile implicitly joins baseline. `authLabComponentTest` selects the audited component-owned `CORE.*` executions only, with absent capabilities reported honestly; default project regression commands remain separate.

Provisional baseline planning budget: startup 10–30 seconds, successful case work 10–60 seconds, cleanup 5–15 seconds, approximately 25–105 seconds overall. These are estimates, not measured results or production-deadline changes. Controlled failure representatives fail promptly. Each real-runner case still has its configured production deadline and declared cleanup allowance; report observed startup/work/cleanup separately before expanding this profile. P2 supplies actual source/parameter bindings, not a different membership set.

## 3. Controlled HTTP and independent expectations

A **controlled application/fixture** is a test target whose replies we can prepare precisely. An **independent expectation** is the answer worked out separately from its acceptance code. For example, when the test supplies user2's credentials, it expects user2's identity; it does not ask the server's validator what identity the test should expect. That independence prevents one shared mistake from making both sides agree.

### Identity and protected routes

An **issuance** is the set of credentials created by one login. **B**, **C1** and **C2** mean bearer, first cookie and second cookie. For example, s0 and s1 are two separate logins as the same user: B from s0 plus C1 from s1 is a mixed-login set even though the account is the same. The [authentication definitions](authentication-test-lab-terms.md#authentication-outputs-and-recovery) explain extraction, selection, injection, publication and recovery too.

Three preserved public fixture accounts are `user`/`pass`, `user2`/`pass2`, `admin`/`adminpass`, matching this checkout's mock application's constants. Each case seeds two logins per account: s0/s1=user, s2/s3=user2, s4/s5=admin. Tokens are random, distinct per role/issuance and private to the case; expectations use these labels rather than regenerating or parsing raw values. These published fixture inputs are distinct from private runtime credential outputs.

`POST /cases/{id}/login/json` accepts exactly `{username,password}` and on success returns 200 `{access_token,accountId,issuanceId}` while setting `LAB_C1` and `LAB_C2`. Bad credentials return 401 `{error:"login_rejected"}` with no issuance or auth cookies. Oversized/malformed JSON returns 400. Cookies default to host-only, case-root Path, HttpOnly, SameSite=Lax, and Secure only on HTTPS. JSON bearer values are opaque unless the case explicitly selects the signed scheduling variant. Browser forms submit the same fields using `application/x-www-form-urlencoded`, preserving `#user`, `#pass` and `#login`.

Protected path: `GET|POST /cases/{id}/protected/{subset}`, where subset is one of the seven `required` labels in section 1. Bearer uses exactly one Authorization field; C1/C2 use the named cookies. Duplicate Authorization or duplicate named auth cookies, malformed/empty supplied auth values, and supplied known-but-unrequired auth roles return 400. Unrelated cookies such as `preferences` are ignored. Missing/unknown/expired/revoked/wrong-kind or mixed-issuance required material returns 401. Success returns 200 `{accountId,issuanceId,acceptedRoles,actionId}` using authenticated server state. Expected account is never a request parameter. Each successful POST increments actions once; GET does not. Rejections perform no action. Safe IDs/counters are available from the isolated controls.

The independent-cookie legacy scenario uses a separate `/protected/independent-cookies` route: C1 and C2 must both be valid and identify the same account, but need not share an issuance. Thus C1=s0/C2=s1 succeeds as user with both issuance labels in the result; C1=s0/C2=s2 fails with 401. This preserves the current mock application's same-account dual-cookie semantics without adding a common-issuance rule to it. It is never used for the strict combined automatic-injection oracle, whose seven routes retain common-issuance enforcement.

### FIX.extra assignments

Unless stated otherwise, use required subset `b_c1_c2` and the complete s0 set. The assertion's expected labels are hand-authored, independent of the server's accept function.

| Variant | Changed input | Expected |
| --- | --- | --- |
| unknown | Replace B with an unregistered nonempty value. | 401, no action. |
| expired | Advance fixture time beyond s0 expiry. | 401, no action. |
| revoked | Revoke s0 before use. | 401, no action. |
| wrong-kind | Supply s0.C1 as B. | 401, no action. |
| duplicated-role-value | Supply s0.C1 in both C1 and C2. | 401, no action. |
| duplicate-authorization | Supply two Authorization fields, including valid s0.B. | 400, no action. |
| duplicate-cookie | Supply LAB_C1 twice, even with identical values. | 400, no action. |
| extra-unrequired | Use subset b, B=s0, C1=s2. | 400; known unrequired auth output is explicit. |
| empty-value | Supply an empty B value. | 400, no action. |
| same-account-other-login | Use subset b_c1, B=s0, C1=s1. | 401 despite the same account. |
| other-account-complete-set | Supply the complete s2 set. | 200 with user2/s2; it must not report user/s0. |
| generator-witness | Hand-written complete s0, missing C1 and mixed s0/s2 assignments. | Respectively 200 user/s0, 401 and 401; do not call the matrix generator for these witnesses. |

The base 511 matrix supplies only required roles. It still has exactly 42 same-issuance successes and 469 missing/mixed rejections. Additional duplicate/malformed/extra-role assertions belong to FIX.extra and do not change that arithmetic.

### Browser flow parameters

A **redirect hop** is one move in the login chain. A **cookie tuple** identifies a cookie by name/domain/path; two same-name cookies can coexist. A **selector** says which one the journey wants. For example, setting the required cookie on hop 1 and requiring it at hop 2 checks that the browser carried state between redirects, rather than accepting a direct visit to the final URL. See [browser and HTTP terms](authentication-test-lab-terms.md#http-browsers-and-certificates) for cookie attributes and origin/site differences.

Use opaque per-case transaction state and an issuance created only at the completed final stage. The server stores the intended return path and checkpoint sequence; clients cannot skip them by changing URL parameters. `json` selects bearer/JSON; `cookie-one` selects C1; `cookie-two` sets both cookies and verifies selected C2 (complete multi-output publication remains separately gated). `two-page` accepts username, then password in a second form. `csrf-cookie` requires both a hidden random CSRF value and its matching case cookie. `javascript` submits via fetch to the same login endpoint; `interstitial` requires a final consent button. Invalid credentials yield the explicit rejection above.

Redirect defaults: zero hops completes locally; one uses a 302 to finish; multi uses three 302 hops. `cookie-each-hop` uses three hops, setting `LAB_H0`, `LAB_H1`, `LAB_H2` at the corresponding origin before the next hop; finish requires the full ledger. Each is host-only, HttpOnly, case-root Path, SameSite=Lax, Secure on HTTPS. Cross-origin uses separate loopback ports; cross-site cookie cases use the named HTTPS origins. `deep-link` finishes at `/cases/{id}/protected/b?view=details`, preserving that path. `post-303` requires the next request to be GET with no submitted body; `post-307` requires POST with identical body. Failure variants remove the named callback/state, substitute a wrong return, create a repeating hop, close the next hop's listener, or cancel at its checkpoint. None reaches unconditional credential issuance.

Cookie rule variants each change one property: host-only omits Domain; domain uses `authlab.test`; path uses `/cases/{id}/protected`; Secure-positive uses HTTPS, Secure-negative sends the Secure cookie over HTTP; HttpOnly forbids document access while browser-cookie extraction still works. Lax uses cross-site top-level GET; Strict-negative uses cross-site navigation; None-positive uses Secure and cross-site POST; None-negative omits Secure and expects rejection/absence. Applicable platform cookie policy remains an observed prerequisite, never bypassed through permissive browser flags.

Selection cases: an IdP/client decoy uses the same name on distinct declared origins; rotation sets a new value for the same tuple; same-name paths use `/` and the case root; same-name domains use host-only and parent-domain forms; deletion uses Max-Age=0 before extraction; ambiguity leaves two selector-applicable tuples without an explicit disambiguator. Every case declares its intended tuple, final value/role and accepting route. Do not derive the expected selected value from the production extractor.

### Browser surface and fresh-state recipes

These specify the existing seven BROW.surfaces and four BROW.fresh entries; they add no groups or requirements. Each surface case first completes the ordinary fixture form login through the real runner. The target retains the actual authenticated account/issuance. The extractor matches only the selected surface response, so the earlier login response cannot satisfy it.

Use app origin A=`http://127.0.0.1:appPort` and, for the CORS case, a second origin R=`http://127.0.0.1:apiPort`; they are distinct origins, not distinct sites. All paths below are under `/cases/{id}`. Unless stated otherwise, selected JSON is `{data:{access_token:B}}` from the case's actual issuance, the selector is `data.access_token`, and the proof is a real GET to `/protected/b` with the extracted B, expecting its actual account/issuance. No second Playwright login engine is used. The template/fixture script implements the page actions; saved journey steps invoke them through the production runner.

| Variant | Route/action and checkpoint order | Selected response and expected result |
| --- | --- | --- |
| early-response | Navigate `/surface/early`; inline script fetches `/surface/token?kind=early` before adding `#ready`. Record `token-emitted` before `ready`. Final journey step waits for `#ready`. | Exact early token URL; the already-armed response listener captures it before the final step. Protected access succeeds. |
| late-response | Navigate `/surface/late`; wait `#ready`; click `#fetch-token`. Token handler records `late-token-requested` and holds at `late-token`. Driver releases it while the production runner waits for output after its last action. | `/surface/token?kind=late`; valid token after the last action but within the cycle deadline, then protected access. Missing runner wait/surface support is a prerequisite failure, not a test-script substitute. |
| nested-json | Click `#fetch-token` at `/surface/nested`. | `/surface/token?kind=nested` returns `{result:{authentication:{access_token:B}}}`; selector is `result.authentication.access_token`; protected access succeeds. |
| popup | At `/surface/popup-parent`, click `#open-popup`, which opens same-origin `/surface/popup-child`. Child fetches its token, then sends a completion message to the exact parent origin; parent exposes `#done`. | `/surface/token?kind=popup`; production context listeners observe the popup response; protected access and popup/page cleanup succeed. |
| frame | At `/surface/frame-parent`, click `#load-frame`; insert `iframe#auth-frame` with same-origin `/surface/frame-child`. Child fetches token and notifies the exact parent origin; parent exposes `#done`. | `/surface/token?kind=frame`; production listener observes frame response; protected access succeeds. |
| cors-fetch | At `/surface/cors`, click `#fetch-token`; fetch R's `/surface/token?kind=cors` with GET and credentials=include. Also request R's harmless `/surface/cors-denied` probe. Wait for positive `#cors-done` and negative-probe `#cors-denied`. | Positive token URL returns exact Access-Control-Allow-Origin=A, Access-Control-Allow-Credentials=true and Vary=Origin. GET is a simple request, no custom headers. The probe omits permission headers and returns no credential; page JavaScript must report its CORS denial. Extract/prove the positive token only. Do not claim CORS makes network responses invisible to browser instrumentation. |
| service-worker | Register `/sw.js` with scope `/surface/sw/`; wait for activation and control of `/surface/sw/page`. Click `#fetch-token` there. Worker handles `/surface/sw/token` by fetching `/surface/token?kind=worker` with credentials=include and returning that JSON. | Match the page-visible `/surface/sw/token` response, not an unrelated network request. Production extraction and protected use succeed. Require the browser's loopback secure-context/worker support; do not disable browser security to manufacture support. |

Parent/child messages accept only the expected origin/source and fixed completion value. Normal application observation routes record page-stage events without exposing the run-control key; they cannot arm/reset/release controls. Driver gates use the independent private listener. Every response matcher includes this case path/generation's private runtime association; another case cannot satisfy its output. If the production runner cannot observe the selected popup/frame/worker response, report that specific unsupported/missing capability rather than silently changing the extraction target.

For each BROW.fresh variant, use two sequential actual attempts of the same saved journey, with the same definition/revision, case and origin. Its entry is `/cases/{caseId}/fresh/{kind}/start`, where kind is `cookies`, `local-storage`, `session-storage` or `service-worker`. The application selects the prime/probe route from the private phase and returns a 302 redirect to that case's corresponding route in the table below. UNARMED entry is 409 STATE_CONFLICT. Browser state never determines this dispatch. Repeated navigation/reloads remain in the selected phase; a GET never advances it. A direct prime-route request in PROBE, or probe-route request in PRIME, is rejected before any state write.

Both attempts perform these unchanged saved actions: navigate to the common start URL; wait for `#fresh-check-complete`; fill `#user` and `#pass`; click `#login`; wait for `#login-complete`. The prime/probe pages expose the same form after their state observation is acknowledged. Use the ordinary case login/output/protected endpoint contract. A and B each verify their new output's identity there. The driver verifies that the saved definition/revision is unchanged across attempts.

PRIME performs the variant's storage/readback operation and records a positive `fresh-prime-observed` event before exposing `#fresh-check-complete`. Repeated PRIME visits reuse the case's marker and remain idempotent. PROBE first reads the tested browser state, records `fresh-probe-observed` with the observed present/absent outcome, and only then exposes `#fresh-check-complete` and the form. It writes none of the tested state and performs no login before that observation; a leak is reported as present, never normalized to absent. A completed observation marker means observation finished, not that the test passed.

The existing case/generation-bound safe event ledger records these observations in LOGIN phase, with `safeIds` containing nonsecret variant, PRIME/PROBE phase and present/absent labels. It contains no raw marker values. B's probe sequence precedes its login/output issuance. The owning production integration test joins these fixture facts to actual context creation/closure observations. The driver requires A's positive witness, distinct real context IDs, A's closure, B's absence observation before login, and protected identity for both new outputs.

All table routes below are relative to `/cases/{caseId}` and use the common observation-completion/form sequence above.

| Variant | Prime witness in A | Probe witness in B |
| --- | --- | --- |
| cookies | `/fresh/cookies/prime` sets HttpOnly LAB_FRESH_MARK at the case path; a following request confirms its presence. | First `/fresh/cookies/probe` request has no marker cookie; record actual request observation and `#fresh-absent`. |
| local-storage | `/fresh/local-storage/prime` writes a nonce under `authlab.fresh` and reads it back, showing `#fresh-present`. | `/fresh/local-storage/probe` reads before any write; value is null and page shows `#fresh-absent`. |
| session-storage | Same sequence using sessionStorage on the same page context in A. | New attempt sees null before writing. This alone does not prove a new BrowserContext, because a new page can have fresh sessionStorage; require the separate context-creation evidence too. |
| service-worker | Register the case-scoped worker, wait for control and confirm its exact scope via getRegistrations. | Probe registration/control before registering or unregistering anything; no registration for that scope and no controller. Check fresh context IDs; cleanup retires only owned state. |

Each requirement has one owner. Its existing owning execution records these observations; no cross-test evidence dependency is implied. The safe page outcome markers contain no raw tokens. Browser/fixture contract checks verify that the prime stages actually stored the state, so an always-empty probe cannot pass. Missing required surface/observation support stays visible as BLOCKED. Current source bindings select actual callable production definitions and witnesses.

## 4. Canonical fixture ownership

`ControlledApplication`, `LoginFlows` and `LabRun` own the shared purpose-specific servers. Native integration facades delegate common serving/lifecycle behavior to those implementations and retain only test-specific callbacks. `TransportFixtures` owns shared unauthenticated HTTP/CONNECT and mTLS mechanics. Keep one maintained implementation for each responsibility.

Reuse existing assertions and current source bindings before adding tests. The standalone fixture module must remain independent of production runtime, Python, Docker and Burp. Production acceptance overlays run only in isolated captures; configured upstream authentication stays outside the selected product scope.

## 5. Federation seed, session binding and negative controls

**Federation** means a login crossing application and identity-provider boundaries. In this proposal, Keycloak is the **identity provider (IdP)**, the application starting login is the **client**, and the API accepting its access token is the **resource server**. **Seed** means the initial users/clients/settings loaded for the test. **Positive controls** are known-valid cases that must succeed; **negative controls** are deliberately invalid cases that must be rejected. Both are needed: rejecting every message is not a passing implementation. See [OAuth/OIDC definitions](authentication-test-lab-terms.md#oauth-oidc-and-federation) and [SAML message definitions](authentication-test-lab-terms.md#saml-message-testing).

### Topology and settings

**Topology** is the arrangement of cooperating applications, addresses and connections. A **realm** is an isolated Keycloak configuration with its own users and clients. **Audience** identifies the intended recipient of a token; **subject** identifies its user/entity; **issuer** identifies who issued it. A **SPA** is a single-page application running client code in the browser. **PKCE** links code exchange to the client instance that began authorization, using a secret verifier and its derived challenge; **S256** uses SHA-256 for that derivation. These terms describe the selected protocol settings below, not additional user-configurable features.

The run resolves a port tuple before launch: client A, resource R, downstream D and optional upstream U. Hostnames stay `app.authlab.test`, `api.authlab.test`, `idp.federation.test`, `idp.upstream-sso.test`; HTTPS ports match internal and published provider ports. Lease from local ports 40000–49999 with an exclusive run record; a bind failure aborts that allocation and never attaches to an existing service. All published ports bind loopback; provider DNS aliases match inside the owned Docker network. Run Doctor's host/browser-trust probes before positive HTTPS cases.

Realm names: `authlab-downstream` and `authlab-upstream`. Downstream issuer is `https://idp.federation.test:D/realms/authlab-downstream`; upstream is analogous on U. Seed the three fixture users with explicit distinct IDs in each isolated realm. Client IDs are `browser-client` (public S256 PKCE), `backend-client` (confidential), `cookie-verifier` (public S256), `wrong-client-control` (confidential S256 control client), `wrong-audience-client` (confidential S256 control client), `authlab-api` (resource audience), and the SAML SP entity ID `https://app.authlab.test:A/saml/metadata`. Secrets are generated into private environment state, never source files.

Browser routes are `/spa`, `/spa/callback`, `POST /session`, `GET /me`, `GET /combined`; backend routes are `/oauth2/authorization/backend` and `/login/oauth2/code/backend`; SAML routes are `/saml2/authenticate/keycloak`, `/login/saml2/sso/keycloak`, `/saml2/metadata/keycloak`; resource route is `/api/me`. Register only those exact callback/origin URLs. Configure the access-token audience as `authlab-api`; the wrong-audience control maps only `authlab-other-api`. The resource validates signature, issuer, expiry and audience, and rejects non-access-token substitutions.

Use access-token lifetime 120 seconds, authorization-code lifetime 30 seconds and IdP SSO idle/max 600 seconds for seeded cases. Client sessions have a 90-second idle limit. Client `LAB_CLIENT` and transaction-session cookies are HttpOnly, Secure, SameSite=None, host-only, Path=/; this supports the real SAML cross-site POST callback without a permissive trust/browser override. Provider-cookie attributes are provider-owned and observed, not silently rewritten. Qualify the single selected IdP cookie exactly as the existing design requires; lack of single-cookie support remains BLOCKED.

For SPA combined access, `/session` validates the obtained access token and stores its subject, provider session identifier when supplied, and SHA-256 of its exact token bytes against a new random client session ID. `/combined` requires that client cookie and the exact validated bearer associated with it. Matching subject alone is insufficient. A different valid token from a second login of the same account fails the combined binding. `/me` proves the cookie's client identity; `/api/me` proves the bearer; `/combined` proves their exact issuance association. No endpoint exposes backend-only tokens.

**Concrete example of credential binding:** login 1 creates client cookie A from bearer X. Cookie A + bearer X succeeds at `/combined`; cookie A + bearer Y from login 2 fails, even when both logins identify user. This is a chosen rule of this test application. A **test binding** instead connects a requirement to a test method; it is a different use of the same word.

Broker alias is `upstream-saml`. Pre-create the upstream/downstream fixture accounts and explicit federated-identity links to their upstream IDs. Ordinary broker cases require those links and disable unexpected registration/consent; an unexpected first-login interaction fails that case rather than being auto-clicked away. The combined-output case uses downstream browser-client OIDC through upstream SAML. It proves actual provider redirects and cookies; the ordinary production attempt still starts with fresh browser state.

### Extension-facing failure control

Use one case-private immediate backend rejection to establish extension failure behavior. The maintained backend client performs ordinary real authorization, but its case-scoped token URI points to the owned HTTPS route `POST /cases/{id}/oauth/token-error`. That route returns the fixed simulated expired-code response immediately. This is an input fixture, not a test of provider expiry or protocol enforcement. There is no expiry sleep.

The valid comparison must first yield an extension-captured cookie that actually accesses the client as the expected identity. For the controlled rejection, the extension must publish no cookie, preserve the available extraction failure, avoid a misleading connection error, and close its resources. The backend error page may identify its known simulated cause; the extension must not invent that cause when its approved observation is only the missing cookie. A bounded private `before-token-exchange` checkpoint coordinates the driver and retires on Stop/reset.

Do not implement a provider/client protocol regression suite for state, verifier, callback, client binding, code reuse, token kind or resource audience. Do not build or alter signed SAML responses to test Spring/OpenSAML signature, time, recipient or replay validation. The out-of-scope `FED.negative` and `FED.saml` entries are explicit exclusions. Only the active case definitions establish acceptance obligations.

Real SAML acceptance uses an actual Keycloak login through the production runner, then proves that the captured client cookie accesses the expected identity. The real flow must be identified as SAML, so an accidental OAuth fallback cannot pass. Maintained validation stays enabled; its implementation is not retested here.

Generated registrations, provider configuration, client secrets and keys live under owned build/environment directories. A prepared lab CA is explicitly trusted once in the user's test environment; per-run leaf material is signed by it. Ordinary run/reset does not install trust or delete that prepared CA. Explicit preparation/removal instructions retain the existing Windows and fingerprint checks. Schema/seed rendering validates all required topology values and forbids wildcard redirects or unresolved placeholders before startup.

## 6. Verification commands and marker behavior

Run verification commands from the repository root using `.\bapp\gradlew.bat -p bapp`.

Recovery assertions require three total attempts and the current pause policy. Reuse shared-caller, admission and cancellation owners; add only verified missing policy assertions.

The self-traffic marker is a short-lived, attempt-owned User-Agent suffix used on explicitly proxied authentication traffic. Its early guard recognizes owned traffic before acquisition, prevents recursion, strips its carrier as specified, excludes correlated responses from recovery and preserves ordinary interception. Native-tag handling and stale/unknown markers follow the current [self-traffic policy](bapp-owned-authentication.md#self-traffic-policy). Detailed guard/carrier combinations stay below Burp.

The documentation artifact set comprises the [main design](authentication-test-lab.md), [case matrix](authentication-test-lab-cases.md), this contract and the [terms companion](authentication-test-lab-terms.md). These are excluded from runtime packaging. Implementation follows the main design's stage gates and source-file boundary.
