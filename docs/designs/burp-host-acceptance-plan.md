# Real Burp acceptance implementation plan

Status: EGM review concluded after authorized readiness repairs. Runner tests and
GUI primitive qualification pass on both VMs. Complete scenario acceptance is
pending resolution of browser startup and HTTP-only Test login failures.

## Objective and execution policy

Add a small, repeatable suite that loads the delivered extension into the installed
Burp, sends traffic through genuine Burp tools, and proves the receiving lab's
account, protocol and request counts. Run it before releases, after Burp upgrades,
and after changes to callback wiring, listener matching, authentication delivery,
replay or unload. Keep it explicit and separate from ordinary `check`; do not
repeat the full component/browser matrix inside Burp.

The first delivery must run unattended on both existing VMs. After documented
one-time VM and installed-Burp provisioning, one explicit invocation must perform
run setup, every required GUI action, scenario dispatch, evidence validation and
cleanup. It must not wait for manual clicks or conversational-agent intervention.

Follow the root [repository instructions](../../AGENTS.md). The current
[URL/listener feature](session-handling-by-url-and-proxy-port.md) is implemented;
its final platform qualification is separate from implementing this runner.
Coordinate with the feature owner before changing shared production files.

## Existing owners to reuse

| Owner | Reuse |
| --- | --- |
| `test/authentication-lab/src/main/java/lab/auth/LabMain.java` and `LabRun.java` | Owned serving run, current targets/generations, private controls, typed faults, snapshots and cleanup. |
| `ControlledApplication`, `LoginFlows`, `HttpAuthenticationFixture` | Real login pages and protected account/protocol/request evidence. Do not create another test server or authentication implementation. |
| Existing journey example exporter and `JourneyJson` | Valid journey exports derived from the active target inventory. Keep credential injection and authentication entirely in production. |
| `test/authentication-lab/src/hostProbe` and `Build-HostProbe.ps1` | Existing explicit Extensions-origin send and passive callback observations. Extend the same helper only where an observation is missing. |
| `src/main/resources/catalog/burp.json` | Existing manual host requirements and their expected observations. Map new automation to the applicable requirements instead of creating duplicate claims. |
| Existing lab Gradle/evidence collectors | Source identity, artifact checksum, invocation ownership, outcome and cleanup reporting. Preserve separate component/browser/host evidence. |
| VM helpers documented in `AGENTS.md` | Transfer, checksum checks, installed Burp and owned guest process management. Never log private credentials or keys. |

The disposable `bapp/build/reports/session-routing/manual-matrix.py` demonstrates
five client requests through Proxy. It is not a maintained entry point: its URL,
case generation and ports are hardcoded. Replace its reusable behavior with a
lab-owned runner. Do not commit or depend on that generated file or its old run.

## Architecture

1. A host orchestrator owns one invocation covering both VMs: installed Burp
   identity, exact product/helper JAR hashes, lab run, project and processes.
   Keep the maintained scenario/check logic in the existing Java lab. Thin
   platform launch/transfer scripts are developer tools, not product code.
2. Start the existing lab and obtain current public targets and case generations
   from its owned inventory. Generate native journey exports with synthetic
   accounts. Select available loopback listener ports and validate actual bound
   sockets; never assume 8080/8081/8082 or reuse stale run URLs.
3. Use Burp configuration files for supported setup. A maintained GUI adapter,
   executed by the runner, performs import/configuration and genuine tool actions
   that cannot be configured programmatically. Never add test-only control
   endpoints, bypass switches or reflection hooks to the product.
4. A normal HTTP client sends the Proxy cases through the actual listening
   sockets, with loopback proxy bypass disabled. It does not fetch credentials,
   preauthenticate requests or execute journey steps itself.
5. Genuine Repeater sends, intercepted-request edits and Loaded off/on actions
   use the UI through that adapter. The helper's Montoya `sendRequest` is Extensions-origin traffic;
   it must never be reported as Repeater, Intruder or Proxy traffic. Passive
   observations verify the actual family/tool/listener and response phases.
6. The accepting lab supplies independent account/protocol/issuance observations
   and counter deltas. A 200, a product success message or a screenshot alone
   cannot establish an authentication pass.

Establish and qualify the GUI adapter on each VM as part of the first delivery.
Its checked-in automation must identify the intended windows and controls, wait
for observed UI state within finite deadlines, and fail with diagnostic evidence
when an action cannot complete. Missing automation, a required manual action or
conversational-agent intervention makes the run incomplete and blocks acceptance;
an assisted run cannot substitute for this requirement. Do not automate OS
authentication dialogs or weaken browser sandboxing. Acceptance execution must
not change system security settings. The approved Linux VM baseline includes a
reviewed AppArmor profile permitting sandbox user namespaces for the verified
bundled Chromium. Install it only as one-time provisioning outside an acceptance
invocation: scope the attachment to the configured verification root, an owned
run leaf, the pinned bundle digest and exact browser executable. Record its
approved hash, syntax check and loaded-profile proof; keep AppArmor and global
namespace restrictions enabled. A browser-bundle update requires renewed profile
review. Test runs never load profiles or change sysctls. Document interactive
desktop and installed-Burp prerequisites alongside this Linux policy baseline,
then verify them before each run.

## Alternatives considered

| Approach | Decision and trade-off |
| --- | --- |
| Continue structured manual checks only | Useful for investigation, but not sufficient as the maintained suite: setup, request counting and evidence joins would remain operator-dependent and difficult to repeat consistently. |
| Build a separate host-testing harness | Keeps host tooling separate, but would duplicate scenario definitions, fixture lifecycle and evidence validation already owned by the Java lab. Keep only platform launch, transfer and GUI operations outside that lab. |
| Put scenario logic in the existing Java lab | Chosen: one owner generates current targets and validates independent observations. Maintained platform GUI adapters perform actual Burp setup and genuine tool actions under the same invocation. |
| Deliver assisted execution before unattended GUI automation | Rejected: manual clicks or conversational-agent intervention would prevent repeatable unattended acceptance. GUI automation on both VMs is required in the first delivery, accepting the cost of adapter implementation, UI-state diagnostics and maintenance across Burp upgrades. |

The chosen split reduces duplicated test logic, but still requires platform-specific
GUI maintenance and installed-Burp qualification. Configuration files cover
supported setup; GUI actions cover the remaining real tool and lifecycle boundaries.

## Detailed implementation plan

### 1. Entry points and process ownership

The acceptance command is:

```powershell
.\bapp\gradlew.bat -p bapp authLabHostTest '-PhostVmConfig=test/authentication-lab/build/host-runtime/host-vms.json' --offline
```

`authLabHostTest` depends on `check`, `verifyNativeDocumentation`, `jar`, the
existing captured-production preparation and the lab helper build. It is never
a dependency of ordinary `check`. It runs Windows and Linux concurrently from
one captured build under one root invocation ID. Each job owns a separate guest
root, process lifecycle and platform report; one platform's failure must not
cancel the other. Retain each platform outcome immediately, then aggregate in
the fixed Windows/Linux order. A run cancellation stops both jobs. It cannot
accept a platform filter. A separate
`authLabHostQualify` task accepts `-PhostPlatform=windows|linux|both` (default
both), produces `QUALIFICATION_ONLY` evidence, and cannot satisfy catalog rows.
Both entry tasks are implemented; full scenario execution and catalog acceptance remain pending.
The configuration path is resolved from the repository root. The documented
file is a local ignored setup file containing helper/install paths, not passwords;
create it during one-time VM provisioning. It is not an alternative VM location.

Add `host-test`, `host-qualify` and `host-guest` to `LabMain`. The first two take
exactly `--workspace`, `--report-directory`, `--artifact`, `--vm-config` and
`--plan`; qualification additionally permits `--platform` and `--stage`. `host-guest` takes
exactly `--plan` and `--report-directory`. Reject unknown, duplicate or missing
arguments before starting a process. Exit 0 means all required work and cleanup
completed; 2 means invalid input; 3 means failed, blocked, interrupted or
incomplete execution. A Gradle failure must still retain the terminal report.

#### Closed plans and scenario inventory

Extract the existing duplicate-key-rejecting `ScenarioCatalog.parseJson` algorithm
into public `LabJson`; retain ScenarioCatalog's exception-compatible delegate.
Both the lab and helper use that single parser, with no catalog/auth engine in
the helper. `LabJson` also owns bounded reads, strict object/type helpers and
streamed SHA-256/file-length verification.
Every object below rejects unknown and missing fields, including nullable fields;
versions must equal 1, hashes are 64 lowercase hex characters, UUIDs are canonical,
byte counts are positive integers, and arrays reject duplicate identities. Read
plans at most 1 MiB and the maintained scenario inventory at most 64 KiB.

Gradle writes the invocation plan; `LabHostInputs` validates it before the
coordinator starts. Its exact fields are `version`, `invocationId`, `mode`
(`ACCEPTANCE|QUALIFICATION`), `platforms`, `taskPath`, `configurationHash`,
`catalogRevision`, `sourceRevision` (captured boundary hash), `head` (Git commit),
`sourceHashes` (repository-relative path to hash), `audit`, `product`, `helper`,
`runtime`, `scenarios`, and `captureDirectory`. `platforms` is an ordered nonempty
subset of `[windows,linux]`, always both for acceptance. The task path must match
the mode. `audit`, `product`, `helper` and `scenarios` each have exactly `path`,
`sha256`, `bytes`; these are existing absolute files inside the fresh captured
directory. `runtime` is a nonempty array with the same fields plus `role`
(`LAB|EXPORTER`); a file may occur in both roles but not twice in one role.
LAB entries form the guest lab classpath; EXPORTER entries form the already
compiled captured example-exporter classpath. The audit must bind the declared
source boundary/hash inventory. The product must match the root task's freshly
built development JAR, rather than merely another JAR with the same filename.

The coordinator produces one guest plan per selected platform. Its exact fields
are `version`, `invocationId`, `mode`, `platform`, `runNonce` (UUID), `taskPath`,
`configurationHash`, `catalogRevision`, `sourceRevision`, `head`, `audit`,
`product`, `helper`, `runtime`, `scenarios`, `guestRoot`, `java`, `burpJar`,
`labJava`, `approvedPreferences`, `display` (null on Windows), and `stage`
(`PRIMITIVES|SCENARIOS`). Artifact objects keep their hashes/lengths and use only
relative paths beneath this invocation's guest root. Guest installation and
approved-preferences paths are absolute; they are prerequisite inputs, never
cleanup targets. The coordinator copies the approved preference subset to the
private root before launch; it never copies guest credentials or VM encryption
material. `host-guest --report-directory` must resolve to this root's `report`
child. The helper path and all host-only private configuration remain on the
host. Qualification may select either stage; acceptance always uses SCENARIOS.
`-PhostStage=primitives|scenarios` is allowed only on `authLabHostQualify`.

`host-scenarios.json` has exactly `version`, `platforms`, `scenarios` and
`requirements`. `platforms` is exactly `[windows,linux]`. `scenarios` is exactly
the ordered array `routing,tags,repeater,http-auth,recovery,rejected-replay,
intercept,unload,ordinary-failure`. Each requirements row has exactly `id`,
`scenarios` (nonempty distinct scenario IDs), and `protocol` (null, BASIC,
NTLM_V1 or NTLM_V2). The twelve IDs and their complete mapping below are the
allowlist, not arbitrary executable commands. Preserve this order in reports.
The scenario inventory hash joins plans, platform reports and catalog bindings.

`LabHostCoordinator` runs on the Windows development host. It captures the
already-built development JAR, helper JAR and lab runtime into a fresh ignored
invocation directory, checks both source and captured checksums, and transfers
those exact bytes. Capturing bytes for evidence is not a candidate build. The
guest verifies SHA-256 before launch and after testing. Changes to the workspace
after capture do not silently change the artifact being qualified.
To avoid repeated large uploads during GUI qualification, each dedicated guest
root may keep `.artifact-cache/product.jar` and `large-runtime.jar`, with an
owned version-1 marker. These two fixed slots hold current bytes and are replaced
on a size/hash mismatch. Before reuse, verify the newly captured local source,
cached size/SHA-256 and copied destination SHA-256. A miss uploads the current
capture directly into that slot, then rechecks it. Each invocation still receives
its own deployed copies and verifies them before launch and after testing.
Reject unowned caches and symlink/reparse-point slots. Reuse of artifact bytes
never reuses a report or qualification result. Setup may seed these slots from
an owned transferred capture only after the same independent size/hash checks.

`LabHostGuest` runs in each VM, using its installed Java 21-or-newer runtime.
It starts an in-process `LabRun` with browser and HTTP-auth fixture selections,
and launches one owned installed Burp JVM. Thus browser, lab, client and Burp
listeners are all guest-local; no private control endpoint is exposed to the
host network. Its scenario engine calls the existing `CaseLease` controls
directly. The coordinator transfers commands and retrieves files through the
existing VM helpers; it never runs journey steps or authenticates a request.

The private VM configuration is a closed version-1 JSON object with `windows`
and `linux` objects. Each has `helper`, `guestRoot`, `java`, `labJava`, `burpJar` and
`approvedPreferences` paths; Linux also has `display`. Paths identify existing
guest tooling/installations, not downloadable installers. `helper` must resolve
to the existing documented guest helper for that VM. Credential values are not
configuration fields. The helper retains ownership of its existing credentials.
`java` is Burp's installed bundled runtime. `labJava` is a full Java 21-or-newer
runtime with `jdk.httpserver`, used only for the existing lab and native exporter.
Burp's trimmed bundled runtime lacks that module and must not host the fixture.
Linux uses its installed full Java; the Windows fixture provisions a portable
Temurin 21 JDK under its private developer setup directory, checks the official
package SHA-256 and verifies `jdk.httpserver`. No global Java setting changes.
The guest root must be an absolute dedicated test directory, never a filesystem
root, home directory, installed-Burp directory or published browser cache.

Each guest creates a new invocation child directory, project, home, preferences,
and data. Windows temp stays inside that child. Linux uses a fresh private
`/tmp/bpsh-<13 hex characters>` directory, at most 23 characters, for JVM and
browser temporary files: Chromium's Unix-domain sockets cannot use the deeply
nested invocation path. Before allocation, publish a strict private
`linux-temp-owner.json` inside the invocation root; an exclusive matching marker
in the short directory binds its allocation, run, guest PID/start time and uid.
Never reuse an existing directory. Select three available loopback Proxy ports, then prove
the ports are actually bound by the owned Burp PID before dispatch. A race to
bind is a failed attempt, not permission to connect to an unknown listener.
Windows uses a bounded numeric `netstat -ano -p tcp` observation in memory,
checking the exact live PID/start identity throughout its ten-second query.
Only exact loopback LISTENING rows qualify; wildcard listeners do not. Timeout,
nonzero exit, malformed and oversized output have distinct fixed diagnostics;
raw network tables are never retained.
Use a 2 GiB maximum Burp heap on both Linux and Windows; record actual VM memory
and JVM settings. This budget leaves room for native/UI/browser overhead in the
existing guests. Qualify the universal JAR through five unload/reload cycles at
this heap and retain complete RSS and GC observations. Never terminate an
unrelated Burp session or change VM settings to make
the test pass. Detect an owned Burp exit immediately and retain joined exit-code
evidence rather than waiting for a missing GUI receipt.
Optional private heap diagnosis may observe natural-GC management notifications
with a 4096-event/1 MiB journal of fixed categories and numeric aggregate heap
use before and after collection. It must not force collection, walk objects,
dump the heap or change the bundled JVM. A major-GC notification does not itself
prove full compaction or an object-retention cause. These observations and
allowlisted JDK allocation stack identifiers never establish an acceptance pass.
Private diagnosis may additionally summarize large-object sizes/counts from the
existing bounded GC log, omitting region addresses, and sample loader stacks only
after natural collections leave at least 1 GiB used. Stack samples are bounded
to 32 records/256 KiB, four threads and four safe class/method identifiers each;
they contain no thread names, source files, values or messages. Collector-local
and native-log GC IDs must not be treated as the same namespace. Neither journal
changes normalized memory evidence or proves object ownership.
Report startup, browser initialization, each measured case and cleanup durations
separately. No timing or memory guarantee is inferred from a warmed request.
For browser initialization, retain a separate externally observed cold first-page
interval: client dispatch to the canonical login page's response start. This
includes admission, browser preparation/launch, first local navigation and fixture
rendering; it excludes response delivery and DOM readiness and is not engine CPU
time. Two host-only form URL aliases bind the cold A/B requests to unique safe
fixture events and later account/issuance proof. Silent resource prewarming before
dispatch is outside this boundary. Do not present this interval as a pure engine
startup measurement.

Process ownership records contain PID, executable, process start time, invocation
nonce and parent relationship. Before terminating a process, recheck this tuple;
PID reuse or an unknown child makes cleanup incomplete. Cancellation creates a
private cancellation marker, stops new actions, releases owned held gates and
runs teardown in `finally`. Budgets are 180 seconds for Burp startup, 30 seconds
per GUI operation, 60 seconds per request, 180 seconds per scenario and 60 seconds
for teardown; total budget is 45 minutes per platform. On timeout, do not repeat
a possibly completed send. First attempt failures remain failures.
After downloading and verifying public evidence and optional private failure
diagnostics, the coordinator removes only that invocation's private guest root.
It checks the exact parent/name, original owner and started-process identities,
requires the guest process to have exited, rejects links/reparse points and bounds
tree enumeration. A root-owned `cleanup.json` records the joined session identity,
guest PID/start time, `rootRemoved` and `COMPLETE|INCOMPLETE`. Missing ownership,
live processes, unsupported entries or deletion failure leave cleanup incomplete.
Linux cleanup validates both ownership markers and removes the short temporary
tree before the invocation root, including coordinator recovery after the guest
runner exits. Refuse links, hard-linked files, changed ownership, reused/live
process identities and ambiguous partial allocation. Preserve the invocation
descriptor on failure; an external tree left behind cannot yield COMPLETE.
It also retains the measured monotonic cleanup `durationMs`; report timings must
use that observation rather than an invented zero.
The provisioned Linux adapter uses `/usr/bin/python3` only for this developer
cleanup helper; it is not part of the extension runtime.
Large immutable artifact transfers have a separate maximum of ten minutes each,
counted inside that same platform deadline. Ordinary helper/control operations
remain bounded to sixty seconds or less. A universal JAR must not inherit the
short request/control timeout during VM transfer.
Retain each platform summary immediately, including failure before the other
platform completes. Persist the private root/nonce ownership descriptor before
the first VM mutation. A missing terminal receipt triggers a bounded read-only
process-status query against PID, start time, executable and run marker; an
exited owner cannot leave the coordinator polling for the full suite deadline.
Windows uses a hidden CIM query when JDK ProcessHandle omits command arguments.
Process status reports OS liveness separately from ownership: `VERIFIED`,
`UNVERIFIED`, `CHANGED` or `EXITED`. Missing/partial argument metadata may use a
positive CIM marker check; unavailable proof must never turn a live PID into a
reported exit. A changed start/executable identity fails closed. After an actual
exit, make one final validated completion/evidence fetch before reporting that
the guest exited without a result.

### 2. Concrete unattended GUI adapter

Use one test-only JDK Swing/AWT adapter on both platforms. Launch the installed
vendor JAR normally with `java -javaagent:<helper>=<owned-root> -jar <burpJar>`.
Do not call `burp.StartBurp.main()` from a wrapper: that bypasses the vendor
manifest startup attributes and can prevent tools from initializing. The agent's
`premain` starts the GUI worker and retains public JDK Instrumentation solely
for optional private library-origin diagnostics. A fixed list of public
third-party class names may be matched against already loaded classes; inspect
only public classloader/code-source metadata and, for one positively identified
product Playwright loader, its already initiated classes. Emit bounded counts
and HOST/HELPER/PRODUCT/OTHER/UNAVAILABLE categories, never code-source paths.
Do not load or initialize classes for this diagnostic, inspect product internals
or use it as authentication evidence. The agent registers no transformer and performs
no class redefinition, private reflection or product method calls.

The same helper is loaded as a normal Montoya probe extension. Reuse its public
`suiteFrame()` and passive observers. All tree inspection runs on the Swing EDT;
actual state-changing actions use `java.awt.Robot` mouse/key input. Do not use
`doClick`, `setText`, table-model changes or direct extension actions. Resolve
controls from public component/accessibility roles, visible labels, tab titles,
table headers and ancestor context. Require one match, check showing/enabled,
focus the owned window, act once, then locate the resulting state afresh. Never
use obfuscated Burp class names, fixed screen coordinates or stale UI objects.
Geometry obtained from the currently matched control is allowed for a real click.
Verify that each pointer target is unobscured using the public mouse-position API;
Java focus state alone cannot establish native foreground ownership. Make one
public exposure request for normal targets even when Java reports focused. For a
still-obscured normal target, allow at most one verified exposed title-bar activation
gesture, with a bounded inset-based search excluding resize edges and window
controls. Recompute and revalidate the target afterward. An obscured popup or
unavailable safe activation point fails rather than clicking another application.
Recheck deadline/cancellation before each new gesture, wheel event or key press;
release already pressed input during cleanup.

Initial qualification targets the installed English Burp Community 2026.10.1
with bundled Java 26.0.2 on Windows 11 and Ubuntu 24.04 x64. A version change must
pass qualification before acceptance. Do not introduce AssertJ Swing: its current
release depends on `java.applet`, which is absent from this bundled JVM. Do not
add module opens to make a GUI library work. The vendor's own manifest remains
in force. The feasibility test selected Repeater then Proxy with real input on
both VMs; it has not yet proved the complete primitive set below.

Use the public `java.util.prefs.PreferencesFactory` property and test-only
`HostGuiPreferences` file store for both OSes. `java.util.prefs.userRoot` alone
does not isolate the Windows registry backend. Seed only the already approved
Community/EULA choice from the private provisioned preferences file. No new
agreement, license, global preference or OS setting is accepted or changed.
The preflight checks an awake unlocked interactive desktop, installed Burp/JVM,
approved preferences and sufficient memory. A locked desktop blocks the run.
Linux uses the active logind seat's lock hint when available. This existing VM
also supports its provisioned Openbox Xorg console without a logind desktop
session: require the public EWMH window-manager check and exact Openbox name.
Real focused input and observed tab changes must then qualify that desktop;
an absent seat alone is not evidence that the screen is locked.
One-time authorized VM provisioning is outside acceptance. Never enter an OS
password as part of a scenario or change locking/security policies.

The helper JAR contains the existing host probe, `hostGui` source-set classes
plus only `LabJson` and `LabHostGuiProtocol` from main, and the lab's already
pinned Gson. This is a test artifact, never included in the
production JAR. Its agent manifest disables redefinition and retransformation.
`Build-HostProbe.ps1` delegates to the single Gradle helper-JAR owner rather than
maintaining a second packaging algorithm.

The private GUI file protocol is version-1 closed JSON. Commands carry
`invocationId`, `platform`, `runNonce`, `productSha256`, `helperSha256`, positive
`sequence`, UUID `operationId`, `operation`, `deadlineEpochMs` and `arguments`.
Read at most 64 KB; reject unknown fields, duplicate keys, wrong identities,
out-of-order commands, expired deadlines and path escapes. Atomically claim a
command before input. A duplicate ID returns the retained receipt without input;
an abandoned claimed command is ambiguous and fails without retry. Receipts carry
the same identity and operation, start/end times, `PASS|FAIL|BLOCKED|CANCELLED`,
a fixed diagnostic code and safe observed state. Private channel receipts do not
echo arguments. The guest retains public receipts with the original
`deadlineEpochMs` and a closed `intent` projection: fixed enums, aliases,
synthetic nonces, status codes and booleans. Input paths become `inputSha256`;
secret references become `secretRef` containing only the four fixture-reference
enums. Output paths and secret values are never retained. The collector validates
this projection independently and joins actions and deadlines to each scenario.
The owner allows two seconds after the input deadline solely for a failure
receipt and private screenshot to finish publishing before teardown. Input is
still forbidden after its original deadline; any late PASS remains invalid.
Publish the primary fixed failure before optional screenshots, and bound
diagnostic EDT queries to 250 ms. A diagnostic failure must not replace or suppress
the primary outcome. The owner waits within that same finite grace for the
private diagnostics-complete marker before teardown. Failure images render only
an owned JVM window. Before readiness identifies the suite frame, retain fixed
startup window/control categories and render a unique showing modal dialog or,
otherwise, a unique showing frame. Ambiguity omits the image; never capture a
different application's foreground pixels. Optional public button-model/action
events distinguish pointer delivery from action generation without invoking or
retrying an action. These observations never grant coverage.
The guest writes private `gui-session.json` with exactly `version`,
`invocationId`, `platform`, `runNonce`, `productSha256`, `helperSha256` and
`root` (absolute owned invocation root). The bootstrap receives only that root
as its agent argument and reads this session through `LabHostGuiProtocol`.

Allowed operations and typed arguments are:

| Operation | Arguments and observed completion |
| --- | --- |
| `READY` | No arguments; owned suite frame with Proxy, Repeater and Extensions tabs available, no unknown modal. |
| `IMPORT_JOURNEY` | Relative generated file path and expected alias; use native Import and file chooser, then observe the alias. |
| `ENTER_SECRET` | Alias and fixture secret reference (`FORM_A`, `FORM_B`, `HTTP_A`, `HTTP_B`); type only into the identified secure field. Values come from guest-private fixture data. |
| `EDIT_RULES` | Relative rule-data path; edit the real Automatic handling controls, apply, observe rows and inline validation. Rule data contains only fixture origins, aliases and owned ports. |
| `OPEN_TOOL` | Enum `PROXY|REPEATER|EXTENSIONS`; selected title must match. |
| `COPY_TO_REPEATER` | Validated synthetic request nonce; select its Proxy history row, use Send to Repeater, observe a Repeater request containing that nonce. |
| `SET_REPEATER_REQUEST` | Relative private request-file path and nonce; replace the focused native raw editor through keyboard input and verify only nonce/length, never export its credential bytes. |
| `SET_REPEATER_NONCE` | Distinct previous/current synthetic nonces; preserve the copied request in memory, change only its correlation header/query through real editor input, never export copied credentials. |
| `SEND_REPEATER` | Nonce; click Send once, observe completion and correlate passive callbacks/server facts. |
| `ASSERT_REPEATER_RESPONSE` | Nonce and expected HTTP status; require the native response pane's current synthetic correlation header and status, rejecting an earlier response. Stopped requests do not invoke this operation. |
| `TEST_LOGIN` | Alias; select its real journey page and click Test login once. Wait for its current result, check visible authentication success/failure, observed HTTP protocol and inline errors. Establish the account independently from fresh fixture observations; no private product method calls. |
| `SET_INTERCEPT` | Boolean; observe actual Intercept state. |
| `EDIT_INTERCEPTED_REQUEST` | Nonce and relative private request file; require exactly that pending nonce before replacing editor text. |
| `FORWARD_INTERCEPTED_REQUEST` | Nonce; click Forward once; prove its pending item left and correlate the server. |
| `SET_PRODUCT_LOADED` | Boolean; match the existing product row and the native Item/Detail table's full Filename using normalized native paths. On unload, acknowledge only the exact `Unload extension` question naming Browser Powered Session Handler, observe its closure, then require the checkbox and suite-tab state. Never remove/re-add. |
| `CAPTURE_PROBE` | Phase label enum; flush/reset or export a bounded passive capture to an owned relative output path. |
| `ASSERT_UI` | Alias plus one fixed code (`URL_REGEX_INVALID`, `RECOVERY_PAUSED`, `LOGIN_FAILED`, `ORDINARY_UNCHANGED`). The unchanged-request code also requires its synthetic nonce: select that native Proxy history row and read its visible Notes outcome naming the selected journey. Return only the code/nonce and observed boolean, never note/secret values. |
| `CLOSE` | No arguments; request normal owned Burp closure, with bounded process cleanup by the guest afterward. |

History selection uses the nonce-bound row's read-only Method cell. Reveal an
offscreen row with bounded real wheel input, then recheck its row identity,
column and viewport before clicking. A missing/reordered nonce, unsafe cell or
clipped Method column fails; never use the row-action dropdown as a substitute.
Journey selection opens Setup before checking the visible enabled name field,
so a remembered wizard page cannot prevent the subsequent Test-login gesture.
Before pressing a control, allow at most four pointer-position observations for
the same component/window while its layout settles. Only changed geometry may
restart that pointer movement; ownership, popup, window and deadline failures
remain fatal. Never retry an already issued gesture.

Only provisioned startup Next/Start Burp/Continue Community actions and the
known old-temporary-files dialog's `Leave` action may be automated outside these
operations. Unknown modal, missing/ambiguous control or lost focus fails with a
fixed code. Diagnostics contain bounded safe roles/labels and control counts;
omit text-editor contents, field values, exception messages and arbitrary window
titles. Screenshots are guest-private diagnostics, excluded from published
evidence and deleted during owned cleanup; reports use safe receipts instead.
During an operation, a private progress file records only its joined identity,
sequence and fixed stage of the control operation. This survives a blocked EDT/input
call and cannot replace a completed GUI receipt or grant coverage.

`EDIT_RULES` consumes closed fixture intent. `REPLACE` has exactly `mode`,
`policy`, `enabled`, `tools` and `rules`; at most eight distinct imported aliases
are allowed. Each rule has `alias`, `enabled`, `urlMode`, `url`, `regex`,
`proxyPort`, `detect`, `detectBy`, `failureStatus`, `responsePattern`. Ports/status
are typed integers or null; ignored URL/detection fields must be empty/default.
`INVALID_REGEX` has only `mode` and a one-based `rule` number; it edits that
existing rule to `[` without replacing its account. All writes use real input.
Wait for visible state to settle across autosave, then prove applied behavior
through the independent receiver; widget state alone never grants coverage.

`CAPTURE_PROBE RESET` reads an owned intent file with exactly `version: 1`,
`origins` (one to four distinct literal loopback HTTP(S) origins with explicit
ports) and `case` (a fixed safe phase label). It stops observation, clears the
visible capture, enters those filters and enables observation through real input.
`EXPORT` stops observation and uses the native Save dialog to write a new owned
output file. The passive capture contains the invocation/artifact identity and
safe synthetic nonce/header-shape facts; invalid nonces, bounded-inspection
truncation and event overflow make it incomplete.

### 3. Shared fixtures, examples and independent observations

Keep native journey creation in the existing captured `ProductionLabExamples`
and `ProductionLabAdapter`. Add a host export mode taking the owned live target
inventory and generating aliases `host_a`/`host_b` from `BROW.basic.json`, roles
`B,C1`, accounts `user`/`user2`, maximum cache age 3500 seconds and skew 10 seconds.
Use its actual `JourneyJson` serializer; never write another native schema
serializer in the lab. Export three HTTP identity pairs for the existing
`BASIC`, `NTLM_V1` and `NTLM_V2` fixtures through the same codec. Exports omit
secrets; the GUI enters synthetic passwords.
Host export plans use `mode: HOST` and the fixed default alias prefix `host`.
Only the final ordinary-failure phase may select `hostAliasPrefix: host_failure`
to import an uncached identity for its replacement lease without colliding with
the earlier journeys. Both variants use the same native builders and serializer.
The exporter is a separate
captured Java process, not the helper or a product testing endpoint. The guest
receives the existing captured exporter runtime and source audit, whose hashes
are recorded separately from the exact loaded product JAR.

The lab run selects `browser,http-auth` and prepares `BROW.basic.json`; that
selection also starts the existing HTTP-auth fixture inventory. Derive origins and generations from its
current inventory and require them unchanged across export/import. Application
requests target `/protected/b_c1` on that case. The different valid protected URL
uses the SAME case and path on `alternateOrigin`, sharing fixture credentials;
do not use a random 404 or a different role subset. No authentication is performed
before the measured cold first request. Measure warmed cases separately. Any
reacquisition after UI setup belongs to a new warmed phase; it must never be
reported as a cold request. Host runs use the existing fixture owners with an explicit 3600-second issuance lifetime. Native host examples use a 3500-second cache lifetime with a 10-second skew, preventing unrelated proactive refresh during these multi-minute routing/recovery recipes. Ordinary lab runs retain their 60-second lifetime and dedicated expiry tests. Explicit revocation still drives the host recovery cases.

Each original test request carries `X-AuthLab-Request: h<16 lowercase hex>`.
This synthetic correlation header is not a product directive. Reject invalid or
duplicate-original nonces in the driver. The receiving application records safe
facts from that header. For genuine Proxy-history selection also append the same
nonce as `host_probe` query metadata; the controlled route still uses its current
generation and the routing cases explicitly include that query in their inputs.
No user credentials are placed in a URL. The receiving application records safe
facts BEFORE authentication rejection: sequence, case ID/generation, nonce,
method, route enum, Authorization-header count, cookie-header count, expected
cookie-name presence, unresolved native-tag presence, HTTP-directive presence,
status and accepted account/issuance/roles. Never retain header/body values.
Expose the bounded observations through `CaseLease.snapshot()` and the existing
private control API. Add the same safe nonce and shape fields to passive probe
rows. An absent credential and an invalid supplied credential must be separately
observable even if both receive 401.

For HTTP authentication expose the fixture's existing safe `WireRequest` list,
adding nonce, challenge phase and accepted-operation identity. Record wire
transmissions, completed handshakes and authenticated application executions
separately. HTTP challenge handling may resend a POST after 401. The invariant
is one authenticated application execution per original nonce and no duplicate
Burp dispatch, not one network transmission. Account/protocol/socket facts come
from the receiving fixture, not from a success popup.

Load the existing probe before the product so its passive global response
callback can observe the original response. It returns unchanged actions.
Join the receiving server's original status to that callback and to the unchanged
client response (or genuine Repeater response pane). A recovery replay is a
separate GLOBAL request, joined by nonce, callback family and accepted issuance;
its response must not be substituted into the original client response. Explicit
direct HTTP-authentication delivery has its own response-spoofing contract.
Do not infer callback ordering from timestamps alone: the primitive qualification
must demonstrate these phases on the pinned Burp. Distinct callback families
for one request are observations, not duplicate sends. Any observer truncation
(1,000 rows), server truncation (10,000 rows), missing sequence or ambiguous nonce
makes the scenario incomplete.

### 4. Executable scenario recipes

`LabHostScenarios` owns the fixed cases below. Each case starts a new measured
phase with counters and probe sequences recorded before dispatch. Browser login
traffic, client originals, challenge transmissions and recovery replays have
separate counters. All required rows run on BOTH platforms. Subcases cannot be
filtered from acceptance. Requests use a normal client configured with an
explicit ProxySelector even for loopback; it never preauthenticates or resolves
tags. Repeater sends always use the GUI operation above.

Request tags select saved journeys and replace cookie/token references together
after successful resolution. They must not receive another automatic injection
pass; use the [request-tag syntax](../../README.md#use-request-tags). The separate
`BPSP-HTTP-AUTHENT` header selects the saved Basic/NTLM identity and must be
consumed; use the [HTTP-authentication contract](http-authentication.md).

| ID | Setup, GUI actions and request | Independent pass observations |
| --- | --- | --- |
| `routing` | Set two assigned listeners to `host_a`/`host_b` and leave the third unassigned. Send concurrent identical protected URLs. Repeat separate URL-only, port-only and URL AND port configurations. Exercise prefix, regex substring/case/anchor variants; edit regex to `[` and observe inline rejection retaining the applied rule. | Assigned requests each accepted once as the intended account; unassigned port lacks credentials and receives 401. Alternate valid origin stays unauthenticated for URL-restricted modes; it IS authenticated for port-only mode. Invalid edit keeps the prior account/rule. Cold and warm deltas reported separately. |
| `tags` | Configure contrary automatic account B; explicitly tag account A bearer AND cookie in Proxy and genuine Repeater requests. Then send an unknown-alias tagged request in Repeater and separately in Proxy. | One accepted A execution per successful nonce, both roles from one issuance, no unresolved tag/directive or second B credential set. Failed Repeater request never reaches server. Native Proxy DROP is best effort: report observed forwarding/drop, do not require prevention or introduce stop headers/handoff. |
| `repeater` | Copy a listener-matched Proxy history item using GUI. First preserve copied ordinary credential bytes and send; then remove them in the native editor and send; repeat with URL-only rule and explicit tags. | Actual Repeater callbacks. Preserved bytes authenticate as ordinary data. Port-only rule adds no credentials after removal (401 with absent shapes); URL-only and tags authenticate once as configured. |
| `http-auth` | For each Basic/v1/v2 pair, run real Test login for A and B, then send tagged A/B/A requests through Proxy and genuine Repeater, including fixture POST bodies. Add a conflicting ordinary Authorization value to prove the explicit directive overrides it. | Each Test login displays the observed expected protocol/result with fresh independent fixture account proof. Tool sends accept expected account and protocol, no directive leak, one authenticated execution per nonce, A/B identity isolation across connections. Handshake wire sends counted separately; no duplicate original tool dispatch. |
| `recovery` | Prime via the product, revoke the current issuance with private fixture controls, hold the next login gate, issue two protected requests, verify one shared login reaches the hold, then release. | Both original client responses remain 401. One shared recovery login/issuance; each original authorizes exactly one separately observed GLOBAL replay, accepted as the intended account. No additional replay after completion. |
| `rejected-replay` | Prime, revoke and hold recovery as above; configure a one-shot PROTECTED rejection for the replay before releasing login. | Original 401 plus exactly one rejected replay, automatic handling visibly pauses with actionable status, and a subsequent ordinary request is sent unchanged. No recursive login/replay loop. |
| `intercept` | Turn Intercept on, submit protected request for a URL-restricted rule, wait for its nonce, edit it to alternate valid origin, Forward, and turn Intercept off in finally. Repeat from nonmatching to matching URL. | Server account/credential presence follows the actually forwarded URL; no pre-edit rule is incorrectly retained. Callback tool/listener identifies Proxy, not Extensions. |
| `unload` | Start cold login with held LOGIN gate, wait for hold, toggle existing product Loaded off, release gate, verify owned product children terminate, toggle Loaded on, enter synthetic secrets again if cleared, send a new nonce. | No late authenticated application delivery after unload; fresh post-reload login/issuance required before success. Existing entry retained, old child/process ownership gone, fresh request succeeds once. This external test does not claim to observe every internal state write. |
| `ordinary-failure` | Prepare a fresh BROW.basic.json lease and import a new uncached automatic journey alias; use a matching URL-only rule with Wait for login, and arm LOGIN occurrences 1, 2 and 3 with existing HTTP_ERROR 503. This covers the coordinator's bounded retries without allowing a later attempt to succeed. Send a credential-free protected GET with a new nonce and a harmless fixed sentinel header/body shape. | The bounded login cycle fails; count login attempts separately from the original request. The original request still reaches the application exactly once with identical method/path/sentinel and no added credentials, returning 401. Observe the product's inline/event failure and unchanged-forward feedback. No automatic replay or unresolved tag. Retire the lease and remove the temporary rule/alias before further cases. |

Use existing `FaultSpec.holdLogin`, gate release, revocation and fault APIs; add
no new server/authentication implementation. For recovery, a receiver nonce may
appear twice: original and one replay. Ordered before/after passive observations,
server acceptance and login/issuance deltas establish that distinction. Unload
proves no late application execution and a mandatory NEW issuance after reload;
it does not inspect internal publication. Existing component lifecycle tests own
the stronger internal state assertions.

Long host runs schedule future faults through `CaseLease.armRelativeFault`:
`FaultSpec.occurrence` is a bounded 1–32 lookahead from the owner's current phase
count, resolved under its lock to an absolute target no greater than 10,000.
The existing catalog/control API and `armFault` retain absolute occurrences up to
32. One internal scheduled-fault owner serves both paths; semantic duplicates
compare the absolute target and all fault behavior fields, while different fault
kinds may share a target. `LoginFlows` queries the owner for a checkpoint rather
than depending on that internal representation. This allows the recovery gates
after earlier routing requests without resetting counters or duplicating a lab.

### 5. Host evidence and catalog contract

Reports live under
`test/authentication-lab/build/authlab/<invocation>/<sha256(":authLabHostTest")>/`;
each platform has a child directory. Private guest runtime and downloaded
diagnostics stay outside that report tree under ignored `build/host-runtime`.
The context is version 1 and includes invocation/task/configuration/catalog
identity, source revision plus dirty-source hashes, captured source audit,
product/helper/exporter/runtime hashes, adapter ID `JDK_AWT_ROBOT_V1`, intended
platform set `[windows,linux]`, actual Burp/JVM/OS identity and `STARTED` state.
Platform completion includes actual listeners, run/case generations, operation
receipts, safe probe/server observations, duration fields, `unattended:true`,
scenario outcomes and cleanup ownership/results. Terminal state is `COMPLETED`
only when both platforms and every scenario pass with complete cleanup.
The source audit includes maintained lab main/test sources, GUI/probe helpers and
declared configuration inputs as well as production sources. Catalog JSON stays
under its separate fingerprint to avoid binding self-hash cycles. Immutable
context records include audit/inventory hashes, runtime role/hash/byte descriptors
and adapter identity. Environment evidence joins the actual Burp PID/start time
to the GUI session and numeric memory summary.
The loaded probe reports its actual `Runtime.maxMemory()` plus PID/start identity;
the guest checks its full session, exact version token, listeners and observed
2,147,483,648-byte maximum heap before retaining `actualMaxHeapBytes`. Requested
launch settings alone cannot establish the heap qualification. RSS sampling has
a 200 ms target cadence and records its largest observed gap; a gap above 2,000 ms
makes that observation incomplete. After Burp stops, bounded numeric GC summaries
retain observed object counts and sizes only. Missing, rotated, malformed or
truncated logs cannot qualify complete evidence.

`LabHostEvidence` validates strict fields, identities, checksum joins, sequence
continuity, required cases/roles, unambiguous send counts, no overflow, deadlines,
unattended receipts and cleanup. Reject missing/stale/foreign evidence, missing
platforms, altered artifacts, unsupported vendor versions, assisted execution
and a success receipt without independent server proof. Report assertion failures
as FAIL, absent prerequisites as BLOCKED, cancellation as INTERRUPTED. No absence
is converted to PASS or EXCLUDED. Empty/partial reports have a non-success exit.

Add executor `HOST` only for layer HOST. A HOST binding has className
`lab.auth.LabHostEvidence$VerifiedRun`, methodSignature
`verifyRequirement(java.lang.String)`, parameterKey equal to the exact existing
requirement ID, executionId `HOST:` followed by that ID, taskPath
`:authLabHostTest`, xmlCaseName null and
the existing source/configuration/witness fields. Binding `sourceRevision` is its
reviewed marker, as for native bindings; it is not the current captured boundary.
Prove currentness from complete binding source hashes joined to current files
and the captured audit, plus the configuration hash. Observed evidence records
the actual plan source revision separately. Explicit refresh updates fingerprints
without manufacturing a new review marker.
This identity names a scenario,
not a fabricated JUnit test. The private-constructed validated run owns this
method; recipe witnesses still point to actual assertions in `LabHostScenarios`.
This keeps the binding attached to its real executable owner without a dummy
method or shared invocation state in the scenario runner.
Route these rows from `LabProductionEvidence` to
`LabHostEvidence`; preserve the existing JUnit/FIXTURE validators and MANUAL
behavior. `LabEvidence` must not preclassify automated HOST rows as manual.
ASSESSMENT rows and unselected HOST rows remain MANUAL.
`verifyRequirement` requires both platforms and ALL scenarios mapped to its
parameterKey in the hashed inventory; no single scenario can satisfy a multi-case
requirement. Witness inputKey is the scenario ID, or `http-auth/<protocol>` for
the protocol rows. Each witness points to that scenario's assertion in
LabHostScenarios. XML matching and JUnit naming rules never apply to HOST.

Add explicit profile `burp-host` with exactly these existing requirement mappings:

| Requirements | Required scenarios |
| --- | --- |
| `H01.tool=proxy~mode=automatic-combined-injection` | routing, intercept |
| `H01.tool=proxy~mode=native-tags` | tags |
| `H01.tool=repeater~mode=automatic-combined-injection` | repeater |
| `H01.tool=repeater~mode=native-tags` | tags, repeater |
| `H02.ordinary-unchanged` | ordinary-failure |
| `H02.tagged-stop` | tags, repeater |
| `H03.successful-replay` | recovery |
| `H03.rejected-replacement-pauses` | rejected-replay |
| `H06.unload-reload` | unload |
| `HOST.http-auth.basic`, `HOST.http-auth.ntlm-v1`, `HOST.http-auth.ntlm-v2` | http-auth, restricted to the named protocol |

The remaining plan scenarios are mandatory profile-level witnesses even where
they do not justify a separate existing catalog row. Do not claim Scanner,
Intruder, offline-load, or intercepted-auth-traffic qualification from these
cases. Promotion sequence: implement collector support with rows still MANUAL;
qualify the full primitive/scenario set on both VMs; promote only these twelve
rows to HOST; run `:auth-lab:refreshBindings`, inspect the diff, then run a NEW
`authLabHostTest` invocation. Qualification results cannot be reused as acceptance.
`authLab -PlabProfiles=burp-host` delegates to that same complete coordinator.

### 6. Exact file boundary and buildable checkpoints

All paths below are repository-relative. Production authentication/UI code is
outside this change; a product regression is reported separately before widening
the write boundary. Generated output globs below are never committed.

| Checkpoint | Action and exact files | Responsibility |
| --- | --- | --- |
| A | Create `test/authentication-lab/src/main/java/lab/auth/LabHostInputs.java`, `LabHostGuiProtocol.java`, `LabHostVmTransport.java`, `LabHostCoordinator.java`, `LabHostGuest.java` | Closed inputs/protocol, finite VM helper transport with sanitized errors, two-platform ownership/cancellation coordinator and minimal guest lifecycle. Guest owns lab/Burp launch, file-command channel and teardown from A; before B's driver exists it truthfully reports BLOCKED. |
| A | Create `test/authentication-lab/src/main/java/lab/auth/LabJson.java`; modify `test/authentication-lab/src/main/java/lab/auth/ScenarioCatalog.java` | Extract shared strict JSON/file helpers while preserving catalog errors and validation. |
| A | Modify `test/authentication-lab/src/main/java/lab/auth/LabMain.java`, `bapp/gradle/auth-lab.gradle.kts`; create `bapp/gradle/auth-lab-host.gradle.kts` | Strict CLI, explicit tasks, artifact/runtime capture, no default-check GUI execution. |
| A | Create `test/authentication-lab/src/test/java/lab/auth/LabHostInputsTest.java`, `LabHostCoordinatorTest.java`, `LabHostVmTransportTest.java`, `LabHostGuiProtocolTest.java` in that same test package | Deterministic infrastructure tests described below. |
| B | Create `test/authentication-lab/src/hostGui/java/lab/auth/gui/HostGuiBootstrap.java`, `HostGuiDriver.java`, `HostGuiSelectors.java`, `HostGuiPreferences.java`, `HostGuiDiagnostics.java`, `README.md` | Public agent entry, Robot operations, unique control selection, isolated preferences and safe diagnostics. |
| B | Modify `test/authentication-lab/build.gradle.kts`, `test/authentication-lab/gradle.lockfile`, `test/authentication-lab/Build-HostProbe.ps1`, `test/authentication-lab/src/hostProbe/java/lab/auth/HostProbeExtension.java`, `test/authentication-lab/src/hostProbe/java/lab/auth/README.md`, `test/authentication-lab/src/hostProbe/README.md` | Single helper build with existing Gson, normal Montoya frame access, nonce/shape observations and worker teardown. Preserve explicit Extensions sends. |
| B | Create `test/authentication-lab/src/test/java/lab/auth/gui/HostGuiSelectorsTest.java`, `test/authentication-lab/src/test/java/lab/auth/gui/HostGuiPreferencesTest.java`, `test/authentication-lab/src/test/java/lab/auth/gui/HostGuiDriverTest.java` | Public Swing synthetic-component selection, preferences isolation, action failure/cancellation tests through injected input/clock seams. |
| C | Create `test/authentication-lab/src/hostGui/java/lab/auth/gui/HostGuiRules.java` and `test/authentication-lab/src/test/java/lab/auth/gui/HostGuiRulesTest.java`; modify `HostGuiDriver.java`, `LabHostGuiProtocol.java` in their owning packages | Strict fixture intent and real-control rule editing, including invalid-regex retention. |
| C | Create `HostGuiProbe.java`, `HostGuiAssertions.java`, `HostGuiMessages.java` and `HostProbeShape.java` under `test/authentication-lab/src/hostGui/java/lab/auth/gui`; create their matching tests under `test/authentication-lab/src/test/java/lab/auth/gui` | Keep passive capture, visible-feedback assertions, bounded request/response correlation and credential-free shape inspection in their owning helper classes. The driver dispatches real-input operations to these owners. |
| B | Create `test/authentication-lab/src/main/java/lab/auth/LabHostArtifactCache.java` and `test/authentication-lab/src/test/java/lab/auth/LabHostArtifactCacheTest.java` | Two current-byte cache slots, captured-source verification, checked fresh deployment, cache-miss replacement and negative protocol tests. |
| B | Create `test/authentication-lab/src/main/java/lab/auth/LabHostMemory.java` and `test/authentication-lab/src/test/java/lab/auth/LabHostMemoryTest.java`; modify `LabHostGuest.java` | Sample only the owned Burp PID's RSS every 200 ms, verify its start identity, bound private samples and retain a numeric summary for the universal-JAR memory qualification. A single owned Windows observer process may query public process memory; Linux reads its owned `/proc` status. Neither performs GUI input. |
| B | Create `test/authentication-lab/src/main/java/lab/auth/LabHostLinuxTemp.java` and its mirrored test; modify `LabHostGuest.java`, `LabHostCoordinator.java`, `LabHostEvidence.java` | Own a short private Linux temp directory with strict persisted allocation identity and shared normal/recovery cleanup; include its implementation in the source inventory. |
| B | Create `HostGuiPointerTrace.java`, `HostLibraryOrigins.java` under `test/authentication-lab/src/hostGui/java/lab/auth/gui` and their mirrored tests; modify `HostGuiBootstrap.java`, `HostGuiDriver.java`, `HostGuiDiagnostics.java` | Optional bounded private diagnosis of actual pointer delivery and already loaded public library origins; no extra input or authentication pass conditions. |
| C | Create `test/authentication-lab/src/main/java/lab/auth/LabHostScenarios.java` and `LabHostObservations.java`; modify `LabHostGuest.java`, `LabRun.java`, `ControlledApplication.java`, `HttpAuthenticationFixture.java`, `FixtureIdentityStore.java` in that package | Extend the same guest owner with all fixed recipes, bounded independent observations and existing fixture reuse. Keep safe receiver shapes and their bounded journal in LabHostObservations. Reuse the fixture account owners for private GUI secret references. |
| C | Modify `test/authentication-lab/src/main/java/lab/auth/LoginFlows.java` for its late-token checkpoint query and bounded host-only `/start` page-response event, with the relative scheduler in `LabRun.java` and targeted native lab tests | Keep fixture scheduling inside its existing owner and preserve the public catalog/control fault limits. The safe journey-alias event does not increment LOGIN attempts or change ordinary fixture behavior. |
| C | Modify `test/authentication-lab/production-tests/bpsh/support/ProductionLabExamples.java`, `ProductionLabAdapter.java`, `bapp/gradle/auth-lab-production.gradle.kts`, `bapp/gradle/auth-lab-production.init.gradle`, `test/authentication-lab/src/main/resources/production-selection.json` | Host export mode and captured exporter deployment/audit; reuse actual production codec, no auth engine duplication. Register the new native-codec regression in the existing audited component selection. |
| C | Create `test/authentication-lab/src/test/java/lab/auth/LabHostObservationsTest.java`, `LabHostScenariosTest.java`; modify `test/authentication-lab/production-tests/bpsh/burp/ui/JourneyRegistryTest.java` | Negative-credential observations, fixture recipes/counter assertions and emitted-host-example codec round trip. |
| E | Modify the existing host form exporter in `ProductionLabAdapter.java`, the cold routing measurement in `LabHostScenarios.java`, and `LabHostEvidence.java` with its tests | Retain two bounded `browserAdmission` observations with alias, original nonce, dispatch time, unique fixture event sequence, elapsed milliseconds and boundary `CLIENT_DISPATCH_TO_LOGIN_PAGE_RESPONSE_START`. Recompute durations from actual events; reject missing, duplicate, stale or mismatched joins. The existing native-codec regression checks the host-only URL alias. |
| D | Create `test/authentication-lab/src/main/java/lab/auth/LabHostEvidence.java`, `test/authentication-lab/src/test/java/lab/auth/LabHostEvidenceTest.java`; modify `ScenarioCatalog.java`, `RefreshBindings.java`, `LabEvidence.java`, `LabProductionEvidence.java` in the main package and `test/authentication-lab/src/test/java/lab/auth/CatalogContractTest.java` | HOST binding and evidence validation; preserve manual/JUnit ownership. |
| D | Modify `test/authentication-lab/src/main/resources/catalog/catalog.json`, `test/authentication-lab/src/main/resources/catalog/burp.json`, `test/authentication-lab/src/main/resources/catalog/http-authentication.json`, `test/authentication-lab/src/main/resources/configuration-inputs.json`; create `test/authentication-lab/src/main/resources/host-scenarios.json` | Exact twelve-row profile/mapping, strict scenario inventory and intentional fingerprints. |
| D | Modify `test/authentication-lab/src/main/resources/catalog/fixtures.json`, `test/authentication-lab/src/main/resources/catalog/browser.json`, `test/authentication-lab/src/main/resources/catalog/credentials.json`, `test/authentication-lab/src/main/resources/catalog/recovery.json`, `test/authentication-lab/src/main/resources/catalog/registry.json`, `test/authentication-lab/src/main/resources/catalog/federation.json`, `test/authentication-lab/src/main/resources/catalog/transport.json`, `test/authentication-lab/src/main/resources/catalog/assessments.json` | Binding-refresh output only: inspect source/configuration fingerprints, preserving unrelated requirement semantics, disposition and coverage. |
| E | Modify `test/authentication-lab/README.md`, `test/authentication-lab/src/main/java/lab/auth/README.md`, `docs/README.md` and this plan | Real commands, private configuration example without credentials, qualified identities, results and current maintenance instructions. |
| E | Delete obsolete disposable `bapp/build/reports/session-routing/manual-matrix.py` and `bapp/build/egm-burp-host/gui-spike/*` only after maintained replacements work | Remove superseded generated runners and diagnostics; no archive. These ignored paths are not source dependencies. |

Unqualified names in a table row resolve against the full package directory
explicitly named earlier in that row. No additional dependency or source file is
authorized by this inventory. If an absent listed existing file is discovered,
correct the inventory before editing instead of creating a substitute silently.

At A, compile the lab and pass the four named infrastructure suites with a fake
VM transport; the host task must produce a truthful BLOCKED report before GUI
exists. At B, add the GUI suites, build the helper and current dev JAR, then run
qualification for READY/Proxy/Repeater/Loaded/import/editor/interception primitives
on each VM. Missing primitive blocks C qualification, not ordinary unit checks.
At C, pass fixture/scenario tests, captured codec tests and complete scenario
qualification on both VMs. At D, pass evidence/catalog tests, promote bindings
only after C, and run fresh two-platform acceptance. At E, documentation and the
final current artifact must pass all checks and a fresh acceptance invocation.

Each checkpoint runs `:auth-lab:test` and `:check :verifyNativeDocumentation :jar`
with `JAVA_HOME` set to JDK 21. Build the development JAR BEFORE any GUI operation.
Transfers compare that exact artifact checksum. Refresh the existing product
entry by Loaded off, replace its owned configured file, then Loaded on; no
remove/re-add. Preserve unrelated VM Burp sessions and processes throughout.

Required deterministic failure tests use injected VM transport, clock, process
owner and GUI-input interfaces; live broken machines are not required. Cover:
unknown/duplicate CLI fields; locked desktop/missing Burp; stale PID ownership;
one platform missing; helper timeout/nonzero exit; stdout/stderr/exception argv
containing secret sentinels; unknown/ambiguous/disabled control; deadline before
and after claimed send; duplicate operation ID; cancellation during hold/send;
assertion-failure cleanup; cleanup failure; wrong hashes/generation/nonce;
missing callback phase; truncated observations; success without server evidence;
unsupported vendor; assisted receipt; and preserving unrelated MANUAL rows.
No failure path may print a subprocess exception, command line or captured
private output. Use fixed typed error codes, including for timeout. Assert the
sentinels are absent from every public report and console stream.

### 7. Completion and delivery

One current invocation must pass every scenario on both VMs with actual tool
origin, independent server facts, unattended GUI receipts and complete owned
cleanup. Earlier feasibility or qualification receipts do not count. Keep
failed attempts as failed evidence; do not retry sends until green. Missing
automation or human input blocks acceptance. Publish no screenshot containing
credentials and no raw command/output from private VM helpers.

Build directly to `bapp/build/libs/browser-powered-session-handler-dev.jar`.
Deliver its checksum and current checks plus both platform result paths. Do not
commit generated JARs, browser payloads, credentials or runtime evidence. Retain
only maintained runner sources, fixtures, tests and current documentation.
