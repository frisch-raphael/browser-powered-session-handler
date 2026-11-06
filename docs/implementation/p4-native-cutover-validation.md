# P4 native production cutover candidate

The source/packaging cutover is implemented in `rfrisch/java-playwright`. P4
remains open for the user's requested interactive UI check in a compatible Burp.
The development artifact has not been accepted as a release or manually verified
inside the installed Burp instance.

## Implemented cutover

`Extension` composes one native registry, secret store, browser runtime, identity
manager, coordinator, traffic guard, resolver, recovery service, diagnostics and
UI. It probes global drop and Proxy action factories before registering any
authentication hooks. Unsupported hosts receive a minimum-capability message
and no partially enabled tag parser. Startup loads only native project/library
formats and does not start authentication.

The global handler classifies owned traffic before all scope/acquisition logic,
rejects nested/invalid markers, preserves the normal User-Agent after stripping
the suffix, and resolves explicit tags regardless of Enabled/tool/scope settings.
Tag failure uses an annotated supported drop; ordinary failure preserves the
original request and logs actionable guidance. Narrow Proxy hooks use
doNotIntercept only for established ownership and retain the suffix until global
send. Global and Proxy response ledgers stay independent. Recovery reads only
actual used-version provenance, and status-only/unattributed/internal responses
do not even fetch the host's response body. Regex paths check encoded actual size
before fetching bytes and retain the independent decoded ceiling.

The new Swing editor provides explicit project/library destinations, saved
journey/automatic identity selection, stable-ID steps, missing-versus-supplied
secret fields, Remember secrets, native import preview with alias edits, separate
Include secrets export consent, exact-fingerprint certificate listing, and raw
or wrapper Copy tag. Ordinary proxy settings remain optional HTTP/direct. The
PKCS#11 middleware is used by Java; certificate common names do not select an
identity. Explicit certificate-list retry and authentication Retry are the only
native recovery actions.

Save, Save and test, Invalidate, shared Cancel and Retry use the native service
graph. Idle Cancel reports no active cycle without applying a cooldown. Its
shared impact, retained-token behavior and cooldown have visible inline help.
Numeric waiter fields stay blank/disabled under independently selected Unlimited
controls; applying a finite limit requires the user's actual number.

UI actions capture inputs on the EDT, validate/persist on a bounded serialized
worker, and guard display completions by editor/selection epochs. Slow saved
selection loads disable the previous editor to prevent wrong-journey edits.
External scope publications invalidate the visible draft's original epoch;
capturing a newer global version cannot make an old draft eligible to overwrite
it. Own library echoes are suppressed. An explicit Reload selected action reads
the managed snapshot, and Reload storage acknowledges discarded persisted/session
state. Dialogs and file choosers use Burp's suite frame.

Unload revokes admission, stops both UI timers/watchers, discards/wipes queued
captures, deregisters hooks, completes waiting callers, revokes markers and closes
owned services. Browser cleanup gets a short bounded join off the EDT before
owned providers are removed. Shared native logout/default TLS changes are not
performed; a truly hung vendor operation remains an acknowledged limitation.

The old mutable configuration fields/parsers/constructors and production
`ApiClient`, `ApiServiceManager`, `LocalTokenCache`, `HackvertorTagBuilder` and
`TokenServiceProtocol` callers are removed. The unused CommonMark dependency is
removed and dependency locks updated. Old persisted data, fixtures and the
tracked unqualified JAR remain preserved for the later approved release cutover.
The new platform JAR rejects retired runtime classes and host/test APIs.

## Automated evidence

| Check | Result |
| --- | --- |
| `gradlew.bat classes test jar verifyNativeDocumentation --offline --console=plain` | Passed; 213 unit tests, no failures/errors/skips |
| Explicit `browserIntegrationTest` | 9 tests, no failures/skips, actual bundled Chromium/classloader |
| Explicit `pkcs11IntegrationTest` with owned SoftHSM fixture | 7 tests, no failures/skips |
| Private documentation | All 180 explicit methods/constructors across the cutover files documented, including 108 private declarations; private Javadoc doclint passed |
| Production source search | No retired service/tag-generator/companion-startup references |
| Actual platform JAR inspection | Zero retired runtime/CommonMark entries; bundled archive hash and structure verified |

The five obsolete legacy compatibility tests were replaced by native coverage.
Seven production-hook tests use a small SDK factory double in the test JVM and
restore it afterward. They exercise real handler methods, scope-independent tags,
annotated drops, ordinary preservation, owned marker stripping, independent Proxy
response IDs, normal interception rules, lazy body guards, and minimum-host
rejection before any authentication registration. They do not establish actual
Burp hook ordering, raw URL handling or target drop/interception behavior.

Seven isolated Swing tests exercise native persistence off the EDT, session-only
secret omission, stable/retyped/reordered step identities, external library
conflicts, preserved invalid project data, stale selection completions, one-action
alias reassignment consent, and timer shutdown. One produces
`bapp/build/ui-previews/p4-native-editor.png` at 1280x820 for offscreen layout
inspection. These operate only our components and private temporary stores,
without controlling the installed Burp process. The image is not a manual Burp
UI acceptance result.

## Manual UI gate: pending

The user explicitly requested a manual works/looks check. Computer Use returned:

> Computer Use was not approved to use Burp Suite Professional

The original Burp 2025.12.5 installation lacks `RequestToBeSentAction.drop()`. The
[official Montoya release notes](https://github.com/PortSwigger/burp-extensions-montoya-api/releases)
list HttpHandler request dropping under 2026.4. The unsupported-host information
path was verified with a test factory, not by loading the candidate into the
denied app.

On 2026-11-04, the user requested installation of the latest Burp EXE and diagnosis
of the access denial. The official stable
[Burp 2026.10.1 Windows x64 installer](https://portswigger.net/burp/releases/professional-community-2026-10-1)
was downloaded directly, verified against the published SHA-256
`793e42d920e14eff09e5aa438d21076970f306e1a15b6a3752184a374c91f206`,
and checked for a valid PortSwigger Ltd Authenticode signature. The unattended
installer exited successfully with code 0. The new executable at
`C:/Users/Rapha/AppData/Local/Programs/BurpSuiteDesktop/BurpSuite.exe` reports
2026.10.1 and has a valid PortSwigger signature. The existing BurpSuitePro
installation was preserved; no Burp process was running during installation.
Static inspection of the new bundled API confirms both `drop()` and
`drop(Annotations)` are available. This clears the known host SDK prerequisite,
without claiming runtime hook acceptance.

Computer Use can enumerate the original app, but launching the new executable
through its documented API is denied before launch:

> Computer Use was not approved to use Burp Suite

The general plugin-permission service does not expose this native-app approval;
its lookup reports Computer Use as not installed despite the available bundled
tool, and is not evidence that the native tool is missing. Official OpenAI
[Computer Use setup guidance](https://developers.openai.com/training/walkthroughs/using-your-computer-and-browser)
places desktop app access under Settings > Computer use.

The user subsequently supplied a screenshot showing Any App enabled and the
original `burpsuitepro` permanently allowed, with no settings changes. Read-only
inspection confirms a saved original-app approval in the active CLI home:
`computer_use.windows.always_allowed_app_ids` contains a map from the original
`process:` executable identity to `true`. Retesting that exact returned original
app through `sky.launch_app` still returns "Computer Use was not approved to use
Burp Suite Professional". The new executable's different identity alone therefore
does not explain the denial. The earlier attribution to an absent user grant was
too definite and is superseded by this evidence.

The current official [Windows configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference)
documents that setting as an array of strings, whereas the local value is a map.
This is a possible compatibility clue, not a proven cause: the installed CLI's
read-only `features list` loads successfully and reports Computer Use enabled.
The shell's parent process chain identifies this task as Orca -> CLI 0.166.0;
separate desktop/daemon/VS Code Codex builds are also running. A stale approval
snapshot or a mismatch between integrations remains a hypothesis. A fresh
Orca/Codex session is the next diagnostic test, not a confirmed fix. Do not ask
the user to enable the already enabled original-app setting again.

No permission setting was changed, and no alternate GUI automation or launch
mechanism was used to bypass the denial. The skill forbids acting on
security/privacy permission requests. Interactive Burp UI verification remains
was open on that runtime approval discrepancy at the time of this diagnosis.

### Follow-up: access restored, partial manual pass and UX review

After the user restarted the session, Computer Use launched Burp 2026.10.1 and
captured its UI without an assistant permission change. This supersedes the
pending-access prerequisite above; the precise stale-state/compatibility cause
was not established. A temporary project was used with existing extensions
initially disabled. The user library did not exist and was not used to save test
journeys. Existing Burp temporary files were preserved.

The candidate loaded successfully, registered its native suite tab and hooks,
and completed a real bundled-browser authentication against an owned loopback
fixture. Save caused zero token-endpoint hits; Save and test acquired a token
without showing its value. Navigation remained responsive during the attempt.
Idle Cancel preserved the cached token, Invalidate removed it, Retry reacquired,
and active Cancel released Test and displayed cooldown. Tabs and missing-module
guidance were inspected; no vendor middleware or default SoftHSM store was used.

At 1280x820 the forms retained their preferred width and scrolled horizontally.
A width-tracking, top-aligned `FormViewport` fixed this. The candidate was unloaded,
rebuilt with `classes test jar verifyNativeDocumentation --offline --console=plain`
(successful; 213 unit tests, zero failures/errors/skips), reloaded, and visually
checked at that size. All six added viewport declarations have detailed comments.
Unload removed the suite tab and registrations; the saved project list returned
after reload. This does not manually establish timer/provider/thread cleanup.

The user then stopped Computer Use with physical Escape and requested a UX
redesign before continuing. No GUI interaction resumed for the UX review. The
native UX critique
uses those Burp observations, current source, and the regenerated Swing fixture.
It records four P1 issues and one P2 issue, with a provisional expert score of
20/40. It recommends task-oriented editing, draft/saved-identity safeguards,
conditional setup, contextual testing feedback, and an explicit Use in requests
section. No production UX redesign has been applied by that review. The original
manual checklist below remains incomplete, especially certificate selection,
transfer/secret dialogs, and keyboard/assistive-technology behavior.

Use a temporary test project and disposable library/store for the manual pass.
Check layout/resizing and all tabs; create/edit/save/reload journeys and steps;
verify secret visibility/Remember/Include semantics; exercise certificate
selection using only the owned SoftHSM fixture in an appropriately isolated host;
check native Copy/import/export, bounded actions, Test/Retry/Invalidate/Cancel,
errors and dialog parenting; then unload and check resource/UI cleanup.

Real-Burp URL-template preservation, tagged zero-origin-hit drops, interception
ordering, proxy transport behavior, release stress, non-Windows artifacts and
physical/vendor-token acceptance remain separate outstanding P5 gates. No release
readiness is claimed while those or the requested manual UI gate remain open.

### Guided-wizard UX implementation and follow-up verification

The author selected the full guided wizard, URL-only configured proxy support,
and single checkbox labels. [DESIGN.md](../designs/interface.md) records the native Swing
contract. The implemented pages are Setup, Login steps, Token, optional Client
certificate, and Test & use. Automatic injection and Settings have independent
Apply actions. Draft protection, saved tag previews, contextual Test/Retry/Cancel,
certificate public metadata, and advanced disclosures replace the flat editor.
Configured upstream username/password fields were removed from the model, owned
secrets, codec/schema, runtime and UI; obsolete credential fields are rejected
with removal/unauthenticated-listener guidance. Internal per-attempt LittleProxy
credentials remain intact.

The final `test jar verifyNativeDocumentation --offline --console=plain` run
passed **220 unit tests**, with zero failures/errors/skips, private documentation
checks, and the native JAR structure/archive-digest gate. Relevant integration
runs passed **9 bundled-browser checks** and **7 SoftHSM checks**, with zero
failures/skips. The SoftHSM negative upstream-authentication fixture now observes
the authentication challenge, because URL-only clients send no Basic credentials.
The positive chain uses an unauthenticated upstream listener and verifies no
proxy authorization at the origin; failures retain zero-origin-hit/no-direct-
fallback behavior. No physical vendor device was tested.

An independent Impeccable finish review identified and then cleared two material
issues: an aborted Discard continuation must preserve dirty state, and externally
replaced storage must disable saved actions until the visible identity is reloaded.
Regression checks cover both, including queued identity rejection. Its follow-up
disposition was ship for those scored fixes; it did not claim whole-release
acceptance or actual Burp appearance from offscreen captures.

The rebuilt candidate was refreshed in Burp 2026.10.1 by toggling the existing
extension's **Loaded** checkbox off, confirming unload, rebuilding, then toggling
it on. It was not removed/re-added. The root [AGENTS.md](../../AGENTS.md) now
requires that workflow. At 1280x820 the real Burp pass verified empty state,
friendly labels after host theme application, saved/draft headers, numbered login
steps, JSON extraction fields, optional certificate-page skipping, and Test & use.
A saved journey completed a real bundled-browser login against an owned
127.0.0.1 fixture; the UI showed success/cache availability without the token.
An unsaved display-name edit disabled Test and Copy tag. Keep editing retained it;
Reload selected followed by Discard restored the original saved journey without
persisting the test edit. The temporary fixture was stopped after verification.

The page captures in `bapp/build/ui-previews/wizard-page-1.png` through page 5
remain offscreen layout evidence, separate from those real Burp observations.
Certificate-picker/middleware interaction in Burp, full transfer/secret flows,
keyboard/screen-reader acceptance, complete raw-request/hook/drop behavior, and
stress measurements remain open P4/P5 checks. This UX pass does not mark the
release ready.

### Author-directed compact UX and named credentials amendment

The next UX pass implements the author's explicit feedback: Project/User tabs,
plus/ellipsis collection controls, vector action icons with accessible tooltips,
conditional field visibility/clearing, selected-source-only JSON/cookie guidance,
concise feedback, and seconds-based debounced waiting settings. The old Copy tag
panel is removed. The request context menu inserts a saved alias, named token
when needed, and explicit encoding at the selected range/caret.

The additive `combined` extraction format captures named JSON values and cookies
together, publishing only a complete set and respecting its earliest expiry.
Tags are `<@journey/>` or `<@journey token="name"/>`, without `bpsh:`. Combined
automatic insertion sends Authorization plus selected cookies; multiple JSON
values require an explicit Authorization token name. Recovery can trigger on
HTTP status, RE2 text, or either condition, avoiding body reads on a status match.

Validation passed **229 unit checks**, **10 bundled-browser integration checks**,
and **7 owned SoftHSM checks**, with no failures/errors/skips. The browser suite
includes actual acquisition of a JSON token plus two cookies. Unit checks cover
named selection, JSON-response routing, missing/ambiguous names, complete-set
expiry, combined header/cookie insertion, conditional clearing, dynamic tooltips,
automatic settings with invalid-input retention, context-menu stale-state checks,
and either-condition recovery. Private documentation checks pass, and the updated
schema parses as JSON; a separate metaschema validator was unavailable in this run.
The independent reviewer scored all five listed UX fixes resolved; its
ship disposition is limited to those fixes.

Read-only actual Burp observations show the amended sidebar, icons and named
source rows. The user was actively editing an unsaved User-journey draft, so this
pass did not issue GUI input or reload it. To avoid replacing the loaded archive,
the final candidate was built with a local ignored Gradle output override into
`bapp/build/review-libs/browser-powered-session-handler-dev-windows-x64.jar`.
Its structure and bundled archive digest passed. After the user handles the
draft, refresh via Loaded off, replace the development archive, then Loaded on.
Final interactive context-menu insertion and the latest tooltip/configuration
transitions remain pending that refresh; earlier manual evidence applies only
to the candidate actually observed. Offscreen captures remain separately labeled.

### Automatic-injection autosave follow-up

The author removed the remaining Apply automatic injection control. Enable,
journey selection, tool checkboxes and URL rules now all trigger an independent
600 ms debounce and serialized background save. Waiting and automatic settings
continue to merge independently. Invalid edits retain the last valid applied
rules; both category timers stop on unload. Validation passed 230 unit tests,
private documentation and staged-JAR packaging checks. The latest JAR remains
in review-libs while the loaded Burp archive and unsaved draft are preserved.

### Latest development JAR refreshed in Burp

The author clarified that test drafts are disposable. The existing extension was
turned off using Loaded, its unload confirmation accepted, and the latest staged
archive copied to the build/libs path actually used by Burp. SHA-256 matched
`7c3a159b76281aaa9f139db606e688079a905676075f2af2bcb26077fef6a186`.
Loaded was turned on again without removing/re-adding the extension. Actual Burp
inspection verified no sidebar Journeys heading, plus/ellipsis together at the
bottom-left, and no automatic-injection Apply control. This supersedes the
previous pending-reload note; broader P4/P5 acceptance is still partial.

### Toolbar placement clarification

The author clarified that bottom-left means the bottom-left of the header area
above the journey list. The plus/ellipsis toolbar now sits below Project/User and
directly above the list, without a sidebar heading. The actual build/libs JAR was
rebuilt after unload confirmation; targeted wizard rendering, packaging and
private documentation checks passed. The running Burp UI was then inspected and
confirmed to show the corrected placement. The existing invalid test-library
guidance was preserved; its file was not changed for this layout correction.

### Regex, injection and journey batch follow-up — 2026-11-05

The development extension was refreshed through Loaded off/on in live Burp
2026.10.1. An owned loopback fixture provided JSON values, start/end regex values
and two captured cookies. A native Test login succeeded. Repeater then resolved
a disabled regex value through an explicit tag, with no automatic credentials.
With the synthetic journey selected for automatic injection and a loopback-only
URL prefix, two Repeater sends replaced stale bearer, custom header and cookie
values, preserved an unrelated cookie and omitted the disabled value. Both
responses reported `automaticPass: true`; the fixture recorded one login total.
The original automatic journey and URL-handling settings were restored.

The native import chooser selected two files, and the review showed three
journeys. Unchecking one imported exactly the remaining two. A host focus issue
found during range selection was corrected by restoring list focusability on
mouse interaction. Shift+Down then selected both disposable journeys in Burp.
Their export contained exactly the two selected aliases. One reviewed deletion
removed both, with all pre-existing Project entries preserved. The batch Cancel
path also preserved the selection. The global Reload storage item was absent;
the menu also provides Select all journeys.

Import and Export opened in the shared last visited directory. Navigating to a
different directory, cancelling and reloading the extension preserved that
location for the next chooser. This checks extension reload persistence; an
entire Burp process restart was not exercised in this pass. Synthetic fixture
inputs, wire report and batch export remain under ignored `bapp/build` folders.

### Ordered automatic journeys — 2026-11-05

Session handling now stores and edits an ordered list of enabled saved journeys,
with independent URL eligibility and expiration detection for each rule. The
Token page no longer contains session recovery. Add, activation, Move up/down,
Remove, conditional details and potential destination overrides use native Swing
controls and autosave through the existing serialized persistence worker.

The coordinator reserves the whole request once and acquires unresolved sessions
sequentially under the original request deadline. Cached sessions are reused.
Header and cookie destinations compose atomically, with later rules winning.
Expiration attribution includes only final credential owners. Failure retains the
existing ordinary unchanged-request warning policy, and explicit tags suppress
automatic rules. Deleting a pending journey releases its whole caller immediately.

Final validation passed 543 unit tests, 11 bundled-browser integration tests,
private Javadoc doclint, platform JAR structure and archive-digest verification.
Real Swing components were reviewed at 740x640 and 1100x640 after correcting
first-layout wrapping and table headers.

After the author released the Burp window, the existing extension was refreshed
through Loaded off/on. Native testing revealed host replacement of enum renderers
and list geometry; a post-theme presentation refresh fixed those details and
passed targeted controller/component regression checks, including all four
AutomaticRulesPanelTest cases. The final loaded JAR SHA-256 is
`32582ae46e50feabb2e1256b21011855aee9694493127d4e02987a83c120013c`.

Two disposable loopback journeys were imported and their automatic rules configured
in the native UI. The server log showed first, then second login, with later bearer
and shared cookies winning, both distinct headers present and unrelated cookie
preserved. Reversing the list changed the winner without another login. Disabling
one row omitted that journey's header. Temporarily detecting the fixture's HTTP
200 response invalidated only the active session; restoring 401 and sending the
next request produced a second login for that journey only. The previous request
was not replayed: five sends produced exactly five server receipts. Evidence is
`bapp/build/ordered-live/report.json`. Both temporary rules/journeys were removed,
the pre-existing journey preserved and the automatic master switch restored off.
Compact native layout, task labels, empty-list geometry and persistence across
extension reload were verified.
