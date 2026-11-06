# Full native UX test pass

Requested 2026-11-05. Burp is available and test drafts/journeys are disposable.
This matrix covers every control family, its meaningful state transitions and
input boundaries. It does not claim all mathematically possible input combinations.
Manual Burp evidence and isolated automated component checks are recorded separately.

Completed 2026-11-05 across all 38 control groups using the combined evidence
below. “Pass” means the group's finite scenarios are covered by automated tests
and the recorded manual host subset; it does not mean every boundary case was
clicked manually in Burp. Historical pending notes describe intermediate builds
and are superseded by session 7. Stress, physical vendor hardware and formal
assistive-technology testing are outside this UX pass.

| ID | Surface / controls | Required scenarios | Status |
|---|---|---|---|
| N01 | Project/User tabs, list, splitter | empty/populated, scope switch, selected identity, dirty Save/Discard/Keep editing, loading, keyboard, resize | Pass: automated checks + manual subset below |
| N02 | Header plus, empty-state plus, ellipsis | creation in both scopes; popup position, empty selection actions | Pass: automated checks + manual subset below |
| N03 | Reload selected / storage | clean/dirty, cancel confirmation, external change, invalid/unavailable store, recovery | Pass: automated checks + manual subset below |
| N04 | Delete | cancel/confirm, alias reuse, selected/new/stale identity, active login cancellation | Pass: automated checks + manual subset below |
| F01 | Display name / alias / login URL | valid, empty, malformed, case, length, active duplicates/reused aliases, URL credentials/scheme/origin | Pass: automated checks + manual subset below |
| F02 | Background browser / client certificate | both states, optional-page enable/skip, disabled data clearing, actual visible/headless login | Pass: automated checks + manual subset below |
| F03 | Proxy URL | empty/direct, valid listener, invalid/authenticated/unavailable proxy, no silent fallback | Pass: automated checks + manual subset below |
| F04 | Remember secrets | off/on, readable-storage guidance, session-only reload, complete/missing secure values | Pass: automated checks + manual subset below |
| F05 | Advanced setup / navigation and token waits | open/close; integer bounds; invalid and exact values | Pass: automated checks + manual subset below |
| W01 | Back / Next / wizard tabs | first/last, Setup validation, optional certificate skipped both ways, retained draft | Pass: automated checks + manual subset below |
| W02 | Save / Ctrl+S / Save and test | new/existing, invalid, while editing/saving/testing, late completion, save without login | Pass: automated checks + manual subset below |
| S01 | Step picker / plus | all seven types; sensible defaults; keyboard | Pass: automated checks + manual subset below |
| S02 | Step type / selectors / text / secure supplied / secret | all type pairs, irrelevant-value clearing, empty/missing/whitespace, tooltip and label association | Pass: automated checks + manual subset below |
| S03 | Load state / URL pattern / wait duration | all states, valid glob, milliseconds/seconds, negatives/fractional/bounds | Pass: automated checks + manual subset below |
| S04 | Up / Down / Remove | first/last/no-op bounds, reorder, remove only row, secret ID ownership and wiping | Pass: automated checks + manual subset below |
| C01 | Credential plus/remove/name | one/multiple, all type transitions, 16-row bound, required/duplicate names, single-value simplification | Pass: automated checks + manual subset below |
| C02 | JSON source | origin/path/JSON path valid and invalid, bounded parsing, missing/late token, selected-type tooltip | Pass: automated checks + manual subset below |
| C03 | Cookie source | URL/name/domain/path, multiple cookies, ambiguity/expiry/missing values, implicit destination | Pass: automated checks + manual subset below |
| C04 | Regex source | origin/path/start/end, valid/invalid/unsupported RE2, match ordering, boundaries, multiline/size | Pass: automated checks + manual subset below |
| C05 | Per-token destination | Disabled/Bearer/Header/Cookie, names, duplicate/conflicting destinations, hidden clearing, actual combined insertion | Pass: automated checks + manual subset below |
| C06 | Cache disclosure / maximum age / refresh skew | bounds, invalid numbers, refresh before expiry, edit/reload, complete credential-set expiry | Pass: automated checks + manual subset below |
| R01 | Recovery disclosure / enable / mode / status / RE2 | disabled/status/text/either, hidden clearing, validation, actual response invalidation and safe body bounds | Pass: automated checks + manual subset below |
| P01 | Middleware Browse / module path | choose/cancel, missing/wrong library, supported owned middleware, dialog parenting | Pass: automated checks + manual subset below |
| P02 | Slot kind/value / PIN supplied / PIN | index/ID, bounds, missing/empty/correct/wrong PIN, clearing and explicit retry | Pass: automated checks + manual subset below |
| P03 | Choose certificate / Retry listing / metadata / fingerprint | no cert/multiple/same subject/exact identity, cancel/select, stale edit, safe errors | Pass: automated checks + manual subset below |
| P04 | Allowed origins / CA PEM | valid/invalid/missing paths, redirects, strict trust/hostname/origin restrictions | Pass: automated checks + manual subset below |
| A01 | Test / Retry / Cancel / clear cache / last result | success, rejected/transport/timeout/setup failure, active/idle/cooldown, retained token, stale result, responsive UI | Pass: automated checks + manual subset below |
| I01 | Automatic enable / journey / tools / URL mode/prefix | every tool and mode, valid/invalid autosave, category independence, scope, hidden clearing, stale choice | Pass: automated checks + manual subset below |
| I02 | Request wait / attempt timeout / total timeout | exact seconds, fractions and bounds, invalid retention, cross-field relationships and unload | Pass: automated checks + manual subset below |
| I03 | Global/per-journey Unlimited and count | all four combinations, valid/invalid counts, autosave, waiting admission and release | Pass: automated checks + manual subset below |
| T01 | Import | chooser cancel, valid/invalid/oversized/UTF-8, preview edits/collision, cancel/confirm, scope and fresh IDs | Pass: automated checks + manual subset below |
| T02 | Export | no selection/dirty/stale, chooser cancel, overwrite cancel/confirm, secret omission/inclusion/missing values, permissions | Pass: automated checks + manual subset below |
| M01 | Request context menu | request/response/read-only/empty, alias/name/encoding choices, caret/selection, stale request/identity | Pass: automated checks + manual subset below |
| M02 | Actual request tags | raw/url/form/json; headers/path/query/text body; named combined credentials; unresolved/invalid stop, automatic failure warning | Pass: automated checks + manual subset below |
| H01 | Help / all tabs / disclosures | current examples, scrolling, no dead control, concise and accurate copy | Pass: automated checks + manual subset below |
| X01 | Keyboard / accessible names / tooltips | Tab/Shift-Tab, Enter/Space, Ctrl+S, focus visibility, labels, icon meaning, selected-type help | Pass: automated checks + manual subset below |
| X02 | Theme / resizing / long text / dialogs | 1280x820 and larger/narrower, scroll, clipping, native theme and parent/stacking | Pass: automated checks + manual subset below |
| X03 | Lifecycle | unload/reload via Loaded checkbox, timers/watchers/background actions, no stale updates, saved data and session-secret policy | Pass: automated checks + manual subset below |

## Findings and retests

- Baseline run initially met a locked standard Gradle report directory; isolate this pass's reports instead of deleting another process's files.

### Manual session 1

- N02/F01/W01: created qa-primary in Project, edited name/alias/login URL; Next blocked the empty URL. Valid Next retained the draft; the optional certificate page was skipped.
- S01/S02/S04: added a Click step, changed it to secure input; supplied toggle showed/hid the secret, masked synthetic input, and cleared it when disabled/re-enabled. Removed the only step successfully.
- W02/A01: Ctrl+S saved with zero token endpoint hits. Test login completed against owned fixture 127.0.0.1:64773; safe success/cache state shown. Clear cached token removed it; Save and test is being checked.
- UI defects found: ineffective Up/Down controls at step boundaries, centered secure-value checkbox, encoding issue in saving-status text. Fixes applied; awaiting rebuild/retest.

- A01/W02: Save and test succeeded after cache clearing; navigation and maintenance stayed responsive during the login.
- T01/X02: Import opened a native file chooser centered over Burp; Escape cancellation is being checked.

### Manual session 2

- T01: malformed JSON was rejected with a syntax/duplicate-fields/value-types message; preview Cancel preserved the list. Confirming the valid four-journey fixture added qa-success, qa-slow, qa-reject and qa-missing without replacing the existing selection.
- A01: qa-slow with a 2-second token wait failed safely with a missing-credential message and paused retries. With 30 seconds, Cancel stopped the active browser wait and showed the cooldown; explicit Retry succeeded after the fixture's 15-second delay. The UI remained responsive.
- I02/I03: invalid 0.5-second request wait was rejected; 61.5 seconds autosaved. All four finite/Unlimited combinations were exercised (global 5, per-journey 2), fields disappeared when Unlimited was selected, and both limits were restored to Unlimited. This uncovered internal-key/millisecond error copy, now fixed pending rebuild.
- I01/M02: automatic injection selected qa-primary and an owned URL prefix. A request through the real Burp listener to /protected returned 200. Disabling automatic injection made the same untagged request return 401.
- M01/M02: the real Repeater request context menu offered saved aliases and Raw/URL component/Form value/JSON string content. Choosing Raw inserted <@qa-primary/> at the caret. Sending the explicit tagged Authorization header while automatic injection was disabled returned 200 (accepted).
- Additional feedback defects: clean journeys always displayed the save-before-testing hint, and successful Retry left an old cancellation message in the global status area. Both fixed pending rebuild/retest.
- Isolated component checks: all 49 ordered step-type pairs, nine ordered credential-type pairs, stable step reordering/removal, credential source limit and destination reselection pass. Re-selecting an unchanged credential type/destination previously erased values; regression fixed. Thirty exact-duration/boundary/malformed settings cases pass, plus the save-hint state test. These are local Swing/component tests, separate from installed Burp evidence.

### Automated session 3 (historical checkpoint)

- UxControlMatrixTest now covers every HTTP-tool subset (32), every recovery-mode transition (9), independent Unlimited modes (4), setup name/alias/URL/proxy boundaries (23), numeric settings and journey boundaries, source/step transitions, source-count bounds, maintenance availability, and late draft-validation feedback.
- UxRequestMenuTest covers both named credentials and all four encodings for caret/selection insertion; response/list/empty/read-only contexts; invalid offsets. Existing NativeTagPipelineTest covers stale request/identity rejection and complete raw-message resolution/drop behavior.
- UxDialogFlowTest exercises real controller storage actions with finite local dialog decisions: Browse choose/cancel; import cancel/malformed/UTF-8/size/kind/collision repair/fresh identities in both scopes; export cancel/dirty/secret inclusion and omission/missing secrets/overwrite; deletion and pending-login cancellation; reload confirmation and session-secret loss. These simulated dialog decisions do not replace manual dialog checks.
- Added real-SoftHSM/local-Swing certificate-picker integration: two identical subjects with distinct fingerprints, selecting row 2 copies its exact SHA-256 and public details; Cancel preserves the prior fingerprint; an unavailable module gives safe guidance. No vendor/user token store is used.
- Further confirmed fixes: disabling client certificates clears old displayed metadata; HTML-looking journey names remain literal; saved-only maintenance actions disable without a saved selection; deleting a journey resets the phase immediately; pending validation cannot overwrite a later Save/Test/native-action result; step creation stops at the existing 256-step model bound and re-enables after removal/clear.
- Manual export of qa-slow produced a valid one-journey export with no secrets. The Save chooser was centered over Burp.
- The extension was unloaded through its existing Loaded checkbox before rebuilding. Restarting the disposable Burp session with SOFTHSM2_CONF for the owned fixture reached a license-activation screen. The user was asked to complete activation and open a temporary project; no authentication/license dialog has been automated. Live-window testing is awaiting that handback while local checks continue.
- Latest verification: 480 unit/component tests, 8 SoftHSM integration tests, and private-member documentation validation passed with zero failures or skips. The earlier browser run passed all 11 tests; subsequent production changes are confined to Swing behavior. The Windows development JAR was rebuilt and its embedded browser-asset structure/digest verified.
- The matrix remains open. Do not report this as a complete manual Burp pass. Remaining manual work includes current-JAR retests, Project/User and dirty-navigation dialogs, full credential/recovery forms, certificate controls, file cancel/overwrite/secret flows, named/encoded request menu choices, resizing/keyboard/tooltips/help, and unload/reload checks.

### Historical build checkpoint (superseded by session 7)

- JAR: `bapp/build/libs/browser-powered-session-handler-dev-windows-x64.jar` (307104413 bytes).
- SHA-256: `cbd8126fc0eae0bcb3707f43aa5d4381ab502f85ad1e1053c75d0f99f2e82a1f`.
- The rebuilt JAR has not yet been reloaded into Burp: the restarted host is awaiting user-completed license activation. Continue by opening a temporary project, turning the existing extension Loaded checkbox on, and executing the remaining manual checks above. Do not count the isolated Swing/native picker test as a manual Burp picker test.
- The owned HTTP fixture was stopped while waiting for activation; restart `bapp/build/ux-qa-fixture.py` and regenerate/update imported fixture origins before resuming HTTP checks.

### Manual session 4: resumed after activation

- Burp 2026.10.1 opened a fresh Temporary Project. The existing development extension was loaded via its Loaded checkbox; there was no remove/re-add.
- Actual compact window is approximately 982x1116 physical pixels. Empty Project/User collections and the empty-state plus work. Saved-only Reload/Export/Delete items disable correctly without a saved selection. Escape dismisses the menu.
- Created a User draft with the empty-state plus. Keep editing preserved the User tab/draft. Save-before-navigation rejected a missing login URL, focused that field, and retained the draft. After correcting the URL, the User save uncovered a host-specific filesystem defect.
- User Save and User import both failed when reopening a newly created private temporary file for writing (AccessDeniedException); the prior library remained preserved. Direct probes of the same operations under JDK 21 and Burp's JRE 26 succeeded outside the host. A read-only host-property check confirmed Burp's user.name differs from the actual OS account. Private ACL creation had trusted that mutable property. The library and browser-cache/export creation paths now resolve the native Windows account with NTSystem instead. A regression with an intentionally invalid user.name passes. No existing permissions or library data were changed.
- Save failures now identify their fixed storage stage and exception category without raw exception messages, and do not suggest restoring a backup for an access-denied write.
- The import preview extended past the left/right edges of the compact host window. Confirmation previews are now bounded to their parent and plain-text confirmations wrap. Component tests pass; real-dialog retest is next.
- Owned loopback fixture restarted: see bapp/build/ux-qa-fixture/manifest.json for current origin/PID. Additional all-journeys.json contains JSON+multiple cookies, regex, all retained step kinds, and the owned SoftHSM certificate journey; user-journey.json supplies a single User import. These files contain synthetic test secrets and must not be logged.
- Account/preview fixes rebuilt with private documentation validation; current real-host retest pending. The former 480-test count is historical; additional regressions will be included in the next full run.

### Manual session 5: combined credentials, native picker and navigation

- User import and subsequent Ctrl+S edit both succeed in the real Burp host after the native-account ACL fix. `<html>UX 中文` renders literally in the sidebar; clean state and saved feedback are correct.
- Project import of all eight owned journeys fits the compact dialog and succeeds. The two JSON plus two cookie journey captures its complete credential set; regex extraction also succeeds. The all-step journey preserves masked values when reordered and executes all retained step kinds after saving a fractional-second wait.
- Real certificate listing succeeds against the owned SoftHSM module. Two same-subject certificates remain distinct by serial/fingerprint; selecting the second copies that identity. Retry listing works; Escape cancellation preserves the selected fingerprint. After extension reload, the unremembered PIN is absent while the saved fingerprint remains.
- Added a wrapping public-details area to the picker because compact table columns truncated identity metadata. Real Burp retest passes: all five metadata values, including the complete SHA-256, are visible before confirmation and follow the selected row.
- Nested session-recovery scrolling clipped its controls on the Token page. Removed the inner scroll pane; real compact-window retest exposes status and expression together in either-condition mode. Empty and unsupported expressions reject the draft; valid input permits Save-before-navigation.
- That Save-before-navigation test found a sidebar/editor mismatch: the newly opened journey was displayed while the previous row stayed highlighted. Save and Discard regression cases reproduce it and pass after synchronizing selection in open(). This latest fix awaits real-host reload/retest.
- Long failure guidance appeared in a one-line last-result box and scrolled past its start. Added a font-sized five-line viewport after host theming and reset the caret when results change; real-host retest pending. Unsupported recovery syntax now gives RE2 correction guidance without a parser-position disclaimer.
- Settings remain responsive during rejected authentication. Invalid attempt timeout 0 shows seconds-based guidance with the visible field name; correcting it to 60 autosaves. Tab and Shift+Tab move between duration fields. Help displays current raw/named/wrapper examples and all guidance fits the compact host.
- Explicit certificate export with secret inclusion succeeds through the real Save chooser. Its single journey contains the synthetic mtlsPin, Remember secrets remains false, and the output ACL has one private entry. No secret value was printed during verification.
- Last complete suite before the navigation/result refinements: 484 unit/component tests, 11 browser integration tests and 8 SoftHSM integration tests, zero failures/errors/skips; documentation validation passed. Focused navigation/recovery/dialog tests pass after the new refinements. A final full run is still required.

### Manual session 6: request acceptance and final refinements

- Real Repeater context-menu navigation works with the keyboard through journey, credential name and encoding. qa-combined -> csrf -> Raw inserts the literal named reference at the caret.
- An actual Repeater POST to the owned verifier used raw/named references and URL/form/JSON wrappers across URL path, query, Authorization, cookies, another header and JSON body. It returned 200 only after all six server-side checks passed. Automatic injection was disabled during this request.
- Configured qa-success with the explicit proxy http://127.0.0.1:8080 and automatic injection for all HTTP tools/all requests. A cold ordinary request through that actual Burp listener returned 200 in roughly 1.5 seconds: the browser login traversed the same listener without re-entering authentication. The UI remained responsive.
- Switching automatic selection to qa-missing caused the original unauthenticated /protected request to reach the fixture and return 401. Burp's extension Errors view logged that the unchanged request was sent, identified the missing credential and advised checking the response filter/cookie selectors. Automatic injection was then disabled again.
- An unresolved explicit tag while automatic injection was disabled was stopped. Burp returned its own no-response error page (HTTP 200 is Burp's generated page status, not the origin's acceptance); the extension logged Request was not sent and alias-repair guidance. No credential values appeared in diagnostics.
- Save-before-navigation and Discard-before-navigation both now pass manually: sidebar selection, display name, alias and phase agree with the journey opened. Back from Test skips disabled client-certificate setup.
- Additional source creation/removal and JSON-to-cookie switching pass manually; conditional names/fields appear and the original regex configuration is preserved. Discarding the draft while switching Project/User preserves the saved User fixture.
- Reload selected opens the saved journey; storage-reload and delete warnings are parented/wrapped. Delete cancellation preserves the saved fixture. Positive deletion, retirement and pending-login cancellation remain covered by the isolated controller/storage tests.
- The first result-height refinement failed its compact real-host retest. A new recursive layout check reproduced minimum-height collapse at narrow editor widths. Preferred width now flexes and minimum height retains five font-sized lines; local 320/450/650-pixel editor checks pass. The corrected JAR is rebuilding for manual retest.

### Manual session 7: final build and closure

- The corrected last-result viewport passed its compact real-Burp retest: multi-line failure details and recovery guidance remain visible and start at the beginning. Visible-browser login also succeeded, complementing the background-browser runs.
- Switching journeys had retained the previous form's scroll position and feedback. Opening a saved journey or creating one now resets form scroll positions, and opening a journey identifies it in the feedback. Save/Discard regressions include old scroll and PIN-warning state. The final installed build passed manual navigation from a scrolled certificate journey to qa-success: display name and alias are visible at the top, sidebar/editor agree and feedback says Loaded qa-success. New journey also starts at its first field; discarding that disposable draft returns correctly to qa-combined.
- The final build's Setup and combined-credential form were inspected at 2560x1380, complementing the compact 982x1116 walkthroughs. Scrolling retains access to the long credential form while navigation/actions stay available.
- Switched Burp from Dark to Light, inspected combined-credential fields, selection, enabled/disabled icons and the five-line result area, then ran a fresh successful combined JSON/cookies login. Restored Dark and the compact window. Theme changes retained the literal names, readable controls and result height.
- Final unit/component run: **487 tests, zero failures/errors/skips**. The most recent browser integration run passed **11 tests** and owned SoftHSM integration passed **8 tests**, also without skips/failures. Subsequent changes were confined to Swing presentation/navigation and safe RE2 feedback. Private-member documentation validation and JAR browser-asset structure/digest verification passed.
- Positive delete/retirement, pending-login deletion, external storage races, overwrite confirmation and exhaustive numeric/type/tool combinations are covered by isolated real-controller/domain tests, with finite dialog decisions. They are not represented as positive manual host operations. The real-host subsets include parented file dialogs, import preview/cancel/confirm, export with and without secrets, delete cancellation, dirty navigation, certificate selection and the actual HTTP acceptance checks in sessions 4–6.
- No unresolved defect remains from this control matrix. Final self-review used the incumbent Swing design and the archived critique findings; it does not claim a new independent reviewer or formal accessibility certification.

### Final build checkpoint

- Loaded in Burp via the existing **Loaded** checkbox: `bapp/build/libs/browser-powered-session-handler-dev-windows-x64.jar` (**307106813 bytes**).
- SHA-256: `1183533fa0b98809279175497ca57e7fe5120f7755d928eff6cafa6e140a8244`.
- Automatic injection is disabled. The saved synthetic journeys remain available; their loopback services are stopped after verification. Unremembered PINs are not persisted. No release artifact was replaced and no commit was created.

### Session 8: unified status and per-journey event dock

- Follow-up author direction replaces the phase/message/test-result outputs with one compact current-status bar and a collapsible per-journey Event log dock inspired by Burp's bottom Event log. The tab, credential labels and settings feedback now say Session handling.
- The event dock provides Time/Type/Message, Info/Warning/Error toggles, literal search, selected-event detail, resize, close/reopen and per-journey clear. Histories use stable scope/UUID keys, survive alias edits within this session, and exclude credentials/raw requests/raw browser exceptions. Retention is bounded to 200 events per journey and 4000 overall; unload clears the history.
- The coordinator records queued/started/successful login, delayed retry, terminal failure, cancellation, cache clearing and session invalidation directly. Automatic acquisition is tested without any UI polling. The controller adds safe Save and validation/setup failures to their captured journey owner.
- Manual Burp checks on the loaded build: combined JSON/cookie login records queue/start/success; missing-token login records Error with full corrective guidance; severity filtering shows the no-matching-events state; literal search narrows the rows; switching journeys retains the open dock but shows only that journey's history; resizing, closing and reopening retain layout/history. The separate Test result box and permanent bottom message box are gone.
- The first compact host render exposed a narrow detail pane and truncated timestamps. The final render uses a 65/35 initial split and host-font-sized metadata columns; both timestamp and recovery guidance are readable at 982x1116. Clear history, bounds, stable ownership, retry/cancellation and literal HTML rendering are also covered by isolated tests.
- The full suite passed 498 tests before the last layout regression was added. The final focused UI/event/transport run passed 249 tests, with documentation and JAR asset validation. A subsequent 499-test whole-workspace run overlapped concurrent diagnostics/cache/traffic-guard cleanup edits and had four failures; those are being checked against the latest source and must not be represented as a clean whole-workspace run.
- Loaded through the existing checkbox: `bapp/build/libs/browser-powered-session-handler-dev-windows-x64.jar`, 307129609 bytes, SHA-256 `82fe9f32698a8d892de00b940975805d65347a3a95550d2f504ddf1395750b56`. This supersedes the session-7 JAR checkpoint.
- Rechecking all four affected suites (AuthTrafficGuardTest, BrowserAssetsTest, DiagnosticsTest and NativeTagPipelineTest) against the latest concurrent cleanup source passed all 73 tests, together with documentation validation. The earlier four failures are resolved; this rerun is separate evidence from the historical full run. Burp was released back to the user after the dock checks, with the verified JAR loaded and the log available for review. The owned loopback fixture was stopped after verification.

### Session 9: remove alias retirement

- Author direction: journey/tag naming is the user's responsibility. Removed retired-name reservations and the Reassign checkbox/help entirely. Rename/deletion frees a name immediately in either scope; only active case-insensitive duplicates remain blocked. Internal UUID/generation protections for stale work remain in place.
- Older managed files still parse with their original retirement metadata, but resolution/edit/import ignore it. New writes emit the compatibility field as an empty array. Updated the active design, product context, README, delete feedback and validation guidance.
- Regression coverage verifies rename/reuse across Project/User, duplicate-active rejection, deletion/recreation with a different UUID, rejection of obsolete identities, legacy records that overlap an active alias, write-time removal of old metadata, and controller Save without any reassignment acknowledgement. Delete/cancellation tests now expect the alias to be free.
- Full unit/component suite: **520 tests, zero failures/errors/skips**; native documentation validation and packaged browser-asset checks passed. Manual Burp check of the rebuilt Advanced setup shows only navigation/token-wait controls and no reassignment option.
- Loaded development JAR: `bapp/build/libs/browser-powered-session-handler-dev-windows-x64.jar`, **307126313 bytes**, SHA-256 `2141723e299cb24a6b3916f456e7c75b11e1f3ef2e8cf8cd220f4d192563d11d`. This supersedes the session-8 checkpoint. No release or commit was created.

### Session 10: selected-journey cache inspection

- Added Current cache immediately to the right of Event log. Both buttons switch the same resizable dock. The cache view shows the selected saved journey's existing usable tokens and cookies, configured names, full selected value, acquisition time, expiry and refresh time. Inspection does not start authentication.
- Values are read-only and remain outside event messages, persistence and exports. Closing the view, switching to the log, losing the saved selection, changing identity or unloading clears its displayed credential references. Combined extraction lists each configured output once.
- Six focused component/controller tests cover combined and single-cookie output, literal HTML-looking values, identity isolation, clearing, read-only fields, mutually exclusive toggles, inspection without acquisition and credential-free event messages. The complete unit/component suite passed **537 tests, zero failures/errors/skips**; native documentation and packaged browser-asset validation passed.
- Manual checks in Burp 2026.10.1 at 1280x1380: no-selection button disabled; empty-cache inspection did not start login; an explicit test login against the owned loopback fixture populated two tokens and two cookies with readable metadata; selecting a row updated the full value; switching to another journey cleared all prior values/metadata; switching back restored the existing cache without another login. Explicit cache clearing emptied the open view. Event log/cache switching, close and reopen all used the same dock and retained readable layout; events contained no credential values.
- Rebuilt and loaded via the existing Loaded checkbox: `bapp/build/libs/browser-powered-session-handler-dev-windows-x64.jar`, **307147796 bytes**, SHA-256 `819332e0acb001a56d9215b4ba155c7bb0654b3db0ef7271c84747ab58b19d0f`. This supersedes the session-9 checkpoint. No release or commit was created.

### Session 11: cache context actions

- Removed the Selected value pane. The cache table now spans the dock, with most width allocated to values. Every token/cookie row offers Copy name and Copy value through right-click or Shift+F10. Token names use their configured names; cookie names use the actual cookie name, without the display alias decoration. Values are copied in full. No explanatory context-action tooltip remains.
- Clipboard access happens only on explicit Copy. Confirmation and clipboard-access failure guidance use the existing status bar without credential text or raw exceptions. Empty/cleared selection disables both actions; clearing closes any open menu and releases its rows.
- All **9 cache component/controller tests passed**, including both copy choices for tokens/cookies, long untruncated values, clipboard failure, selection/invalidation, keyboard bindings and the removed split pane. Documentation and packaged browser-asset validation passed. The latest whole-workspace run discovered **542 tests with one failure**: the library-import dialog test timed out waiting for background feedback. This is separate from the passing cache tests and is not a clean full-suite result.
- Manual Burp check at 982x1116 confirmed the full-width table, right-click selection of a different row, both menu choices, keyboard opening, and safe copy feedback. System clipboard assertions verified the token name and the actual cookie name/value against synthetic fixture values. The owned loopback fixture was stopped afterward. The final tooltip-only cleanup was rebuilt and refreshed through the existing Loaded checkbox.
- Development JAR: `bapp/build/libs/browser-powered-session-handler-dev-windows-x64.jar`, **307173502 bytes**, SHA-256 `a916334a087ec5874905b2a5ef03f7fa51e259b7e11fe48c9722f5a9805f26e7`. This supersedes the session-10 checkpoint. No release or commit was created.

### Session 12: dock headings, concise setup and generated journey tags

- Removed both repeated dock headings (Event log/Current cache plus journey alias). Event log Close shares the filter/action row; cache Close shares the metadata/empty-state row. Journey ownership remains available to assistive technology.
- Moved the Remember secrets persistence explanation from its permanent paragraph into the checkbox tooltip and accessible description. Advanced setup navigation timeout and token wait now display/accept seconds, with exact fractional-second conversion to the existing millisecond storage format. Bounds and invalid-input guidance use seconds too.
- Per author direction, the editable journey name now generates a read-only request-tag preview. Every name edit derives a new lowercase portable alias, committed on Save. Existing request text is not rewritten. Opening an existing/imported journey and unrelated edits preserve its recorded alias until its name is edited. Active generated-tag collisions across Project/User reject Save and ask for a different journey name; import's existing reviewed alias-repair flow is retained.
- Added naming coverage for normalization, Unicode-only fallback, bounded aliases, live preview, saved rename/reopen, preservation of legacy aliases on unrelated edits and cross-scope duplicates. Updated numeric boundary tests for seconds, fractions, sub-millisecond rejection and exact reopen, and adjusted older rename expectations to the selected behavior. The final full unit/component suite passed **547 tests, zero failures/errors/skips**, with private-member documentation and packaged browser-asset validation.
- Inspected the freshly generated isolated Swing Setup preview: one editable name, a literal request-tag preview, no permanent Remember secrets paragraph and retained Advanced setup disclosure. This is component-render evidence, not a new manual Burp pass. The user stopped Computer Use with physical Escape before the first heading refresh; no subsequent Burp inputs were sent. The newer changes have not been loaded into Burp.
- Ready candidate: `bapp/build/ux-rename-preview/browser-powered-session-handler-dev-windows-x64.jar`, **307175306 bytes**, SHA-256 `e2641709878b8dbc660a8be319e12615d9f9d5426eb0446e3fd9c6b9cf3be47f`. The standard loaded JAR was not replaced. No release or commit was created.

### Session 13: Journey cache naming and toolbar without status text

- Renamed the cache toggle to Journey cache. Removed the toolbar's text-output component entirely: authentication states, loaded/saved notices, waiting counts and confirmations no longer appear between its dock buttons and contextual action icons. Internal controller/accessibility state remains separate from visible text.
- Successful clipboard actions have no status confirmation. Clipboard failures append a safe warning to the selected journey's Event log; copied names/values remain excluded.
- Reused the three focused existing suites: **23 checks, zero failures/errors/skips**. Documentation validation and JAR structure/archive verification passed. No parallel lab, fixture set or full acceptance suite was added or run.
- Inspected the isolated native toolbar render at `bapp/build/ui-previews/journey-toolbar.png` after supplying authentication, load and error messages: only Event log, Journey cache and the contextual icon are visible. This is component-render evidence; Burp was not refreshed.
- Ready candidate: `bapp/build/ux-rename-preview/browser-powered-session-handler-dev-windows-x64.jar`, **307187910 bytes**, SHA-256 `4806917915d80305dbaa53726484eb03616e918b19abe79dacf9b9b16cb36f8e`. No installed JAR replacement, release or commit was performed.

### Session 14: retain each journey's wizard step

- Each journey remembers its displayed wizard page by scope and stable UUID for this extension session. Switching journeys or main tabs preserves it; Project/User tabs reopen their last selected journey at its remembered page. New journeys start at Setup. If a saved certificate page becomes unavailable, reopening uses the preceding enabled page.
- Loading another journey cannot overwrite its remembered page with the previous form's state. Deletion and unload release the associated view state. This navigation state is not exported or persisted as journey configuration.
- Reused the existing native editor suite: **20 tests, zero failures/errors/skips**, including independent Project/User identities with the same UUID, collection/main-tab navigation, new-journey creation and optional-page fallback. Private-member documentation and packaged JAR/archive verification passed. No duplicate lab, acceptance or stress suite was introduced.
- Overlapping builds removed intermediate compiled outputs during the first checks. The successful run used an independent Gradle project cache and output directory. Ready candidate: `bapp/build/ux-step-memory/libs/browser-powered-session-handler-dev-windows-x64.jar`, **307247105 bytes**, SHA-256 `2d3285c7cdb7c24d2f1db1a6c04188cb96b80c51c66f6fc7fec876e76e620c48`. Burp was not refreshed, and the installed JAR was not replaced. No release or commit was created.
