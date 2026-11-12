# Native Burp journey editor

## Authority and native system

This contract defines the maintained guided-wizard interface. Burp's Swing theme, fonts, semantic UIManager colors, focus and
selection states remain authoritative. Use 10 px outer insets, 8 px major gaps,
and 5-6 px within groups. Forms track viewport width and scroll vertically.
Review at 1280x820 and larger windows. No browser-rendered UI or decorative palette.

## Journey navigation

Project and User tabs above the journey list select its collection and the
destination for creation/import. The list shows name and alias without scope
prefixes. Plus and ellipsis actions sit together at the bottom-left of the header,
below the Project/User tabs and directly above the list. There is no sidebar
heading. The maintenance menu opens below its button.
There is no separate storage chooser. Autosave journey edits after 500 ms
without changes. Before switching collection, selecting another journey, creating
another journey or executing, flush the latest edits and wait for commitment.
Plus immediately creates a persisted journey with a unique default name. Incomplete fields save and reopen literally; show configuration errors only
when execution is requested, before browser setup. Alias collisions also remain
editable and block execution rather than saving.
Save activity appears only in Event log: coalesced Info creation/success, Warning
for a temporary failure with a pending automatic retry, and Error when saving
stops. Do not show Saving/Saved/Unsaved notices or a separate save-status widget.
Retain stale-storage guidance when external changes require a reload.

The list supports Ctrl/Shift multi-selection within the current collection. One
selected journey opens its editor; several show a selection count and batch-action
guidance. Background list refreshes preserve the selected set. Delete selected
reviews the full set in one confirmation and performs one revision-checked write;
it cancels authentication only for removed journeys and preserves unselected
journeys and drafts. Export selected includes the whole saved selection.

With one journey selected, Duplicate selected in the maintenance menu flushes
pending edits, saves an independent copy in the same collection and opens it.
The copy receives fresh journey and step identities and a unique name and
derived tag alias. Unfinished settings and configured session secrets are copied,
including popup step references; Remember secrets is off for the copy. Cached
tokens, cookies, event history and automatic session-handling rules are not copied.

Import accepts several export files in one chooser. A single review table has an
Import checkbox, journey name, source file and editable tag alias for each row,
plus Select all/Select none and a selected count. Import only the checked rows,
validate the complete batch before writing, and allocate fresh identities and
session-only imported secrets. Row identity includes both its source file and
source UUID, so matching source aliases or IDs in different files can be edited
independently. Sorting the table must preserve those row identities.

Import and Export share the last visited folder through Burp user preferences,
including navigation followed by Cancel. The location survives extension and
Burp restarts; middleware browsing uses its own chooser. There is no Reload
storage command. Startup loading and user-library observation remain internal;
Reload selected only restores a saved journey into its editor.

## Wizard

1. Setup: display name, login URL, background mode, **Allow untrusted HTTPS certificates** (off by default), an Authentication methods group with independent **Use form-based authentication**, **Use a client certificate (PKCS#11)** and **Use HTTP authentication (Basic or NTLM)** checkboxes,
   optional proxy URL, Remember secrets. Its persistence explanation is a tooltip
   on the checkbox, without a permanent paragraph below it. Advanced settings remain collapsed.
   Browser action timeout and final capture wait are entered in seconds, including
   exact fractional seconds, and retain milliseconds only in the saved format.
   Certificate bypass applies to this journey's recording and login browser only; the client-certificate transport retains its separate Trusted CA verification.
   Form-based authentication is selected for new journeys. Its checkbox controls
   Login steps; disabling it retains saved steps but skips their execution and
   required step secrets. Capture credentials stays available with every method.
   Test & use and the Test login action are visible only when at least one method
   is selected. With none selected, Setup asks the user to choose a method and
   retains the unfinished journey. Certificate and HTTP pages follow their own
   checkboxes. Existing journeys infer the form-based choice from their steps and
   other configured methods when the saved choice is absent.
2. Client certificate: optional page, enabled from Setup. Show only Middleware
   file initially. After the middleware path is entered, discover devices in the
   background without a PIN. Automatically select a sole device and display its
   name; multiple devices use an inline native dropdown with Choose device as
   its unselected prompt, readable names and serial numbers. A Refresh devices
   icon beside it handles connections changing. There are no manual slot fields.
   Reveal PIN, Choose certificate and Advanced settings only after a device is
   selected. Choose certificate only lists that device's certificates; it never
   discovers or selects a device. Hide the Selected certificate label and value
   entirely until the current editor has loaded an actual selected certificate;
   show no saved-selection placeholder instructions. Changing middleware
   or device clears the previous certificate and PIN. Late discovery results
   cannot update another middleware selection or journey. The HTTPS Login URL's
   server receives the selected certificate automatically when requested. Advanced
   settings group Additional authentication servers and the optional Trusted CA
   file. Both fields have task-oriented tooltips; Trusted CA explains adding a PEM
   CA file for a server certificate that is not already trusted.
   Certificate selection leads with readable name, organization/email where
   available, issuer and validity dates; technical identifiers are expandable.
   Listing has a busy state; Retry appears only for an established PIN recovery
   condition. Empty listings have inline feedback. Inspect saved certificate is
   available only after a successful selection in the current editor, while its
   PIN and device remain configured. Reload, PIN edits, device changes and failed
   reads clear that availability; a saved fingerprint alone cannot restore it.
   Explicit saved-certificate
   inspection does not replace the pinned identity. Show only additional servers in
   the editor; normalize the HTTPS Login URL's server into the saved allowlist.
   Advanced settings start collapsed, including when extra servers or CA files
   are saved. Expand them on request or to reveal a validation error.
   HTTP Login URLs require an explicitly configured HTTPS authentication server.
   The optional CA picker remembers its own folder.
3. Login steps: source action picker and plus; numbered stable steps with native
   move/remove icons. Record in browser is an icon action with a tooltip and
   accessible name. Duration help belongs to the duration field's tooltip.
   Recording review names omitted browser interactions when known and explains
   that their numbers are independent of step numbers. Partial recordings,
   missing values and unresolved popup relationships can replace the captured
   rows as an editable draft. Finish them in Login steps; Test login validates
   before execution. Replacement remains one undoable edit.
   Empty sequences ask the user to add the actions needed to sign in. Explain
   that zero steps applies only when opening the URL returns credentials without
   further interaction. Group Interactions, Waits, Controls, Pages and Frames in the picker. Use one expanded
   row with compact action/selector summaries for the rest; exclude entered text
   and secrets from summaries. Adding reveals and focuses the new row.
   Alt+Up/Down moves, Alt+Delete removes, and the Undo icon (tooltip and Alt+Backspace) restores a
   structural edit without overwriting edits to other rows. History is bounded
   and session-only, and its secret buffers are wiped on discard/navigation.
   Duration uses seconds, including exact fractional seconds. Legacy unfinished
   drafts retain their unit; executable storage remains milliseconds.
   Browser load options have readable captions. URL waits offer Exact URL and
   URL pattern; element waits offer Visible, Hidden, Present in page and Removed
   from page. Legacy defaults remain compatible.
   Enter secret always shows its masked input; missing versus explicitly empty
   values are tracked internally without a Provide a secure value checkbox.
   Every action has its own concise tooltip on the hovered list item before selection,
   in the Add picker and each row. Keyboard highlighting exposes the same help.
   Hovering never selects an action or saves the draft. Use the exact copy in
   [browser recording](browser-journey-recording.md#action-picker-tooltips-and-wording).
   Checkbox/radio steps choose Checked or Unchecked; new rows require a choice.
   Dropdown options use an editable value list with Add/Remove, preserving an empty
   list separately from an empty value. Press key offers Enter, Ctrl+Enter, Tab
   and Shift+Tab in a native selector. The compact summary names the selected key.
   Frame steps enter one embedded frame, leave one level or
   leave all frames. Page steps declare a popup before its next opening action,
   select the initial tab or a declared popup, and explicitly close the current page.
   No automatic context fallback follows a closed page or detached frame.
   Field guidance explains selectors, seconds, URL modes, option values and popup
   names even after typing. Popup references use native choices and retain missing
   references as invalid drafts for correction.
4. Capture credentials: one or several JSON-response/regex/cookie sources, added with plus. Multiple
   sources require unique user-defined token names.
   Credential-name tooltips explain the 1-64 ASCII character format and case-insensitive
   uniqueness. Validate names on leaving the field, then update shown errors as names
   change, including duplicates affected by other rows. Test login and Copy token
   reference reveal the first invalid name. Autosave retains unfinished input.
   Each source shows only its applicable fields, captions and explanations. Source changes clear irrelevant
   selectors. JSON path help gives a short dotted-key/array-index example; cookie
   help describes capture and replacement of the same named cookie. Regex sources use the
   same response-origin/path filters as JSON and expose Start regex and End regex.
   Each response-token row owns its automatic-injection destination and shows a
   destination-name field only for Header or Cookie. Captured-cookie rows explain
   that automatic injection replaces their original cookie names.
   New sources start blank. Expandable named rows separate Capture from browser
   from Use on matching requests for JSON/regex tokens. Cookie rows omit that
   box and its explanatory sentence. The Cookie name label and field share a tooltip
   explaining that the captured value replaces the cookie with the same name in
   matching requests; the Cookie source selector has no tooltip. Credential groups retain their existing structure with
   12 px inner side/bottom padding, 12 px field spacing, 12 px below the credential
   header and 16 px between capture and injection boxes. Optional cookie filters collapse unless saved
   values need them. Multiple sources reveal naming guidance and focus a newly
   required name. Once exposed, the name field stays editable when other sources
   are removed, including while its text is cleared and retyped. Reloading a named
   single source also keeps its name field visible. Existing JSON/origin tooltips remain sufficient. Cookie sources
   use Capture URL with task-oriented help: a page where the cookie is available
   after signing in. Avoid storage/filtering implementation details in the tooltip.
5. Test & use: separate Test login and Use in requests groups. Test login has a
   visible label. Clear cached credentials is a trash icon with an accessible
   action name and a tooltip explaining that it clears this journey's cached
   credentials and HTTP authentication sessions. Explicit testing preserves the
   current dock view and highlights Event log for new test activity instead of
   opening it. Opening the log clears that journey's highlight;
   failed actions carry their exact saved generation and stable step ID, with
   Go to step available only while that generation remains current. Capture that
   ends response-only execution early explains skipped remaining steps in the log.
   Cookie-based journeys complete all configured login steps before accepting
   captured credentials, including when the login page already sets a session cookie.
   When an explicit Test login or Retry succeeds, show a native result dialog
   naming the journey and the captured token/cookie names and count. Errors with
   an identified field, settings group or step instead reveal that location and
   show specific inline guidance, without an error dialog. Generic errors without
   an associated UI location may use a popup. Focus the identified field; when a rejected
   account cannot be narrowed to a field, show the observed error at the HTTP
   authentication group. Background validation never changes page or focus.
   Captured values remain in Journey cache. Refresh the completed controls before
   opening a result dialog. Automatic authentication
   stays non-modal. Do not show obsolete results after editing, changing journeys,
   cancelling the test or unloading the extension; unload dismisses an open result.
   Copy BPSH tag offers named credentials and explicit encodings without
   logging in or reading cached values. HTTP-only journeys instead show
   Copy HTTP authentication header, which copies directly without a format menu.
   Mixed journeys include HTTP authentication header as a menu choice, followed
   by formats for their configured captured credentials. The HTTP settings show
   the custom header using the current journey's tag name and explain that it
   triggers HTTP authentication for that request and is removed before delivery.
   Allowed-origin syntax and scope live in tooltips on the input and its label.
   Browser certificate-check guidance is the checkbox tooltip; proxy connection
   and unsupported proxy-authentication guidance is the Proxy URL tooltip.

Back/Next are arrow icons and skip the disabled certificate page. There are no
Save or Save and test controls. Test login flushes the latest edits before
execution. Shared Cancel remains available during active authentication. Ctrl+S
flushes or retries autosave; creation uses plus. Icon
buttons have tooltips, accessible action names, native focus and theme colors.
The vector family uses an 18 px canvas and consistent 1.7 px rounded stroke.
Tabs and arrow navigation permit incomplete settings consistently. Validate on
execution, and omit redundant numeric page progress when certificate setup is
optional. A contextual name-edit explanation states the reference consequence.

## Credentials and request insertion

A login succeeds after all configured JSON/regex/cookie values have arrived. Named
credentials share one cache publication, cancellation and earliest expiry.
A single value uses <@employee/>; several use <@employee token="access"/>.
Encoding wrappers are <@url>, <@form> and <@json>, without a bpsh: namespace.
Other Hackvertor tags are the user's responsibility; all tag-like source notation
is handled by this extension.

In an editable request, Add authentication token offers saved journey aliases,
then token names when necessary, then Raw/URL component/Form value/JSON string
content. Insert the literal reference at the caret/selection; never copy the
credential value. Recheck both the identity and request bytes before insertion.
Automatic injection maps each JSON/regex token independently to Disabled, Bearer,
a named Header, or a named Cookie. Disabled tokens remain available through tags.
All captured cookies are written under their original names. Reject duplicate
header destinations case-insensitively (Bearer targets Authorization) and duplicate
cookie destinations case-sensitively, including captured cookies. A Header named
Cookie must use the named Cookie destination instead. Cache lifetime remains shared
under the Token cache disclosure, separate from these per-source destinations.

Regex extraction reads a bounded UTF-8 response body (1 MiB), using bounded RE2
start/end expressions (4096 UTF-8 bytes and 10,000 compiled instructions each).
Matching spans line breaks; captures begin after the first start match and end
before the next end match. Delimiters are excluded. Missing boundaries and empty
captures wait for another response. Captured text uses the same normalization,
expiry and control-character checks as JSON tokens. Response contents and token
values never appear in diagnostics.

## Conditional settings and feedback

An explicit Test login or Retry failure associated with a field, settings group or
journey step opens that page, expands the relevant controls, displays the complete
safe error beside the control and focuses it. Do not show an error popup first.
A generic failure without an associated UI location may use a popup. Background
authentication failures must not move the user's focus or open a popup.

Burp request notes report the extension's observed action, the failing journey
only when known, the specific safe error and any supported next action. Automatic
failure says BPSH left the request unchanged; it does not claim delivery. A drop
note says Burp was asked to drop the request, without promising server-side
absence. Direct HTTP-auth delivery uncertainty must retain its warning to check
the server before resending. Never infer a bad password, missing library or
sandbox permission from an unclassified exception, or expose vendor exception
text, URLs, selectors or credentials. Format journey attribution once. A recovery
rule match is reported as a match, not proof that the session expired; distinguish
requested replay, submission to Burp and replay failure, keeping the original
response. Preserve existing user notes and avoid adding an identical note twice.

The bottom toolbar contains Event log, Journey cache and contextual action
buttons only. Do not display authentication state, loaded/saved messages, waiting
counts or other status/confirmation text beside them. Keep actionable failures
in event history or inline field guidance, without introducing another permanent
message box or Test & use result box. Event log opens a resizable
bottom dock inspired by Burp's own event log, with Time/Type/Message columns,
Info/Warning/Error filters, literal message search and selected-event details.
Start the dock with its filters and actions; omit the repeated Event log/journey
heading above them. Keep Close alongside the other dock actions.
History follows the stable selected journey ID across configuration pages and
alias edits. It is kept only in memory, bounded to 200 events per journey and
4000 overall, and cleared on unload. Lifecycle events are recorded by the
authentication coordinator so automatic logins and retries are included even
when their journey is not currently displayed. No credential, raw response,
request or unclassified exception is accepted as event data. Show Cancel only
during authentication, Retry after a failed attempt, or Open certificate settings
when the configured PIN requires attention. An open event
dock remains open and switches to the selected journey's own history.
Validation guidance appears beside the corresponding field, clears on editing,
and never steals focus during background validation.
An explicit failed Test login reveals the identified input or login step. A
missing mTLS PIN opens Client certificate and focuses PIN once device discovery
has made it available, unless the operator has moved away or edited the journey.
This keeps the event dock in its current state. Credential errors identify the
row and its valid entered name; unnamed credentials use their row number.
Runtime failures carry optional typed input attribution from the operation that
observed them. Known proxy, middleware, device, PIN, certificate, CA and capture
problems reveal that control; combined capture failures retain the exact row.
Focus waits for expanded controls to be laid out. Service, lifecycle and unknown
failures with no identified input leave the current control alone.

Journey cache sits immediately to the right of Event log. It switches the same
journey-owned dock. HTTP authentication rows show the configured protocol and
account in Name and only each exact allowed origin in Value. The origin's tooltip
contains the latest observed progress/result and timestamp, or Not yet observed
before an exchange, including HTTP-only journeys.
Keep HTTP observations separate from token/cookie expiry metadata: an observed
success does not promise a live connection. HTTP rows have no Copy name/value
actions and expose neither passwords nor NTLM payloads. Clear cache removes the
observations and fences late in-flight updates; saved settings remain visible.
Recording can expose its validated HTTP identity while capture settings are still
unfinished. That inspection remains bound to the recording's saved generation.

Event log includes fixed HTTP-authentication stages for browser login, recording,
HTTP-only tests and direct requests. NTLM reports type 1 negotiation, validated
type 2 challenge, type 3 response, acceptance and authenticated connection reuse.
Principal failures include rejection, invalid challenge, response construction,
connection loss, TLS, unreachable server/proxy, timeout, missing secrets, capacity,
origin and Authorization conflicts, proxy authentication, HTTP 403 and server
errors. Messages contain corrective guidance and safe status codes, never account
secrets, headers, challenge bytes, URLs with paths/queries or vendor exceptions.

The same dock provides explicit, read-only inspection of the selected saved journey's
usable atomic cache publication: configured token/cookie names, values, cache
acquisition time, expiry and refresh time. Show fixed expiry and refresh timestamps
first, followed by acquisition time, in a compact native summary. Display the day,
month and clock time; full timestamps with year and timezone appear in plain-text
tooltips and accessible descriptions. Times stay unchanged until a new cache
publication is displayed. It never acquires or refreshes a token.
Saved edits retain usable cached values with their original acquisition, expiry
and refresh times. Renamed and reordered credentials follow their unchanged
capture sources; removed credentials disappear. A newly required source needs
a fresh login. While edits are incomplete, the inspector shows the previous
captured selection and execution stays blocked until the settings are valid.
Clear cache, deletion, unavailability and expiry discard the cached values.
Omit the repeated Journey cache/journey heading; align Close with the cache summary.
Use the full-width table without a selected-value pane. Each token/cookie row has a context
menu with Copy name and Copy value, also available through Shift+F10. Copy name
uses the configured token name or the actual cookie name, without the display
alias decoration. Copy value copies the complete captured value. Clipboard
writes occur only after that explicit action. Successful copies have no status
confirmation; clipboard failures enter that journey's event log without names,
values or raw exceptions.
Event log and Journey cache are mutually exclusive views; neither appears as an
additional permanent output area. Closed inspection, expiry, invalidation,
unavailable/stale selection, multiple selection and unload remove displayed value
references. Only explicitly opened inspection reads credential values; they
remain excluded from logs, storage, exports and general diagnostic strings.

Session handling contains an ordered table of automatic journeys with an On
checkbox, saved identity, URL scope, Proxy port and expiration summary. URL handling
uses Burp target scope, All requests or Custom URL. Custom URL shares one input
with a Use regex checkbox (off for a literal prefix); its exact tooltip is
"Regex matched anywhere in the URL." Regex is case-sensitive by default and
searches anywhere in the unmodified URL. URL and incoming-port restrictions must
both match. Proxy port offers Any listener and distinct existing configured ports.
Saved missing/stopped ports remain selected with advisory labels; they never
silently become Any listener. Refresh on entry/focus and dropdown opening runs
off the EDT, preserves unfinished edits and never saves or starts login. Add chooses an unused
saved Project/User journey. Move up/down changes execution and injection order;
Remove deletes the rule only. Sorting never changes execution order. Missing
saved identities remain visible and never fall back to another journey. Selecting
a row edits its URL scope and session-expiration detection directly below the list.
Potential header/cookie overrides are explained when enabled rule scopes overlap;
the last matching rule wins. Rule rows, activation and ordering save automatically
after a 600 ms pause. Turning off automatic handling preserves the rule list.
Eligible HTTP tools and the master switch are shared. Session recovery is absent
from Token and is configured per automatic rule: HTTP status, response text (RE2),
or either condition. Waiting Settings remain separate, in seconds, and use the
same independent debounce. Invalid edits retain the last valid applied controls.

Show only Failure status and/or RE2 expression as appropriate. Failure status accepts
up to three digits, defaults to 401 when status detection is enabled, and requires
a value from 100 to 599 when used. Empty or out-of-range edits show inline guidance
and retain the last valid applied controls. Clearing an option removes irrelevant
values. Field/row errors use human captions and reveal the
corresponding source when execution is requested. Background validation leaves
unfinished inputs in place and never steals focus. Errors explain the observed problem and a concrete next action; internal
terms such as cycle budget and main-frame transport do not appear in guidance.

## Draft and identity safety

Remember each journey's last displayed wizard step for the extension session,
keyed by Project/User scope and stable journey ID. Switching journeys, main tabs
or collection tabs must not reset that step. Project/User tabs reopen their last
selected journey; a new journey starts at Setup. Loading another definition must
not overwrite its remembered step with the previous form's state. If a remembered
optional page is no longer available, use the nearest preceding enabled page.
This view state is not part of journey exports or persistent configuration.

Journey name is the editable naming input. Keep its generated tag internal and
offer explicit reference copying from Test & use. Generate lowercase ASCII aliases from
the name, with spaces/punctuation replaced by hyphens and accents normalized.
Every name edit regenerates the alias; saving commits that rename and existing
request tags must be updated by the user. Opening an existing/imported journey
or changing unrelated inputs preserves its recorded alias until the name is
edited. Conflicting generated tags can be saved, but execution reports rename
guidance rather than choosing an implicit owner.

Only active aliases must be unique across Project and User. Deleted/renamed
aliases are immediately reusable without a warning, reservation or reassignment
checkbox. Existing tags resolve to the current active owner of the chosen name.
Internal UUID/generation checks still reject obsolete in-flight work. Legacy
retirement metadata does not reserve names and is omitted on subsequent saves.

Navigation waits for the latest autosave without a Save/Discard prompt. Writes
are serialized; edits made during a write replace pending work and cannot be
marked saved by an older completion. Storage failures retain the editor inputs;
transient busy failures retry twice, while conflicts and unavailable storage
stop saving with recovery guidance in Event log. Reload selected explicitly
replaces local edits with saved settings. Extension cleanup flushes the final
captured edits off the EDT. New, edited, unavailable or externally stale
definitions cannot act as a reviewed saved identity. Require Reload after external storage changes and recheck queued
saved actions. No token, PIN or private key appears in UI diagnostics or exports.

## Evidence boundaries

Offscreen captures under bapp/build/ui-previews verify native layout, separately
from actual Burp checks. Refresh an existing Burp test extension using its Loaded
checkbox off/on as required by AGENTS.md. Certificate/middleware interaction,
complete transfer/secret and assistive-technology acceptance, raw-request/drop
acceptance and stress remain separately recorded gates.


## Step-log acceptance requirements

The integrated Java authentication lab owns browser and host acceptance. Reuse its current fixtures and assertions.

Step controls include explicit element conditions (visible, hidden,
attached, detached) and URL matching modes (exact, glob). Include runtime checks
for those modes and verify old journeys without the optional fields retain
visible-element and inferred URL matching behavior. New wait-duration drafts
record their unit; executable durationMs remains unchanged. Test legacy draft
reload and exact fractional seconds alongside failed-step attribution.

- Cause a failure at a known non-first action for every supported step type.
  The event must report that attempt's one-based step number and action name.
  Initial navigation failures must remain navigation failures, without a step.
- Verify timeout and positively reported multiple-selector-match wording.
  Unclassified failures must retain generic factual wording. Selector strings,
  entered values, passwords, PINs and raw browser exceptions must not enter logs.
- Missing secure input and invalid indexed step configuration must identify the
  owning row. Reordering must preserve its UUID and secret association.
- Selecting the failure event offers Go to step for the exact unchanged saved
  generation. The action reveals the correct row. It becomes unavailable after
  edits, generation replacement, deletion or a switch to another journey.
- Event sorting/filtering must keep Go to step attached to the selected event,
  not its visible row number or the most recent failure from another run.
- Explicit Test login flushes autosave, exposes the normal shared Cancel action
  while running, records its outcome and opens the completion summary. It keeps
  the current dock view and highlights Event log. Background authentication
  must not force the dock or a completion dialog open.
- When all configured response-only credentials arrive early, remaining actions are skipped
  under the existing completion policy and the log records the correct count.

## Native integration requirements

The HTTPS Login URL's exact canonical server is included in the client-certificate allowlist. Additional authentication servers and Trusted CA remain advanced settings. HTTP login URLs require an explicit HTTPS authentication server. Verify same-host/different-port isolation, explicitly allowed redirect servers and absence of certificate delivery to unrelated resources. These are acceptance requirements, not a physical-token compatibility claim.

Step failure navigation uses stable step UUIDs and the exact journey generation, never parsed log text or the current visible row. Journey attribution and paused-recovery wrapping must preserve that target. Response-only early completion records skipped-step metadata without executing the remaining steps. Any cookie capture requires successful completion of the configured sequence; an anonymous cookie must not turn a failed login step into a success.

Automatic requests use the project Automatic handling policy in Settings. **Wait for login** (the default) waits within the configured request deadline. **Send immediately** adds valid cached credentials immediately. When credentials are missing or expired, it sends the original automatic request unchanged and starts or joins background login without retaining an HTTP waiter. The original request may be unauthenticated; successful login supplies credentials to later requests. Explicit BPSH tags always wait for resolution, failed resolution requests a native drop. Proxy drops are best effort as described below. The extension does not replay the unchanged request when background login finishes.

Token response capture streams matching Chromium response bodies with a 1 MiB decoded limit before extraction. Oversized network responses are aborted; service-worker response capture stops at the same decoded limit. Responses within the limit retain their status and headers (with transport encoding headers adjusted for the decoded body).

Settings keeps the selected authentication policy explanation visible below its selector. It states whether a request waits or is sent unchanged, when background credentials take effect, and that valid cached credentials are added immediately. Tooltips and accessible descriptions use the same selected-policy explanation.

## Authentication resource controls

Settings exposes finite numeric global and per-journey request limits, defaulting
to 64 and 16. They cover direct HTTP-authentication callbacks as well as token
handling. The Unlimited controls are removed. Capacity refusal follows ordinary
send-unchanged versus explicit fail-closed policy. The Setup proxy tooltip names
browser login, recording and Basic/NTLM delivery and explains that an empty field
means direct and Burp upstream-proxy settings are not inherited.

Settings includes a native **Burp Browser** group with an editable executable,
**Browse**, **Use automatic**, detected/selected location and persistent help about
separate temporary sessions. The raw per-user selection stays visible even when
invalid. Clearing it restores automatic discovery. File discovery runs on workers;
stale results cannot overwrite a newer selection or unloaded UI. Paths render as
literal text with plain accessible descriptions and the normal tooltip factory.
The override is absent from journey/project exports and affects later attempts.

Browser prerequisite and launch errors appear inline at this group. Explicit
Test login, Retry and recording reveal Settings and focus the executable input,
with no error popup. Background failures display the result without navigation or
focus changes. Unknown failures say Burp Browser could not start without inferring
missing libraries, permissions or version incompatibility. Confirmed sandbox
failures and startup timeouts have specific guidance. A sandboxed launch is always
required. A generic popup remains available only for errors without an associated
input or journey step.
Recorded option values and event rows disable Swing HTML before their first text
assignment, while their literal saved/replayed values remain unchanged.

Formatted help uses the [Swing tooltip contract](swing-tooltips.md). The actual
tooltip opts into HTML after the host UI installs; its control and caption use
the shared factory and builder. Preserve headings, paragraph breaks and wrapping,
with plain accessible descriptions. Disabling HTML in saved-data renderers does
not prohibit formatting their separately owned help tooltips.

## Proxy failure feedback

Failed tagged Proxy processing requests Burp's native DROP action. The tested
Burp version may still forward that request; guaranteed blocking is not required.
Show the observed failure and say that Burp was asked to drop the request, without
claiming delivery was prevented. No internal stop header, ticket or extra global
credential pass is used. Global-owned request failures retain native global drop
handling. See the [routing design](session-handling-by-url-and-proxy-port.md#proxy-failure-policy-native-drop-is-best-effort).
