# Session handling by URL and browser proxy port

- **Author:** rfrisch
- **Status:** Routing implemented; final acceptance and platform qualification in progress
- **Date:** 2026-11-10

## Overview

Extend each Session handling rule with an optional incoming Burp proxy-port
condition, alongside its URL scope. When both conditions restrict the request,
**the URL and listener must both match** before the rule's saved journey applies.

Browser-specific routing uses a deliberately assigned listener. For example, one
browser or profile uses `127.0.0.1:8081`, and another uses `127.0.0.1:8082`.
Rules associate traffic arriving through each listener with the intended saved
journey. Browsers may send identical User-Agent values without sharing the same
journey assignment.

The resulting rule supports three uses:

- **URL only:** configure URL scope and leave the listener unrestricted.
- **Browser only:** configure a listener and use the existing All requests URL mode.
- **URL and browser:** configure both restrictions; both must match.

The incoming listener's port identifies the route. Every client using that port
shares its assignment, including listeners on different binding addresses with
the same port. The rule stores the port, not an address/port binding. The
extension does not infer a browser process, window, profile name, or browser brand.

URL regex searches anywhere in the full request URL. Its field tooltip identifies
the input as regex and explains substring matching. One URL field has a
**Use regex** checkbox: unchecked preserves literal prefix matching; checked
interprets that field as a regex, case-sensitive by default. General header/body matching is deferred.
Response conditions remain part of existing expired-session detection.

## The Problem

Users need to assign different journeys to different browsing contexts, including
two browsers or profiles accessing the same application as different accounts.
The current URL rules match both contexts and cannot select the intended journey
based on which browser sent the request.

Browser identification headers do not provide a dependable identity for that
purpose. Chromium-based browsers can share User-Agent strings, and two profiles
of the same browser can expose identical browser-identification headers. A
deliberately assigned proxy listener gives Session handling an observable
difference between those browsing contexts.

Users also need to control destinations independently. A journey can apply to
one application's URLs, to traffic through an assigned listener, or only to the
intersection of the two.

Matching journeys currently run in order. Later injections overwrite earlier
values only at the same header or cookie destination. The new condition must preserve that behavior while making the
rule's URL and listener restrictions understandable.

## Goals

- Retain URL scope and add an optional incoming proxy-port restriction to
  each automatic journey rule.
- Combine URL and listener restrictions with AND. An unrestricted listener
  leaves existing URL-only behavior intact; All requests allows listener-only
  selection.
- Distinguish browsers or profiles sharing a destination by configuring them to
  use different listeners, without relying on User-Agent fingerprints or adding
  browser-identification headers to application requests.
- Support URL regex matching alongside the existing URL handling capabilities.
  Search for a match anywhere in the full URL, and explain substring matching
  in the regex field's tooltip. Keep one URL field with a Use regex checkbox,
  unchecked for literal-prefix matching.
- Show both restrictions clearly when configuring and inspecting a rule.
- Use a coherent current rule model and stored format without a backward-
  compatibility requirement for previously saved session-handling rules.
  Rules explicitly configured with Any listener have no incoming-port restriction.
- Preserve shared tool selection, the master switch, rule ordering, cache reuse,
  request-waiting policies, and expired-session recovery. Explicit tags keep
  their existing independent behavior.
- Apply listener-restricted rules only to live Proxy traffic. Repeater, Intruder,
  and other tools use unrestricted-listener URL rules or explicit journey tags;
  copying a request does not carry a browser assignment into those tools.
  Missing listener identity must not match a restricted listener.
- Report invalid listener settings and URL patterns inline. An unfinished or
  invalid edit must not replace the last valid applied controls.
- Keep matching and any retained listener attribution bounded. Request bodies,
  credential values, and browser-identification headers are not needed to
  identify the selected listener.
- Refactor existing request handling where needed to keep authentication,
  injection, and recovery logic shared and responsibilities clear. Burp callback
  adapters must not become separate implementations of the same policies.
  Remove superseded paths and unnecessary indirection; preserve documented
  behavior through verification rather than retaining the current structure
  solely to avoid changing it. Keep the package boundaries defined in
  [Java architecture](./code-structure.md).

## Non-Goals

- General header/body regex selectors in this version.
- User-Agent or client-hint browser fingerprinting.
- Per-profile marker headers or a companion browser add-on.
- Automatically inferring browser names, processes, windows, or profile identities.
- Creating, editing, starting, stopping or deleting Burp proxy listeners, or
  changing external browser proxy settings. Users manage listeners in Burp and
  configure each browser to use its intended listener.
- A general AND/OR expression builder; URL and listener conditions use AND.
- Changing authentication methods, journey recording, or credential capture.
- Rewriting application requests to give them a browser identity.
- Choosing a journey dynamically from regex capture groups.
- Migrating old session-handling rules, maintaining legacy rule readers or
  preserving old internal constructors/storage fields for compatibility.
  Unsupported stored rules block the Project collection. Offer a confirmed reset
  of BPSH project storage in the existing Burp project, preserving User journeys
  and other Burp data. Do not automatically delete or rewrite unsupported storage.
- Adding new response selectors; existing response-based recovery remains separate.

## Critical User Journeys

### Apply an account's journey only to its browser and application

- **Given:** a rule selects Journey A, the application's URL scope, and proxy port
  `8081`. Browser A uses a listener on that port; Browser B uses port `8082`.
- **When:** either browser sends a request to the application, or Browser A sends
  a request outside that URL scope.
- **Then:** Journey A applies only to Browser A's requests inside the configured
  URL scope. Browser B's requests and Browser A's requests outside the scope do
  not match this rule. Other independently matching rules retain their behavior.

### Copy a browser request into another Burp tool

- **Given:** Browser A's request matched a listener-restricted rule in Proxy.
- **When:** the user copies that request to Repeater or Intruder.
- **Then:** the copied request does not inherit the browser's listener assignment.
  URL-only rules remain eligible under the existing tool settings. The user can
  select a journey through an explicit tag using its existing independent policy.

## Feasibility finding: annotation handoff

An actual Burp Community 2026.10.1-54773 experiment on the Ubuntu verification VM
rejected the proposed annotation bridge from Proxy to the global HTTP callback.
Across 144 successful concurrent requests through two listeners, annotation notes
were present at Proxy to-be-sent and empty at the global HTTP callback in every
case. Returning copied annotations at either Proxy stage and directly mutating
notes all had the same result. Listener identity itself was available in Proxy.

The test included 72 HTTP/1.1 client requests and 72 HTTPS requests for which curl
reported HTTP/2; Montoya represented all recorded requests as `HTTP/1.1`. A native
Proxy-history copy sent from Repeater also had no listener context in its global
callbacks. These observations apply to the tested runtime, not a cross-version
API guarantee.

The listener-based product behavior remains agreed. Following this finding, the
author accepted invoking shared authentication logic from Proxy callbacks where
listener identity is available, with refactoring as needed. The callback ownership,
HTTP-authentication delivery exception and recovery design below were subsequently
approved. Each request must be processed once without relying on annotation
notes to carry listener identity into the global callback. No production feature
implementation was made during this experiment.

The [generated experiment report](../../bapp/build/reports/listener-annotation-probe/report.md)
contains the method, variant counts, limitations and raw evidence. It is local
generated evidence and is not committed with this design.

## Proxy failure policy: native DROP is best effort

The 2026-11-10 probe on Burp Community 2026.10.1-54773 in the Ubuntu 24.04
verification VM established final-Proxy request mutation, actual listener
metadata, final interception edits and same-family response correlation. Native
final-Proxy DROP was not reliable: both the convenience factory and the explicit
DROP action allowed fixture requests to continue to the target. Global and
request-received drop controls did stop their fixture requests. See the
[callback experiment](../../bapp/build/reports/listener-callback-probe/report.md).

On 2026-11-11 the author clarified that guaranteed blocking of a failed tagged
Proxy request is not a requirement. The adapter requests the normal native DROP
action and annotates the observed failure without claiming that delivery was
prevented. The tested Burp version may still forward the original request,
including unresolved authentication tags or existing credential bytes. This is
an accepted limitation during normal Proxy operation as well as unload/reload.
Do not add an internal stop header, cross-callback ticket store, fallback request
or extra authentication pass to enforce a drop. No special unload guarantee is
required. Global handling retains its existing native drop behavior for requests
it owns, including explicit HTTP-authentication directives.

Successful requests are held only according to the configured waiting policy,
receive committed credentials and continue once. They are not dropped and
recreated. Application-session recovery is separate: an already-sent request
that receives a configured expiration response may authorize one later replay,
while its original response is retained. This distinction is part of the product
contract and must remain clear in tests and documentation.

CP0 accepts the observed Proxy DROP limitation; mutation, listener attribution,
final edits and response ownership remain required. The additional callback
checks confirmed native editor changes and normal off/on reload. These are host
feasibility observations, not final production qualification.

## Technical Plan

The author approved callback ownership after reviewing the concrete two-browser,
expired-session and Repeater examples, selected existing Burp listeners only for
setup, and chose port matching independently of binding address. URL regex uses
substring matching with an explanatory tooltip and shares the prefix field through
a Use regex checkbox. Regex is case-sensitive by default. The supporting
validation, persistence and presentation arrangements below were approved with
the complete Technical Plan. The revised file-by-file implementation plan below
was subsequently approved, including the removal of old-rule compatibility.

### Use existing Burp listeners

Session handling selects ports from listeners that the user has already configured
in the current Burp project. The extension does not create or modify listeners, reserve
ports, or change browser proxy settings. Users configure distinct listeners in
Burp and point each browser or profile at its intended listener. Rules without a
listener restriction continue to accept traffic independently of that setup.

Burp remains the owner of listener binding and project configuration, as described
in its [Proxy settings documentation](https://portswigger.net/burp/documentation/desktop/settings/tools/proxy).

### Match the incoming proxy port

The author selected port-only matching. A rule stores either no restriction or
one integer port in the range 1–65535. Port `8081` matches incoming Proxy requests
reported on that port on any binding address. It does not match the destination
server's port, a journey's outbound proxy port, or an ephemeral client source port.
Changing a listener's binding address while keeping its port does not change the
rule's assignment. Browsers that need different assignments must use different
incoming proxy ports.

The selector offers **Any listener** and distinct configured port numbers. When
multiple bindings share a port, they represent one selection; binding addresses
can be shown as supporting information without becoming part of the saved value.
New rules explicitly represent Any listener or a selected port.

Stopping or removing a listener does not erase its selected port or reset the
rule to Any listener. Retain the saved value and display its unavailable/stopped
state. With no incoming traffic on that port, the rule matches no new requests;
another listener on the same port remains eligible. Recreating a listener on the
saved port makes the rule applicable to that incoming traffic again. There is no
implicit journey reassignment to another port.

At request time, the Proxy adapter extracts the incoming port from Montoya's
listener metadata through one shared boundary parser. An absent, malformed or
out-of-range value provides no listener identity and cannot match a restricted
rule. Runtime matching uses the actual callback context, not the editor's last
listener-list refresh. Non-Proxy requests have no incoming port. The settings
refresh and persistence arrangements are described below.

### One URL field with a Use regex checkbox

The author chose a shared URL field rather than separate prefix and regex modes
or an additional URL filter. Retain the three top-level scope choices: All
requests, Burp target scope, and a custom URL. The custom-URL choice shows one
field labelled **URL** and a **Use regex** checkbox.

- Unchecked: interpret the field as a literal URL prefix, preserving existing
  prefix behavior and validation.
- Checked: interpret the same field as a regex and apply substring matching.

Literal-prefix matching uses Use regex unchecked. All requests and Burp target
scope remain available as matching behaviors. The URL field and checkbox are
shown only for custom URL matching; regex is not a second condition layered on
Burp target scope or All requests. The incoming proxy port remains a separate
optional restriction combined with the selected URL condition using AND.

Changing the checkbox changes how the field is interpreted; it does not silently
rewrite, escape or replace the user's text. If the selected interpretation makes
the text invalid, retain the edit, report the problem inline and keep the last
valid applied controls until the edit becomes valid.

### URL regex substring matching and tooltip

The author selected substring search against the full request URL. A pattern
matches when it finds a matching substring anywhere in that URL; the user does
not need to wrap partial patterns in `.*`. For example, `/admin` matches
`https://app.test/admin/settings`. Users can anchor their expression with `^`
and `$` when they want a whole-URL match. A configured incoming port must also
match, as for the other URL conditions.

Use this tooltip on the URL regex input:

> Regex matched anywhere in the URL.

The tooltip belongs to the URL selector, independently of the existing response
regex used to detect expired sessions. Invalid URL expressions are reported
inline and do not replace the last valid applied settings.

### Case behavior and bounded regex validation

The author selected case-sensitive regex matching by default: `/Admin` and
`/admin` differ. Keep prefix matching's current case-sensitive behavior as well.
Do not normalize, decode or lowercase the URL before matching. Regex operates
on the full request URL supplied by Burp. Explicit credential tags retain their
existing precedence before the host URL/scope helpers are consulted.

Reuse the existing RE2/J dependency and the established expression bounds:
nonblank input, at most 4,096 UTF-8 source bytes and at most 10,000 compiled
instructions. URL matching uses `find`, without recovery's implicit DOTALL flag.
Standard supported inline flags remain available, so an author can explicitly
write `(?i)` when desired; there is no additional case checkbox in this design.
Unsupported constructs are rejected inline with safe position guidance. RE2/J
provides linear-time matching, with its supported grammar documented by the
[RE2/J project](https://github.com/google/re2j) and
[RE2 syntax reference](https://github.com/google/re2/wiki/Syntax).

Extract the bounded compilation mechanism currently owned by `RecoveryPattern`
into a small shared `bpsh.pattern` leaf package. It receives the source and flags
and reports safe syntax/limit failures without retaining expression text in
diagnostics. Recovery keeps its own messages, DOTALL flag and existing behavior;
the URL matcher supplies URL-specific messages and default flags. This shares
the validation algorithm without making URL handling depend on recovery policy.
Update the documented and enforced dependency graph for the shared leaf.

Request settings remain framework-free values containing the matching source
and mode, with no RE2, Swing, Montoya or Playwright imports. A host-boundary
rule matcher holds the compiled URL patterns for the exact validated controls
snapshot. Compile as part of controls validation/publication, not once per
request. There are at most 64 rules; do not introduce an unbounded pattern cache.
UI validation, document parsing and runtime plan preparation use the same
compiler rather than separate regex-validation implementations.

### Persist and publish validated rules

Use one typed URL condition in each project rule, plus an optional incoming
proxy port. A regex is text, not an HTTP URI; do not route it through a
literal-prefix URI parser. The UI's single field and checkbox translate to
distinct validated Prefix and Regex values, without retaining legacy nullable
URL fields or an old-rule conversion path.

The author explicitly removed the backward-compatibility requirement for rule
storage. Replace the old rule layout with the versioned current layout specified
below. Reject unsupported/unversioned stored rules and offer **Reset project
storage...** beside the persistent error. Confirmation replaces only BPSH's
project entry with an empty current-format document, keeping User journeys and
all other Burp project data. Never reinterpret old rules as unrestricted or automatically overwrite
the document. Reject out-of-range ports, unsupported matcher kinds and conflicting
URL members at the shared codec boundary. Serialize explicitly so compiled
patterns and display-only listener states cannot enter storage. Keep project
controls out of library documents. Journey definitions and secrets are not being
redesigned as part of this rule-format change.

The editor retains raw incomplete text until the full controls snapshot is
valid. Compile and validate before publication, retain the existing persistence
conflict checks, and publish source controls and their matching plan consistently.
A runtime request must never combine a new port restriction with an older URL
matcher. Use the same immutable snapshot throughout one request's selection.

### Refresh listener choices and explain overlap

Add a Burp-boundary listener reader that exports only the proxy-listener settings
and returns distinct configured ports plus advisory binding/configured-state
information. Refresh asynchronously when Session handling opens or regains
focus and when its listener selector opens. Coalesce overlapping refreshes;
never make a host export or a network connection from a rule-match operation.
Apply results on the EDT without overwriting unfinished field edits.

Listener-list refresh is advisory. A settings-read failure retains the selected
port and the last known choices, with inline guidance to check Burp's Proxy
settings. It never clears a restriction. A configured enabled flag does not
prove that the socket bound successfully; show only the state actually observed.
Match actual incoming callback metadata independently of this UI snapshot.

Show proxy-port restriction in the ordered rules table alongside URL scope and
expired-session detection. Summaries distinguish literal-prefix and regex rules
and display Any listener or the selected port. Preserve literal text rendering,
keyboard operation, native theme and the exact approved regex tooltip.

Keep all existing ordering and destination ownership rules. Every matching
enabled rule runs in configured order; later values overwrite earlier values
only at the same injection destination. Port-specific rules have no hidden
priority over unrestricted rules. Attribute recovery only to credential versions
that survive in the final committed request, as the existing resolver does.
Keep the existing limit of one automatic rule per saved journey in this feature.

Use this brief guidance next to the ordered rules:

> Matching rules run from top to bottom. Later rules overwrite earlier values
> in the same header or cookie.

Direct HTTP-authentication identities keep their existing allowed-origin
checks and explicit directive selection. A matching URL or incoming port does
not expand those origins or change the selected HTTP identity. This preserves
the previously approved separation of automatic captured-credential injection
and explicit direct HTTP-authentication delivery.

### One shared request-processing pipeline

Extract request preparation from `HttpSessionHandler` into one shared processor
under `bpsh.burp.http`. It owns explicit-tag precedence, ordered automatic-rule
selection, credential resolution, final commit checks and the existing failure
policy. Proxy and global adapters supply their request context and translate its
result into the action supported by their callback. Neither adapter contains a
second tag parser, authentication implementation or recovery algorithm.

The request context distinguishes the callback family, its message ID, the Burp
tool and an optional incoming listener. A Proxy adapter supplies its actual
listener. A non-Proxy adapter supplies no listener; it cannot match a restricted
listener rule. Rule matching consumes one validated controls snapshot. Listener
matching is combined with URL matching using AND, before acquiring credentials.

Keep `NativeTagResolver`, `AuthenticationCoordinator` and the existing HTTP
identity/transport services as the owners of their respective algorithms.
`HttpSessionHandler` may be replaced with cohesive adapters and lifecycle wiring;
keeping that class or its current method layout is not a compatibility goal.
Domain and request-setting contracts retain their framework-free dependencies.

Automatic injection selection and recovery attribution for explicit tags are
different operations. Tags still resolve independently of the master switch and
automatic-tool selection. After committing tagged output, recovery attribution
uses enabled rules for the referenced saved identity and the committed URL when
the captured master switch is on. It ignores the automatic-tool selection, but
does require a rule's incoming-port restriction to match actual live Proxy context.
Without such a match, keep that explicit use's existing disabled-recovery policy.
Direct HTTP-authentication delivery remains outside this application-recovery path.

### Divide responsibility by request kind

| Request kind | Preparation and delivery owner | Recovery attribution |
| --- | --- | --- |
| Live Proxy request without an HTTP-authentication directive | Proxy to-be-sent adapter invokes the shared processor; successful output continues, failed tagged processing requests native DROP on a best-effort basis | Proxy message-ID family |
| Repeater, Intruder, Scanner or Extensions request without that directive | Global request adapter invokes the same processor | Global message-ID family |
| Explicit `BPSP-HTTP-AUTHENT` request from any tool | Global adapter uses the shared direct HTTP-authentication operation and returns the actual response through `spoof` | Preserve existing direct-delivery policy; do not add automatic session replays |
| Owned login traffic | Existing traffic guard exempts it from ordinary processing; the global adapter removes its owned marker | Excluded from application-session recovery |
| Authorized application recovery replay | Existing owned replay delivery invokes final generation/version checks in the global adapter | Global replay attribution, referring to the original family and ID |

The Proxy request-received callback preserves normal interception and the
existing owned-login exemption. Ordinary credential processing happens at Proxy
to-be-sent, after the user has had an opportunity to edit the intercepted request.
Tool selection and the automatic master switch still apply there. Explicit tags
retain their existing independent policy, including requesting native DROP on failure; Proxy delivery prevention is best effort.

Global handling checks owned traffic and explicit HTTP-authentication delivery,
then bypasses ordinary Proxy processing based on its tool source. This is a
fixed ownership rule, not a per-request annotation or a content-hash lookup.
Proxy and global IDs are never joined. Ordinary Proxy output is not parsed for
credential tags a second time.

The HTTP-authentication exception is required by the host API: the pinned
Montoya 2026.4 `ProxyRequestToBeSentAction` offers continuation and drop, whereas
global `RequestToBeSentAction` also offers response spoofing. Current public
[Proxy action documentation](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/proxy/http/ProxyRequestToBeSentAction.html)
and [global action documentation](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/http/handler/RequestToBeSentAction.html)
show the same distinction. A Proxy request carrying the explicit directive is
deferred unchanged; the global operation consumes the directive and resolves
its dependent capture tags once, as it does today. Automatic listener rules do
not choose a direct HTTP-authentication identity in this feature.

Before committing ordinary output, shared validation must prevent captured data
or automatic header injection from creating an HTTP-authentication
directive or owned-traffic marker that a later callback would interpret as a
new command. Report such output through the existing atomic tagged/ordinary
failure policy. Do not introduce a new header or User-Agent suffix to mark
ordinary browser requests as processed.

### Share recovery across independent callback families

Refactor `SessionRecovery` to key attribution by callback family and message ID,
instead of assuming every ID comes from the global HTTP callback. Keep one
recovery implementation and one aggregate set of retention limits: 10,000
records, five-minute retention, 4 MiB per replay template and 32 MiB retained
template budget. Splitting callback adapters must not double those budgets.

Record provenance only after a complete request commit. Retain the exact used
journey generations, credential versions, recovery policies and bounded replay
template. Proxy responses consult Proxy records; global responses consult global
records. Each record is consumed once, and absent attribution does not cause
credential recovery or response-body materialization.

An expired Proxy session can authorize the existing single application replay.
Its template already binds the original selected journeys; a replay does not
rematch browser rules using the Extensions tool or infer a listener for its new
connection. It rechecks journey availability and credential usability before
delivery. The replay receives a global-family delivery ID while retaining its
original Proxy-family reference for diagnostics. Replays cannot authorize
another replay. Keep the original application response unchanged.

Normal copies to Repeater or Intruder have no such recovery authorization. Their
fresh request context has no incoming listener and matches only unrestricted
listener rules or uses explicit tags. Cancelling one wait releases its own
resources; shared authentication for other requests continues. Unload closes
both adapters, pending recovery and replay work through their shared lifecycle.

### Verification needed before implementation is accepted

The intended ownership and data flow is:

```text
Validated project controls + compiled URL patterns
                     |
       +-------------+------------------+
       |                                |
Proxy request + incoming port      Non-Proxy request
       |                                |
       +---- shared request processor --+
                     |
           credential resolution
                     |
         final commit + used versions
                     |
      recovery record (callback family, ID)
                     |
       same-family response -> shared recovery
                     |
        one authorized global delivery replay

Explicit HTTP-authentication directive -> global direct delivery + spoof
Owned login traffic -> traffic guard, excluded from ordinary processing
```

Extend the existing disposable real-Burp probe to exercise this ownership rule
before committing to the refactor: mutate a Proxy request in its final callback and record native DROP behavior as best effort,
observe it in the global callback without processing it again, and correlate the
response in the Proxy family. Include two listeners sending identical concurrent
requests, manual interception edits, and the explicit HTTP-authentication bypass.
The earlier annotation experiment did not establish these behaviors.

Reuse existing lab fixtures and acceptance overlays to verify the final feature:
one credential-processing pass per request, original-send suppression for direct
HTTP authentication, Proxy-family recovery followed by one global replay,
independent equal numeric IDs across families, and no inherited listener when
copying to another tool. Exercise reserved-control output as data, ordinary and
tagged failures, cancellation, unload and shared retention limits. Then run the
required architecture/check tasks, build the universal development JAR directly
to its prescribed path and qualify that artifact in authorized verification VMs.

## Alternatives Considered

### Identify a browser through User-Agent or other request fingerprints

This would match existing request data without configuring separate listeners.
It does not provide a deliberate identity for two profiles of the same browser,
which can issue identical requests, and ties routing to client-header behavior.

**Rejected by author:** use deliberately assigned incoming proxy ports to
distinguish browsing contexts. This requires configuring each browser's proxy
and means every client on the same incoming port shares that assignment.

### Add browser/profile marker headers or general header/body selectors

An explicit per-profile marker could distinguish otherwise identical requests,
but needs browser-side configuration or a companion component. General regex
selectors over headers and bodies offer broader request matching but add selector
scope beyond the agreed URL and browser-routing conditions.

**Rejected by author for this version:** use URL conditions plus incoming proxy
port, with no companion browser add-on or application-facing browser marker.
General header/body filtering is deferred, not ruled out for future work. This
does not remove the existing owned-login and recovery traffic guard.

### Carry the incoming listener into the global hook through annotations

This would keep ordinary authentication in the existing global callback and add
a small Proxy-to-global metadata handoff. It depended on annotation propagation
that the public interface alone did not establish.

**Rejected by runtime evidence, followed by author approval of Proxy-side
processing:** all 144 requests in the measured real-Burp run retained their
marker at Proxy to-be-sent, and none retained it in the global request callback.
Copying notes at either Proxy stage and mutating received notes all failed to
provide the handoff. See the [experiment report](../../bapp/build/reports/listener-annotation-probe/report.md).

Equal numeric IDs across callback families do not repair this missing contract.
Content matching cannot distinguish the experiment's 72 pairs of byte-identical
requests arriving through different listeners. The selected design keeps
request processing and response attribution within each callback family and
shares the authentication/recovery algorithms instead.

### Create and manage proxy listeners from Session handling

This would reduce the setup steps needed before selecting a browser-specific
port. It also makes the extension responsible for creating shared project
listeners, handling occupied ports and defining ownership when settings change.

**Rejected by author:** select existing Burp listeners only. Burp owns listener
creation and editing; users configure their browser proxy settings separately.
The extension reports unavailable selections without creating replacements or
relaxing a rule's restriction.

### Match an exact listener address and port

Exact binding identity would distinguish listeners on the same port bound to
different interfaces. Changing the binding address would require updating the
rule even if the browser kept using the same proxy port.

**Rejected by author:** identify the incoming route by port only, independently
of binding address. This accepts the explicit tradeoff that all listeners using
that port share the rule's assignment; separate browser assignments require
different ports.

### Add a separate URL-regex mode or an additional URL-regex condition

A fourth top-level URL mode would make regex a distinct dropdown selection.
An additional regex condition would allow intersections such as Burp target
scope AND a regex, but adds another URL restriction for users to configure.

**Rejected by author after reviewing the existing prefix field:** keep one
custom-URL field with a Use regex checkbox. Unchecked preserves literal-prefix
behavior; checked uses regex. All requests and Burp target scope retain their
existing meanings. The selected design does not offer a separate regex filter
combined with Burp target scope.

### Require whole-URL regex matching or ignore case by default

Whole-URL matching would require patterns to describe the entire URL rather than
allow partial expressions such as `/admin`. Case-insensitive defaults would make
`/Admin` and `/admin` match alike without an explicit pattern flag.

**Rejected by author:** search anywhere in the full URL and match case-sensitively
by default. Users can express whole-URL anchoring or case-insensitive matching
in the supported regex grammar. The approved tooltip remains exactly
“Regex matched anywhere in the URL.”

### Preserve or migrate the old rule-storage layout

Keeping old rule fields/readers would let earlier saved rules load automatically,
but would constrain the current model or require a conversion path.

**Rejected by author during implementation-plan review:** backward compatibility
for session-handling rules is not required. Use one typed URL condition and the
current versioned rule block; remove obsolete rule fields/readers rather than
maintain them for old documents. Unsupported stored rules produce an explicit
load error with an explicit, confirmed reset of BPSH project storage in place,
without silent reinterpretation or automatic data deletion.

## Open Questions

The author accepted best-effort native Proxy DROP on 2026-11-11. Guaranteed
blocking, the internal stop-marker handoff and its diagnostic tickets are outside
scope. CP0's observed forwarding is an accepted limitation, not a blocker.
Continue the implementation and remaining qualification checks; final production
acceptance has not run successfully.

## Detailed Implementation Plan

Use checkpoints CP0–CP3 below as the execution order. The numbered items that
follow are the implementation contracts and exact file catalog; they are not
independent sequential cutovers. Complete each checkpoint as one coherent set of
edits, including its callers and tests, before advancing. Reuse the existing lab
and remove superseded code. Displayed file paths are repository-relative;
Markdown link targets are relative to this document. New production files are
planned files; they were not created as part of this design.

### Buildable checkpoints

Execution on 2026-11-11: CP0 established listener metadata, mutation, native
interception edits, same-family responses and normal reload. Its unreliable
Proxy DROP behavior is accepted. CP1 and CP2 are implemented. The simplified
cutover passes all 1,166 native tests, architecture and native documentation
checks. The universal development JAR has SHA-256
`9120a0dcbf33d0e66b8a8dc72716c3ca5aa7043ed69c258ef4731553354c0b5b`.
Captured component acceptance passes 630 tests with none failed or skipped
(invocation `cbc17ad5-b543-471a-8d58-e9c466619b14`). Source/configuration binding
refreshes retain the catalog's requirement semantics. The broader browser
profile still has two response-capture failures: popup and service-worker token
responses. Those cases are not qualified. Current-artifact Windows/Linux VM
qualification remains pending. Current-artifact host verification in installed
Burp Professional 2026.10.1 passes five client/server checks: identical concurrent
URLs select `user` on incoming port 8081 and `user2` on 8082; port 8080 and a
nonmatching protected URL on either assigned port remain unauthenticated. The
lab recorded exactly five incoming requests for those five clients. This uses
the existing browser lab fixture, a warmed browser runtime and a 45-second cache
age for its 60-second opaque tokens. It is host evidence, not VM qualification.
The observed second cold login previously exhausted a ten-second browser setup
wait while the first verified the bundled cache. The runtime now lets journeys
sharing its manager wait within their own original attempt deadlines, retaining
independent cancellation. A native regression holds setup beyond ten seconds and
proves one shared preparation, successful patient wait, and independent shorter
deadline/cancellation. External cache file-lock contention retains its bounded
ten-second ceiling. The changed build still needs current-artifact host/VM
qualification; the warm-runtime host results above qualify their recorded JAR.

The separate-agent [real Burp acceptance plan](burp-host-acceptance-plan.md)
defines the maintained host runner. It is not implemented and does not replace
the current feature's required qualification.

| Checkpoint | Exact allocation of planned changes | Required exit check |
| --- | --- | --- |
| CP0 — Host feasibility | Item 1 only: disposable sources and ignored execution/evidence metadata. No maintained production changes. | Build the current development JAR before Computer Use; require final-Proxy mutation/defer, actual listener metadata, final edits and same-family responses. Record native DROP behavior as best effort; forwarding after a requested Proxy drop is accepted. |
| CP1 — Shared regex compiler | Only item 3's BoundedRegex.java, pattern README, BoundedRegexTest.java, RecoveryPattern.java and architecture.gradle.kts; update the shared-leaf portions of code-structure.md, bpsh/README.md and credentials/README.md. No rule/model, handler or UI API changes yet. | Run test with BoundedRegexTest and the existing SessionRecoveryTest, then check and verifyNativeDocumentation. Existing recovery semantics must still pass. |
| CP2 — Coordinated feature cutover | All remaining production/model/codec/schema/UI changes from items 2–8, including RequestExchange, matcher/state/listener classes, shared operations, both adapters, Extension wiring and Diagnostics/SessionRecovery APIs. Update every native and captured-overlay caller/test listed in item 8 in the same checkpoint, except BoundedRegexTest already completed in CP1. IntegrationFixtures is reused unchanged. production-selection.json is assigned to CP3. | Run the changed native owners, then check, verifyNativeDocumentation and jar. All native tests and test compilation must pass; no production/test reference to the removed UrlMode, constructor shape or HttpSessionHandler may remain. |
| CP3 — Acceptance and qualification | Item 8's production-selection.json owner selection; item 9's host helper/documentation and all ten binding files; remaining documentation edits from item 10. Reuse Build-HostProbe.ps1 unchanged. | Build the helper, refresh/review bindings, run captured acceptance in separate invocations, rerun required checks and build the final development JAR. Verify that exact artifact in authorized Windows/Linux VMs using fresh projects. |

The CP2 model, stored format, runtime matching, callbacks, composition and tests
change together. Do not remove the old handler at the start of item 5: delete it
only in CP2 after the replacement adapters are wired and its callers/tests are
updated in that same checkpoint. No compatibility constructors or parallel
global/Proxy execution paths remain at CP2 completion. Keep Java comments current
within the checkpoint that changes the corresponding API. CP3 documentation may
finish the broader user/operating contracts, but its checks may not depend on an
API fix deferred from CP2.

For CP1 use these concrete checks:

```powershell
.\bapp\gradlew.bat -p bapp test --tests bpsh.pattern.BoundedRegexTest --tests bpsh.burp.http.SessionRecoveryTest --offline --console=plain
.\bapp\gradlew.bat -p bapp check verifyNativeDocumentation --offline --console=plain
```

CP2 uses the focused owners named in item 8 and then:

```powershell
.\bapp\gradlew.bat -p bapp check verifyNativeDocumentation jar --offline --console=plain
```

### 1. Prove the new host boundary before the large refactor

The active disposable baseline sources, hashes, compiler/classpath, normal Burp
launch arguments, listener setup payload and evidence directory are identified in
the ignored [execution manifest](../../bapp/build/reports/listener-annotation-probe/execution.json).
Its current sources are ListenerAnnotationProbe.java and FixtureLauncher.java
under the recorded private scratch directory, outside the repository. The baseline
was located and compiled during review resolution; that is compile evidence only,
not proof of the new callback experiment.

To repeat that baseline compilation on this checkout:

```powershell
$probeExecution = Get-Content -LiteralPath bapp/build/reports/listener-annotation-probe/execution.json -Raw | ConvertFrom-Json
$probeCompileArgs = @('--release', '21', '-cp', ($probeExecution.compileClasspath -join [IO.Path]::PathSeparator), '-d', $probeExecution.classesDirectory) + @($probeExecution.sources)
& ($probeExecution.javac) @probeCompileArgs
if ($LASTEXITCODE -ne 0) { throw 'Disposable probe compilation failed.' }
```

Use the manifest's package recipe to include the extension entry class before its
nested classes and Jackson dependencies, with the fixture launcher in a separate
JAR. Substitute a newly created private guest directory for RUN in its launch
arrays, transfer the current artifacts, start the existing lab fixture and the
installed Burp, complete temporary-project startup, then configure both listeners
after startup through the recorded setup endpoint. All configuration and evidence
are confined to that isolated run; no guest credentials belong in the manifest.

The manifest is local execution context, not a dependency on a permanently retained
temporary directory. If it or its sources are absent on another checkout, recreate
the disposable probe in a new private scratch directory from these maintained
starting points: [HostProbeExtension.java](../../test/authentication-lab/src/hostProbe/java/lab/auth/HostProbeExtension.java)
for Montoya registration/unload and fixture-only test boundaries, and
[HttpAuthenticationFixture.java](../../test/authentication-lab/src/main/java/lab/auth/HttpAuthenticationFixture.java)
for the existing BASIC fixture's anonymous HTTP/HTTPS endpoints. Compile against
the Montoya version declared in bapp/build.gradle.kts and the current product/lab
JARs. Record the new paths/hashes and commands in a new local execution manifest.

The recreated class implements BurpExtension, ProxyRequestHandler,
ProxyResponseHandler and HttpHandler. Register those three handler interfaces
at initialize and deregister them on unload. Filter every observed request/response
to the selected local fixture and X-Listener-Probe-Case header. Record phase,
family, message ID, actual listener/port, case, source tool and HTTP representation;
do not retain credential contents. Bound the capture to 1000 events and mark an
overflow incomplete. The required cases are:

| Case | Fixture-only probe behavior and required observation |
| --- | --- |
| Plain paired requests | Send identical request bytes through 18081 and 18082; observe both incoming ports at Proxy and correlate each response to its own Proxy-family request ID. Record the independent global IDs without joining families. |
| Final-Proxy mutation | Add X-Listener-Probe-Stage: proxy at Proxy to-be-sent. Global handling observes that one value and leaves it unchanged. Confirm the actual response returns through the Proxy family. |
| Native Proxy DROP | Failed tagged processing returns the supported native DROP action with the unchanged original request and safe failure notes. Actual forwarding is permitted by the accepted host limitation; no internal marker or second authentication pass is added. |
| Directive deferral | Preserve a synthetic BPSP-HTTP-AUTHENT header at Proxy to-be-sent, observe it in global handling, then remove it there before continuing to the anonymous fixture. This proves callback deferral only, not authentication or production spoofing. |
| Manual interception edit | Edit the fixture request before Forward. Final Proxy and global observations must contain the forwarded target/value rather than the original draft. |

Extend the located baseline with those response/mutation/drop/defer cases; its
old annotation-only variants do not satisfy this gate. Add Proxy response observations and a harmless
fixture-only request replacement in Proxy to-be-sent. Exercise normal forwarding,
interception/edit/forward, drop, two identical concurrent client requests through
different ports, and a directive-bearing request deliberately deferred to the
global hook. Record actual callback-family IDs, order, source tools and safe
fixture observations. Do not use annotations or content hashes to recover a
listener in global processing. Hashes may compare fixture bytes as evidence only.

Run a normally loaded probe in the existing verification VM's separate temporary
Burp project. Build the current universal development JAR before Computer Use, transfer
that exact JAR and verify its checksum. Reuse the existing anonymous and account
fixtures; do not create a new lab. If final-Proxy replacement or same-family
response correlation fails, resolve that finding before implementing this plan.

### 2. Define the rule contract and exact persisted representation

Modify [RequestSettings.java](../../bapp/src/main/java/bpsh/request/RequestSettings.java).
Replace the `UrlMode` plus nullable URI representation with a JDK-only sealed
`UrlCondition`: AllRequests, BurpScope, Prefix(URI value), and Regex(String value).
`AutomaticRule` contains enabled, journey, url, nullable proxyPort, and recovery,
in that order. Its URL condition is nonnull; variants carry only the value they
need. Prefix retains literal startsWith matching, without giving regex text a URI
type. Remove the old UrlMode and obsolete constructor signatures and update all
internal callers directly.

The domain validates nonnull variant values, prefix structure, and integer port
range using JDK types only. It does not import RE2 or a host/UI package. The
concrete regex compiler validates grammar at persistence and runtime-plan
boundaries. Do not store an independent `useRegex` Boolean: the checkbox derives
its state from the URL condition, avoiding contradictory saved settings.

Modify [NativeDocumentCodec.java](../../bapp/src/main/java/bpsh/journey/persistence/NativeDocumentCodec.java)
and [journey-registry.schema.json](../../bapp/src/main/resources/journey-registry.schema.json)
to implement this exact rule contract. A stored rule has required enabled,
journey, url, proxyPort, and recovery members. Its nested url object is:

| `url.type` | `url.value` | Meaning |
| --- | --- | --- |
| `burp_scope` | forbidden | Burp target scope |
| `all_requests` | forbidden | Unrestricted URL mode |
| `prefix` | required HTTP(S) URI string | Literal URL prefix |
| `regex` | required nonblank string | Case-sensitive default, substring search |

`proxyPort` is required and nullable: null explicitly means Any listener; an
integer from 1 through 65535 is an incoming-port restriction. Reject strings,
fractions, Boolean values, missing required members, other ranges and unknown
or conflicting URL members. Always serialize this current shape explicitly;
do not emit/read legacy urlMode, urlPrefix or urlRegex members.

Add `controls.rulesVersion` with supported value 1, the first explicit version
of this new rule block. When controls.rules is supplied, rulesVersion must also
be supplied and supported. Writing project controls always emits rulesVersion: 1
and the rules array, including when empty. A controls object that omits both
rules members means no rules. Reject an unversioned rules array or an unsupported
rulesVersion with the guidance “Unsupported Session handling storage format.
Reset project storage to create journeys in this project.” Offer the confirmed
reset described in [the interface contract](interface.md). Do not silently ignore
or rewrite the saved block. Keep the surrounding journey
envelope/secret representation unchanged: the new rule-version boundary does
not require a migration of unrelated journey fields.

Keep rule order, the 64-rule limit, duplicate-journey rejection and project-only
controls. A missing configured listener is an advisory UI condition, not a reason
to reject an otherwise valid saved port. Old rule documents are negative fixtures
for explicit rejection, not compatibility fixtures that implementation must load.

### 3. Share bounded compilation and publish matching plans atomically

Create [BoundedRegex.java](../../bapp/src/main/java/bpsh/pattern/BoundedRegex.java)
and its [README.md](../../bapp/src/main/java/bpsh/pattern/README.md). The shared leaf
provides `compile(source, flags)` returning the RE2/J pattern and a nested safe
failure type containing only a reason category and optional syntax index.
Enforce nonblank source, 4096 UTF-8 bytes and 10,000 compiled instructions.
Do not retain or chain the original pattern-bearing syntax exception in a
user-visible diagnostic. Callers supply context-specific messages.

Modify [RecoveryPattern.java](../../bapp/src/main/java/bpsh/authentication/credentials/RecoveryPattern.java)
to delegate compilation to that leaf while preserving its existing exception
type, recovery messages and DOTALL behavior. Existing extraction algorithms are
outside this change; do not widen their grammar or change their limits.

Create [RequestRuleMatcher.java](../../bapp/src/main/java/bpsh/burp/http/RequestRuleMatcher.java).
Its factory compiles the regex rules in one immutable Controls snapshot with
default flags. It exposes separate automatic-selection and tagged-recovery
operations, as specified below. AllRequests must not need a URL helper; scope
and URL access remain lazy and occur only after explicit-tag classification.
Prefix uses the current URI string and literal startsWith behavior. Regex uses
find on the unmodified Burp URL, with no decoding, normalization or automatic anchoring.

Define its immutable Context as exchange, nullable supported Tool, and nullable
incomingPort. An unsupported tool is null for automatic selection. The factory
binds one validated Controls snapshot, and both operations below use only that
snapshot and its compiled patterns:

- `automaticRules(request, context)` returns enabled matching AutomaticRule
  values in configured order. Require captured Controls.enabled and a selected
  supported tool, then evaluate each rule's port and URL against the untagged
  request before injection.
- `taggedRecovery(usedIdentity, committedRequest, context)` returns an optional
  Recovery policy. Require captured Controls.enabled, an enabled rule for the
  used identity's scoped journey key, matching actual port and matching committed
  URL. Do not consult Controls.tools. Return no policy when these conditions do
  not match; the resolved explicit use keeps its default disabled recovery.

Use the same port predicate in both operations: null restriction matches any
context; a restricted port requires Family.PROXY, Tool.PROXY and that actual
incomingPort. Non-Proxy or missing/invalid metadata never supplies a port by
inference. The one-rule-per-journey invariant makes tagged attribution unambiguous.
Do not use a request's pre-substitution URL for tagged recovery.

SessionRequestProcessor resolves explicit tags first, commits the complete
request and obtains Resolved.uses(). It maps each explicit use through
taggedRecovery using that committed request and the already captured Applied
snapshot, retaining identity/version and replacing only the recovery policy when
present. It then records the uses and replay template under the family-qualified
exchange. Tagged credentials still resolve with the master switch off or the
tool excluded; only configured recovery attribution depends on the master switch.
Do not apply this lookup to direct HTTP-authentication delivery or rematch pinned
replay policies.

Create [RequestControlState.java](../../bapp/src/main/java/bpsh/burp/http/RequestControlState.java).
This owns one atomic reference to an immutable Applied value containing the source
Controls and its RequestRuleMatcher. `prepare(Controls)` validates/compiles without
publishing; `publish(Applied)` performs the single replacement; `snapshot()` returns
the pair, exposed as `Applied.controls()` and `Applied.matcher()`. Readers capture
it once per request. There is no separately updated
regex cache or listener restriction and no unbounded pattern map.

In project load/save paths, prepare this pair before storage publication. Retain
the existing conflict-checked save, catalog publication and coordinator policy
update, then publish the prepared pair. Verify that the saved Controls match the
prepared source; use the committed document when updating the visible editor.
Failed validation or save leaves the previous applied pair intact. Library-only
saves must not replace project controls. Remove the old raw AtomicReference of
Controls from host/UI wiring rather than maintain two mutable control stores.

Modify [architecture.gradle.kts](../../bapp/gradle/architecture.gradle.kts) and
[code-structure.md](./code-structure.md) to register `bpsh.pattern`
as a leaf with no application-package dependencies. Permit credentials, Burp HTTP
and persistence to consume it. Keep `bpsh.request` JDK-only with its current inward
dependencies. No Swing, Montoya or Playwright dependencies enter core contracts.

### 4. Give listener discovery one read-only host boundary

Create [ProxyListeners.java](../../bapp/src/main/java/bpsh/burp/http/ProxyListeners.java).
It exports only `proxy.request_listeners` from Montoya and parses the returned
`proxy.request_listeners` array. Read integer `listener_port` and configured
`running` state; preserve advisory binding fields without resolving addresses or
opening sockets. Group valid entries by port, sort ports numerically and expose
immutable choices. Unknown optional settings do not invalidate valid ports;
malformed required structure produces a safe refresh failure.

The same class owns `incomingPort(listenerInterface)` for callback metadata.
Treat the binding prefix as opaque, require it to be nonempty, and parse the
terminal colon plus decimal port strictly. Accept bracketed IPv6 and wildcard
binding prefixes without splitting on their earlier colons. Reject missing
metadata, missing/non-numeric suffixes and ports outside 1–65535; return no identity
rather than guessing from service destination, source address or UI selection.

UiController schedules exports on its existing I/O worker only after the Session
handling surface is active. Coalesce refresh requests made on opening, focus
return or dropdown opening. Return results to the EDT using the current project
epoch; discard late results after project changes or unload. Keep last-known
choices and a missing saved selection after failures. Do not change controls,
start authentication, or save merely because listener availability changed.

### 5. Refactor request handling into shared operations and thin adapters

Create these production files, with the following single owners:

| File | Contract and reason |
| --- | --- |
| [RequestExchange.java](../../bapp/src/main/java/bpsh/burp/http/RequestExchange.java) | Immutable pair of existing `AuthTrafficGuard.Family` and host message ID; safe labels include both. Reuse the existing family enum instead of inventing a competing namespace. |
| [SessionRequestProcessor.java](../../bapp/src/main/java/bpsh/burp/http/SessionRequestProcessor.java) | Shared ordinary/tagged request preparation, matching, resolution, atomic commit, safe failure mapping and recording of the exact used versions. Its context supplies HttpRequest, annotations, family-qualified exchange, eligible tool and optional incoming port. Its result is continue-with-request or drop-with-annotations; it does not return a Montoya callback-specific action. |
| [HttpAuthenticationDelivery.java](../../bapp/src/main/java/bpsh/burp/http/HttpAuthenticationDelivery.java) | Extract current authenticatedRequest orchestration, preserving directive consumption, dependent-tag resolution, exact origins, deadline/admission, body ownership, Authorization replacement, actual-response materialization and indeterminate-delivery semantics. The global adapter translates the result to spoof; no NTLM logic is copied from the existing transport. |
| [RecoveryReplayDelivery.java](../../bapp/src/main/java/bpsh/burp/http/RecoveryReplayDelivery.java) | Own the existing bounded replay executor, active replay leases/jobs, one-time claim, final generation/version checks, transport dispatch and cleanup. Keep two workers and the existing queue cap of 256. |
| [GlobalHttpSessionAdapter.java](../../bapp/src/main/java/bpsh/burp/http/GlobalHttpSessionAdapter.java) | Implement HttpHandler: classify guard/replay first, handle explicit HTTP directives, bypass ordinary PROXY requests, then invoke the shared processor for other sources. Global responses consult only GLOBAL attribution. Unsupported tool origins remain ineligible for automatic rules; explicit tags retain their policy. |
| [ProxyHttpSessionAdapter.java](../../bapp/src/main/java/bpsh/burp/http/ProxyHttpSessionAdapter.java) | Implement ProxyRequestHandler and ProxyResponseHandler. Preserve received-stage interception/owned-login policy; process ordinary/tagged requests at final send with the actual incoming port; request native Proxy DROP for failed tagged processing without a global retry or internal marker. Defer explicit HTTP directives unchanged to global handling. Proxy responses consult only PROXY attribution; final response handling preserves normal Burp policy. |

Both adapters call the same ownership classification and safe annotation helpers;
keep these small helpers within the shared processor rather than duplicate them.
Do not add an interface for each concrete adapter. Keep annotations for operator
notes only and preserve existing user notes/highlights.

Modify [NativeTagResolver.java](../../bapp/src/main/java/bpsh/burp/http/NativeTagResolver.java)
to validate prepared output against reserved control syntax before publishing a
Resolved result. Captured data must not create an HTTP-authentication directive
or an owned User-Agent marker that a later callback would execute. Reuse the
existing directive detector and guard grammar, not a second parser in the UI or
adapters. A captured value containing ordinary native-tag-looking text remains
data and is not parsed again. Apply the same output validation to freshly
prepared recovery templates.

Modify [AuthTrafficGuard.java](../../bapp/src/main/java/bpsh/browser/AuthTrafficGuard.java)
to expose a pure reserved-marker predicate for that validation; it must not
grant ownership or insert ledger entries. Preserve its existing random leases,
independent response ledgers and marker-stripping contract. Change its
[test](../../bapp/src/test/java/bpsh/browser/AuthTrafficGuardTest.java) to cover that
predicate alongside unchanged owned/stale/ambiguous marker behavior.

Modify [Diagnostics.java](../../bapp/src/main/java/bpsh/burp/http/Diagnostics.java) so
request notices and replay references identify the callback family and ID. Keep
safe messages and the existing aggregate rate-limiting policy; do not double
suppression capacity by creating a Diagnostics instance per adapter.

Delete `HttpSessionHandler.java`
after callers and tests use the new owners. Do not keep a forwarding facade,
an annotation bridge, a content-join cache or an obsolete global automatic path.

### 6. Carry response attribution through one recovery implementation

Modify [SessionRecovery.java](../../bapp/src/main/java/bpsh/burp/http/SessionRecovery.java)
so record, receive/receivedPlan, Pending and ReplayPlan use RequestExchange
instead of an unqualified long ID. Keep a single aggregate attribution map,
template budget, pending/ready-plan accounting and expiration clock. Remove
obsolete family-less overloads and update their callers.

Expose the original exchange from a replay plan. After claim, RecoveryReplayDelivery
registers the replay against its actual GLOBAL exchange and records its used
versions as replay provenance. A Proxy original keeps its PROXY reference in
notes and diagnostics, while the replay's response is consumed in GLOBAL.
No cross-family lookup or ordinary-rule rematch is performed. Preserve the
original response, shared reauthentication, pause-on-rejected-replacement behavior,
one replay per original, lazy body evaluation and exact version invalidation.

Release reservations on overwrite within the same family, expiration, eviction,
failed preparation, cancellation and unload. Equal numeric IDs in different
families must occupy distinct records while still sharing the same global caps.

### 7. Wire lifecycle and the native rule editor

Modify [Extension.java](../../bapp/src/main/java/bpsh/Extension.java) to construct one
RequestControlState, processor, direct-delivery owner, replay-delivery owner,
listener reader, diagnostics and recovery service. Register the global adapter
as HttpHandler and the Proxy adapter for both Proxy handler interfaces. Extend
the inert capability check to final-Proxy continuation and global drop. On unload, close admission, cancel shared owned work, deregister hooks, discard
late refresh results and close each service once. Proxy drops remain best effort.
Preserve the existing
UI-save and browser/transport teardown ordering; do not create another worker
pool for listener refresh. A shared processing-closed state must reject new
explicit/direct/replay work in callbacks still entering during shutdown; ordinary
requests keep the existing unchanged-forwarding policy. Do not promise callback
execution after Burp removes the registration.

Modify [UiController.java](../../bapp/src/main/java/bpsh/burp/ui/UiController.java)
to consume RequestControlState and the read-only listener reader. Update project
load, save and apply-controls paths to the prepare/save/publish contract above.
The UI continues to edit/store through existing editing/persistence services;
neither the matcher nor the adapters can mutate JourneyWorkspace.

Modify [AutomaticRulesPanel.java](../../bapp/src/main/java/bpsh/burp/ui/AutomaticRulesPanel.java):

- Keep the three visible URL choices: Burp target scope, All requests and URL.
  Internally map URL plus Use regex unchecked to Prefix, and checked to Regex.
  Use a UI-only three-choice selector rather than retain the removed UrlMode enum.
- Keep one raw-text URL draft value, one Use regex checkbox and nullable port
  selection. Only the URL choice shows its field/checkbox. Switching the checkbox
  preserves text exactly. Switching from URL to All requests or Burp target scope
  clears the URL draft, matching the current editor behavior. Preserve the existing
  recovery-field clearing rules.
- Change the field label to URL. Unchecked uses the existing prefix tooltip;
  checked uses exactly “Regex matched anywhere in the URL.” Render error position
  and safe correction guidance inline without placing the raw expression in logs.
- Add Proxy port with Any listener and deduplicated configured ports. Preserve a
  selected absent/stopped port as an explicit choice with advisory text. Updating
  choices must not emit a controls edit or reset unfinished URL text.
- Add a Proxy port table column and distinguish prefix versus regex in the URL
  summary. Keep array order, explicit move controls, native sizing/theme, literal
  renderers, keyboard access and the approved later-destination-wins guidance.

### 8. Update native tests and captured production overlays

These are behavioral tests, not evidence that Burp propagates callbacks as a
simulated host does. Reuse the existing controlled scheduler, Host double,
IntegrationFixtures and authentication-lab account servers.

| File | Action and required evidence |
| --- | --- |
| [BoundedRegexTest.java](../../bapp/src/test/java/bpsh/pattern/BoundedRegexTest.java) | Add: valid grammar/flags and source/program-size boundaries; errors do not echo the source; recovery keeps DOTALL while URL defaults do not add it. |
| [AutomaticRuleCodecTest.java](../../bapp/src/test/java/bpsh/journey/persistence/AutomaticRuleCodecTest.java) | Add: current rulesVersion and all four typed URL conditions, explicit null/selected port, strict member/type/range rejection, explicit rejection of old unversioned layouts and unsupported versions, order and round trips without compiled/display state. Keep fixtures as small test literals in this file. |
| [RequestRuleMatcherTest.java](../../bapp/src/test/java/bpsh/burp/http/RequestRuleMatcherTest.java) | Add: URL-only, port-only and AND matrix; prefix literals, substring regex, anchors, default case and inline flags; non-Proxy/missing port cannot match restricted rules. Separately verify ordinary tool filtering versus taggedRecovery from excluded tools, master on/off, referenced identity, committed URL after substitution, and matching/missing/restricted Proxy ports; avoid unnecessary URL/body reads. |
| [RequestControlStateTest.java](../../bapp/src/test/java/bpsh/burp/http/RequestControlStateTest.java) | Add: failed preparation/publication retains the prior pair; concurrent requests observe one complete source/compiled snapshot rather than mixed port/pattern settings. |
| [ProxyListenersTest.java](../../bapp/src/test/java/bpsh/burp/http/ProxyListenersTest.java) | Add: deduplicated/sorted configured ports, stopped/unknown fields, malformed export and callback suffixes, wildcard/IPv6 metadata, and no guessing from destination/source ports. |
| [SessionRoutingTest.java](../../bapp/src/test/java/bpsh/burp/http/SessionRoutingTest.java) | Add: separate request objects, annotations and ID namespaces for Proxy and global stages; token data is processed once, explicit HTTP directives defer once, reserved-control output cannot become commands, and copied Repeater/Intruder requests have no implicit listener. A tagged excluded-tool request still receives recovery from a qualifying unrestricted rule when the master is on; a restricted-port rule does not qualify without actual Proxy context. |
| [NativeTagPipelineTest.java](../../bapp/src/test/java/bpsh/burp/http/NativeTagPipelineTest.java) | Modify existing Host to compose new owners, set source tool/port per callback, support final-Proxy factories, and publish Controls through prepare/publish. Update constructor references and maintain existing global-tag, failures, policy, menu and owned-traffic assertions. Do not make shared annotations across hooks the default. |
| [OrderedSessionHandlingTest.java](../../bapp/src/test/java/bpsh/burp/http/OrderedSessionHandlingTest.java) | Modify rule constructors and family-qualified attribution; add overlapping unrestricted/port-restricted rules proving no hidden specificity priority and final-winner recovery. |
| [SessionRecoveryTest.java](../../bapp/src/test/java/bpsh/burp/http/SessionRecoveryTest.java) | Modify exchange API; cover equal IDs across families, Proxy original to GLOBAL replay, one-use consumption, shared capacity/expiry/cancellation, original response retention and existing recovery pause semantics. |
| [HttpAuthenticationHookTest.java](../../bapp/src/test/java/bpsh/burp/http/HttpAuthenticationHookTest.java) | Modify host/constructor references; preserve Basic/NTLM account, body, actual-error-response and no-fallback assertions; add Proxy-deferred direct delivery with no ordinary automatic pass. |
| [AutomaticRulesPanelTest.java](../../bapp/src/test/java/bpsh/burp/ui/AutomaticRulesPanelTest.java) | Modify: Prefix/Regex map to the checkbox and shared field, exact tooltip, default case, port selection/missing state, table summary and invalid edits retaining applied controls. |
| [UxControlMatrixTest.java](../../bapp/src/test/java/bpsh/burp/ui/UxControlMatrixTest.java) | Modify constructor/control wiring and conditional URL/regex/port presentation without changing unrelated journey workflows. |
| [JourneyRegistryTest.java](../../bapp/src/test/java/bpsh/burp/ui/JourneyRegistryTest.java) | Modify the shared UI Host constructor and Controls access to RequestControlState; preserve storage conflict, applied-settings and journey-registry assertions for its dependent UI tests. |
| [AutoSaveLoginTest.java](../../bapp/src/test/java/bpsh/burp/ui/AutoSaveLoginTest.java) | Extend project-save checks: compile before persistence/publication, failed/stale saves retain applied settings, and listener-only refresh does not autosave or start authentication. |
| [JourneyRecordingTest.java](../../bapp/src/test/java/bpsh/burp/ui/JourneyRecordingTest.java) | Update shared UI Host controls access to Applied.controls; preserve recording save/publication and draft isolation behavior. |
| [DiagnosticsTest.java](../../bapp/src/test/java/bpsh/burp/ui/DiagnosticsTest.java) | Modify request reference API; preserve redaction, note content and aggregate suppression across families. |
| [JourneyEventLogTest.java](../../bapp/src/test/java/bpsh/burp/ui/JourneyEventLogTest.java) | Update references to the extracted hooks/recovery, retaining observed event outcomes. |
| [CombinedCredentialsTest.java](../../bapp/src/test/java/bpsh/authentication/credentials/CombinedCredentialsTest.java) | Update changed attribution references; retain complete-output and token/cookie lifetime assertions. |
| [BrowserJourneyIntegrationTest.java](../../bapp/src/test/java/bpsh/browser/BrowserJourneyIntegrationTest.java) | Update actual hook ownership/reference wiring while retaining account and owned-browser isolation evidence. |
| [IntegrationFixtures.java](../../bapp/src/test/java/bpsh/support/IntegrationFixtures.java) | Reuse unchanged; it contains no removed hook/model constructors to migrate. Its existing fixture proxy and browser runtime remain the shared verification boundary. This row is a dependency, not a planned write. |

Update the following captured production overlays to the new construction and
RequestExchange API while retaining their assertion IDs and independent fixture
observations. They run only in the isolated captured production build:

| File | Reason |
| --- | --- |
| [NativeTagPipelineTest.java](../../test/authentication-lab/production-tests/bpsh/burp/http/NativeTagPipelineTest.java) | Adapt the acceptance Host and request-source distinctions; retain actual production request/tag and owned-traffic observations. |
| [SessionRecoveryTest.java](../../test/authentication-lab/production-tests/bpsh/burp/http/SessionRecoveryTest.java) | Preserve recovery-matrix evidence with family-qualified originals/replays and the existing aggregate resource observations. |
| [DiagnosticsTest.java](../../test/authentication-lab/production-tests/bpsh/burp/ui/DiagnosticsTest.java) | Update family-labelled notice calls without weakening redaction or suppression assertions. |
| [JourneyRegistryTest.java](../../test/authentication-lab/production-tests/bpsh/burp/ui/JourneyRegistryTest.java) | Adapt the shared acceptance UI Host to atomic applied controls while retaining registry/storage witness methods and assertion IDs. |
| [JourneyEventLogTest.java](../../test/authentication-lab/production-tests/bpsh/burp/ui/JourneyEventLogTest.java) | Adapt hook ownership references; preserve error/warning/info outcomes. |
| [CombinedCredentialsTest.java](../../test/authentication-lab/production-tests/bpsh/authentication/credentials/CombinedCredentialsTest.java) | Adapt attribution API; preserve the accepting service's account/output-set proof. |
| [BrowserJourneyIntegrationTest.java](../../test/authentication-lab/production-tests/bpsh/browser/BrowserJourneyIntegrationTest.java) | Adapt extracted hook references without changing browser login, capture or fixture ownership. |

Modify [production-selection.json](../../test/authentication-lab/src/main/resources/production-selection.json)
to select the new native rule/codec/state/listener/routing owners as additional
component checks in the captured production invocation. Do not label them as
newly proven catalog requirements or count their host doubles as real Burp
coverage. Existing production-policy method selections remain valid by retaining
their behavioral test method names; do not silently drop existing owners.

Use these exact additional component-owner methods, with related boundary cases
inside each owner, so the selection file contains concrete executable names:

- `bpsh.pattern.BoundedRegexTest.boundedCompilationPreservesFlagsAndRedactsFailures`
- `bpsh.journey.persistence.AutomaticRuleCodecTest.currentTypedRulesRoundTripAndUnsupportedLayoutsAreRejected`
- `bpsh.burp.http.RequestRuleMatcherTest.urlAndIncomingPortConditionsMatchIndependentlyAndTogether`
- `bpsh.burp.http.RequestControlStateTest.concurrentRequestsObserveOneCompleteAppliedSnapshot`
- `bpsh.burp.http.ProxyListenersTest.configuredChoicesAndCallbackPortsAreParsedWithoutFallback`
- `bpsh.burp.http.SessionRoutingTest.proxyAndGlobalAdaptersProcessEachRequestOnceWithoutMetadataSharing`

### 9. Maintain the existing real-Burp helper and binding evidence

Modify [HostProbeExtension.java](../../test/authentication-lab/src/hostProbe/java/lab/auth/HostProbeExtension.java)
to add an opt-in bounded callback-observation mode for explicitly selected local
fixture traffic. Observe Proxy/global requests and responses with their actual
families, IDs, incoming port, tool, phase and safe fixture outcomes; do not perform
authentication, choose journeys or forward an intercepted application request
from the helper. Preserve its existing explicit single-send Extensions action.
Keep fixture filtering, export and clear controls local to the probe tab; do not
add a remote-control service. Bound each capture to 1000 events, mark overflow
as incomplete evidence, and release registrations/capture state on unload.

Use the existing [Build-HostProbe.ps1](../../test/authentication-lab/Build-HostProbe.ps1)
unchanged to package it. The following helper documentation changes describe the
additional observation mode and its limits:

- [hostProbe/README.md](../../test/authentication-lab/src/hostProbe/README.md): distinguish explicit dispatch from passive observation.
- [host probe package README.md](../../test/authentication-lab/src/hostProbe/java/lab/auth/README.md): document fixture filtering, fields, capacity, cleanup and the unchanged no-authentication boundary.
- [authentication-lab/README.md](../../test/authentication-lab/README.md): document the two-listener manual recipe, source/artifact identity, server-side send/account proof and separate platform results.

Binding refresh writes every data file indexed by the existing catalog. Explicitly
review these ten files for fingerprint/configuration changes, preserving the
requirement meanings and assertion IDs:

- [fixtures.json](../../test/authentication-lab/src/main/resources/catalog/fixtures.json): fixture-owner source/configuration fingerprints.
- [browser.json](../../test/authentication-lab/src/main/resources/catalog/browser.json): browser-owner fingerprints after hook composition changes.
- [credentials.json](../../test/authentication-lab/src/main/resources/catalog/credentials.json): output/tag/injection owner fingerprints.
- [recovery.json](../../test/authentication-lab/src/main/resources/catalog/recovery.json): family-aware recovery owner fingerprints and source witnesses.
- [registry.json](../../test/authentication-lab/src/main/resources/catalog/registry.json): existing controls/configuration owner fingerprints.
- [federation.json](../../test/authentication-lab/src/main/resources/catalog/federation.json): shared configuration fingerprints without altering federation semantics.
- [transport.json](../../test/authentication-lab/src/main/resources/catalog/transport.json): shared configuration fingerprints without changing transport algorithms.
- [http-authentication.json](../../test/authentication-lab/src/main/resources/catalog/http-authentication.json): existing direct-delivery owner fingerprints.
- [burp.json](../../test/authentication-lab/src/main/resources/catalog/burp.json): shared configuration fingerprints; manual rows remain manual evidence.
- [assessments.json](../../test/authentication-lab/src/main/resources/catalog/assessments.json): refresh existing bound fingerprints only; unbound assessments remain unproven.

Before refresh, remove any deleted HttpSessionHandler source-path witness and
replace it with the concrete new owner(s) that actually implement the same
assertion. Update only affected binding witness/hash entries; the refresh command
does not infer ownership changes and will fail on a deleted source. Retain
unbound rows and explicit exclusions. Review the diff before running acceptance
in a separate invocation. No federation-client source changes or duplicate lab
servers are part of this feature.

### 10. Update current contracts and remove obsolete references

| File | Required update |
| --- | --- |
| [README.md](../../README.md) | Explain URL prefix versus Use regex and configuring a browser's incoming proxy port; distinguish copies from retained credentials already present in a copied request. |
| [docs/product.md](../product.md) | Record port-only selection, AND behavior, regex that is case-sensitive by default, listener-only scope and preserved ordering/tool/tag behavior. |
| [docs/designs/interface.md](./interface.md) | Specify the single field/checkbox, exact tooltip, table/port controls, inline validation and missing-listener state. |
| [docs/designs/bapp-owned-authentication.md](./bapp-owned-authentication.md) | Replace global-only processing assumptions with the ownership table, family-qualified recovery and bounded publication. |
| [docs/designs/http-authentication.md](./http-authentication.md) | Replace HttpSessionHandler path references with the direct-delivery/global adapter owners; preserve direct identity, spoofing and origin contracts. |
| [docs/designs/browser-journey-recording.md](./browser-journey-recording.md) | Replace obsolete combined-handler references with the shared processor and adapters while preserving owned-browser marker/interception requirements. |
| [docs/designs/code-structure.md](./code-structure.md) | Document the new shared pattern leaf and actual host/compiled-state owners in the enforced acyclic graph. |
| [docs/README.md](../README.md) | Index this design at designs/session-handling-by-url-and-proxy-port.md; describe implementation/qualification status truthfully. |
| [this design](./session-handling-by-url-and-proxy-port.md) | Keep actual implementation/qualification status current, and replace its current-handler resource link with the implemented processor/adapters when CP2 removes that handler. |
| [bapp/README.md](../../bapp/README.md) | Document the new focused checks and exact-JAR two-platform verification; preserve universal build instructions. |
| [bpsh/README.md](../../bapp/src/main/java/bpsh/README.md) | Add the shared pattern leaf and revised composition responsibilities. |
| [request/README.md](../../bapp/src/main/java/bpsh/request/README.md) | Describe optional incoming port and separate raw prefix/regex values; keep core free of host and regex implementation imports. |
| [burp/http/README.md](../../bapp/src/main/java/bpsh/burp/http/README.md) | Replace the deleted handler interface entry with the actual processor, adapters, matcher/state, listener reader and delivery owners and their invariants. |
| [burp/ui/README.md](../../bapp/src/main/java/bpsh/burp/ui/README.md) | Describe the updated rule editor and advisory listener refresh without moving storage ownership into the UI. |
| [credentials/README.md](../../bapp/src/main/java/bpsh/authentication/credentials/README.md) | Explain that RecoveryPattern retains recovery policy/messages while bounded compilation lives in the shared leaf. |
| [persistence/README.md](../../bapp/src/main/java/bpsh/journey/persistence/README.md) | Document the current versioned typed-rule layout, explicit rejection of unsupported blocks and source-only serialization. |

The new pattern README is listed in item 3. The maintained feature design is this document at
`docs/designs/session-handling-by-url-and-proxy-port.md`. Keep one current copy
and do not create a historical archive. Do not
commit generated JARs, browser payloads, captured builds or local probe reports.

### 11. Execute verification and deliver the exact development artifact

First run the changed native owners, then the complete required native checks:

```powershell
.\bapp\gradlew.bat -p bapp check verifyNativeDocumentation --offline --console=plain
```

Build the existing helper through its current packaging script and run the
explicit binding maintenance operation:

```powershell
.\test\authentication-lab\Build-HostProbe.ps1 -JdkHome 'C:\Program Files\Java\jdk-21'
.\bapp\gradlew.bat -p bapp :auth-lab:refreshBindings --offline --console=plain
```

Inspect all refreshed diffs. In a new invocation, run captured component and
browser acceptance and the affected direct HTTP/transport and federation
regressions using their existing prerequisites. Record missing token/provider
prerequisites as pending and identify the prerequisite. Report native Host-double
results as component evidence; record Burp VM results separately:

```powershell
.\bapp\gradlew.bat -p bapp authLabComponentTest --offline --console=plain
.\bapp\gradlew.bat -p bapp authLabBrowserTest --offline --console=plain
.\bapp\gradlew.bat -p bapp authLabTransportTest --offline --console=plain
.\bapp\gradlew.bat -p bapp authLab -PlabProfiles=federation --offline --console=plain
.\bapp\gradlew.bat -p bapp jar --offline --console=plain
```

The final command builds directly to
`bapp/build/libs/browser-powered-session-handler-dev.jar`, bundling Windows x64,
Linux x64 and Intel macOS. Do not build a candidate JAR to preserve older bytes.
Record its SHA-256. Required checks and this JAR must exist before starting
Computer Use so the user can inspect the artifact even if GUI work is cancelled.

When GUI verification is authorized, use fresh temporary projects in the existing
Windows 11 and Ubuntu verification VMs named in repository instructions. Existing
projects with unsupported stored rules are not qualification prerequisites.
Transfer this exact JAR,
verify each guest checksum, and refresh the existing product extension by toggling
Loaded off/on. Use the installed Burp and normal extension loading. Keep guest
keys/credentials out of logs. WSL is not a substitute for Linux Burp verification.

For each platform, record these concrete outcomes against the current JAR:

| Case | Required outcome |
| --- | --- |
| Two ports, identical simultaneous requests, separate journeys | The accepting service sees the expected account for each port, with exactly one original application send per client request. |
| URL-only, port-only, and combined rule | Each independently matches as configured; the combined rule requires both conditions and an unmatched rule adds no credentials. |
| Same port on another supported binding | Port assignment is unchanged; no address-based reassignment is inferred. |
| Prefix, regex substring, anchors, case and invalid edits | Literal behavior survives reload; regex searches the full URL with the approved default case; invalid drafts retain prior applied controls and do not autosave partial settings. |
| Manual interception and edited URL | Final Proxy processing uses the forwarded URL; normal user interception remains available. |
| Overlapping rules | Existing order decides final header/cookie values; only surviving versions own recovery. |
| Expired Proxy session | The original response is retained, one shared recovery occurs, each authorized original has at most one separately identified global replay, and replay rejection cannot cause another replay. |
| Copy to Repeater/Intruder | No incoming listener is attributed; listener-restricted rules do not apply. Existing copied credential bytes remain ordinary request data. URL-only rules and explicit tags retain their behavior. |
| Explicit HTTP-auth directive through Proxy and Repeater | Independent fixture evidence confirms the selected account/protocol, actual response and no second original send; automatic rules do not select the direct identity. |
| Stop/delete/recreate listener and failed refresh | The saved port remains selected, never becomes Any listener, and becomes applicable again only to actual incoming traffic on that port. |
| Cancellation and unload under pending work | Owned wait/replay/refresh resources close, no late result is published and aggregate retention limits are released. Proxy drop delivery prevention is best effort; no internal handoff or unload guarantee is required. |

Retain current source identity, artifact hashes, test completion, safe server
observations and platform-specific Burp results in ignored build reports. Mark
unexercised cases as pending, not passed. A build, a source binding or a previous
VM report is not evidence that the current artifact passed these cases.

## Additional Resources

- [Product contract](../product.md)
- [Session handling interface contract](./interface.md)
- [Request settings and automatic rules](../../bapp/src/main/java/bpsh/request/RequestSettings.java)
- [Current rule editor](../../bapp/src/main/java/bpsh/burp/ui/AutomaticRulesPanel.java)
- [Shared outgoing request processing](../../bapp/src/main/java/bpsh/burp/http/SessionRequestProcessor.java)
- [Burp proxy listeners](https://portswigger.net/burp/documentation/desktop/settings/tools/proxy)
- [Proxy request listener metadata](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/proxy/http/InterceptedRequest.html)

*Drafted with EGM*
