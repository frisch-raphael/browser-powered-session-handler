# Browser Powered Session Handler

<!-- impeccable:product-schema 1 -->

## Platform

Native desktop Java Swing inside Burp Suite. Impeccable's web/iOS/Android platform
categories do not describe this surface; web detectors and browser overlays do
not assess these components.

## Users and purpose

Burp users configure automated browser authentication journeys, test them, and
reuse the resulting credentials in HTTP requests through saved journey tags or
optional automatic injection. A successful journey can authenticate repeatedly
without interactive PIN or certificate prompts.

## Confirmed workflow

The guided wizard covers setup,
login steps, token capture, optional PKCS#11 certificate setup, then review/testing
and tag usage. Existing saved journeys remain editable. Changes autosave after
500 ms without editing; navigation and execution flush the latest edits first.
Plus immediately creates a new saved journey. Incomplete settings are retained;
configuration errors appear when executing the journey.
Duplicate selected creates and opens an independent copy in the same collection,
with a unique name/tag and session-only configured secrets. Cached credentials
and automatic session-handling rules are not copied.
Browser recording supports
Enter, Ctrl+Enter, Tab and Shift+Tab.
Review explains omitted interactions and allows replacing partial recordings
so users can finish the steps manually before Test login. Save activity belongs
only in Event log, with coalesced Info successes, Warning while a temporary
retry is pending, and Error when saving stops. There are no manual-save controls
or Save/Discard prompts. Insert tags from the request context menu using a saved, active journey reference. Keep shared Cancel authentication.

## Capabilities and constraints

- The BApp owns authentication. No Python API or Hackvertor dependency is used.
- Each journey can use one optional HTTP proxy URL; empty means direct. The user
  explicitly removed configured proxy Basic authentication support. Reject
  credential-bearing URLs and credential fields with actionable guidance.
- Ordinary journeys use the configured proxy directly. Only mTLS journeys create
  the attempt-owned Java TLS proxy; its internal access credentials remain an
  implementation detail, independent of configured upstream proxy support.
- **Allow untrusted HTTPS certificates** is an explicit journey setting, off by
  default, for browser recording and login through either direct or proxied
  connections. It changes no system trust or other journeys. The mTLS transport
  retains its upstream server verification and optional Trusted CA bundle.
- Java uses vendor PKCS#11 middleware and an exact certificate fingerprint. PINs
  are configured explicitly; multiple certificates with the same subject remain
  distinguishable. PKCS#12 support is out of scope.
- Saved journeys have explicit project/library storage. Alias collisions can be
  saved and repaired, but block execution; there is no implicit collision winner. Tag resolution is independent of
  automatic injection's enable/tool/URL rules.
- The editor derives the request-tag alias from the journey name and keeps it
  internal. Test & use offers Copy BPSH tag, including named credentials
  and explicit encodings, without acquiring credentials. Renaming updates the alias when saved, so existing
  request tags need updating. Existing/imported aliases remain intact until the
  name is edited; duplicate generated aliases block execution with rename guidance.
- HTTP-only journeys offer Copy HTTP authentication header as a direct action.
  Mixed journeys offer that header alongside tags and encodings for their
  configured captured credentials. The HTTP settings explain that the custom
  header applies authentication to its request and is removed before delivery;
  its example uses the selected journey's current tag name.
- Previously used aliases are freely reusable after rename/deletion. Naming and
  the meaning of existing request tags are the user's responsibility; there is
  no retired-name reservation or reassignment acknowledgement. Legacy retirement
  metadata is accepted for compatibility, ignored for resolution and dropped on save.
- Tags use literal raw HTTP notation and explicit URL/form/JSON wrappers. A tag
  failure stops the request; ordinary authentication failure forwards unchanged
  with a warning. Preserve all existing admission, timing and cancellation rules.
- Remember secrets is off by default. Remembered values are readable in storage;
  export inclusion is a separate unchecked choice. Tokens and private keys are
  never exported. Cached tokens and cookies are visible only in the explicitly
  opened Journey cache inspector; they never enter event logs or saved config.
- Journey cache also shows HTTP identities and their latest observed result per
  allowed origin, including HTTP-only journeys. Event log reports NTLM handshake
  stages, server acceptance and actionable failures for every
  delivery path. Passwords, authentication payloads and raw exceptions stay out
  of both views. Clear cache fences late observation updates.
  Routine authenticated connection reuse updates cache observations without
  appending an event for each request or redirect.
- For mTLS, Journey cache shows only the saved selected certificate's SHA-256
  fingerprint. It does not show origins or the last HTTPS result, and opening
  the inspector does not access certificate middleware, the PIN or private key.
- Changing HTTP authentication settings retires the previous connection pool
  automatically. Test login and subsequent automatic requests use the corrected
  identity without requiring Clear cache.
- Editing a journey keeps usable cached credentials and their original expiry
  and refresh times, including while an unfinished edit temporarily blocks
  execution. Renaming, reordering or removing captured outputs retains matching
  sources. A newly required capture source needs a fresh login. Clear cache,
  deletion, unavailability and expiry still discard credentials; a successful
  new login replaces them.
- Browser assets for Windows x64, Linux x64 and Intel macOS are bundled in one universal offline JAR. No runtime browser
  download or separate Java executable is required by the extension.

The interface uses Project/User collection tabs and compact icon
actions, conditional input clearing, automatic saving of injection rules and
waiting settings (with durations in seconds),
combined named JSON/cookie credentials and either-condition session recovery.
Multiple credentials require user-defined names and use
`<@journey_name token="token_name"/>`; a single value uses `<@journey_name/>`.
Encoding wrappers have no `bpsh:` prefix. The request context menu inserts literal
references and explicit encoding choices without reading token values.

## Interface commitments

Setup groups form-based, PKCS#11 client-certificate and HTTP authentication as
independent methods. Form-based authentication controls Login steps and is on for
new journeys. Disabled login steps remain saved and do not execute. Capture
credentials stays available; HTTP and client-certificate authentication can run with no captured token or cookie. Remove all capture rows for that mode. A transport-only test uses the configured request authentication and reports its server response without creating a token cache. Test & use requires at least one enabled method.

Preserve Burp's native theme, controls, fonts, keyboard conventions and dialog
parenting. Simplify duplicate checkbox labels: the checkbox owns its label and
adjacent help explains consequences. Keep advanced settings discoverable without
making them prerequisites for a normal first login. All slow work stays off the
Swing event dispatch thread.

The bottom toolbar contains Event log, Journey cache and contextual action
buttons, without authentication state, loaded/saved notices or other status text.
The per-journey Event log dock is inspired by Burp's bottom event log and retains timestamped
Info/Warning/Error history for automatic and explicit authentication, supports
filter/search and event details, and follows stable journey identity. Logs are
session-only and bounded; credential values and raw request/response data are
excluded. Repeated identical warnings/errors share one row with an occurrence
count and first/last seen times in its details, including across intervening
events. Valid tokenless HTTP/mTLS authentication does not warn about missing
captured credentials. The former phase line, permanent feedback box and separate test-result
box are removed. Automatic injection is named Session handling in the UI.
Successful Test login and Retry finish with a native popup summarizing captured
credential names and counts. Values remain in Journey cache. Errors associated
with a field, settings group or journey step appear inline at that location,
without an error popup. Explicit actions reveal and focus that location;
background validation never steals focus. Generic errors without an associated
UI location may use a popup.
Automatic authentication does not open completion popups.

## Evidence and acceptance

The implementation has unit, bundled-browser and owned SoftHSM integration tests.
Qualify responsive login, cancellation, cache actions, storage, transfer/secrets, certificate selection, tagged/automatic protected access, compact/wide forms and Burp themes against the delivered artifact. Stress, assistive-technology and physical-device checks require their own observations. The lab guide specifies current commands and evidence boundaries.

Automatic authentication uses ordered journeys selected by tool, URL and optional incoming Proxy listener. Captured journeys acquire their application credentials sequentially; later mappings overwrite earlier values at the same destination. A journey without capture can instead provide HTTP or client-certificate request authentication. The last matching transport-only journey whose exact allowed origins include the destination supplies that identity. Captured journeys with HTTP authentication retain their browser-login semantics; they are not silently converted into direct identity providers. A separately selected HTTP identity owns Authorization, so a capture used only for that overwritten header is not acquired. Other cookies and headers remain atomic. Explicit tags retain their independent request-wide policy.

Automatic requests use the project Automatic handling policy in Settings. **Wait for login** waits within the request deadline and allows the selected HTTP identity to negotiate authentication when needed. **Send immediately** preserves the whole original request when any required captured credential or transport identity is not ready, and starts or joins background authentication. For HTTP identities, background work sends a bounded HEAD for the actual permitted origin, preferring the configured protected login URL when it is on that origin in the reusable DIRECT pool, without the original body, application Authorization or cookies. Once ready, an automatic HTTP request uses existing authentication without challenge negotiation: an actually reused NTLM connection can authenticate it, while a cold connection's real 401 is retained and triggers background warmup for later requests. The original request is never replayed by this policy. Explicit journey tags remain independent and wait within their deadlines.

Token response capture streams matching Chromium response bodies with a 1 MiB decoded limit before extraction. Oversized explicitly path-filtered network responses are aborted. Origin-only capture and service-worker capture stop collecting each oversized response at the same decoded limit while ordinary browser delivery continues; unrelated page assets must not be blocked by broad capture. Responses within the limit retain their status and headers (with transport encoding headers adjusted for the decoded body).

## Request and native-resource bounds

Request admission defaults to 64 global and 16 per saved journey, with finite
operator-adjustable values. The callback budget includes direct HTTP authentication
through response delivery; Send immediately never waits for a pending login.
Automatic HTTP authentication under **Wait for login** queues at the Global delivery
boundary within the original request deadline, with at most 64 queued callbacks and
active plus queued work sharing the configured global limit. Per-journey active
work also respects the native scope ceiling of 16. Queued payload reservations
share the 512 MiB copy budget; queued work reserves no transport body or socket.
If capacity, cancellation or the deadline prevents dispatch, BPSH returns a local
503 without a server authentication challenge. A full Proxy handoff buffer drops
the request because that callback cannot supply a response. **Send immediately**
and capture-only automatic capacity failures retain unchanged forwarding with
diagnostics; explicit requests fail closed. Request-copy reservations total at most 512 MiB
and charge four times message length plus 16 MiB for bounded header expansion, imposing
a 124 MiB automatic-message ceiling.
Automatic edits process headers separately and preserve body bytes. Recovery
copies are admitted before construction, only for enabled detection, within
4 MiB per template and 32 MiB retained in aggregate.

Browser login and recording use only the installed Burp Browser. Automatic
selection prefers the running installation when identifiable; ambiguous or missing
installations require correction in Settings. A per-user explicit executable is
authoritative, survives invalid paths for correction and never enters project or
journey exports. Selection is captured afresh per attempt, with no retry of another
binary after launch failure. Verified bundled Node/driver files use the independent
`drivers-v3` cache. Every browser launch owns a separate process, temporary profile
and fresh context. BPSH never attaches to, reads, clears or terminates a user's
existing browser/profile and never imports cookies or storage from it.

Login and recording explicitly require Chromium sandboxing. Linux must allow the
installed Burp Browser to create the namespaces its sandbox requires; AppArmor policy can
restrict this permission. Its installed SUID sandbox helper must also have the ownership
and permissions required by Chromium. A confirmed native sandbox failure reports this
prerequisite with administrator guidance. PKCS#11 configuration, login and
private-key signing use owned helper processes. The host retains public
certificate chains and opaque signing references, not native key handles. Unload
revokes admission, attempts every resource close despite individual failures and
observes bounded worker/helper termination away from the EDT. A helper failure or
uncertain PIN outcome does not authorize an automatic PIN retry.

## Session handling by URL and incoming proxy port

Each automatic rule combines a typed URL condition (all requests, Burp scope,
literal prefix or RE2 regex) with an optional incoming Burp listener port. Both
must match. Regex searches anywhere in the unmodified URL and is case-sensitive
by default. Users select existing Burp listeners; this extension does not create
listeners or infer browser profiles. Every client using a selected port shares
its assignment. Listener-restricted rules apply only to live Proxy traffic;
Repeater, Intruder and other tools never inherit that assignment from copied
requests. Explicit tags retain their independent resolution policy.

Rule ordering, tool selection, cache reuse, waiting policy and version-specific
recovery remain shared. Final Proxy processing sees the user's interception
edits; global handling delivers explicit HTTP identities. Failed tagged Proxy requests
use the normal native Proxy DROP action on a best-effort basis. Successful Proxy requests receive no processing marker. Failed explicit Proxy processing adds no internal stop header, diagnostic ticket
or global retry. Captured data cannot create HTTP identity or ownership commands.

Project controls use rulesVersion 1 with explicit typed url and nullable proxyPort
members. Unsupported or unversioned saved rule arrays block the Project collection
and offer an explicit, confirmed reset of BPSH project storage in the same Burp
project. User journeys and all other Burp project data remain intact; there is no
silent migration or deletion of stored journeys. Invalid drafts and
failed saves retain the last atomically applied controls and matching plan.
Rule validation appears beside the relevant URL, status or response-pattern input.
An error on another row appears at the rules group without changing selection or
focus. Correcting the draft clears its feedback; delayed failures from older edits
cannot mark a newer value invalid.

### Accepted Proxy DROP limitation

On the tested Burp version, a native final-Proxy DROP action may be ignored. A
failed tagged request can therefore reach the target with unresolved tags or
existing credential bytes. Guaranteed blocking is not a requirement; this
limitation is accepted during ordinary operation and unload/reload. Failure notes
say that Burp was asked to drop the request rather than claiming it was not sent.
The [routing design](designs/session-handling-by-url-and-proxy-port.md) records the
tested host/version and the current qualification scope. Global-owned requests
retain their existing native drop behavior. Successful requests continue once;
a drop failure does not initiate another authentication attempt or resend.

Response token capture requires an exact origin and a JSON selector or text boundaries. Its URL path filter is optional: blank matches any response path on that origin, while a supplied filter narrows matching. Cookie capture accepts an origin-only Capture URL when the cookie is applicable there; exact cookie domain and path filters are optional. Transport-only journeys do not require capture-wait or credential-cache settings. A client-certificate-only request retains any existing application Authorization header; selecting Basic/NTLM continues to replace that header with the selected identity.
