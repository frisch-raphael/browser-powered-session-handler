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
configuration errors appear when executing the journey. Browser recording supports
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
excluded. The former phase line, permanent feedback box and separate test-result
box are removed. Automatic injection is named Session handling in the UI.
Explicit Test login and Retry finish with a native popup summarizing captured
credential names and counts or the safe error and failed step. Values remain in
Journey cache. Automatic authentication does not open completion popups.

## Evidence and acceptance

The implementation has unit, bundled-browser and owned SoftHSM integration tests.
Qualify responsive login, cancellation, cache actions, storage, transfer/secrets, certificate selection, tagged/automatic protected access, compact/wide forms and Burp themes against the delivered artifact. Stress, assistive-technology and physical-device checks require their own observations. The lab guide specifies current commands and evidence boundaries.

Automatic authentication uses multiple ordered journeys. Session
handling owns activation, URL scope and expiration detection per rule. Matching
journeys are acquired sequentially with cache reuse, and later rules overwrite
earlier destinations. Commit all injections together only after every required
session succeeds. Explicit tags retain their independent request-wide policy.

Automatic requests use the project Automatic handling policy in Settings. **Wait for login** (the default) waits within the configured request deadline. **Send immediately** adds valid cached credentials immediately. When credentials are missing or expired, it sends the original automatic request unchanged and starts or joins background login without retaining an HTTP waiter. The original request may be unauthenticated; successful login supplies credentials to later requests. Explicit BPSH tags always wait for resolution, so unresolved tag text is never sent to the server. The extension does not replay the unchanged request when background login finishes.

Token response capture streams matching Chromium response bodies with a 1 MiB decoded limit before extraction. Oversized network responses are aborted; service-worker response capture stops at the same decoded limit. Responses within the limit retain their status and headers (with transport encoding headers adjusted for the decoded body).
