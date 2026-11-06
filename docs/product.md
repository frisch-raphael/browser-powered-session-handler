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

The user selected a full UX redesign with a guided wizard on 2026-11-04: setup,
login steps, token capture, optional PKCS#11 certificate setup, then review/testing
and tag usage. Existing saved journeys remain editable. Changes autosave after
500 ms without editing; navigation and execution flush the latest edits first.
Plus immediately creates a new saved journey. Incomplete settings are retained;
configuration errors appear when executing the journey. Save activity belongs
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
- Browser assets are bundled in platform-specific JARs. No runtime browser
  download or separate Java executable is required by the extension.

The author subsequently chose Project/User collection tabs and compact icon
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

## Evidence and acceptance

The implementation has unit, bundled-browser and owned SoftHSM integration tests.
The 2026-11-05 control matrix combines manual Burp 2026.10.1 walkthroughs with
automated Swing/controller boundary and transition checks. It covers responsive
visible/background login, cancellation, cache actions, project/user storage,
transfer and secret flows, exact SoftHSM certificate selection, actual tagged and
automatically authenticated HTTP requests, compact/wide forms and both Burp
themes. Evidence and the distinction between manual and automated scenarios are
recorded in `docs/implementation/ux-test-matrix.md`; the UX critique is archived
under `.impeccable/critique/`. Stress testing and assistive-technology assessment
remain separate gates. Physical vendor hardware has not been tested. No
user-study or formal accessibility compliance claim is established.

The author chose multiple ordered automatic journeys on 2026-11-05. Session
handling owns activation, URL scope and expiration detection per rule. Matching
journeys are acquired sequentially with cache reuse, and later rules overwrite
earlier destinations. Commit all injections together only after every required
session succeeds. Explicit tags retain their independent request-wide policy.
