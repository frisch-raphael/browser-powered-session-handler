# P3 coordination, native tags and recovery

P3 implements the request-independent native services from design items 8-10.
The production Extension, UI and HTTP hooks still use the existing API runtime
until the approved atomic P4 cutover. No Python/API/Hackvertor runtime dependency
has been removed prematurely.

## Components and ownership

`AuthenticationCoordinator` owns two daemon browser workers, a finite 32-cycle
waiting/backoff queue, one shared epoch per journey generation, and independent
request futures. Optional global and per-journey HTTP waiter limits default to
Unlimited; finite limits reserve all unresolved journeys atomically. Test/Retry
uses the same finite cycle admission without consuming HTTP waiter counts.
Caller budgets are request-wide, cycle budgets begin on admission, and attempt
budgets begin on worker admission. Temporary retries use 5/15/30 seconds, release
their worker between attempts, and cannot extend the original cycle deadline.
Retry-After can increase a 429/503 delay only within that budget.

Each generation publishes an immutable `TokenSnapshot` through an atomic
reference. `TokenLifetime` independently bounds monotonic age and JWT wall-clock
expiry; opaque/malformed/non-expiring tokens always receive finite maximum age.
Skew is capped at half the acquired usable lifetime. The browser result now
carries its original monotonic acquisition time as well as wall time, preventing
cleanup from extending cache age. The first success activates one refresh timer;
loading a library does not log into all its journeys. Capacity denial coalesces
proactive deferral, while exhausted cycles do not restart from past-due timers.

Caller timeout/cancellation releases only that caller. Operator Cancel revokes
the selected shared epoch, completes all its owners, retains a still-usable token
and applies the 60-second cooldown. Save and test/explicit Retry can bypass that
cooldown; only explicit Retry supplies native PIN recovery. PIN suppression is
checked again before retries and before successful publication, so a device
state change during backoff cannot permit another automatic submission or use
of an invalid result. Registry/secret changes and unload reject late results.
Manual Invalidate clears the token and supersedes the cycle; response recovery
invalidates only the exact used token version and preserves healthy shared work.

`NativeTagParser` parses the native lowercase namespace without a regex grammar.
Self-closing aliases resolve case-insensitively; paired url/form/json wrappers
evaluate whole content from inside out. The limits are request-wide: 256 tag
nodes, 16 distinct references, depth eight, 1 MiB marked text and 4 MiB expanded
message. Output is never reparsed as source. All syntax and alias checks precede
authentication admission.

`NativeTagResolver` inspects raw message bytes before any URL helpers, preserves
bytes outside planned edits, and treats any explicit wrapper/reference as
tags-only regardless of ordinary Enabled/tool/scope eligibility. It supports
header values, path/query targets, and declared UTF-8/ASCII/ISO-8859-1 text bodies.
Unsupported body formats/codings, folded/invalid headers, method/authority/Host
or framing-header markers, and percent-encoded target notation stop with
conversion/raw-editor guidance. It does not decode binary bodies or guess a
charset. Body replacements update actual Content-Length. Raw, form, URL-component
and JSON-string-content encoding remain explicit. Automatic bearer/cookie
injection shares acquisition and remains request-local; named cookies are
replaced once while other cookies are preserved.

The final `Resolved.commit()` copies only complete output, then validates every
used generation/version/usability together under a short metadata lock and
consistent registry view. A failed journey has exact generation attribution,
so a mixed-reference failure identifies the actual failing alias. No partially
modified request is returned. `uses()` supplies only token-free provenance and
must be recorded after successful commit.

`SessionRecovery` retains only used identity/version/rule metadata keyed by
global request ID, capped at 10,000 records/five minutes. Internal, unknown,
expired and duplicate responses cannot invalidate unrelated current tokens.
Status rules never open response bodies. RE2/DOTALL/find body rules check actual
encoded bytes and declared MIME before reading, then apply an independent 64 KiB
decoded cap for gzip/zlib-deflate. Unsupported textual codings/charsets provide
fixed conversion/status-rule guidance through a safe host callback. Source and
compiled-pattern limits apply on configuration save too. An unavailable RE2
error position is reported honestly without echoing the configured source.

`Diagnostics` preserves per-request stopped annotations while rate-limiting
identical safe warnings for five seconds with suppression counts. It separates
tagged-stop, ordinary-unchanged and background-state wording. Inputs are typed
safe native failures rather than raw browser exceptions, bodies, tokens or URLs.

## Validation

| Check | Result |
| --- | --- |
| `gradlew.bat classes test --offline --console=plain` | 203 unit tests, zero failures/errors/skips |
| P3 deterministic suites | 77 tests across coordinator, lifetime, tag pipeline, recovery and diagnostics |
| `browserIntegrationTest` | 9 tests, zero failures/skips; includes a real browser through the production coordinator constructor |
| `pkcs11IntegrationTest` with explicit owned fixture | 7 tests, zero failures/skips; existing same-host SoftHSM isolation gates remain green |
| Private Javadoc/doclint | Passed for P1-P3; 142 explicit P3 methods/constructors documented, including 62 private declarations |

Deterministic tests cover 200 simultaneous fake HTTP callers sharing one cycle,
independent deadlines, finite/Unlimited/live limits, atomic reservation rollback,
queue capacity and coalesced proactive deferral, retry counts/delays and PIN
suppression, queued/backoff/running Cancel, cooldown/explicit recovery, stale
publication, version-specific invalidation and both expiry clocks. This is a
concurrency-policy check, not a real-Burp performance/stress result.

Pipeline tests cover supported locations/encodings, byte and length preservation,
case/syntax errors, reserved self-closing wrapper names, nested whole-content
encoding, global limits, unsupported locations/body formats, large untagged
uploads, mixed failures, capacity failures, cancellation and final commit checks.
The tag pipeline uses a fake runner and does not claim URL-tag preservation or
drop behavior in actual Burp. The browser task independently exercises the actual
packaged classloader/Chromium and the production coordinator worker composition.

## P4 integration obligations

Compose one registry/coordinator/guard/resolver/recovery/diagnostics service graph.
Notify `configurationChanged()` after applied registry/secret updates and apply
validated project controls through `updateControls()`. HTTP callers must use one
`Operation`, detach on their own cancellation, commit once, then record only its
actual `uses()`. Route typed native failures to supported drop/annotation behavior;
ordinary failures forward the original request with a warning. Connect skipped
body-recovery guidance to the rate-limited background diagnostics callback.

Keep guard classification/stripping before all acquisition and native resolution;
global and narrow Proxy ownership ledgers remain independent. Wire the saved
journey UI, shared Cancel/Retry, background EDT-safe actions and ordered unload
together with removal of the legacy callers. Real-Burp hook ordering, raw URL
templates, interception/drop acceptance, physical/vendor-token behavior,
non-Windows packages, mock-auth JWT/example migration and release stress gates
remain pending in the approved later phases.
