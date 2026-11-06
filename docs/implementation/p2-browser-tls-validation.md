# P2 browser and TLS validation

Validated on Windows x64 with JDK 21, the pinned Chromium/Playwright platform
bundle, LittleProxy 2.9.1 and an explicitly owned disposable SoftHSM2 store.
These components are not yet registered in the production Extension/UI; the
approved P4 cutover remains pending.

| Check | Result |
| --- | --- |
| `gradlew.bat classes test --offline --console=plain` | 126 unit tests, zero failures/errors/skips; no browser or native initialization |
| `gradlew.bat browserIntegrationTest --offline --console=plain` | 8 tests, zero failures/skips, actual bundled Chromium |
| `gradlew.bat pkcs11IntegrationTest -Ppkcs11Fixture=<owned fixture.json> --offline --console=plain` | 7 tests, zero failures/skips, actual SoftHSM2 |
| Python mTLS issuer/resource checks | Existing 8 tests retained and passing |
| Private Java documentation checks | Javadoc doclint passed for P1/P2; all 182 explicit P2 methods/constructors documented, including 63 private declarations |

The browser suite exercises the retained seven step kinds, secure input, early
JSON extraction, applicable cookies, fresh context state, useful error priority,
deadline/cancellation behavior and isolated initialization from the actual
platform JAR. Its classloader check confirms the pinned adapter leaves the
public SDK's cached Driver singleton and JVM-wide driver properties unchanged.

The exact User-Agent suffix is validated on redirects, popups, frames,
cross-origin fetch, dedicated/service-worker requests and the WebSocket HTTP
upgrade. Removing it preserves the complete original agent. Worker-script
requests that omit User-Agent from Playwright's header map now use the captured
real browser default as the route fallback. The test proxy emulates global
stripping on HTTP requests. Its CONNECT tunnel is opaque, so the WebSocket
upgrade is inspected at the owned origin boundary. This is not real-Burp hook
ordering or interception evidence; no WebSocket data-message handling is added.

The native suite selects two distinct certificate fingerprints with the same
display common name. Concurrent production-runner journeys make repeated
requests to the same HTTPS origin, including reused connections and upstream
TLS session resumption. The origin compares the requested account against the
actual peer fingerprint; each returned bearer is subsequently checked against
an independent protected-resource origin. The suite also exercises PIN rejection
and explicit recovery, CA/hostname/origin restrictions, owned SPKI scoping,
local proxy credential rejection, explicit upstream Basic CONNECT success and
failed/unavailable upstreams with zero origin hits and no direct fallback.
JVM default SSLContext and provider order are checked after owned cleanup.

The disposable fixture generator creates on-token private keys and does not
export them. The tests additionally require selected provider key handles to
return `null` from `getEncoded()`. This establishes software-token behavior only;
physical/vendor middleware cancellation, UI and device behavior remain unverified.

Tests exposed two production issues that are now fixed: Windows private
directories needed inheritable owner ACLs for Chromium child files, and stripping
all proxy credentials also stripped the configured chain's outer CONNECT Basic
header. Local credentials are removed; upstream credentials are now attached only
to the outer proxy request and never delivered inside decrypted HTTPS requests.

The Windows platform JAR is a development artifact. Runtime extraction is local,
with no installer/network fallback. Non-Windows artifacts, real Burp, coordinator,
native tags, production UI cutover and stress/release acceptance remain in later
phases. The mock-auth fresh-JWT/example migration remains in the approved P5
fixture/documentation work; the old dual-cookie tag script remains until its
native replacement passes.

Automatic approval review rejected a manual cleanup command for nine old
failed-test temporary directories with only `blocked by policy`. The command
did not execute and those directories were left in place; no alternate deletion
mechanism was used. New attempts use the corrected owned-directory permissions.
