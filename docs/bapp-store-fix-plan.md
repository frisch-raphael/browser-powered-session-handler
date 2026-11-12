# BApp Store fixes and remaining qualification

Implementation status on 2026-11-10. See the [audit](bapp-store-verification.md)
for evidence and the [requirements](bapp-store-requirements.md) for the supplied
checklist. This replaces the proposed remediation sequence with the changes
actually made and the qualification still required.

## Implemented changes

| Finding | Implementation | Verification and remaining boundary |
| --- | --- | --- |
| F6: HTML rendering | Dropdown options and event rows disable HTML before assigning any text. Stored/replayed option values remain literal. | Regression renders the production options editor twice, recreates it and observes zero image fetches to an owned loopback server. |
| F1: browser sandbox | Shared login/recording launcher explicitly enables Chromium sandboxing. No automatic fallback; launch failures explain prerequisites. | Packaged Windows browser/native tests exercise real launches. Linux VM and Intel macOS execution remain separate qualification. |
| F5: copying | Automatic injection resolves only headers; Burp byte arrays assemble the unchanged body. Request admission reserves copy capacity before materialization. Replay admission precedes template copying. Shared span rendering allocates its output once. | An 8 MiB production-hook regression preserves the complete upload and unrelated header formatting. Disabled or oversized replay retention never calls its copying supplier. Real Burp allocation/heap measurements remain pending. |
| F2: callback capacity | Numeric finite defaults of 64 globally / 16 per journey replace Unlimited. A callback keeps one global lease across credentials, identity setup and direct response delivery. Immediate capacity refusal follows ordinary/explicit policy. | Tests cover refusal, release, multi-identity accounting and Send immediately while login is pending. Burp concurrency/EDT qualification remains pending; the synchronous API constraint remains. |
| F3: unload | Shared exception-safe cleanup attempts all owners; worker/timer completion is observed off the EDT. PKCS#11 provider configuration, login, certificate/key access and signing run in terminable helpers. | A stalled-helper regression checks host PIN wiping, process exit and caller release. Packaged SoftHSM cases exercise real signing, wrong-PIN suppression, retry replacement and mTLS. Physical vendor devices and other OSes need qualification. |
| F4: routing | Setup tooltip and user guide identify every authentication path using the journey proxy and explain direct/Burp-global behavior. | NTLMv1/v2 tests cover direct/browser/recording scopes through an explicit proxy and an unavailable proxy with no direct fallback. Existing HTTPS CONNECT tests cover connection reuse. Exact Burp-listener/upstream and recursion qualification remain pending. |

Final local checks passed, including 53 packaged Windows browser tests, ten
software-token tests and 47 isolated HTTP-authentication acceptance checks.
The audit records the exact delivered JAR and full evidence breakdown. No BApp Store reviewer exception or
acceptance is implied.

## Request behavior and resource limits

Automatic Send immediately continues the original request while credentials are
pending; shared background login remains available to later requests. Wait for
login preserves the original transaction within its deadline. Explicit tags and
direct HTTP authentication fail closed when credentials or capacity are unavailable.
There is no asynchronous suspend/resume API in the selected Montoya integration.

The callback cap includes preparation as well as waits. A separate 512 MiB shared
copy budget reserves four times message length plus 16 MiB for bounded header
expansion before materializing data. Limits apply together, so memory admission
can refuse work before the numeric callback cap is reached. Automatic messages
above 124 MiB continue unchanged with a capacity diagnostic. Explicit tagged and
direct HTTP-auth messages retain their 4 MiB ceiling. Automatic header expansion
also has a 4 MiB ceiling. This makes the large-request limitation explicit rather
than relying on available heap.

Recovery copies are constructed only for enabled detection, within 4 MiB per
original and 32 MiB retained in aggregate. Losing replay retention still permits
shared reauthentication; the original then needs a manual resend. Host byte-array
assembly avoids repeated extension-owned body arrays, but does not establish
zero-copy behavior inside Burp.

## PKCS#11 isolation boundary

The feasibility slice established an alternative to moving the complete HTTP
transport into a child: expose a nonexportable JCA signing reference to the host,
while the child owns all native key access. The existing TLS origin policy,
fingerprint-pinned key manager, NTLM connection ownership and HTTP transport stay
with their existing owners. No package dependency cycle or duplicated HTTP stack
is introduced.

The helper authenticates over an owned loopback socket using a random capability
passed through stdin. PINs travel in bounded binary fields, are wiped from the
host before awaiting the result, and are never placed in arguments, environment,
files or logs. The child clears its PIN after login; termination ends a stuck
native operation. No Java object deserialization or private-key export is used.

A failed helper is not restarted to resubmit a PIN automatically. Existing
rejected/indeterminate PIN suppression remains shared by device. Explicit Retry
terminates its previous helper before starting another. Cached TLS scopes become unusable when their helper exits or is replaced. A lost
device session exposes explicit Retry without automatically resubmitting a PIN.
Signing failures retain
device guidance instead of blaming the destination certificate. Graceful protocol close has a separate two-second deadline; successful forced
process termination can complete cleanup when a close reply is lost. Windows
temporary-file deletion retries transient filesystem errors for at most one
second while retaining containment checks. Driver cancellation retains descendant handles through forced shutdown and
reports browser-close completion once process exit is confirmed. Cleanup observes
owned child/descendant exit with a bounded wait, including interrupted workers.

A host call such as Burp's own replay send may still ignore interruption until
its response deadline. Cleanup reports incomplete worker termination rather than
calling a detached thread complete. Exact host behavior needs Burp verification.

## Remaining release qualification

1. Transfer the final universal development JAR to the existing Windows and Ubuntu
   verification VMs, verify its SHA-256 and refresh their existing extension
   entries by toggling Loaded. Qualify that artifact, not an earlier build.
2. Exercise cold-cache offline launches, denied sandbox permissions, headed
   recording and headless login. On Linux verify Chromium user-namespace/policy
   prerequisites. Intel macOS needs native execution evidence.
3. Load Burp with stalled login and HTTP responses, both automatic policies,
   explicit credentials, concurrent uploads and requests above each capacity
   limit. Measure callback latency, memory, unrelated traffic and EDT responsiveness.
4. Repeat unload during login, recording, signing, identity setup and replay.
   Compare owned processes, workers, sockets and providers against the baseline.
   Verify failed cleanup still attempts later owners and reports incomplete work.
5. Verify authentication through a Burp listener and Burp's configured upstream
   proxy, including TLS failures, redirects, origin restrictions, A/B/A identities
   and recursion protection. Keep incoming browser routing ports distinct from
   outgoing authentication proxy configuration.
6. Qualify physical PKCS#11 middleware and supported signing mechanisms. Preserve
   explicit evidence boundaries for software-token versus vendor-device support.
7. Before submission, review locked dependencies for current advisories and
   license/source obligations, state OS/vendor prerequisites and distribution
   size accurately, and explain specialized routing and synchronous callback
   constraints. Store acceptance remains a reviewer decision.

Windows cache publication retries transient access denials for at most one
second within the existing deadline, using the same verified staging tree and
atomic move. Permanent denial and cancellation remain failures. This addresses
publication contention found during the cold-cache browser check.

Tests and acceptance captures reuse the maintained authentication lab. Binding
refreshes are reviewed before acceptance runs. Generated evidence and browser
payloads remain under ignored build directories; the deliverable is built
directly to `bapp/build/libs/browser-powered-session-handler-dev.jar`.
