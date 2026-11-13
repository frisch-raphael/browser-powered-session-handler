# Authentication journeys and request tags

The Java extension owns saved journeys, browser execution, credential capture, caching, request mutation, session recovery and PKCS#11 TLS. The Montoya entry point is `bpsh.Extension`. [Code structure](code-structure.md) defines component ownership and dependency boundaries; [the interface contract](interface.md) defines editing and feedback.

## Journeys, storage and secrets

Project and User collections contain saved journeys with stable identities and configuration generations. Project storage uses `bpsh_project_v3`; the User library is `user.home/.bpsh/library-v3.json`. Strict native codecs own validation and serialization. Imports, exports and editor execution reuse those codecs and the draft compiler.

Journey edits autosave after 500 ms without changes, including unfinished input. Switching selection or executing Test login flushes the latest edits first. Execution validates the saved definition before browser preparation. Storage writes are serialized and revision checked. A stale completion cannot replace a newer editor/storage generation or overwrite an external revision.

Aliases identify saved journeys independently of automatic injection. Ambiguous aliases block execution; there is no implicit winner across scopes. Renaming changes the derived alias when saved, so existing request tags may need updating. Aliases may be reused after rename or deletion.

Remember secrets is off by default. Remembered values are readable in owned storage; export inclusion requires a separate explicit choice. Imports allocate fresh journey identities and follow the current remember/export policy. PINs and secure step inputs have owned buffers and distinct session lifetimes. Cached credentials, browser profiles and private keys are never exported or written into journey events or diagnostics.

## Browser execution and credential capture

Each authentication attempt owns a fresh browser context and its page/browser/driver resources. Browser, network, provider and filesystem operations run off Swing's event thread. Cancellation, deadlines, saved generations and unload are checked across asynchronous boundaries. A later result cannot publish into a superseded journey generation.

The extension runs its pinned, bundled Chromium and Playwright driver. [Universal packaging](universal-packaging.md) defines offline preparation, integrity and supported hosts. Runtime setup does not download a browser or discover a system browser. Playwright CLI entry points must never be invoked inside Burp.

On Windows, each newly started driver enters an unnamed, noninherited Windows job before protocol initialization can launch Chromium. The job retains all descendants and enables kill-on-close without breakaway. Before protocol shutdown, cleanup retains native synchronization handles for verified job members; it waits for those handles and confirms zero active members within a five-second Windows process-wait budget before releasing the handles. Other platforms retain their existing process ownership. This is needed because an observed sandboxed Chromium process still held its profile lock while Java's `ProcessHandle.isAlive()` reported false; extending file-deletion retries did not repair that ownership failure. The [OpenJDK Windows implementation](https://github.com/openjdk/jdk21u/blob/master/src/java.base/windows/native/libjava/ProcessHandleImpl_win.c) can report an inaccessible process as absent. [Windows job accounting](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects) avoids relying on those child queries, while [native termination waits](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess) observe completion of asynchronous termination. Browser sandboxing stays enabled, no unrelated process is assigned, and failure to establish containment fails setup.

The Windows native binding uses the already bundled JNA library. JNA maintains its own `jna.loaded` and `jnidispatch.path` loader bookkeeping properties. Packaged-classloader checks permit only those two Windows loader keys; the Playwright singleton and all other JVM properties, including browser and proxy configuration, must remain unchanged.

Journeys execute the configured page actions and capture JSON-response values, bounded regex response text, cookies, or a combined set. Multiple values require unique user-defined names. All required values must arrive before one atomic credential snapshot is published; the earliest applicable expiry bounds the set. Response-only capture may complete early and records the correct skipped count. When any capture source is a cookie, every configured login step and popup expectation must finish successfully before credentials are accepted: the login page can issue an anonymous cookie before authentication. A matching cookie cannot hide a failed required action. Journeys with no configured steps can still capture credentials returned by opening the Login URL.

Response capture uses the configured canonical origin/path filters. Regex capture selects text after the Start match and before the next End match, excluding the boundaries. Cookie selection respects the configured cookie identity and scope. Missing outputs, invalid selectors and browser failures retain their actual stage/cause and safe corrective guidance.

Each response token has one automatic destination: Disabled, Bearer, named Header or named Cookie. Captured cookies replace their original cookie names. Bearer and an Authorization header occupy the same destination; duplicate destinations are rejected. Disabled values remain usable through explicit tags.

## Request tags and atomic mutation

`<@journey/>` selects a journey's single value. `<@journey token="name"/>` selects a named value. Explicit encoding wrappers are `<@url>`, `<@form>` and `<@json>`. The request-editor menu inserts references and encodings without reading or acquiring credential values.

The bounded parser resolves all saved identities and validates tag syntax and destinations before authentication. Limits include 256 tag nodes, sixteen distinct journeys, eight encoding levels, 1 MiB of tagged text and 4 MiB of expanded output. Captured text is output, never recursively interpreted as another authentication request.

Resolve all required snapshots before committing request changes. A syntax, identity or tag-expansion failure stops the request. Ordinary automatic-authentication failure forwards the original request with corrective feedback. Preserve the original request bytes until a complete replacement is ready.

Session handling evaluates enabled, matching journeys in order. It acquires them sequentially with cache reuse; later destinations overwrite earlier ones. Commit all selected injections together only after every required session succeeds. Explicit tags retain their request-wide policy independently of ordinary automatic tool eligibility.

## Shared acquisition and lifetime

Concurrent callers for the same saved generation share acquisition. Worker and waiting limits apply before starting work. Cancellation releases only the caller's owned reservation; attempts, pending requests and unload retain bounded cleanup ownership. Previous worker/browser/context ownership must finish before another attempt for the same stable journey starts.

Initial acquisition, proactive refresh and each recovery cycle permit three total sequential attempts. Only positively classified temporary transport/service failures retry, after 5 and 15 seconds, respecting Retry-After and the total budget. Configuration, extraction, cancellation and PIN failures do not become generic retryable network failures.

Credential publication and request use require the current generation. An edit revokes obsolete work and request snapshots, but carries usable captured credentials into the immediately following available generation when every selected source still matches. Renames, reordering and removal remap by exact capture selector. New sources require fresh acquisition. Unfinished drafts retain the previous captured selection for inspection without allowing execution. Retention preserves the version and original lifetime, never extending expiry or resetting refresh; new cache settings apply to the next successful acquisition. Clear cache, deletion, unavailability and expiry prevent later edits from restoring credentials. No late result revives invalidated credentials. Refresh and clear/cancel actions preserve attribution and do not leak acquired values into logs.

## Session-loss recovery

A configured session-loss match while Session handling is enabled starts or joins recovery for the exact rejected publication. Only the final credential owners' captured rules are evaluated. Explicit tags use matching enabled rules for each referenced saved identity and URL. An original timeout alone does not authorize replay. Combined status/RE2 mode matches either condition and avoids body decoding when status already matches.

Exhausted recovery, terminal failure, cancellation or rejection of replacement credentials pauses the stable journey. Automatic requests, timers, tags, invalidation and saves cannot clear that pause. It survives saved-generation changes in the running extension, but is not serialized across unload/restart. Deletion removes it; successful explicit Test login clears it. Explicit Test/Retry never resends old requests, and PIN suppression remains authoritative.

Capturing credentials does not establish protected access. A nonmatching observed 2xx application response marks accepted use and rearms future loss detection. Replacement-validation requests keep episode attribution. Delayed rejection cannot silently begin another cycle; stale responses cannot invalidate newer publications or pause newer episodes.

Each affected original may receive one separately sent replay using its frozen pre-injection template, saved generations, aliases and destinations. Recheck every snapshot at claim and in the global outgoing hook. Alias reassignment or configuration replacement rejects the replay. A replay is never replayed again. Missing template capacity still allows shared recovery, but does not authorize replay.

Original responses remain unchanged. Replays use Montoya `Http.sendRequest` on a bounded executor with two workers and 256 queued jobs, retain original/replay message-ID attribution and appear separately in Burp. The original caller receives its original response. The replay marker is stripped at the outgoing hook and cannot bypass ordinary Proxy interception or response detection.

Provenance retains at most 10,000 records for five minutes. Replay templates are limited to 4 MiB each and 32 MiB total. Reservations remain charged while pending/ready and release on completion, eviction or cancellation. Resource counters distinguish metadata-only SDK lifecycle observations from actual OS-process termination.

## Self-traffic policy

Authentication traffic routed through Burp must be recognized before acquisition to prevent recursion. Attempt-owned traffic attribution and its carrier are bounded and removed according to the outgoing traffic guard. Correlated authentication responses are excluded from application-session recovery. Ordinary application interception remains active. Guard matching must not turn unknown or stale attribution into authorization to skip normal request processing.

## TLS and certificate ownership

Ordinary journeys use their configured optional HTTP proxy directly; empty means direct. Configured upstream proxy authentication is unsupported. Certificate and HTTP-authentication browser journeys create the attempt-owned Java proxy. Its internal access credentials are independent of configured upstream proxy support.

Java uses explicit key/trust configuration and vendor PKCS#11 middleware. Device discovery does not require a PIN. Certificate choice is pinned to the exact fingerprint and compatible handshake identity; identical subjects do not permit substitution. The HTTPS login server is included in the certificate allowlist, additional servers and trusted CA are explicit advanced inputs, and unrelated servers must never receive the selected certificate. No JVM-global TLS configuration or Burp certificate-host rule is mutated.

## Lifecycle, diagnostics and verification

The composition root probes required host capabilities before registering hooks. Unload cancels owned work, closes resources, detaches hooks and wipes owned secrets. Generation checks cover late storage, device, browser and authentication completions.

Journey events contain safe stage/cause, one-based failed-step attribution and corrective actions. Go to step uses the exact step UUID and saved generation. Initial navigation failures remain navigation failures. Credentials captured and Request accepted are distinct states. Only explicit Journey cache inspection and deliberate copy/request insertion expose cached values.

Use the existing native tests and [Java authentication lab](../../test/authentication-lab/README.md). Qualify the exact source and delivered JAR with current reports; component, browser, software-token and actual Burp results remain separate acceptance boundaries.

Automatic requests use the project Automatic handling policy in Settings. **Wait for login** (the default) waits within the configured request deadline. **Send immediately** adds valid cached credentials immediately. When credentials are missing or expired, it sends the original automatic request unchanged and starts or joins background login without retaining an HTTP waiter. The original request may be unauthenticated; successful login supplies credentials to later requests. Explicit BPSH tags always wait for resolution, so unresolved tag text is never sent to the server. The extension does not replay the unchanged request when background login finishes.

Token response capture streams matching Chromium response bodies with a 1 MiB decoded limit before extraction. Oversized explicitly path-filtered network responses are aborted. Origin-only and service-worker capture stop collecting each oversized response while ordinary browser delivery continues. Responses within the limit retain their status and headers (with transport encoding headers adjusted for the decoded body).

## URL/listener routing ownership

RequestControlState publishes one immutable Controls/RequestRuleMatcher pair after
validation and persistence. Ordinary matching combines typed URL conditions and
optional incoming Proxy ports, preserving configured order. Final Proxy
processing uses the user's edited request and actual listener. Non-Proxy global
processing has no listener identity; copied requests do not inherit one.
SessionRequestProcessor owns shared preparation, GlobalHttpSessionAdapter and
ProxyHttpSessionAdapter translate host actions, HttpAuthenticationDelivery owns
shared direct identity delivery. AutomaticHttpAuthentication selects eligible transport-only identities; DeferredRequestDelivery shares one-use pinned plans with RecoveryReplayDelivery. Captures resolve once; no cross-family IDs or annotations are joined.

RequestExchange qualifies every ID with its callback family. Proxy and global
response attribution never join numeric IDs. A Proxy recovery replay is a new
GLOBAL delivery pinned to the original policies and versions, with no listener
rematch. Recovery attribution and pending replay plans retain at most 10,000 records for
five minutes; replay templates retain their existing 4 MiB individual and 32 MiB
aggregate limits. Replay dispatch uses two workers and queue capacity 256.

Final-Proxy DROP was unreliable on the tested Burp host. The author accepts that
failed tagged Proxy requests may reach the server. The adapter requests native
DROP with safe failure notes; no internal stop header, diagnostic-ticket bridge
or extra global pass enforces failed tagged drops. Capture-only preparation continues normally. Trusted transport/recovery handoffs separately use bounded one-use plans for actual native delivery.
Global-owned failures retain their existing native drop action. Captured output
still cannot create HTTP-authentication directives or owned-traffic markers that
a later callback would execute. See the [routing design](session-handling-by-url-and-proxy-port.md#proxy-failure-policy-native-drop-is-best-effort).
