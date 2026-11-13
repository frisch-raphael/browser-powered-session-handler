# HTTP identity lifecycle

This JDK-only package defines the HTTP transport port, owned message bodies and
authentication observations. HttpIdentityManager selects a saved journey and its
invalidation epoch before dependent captures are resolved. It reuses compatible
direct scopes and gives each explicit test a fresh scope.

Callers acquire a single-use Delivery before copying a body into the shared
allocator. Closing a lease cancels its delivery; running work retains its admission
and byte ownership until the worker exits. Request and response body handles must
be closed by their owners. A completed response remains a server result even when
its authentication observation is unconfirmed or rejected.

HttpTransportFactory snapshots secrets before asynchronous setup returns. Its
concrete implementation lives in transport.httpauth. Browser and Burp adapters
depend on this port. No Swing, Montoya, Playwright or TLS-provider types enter here.

Native tests mirror this package. The maintained transport contract and acceptance
gates are in docs/designs/http-authentication.md.

HttpAuthenticationProgress carries fixed handshake stages and typed failure
guidance. HttpAuthenticationActivity retains bounded, session-only observations
for the current saved generation and secret revision, rejects cleared/stale
publishers, and supplies a safe event sink plus read-only inspection snapshots.
Routine connection reuse remains available in inspection snapshots but does not enter the event sink on every request or redirect. Fresh handshakes and failures remain events. Neither owner acquires credentials, opens connections or retains raw messages.

ChallengePolicy is independent of AuthorizationPolicy. ESTABLISHED_ONLY permits one application transmission without a challenge resend; recent acceptance does not prove the next pooled socket is authenticated. HttpIdentityManager warms the DIRECT pool with a body-free/header-free HEAD for the exact destination, single-flight per selection/epoch/origin, bounded to eight active operations and 128 two-second cooldown records. Clear/edit/unload cancel stale work. Explicit tests retain fresh TEST scopes.
