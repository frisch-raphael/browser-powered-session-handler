# Browser proxy

JourneyBrowserProxy owns local HTTP/CONNECT ingress, attempt authentication and
channel cancellation. BrowserProxyForwarder owns attempt evidence and closes the
scope borrowed from HttpTransportRuntime. It creates no HTTP executor or client.
BrowserSessionLauncher binds the scope before navigation for both run and record.

Ingress validates headers and acquires nonblocking transport admission before
retaining body chunks. It limits local channels, pipelining and message sizes;
disconnects cancel only their owned work. Response chunks remain borrowed until
Netty completes the write. A failed local TLS handshake does not retire the whole
attempt.

Native integration tests mirror this package. Shared HTTP fixtures remain in the
authentication lab. See docs/designs/http-authentication.md for the full contracts
and acceptance requirements.
