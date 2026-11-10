# HTTP authentication transport

HttpTransportRuntime owns shared bounded delivery workers and direct/browser
scopes, capped at 32 combined. Each scope owns a separate four-connection pool.
Browser scopes may forward ordinary origins without selected HTTP credentials;
direct scopes reject destinations outside their exact allowlist.

HttpClientAuthenticationTransport adapts HttpClient. NtlmAuthScheme and NtlmMessages
own the selected NTLM profile. BoundedResponseEntity limits final and intermediate
challenge bodies before the library can drain them. No ambiguous-delivery retry
is enabled. Closing a browser scope leaves other identities usable.

HTTPS CONNECT is proxy setup, separate from destination authentication. It does
not publish identity evidence, consume the destination challenge budget or bind
NTLM state to the plain socket before TLS. Refused tunnel bodies are drained
through the response limit before HttpClient can buffer them.

The runtime owns four setup workers, sixteen delivery workers, at most 64 delivery
leases (16 per scope), 16 connections and a 64 MiB body allocator. Admission occurs
before body retention. Worker completion, cancellation and shutdown release the
same owners; completion of a future alone does not release a running worker's bytes.
Idle direct scopes and sockets expire after 30 seconds. Browser and recording
attempts pin their logical scope until closed; idle sockets remain reclaimable.

Native tests mirror this package and reuse the authentication lab's independent
multi-user verifier. HTTP acceptance uses the separate http-auth profile without
requiring PKCS#11. Actual Burp and operating-system qualification remain separate
gates in docs/designs/http-authentication.md.
