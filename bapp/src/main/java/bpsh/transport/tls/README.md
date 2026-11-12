# Destination TLS and client certificates

JourneyTlsContexts builds independent validating contexts from normal JVM roots
and an optional CA bundle. It restricts the selected client identity to exact
configured origins. Explicit browser trust consent applies only without mTLS;
direct requests and mTLS keep certificate and hostname validation.

Pkcs11IdentityManager and its discovery helpers own device discovery, selection,
PIN state and provider cleanup. Pkcs11ProcessAccess exposes public certificate
chains and nonexportable signing references to the host; Pkcs11KeyMain owns
provider configuration, login and signatures in a terminable child JVM. Bounded
authenticated socket IPC carries temporary PINs without command-line, file or log
exposure. Helper failure never automatically resubmits a PIN. HttpTransportRuntime composes this owner during
asynchronous scope setup. NTLM message construction has no PKCS#11 dependency.
Browser and direct transport use the same TLS policy; no global SSL default or
trust-store change is made.

Structured TLS/proxy failures produce safe diagnostics. Peer exception text is
kept out of user messages. Native tests mirror the TLS owner and use explicitly
disposable software-token material for the packaged mTLS integration suite.
