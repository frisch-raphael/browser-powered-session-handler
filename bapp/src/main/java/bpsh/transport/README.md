# Shared transport

httpauth owns HTTP delivery and isolated authentication pools. tls owns destination
trust, certificates and security devices. TLS ownership is independent of Basic or
NTLM. The extension composition root owns shutdown of these services.
