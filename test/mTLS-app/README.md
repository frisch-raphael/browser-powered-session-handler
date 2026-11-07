# Local mTLS and token fixture

The fixture runs two loopback-only listeners:

| URL | Behavior |
| --- | --- |
| `https://localhost:7576/token` | Requires a CA-trusted client certificate with client-auth usage. Issues a signed JWT tied to the SHA-256 fingerprint of the certificate actually received. |
| `https://localhost:7576/` | Compatible alias of `/token` for existing login configurations. |
| `http://127.0.0.1:7578/protected` | Requires `Authorization: Bearer <issued-token>`. No client certificate is needed on this listener. Returns the certificate-derived subject and token ID, or HTTP 401 for missing, invalid or expired tokens. |

## Run

From the repository root:

```powershell
python test/mTLS-app/mtls-app.py --token-ttl-seconds 30
```

Python's standard library is sufficient to run the fixture. The default CA, server certificate and server key are resolved beside the script, independent of the working directory. Use `--ca`, `--cert` and `--key` to supply other PEM files; `--port` and `--protected-port` change the listeners. Token lifetime must be positive.

The client certificate must be signed by the configured CA, valid at the current time, and suitable for client authentication. The server certificate must also be valid and trusted by the test client. The script does not renew the checked-in certificates or alter SoftHSM2 tokens.

Suggested journey configuration: navigate to `https://localhost:7576/token`, capture the response URL containing `/token`, and extract JSON path `access_token`. With SoftHSM2 configured in the chosen browser/TLS integration, select the desired certificate and provide its PIN through that integration.

The response includes `identity.sha256`, `identity.common_name`, `identity.serial_number`, `expires_in` and `expires_at`. Certificate fingerprint is the identity: two certificates with the same CN remain distinct. To verify selection, compare the expected certificate fingerprint with `identity.sha256`, then use the token at `/protected` and compare `subject` with the same fingerprint. A new login issues a different token ID. Expiry is enforced at `now >= exp`; restarting the fixture also invalidates old tokens because it generates a new signing key.

This is a local test issuer, not a production authentication service. The protected HTTP listener is deliberately separate from mTLS so a successful protected request proves token consumption without certificate authentication on that connection. Both listeners bind to `127.0.0.1`. Tokens, authorization headers and request URLs are not logged. There is no static-file serving.

## Automated fixture checks

Requires Python and the OpenSSL CLI on PATH:

```powershell
python -m unittest discover -s test/mTLS-app -p test_mtls_app.py -v
```

The eight tests generate a temporary CA and server/client PEM certificates outside the repository, run both listeners on ephemeral ports, and clean them up. They cover server-observed identity, two distinct certificates sharing a CN, token-only protected access, expiry and fresh login, missing/malformed/tampered tokens, another signing key, missing/wrong-purpose client certificates, the root alias and absence of static-file serving. The expiry test controls the token clock rather than sleeping for expiry. Certificate checks use the real TLS clock.

These tests validate the fixture only. They do not use PKCS#12, SoftHSM2, a browser, Burp request hooks or physical devices. If OpenSSL is missing the test class is skipped; a skipped run is not evidence of a passing mTLS path.

## Existing SoftHSM2 setup notes

The following manual setup notes remain for the software-token fixture. Installing/enrolling the module and proving unattended browser/PIN/certificate selection are separate integration checks.

# List Available Slots
& "C:\SoftHSM2\bin\softhsm2-util.exe" --show-slots  
# Create a New Token
```
& "C:\SoftHSM2\bin\softhsm2-util.exe" `  
  --init-token --slot 0 `  
  --label "TestToken" `  
  --so-pin 0000 `  
  --pin 1234
```
# Generate a protected key inside the token  
```
& "C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe" `  
  --module "C:\SoftHSM2\lib\softhsm2-x64.dll" `  
  --login --pin 1234 `  
  --keypairgen --key-type rsa:2048 `  
  --id 01 --label "auth-key"  
```
# List Objects in a Token 
```
& "C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe" `
  --module "C:\SoftHSM2\lib\softhsm2-x64.dll" `
  --login --pin 1234 -O
  ```
# Create certificate based on private key
```
openssl req -new -x509 -days 365 -sha256 `
  -key "pkcs11:token=TestToken;object=auth-key;type=private" `
  -subj "/CN=rfrisch" `
  -out rfrisch-cert.pem
  ```
# import the cert in the token
    ```
  & "C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe" `
  --module "C:\SoftHSM2\lib\softhsm2-x64.dll" `
  --login --pin 1234 `
  --write-object .\rfrisch-cert.pem `
  --type cert `
  --id 01 `
  --label "rfrisch cert"
    ```
# Vérifier si lien avec dll pkcs11
openssl storeutl -text "pkcs11:token=TestToken"
