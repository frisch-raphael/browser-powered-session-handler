# Windows preparation for federation tests

The federation tests use dedicated HTTPS certificates for four loopback names. Prepare current material for this checkout and independently verify its CA fingerprint before installing it. Normal tests do not install trust or modify the Windows hosts file.

The dedicated test CA lasts 3650 days and is reused across runs. Each run generates short-lived server certificates under that authority. Keep the installed CA for repeated local testing; remove it when retiring the environment. Renewing an existing CA certificate still requires installing the renewed certificate, even when its private key stays the same.

Open **PowerShell as Administrator using the same Windows account**, then run:

```powershell
# Run from the current repository root.
# Set $reviewedCaFingerprint to the independently reviewed current CA SHA-256.
$manifest = Get-Content 'test/authentication-lab/build/prepared/federation/public-material.json' -Raw | ConvertFrom-Json
& './test/authentication-lab/Setup-WindowsFederation.ps1' -Action Install -Certificate $manifest.caCertificate -ExpectedSha256 $reviewedCaFingerprint
```

The script verifies the certificate fingerprint, ownership and validity. It adds one marked hosts block mapping `app.authlab.test`, `api.authlab.test`, `idp.federation.test` and `idp.upstream-sso.test` to `127.0.0.1`, preserving other hosts bytes. It imports this exact CA into **CurrentUser/Root**, then flushes DNS. Adding `-Preview` inspects the change without applying it and does not require elevation.

To undo this preparation, use the same commands with **`-Action Remove`**. Removal checks the same fingerprint, removes only its marked hosts block and exact installed certificate, and retains prepared key files. Keep the public certificate until removal is complete. Rerun the script if a partial installation needs completion or removal.

This installation is a prerequisite, not a passing federation login test. A managed-browser HTTPS trust probe must pass before provider/browser tests are reported runnable. No browser certificate-error bypass is used.

## Explicit WSL recovery

If WSL/Docker is unresponsive, save work in all WSL sessions before explicitly invoking the recovery helper.

From an Administrator PowerShell window under the same user, run:

```powershell
# Run from the current repository root.
& './test/authentication-lab/Recover-WslDocker.ps1' -OperationId ([Guid]::NewGuid())
```

This explicit helper restarts the WSL service and retries bounded WSL shutdown. If modern WslService cannot stop normally, it verifies that service's exact PID, creation time and dedicated `wslservice.exe` executable before stopping that process; it never terminates a shared Windows service host. It preserves distributions and Docker data. The printed result and operation-specific JSON distinguish a completed shutdown from the stage that failed. Docker Desktop is reopened separately under the ordinary user after successful recovery. Normal tests never invoke this recovery.
