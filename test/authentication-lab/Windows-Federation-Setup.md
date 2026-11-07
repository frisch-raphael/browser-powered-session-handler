# Windows preparation for federation tests

This guide records the original worktree preparation. Its private keys, CA and preparation manifests were not copied into main; the recorded fingerprint below is historical. Prepare dedicated material for the current checkout and verify its actual fingerprint before using the install command.

The approved federation tests use four HTTPS names on this machine. Their dedicated certificate authority (CA) signs lab certificates. Normal test execution does not install trust or modify the Windows hosts file.

The prepared CA expires on **2026-11-12 at 21:49 UTC**. Its SHA-256 fingerprint is:

```text
6a46eed42e9f1274bff504bd1cb1e6fbd5c1be9922c09aac07d3dd4d8b40235f
```

The public material manifest is `build/prepared/federation/public-material.json`. Private CA/leaf keys remain in that owned build directory; do not publish it. On this workspace, the author completed installation on 2026-11-05: all four names resolve to loopback, the exact CA is in CurrentUser/Root, and bundled Chromium accepted all four HTTPS origins with normal certificate checking. It rejected a wrong-host certificate, and all ten observed probe processes closed. The safe probe record is `../federation-client/build/p3/preparation/browser-trust-probe.json`. Other machines still need the explicit setup below.

Open **PowerShell as Administrator using the same Windows account**, then run:

```powershell
# Run from the current repository root.
# Set $reviewedCaFingerprint to the independently reviewed current CA SHA-256.
$manifest = Get-Content 'test/authentication-lab/build/prepared/federation/public-material.json' -Raw | ConvertFrom-Json
& './test/authentication-lab/Setup-WindowsFederation.ps1' -Action Install -Certificate $manifest.caCertificate -ExpectedSha256 $reviewedCaFingerprint
```

The script verifies the certificate fingerprint, ownership and validity. It adds one marked hosts block mapping `app.authlab.test`, `api.authlab.test`, `idp.federation.test` and `idp.upstream-sso.test` to `127.0.0.1`, preserving other hosts bytes. It imports this exact CA into **CurrentUser/Root**, then flushes DNS. Adding `-Preview` inspects the change without applying it and does not require elevation.

Windows PowerShell 5.1 compatibility: atomic replacement passes an explicitly typed null backup filename. A plain `$null` is converted to an empty path by that version and causes the reported invalid-path exception. The corrected actual replacement call was verified against temporary files for both installation and restoration, including byte preservation and absence of backup/staging leftovers. If the previous version failed at `Replace`, rerun the corrected Install command; certificate import occurs after that step.

To undo this preparation, use the same commands with **`-Action Remove`**. Removal checks the same fingerprint, removes only its marked hosts block and exact installed certificate, and retains prepared key files. Keep the public certificate until removal is complete. Rerun the script if a partial installation needs completion or removal.

This installation is a prerequisite, not a passing federation login test. A managed-browser HTTPS trust probe must pass before provider/browser tests are reported runnable. The automation shell is not elevated; installation was performed by the author. No browser certificate-error bypass is used.

## Recovering the observed WSL hang

The author approved stopping all WSL sessions after saving their work. Standard `wsl --shutdown` still timed out after 45 seconds, and Windows reported the automatic administrator-helper launch as cancelled. The helper did not start.

From an Administrator PowerShell window under the same user, run:

```powershell
# Run from the current repository root.
& './test/authentication-lab/Recover-WslDocker.ps1' -OperationId ([Guid]::NewGuid())
```

This explicit helper restarts the WSL service and retries bounded WSL shutdown. If modern WslService cannot stop normally, it verifies that service's exact PID, creation time and dedicated `wslservice.exe` executable before stopping that process; it never terminates a shared Windows service host. It preserves distributions and Docker data. The printed result and operation-specific JSON distinguish a completed shutdown from the stage that failed. Docker Desktop is reopened separately under the ordinary user after successful recovery. Normal tests never invoke this recovery.
