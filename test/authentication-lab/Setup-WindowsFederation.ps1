param(
    [Parameter(Mandatory=$true)][ValidateSet('Install','Remove')][string]$Action,
    [Parameter(Mandatory=$true)][string]$Certificate,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedSha256,
    [switch]$Preview
)

# Explicit preparation only. Normal lab execution never changes hosts or Windows trust.
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $Preview -and -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this explicit setup in an elevated PowerShell window under the same Windows user.'
}
$certificatePath = (Resolve-Path -LiteralPath $Certificate).Path
$owner = (Get-Acl -LiteralPath $certificatePath).Owner
$ownerSid = if ($owner.StartsWith('S-1-')) { $owner } else { ([Security.Principal.NTAccount]::new($owner)).Translate([Security.Principal.SecurityIdentifier]).Value }
if ($identity.User.Value -ne $ownerSid) { throw 'Use the Windows account that owns this prepared lab certificate.' }
$cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificatePath)
$sha = [Security.Cryptography.SHA256]::Create()
try { $actualSha256 = ([BitConverter]::ToString($sha.ComputeHash($cert.RawData))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
if ($actualSha256 -ne $ExpectedSha256.ToLowerInvariant()) { throw 'The prepared CA fingerprint does not match. Nothing was installed or removed.' }
$constraints = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' } | Select-Object -First 1
if ($null -eq $constraints -or -not $constraints.CertificateAuthority) { throw 'This certificate is not a CA.' }
if ($Action -eq 'Install' -and ($cert.NotAfter -le (Get-Date) -or $cert.NotBefore -gt (Get-Date))) { throw 'Prepare a currently valid dedicated lab CA first.' }

$names = @('app.authlab.test','api.authlab.test','idp.federation.test','idp.upstream-sso.test')
$hostsDirectory = [IO.Path]::GetFullPath((Join-Path $env:SystemRoot 'System32/drivers/etc'))
$hostsPath = [IO.Path]::GetFullPath((Join-Path $hostsDirectory 'hosts'))
if ([IO.Path]::GetDirectoryName($hostsPath) -ne $hostsDirectory) { throw 'Unexpected hosts target.' }
$original = [IO.File]::ReadAllBytes($hostsPath)
Import-Module (Join-Path $PSScriptRoot 'WindowsFederationHosts.psm1') -Force
$bytes = Update-AuthLabHosts -Original $original -Action $Action -CaSha256 $actualSha256
if ($Preview) {
    Write-Output ('Preview: ' + $Action + ' CA SHA-256 ' + $actualSha256 + ' in CurrentUser/Root; only its managed hosts block changes.')
    Write-Output ('Host names: ' + ($names -join ', '))
    Write-Output 'No trust or hosts change was made.'
    return
}
$temporary = [IO.Path]::GetFullPath((Join-Path $hostsDirectory ('authlab-' + [Guid]::NewGuid().ToString('N') + '.tmp')))
if ([IO.Path]::GetDirectoryName($temporary) -ne $hostsDirectory) { throw 'Unexpected temporary hosts path.' }
try {
    [IO.File]::WriteAllBytes($temporary, $bytes)
    # Refuse to overwrite somebody else's edit made after our snapshot.
    if ([Convert]::ToBase64String($original) -cne [Convert]::ToBase64String([IO.File]::ReadAllBytes($hostsPath))) { throw 'The hosts file changed during preparation. Retry after reviewing it.' }
    # Windows PowerShell 5.1 binds plain $null to an empty string for this .NET
    # parameter, which is rejected as an invalid backup path. Pass a typed null.
    [IO.File]::Replace($temporary, $hostsPath, [System.Management.Automation.Language.NullString]::Value, $true)
} finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary } }

if ($Action -eq 'Install') {
    Import-Certificate -FilePath $certificatePath -CertStoreLocation 'Cert:/CurrentUser/Root' | Out-Null
} else {
    # Exact certificate only; no store-wide deletion and no removal of prepared key material.
    $installed = Get-Item -LiteralPath ('Cert:/CurrentUser/Root/' + $cert.Thumbprint) -ErrorAction SilentlyContinue
    if ($null -ne $installed) {
        if ([Convert]::ToBase64String($installed.RawData) -cne [Convert]::ToBase64String($cert.RawData)) { throw 'The installed certificate differs. It was not removed.' }
        Remove-Item -LiteralPath $installed.PSPath
    }
}
Clear-DnsClientCache
Write-Output ('AuthLab Windows preparation ' + $Action.ToLowerInvariant() + ' completed for CA SHA-256 ' + $actualSha256 + '.')
Write-Output 'A managed-browser trust probe must still pass before HTTPS/provider cases are reported runnable.'
