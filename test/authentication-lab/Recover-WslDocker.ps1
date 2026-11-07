param(
    [Parameter(Mandatory=$true)][Guid]$OperationId
)

# Explicit recovery after authorized WSL shutdown itself timed out. No distro or Docker data is deleted.
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'WSL service recovery requires an administrator PowerShell.' }
$owner = (Get-Acl -LiteralPath $PSCommandPath).Owner
$ownerSid = if ($owner.StartsWith('S-1-')) { $owner } else { ([Security.Principal.NTAccount]::new($owner)).Translate([Security.Principal.SecurityIdentifier]).Value }
if ($identity.User.Value -ne $ownerSid) { throw 'Use the Windows account that owns this workspace.' }
$resultDirectory = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../federation-client/build/p3/preparation'))
[IO.Directory]::CreateDirectory($resultDirectory) | Out-Null
$resultPath = Join-Path $resultDirectory ('wsl-recovery-' + $OperationId.ToString() + '.json')
$result = [ordered]@{operationId=$OperationId.ToString(); startedAt=[DateTime]::UtcNow.ToString('o'); state='STARTING'; stage='CHECK_SERVICE'; service=$null; forcedServiceStop=$false}
try {
    $service = Get-Service -Name WslService -ErrorAction SilentlyContinue
    if ($null -eq $service) { $service = Get-Service -Name LxssManager -ErrorAction Stop }
    $result.service = $service.Name
    if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
        $record = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $service.Name + "'")
        $serviceProcess = Get-Process -Id $record.ProcessId
        $serviceStart = $serviceProcess.StartTime
        $serviceExecutable = $serviceProcess.Path
        $result.stage = 'STOP_SERVICE'
        $service.Stop()
        try { $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(20)) }
        catch [ServiceProcess.TimeoutException] {
            # Only the dedicated modern WSL service can be stopped this way; never a shared svchost.
            if ($service.Name -ne 'WslService' -or [IO.Path]::GetFileName($serviceExecutable) -ine 'wslservice.exe') { throw 'WSL service did not stop; no shared Windows service process was terminated.' }
            $current = Get-Process -Id $record.ProcessId
            $currentService = Get-CimInstance -ClassName Win32_Service -Filter "Name='WslService'"
            if ($currentService.ProcessId -ne $current.Id -or $current.StartTime -ne $serviceStart -or $current.Path -ine $serviceExecutable) { throw 'WSL service process identity changed; it was not terminated.' }
            $result.stage = 'STOP_HUNG_DEDICATED_SERVICE'
            $current.Kill()
            if (-not $current.WaitForExit(10000)) { throw 'Dedicated WSL service stop timed out.' }
            $result.forcedServiceStop = $true
            $service.Refresh()
            $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(10))
        }
    }
    $result.stage = 'START_SERVICE'
    $service.Start()
    $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(20))
    $result.stage = 'SHUTDOWN_WSL_DISTRIBUTIONS'
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = Join-Path $env:SystemRoot 'System32/wsl.exe'
    $start.Arguments = '--shutdown'
    $start.CreateNoWindow = $true
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $shutdown = [Diagnostics.Process]::Start($start)
    try {
        if (-not $shutdown.WaitForExit(30000)) { $shutdown.Kill(); $shutdown.WaitForExit(); throw 'WSL shutdown still timed out after its service restarted.' }
        if ($shutdown.ExitCode -ne 0) { throw ('WSL shutdown failed with exit ' + $shutdown.ExitCode + '.') }
    } finally { $shutdown.Dispose() }
    $result.state = 'RUNNING'
    $result.stage = 'COMPLETE'
} catch {
    $result.state = 'FAILED'
    $result.error = $_.Exception.GetType().FullName
    $result.message = $_.Exception.Message
} finally {
    $result.completedAt = [DateTime]::UtcNow.ToString('o')
    [IO.File]::WriteAllText($resultPath,($result | ConvertTo-Json),[Text.UTF8Encoding]::new($false))
}
if ($result.state -ne 'RUNNING') {
    Write-Output ('WSL service recovery failed during ' + $result.stage + ': ' + $result.message)
    Write-Output ('Retained result: ' + $resultPath)
    exit 3
}
Write-Output ('WSL service restarted and WSL distributions stopped. Retained result: ' + $resultPath)
