[CmdletBinding()]
param([string] $JdkHome = $env:JAVA_HOME)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($JdkHome)) { throw 'Supply -JdkHome with a Java 21 JDK, or set JAVA_HOME.' }
$jarTool = Join-Path $JdkHome 'bin/jar.exe'
if (-not (Test-Path -LiteralPath $jarTool -PathType Leaf)) { throw 'The selected JDK has no jar.exe.' }
$workspace = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path
$gradle = Join-Path $workspace 'bapp/gradlew.bat'
$output = Join-Path $PSScriptRoot 'build/host-probe/authentication-lab-host-probe.jar'
$previousJavaHome = $env:JAVA_HOME
try {
    $env:JAVA_HOME = $JdkHome
    & $gradle -p (Join-Path $workspace 'bapp') ':auth-lab:hostProbeJar' --offline --console=plain
    if ($LASTEXITCODE -ne 0) { throw 'Host probe compilation failed.' }
    $entries = & $jarTool --list --file $output
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect the host probe artifact.' }
    $unexpected = @($entries | Where-Object { $_ -notmatch '^(META-INF(?:/.*)?|com/|com/google/|com/google/gson(?:/.*)?|lab/|lab/auth/|lab/auth/gui(?:/.*)?|lab/auth/(?:HostProbeExtension|LabJson|LabHostGuiProtocol)(?:\$[^/]*)?\.class)$' })
    if ($unexpected.Count -gt 0) { throw 'The host probe contains unexpected classes or resources.' }
    Write-Output ('Host probe: ' + $output)
    Write-Output ('SHA-256: ' + (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant())
    Write-Output 'This developer helper contains the passive probe, public JDK GUI driver and pinned Gson. It contains no authentication engine. Building it grants no Burp acceptance.'
}
finally { $env:JAVA_HOME = $previousJavaHome }
