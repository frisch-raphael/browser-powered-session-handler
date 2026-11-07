[CmdletBinding()]
param([string] $JdkHome = $env:JAVA_HOME)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($JdkHome)) { throw 'Supply -JdkHome with a Java 21 JDK, or set JAVA_HOME.' }
$jarTool = Join-Path $JdkHome 'bin/jar.exe'
if (-not (Test-Path -LiteralPath $jarTool -PathType Leaf)) { throw 'The selected JDK has no jar.exe.' }
$workspace = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path
$gradle = Join-Path $workspace 'bapp/gradlew.bat'
$classes = Join-Path $PSScriptRoot 'build/classes/java/hostProbe'
$output = Join-Path $PSScriptRoot 'build/host-probe/authentication-lab-host-probe.jar'
$previousJavaHome = $env:JAVA_HOME
try {
    $env:JAVA_HOME = $JdkHome
    & $gradle -p (Join-Path $workspace 'bapp') ':auth-lab:compileHostProbeJava' --offline --console=plain
    if ($LASTEXITCODE -ne 0) { throw 'Host probe compilation failed.' }
    New-Item -ItemType Directory -Path (Split-Path -Parent $output) -Force | Out-Null
    & $jarTool --create --file $output -C $classes .
    if ($LASTEXITCODE -ne 0) { throw 'Host probe packaging failed.' }
    $entries = & $jarTool --list --file $output
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect the host probe artifact.' }
    $unexpected = @($entries | Where-Object { $_ -notmatch '^(META-INF/|META-INF/MANIFEST\.MF|lab/|lab/auth/|lab/auth/HostProbeExtension(?:\$[^/]*)?\.class)$' })
    if ($unexpected.Count -gt 0) { throw 'The host probe contains unexpected classes or resources.' }
    Write-Output ('Host probe: ' + $output)
    Write-Output ('SHA-256: ' + (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant())
    Write-Output 'This development-only JAR contains no lab dependencies or authentication engine. No Burp acceptance is claimed by building it.'
}
finally { $env:JAVA_HOME = $previousJavaHome }
