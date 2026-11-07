function Update-AuthLabHosts {
    param(
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][byte[]]$Original,
        [Parameter(Mandatory=$true)][ValidateSet('Install','Remove')][string]$Action,
        [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$CaSha256
    )
    if ($Original.Length -gt 1MB) { throw 'The hosts file exceeds the supported preparation size.' }
    $encoding = [Text.Encoding]::GetEncoding(28591)
    $text = $encoding.GetString($Original)
    $fingerprint = $CaSha256.ToLowerInvariant()
    $begin = '# BEGIN AUTHLAB ' + $fingerprint
    $end = '# END AUTHLAB ' + $fingerprint
    $pattern = '(?ms)^' + [regex]::Escape($begin) + '( OWNED-NEWLINE)?\r?\n.*?^' + [regex]::Escape($end) + '(?:\r?\n|$)'
    $managedMatches = [regex]::Matches($text, $pattern)
    if ($managedMatches.Count -gt 1) { throw 'Duplicate managed hosts blocks require review.' }
    $without = $text
    if ($managedMatches.Count -eq 1) {
        $match = $managedMatches[0]; $start = $match.Index; $length = $match.Length
        if ($match.Groups[1].Success) {
            if ($start -lt 2 -or $text.Substring($start - 2, 2) -ne "`r`n") { throw 'The managed newline is inconsistent.' }
            $start -= 2; $length += 2
        }
        $without = $text.Remove($start, $length)
    }
    if ($Action -eq 'Install' -and $without -match '(?m)^# BEGIN AUTHLAB ') { throw 'Remove the different lab CA preparation explicitly first.' }
    $names = @('app.authlab.test','api.authlab.test','idp.federation.test','idp.upstream-sso.test')
    if ($Action -eq 'Install') { foreach ($line in ($without -split '\r?\n')) {
        $parts = (($line -split '#',2)[0].Trim() -split '\s+')
        if ($parts.Length -lt 2) { continue }
        foreach ($name in $parts[1..($parts.Length-1)]) {
            if ($names -contains $name -and $parts[0] -ne '127.0.0.1') { throw ('An existing hosts record conflicts with ' + $name + '. No unrelated record was changed.') }
        }
    } }
    if ($Action -eq 'Remove') { return ,$encoding.GetBytes($without) }
    $prefix = ''; $marker = $begin
    if ($without.Length -gt 0 -and -not $without.EndsWith("`n")) { $prefix = "`r`n"; $marker += ' OWNED-NEWLINE' }
    return ,$encoding.GetBytes($without + $prefix + $marker + "`r`n127.0.0.1 " + ($names -join ' ') + "`r`n" + $end + "`r`n")
}
Export-ModuleMember -Function Update-AuthLabHosts
