param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string] $RequestPath,

    [Parameter(Mandatory = $true, Position = 1)]
    [ValidateNotNullOrEmpty()]
    [string] $ResultPath
)

$ErrorActionPreference = 'Stop'
$outcome = 'DENIED'
$nonce = 'invalid-request'

# This process is launched via cmd /c start /wait with no stdio redirection to
# this script's own stdout/stdin, so the outcome can no longer travel back to
# the caller that way. It is written here instead, atomically (temp file +
# rename) so the caller never observes a partially written file. Windows
# PowerShell 5.1's `Set-Content -Encoding utf8` writes a UTF-8 BOM (unlike
# PowerShell 7+); Node's JSON.parse on the reading side throws on that leading
# BOM byte sequence, so [System.IO.File]::WriteAllText with an explicit
# no-BOM UTF8Encoding is used instead.
function Write-ResultAtomic {
    param([string] $Path, [string] $Outcome, [string] $Nonce)
    $temp = "$Path.$([guid]::NewGuid().ToString()).tmp"
    $json = (@{ outcome = $Outcome; nonce = $Nonce } | ConvertTo-Json -Compress)
    [System.IO.File]::WriteAllText($temp, $json, (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temp -Destination $Path -Force
}

function ConvertTo-CanonicalJson {
    param($Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [string]) { return ($Value | ConvertTo-Json -Compress) }
    if ($Value -is [System.Collections.IDictionary]) {
        $parts = @()
        foreach ($key in @($Value.Keys | ForEach-Object { [string] $_ } | Sort-Object)) {
            $parts += ((($key | ConvertTo-Json -Compress) + ':') + (ConvertTo-CanonicalJson $Value[$key]))
        }
        return '{' + ($parts -join ',') + '}'
    }
    if ($Value -is [pscustomobject]) {
        $parts = @()
        foreach ($key in @($Value.PSObject.Properties.Name | Sort-Object)) {
            $parts += ((($key | ConvertTo-Json -Compress) + ':') + (ConvertTo-CanonicalJson $Value.$key))
        }
        return '{' + ($parts -join ',') + '}'
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        return '[' + ((@($Value | ForEach-Object { ConvertTo-CanonicalJson $_ })) -join ',') + ']'
    }
    return ($Value | ConvertTo-Json -Compress)
}

function Get-RequestSha256 {
    param([string] $Text)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    try { return ([System.BitConverter]::ToString(([System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()) }
    finally { [Array]::Clear($bytes, 0, $bytes.Length) }
}

try {
    $request = Get-Content -LiteralPath $RequestPath -Raw | ConvertFrom-Json
    $allowed = @(
        'authorizationSchema', 'nonce', 'approvalPhrase', 'preflightHashes',
        'profiles', 'itemMaxima', 'requestedUsd', 'maxJobs', 'expiresAt', 'requestSha256'
    )
    foreach ($name in $request.PSObject.Properties.Name) {
        if ($allowed -notcontains $name) { throw "Unexpected request field: $name" }
    }
    foreach ($name in $allowed) {
        if (-not $request.PSObject.Properties.Name.Contains($name)) { throw "Missing request field: $name" }
    }
    if ($request.authorizationSchema -ne 'openrouter_review_authorization_v1') { throw 'Unsupported authorization schema' }
    if ($request.nonce -notmatch '^[0-9a-f-]{36}$') { throw 'Invalid nonce' }
    $nonce = [string] $request.nonce
    $unsigned = [ordered]@{}
    foreach ($name in $allowed) { if ($name -ne 'requestSha256') { $unsigned[$name] = $request.$name } }
    if ([string] $request.requestSha256 -ne (Get-RequestSha256 (ConvertTo-CanonicalJson $unsigned))) { throw 'Request integrity hash does not match' }
    $expiresAt = [DateTimeOffset]::Parse([string] $request.expiresAt).ToUniversalTime()

    Write-Host 'OpenRouter advisory-review workflow authorization'
    Write-Host ("Nonce: {0}" -f $nonce)
    Write-Host ("Profiles: {0}" -f (($request.profiles | ForEach-Object { [string] $_ }) -join ', '))
    Write-Host ("Preflight hashes: {0}" -f (($request.preflightHashes | ForEach-Object { [string] $_ }) -join ', '))
    Write-Host ("Per-item maximums: {0}" -f (($request.itemMaxima | ForEach-Object { "{0}=${1}" -f $_.itemId, $_.maxUsd }) -join ', '))
    Write-Host ("Requested workflow cap: {0}" -f $request.requestedUsd)
    Write-Host ("Maximum jobs: {0}" -f $request.maxJobs)
    Write-Host ("Expires (UTC): {0}" -f $expiresAt.ToString('o'))

    if ([DateTimeOffset]::UtcNow -ge $expiresAt) {
        $outcome = 'TIMED_OUT'
    } else {
        $approvalPhrase = "APPROVE $nonce"
        $reply = Read-Host ("Type exactly '{0}' once to authorize this workflow" -f $approvalPhrase)
        if ([DateTimeOffset]::UtcNow -ge $expiresAt) {
            $outcome = 'TIMED_OUT'
        } elseif ($reply -ceq $approvalPhrase) {
            $outcome = 'APPROVED'
        } else {
            $outcome = 'DENIED'
        }
    }
} catch {
    $outcome = 'DENIED'
}

Write-Host ("Recorded outcome: {0}" -f $outcome)
Write-ResultAtomic -Path $ResultPath -Outcome $outcome -Nonce $nonce
Write-Host 'This window will close automatically.'
Start-Sleep -Seconds 3
