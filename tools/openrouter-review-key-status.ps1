<#
Read-only OpenRouter key-status probe.

Prints exactly one line of JSON describing the key's own server-side spend limit:
    {"limit":<number|null>,"limitRemaining":<number|null>,"limitReset":"<string|null>"}

Spends nothing and sends no chat completion -- this is a GET against /api/v1/key. The API key
itself is decrypted only into a local variable, never printed, logged, or returned. Mirrors
openrouter-review-dispatch.ps1's credential handling exactly; see that file for the rationale
behind Add-Type (System.Security is not loaded by default under -NoProfile) and the finally-block
buffer clearing.

The key's monthly spend limit that this reads is enforced by OpenRouter's own servers, not by this repository:
once limit_remaining reaches zero OpenRouter returns HTTP 402 regardless of anything local. This
probe exists so the local side can warn BEFORE that happens, not to enforce the limit itself.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

Add-Type -AssemblyName System.Security

$script:OpenRouterKeyUri = 'https://openrouter.ai/api/v1/key'
$script:CredentialDirectoryName = 'OpenRouterReviewMcp'
$script:CredentialFileName = 'credential.dpapi'

function Get-OpenRouterReviewCredentialPath {
    $root = Join-Path $env:LOCALAPPDATA $script:CredentialDirectoryName
    return (Join-Path $root $script:CredentialFileName)
}

$protectedBytes = $null
$keyBytes = $null
$webRequest = $null
$webResponse = $null
try {
    $credentialPath = Get-OpenRouterReviewCredentialPath
    if (-not (Test-Path -LiteralPath $credentialPath -PathType Leaf)) {
        Write-Output '{"limit":null,"limitRemaining":null,"limitReset":null}'
        exit 0
    }
    $protectedBytes = [IO.File]::ReadAllBytes($credentialPath)
    $keyBytes = [Security.Cryptography.ProtectedData]::Unprotect(
        $protectedBytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser
    )

    $webRequest = [Net.WebRequest]::Create($script:OpenRouterKeyUri)
    $webRequest.Method = 'GET'
    $webRequest.Timeout = 15000
    $webRequest.ReadWriteTimeout = 15000
    $authorizationHeaderValue = ('Bearer {0}' -f [Text.Encoding]::UTF8.GetString($keyBytes))
    $webRequest.Headers.Add('Authorization', $authorizationHeaderValue)
    $authorizationHeaderValue = $null

    $webResponse = $webRequest.GetResponse()
    $reader = New-Object IO.StreamReader($webResponse.GetResponseStream())
    try { $bodyText = $reader.ReadToEnd() } finally { $reader.Dispose() }
    $parsed = $bodyText | ConvertFrom-Json

    $result = [ordered]@{
        limit          = $parsed.data.limit
        limitRemaining = $parsed.data.limit_remaining
        limitReset     = $parsed.data.limit_reset
    }
    Write-Output ($result | ConvertTo-Json -Compress)
    exit 0
}
catch {
    # Never leak the exception text: a WebException message can echo request details.
    Write-Output '{"limit":null,"limitRemaining":null,"limitReset":null}'
    exit 0
}
finally {
    if ($null -ne $webRequest) { try { $webRequest.Headers.Remove('Authorization') } catch { } }
    if ($null -ne $webResponse) { try { $webResponse.Dispose() } catch { } }
    if ($null -ne $keyBytes) { [Array]::Clear($keyBytes, 0, $keyBytes.Length) }
    if ($null -ne $protectedBytes) { [Array]::Clear($protectedBytes, 0, $protectedBytes.Length) }
}
