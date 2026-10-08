<#
One-shot OpenRouter review dispatch worker.

Reads the exact JSON request body already assembled by the Node review engine
from -RequestPath, decrypts the DPAPI-protected credential written by
openrouter-review-configure.ps1, sends exactly ONE HTTPS POST to the OpenRouter
chat completions endpoint before -DeadlineUtc, and writes exactly one line of
JSON to stdout: either the raw provider response bytes, or a typed
secret-free failure object. Nothing else is written to stdout; the
Authorization header value is never logged.

This script never retries and never shells out to any other
OpenRouter-dispatching script in this repository -- it is a narrower,
single-purpose worker invoked only by the review engine's own dispatch
adapter.

Durable outcome capture: the calling Node process
(openrouter-review-mcp-server.mjs) can itself be replaced mid-dispatch by
something outside this repository's control (for example, an MCP client
that restarts its server). When that happens, whatever this script returns
on stdout is never read by anyone -- a real, successful OpenRouter response
would be silently discarded, indistinguishable on the Node side from the
dispatch having never happened at all, forcing review-engine.mjs to charge a
worst-case cost with no recoverable content. This script therefore ALSO
writes its outcome to -ResponsePath, atomically, the instant it has one --
before ever returning on stdout -- so a later process (via
dispatch-outcome-store.mjs's read side) can recover a real response its
original caller never got to see, instead of treating it as an unknown,
unrecoverable outcome. The raw REQUEST (built from
potentially sensitive source text) is still never written here and never
kept by the caller past one dispatch (see -RequestPath handling in
openrouter-review-mcp-server.mjs's createDispatchAdapter); only the
RESPONSE -- the reviewer's own generated output, no different in kind from
the advisory content result-store.mjs already keeps forever on a normal
successful pass -- is captured this way.

stdout contract (always exactly one line, and the same content is durably
written to -ResponsePath before this line is ever printed):
    {"kind":"RESPONSE","envelopeJsonText":"{\"httpStatus\":<int>,\"bodyBase64\":\"<b64>\"}"}
    {"kind":"FAILURE","envelopeJsonText":"{\"failureKind\":\"<code>\",\"message\":\"<text>\"}"}
#>

param(
    [Parameter(Position = 0, ParameterSetName = 'Legacy')]
    [ValidateNotNullOrEmpty()]
    [string] $RequestPath,

    [Parameter(Position = 1, ParameterSetName = 'Legacy')]
    [ValidateNotNullOrEmpty()]
    [string] $DeadlineUtc,

    [Parameter(Position = 2, ParameterSetName = 'Legacy')]
    [ValidateNotNullOrEmpty()]
    [string] $ResponsePath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Managed')]
    [switch] $ManagedWorker
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# System.Security.Cryptography.ProtectedData lives in System.Security.dll, which
# a fresh -NoProfile PowerShell 5.1 session does not load by default -- without
# this, [Security.Cryptography.ProtectedData]::Unprotect below throws "Unable
# to find type", caught and misreported as CREDENTIAL_DECRYPT_FAILED even
# though the credential itself is fine.
Add-Type -AssemblyName System.Security
. (Join-Path $PSScriptRoot 'openrouter-review-shared-storage.ps1')

$script:OpenRouterChatCompletionsUri = 'https://openrouter.ai/api/v1/chat/completions'
$script:CredentialDirectoryName = 'OpenRouterReviewMcp'
$script:CredentialFileName = 'credential.dpapi'
$script:MaxRequestBytes = 4194304
$script:MaxResponseBytes = 16MB

function Get-OpenRouterReviewCredentialPath {
    $root = Join-Path $env:LOCALAPPDATA $script:CredentialDirectoryName
    return (Join-Path $root $script:CredentialFileName)
}

function Write-OpenRouterOutcomeAtomic {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Path, [Parameter(Mandatory = $true)][string]$Line)
    if ($Path.Length -eq 0) { return }
    # Best-effort only: a durable-write failure here (disk full, path
    # unwritable) must never prevent this script from still returning its
    # normal stdout line -- this file is a recovery safety net, never a
    # precondition for the primary, still-connected-caller path. Mirrors
    # openrouter-review-authorize.ps1's own Write-ResultAtomic exactly: temp
    # file + [System.IO.File]::WriteAllText with an explicit no-BOM
    # UTF8Encoding (Set-Content -Encoding utf8 writes a BOM that Node's
    # JSON.parse chokes on -- the same fix already applied there), then an
    # atomic Move-Item into place so a reader never observes a partial write.
    try {
        $directory = Split-Path -Parent $Path
        if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
        $temp = "$Path.$([guid]::NewGuid().ToString()).tmp"
        [System.IO.File]::WriteAllText($temp, $Line, (New-Object System.Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $temp -Destination $Path -Force
    }
    catch { }
}

function ConvertTo-OpenRouterDispatchLine {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('RESPONSE', 'FAILURE')][string]$Kind,
        [Parameter(Mandatory = $true)][Collections.IDictionary]$Envelope,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ResponsePath
    )
    $envelopeJsonText = ($Envelope | ConvertTo-Json -Compress -Depth 6)
    $outer = [ordered]@{ kind = $Kind; envelopeJsonText = $envelopeJsonText }
    $line = ($outer | ConvertTo-Json -Compress -Depth 3)
    # Written BEFORE this function returns the line to its caller -- the
    # whole point is a durable record existing even if the caller (this
    # process's own parent) never gets to read the stdout this feeds.
    Write-OpenRouterOutcomeAtomic -Path $ResponsePath -Line $line
    return $line
}

function New-OpenRouterFailureLine {
    param(
        [Parameter(Mandatory = $true)][string]$FailureKind,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ResponsePath
    )
    return (ConvertTo-OpenRouterDispatchLine -Kind 'FAILURE' -ResponsePath $ResponsePath -Envelope ([ordered]@{
        failureKind = $FailureKind
        message     = $Message
    }))
}

function New-OpenRouterResponseLine {
    param(
        [Parameter(Mandatory = $true)][int]$HttpStatus,
        [Parameter(Mandatory = $true)][byte[]]$BodyBytes,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ResponsePath
    )
    return (ConvertTo-OpenRouterDispatchLine -Kind 'RESPONSE' -ResponsePath $ResponsePath -Envelope ([ordered]@{
        httpStatus = $HttpStatus
        bodyBase64 = [Convert]::ToBase64String($BodyBytes)
    }))
}

function Read-OpenRouterResponseBytes {
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream)
    $memoryStream = New-Object IO.MemoryStream
    try {
        $Stream.CopyTo($memoryStream)
        if ($memoryStream.Length -gt $script:MaxResponseBytes) { throw 'response exceeded the bounded size limit' }
        return $memoryStream.ToArray()
    }
    finally { $memoryStream.Dispose() }
}

function Invoke-OpenRouterReviewDispatch {
    param(
        [Parameter(Mandatory = $true)][string]$RequestPath,
        [Parameter(Mandatory = $true)][string]$DeadlineUtc,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ResponsePath,
        [byte[]]$RequestBytesOverride,
        [int]$MaximumTimeoutMs = [int]::MaxValue
    )

    $deadline = $null
    try { $deadline = [DateTimeOffset]::Parse($DeadlineUtc).ToUniversalTime() }
    catch { return (New-OpenRouterFailureLine -FailureKind 'INVALID_DEADLINE' -Message 'deadline could not be parsed as a timestamp' -ResponsePath $ResponsePath) }

    # Early exit only -- avoids the request-file read and DPAPI credential
    # decrypt below for an already-doomed dispatch. NOT reused for
    # $webRequest.Timeout: a stale value computed here would drift, since
    # real time elapses in the request-file read and (especially) the DPAPI
    # decrypt between this point and where the timeout is actually applied.
    # See the second, fresh computation immediately before that assignment.
    $remainingMs = [int][Math]::Floor(($deadline - [DateTimeOffset]::UtcNow).TotalMilliseconds)
    if ($remainingMs -le 0) { return (New-OpenRouterFailureLine -FailureKind 'DEADLINE_EXCEEDED' -Message 'the deadline had already passed before dispatch began' -ResponsePath $ResponsePath) }

    $requestBytes = $null
    if ($null -ne $RequestBytesOverride) { $requestBytes = $RequestBytesOverride }
    else {
        if (-not (Test-Path -LiteralPath $RequestPath -PathType Leaf)) {
            return (New-OpenRouterFailureLine -FailureKind 'REQUEST_FILE_INVALID' -Message 'the request file does not exist' -ResponsePath $ResponsePath)
        }
        try { $requestBytes = [IO.File]::ReadAllBytes($RequestPath) }
        catch { return (New-OpenRouterFailureLine -FailureKind 'REQUEST_FILE_INVALID' -Message 'the request file could not be read' -ResponsePath $ResponsePath) }
    }
    if ($requestBytes.Length -eq 0 -or $requestBytes.Length -gt $script:MaxRequestBytes) {
        return (New-OpenRouterFailureLine -FailureKind 'REQUEST_FILE_INVALID' -Message 'the request file is empty or exceeds the bounded size limit' -ResponsePath $ResponsePath)
    }

    $credentialPath = Get-OpenRouterReviewCredentialPath
    if (-not (Test-Path -LiteralPath $credentialPath -PathType Leaf)) {
        return (New-OpenRouterFailureLine -FailureKind 'CREDENTIAL_MISSING' -Message 'no provisioned credential was found; run openrouter-review-configure.ps1 first' -ResponsePath $ResponsePath)
    }

    $protectedBytes = $null
    $keyBytes = $null
    $requestStream = $null
    $webRequest = $null
    $webResponse = $null
    try {
        try {
            $protectedBytes = [IO.File]::ReadAllBytes($credentialPath)
            $keyBytes = [Security.Cryptography.ProtectedData]::Unprotect(
                $protectedBytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser
            )
        }
        catch {
            return (New-OpenRouterFailureLine -FailureKind 'CREDENTIAL_DECRYPT_FAILED' -Message 'the provisioned credential could not be decrypted for the current Windows user' -ResponsePath $ResponsePath)
        }
        if ($keyBytes.Length -eq 0) {
            return (New-OpenRouterFailureLine -FailureKind 'CREDENTIAL_DECRYPT_FAILED' -Message 'the decrypted credential was empty' -ResponsePath $ResponsePath)
        }

        # Re-derived from $deadline (the absolute, already-parsed instant --
        # never itself stale) via a FRESH UtcNow read taken here, immediately
        # before use, rather than reusing $remainingMs from above: this is
        # the same relative-duration-drift guard applied at its two callers
        # (review-engine.mjs's review(), and the dispatch adapter in
        # openrouter-review-mcp-server.mjs), applied one layer deeper here,
        # since the request-file read and DPAPI credential decrypt above can
        # themselves take real time that $remainingMs never accounted for.
        $effectiveRemainingMs = [int][Math]::Floor(($deadline - [DateTimeOffset]::UtcNow).TotalMilliseconds)
        if ($effectiveRemainingMs -le 0) {
            return (New-OpenRouterFailureLine -FailureKind 'DEADLINE_EXCEEDED' -Message 'the deadline passed during request-file/credential setup, before the request could be sent' -ResponsePath $ResponsePath)
        }

        $webRequest = [Net.WebRequest]::Create($script:OpenRouterChatCompletionsUri)
        $webRequest.Method = 'POST'
        $webRequest.ContentType = 'application/json'
        if ($MaximumTimeoutMs -lt $effectiveRemainingMs) { $effectiveRemainingMs = $MaximumTimeoutMs }
        $webRequest.Timeout = $effectiveRemainingMs
        $webRequest.ReadWriteTimeout = $effectiveRemainingMs
        # KNOWN LIMITATION: [Net.WebRequest]'s Headers
        # collection only accepts a System.String value, so a plaintext copy
        # of the key must exist as a .NET string for this call. .NET strings
        # are immutable and cannot be zeroed the way $keyBytes is below, so
        # this string is not scrubbed -- only dereferenced as early as
        # possible (cleared from the local variable and removed from
        # $webRequest.Headers in the finally block once the request has been
        # sent) so it becomes eligible for garbage collection as soon as this
        # call completes. It is never assigned to a script-scoped variable,
        # never passed to any Write-* cmdlet, and never placed in an
        # exception. This is a disclosed gap in "clears decrypted bytes in
        # finally", not a claim that the string itself is cleared.
        $authorizationHeaderValue = ('Bearer {0}' -f [Text.Encoding]::UTF8.GetString($keyBytes))
        $webRequest.Headers.Add('Authorization', $authorizationHeaderValue)
        $authorizationHeaderValue = $null
        $webRequest.ContentLength = $requestBytes.Length

        try {
            $requestStream = $webRequest.GetRequestStream()
            $requestStream.Write($requestBytes, 0, $requestBytes.Length)
            $requestStream.Flush()
        }
        catch { return (New-OpenRouterFailureLine -FailureKind 'NETWORK_ERROR' -Message 'the request body could not be sent' -ResponsePath $ResponsePath) }
        finally {
            if ($null -ne $requestStream) { $requestStream.Dispose() }
            $requestStream = $null
        }

        try {
            $webResponse = $webRequest.GetResponse()
        }
        catch [Net.WebException] {
            $webException = $_.Exception
            if ($null -eq $webException.Response) {
                if ($webException.Status -eq [Net.WebExceptionStatus]::Timeout) {
                    return (New-OpenRouterFailureLine -FailureKind 'TIMEOUT' -Message 'the request did not complete before the deadline' -ResponsePath $ResponsePath)
                }
                return (New-OpenRouterFailureLine -FailureKind 'NETWORK_ERROR' -Message 'the request failed before any response was received' -ResponsePath $ResponsePath)
            }
            $webResponse = $webException.Response
        }
        catch { return (New-OpenRouterFailureLine -FailureKind 'NETWORK_ERROR' -Message 'the request failed before any response was received (non-WebException)' -ResponsePath $ResponsePath) }

        try {
            $httpStatus = [int]$webResponse.StatusCode
            $bodyBytes = Read-OpenRouterResponseBytes -Stream $webResponse.GetResponseStream()
            return (New-OpenRouterResponseLine -HttpStatus $httpStatus -BodyBytes $bodyBytes -ResponsePath $ResponsePath)
        }
        # Deliberately a DIFFERENT FailureKind than the NETWORK_ERROR used above and below --
        # review-engine.mjs's zero-cost-on-transport-failure rule relies on this
        # distinction being real, not cosmetic: by the point this catch can fire, $webResponse.
        # GetResponse() has already succeeded, meaning OpenRouter's HTTP status/headers were
        # already received. This is a NON-streaming request (every reviewer sets stream:false in
        # reviewer-registry.mjs), so a successful GetResponse() means the full completion was very
        # likely already generated -- and, per standard non-streaming-API billing practice,
        # probably already billed -- server-side before this local body-read ever failed. That is
        # NOT true of every other FailureKind in this script (all provably occur before any
        # response was ever received, or before the network was touched at all), so this one case
        # must never be folded into the same cost bucket as those, even though the underlying
        # local error is superficially "a network error" too.
        catch { return (New-OpenRouterFailureLine -FailureKind 'RESPONSE_READ_FAILED' -Message 'a response was received but its body could not be fully read' -ResponsePath $ResponsePath) }
    }
    finally {
        # Drop the CLR's own reference to the header string as early as
        # possible (see KNOWN LIMITATION comment above -- this makes the
        # string eligible for collection sooner; it does not scrub it).
        if ($null -ne $webRequest) { try { $webRequest.Headers.Remove('Authorization') } catch { } }
        if ($null -ne $webResponse) { try { $webResponse.Dispose() } catch { } }
        if ($null -ne $keyBytes) { [Array]::Clear($keyBytes, 0, $keyBytes.Length) }
        if ($null -ne $protectedBytes) { [Array]::Clear($protectedBytes, 0, $protectedBytes.Length) }
        $keyBytes = $null
        $protectedBytes = $null
    }
}

function Invoke-OpenRouterManagedDispatch {
    param([Parameter(Mandatory = $true)]$StartFrame)
    $jobId = ''
    $requestBytes = $null
    $captureBytes = $null
    $ciphertext = $null
    try {
        Assert-Shape -Value $StartFrame -Required @('type','version','association','installationRoots','requestRef','candidate','notAfterMs','httpTimeoutMs','reservedBytes')
        if ($StartFrame.type -cne 'MANAGED_DISPATCH_START' -or $StartFrame.version -ne 1) { throw 'INVALID_FRAME' }
        Assert-Shape -Value $StartFrame.association -Required @('jobId','reviewerId','intentDigest')
        Assert-Shape -Value $StartFrame.requestRef -Required @('objectId','sha256','encryptedBytes')
        Assert-Shape -Value $StartFrame.candidate -Required @('objectId','relativePath')
        $jobId = [string]$StartFrame.association.jobId
        if ($jobId -notmatch '^[a-f0-9]{64}$') { throw 'INVALID_FRAME' }
        if (([string]$StartFrame.association.intentDigest) -notmatch '^[a-f0-9]{64}$') { throw 'INVALID_FRAME' }
        if (([string]$StartFrame.requestRef.objectId) -notmatch '^[a-f0-9-]{36}$') { throw 'INVALID_FRAME' }
        if (([string]$StartFrame.requestRef.sha256) -notmatch '^[a-f0-9]{64}$') { throw 'INVALID_FRAME' }
        if (([string]$StartFrame.candidate.objectId) -notmatch '^[a-f0-9-]{36}$') { throw 'INVALID_FRAME' }
        if ([long]$StartFrame.requestRef.encryptedBytes -le 0) { throw 'INVALID_FRAME' }
        if ([long]$StartFrame.notAfterMs -le 0) { throw 'INVALID_FRAME' }
        if ([long]$StartFrame.httpTimeoutMs -le 0) { throw 'INVALID_FRAME' }
        if ([long]$StartFrame.reservedBytes -le 0) { throw 'INVALID_FRAME' }
        $expectedCandidate = 'dispatch-candidates/dispatch-outcome-{0}.candidate.v1.bin' -f [string]$StartFrame.candidate.objectId
        if ([string]$StartFrame.candidate.relativePath -cne $expectedCandidate) { throw 'INVALID_FRAME' }
        Verify-Roots -Roots $StartFrame.installationRoots
        $rootMap = Get-RootMap -Roots $StartFrame.installationRoots
        $requestRelative = 'dispatch-request-{0}.v1.bin' -f [string]$StartFrame.requestRef.objectId
        $requestPath = Join-Path $rootMap.objects $requestRelative
        $candidatePath = Join-Path $rootMap.objects ([string]$StartFrame.candidate.relativePath)
        Assert-ProtectedAcl -Path $requestPath -Directory $false
        Assert-ProtectedAcl -Path $candidatePath -Directory $false
        $requestCiphertext = [IO.File]::ReadAllBytes($requestPath)
        try {
            if ($requestCiphertext.LongLength -ne [long]$StartFrame.requestRef.encryptedBytes) { throw 'INTEGRITY_FAILED' }
            if ((Get-Sha256Hex -Bytes $requestCiphertext) -cne ([string]$StartFrame.requestRef.sha256)) { throw 'INTEGRITY_FAILED' }
            $requestBytes = ConvertFrom-ProtectedBytes -Purpose 'dispatch-request' -ObjectId ([string]$StartFrame.requestRef.objectId) -Ciphertext $requestCiphertext
        }
        finally { if ($null -ne $requestCiphertext) { [Array]::Clear($requestCiphertext, 0, $requestCiphertext.Length) } }
        $deadline = [DateTimeOffset]::FromUnixTimeMilliseconds([long]$StartFrame.notAfterMs).ToString('o')
        $line = Invoke-OpenRouterReviewDispatch -RequestPath 'managed-memory' -DeadlineUtc $deadline -ResponsePath '' -RequestBytesOverride $requestBytes -MaximumTimeoutMs ([int]$StartFrame.httpTimeoutMs)
        $outcome = $line | ConvertFrom-Json
        Assert-Shape -Value $outcome -Required @('kind','envelopeJsonText')
        if (@('RESPONSE','FAILURE') -notcontains [string]$outcome.kind) { throw 'INTEGRITY_FAILED' }
        $capture = [ordered]@{
            version = 1
            association = [ordered]@{ jobId=$jobId; reviewerId=[string]$StartFrame.association.reviewerId; intentDigest=[string]$StartFrame.association.intentDigest }
            outcome = [ordered]@{ kind=[string]$outcome.kind; envelopeJsonText=[string]$outcome.envelopeJsonText }
        }
        $captureBytes = [Text.Encoding]::UTF8.GetBytes(($capture | ConvertTo-Json -Compress -Depth 8))
        $ciphertext = ConvertTo-ProtectedBytes -Purpose 'dispatch-outcome' -ObjectId ([string]$StartFrame.candidate.objectId) -Content $captureBytes
        if ($ciphertext.LongLength -gt (2 * 32MB + 131072) -or $ciphertext.LongLength -gt [long]$StartFrame.reservedBytes) { throw 'CONTENT_TOO_LARGE' }
        $stream = New-Object IO.FileStream($candidatePath, [IO.FileMode]::Truncate, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($ciphertext, 0, $ciphertext.Length); $stream.Flush($true) }
        finally { $stream.Dispose() }
        Assert-ProtectedAcl -Path $candidatePath -Directory $false
        return [ordered]@{
            type='MANAGED_DISPATCH_COMPLETE'; version=1; status='CAPTURE_CANDIDATE'; jobId=$jobId
            outcomeObjectId=[string]$StartFrame.candidate.objectId
            sha256=(Get-Sha256Hex -Bytes $ciphertext); encryptedBytes=[long]$ciphertext.LongLength
        }
    }
    catch {
        return [ordered]@{ type='MANAGED_DISPATCH_COMPLETE'; version=1; status='CAPTURE_FAILED'; jobId=$jobId }
    }
    finally {
        if ($null -ne $requestBytes) { [Array]::Clear($requestBytes, 0, $requestBytes.Length) }
        if ($null -ne $captureBytes) { [Array]::Clear($captureBytes, 0, $captureBytes.Length) }
        if ($null -ne $ciphertext) { [Array]::Clear($ciphertext, 0, $ciphertext.Length) }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($ManagedWorker) {
        try {
            $managedStart = Read-Frame
            $managedCompletion = Invoke-OpenRouterManagedDispatch -StartFrame $managedStart
            Write-Frame $managedCompletion
            exit 0
        }
        catch { exit 1 }
    }
    if ([string]::IsNullOrWhiteSpace($RequestPath) -or [string]::IsNullOrWhiteSpace($DeadlineUtc) -or [string]::IsNullOrWhiteSpace($ResponsePath)) { exit 1 }
    # Diagnostic instrumentation for STATUS_CONTROL_C_EXIT failures -- see
    # openrouter-review-ctrl-signal-log.ps1's own header for the full rationale. Installed as
    # early as possible, before any real dispatch work (request-file read, DPAPI decrypt, HTTPS
    # call) begins, since such a failure can arrive within seconds of process start.
    #
    # Wrapped in its own try/catch: dot-sourcing runs the module's Add-Type at parse time,
    # outside any function body, so Install-OpenRouterCtrlSignalLog's own internal error
    # handling (which only covers the SetConsoleCtrlHandler call itself) can never catch an
    # Add-Type compilation failure. This diagnostic must never be why a real dispatch fails.
    try {
        . (Join-Path $PSScriptRoot 'openrouter-review-ctrl-signal-log.ps1')
        Install-OpenRouterCtrlSignalLog -LogPath (Join-Path (Split-Path -Parent $ResponsePath) 'ctrl-signals.log') -Role 'worker' | Out-Null
    }
    catch {
        Write-Warning "console-control diagnostics could not be installed: $($_.Exception.Message)"
    }
    try {
        Write-Output (Invoke-OpenRouterReviewDispatch -RequestPath $RequestPath -DeadlineUtc $DeadlineUtc -ResponsePath $ResponsePath)
        exit 0
    }
    catch {
        Write-Output (New-OpenRouterFailureLine -FailureKind 'INTERNAL_ERROR' -Message 'an unexpected error occurred during dispatch' -ResponsePath $ResponsePath)
        exit 0
    }
}
