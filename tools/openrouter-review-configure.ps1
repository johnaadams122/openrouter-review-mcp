<#
Human-only, one-time OpenRouter review-MCP credential provisioning.

This script is run directly by a person at a console. It is never invoked by an
MCP tool, by any agent, or by any other script in this repository -- the local
stdio review MCP server has no code path that shells out to this file. Its
only job is: ask for the key once, protect it with Windows DPAPI under the
current Windows user, write the protected blob to a restricted-ACL file, and
report success or failure. It never reads, prints, logs, or returns the key
itself, and it never writes the key (or anything derived from it) anywhere
that could reach PSReadLine history, a transcript, or an exception message.

Usage (interactive only):
    .\tools\openrouter-review-configure.ps1
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# System.Security.Cryptography.ProtectedData lives in System.Security.dll, which
# a fresh -NoProfile PowerShell 5.1 session does not load by default -- without
# this, every [Security.Cryptography.ProtectedData] reference below throws
# "Unable to find type", caught by the deliberately-silent handler and reported
# only as the bare "FAILURE" this script is designed to print.
Add-Type -AssemblyName System.Security

$script:CredentialDirectoryName = 'OpenRouterReviewMcp'
$script:CredentialFileName = 'credential.dpapi'

function Get-OpenRouterReviewCredentialPath {
    $root = Join-Path $env:LOCALAPPDATA $script:CredentialDirectoryName
    return (Join-Path $root $script:CredentialFileName)
}

function Set-OpenRouterReviewCredentialAcl {
    param([Parameter(Mandatory = $true)][string]$Path)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule(
        $identity, 'FullControl', 'Allow'
    )
    $acl.AddAccessRule($rule)
    $acl.SetOwner($identity)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Invoke-WithOpenRouterReviewSecureBytes {
    param(
        [Parameter(Mandatory = $true)][Security.SecureString]$SecureString,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )
    $bstr = [IntPtr]::Zero
    $chars = $null
    $bytes = $null
    try {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        $byteLength = [Runtime.InteropServices.Marshal]::ReadInt32($bstr, -4)
        if ($byteLength -le 0 -or ($byteLength % 2) -ne 0 -or $byteLength -gt 2048) { throw 'key material has an unexpected length' }
        $chars = New-Object char[] ($byteLength / 2)
        [Runtime.InteropServices.Marshal]::Copy($bstr, $chars, 0, $chars.Length)
        $bytes = [Text.Encoding]::UTF8.GetBytes($chars)
        if ($bytes.Length -le 0 -or $bytes.Length -gt 1024) { throw 'key material has an unexpected byte length' }
        $null = & $Action $bytes
    }
    finally {
        if ($null -ne $bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
        if ($null -ne $chars) { [Array]::Clear($chars, 0, $chars.Length) }
        if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        $bytes = $null
        $chars = $null
        $bstr = [IntPtr]::Zero
    }
}

function Protect-OpenRouterReviewCredential {
    param([Parameter(Mandatory = $true)][byte[]]$KeyBytes)
    $protectedBytes = $null
    $roundTripBytes = $null
    try {
        $protectedBytes = [Security.Cryptography.ProtectedData]::Protect(
            $KeyBytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        # Verify the round trip before ever committing the blob to disk -- a
        # write that cannot later be decrypted is worse than no write at all.
        $roundTripBytes = [Security.Cryptography.ProtectedData]::Unprotect(
            $protectedBytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        if ($roundTripBytes.Length -ne $KeyBytes.Length) { throw 'DPAPI round-trip length mismatch' }
        $difference = 0
        for ($index = 0; $index -lt $KeyBytes.Length; $index++) {
            $difference = $difference -bor ($KeyBytes[$index] -bxor $roundTripBytes[$index])
        }
        if ($difference -ne 0) { throw 'DPAPI round-trip content mismatch' }
        return , $protectedBytes
    }
    finally {
        if ($null -ne $roundTripBytes) { [Array]::Clear($roundTripBytes, 0, $roundTripBytes.Length) }
        $roundTripBytes = $null
    }
}

function Write-OpenRouterReviewCredentialFile {
    param([Parameter(Mandatory = $true)][byte[]]$ProtectedBytes)
    $path = Get-OpenRouterReviewCredentialPath
    $directory = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $directory)) {
        $null = New-Item -ItemType Directory -Path $directory -Force
    }
    [IO.File]::WriteAllBytes($path, $ProtectedBytes)
    Set-OpenRouterReviewCredentialAcl -Path $path
}

function Invoke-OpenRouterReviewConfigure {
    $secure = $null
    try {
        $secure = Read-Host -AsSecureString 'Enter the dedicated OpenRouter API key for the review MCP credential store'
        if ($secure.Length -eq 0) { throw 'no key was entered' }
        Invoke-WithOpenRouterReviewSecureBytes -SecureString $secure -Action {
            param($KeyBytes)
            $protectedBytes = $null
            try {
                $protectedBytes = Protect-OpenRouterReviewCredential -KeyBytes $KeyBytes
                Write-OpenRouterReviewCredentialFile -ProtectedBytes $protectedBytes
            }
            finally {
                if ($null -ne $protectedBytes) { [Array]::Clear($protectedBytes, 0, $protectedBytes.Length) }
                $protectedBytes = $null
            }
        }
        return $true
    }
    catch {
        # Deliberately never surface $_.Exception.Message: nothing about the
        # key, its length, or the reason for failure is written anywhere.
        return $false
    }
    finally {
        if ($null -ne $secure) { $secure.Dispose() }
        $secure = $null
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    if (Invoke-OpenRouterReviewConfigure) {
        Write-Output 'SUCCESS'
        exit 0
    }
    else {
        Write-Output 'FAILURE'
        exit 1
    }
}
