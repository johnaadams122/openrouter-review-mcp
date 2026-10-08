Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Security

$script:MaxControlBytes = 4096
$script:MaxFrameBytes = 1048576
$script:MaxChunkBytes = 524288
$script:PurposeLimits = @{
    'identity-key' = 32
    'binding-credential' = 4096
    'installation-config' = 1048576
    'preflight-context' = 64MB
    'scrub-mapping' = 64MB
    'prepared-envelope' = 131072
    'dispatch-request' = 4194304
    'dispatch-outcome' = 32MB
    'advisory-result' = 128MB
    'terminal-result' = 128MB
    'public-transfer' = 128MB
}

function Read-ExactBytes {
    param([IO.Stream]$Stream, [int]$Count, [switch]$AllowEof)
    $buffer = New-Object byte[] $Count
    $offset = 0
    $transferred = $false
    try {
        while ($offset -lt $Count) {
            $read = $Stream.Read($buffer, $offset, $Count - $offset)
            if ($read -eq 0) {
                if ($AllowEof -and $offset -eq 0) { return $null }
                throw 'INVALID_FRAME'
            }
            $offset += $read
        }
        $transferred = $true
        return $buffer
    }
    finally {
        if (-not $transferred -and $null -ne $buffer) { [Array]::Clear($buffer, 0, $buffer.Length) }
    }
}

function Read-Frame {
    param([int]$MaximumBytes = $script:MaxFrameBytes, [switch]$AllowEof)
    $stream = [Console]::OpenStandardInput()
    $prefix = $null
    $payload = $null
    try {
        $prefix = Read-ExactBytes -Stream $stream -Count 4 -AllowEof:$AllowEof
        if ($null -eq $prefix) { return $null }
        $length = [BitConverter]::ToUInt32($prefix, 0)
        if ($length -gt $MaximumBytes) { throw 'INVALID_FRAME' }
        $payload = Read-ExactBytes -Stream $stream -Count ([int]$length)
        $utf8 = New-Object Text.UTF8Encoding($false, $true)
        try { $json = $utf8.GetString($payload) } catch { throw 'INVALID_FRAME' }
        try { return ($json | ConvertFrom-Json) } catch { throw 'INVALID_FRAME' }
    }
    finally {
        if ($null -ne $prefix) { [Array]::Clear($prefix, 0, $prefix.Length) }
        if ($null -ne $payload) { [Array]::Clear($payload, 0, $payload.Length) }
    }
}

function Write-Frame {
    param([Parameter(Mandatory = $true)]$Value)
    $json = $Value | ConvertTo-Json -Compress -Depth 12
    $payload = $null
    $prefix = $null
    try {
        $payload = [Text.Encoding]::UTF8.GetBytes($json)
        if ($payload.Length -gt $script:MaxFrameBytes) { throw 'INVALID_FRAME' }
        $prefix = [BitConverter]::GetBytes([uint32]$payload.Length)
        $stream = [Console]::OpenStandardOutput()
        $stream.Write($prefix, 0, $prefix.Length)
        $stream.Write($payload, 0, $payload.Length)
        $stream.Flush()
    }
    finally {
        if ($null -ne $prefix) { [Array]::Clear($prefix, 0, $prefix.Length) }
        if ($null -ne $payload) { [Array]::Clear($payload, 0, $payload.Length) }
    }
}

function Assert-Shape {
    param($Value, [string[]]$Required)
    if ($null -eq $Value -or $Value -is [Array]) { throw 'INVALID_FRAME' }
    $names = @($Value.PSObject.Properties.Name)
    if ($names.Count -ne $Required.Count) { throw 'INVALID_FRAME' }
    foreach ($name in $Required) { if ($names -notcontains $name) { throw 'INVALID_FRAME' } }
}

function Get-Sha256Hex {
    param([byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    $digestBytes = $null
    try {
        $digestBytes = $sha.ComputeHash($Bytes)
        return (($digestBytes | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        if ($null -ne $digestBytes) { [Array]::Clear($digestBytes, 0, $digestBytes.Length) }
        $sha.Dispose()
    }
}

function Get-Entropy {
    param([string]$Purpose, [string]$ObjectId)
    $sha = [Security.Cryptography.SHA256]::Create()
    $inputBytes = $null
    try {
        $inputBytes = [Text.Encoding]::UTF8.GetBytes("shared-protected-dpapi-v1`0$Purpose`0$ObjectId")
        return $sha.ComputeHash($inputBytes)
    }
    finally {
        if ($null -ne $inputBytes) { [Array]::Clear($inputBytes, 0, $inputBytes.Length) }
        $sha.Dispose()
    }
}

function Assert-PurposeLength {
    param([string]$Purpose, [long]$Length)
    if (-not $script:PurposeLimits.ContainsKey($Purpose)) { throw 'INVALID_FRAME' }
    $maximum = [long]$script:PurposeLimits[$Purpose]
    if ($Purpose -eq 'identity-key') {
        if ($Length -ne 32) { throw 'CONTENT_TOO_LARGE' }
    }
    elseif ($Length -lt 0 -or $Length -gt $maximum) { throw 'CONTENT_TOO_LARGE' }
}

function Assert-RelativePath {
    param([string]$RelativePath)
    if ([string]::IsNullOrWhiteSpace($RelativePath) -or [IO.Path]::IsPathRooted($RelativePath)) { throw 'ACL_INVALID' }
    $parts = $RelativePath -split '[\\/]'
    if ($parts.Count -eq 0 -or @($parts | Where-Object { $_ -eq '' -or $_ -eq '.' -or $_ -eq '..' }).Count -gt 0) { throw 'ACL_INVALID' }
}

function Set-ProtectedDirectoryAcl {
    param([string]$Path)
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $ownerAccount = $sid.Translate([Security.Principal.NTAccount])
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($ownerAccount)
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $inherit, 'None', 'Allow')
    [void]$acl.AddAccessRule($rule)
    [IO.Directory]::SetAccessControl($Path, $acl)
    $item = Get-Item -LiteralPath $Path -Force
    $item.Attributes = $item.Attributes -bor [IO.FileAttributes]::NotContentIndexed
}

function Set-ProtectedFileAcl {
    param([string]$Path)
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $ownerAccount = $sid.Translate([Security.Principal.NTAccount])
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetOwner($ownerAccount)
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')
    [void]$acl.AddAccessRule($rule)
    [IO.File]::SetAccessControl($Path, $acl)
}

function Assert-NoReparsePoint {
    param([string]$Path)
    $current = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Path))
    $relative = [IO.Path]::GetFullPath($Path).Substring($current.Length)
    foreach ($part in ($relative -split '[\\/]' | Where-Object { $_ -ne '' })) {
        $current = Join-Path $current $part
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'ACL_INVALID' }
        }
    }
}

function Assert-ProtectedAcl {
    param([string]$Path, [bool]$Directory)
    Assert-NoReparsePoint -Path $Path
    if (-not (Test-Path -LiteralPath $Path)) { throw 'ACL_INVALID' }
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($Directory) { $acl = [IO.Directory]::GetAccessControl($Path) }
    else { $acl = [IO.File]::GetAccessControl($Path) }
    try { $owner = ([Security.Principal.NTAccount]$acl.Owner).Translate([Security.Principal.SecurityIdentifier]) }
    catch { $owner = New-Object Security.Principal.SecurityIdentifier($acl.Owner) }
    if ($owner.Value -ne $sid.Value -or -not $acl.AreAccessRulesProtected) { throw 'ACL_INVALID' }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -lt 1) { throw 'ACL_INVALID' }
    foreach ($rule in $rules) {
        if ($rule.IdentityReference.Value -ne $sid.Value -or $rule.IsInherited -or $rule.AccessControlType -ne 'Allow') { throw 'ACL_INVALID' }
    }
    if ($Directory) {
        $item = Get-Item -LiteralPath $Path -Force
        if (($item.Attributes -band [IO.FileAttributes]::NotContentIndexed) -eq 0) { throw 'ACL_INVALID' }
    }
}

function Get-RootMap {
    param($Roots)
    Assert-Shape -Value $Roots -Required @('managedRoot','objects','config','credentials','builds')
    try {
        $managedRoot = [IO.Path]::GetFullPath([string]$Roots.managedRoot).TrimEnd('\','/')
        $canonicalDataRoot = [IO.Directory]::GetParent($managedRoot).FullName.TrimEnd('\','/')
        $expectedManaged = [IO.Path]::GetFullPath((Join-Path $canonicalDataRoot 'managed-shared-v1')).TrimEnd('\','/')
        $map = @{
            managedRoot = $expectedManaged
            objects = [IO.Path]::GetFullPath((Join-Path $expectedManaged 'objects')).TrimEnd('\','/')
            config = [IO.Path]::GetFullPath((Join-Path $expectedManaged 'config')).TrimEnd('\','/')
            credentials = [IO.Path]::GetFullPath((Join-Path $expectedManaged 'credentials')).TrimEnd('\','/')
            builds = [IO.Path]::GetFullPath((Join-Path $expectedManaged 'builds')).TrimEnd('\','/')
        }
        foreach ($key in @('managedRoot','objects','config','credentials','builds')) {
            $provided = [IO.Path]::GetFullPath([string]$Roots.$key).TrimEnd('\','/')
            if (-not [string]::Equals($provided, $map[$key], [StringComparison]::OrdinalIgnoreCase)) { throw 'ACL_INVALID' }
        }
        return $map
    }
    catch { throw 'ACL_INVALID' }
}

function Initialize-Roots {
    param($Roots)
    $map = Get-RootMap -Roots $Roots
    if (Test-Path -LiteralPath $map.managedRoot) {
        foreach ($path in @($map.managedRoot, $map.objects, $map.config, $map.credentials, $map.builds)) {
            Assert-ProtectedAcl -Path $path -Directory $true
        }
        return
    }
    foreach ($path in @($map.managedRoot, $map.objects, $map.config, $map.credentials, $map.builds)) {
        Assert-NoReparsePoint -Path (Split-Path -Parent $path)
        [void][IO.Directory]::CreateDirectory($path)
        Set-ProtectedDirectoryAcl -Path $path
        Assert-ProtectedAcl -Path $path -Directory $true
    }
}

function Verify-Roots {
    param($Roots)
    $map = Get-RootMap -Roots $Roots
    foreach ($path in @($map.managedRoot, $map.objects, $map.config, $map.credentials, $map.builds)) {
        Assert-ProtectedAcl -Path $path -Directory $true
    }
}

function Prepare-EmptyFile {
    param($Roots, [string]$Area, [string]$RelativePath)
    $map = Get-RootMap -Roots $Roots
    if (@('objects','config','credentials','builds') -notcontains $Area) { throw 'ACL_INVALID' }
    Assert-RelativePath -RelativePath $RelativePath
    Verify-Roots -Roots $Roots
    $full = Join-Path $map[$Area] $RelativePath
    $parent = Split-Path -Parent $full
    if (-not (Test-Path -LiteralPath $parent)) {
        [void][IO.Directory]::CreateDirectory($parent)
        Set-ProtectedDirectoryAcl -Path $parent
    }
    Assert-NoReparsePoint -Path $parent
    $stream = $null
    try {
        $stream = New-Object IO.FileStream($full, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $stream.Flush($true)
    }
    finally { if ($null -ne $stream) { $stream.Dispose() } }
    Set-ProtectedFileAcl -Path $full
    Assert-ProtectedAcl -Path $full -Directory $false
}

function ConvertTo-ProtectedBytes {
    param([string]$Purpose, [string]$ObjectId, [byte[]]$Content)
    Assert-PurposeLength -Purpose $Purpose -Length $Content.LongLength
    $inner = [ordered]@{
        version = 1
        purpose = $Purpose
        objectId = $ObjectId
        contentSha256 = Get-Sha256Hex -Bytes $Content
        contentBase64 = [Convert]::ToBase64String($Content)
    }
    $innerBytes = $null
    $entropy = $null
    try {
        $innerBytes = [Text.Encoding]::UTF8.GetBytes(($inner | ConvertTo-Json -Compress -Depth 4))
        $entropy = Get-Entropy -Purpose $Purpose -ObjectId $ObjectId
        return [Security.Cryptography.ProtectedData]::Protect($innerBytes, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    }
    finally {
        if ($null -ne $innerBytes) { [Array]::Clear($innerBytes, 0, $innerBytes.Length) }
        if ($null -ne $entropy) { [Array]::Clear($entropy, 0, $entropy.Length) }
    }
}

function ConvertFrom-ProtectedBytes {
    param([string]$Purpose, [string]$ObjectId, [byte[]]$Ciphertext)
    $entropy = Get-Entropy -Purpose $Purpose -ObjectId $ObjectId
    $innerBytes = $null
    $content = $null
    $transferred = $false
    try {
        $innerBytes = [Security.Cryptography.ProtectedData]::Unprotect($Ciphertext, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        $utf8 = New-Object Text.UTF8Encoding($false, $true)
        $inner = ($utf8.GetString($innerBytes) | ConvertFrom-Json)
        Assert-Shape -Value $inner -Required @('version','purpose','objectId','contentSha256','contentBase64')
        if ($inner.version -ne 1 -or $inner.purpose -cne $Purpose -or $inner.objectId -cne $ObjectId) { throw 'INTEGRITY_FAILED' }
        try { $content = [Convert]::FromBase64String([string]$inner.contentBase64) } catch { throw 'INTEGRITY_FAILED' }
        Assert-PurposeLength -Purpose $Purpose -Length $content.LongLength
        if ((Get-Sha256Hex -Bytes $content) -cne [string]$inner.contentSha256) { throw 'INTEGRITY_FAILED' }
        $transferred = $true
        return $content
    }
    finally {
        if (-not $transferred -and $null -ne $content) { [Array]::Clear($content, 0, $content.Length) }
        if ($null -ne $innerBytes) { [Array]::Clear($innerBytes, 0, $innerBytes.Length) }
        [Array]::Clear($entropy, 0, $entropy.Length)
    }
}

function Read-ContentFrames {
    param($Start)
    Write-Frame ([ordered]@{ type='ACK'; sequence=-1 })
    $memory = New-Object IO.MemoryStream
    $sequence = 0
    $result = $null
    $transferred = $false
    try {
        while ($true) {
            $frame = Read-Frame
            $type = [string]$frame.type
            if ($type -eq 'CHUNK') {
                Assert-Shape -Value $frame -Required @('type','sequence','dataBase64')
                if ([int]$frame.sequence -ne $sequence) { throw 'INVALID_FRAME' }
                $bytes = $null
                try {
                    try { $bytes = [Convert]::FromBase64String([string]$frame.dataBase64) } catch { throw 'INVALID_FRAME' }
                    if ($bytes.Length -gt $script:MaxChunkBytes -or ($memory.Length + $bytes.Length) -gt [long]$Start.declaredBytes) { throw 'INVALID_FRAME' }
                    $memory.Write($bytes, 0, $bytes.Length)
                }
                finally { if ($null -ne $bytes) { [Array]::Clear($bytes, 0, $bytes.Length) } }
                Write-Frame ([ordered]@{ type='ACK'; sequence=$sequence })
                $sequence += 1
                continue
            }
            if ($type -ne 'FINAL') { throw 'INVALID_FRAME' }
            Assert-Shape -Value $frame -Required @('type','declaredBytes','sha256')
            if ([long]$frame.declaredBytes -ne [long]$Start.declaredBytes -or [string]$frame.sha256 -cne [string]$Start.sha256) { throw 'INVALID_FRAME' }
            $result = $memory.ToArray()
            if ($result.LongLength -ne [long]$Start.declaredBytes -or (Get-Sha256Hex -Bytes $result) -cne [string]$Start.sha256) { throw 'INVALID_FRAME' }
            $transferred = $true
            return $result
        }
    }
    finally {
        if (-not $transferred -and $null -ne $result) { [Array]::Clear($result, 0, $result.Length) }
        $memoryBuffer = $null
        try { $memoryBuffer = $memory.GetBuffer() } catch { }
        if ($null -ne $memoryBuffer) { [Array]::Clear($memoryBuffer, 0, $memoryBuffer.Length) }
        $memory.Dispose()
    }
}

function Write-ContentFrames {
    param([byte[]]$Bytes)
    $digest = Get-Sha256Hex -Bytes $Bytes
    Write-Frame ([ordered]@{ type='RESULT_START'; status='OK'; declaredBytes=$Bytes.LongLength; sha256=$digest })
    $sequence = 0
    for ($offset = 0; $offset -lt $Bytes.Length; $offset += $script:MaxChunkBytes) {
        $count = [Math]::Min($script:MaxChunkBytes, $Bytes.Length - $offset)
        $chunk = New-Object byte[] $count
        try {
            [Array]::Copy($Bytes, $offset, $chunk, 0, $count)
            Write-Frame ([ordered]@{ type='CHUNK'; sequence=$sequence; dataBase64=[Convert]::ToBase64String($chunk) })
            $ack = Read-Frame -MaximumBytes $script:MaxControlBytes
            Assert-Shape -Value $ack -Required @('type','sequence')
            if ([string]$ack.type -cne 'ACK' -or [int]$ack.sequence -ne $sequence) { throw 'INVALID_FRAME' }
        }
        finally { [Array]::Clear($chunk, 0, $chunk.Length) }
        $sequence += 1
    }
    Write-Frame ([ordered]@{ type='COMPLETE'; status='OK'; declaredBytes=$Bytes.LongLength; sha256=$digest })
}

function Complete-Failure {
    param([string]$Status)
    if (@('INVALID_FRAME','CONTENT_TOO_LARGE','DPAPI_FAILED','ACL_INVALID','INTEGRITY_FAILED') -notcontains $Status) { $Status = 'INVALID_FRAME' }
    try { Write-Frame ([ordered]@{ type='COMPLETE'; status=$Status }) } catch { }
    [Console]::Error.WriteLine($Status)
    exit 1
}

if ($MyInvocation.InvocationName -ne '.') {
try {
    $start = Read-Frame -MaximumBytes $script:MaxControlBytes
    $operation = [string]$start.operation
    if (@('ROOT_INITIALIZE','ROOT_VERIFY') -contains $operation) {
        Assert-Shape -Value $start -Required @('type','version','operation','installationRoots')
        if ($start.type -cne 'START' -or $start.version -ne 1) { throw 'INVALID_FRAME' }
        if ($operation -eq 'ROOT_INITIALIZE') { Initialize-Roots -Roots $start.installationRoots }
        else { Verify-Roots -Roots $start.installationRoots }
        Write-Frame ([ordered]@{ type='COMPLETE'; status='OK' })
        exit 0
    }
    if (@('FILE_PREPARE','FILE_VERIFY') -contains $operation) {
        Assert-Shape -Value $start -Required @('type','version','operation','installationRoots','area','relativePath')
        if ($start.type -cne 'START' -or $start.version -ne 1) { throw 'INVALID_FRAME' }
        if ($operation -eq 'FILE_PREPARE') { Prepare-EmptyFile -Roots $start.installationRoots -Area ([string]$start.area) -RelativePath ([string]$start.relativePath) }
        else {
            $map = Get-RootMap -Roots $start.installationRoots
            Assert-RelativePath -RelativePath ([string]$start.relativePath)
            Assert-ProtectedAcl -Path (Join-Path $map[[string]$start.area] ([string]$start.relativePath)) -Directory $false
        }
        Write-Frame ([ordered]@{ type='COMPLETE'; status='OK' })
        exit 0
    }
    if (@('PROTECT','UNPROTECT') -notcontains $operation) { throw 'INVALID_FRAME' }
    Assert-Shape -Value $start -Required @('type','version','operation','purpose','objectId','declaredBytes','sha256')
    if ($start.type -cne 'START' -or $start.version -ne 1 -or [long]$start.declaredBytes -lt 0 -or [string]$start.sha256 -notmatch '^[a-f0-9]{64}$') { throw 'INVALID_FRAME' }
    if ($operation -eq 'PROTECT') { Assert-PurposeLength -Purpose ([string]$start.purpose) -Length ([long]$start.declaredBytes) }
    else {
        $plainMaximum = [long]$script:PurposeLimits[[string]$start.purpose]
        if ([long]$start.declaredBytes -gt (2 * $plainMaximum + 131072)) { throw 'CONTENT_TOO_LARGE' }
    }
    $inputBytes = $null
    $outputBytes = $null
    try {
        $inputBytes = Read-ContentFrames -Start $start
        try {
            if ($operation -eq 'PROTECT') { $outputBytes = ConvertTo-ProtectedBytes -Purpose ([string]$start.purpose) -ObjectId ([string]$start.objectId) -Content $inputBytes }
            else { $outputBytes = ConvertFrom-ProtectedBytes -Purpose ([string]$start.purpose) -ObjectId ([string]$start.objectId) -Ciphertext $inputBytes }
        }
        catch {
            if ($_.Exception.Message -eq 'CONTENT_TOO_LARGE') { throw }
            if ($_.Exception.Message -eq 'INTEGRITY_FAILED') { throw }
            throw 'DPAPI_FAILED'
        }
        Write-ContentFrames -Bytes $outputBytes
        exit 0
    }
    finally {
        if ($null -ne $inputBytes) { [Array]::Clear($inputBytes, 0, $inputBytes.Length) }
        if ($null -ne $outputBytes) { [Array]::Clear($outputBytes, 0, $outputBytes.Length) }
    }
}
catch {
    Complete-Failure -Status ([string]$_.Exception.Message)
}
}
