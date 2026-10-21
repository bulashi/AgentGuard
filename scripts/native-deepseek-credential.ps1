# Resolve built-in security cmdlets from this PowerShell version, not inherited Core modules.
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop

function Get-NativeDeepSeekKeyPath([string]$ProjectRoot) {
    return Join-Path $ProjectRoot '.native\secrets\deepseek-api-key.dpapi'
}

function Assert-NativeCredentialPath([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -ne $item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'The native credential path must not be a link or junction.'
    }
}

function Read-NativeDeepSeekKey([string]$ProjectRoot) {
    $path = Get-NativeDeepSeekKeyPath $ProjectRoot
    Assert-NativeCredentialPath (Join-Path $ProjectRoot '.native')
    Assert-NativeCredentialPath (Split-Path -Parent $path)
    Assert-NativeCredentialPath $path
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    $encrypted = [IO.File]::ReadAllText($path).Trim()
    try {
        return ConvertTo-SecureString -String $encrypted -ErrorAction Stop
    }
    catch {
        throw [InvalidOperationException]::new(
            'The saved DeepSeek credential cannot be decrypted by this Windows user. Configure it again on this computer.',
            $_.Exception
        )
    }
}

function Save-NativeDeepSeekKey([string]$ProjectRoot, [Security.SecureString]$Key) {
    if ($null -eq $Key -or $Key.Length -eq 0 -or $Key.Length -gt 1024) {
        throw 'The DeepSeek API key is empty or too long.'
    }
    $path = Get-NativeDeepSeekKeyPath $ProjectRoot
    $directory = Split-Path -Parent $path
    Assert-NativeCredentialPath (Join-Path $ProjectRoot '.native')
    Assert-NativeCredentialPath $directory
    Assert-NativeCredentialPath $path
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule(
        $sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'
    )
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $directory -AclObject $acl
    $encrypted = ConvertFrom-SecureString -SecureString $Key -ErrorAction Stop
    [IO.File]::WriteAllText($path, $encrypted, [Text.UTF8Encoding]::new($false))
    $fileAcl = New-Object Security.AccessControl.FileSecurity
    $fileAcl.SetOwner($sid)
    $fileAcl.SetAccessRuleProtection($true, $false)
    $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'Allow'))
    Set-Acl -LiteralPath $path -AclObject $fileAcl
}
