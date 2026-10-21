function Get-NativeAgentCloudEnabled([string]$ProjectRoot) {
    $path = Join-Path $ProjectRoot '.native\agent-preferences.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $true }
    $settings = [IO.File]::ReadAllText($path) | ConvertFrom-Json
    if ($settings.schema_version -ne '1.0' -or $settings.cloud_enabled -isnot [bool]) {
        throw 'The native agent preference file is invalid. Review the configuration before starting.'
    }
    return [bool]$settings.cloud_enabled
}

function Save-NativeAgentCloudEnabled([string]$ProjectRoot, [bool]$Enabled) {
    $directory = Join-Path $ProjectRoot '.native'
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    $document = @{ schema_version = '1.0'; cloud_enabled = $Enabled } | ConvertTo-Json
    [IO.File]::WriteAllText((Join-Path $directory 'agent-preferences.json'), $document, [Text.UTF8Encoding]::new($false))
}
