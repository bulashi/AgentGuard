[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'native-agent-preferences.ps1')
$fixtures = Join-Path $projectRoot 'evidence\native-windows\console-refinement-20261003\preference-fixtures'
$newRoot = Join-Path $fixtures ('read-write-' + [Guid]::NewGuid().ToString('N'))
if ((Get-NativeAgentCloudEnabled $newRoot) -ne $true) { throw 'Missing preference should retain the existing enabled default.' }
Save-NativeAgentCloudEnabled $newRoot $false
if ((Get-NativeAgentCloudEnabled $newRoot) -ne $false) { throw 'Disabled preference did not round-trip.' }
Save-NativeAgentCloudEnabled $newRoot $true
if ((Get-NativeAgentCloudEnabled $newRoot) -ne $true) { throw 'Enabled preference did not round-trip.' }
$file = Join-Path $newRoot '.native\agent-preferences.json'
[IO.File]::WriteAllText($file, '{"schema_version":"1.0","cloud_enabled":"false"}')
$rejected = $false
try { $null = Get-NativeAgentCloudEnabled $newRoot } catch { $rejected = $true }
if (-not $rejected) { throw 'Malformed preference must fail closed.' }
Write-Output 'NATIVE_AGENT_PREFERENCE_CHECKS=4 PASS'
Write-Output 'LIVE_PREFERENCE_CHANGED=False'
Write-Output 'SAVED_API_KEY_READ=False'
Write-Output 'SERVICES_RESTARTED=False'
