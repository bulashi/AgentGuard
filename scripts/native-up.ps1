param([int]$UiPort = 0, [int]$PostgresPort = 15432, [switch]$WithLlm, [switch]$OpenBrowser)

$ErrorActionPreference = 'Stop'
if ($WithLlm) {
    throw 'Local models are retired. Use .\scripts\start-cloud-native.ps1 -Mode Cloud -OpenBrowser for DeepSeek.'
}
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$python = Join-Path $projectRoot '.runtime\python\python.exe'
if (-not (Test-Path -LiteralPath $python)) { $python = Join-Path $projectRoot '.venv\Scripts\python.exe' }
if (-not (Test-Path -LiteralPath $python) -or -not (Test-Path -LiteralPath 'frontend\dist\index.html')) {
    & (Join-Path $PSScriptRoot 'bootstrap.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'Native bootstrap failed.' }
    $python = Join-Path $projectRoot '.venv\Scripts\python.exe'
}
$arguments = @('-m', 'scripts.native_runtime', 'up', '--ui-port', "$UiPort", '--postgres-port', "$PostgresPort")
& $python @arguments
if ($LASTEXITCODE -ne 0) { throw 'native AgentGuard startup failed; see .native\logs\' }
if ($OpenBrowser) {
    $state = Get-Content -LiteralPath (Join-Path $projectRoot '.native\processes.json') -Raw -Encoding utf8 | ConvertFrom-Json
    Start-Process -FilePath "http://127.0.0.1:$($state.ui_port)"
}
