$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$python = Join-Path $projectRoot '.runtime\python\python.exe'
if (-not (Test-Path -LiteralPath $python)) { $python = Join-Path $projectRoot '.venv\Scripts\python.exe' }
if (-not (Test-Path -LiteralPath $python)) { throw "Project Python runtime is missing: $python" }
& $python -m scripts.native_runtime down
if ($LASTEXITCODE -ne 0) { throw 'native AgentGuard stop failed; inspect .native\processes.json' }
