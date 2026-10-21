param([int]$UiPort = 0)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$python = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) { throw "Project virtual environment is missing: $python" }
$arguments = @('-m', 'scripts.native_runtime', 'doctor', '--ui-port', "$UiPort")
& $python @arguments
exit $LASTEXITCODE
