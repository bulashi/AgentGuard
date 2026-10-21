$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
& (Join-Path $projectRoot '.venv\Scripts\python.exe') -m scripts.verify_native
if ($LASTEXITCODE -ne 0) { throw 'Native verification failed; inspect evidence/native-windows/' }
