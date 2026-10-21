$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot

$python = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) {
    throw "Project virtual environment is missing: $python. Run scripts/bootstrap.ps1 first."
}
$npm = (Get-Command npm.cmd -ErrorAction Stop).Source

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][scriptblock]$Command
    )
    Write-Output "TEST_STEP_START=$Label"
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
    Write-Output "TEST_STEP_PASS=$Label"
}

Invoke-Checked -Label 'compileall' -Command { & $python -m compileall -q backend scripts }
Invoke-Checked -Label 'ruff' -Command { & $python -m ruff check backend scripts }
Invoke-Checked -Label 'backend-unit-and-matrix-contract' -Command {
    & $python -m pytest backend/tests/unit backend/tests/security/test_matrix_contract.py -q
}
Invoke-Checked -Label 'root-typecheck' -Command { & $npm run typecheck }
Invoke-Checked -Label 'canonical-protocol-vectors' -Command { & $npm run protocol:check }

Push-Location -LiteralPath (Join-Path $projectRoot 'frontend')
try {
    Invoke-Checked -Label 'frontend-lint' -Command { & $npm run lint -- --max-warnings=0 }
    Invoke-Checked -Label 'frontend-typecheck' -Command { & $npm run typecheck }
    Invoke-Checked -Label 'frontend-unit' -Command { & $npm run test }
    Invoke-Checked -Label 'frontend-production-build' -Command { & $npm run build }
}
finally {
    Pop-Location
}

Write-Output 'HOST_TEST_RESULT=PASS'
