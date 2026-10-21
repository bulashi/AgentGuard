$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot

$pythonPath = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) {
    $candidate = Join-Path $env:APPDATA 'uv\python\cpython-3.12.14-windows-x86_64-none\python.exe'
    if (Test-Path -LiteralPath $candidate) {
        & $candidate -m venv .venv
    }
    else {
        $py = Get-Command py.exe -ErrorAction SilentlyContinue
        if ($null -eq $py) {
            throw 'Python 3.12 is required. Neither the managed runtime nor py.exe was found.'
        }
        & $py.Source -3.12 -m venv .venv
    }
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $pythonPath)) {
        throw 'Failed to create the Python 3.12 virtual environment.'
    }
}

$pythonVersion = (& $pythonPath -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')").Trim()
if ($LASTEXITCODE -ne 0 -or $pythonVersion -notmatch '^3\.12\.') {
    throw "AgentGuard requires Python 3.12.x; project environment reports $pythonVersion"
}

& $pythonPath -m pip install --cache-dir .native/pip-cache --requirement requirements.lock
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$npm = (Get-Command npm.cmd -ErrorAction Stop).Source
& $npm ci --cache .native/npm-cache
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Push-Location -LiteralPath (Join-Path $projectRoot 'frontend')
try {
    & $npm ci --cache ../.native/npm-cache
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & $npm run build
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    Pop-Location
}

Write-Output "PYTHON_VERSION=$pythonVersion"
Write-Output "NODE_VERSION=$(& node.exe --version)"
Write-Output "NPM_VERSION=$(& $npm --version)"
Write-Output 'BOOTSTRAP_RESULT=PASS'
