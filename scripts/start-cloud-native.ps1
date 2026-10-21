[CmdletBinding()]
param(
    [ValidateSet('Choose', 'Deterministic', 'Cloud', 'Auto')]
    [string]$Mode = 'Cloud',
    [string]$Model = '',
    [ValidateRange(0, 65535)]
    [int]$UiPort = 0,
    [ValidateRange(0, 65535)]
    [int]$PostgresPort = 0,
    [switch]$OpenBrowser,
    [switch]$NonInteractive,
    [switch]$ReuseRunning,
    [switch]$OpenModelSettings,
    [switch]$Initialize
)

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$nativeRoot = Join-Path $projectRoot '.native'
$python = Join-Path $projectRoot '.runtime\python\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    $python = Join-Path $projectRoot '.venv\Scripts\python.exe'
}
$statePath = Join-Path $nativeRoot 'processes.json'
. (Join-Path $PSScriptRoot 'native-deepseek-credential.ps1')
. (Join-Path $PSScriptRoot 'native-agent-preferences.ps1')

function Read-NativeJson([string]$Path) {
    try {
        return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        throw "Cannot read native setup file: $Path. File contents are not displayed."
    }
}

function Throw-SetupError([string]$Reason) {
    $message = @(
        $Reason
        'This launcher requires an existing initialized native environment.'
        "Prepare it explicitly in $projectRoot :"
        '  .\scripts\bootstrap.ps1'
        '  .\scripts\native-up.ps1'
        '  .\scripts\native-down.ps1'
        'These setup commands may download dependencies and initialize data.'
        'Review the Windows native runtime documentation in docs before running them yourself.'
    )
    # Keep the executable script ASCII for Windows PowerShell 5.1.
    throw ($message -join [Environment]::NewLine)
}

function Get-PreparedPostgresPort {
    $required = @(
        'frontend\dist\index.html',
        '.native\config.json',
        '.native\seeded.json',
        '.native\postgres\data\PG_VERSION',
        '.native\postgres\data\global\pg_control'
    )
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        Throw-SetupError 'The project Python runtime is missing.'
    }
    $pythonRoot = if ($python -like '*\.runtime\python\python.exe') {
        Join-Path $projectRoot '.runtime\python'
    } else { Join-Path $projectRoot '.venv' }
    foreach ($package in @(
        'fastapi', 'gmssl', 'httpx', 'psutil', 'psycopg', 'pydantic',
        'pydantic_settings', 'uvicorn'
    )) {
        if (-not (Test-Path -LiteralPath (Join-Path $pythonRoot "Lib\site-packages\$package\__init__.py") -PathType Leaf)) {
            Throw-SetupError ("Missing Python dependency: " + $package)
        }
    }
    foreach ($name in @(
        'authorization', 'agent-coordinator', 'agent-knowledge', 'agent-case',
        'agent-refund', 'gateway', 'receipt', 'audit'
    )) {
        $required += ".native\keys\private\$name.private"
        $required += ".native\keys\public\$name.public"
    }
    $missing = @($required | Where-Object {
        -not (Test-Path -LiteralPath (Join-Path $projectRoot $_) -PathType Leaf)
    })
    if ($missing.Count) {
        Throw-SetupError ("Missing setup files: " + ($missing -join ', '))
    }
    $config = Read-NativeJson (Join-Path $nativeRoot 'config.json')
    foreach ($name in @(
        'admin_password', 'main_password', 'audit_password', 'ui_password', 'workflow_password'
    )) {
        if ([string]::IsNullOrWhiteSpace([string]$config.$name)) {
            Throw-SetupError 'Native database configuration is incomplete.'
        }
    }
    $port = 0
    if (-not [int]::TryParse([string]$config.postgres_port, [ref]$port) -or
        $port -lt 1 -or $port -gt 65535) {
        Throw-SetupError 'Native PostgreSQL port is invalid.'
    }
    $version = (Get-Content -LiteralPath (Join-Path $nativeRoot 'postgres\data\PG_VERSION') -Raw).Trim()
    if ($version -ne '16') {
        Throw-SetupError 'The existing native database is not PostgreSQL 16.'
    }
    $lock = Read-NativeJson (Join-Path $PSScriptRoot 'native-dependencies.lock.json')
    $spec = $lock.postgresql
    $directory = Join-Path (Join-Path $nativeRoot 'deps') $spec.directory
    $executable = Join-Path $directory $spec.executable
    $receiptPath = Join-Path $directory 'native-install.json'
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf) -or
        -not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) {
        Throw-SetupError 'The locked portable PostgreSQL installation is missing.'
    }
    $receipt = Read-NativeJson $receiptPath
    if (@($receipt.PSObject.Properties).Count -ne @($spec.PSObject.Properties).Count) {
        Throw-SetupError 'The PostgreSQL installation receipt does not match the dependency lock.'
    }
    foreach ($property in $spec.PSObject.Properties) {
        $actual = $receipt.PSObject.Properties[$property.Name]
        if ($null -eq $actual -or $actual.Value -cne $property.Value) {
            Throw-SetupError 'The PostgreSQL installation receipt does not match the dependency lock.'
        }
    }
    return $port
}

function Get-ManagedState {
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) { return $null }
    $state = Read-NativeJson $statePath
    if ($state.schema_version -ne 1 -or
        -not [string]::Equals([string]$state.project_root, $projectRoot,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Managed process state belongs to another project or has an unsupported format. Nothing was stopped.'
    }
    if ($null -eq $state.processes) {
        throw 'Managed process state is incomplete. Nothing was stopped.'
    }
    return $state
}

function Get-SavedModelProfile {
    $path = Join-Path $nativeRoot 'model-configurations.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    $document = Read-NativeJson $path
    if ($document.schema_version -ne 'model-profiles-v1') { throw 'Model configuration version is invalid.' }
    if (-not $document.default_id) { return $null }
    $property = $document.items.PSObject.Properties[[string]$document.default_id]
    if ($null -eq $property) { throw 'Default model configuration is missing.' }
    if ($property.Value.enabled -ne $true -or -not $property.Value.credential) { return $null }
    return @{ model = [string]$property.Value.model; base_url = [string]$property.Value.base_url }
}

function Open-AgentGuard([int]$Port) {
    $url = "http://127.0.0.1:$Port"
    if ($OpenModelSettings) { $url += '/?settings=models' }
    $path = Join-Path $nativeRoot 'operator-session.dpapi'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw 'Operator session is missing. Restart the current version through the maintenance entry.'
    }
    $bytes = $null
    $launchToken = $null
    try {
        Add-Type -AssemblyName System.Security
        $encrypted = [Convert]::FromBase64String([IO.File]::ReadAllText($path).Trim())
        $bytes = [Security.Cryptography.ProtectedData]::Unprotect(
            $encrypted, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        $launchToken = [Text.Encoding]::ASCII.GetString($bytes)
        if ($launchToken -cnotmatch '^[0-9a-f]{64}$') { throw 'Operator session is invalid.' }
        $url += '#launch_token=' + $launchToken
        Start-Process -FilePath $url
    }
    finally {
        if ($null -ne $bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
        $launchToken = $null
        $url = $null
    }
}

function Get-ApprovalRequirement($State) {
    $explicit = $env:AGENTGUARD_COAUTHORIZATION_REQUIRED
    if ($explicit -and $explicit.ToLowerInvariant() -notin @('true', 'false', '1', '0', 'yes', 'no', 'on', 'off')) {
        throw 'AGENTGUARD_COAUTHORIZATION_REQUIRED must be an explicit boolean. Nothing was stopped.'
    }
    $required = if ($explicit) {
        $explicit.ToLowerInvariant() -in @('true', '1', 'yes', 'on')
    } else { $State.coauthorization_required -eq $true }
    if ($State.coauthorization_required -eq $true -and $explicit -and -not $required) {
        throw 'Model switching must not disable the recorded joint-approval requirement. Nothing was stopped.'
    }
    $authority = @($State.processes | Where-Object { $_.name -eq 'authorization-authority' })
    if ($authority.Count -gt 1) { throw 'Managed authority state is ambiguous. Nothing was stopped.' }
    if ($authority.Count -eq 1 -and (Get-Process -Id ([int]$authority[0].pid) -ErrorAction SilentlyContinue)) {
        $response = $null
        $reader = $null
        try {
            $request = [Net.HttpWebRequest]::Create('http://127.0.0.1:18001/extensions/coauthorization/v1/status')
            $request.Proxy = $null
            $request.AllowAutoRedirect = $false
            $request.Timeout = 3000
            $request.ReadWriteTimeout = 3000
            $response = $request.GetResponse()
            $reader = [IO.StreamReader]::new($response.GetResponseStream())
            $status = $reader.ReadToEnd() | ConvertFrom-Json
            if ($status.schema_version -ne '1.0' -or $status.enabled -isnot [bool] -or
                $status.policy_source -ne 'SERVER_REGISTERED_PUBLIC_KEYS' -or
                $status.signing -ne 'EXTERNAL_APPROVERS_ONLY') {
                throw 'Invalid approval status.'
            }
            if ($status.enabled) {
                if ($explicit -and -not $required) {
                    throw 'Model switching must not disable existing joint approval.'
                }
                $required = $true
            }
        }
        catch {
            throw 'Cannot preserve the active approval requirement. Nothing was stopped; review joint-approval configuration before switching models.'
        }
        finally {
            if ($null -ne $reader) { $reader.Dispose() }
            if ($null -ne $response) { $response.Close() }
        }
    }
    return ([string][bool]$required).ToLowerInvariant()
}

function Invoke-NativeLifecycle(
    [ValidateSet('up', 'down', 'doctor')][string]$Operation,
    [hashtable]$Values = @{},
    [string]$CloudKey = ''
) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $python
    $info.WorkingDirectory = $projectRoot
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.Arguments = "-B -m scripts.native_runtime $Operation"
    if ($Operation -eq 'up') {
        if (-not $Initialize) { $info.Arguments += ' --prepared-only' }
        $info.Arguments += " --ui-port $UiPort --postgres-port $PostgresPort"
    }
    foreach ($name in @($info.EnvironmentVariables.Keys)) {
        if ($name -like 'AGENTGUARD_*' -or $name -in @('DEEPSEEK_API_KEY', 'OPENAI_API_KEY')) {
            $info.EnvironmentVariables.Remove($name)
        }
    }
    $info.EnvironmentVariables['PYTHONDONTWRITEBYTECODE'] = '1'
    foreach ($name in $Values.Keys) {
        $info.EnvironmentVariables[$name] = [string]$Values[$name]
    }
    if ($CloudKey) { $info.EnvironmentVariables['AGENTGUARD_NATIVE_CLOUD_KEY_STDIN'] = '1' }
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    $started = $false
    try {
        $started = $process.Start()
        if (-not $started) { throw 'Native lifecycle controller did not start.' }
        if ($CloudKey) {
            # The key is a single stdin line, never an argument or an environment value.
            $process.StandardInput.WriteLine($CloudKey)
        }
        $process.StandardInput.Close()
        $outputTask = $process.StandardOutput.ReadToEndAsync()
        $errorTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $output = $outputTask.GetAwaiter().GetResult()
        $errors = $errorTask.GetAwaiter().GetResult()
        if ($CloudKey) {
            $output = $output.Replace($CloudKey, '[REDACTED]')
            $errors = $errors.Replace($CloudKey, '[REDACTED]')
        }
        $logPath = Join-Path $nativeRoot "logs\lifecycle-$Operation.log"
        [IO.Directory]::CreateDirectory((Split-Path -Parent $logPath)) | Out-Null
        [IO.File]::AppendAllText($logPath, $output + $errors, [Text.UTF8Encoding]::new($false))
        if ($output) { Write-Host $output.TrimEnd() }
        if ($errors) { [Console]::Error.WriteLine($errors.TrimEnd()) }
        return $process.ExitCode
    }
    catch {
        throw "Native $Operation did not finish normally. Inspect .native\processes.json and .native\logs; cloud success is unverified."
    }
    finally {
        if ($started) {
            try { $process.StandardInput.Close() } catch { }
        }
        $CloudKey = $null
        $info.EnvironmentVariables.Clear()
        $process.Dispose()
    }
}

$secureKey = $null
$plainKey = $null
$keyPointer = [IntPtr]::Zero
$result = 0
try {
    Write-Host "AgentGuard model configuration: $projectRoot"
    $savedProfile = Get-SavedModelProfile
    if ($NonInteractive -and $Mode -eq 'Choose') {
        throw 'Noninteractive startup does not support the mode menu.'
    }
    if (($Mode -eq 'Auto' -or $ReuseRunning) -and -not $NonInteractive) {
        throw 'Automatic mode and runtime reuse require noninteractive startup.'
    }
    if (-not $NonInteractive) {
        Write-Host 'Restart requires explicit confirmation and stops this project''s recorded services.'
        Write-Host 'Managed PostgreSQL and recorded project services are included. Finish in-flight workflows first.'
    }
    if ($Mode -eq 'Choose') {
        Write-Host '[1] Deterministic rules'
        Write-Host '[2] DeepSeek V4.1-Flash cloud review (synthetic data leaves this PC; fees may apply)'
        Write-Host '[0] Cancel'
        switch (Read-Host 'Choose 1, 2 or 0') {
            '1' { $Mode = 'Deterministic' }
            '2' { $Mode = 'Cloud' }
            '0' { Write-Host 'Cancelled before restart.'; exit 0 }
            default { throw 'No valid mode was selected. Nothing was stopped.' }
        }
    }
    $cloudEnabled = ($null -ne $savedProfile) -or (Get-NativeAgentCloudEnabled $projectRoot)
    if (-not $cloudEnabled -and $Mode -eq 'Cloud') {
        throw 'Cloud agent review is disabled in the native agent preferences. Enable it in the configuration window first.'
    }
    if (-not $cloudEnabled -and $Mode -eq 'Auto') {
        $Mode = 'Deterministic'
        Write-Host 'NATIVE_LAUNCH_MODE=Deterministic cloud_enabled=False saved_credential_not_read=True'
    }
    if ($Initialize) {
        if (Test-Path -LiteralPath (Join-Path $nativeRoot 'config.json') -PathType Leaf) {
            throw 'First-run initialization is not permitted over an existing configuration.'
        }
        if (Test-Path -LiteralPath (Join-Path $nativeRoot 'postgres\data') -PathType Container) {
            throw 'Existing database data was found; initialization was not attempted.'
        }
        if (-not (Test-Path -LiteralPath $python -PathType Leaf) -or
            -not (Test-Path -LiteralPath (Join-Path $projectRoot 'frontend\dist\index.html') -PathType Leaf)) {
            throw 'The complete Windows release runtime and compiled frontend are required.'
        }
        $configuredPort = 15432
    } else { $configuredPort = Get-PreparedPostgresPort }
    if ($PostgresPort -eq 0) { $PostgresPort = $configuredPort }
    if ($PostgresPort -ne $configuredPort) {
        throw 'PostgresPort differs from the existing native configuration. No new database will be initialized.'
    }
    # Refuse older launchers before reading a key or stopping any service.
    $runtimeSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'native_runtime.py') -Raw -Encoding UTF8
    $preparedArgument = '(?m)^\s*parser\.add_argument\(\s*["'']--prepared-only["'']\s*[,)]'
    if (-not [regex]::IsMatch($runtimeSource, $preparedArgument)) {
        throw 'The native runtime has no --prepared-only startup. No services were stopped and no API key was read. See the DeepSeek cloud guide in docs.'
    }
    $state = Get-ManagedState
    if ($UiPort -eq 0 -and $null -ne $state) {
        $recordedPort = 0
        if (-not [int]::TryParse([string]$state.ui_port, [ref]$recordedPort) -or
            $recordedPort -lt 1 -or $recordedPort -gt 65535) {
            throw 'Managed state has an invalid UI port. Nothing was stopped.'
        }
        $UiPort = $recordedPort
    }
    $values = @{
        AGENTGUARD_CLOUD_LLM_ENABLED = 'false'
        AGENTGUARD_COAUTHORIZATION_REQUIRED = (Get-ApprovalRequirement $state)
    }
    $hasRunningProcess = $null -ne $state -and @($state.processes | Where-Object {
        Get-Process -Id ([int]$_.pid) -ErrorAction SilentlyContinue
    }).Count -gt 0
    if ($NonInteractive -and $hasRunningProcess) {
        if (-not $ReuseRunning) {
            throw 'Existing services were not stopped. Use the explicit maintenance restart entry.'
        }
        $recordedApproval = ([string][bool]$state.coauthorization_required).ToLowerInvariant()
        if ($values.AGENTGUARD_COAUTHORIZATION_REQUIRED -cne $recordedApproval) {
            throw 'Approval configuration changed. Existing services were not stopped; review it before restarting.'
        }
        if ($Mode -ne 'Auto' -and (($Mode -eq 'Cloud') -ne [bool]$state.cloud_configured)) {
            throw 'The requested mode differs from the running services. Existing services were not stopped.'
        }
        if (($UiPort -ne 0 -and $UiPort -ne [int]$state.ui_port) -or (Invoke-NativeLifecycle -Operation doctor) -ne 0) {
            throw 'The recorded runtime is not healthy. No services were restarted or stopped.'
        }
        Write-Host 'NATIVE_LAUNCH_RESULT=REUSED_HEALTHY_RUNTIME'
        Write-Host "NATIVE_UI=http://127.0.0.1:$UiPort"
        if ($OpenBrowser) { Open-AgentGuard $UiPort }
        exit 0
    }
    if ($Mode -eq 'Auto') {
        try { if ($cloudEnabled -and $null -eq $savedProfile) { $secureKey = Read-NativeDeepSeekKey $projectRoot } }
        catch {
            if ($_.Exception -isnot [InvalidOperationException]) { throw }
            $cause = $_.Exception.InnerException
            if ($null -eq $cause -or $cause -is [Management.Automation.CommandNotFoundException]) { throw }
            Write-Host 'NATIVE_CLOUD_CREDENTIAL=NOT_DECRYPTABLE_FOR_CURRENT_USER'
        }
        if ($null -ne $secureKey -or $null -ne $savedProfile) {
            $Mode = 'Cloud'
            Write-Host 'NATIVE_LAUNCH_MODE=Cloud'
        }
        else {
            $Mode = 'Deterministic'
            Write-Host ("NATIVE_LAUNCH_MODE=Deterministic cloud_enabled=" + $cloudEnabled + ' usable_saved_cloud_credential=False')
        }
    }
    if ($env:AGENTGUARD_COAUTHORIZATION_CHALLENGE_TTL_SECONDS) {
        $ttl = 0
        if (-not [int]::TryParse($env:AGENTGUARD_COAUTHORIZATION_CHALLENGE_TTL_SECONDS, [ref]$ttl) -or
            $ttl -lt 1 -or $ttl -gt 3600) {
            throw 'Approval challenge TTL must be between 1 and 3600 seconds. Nothing was stopped.'
        }
        $values['AGENTGUARD_COAUTHORIZATION_CHALLENGE_TTL_SECONDS'] = [string]$ttl
    }
    if ($Mode -eq 'Cloud') {
        if ($null -ne $savedProfile) {
            if ($Model -and $Model -cne $savedProfile.model) {
                throw 'Select a different default model in the web configuration before restart.'
            }
            $values['AGENTGUARD_CLOUD_LLM_ENABLED'] = 'true'
            Write-Host 'Using the enrolled cloud profile. The key is not read by this launcher.'
        }
        else {
        if ($env:AGENTGUARD_CLOUD_LLM_BASE_URL -and
            $env:AGENTGUARD_CLOUD_LLM_BASE_URL -cne 'https://api.deepseek.com') {
            throw 'This entry accepts only the official https://api.deepseek.com endpoint. Review the existing session endpoint configuration.'
        }
        if (-not $Model) { $Model = $env:AGENTGUARD_CLOUD_LLM_MODEL }
        if (-not $Model) { $Model = 'deepseek-flash' }
        if ($Model -cne 'deepseek-flash') {
            throw 'This project uses DeepSeek V4.1-Flash only: API model ID deepseek-flash. Other models and legacy aliases are not substituted.'
        }
        $values['AGENTGUARD_CLOUD_LLM_ENABLED'] = 'true'
        $values['AGENTGUARD_CLOUD_LLM_BASE_URL'] = 'https://api.deepseek.com'
        $values['AGENTGUARD_CLOUD_LLM_MODEL'] = $Model
        Write-Host "DeepSeek V4.1-Flash cloud review: $Model"
        Write-Host 'Cloud workflows send ticket/customer IDs, amounts, knowledge, prompts and tool results.'
        Write-Host 'Use synthetic data only. DeepSeek may charge for input and output tokens.'
        Write-Host 'This launcher sends no cloud requests. Each cloud workflow still needs UI confirmation.'
        }
    }
    elseif ($Model) {
        throw 'Model applies only to Cloud mode.'
    }
    Write-Host 'No local model runtime, model weights, WSL or Docker will be started.'
    if (-not $NonInteractive -and (Read-Host 'Type RESTART to allow this project restart, or press Enter to cancel') -cne 'RESTART') {
        Write-Host 'Cancelled before restart.'
        exit 0
    }
    if ($Mode -eq 'Cloud' -and $null -eq $savedProfile) {
        if ($null -eq $secureKey) { $secureKey = Read-NativeDeepSeekKey $projectRoot }
        if ($null -eq $secureKey) {
            if ($NonInteractive) {
                throw 'No saved cloud credential is available. Configure it with the desktop credential window.'
            }
            $secureKey = Read-Host 'DeepSeek API key (hidden; not saved)' -AsSecureString
        }
        else {
            Write-Host 'Using the saved Windows-user encrypted DeepSeek credential.'
        }
        if ($secureKey.Length -eq 0 -or $secureKey.Length -gt 1024) {
            throw 'The API key is empty or too long. Nothing was stopped.'
        }
        $keyPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
        $plainKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($keyPointer)
        if ($plainKey -match '[^\x21-\x7E]') {
            throw 'The API key contains whitespace or unsupported characters. Nothing was stopped.'
        }
    }
    Write-Host 'Stopping the recorded native runtime...'
    $stopResult = Invoke-NativeLifecycle -Operation down
    if ($stopResult -ne 0) { throw 'Native stop failed. Startup was not attempted.' }
    Write-Host 'Starting existing prepared Windows services...'
    $startResult = Invoke-NativeLifecycle -Operation up -Values $values -CloudKey $plainKey
    if ($startResult -ne 0) {
        throw 'Native startup failed. Existing services may be stopped; inspect .native\logs. No cloud call was verified.'
    }
    $startedState = Get-ManagedState
    $startedPort = 0
    if ($null -eq $startedState -or
        -not [int]::TryParse([string]$startedState.ui_port, [ref]$startedPort) -or
        $startedPort -lt 1 -or $startedPort -gt 65535) {
        throw 'Startup returned zero but no valid UI state was recorded. Runtime success is unverified.'
    }
    Write-Host "UI address: http://127.0.0.1:$startedPort"
    if ($OpenBrowser) { Open-AgentGuard $startedPort }
    Write-Host "Configured mode: $Mode. Select the corresponding mode in the business workspace."
    Write-Host 'No workflow was submitted. Runtime/model/usage evidence must come from your actual run.'
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    $result = 1
}
finally {
    $plainKey = $null
    if ($keyPointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($keyPointer)
    }
    if ($null -ne $secureKey) { $secureKey.Dispose() }
    # ProcessStartInfo supplied child environments; the caller's environment was never changed.
}
exit $result
