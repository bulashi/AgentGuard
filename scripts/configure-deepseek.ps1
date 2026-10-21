[CmdletBinding()]
param([switch]$TestConnection, [switch]$UseSavedKey)

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
. (Join-Path $PSScriptRoot 'native-deepseek-credential.ps1')
$secureKey = $null
$plainKey = $null
$pointer = [IntPtr]::Zero
$process = $null
try {
    if ($UseSavedKey) {
        $secureKey = Read-NativeDeepSeekKey $projectRoot
        if ($null -eq $secureKey) { throw 'No saved DeepSeek credential exists.' }
    }
    else {
        $secureKey = Read-Host 'DeepSeek API key (hidden; saved with Windows user DPAPI)' -AsSecureString
        Save-NativeDeepSeekKey $projectRoot $secureKey
        Write-Host 'DEEPSEEK_CREDENTIAL_SAVED=WINDOWS_CURRENT_USER_DPAPI'
    }
    if ($TestConnection) {
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
        $plainKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = Join-Path $projectRoot '.venv\Scripts\python.exe'
        $info.WorkingDirectory = $projectRoot
        $info.Arguments = '-B -m scripts.verify_deepseek_cloud'
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardInput = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        foreach ($name in @($info.EnvironmentVariables.Keys)) {
            if ($name -like 'AGENTGUARD_*' -or $name -in @('DEEPSEEK_API_KEY', 'OPENAI_API_KEY')) {
                $info.EnvironmentVariables.Remove($name)
            }
        }
        $info.EnvironmentVariables['PYTHONDONTWRITEBYTECODE'] = '1'
        $process = New-Object Diagnostics.Process
        $process.StartInfo = $info
        if (-not $process.Start()) { throw 'The connection verifier did not start.' }
        $process.StandardInput.WriteLine($plainKey)
        $process.StandardInput.Close()
        $outputTask = $process.StandardOutput.ReadToEndAsync()
        $errorTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $output = $outputTask.GetAwaiter().GetResult()
        $errors = $errorTask.GetAwaiter().GetResult()
        $output = $output.Replace($plainKey, '[REDACTED]')
        $errors = $errors.Replace($plainKey, '[REDACTED]')
        if ($output) { Write-Host $output.TrimEnd() }
        if ($errors) { [Console]::Error.WriteLine($errors.TrimEnd()) }
        if ($process.ExitCode -ne 0) { throw 'DeepSeek verification failed. See the sanitized verification report.' }
    }
}
finally {
    $plainKey = $null
    if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    if ($null -ne $secureKey) { $secureKey.Dispose() }
    if ($null -ne $process) { $process.Dispose() }
}
