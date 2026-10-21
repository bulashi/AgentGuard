[CmdletBinding()]
param([ValidateSet('Start', 'Configure')][string]$Operation = 'Start')

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$texts = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'agentguard-desktop.zh-CN.json')) | ConvertFrom-Json
. (Join-Path $PSScriptRoot 'native-agent-preferences.ps1')
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()

$mutex = New-Object Threading.Mutex($false, 'Local\AgentGuardDesktopLauncher')
$owned = $false
$process = $null
$form = $null
$result = 1
try {
    try { $owned = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $owned = $true }
    if (-not $owned) { exit 0 }
    $firstRun = -not (Test-Path -LiteralPath (Join-Path $root '.native\config.json') -PathType Leaf)
    if ($firstRun) {
        if (Test-Path -LiteralPath (Join-Path $root '.native\postgres\data') -PathType Container) {
            throw 'Existing database data was found without configuration; no initialization was attempted.'
        }
        $consent = [Windows.Forms.MessageBox]::Show($texts.first_run, $texts.title, 'YesNo', 'Question')
        if ($consent -ne [Windows.Forms.DialogResult]::Yes) { exit 0 }
    }
    $form = New-Object Windows.Forms.Form
    $form.Text = $texts.title
    $form.ClientSize = [Drawing.Size]::new(460, 155)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.ControlBox = $false
    $form.BackColor = [Drawing.Color]::White
    $form.Font = [Drawing.Font]::new('Microsoft YaHei UI', 9)
    $heading = New-Object Windows.Forms.Label
    $heading.Text = $texts.starting
    $heading.Location = [Drawing.Point]::new(24, 22)
    $heading.Size = [Drawing.Size]::new(412, 30)
    $heading.Font = [Drawing.Font]::new('Microsoft YaHei UI', 12, [Drawing.FontStyle]::Bold)
    $heading.ForeColor = [Drawing.Color]::FromArgb(43, 99, 174)
    $detail = New-Object Windows.Forms.Label
    $detail.Text = $texts.startup_detail
    $detail.Location = [Drawing.Point]::new(24, 62)
    $detail.Size = [Drawing.Size]::new(412, 26)
    $bar = New-Object Windows.Forms.ProgressBar
    $bar.Location = [Drawing.Point]::new(24, 108)
    $bar.Size = [Drawing.Size]::new(412, 8)
    $bar.Style = 'Marquee'
    $form.Controls.AddRange(@($heading, $detail, $bar))
    $form.Show()
    [Windows.Forms.Application]::DoEvents()

    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = Join-Path $PSHOME 'powershell.exe'
    $info.WorkingDirectory = $root
    $info.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $PSScriptRoot 'start-cloud-native.ps1') + '" -Mode Auto -NonInteractive -ReuseRunning -OpenBrowser'
    if ($Operation -eq 'Configure') { $info.Arguments += ' -OpenModelSettings' }
    if ($firstRun) { $info.Arguments += ' -Initialize' }
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.EnvironmentVariables.Remove('PSModulePath')
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    if (-not $process.Start()) { throw 'The managed launcher did not start.' }
    $process.StandardInput.Close()
    $outputTask = $process.StandardOutput.ReadToEndAsync()
    $errorTask = $process.StandardError.ReadToEndAsync()
    while (-not $process.WaitForExit(100)) { [Windows.Forms.Application]::DoEvents() }
    $output = $outputTask.GetAwaiter().GetResult()
    $errors = $errorTask.GetAwaiter().GetResult()
    $logDirectory = Join-Path $root '.native\logs'
    [IO.Directory]::CreateDirectory($logDirectory) | Out-Null
    [IO.File]::WriteAllText((Join-Path $logDirectory 'desktop-launcher.log'), $output + $errors, [Text.UTF8Encoding]::new($false))
    if ($process.ExitCode -ne 0) { throw 'The managed launcher reported a failure.' }
    $result = 0
}
catch {
    if ($null -ne $form) { $form.Hide() }
    $choice = [Windows.Forms.MessageBox]::Show($texts.failed, $texts.title, 'YesNo', 'Error')
    if ($choice -eq [Windows.Forms.DialogResult]::Yes) {
        $logs = Join-Path $root '.native\logs'
        if (Test-Path -LiteralPath $logs -PathType Container) { Start-Process explorer.exe -ArgumentList ('"' + $logs + '"') -WindowStyle Hidden }
    }
}
finally {
    if ($null -ne $process) { $process.Dispose() }
    if ($null -ne $form) { $form.Dispose() }
    if ($owned) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
exit $result
