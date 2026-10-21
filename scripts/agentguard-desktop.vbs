Option Explicit
Dim shell, files, scriptPath, operation, command, result
Set shell = CreateObject("WScript.Shell")
Set files = CreateObject("Scripting.FileSystemObject")
scriptPath = files.BuildPath(files.GetParentFolderName(WScript.ScriptFullName), "agentguard-desktop.ps1")
operation = "Start"
If WScript.Arguments.Count > 0 Then
    If LCase(WScript.Arguments(0)) = "configure" Then operation = "Configure"
End If
command = "powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & scriptPath & """ -Operation " & operation
result = shell.Run(command, 0, True)
WScript.Quit result
