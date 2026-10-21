@echo off
setlocal
start "" "%SystemRoot%\System32\wscript.exe" "%~dp0scripts\agentguard-desktop.vbs" start
exit /b 0
