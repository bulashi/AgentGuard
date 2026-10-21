@echo off
setlocal
start "" "%SystemRoot%\System32\wscript.exe" "%~dp0scripts\agentguard-desktop.vbs" configure
exit /b 0
