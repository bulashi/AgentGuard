@echo off
setlocal
pushd "%~dp0"
if errorlevel 1 exit /b 1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "scripts\native-down.ps1"
set "result=%errorlevel%"
if not "%result%"=="0" pause
popd
exit /b %result%
