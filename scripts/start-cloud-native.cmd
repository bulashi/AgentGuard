@echo off
setlocal
pushd "%~dp0.."
if errorlevel 1 exit /b 1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-cloud-native.ps1" -Mode Cloud -OpenBrowser
set "result=%errorlevel%"
echo.
pause
popd
exit /b %result%
