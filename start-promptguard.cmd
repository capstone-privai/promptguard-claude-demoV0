@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-promptguard.ps1" %*
exit /b %ERRORLEVEL%
