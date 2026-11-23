@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title KeySafe v1.1.0 - Security Verification
cls
echo ================================================================
echo                  KeySafe v1.1.0
 echo               SECURITY AND VULNERABILITY TESTS
echo ================================================================
echo.
where powershell >nul 2>nul
if errorlevel 1 (
    echo ERROR: Windows PowerShell is required.
    exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\SECURITY-TEST-WINDOWS.ps1" -ProjectRoot "%CD%"
set "result=%errorlevel%"
echo.
if not "%result%"=="0" echo WARNING: One or more security checks failed or could not be completed. Review the report.
echo Security reports are in "%~dp0security-reports"
exit /b %result%
