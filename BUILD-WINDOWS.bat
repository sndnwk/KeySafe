@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title KeySafe v1.1.0 - Windows Build

cls
echo ================================================================
echo                      KeySafe v1.1.0
echo                 TEST AND RELEASE BUILD
echo ================================================================
echo.
where dotnet >nul 2>nul
if errorlevel 1 goto missingSdk

echo Restoring pinned dependencies in locked mode...
dotnet tool restore
if errorlevel 1 goto failed
dotnet restore "src\KeySafe\KeySafe.csproj" --locked-mode
if errorlevel 1 goto failed
dotnet restore "tests\KeySafe.Smoke\KeySafe.Smoke.csproj" --locked-mode
if errorlevel 1 goto failed
dotnet restore "tests\KeySafe.Resilience\KeySafe.Resilience.csproj" --locked-mode
if errorlevel 1 goto failed
dotnet restore "tests\KeySafe.Memory\KeySafe.Memory.csproj" --locked-mode
if errorlevel 1 goto failed
dotnet restore "tests\KeySafe.Clipboard\KeySafe.Clipboard.csproj" --locked-mode
if errorlevel 1 goto failed
dotnet restore "tests\KeySafe.Ui\KeySafe.Ui.csproj" --locked-mode
if errorlevel 1 goto failed

dotnet --list-sdks | findstr /R /C:"^10\." >nul
if errorlevel 1 goto missingSdk

echo Running encrypted-vault smoke tests...
dotnet run --project "tests\KeySafe.Smoke\KeySafe.Smoke.csproj" --configuration Release --no-restore
if errorlevel 1 goto failed

echo.
echo Running isolated abrupt-crash and SQLite resilience tests...
dotnet run --project "tests\KeySafe.Resilience\KeySafe.Resilience.csproj" --configuration Release --no-restore
if errorlevel 1 goto failed

echo.
echo Running synthetic full-memory exposure test...
dotnet run --project "tests\KeySafe.Memory\KeySafe.Memory.csproj" --configuration Release --no-restore
if errorlevel 1 goto failed

echo.
echo Running Windows secure clipboard tests...
dotnet run --project "tests\KeySafe.Clipboard\KeySafe.Clipboard.csproj" --configuration Release --no-restore
if errorlevel 1 goto failed

echo.
echo Running isolated WPF editor and theme tests...
dotnet run --project "tests\KeySafe.Ui\KeySafe.Ui.csproj" --configuration Release --no-restore
if errorlevel 1 goto failed

echo.
echo Publishing a self-contained Windows x64 folder release...
if not exist "dist" mkdir "dist"
dotnet publish "src\KeySafe\KeySafe.csproj" --configuration Release --runtime win-x64 --self-contained true -p:PublishSingleFile=false -p:PublishReadyToRun=false --output "dist\KeySafe"
if errorlevel 1 goto failed
if not exist "dist\KeySafe\KeySafe.exe" goto failed

echo.
echo Running a Windows GUI startup smoke check...
powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\TEST-GUI-STARTUP.ps1" -Executable "%CD%\dist\KeySafe\KeySafe.exe"
if errorlevel 1 goto failed

echo.
echo Generating CycloneDX software bill of materials...
if not exist "security-reports" mkdir "security-reports"
dotnet tool run dotnet-CycloneDX "src\KeySafe\KeySafe.csproj" --output "security-reports" --filename "KeySafe-v1.1.0.cdx.json" --json
if errorlevel 1 goto failed

echo.
echo ================================================================
echo BUILD SUCCEEDED
echo Executable: %CD%\dist\KeySafe\KeySafe.exe
echo ================================================================
exit /b 0

:missingSdk
echo.
echo ERROR: .NET SDK 10 is not installed or is not on PATH.
echo Download from https://dotnet.microsoft.com/download/dotnet/10.0
goto failed

:failed
echo.
echo ================================================================
echo BUILD OR TESTS FAILED - DO NOT TRUST THIS RELEASE WITH REAL DATA
echo ================================================================
exit /b 1
