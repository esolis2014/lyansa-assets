@echo off
setlocal

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b
)

set "SCRIPT_DIR=%~dp0"
set "PS1_FILE=%SCRIPT_DIR%Harden-NxProxy.ps1"

if not exist "%PS1_FILE%" (
    echo.
    echo ERROR: Harden-NxProxy.ps1 not found.
    echo Expected: %PS1_FILE%
    echo Place both files in the same folder.
    echo.
    pause
    exit /b 1
)

echo.
echo ============================================
echo  NxProxy DNS Hardening - Launcher
echo ============================================
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1_FILE%"

echo.
echo Press any key to close.
pause >nul
