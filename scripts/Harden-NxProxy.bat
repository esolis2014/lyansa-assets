@echo off
setlocal

:: =============================================================================
:: Harden-NxProxy Launcher
:: Self-elevates to Administrator, bypasses execution policy, launches PS1.
:: =============================================================================

:: --- Check for Administrator privileges ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b
)

:: --- Resolve script directory (handles spaces in path) ---
set "SCRIPT_DIR=%~dp0"
set "PS1_FILE=%SCRIPT_DIR%Harden-NxProxy.ps1"

:: --- Verify PS1 exists ---
if not exist "%PS1_FILE%" (
    echo.
    echo ERROR: Harden-NxProxy.ps1 not found.
    echo Expected location: %PS1_FILE%
    echo Place this .bat file in the same folder as Harden-NxProxy.ps1
    echo.
    pause
    exit /b 1
)

:: --- Run with execution policy bypass ---
echo.
echo ============================================
echo  NxProxy DNS Hardening — Launcher
echo ============================================
echo.
echo Running: %PS1_FILE%
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1_FILE%"

echo.
echo ============================================
echo  Script finished. Review output above.
echo  Press any key to close.
echo ============================================
pause >nul
