@echo off
REM pcap-analyzer installer (Windows)
REM Usage: install.bat
REM NOTE: keep this file ASCII-only. cmd.exe misparses batch lines that
REM       contain multibyte (Korean) characters, eating parts of lines.
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

REM cd to script location
cd /d "%~dp0"

set "VERSION=unknown"
if exist VERSION set /p VERSION=<VERSION
echo === pcap-analyzer %VERSION% install ===

REM [1/5] system dependencies
echo [1/5] Checking system dependencies
where python >nul 2>&1
if errorlevel 1 (
    echo   ERROR: python is required.
    echo     Install: https://www.python.org/downloads/  ^(3.10+, check "Add python.exe to PATH"^)
    exit /b 1
)
REM Reject the Microsoft Store alias: it is found on PATH but exits non-zero.
python --version >nul 2>&1
if errorlevel 1 (
    echo   ERROR: 'python' on PATH is the Microsoft Store alias, not a real installation.
    echo     Fix 1: install from https://www.python.org/downloads/ with "Add python.exe to PATH" checked.
    echo     Fix 2: Settings ^> Apps ^> Advanced app settings ^> App execution aliases
    echo            - turn OFF python.exe / python3.exe, then retry.
    exit /b 1
)
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set "PYV=%%i"
for /f "tokens=1,2 delims=." %%a in ("!PYV!") do (
    set "MAJOR=%%a"
    set "MINOR=%%b"
)
if "!MINOR!"=="" (
    echo   ERROR: could not parse Python version ^(got: "!PYV!"^)
    exit /b 1
)
if !MAJOR! LSS 3 (
    echo   ERROR: Python 3.10+ required ^(current: !PYV!^)
    exit /b 1
)
if !MAJOR! EQU 3 if !MINOR! LSS 10 (
    echo   ERROR: Python 3.10+ required ^(current: !PYV!^)
    exit /b 1
)
echo   python: !PYV!

where tshark >nul 2>&1
if errorlevel 1 (
    echo   ERROR: tshark is required.
    echo     Install Wireshark: https://www.wireshark.org/  ^(check "Add Wireshark to system PATH"^)
    exit /b 1
)
for /f "delims=" %%i in ('where tshark') do set "TSHARK=%%i"
echo   tshark: !TSHARK!

REM [2/5] Python venv
echo [2/5] Creating Python venv
if exist .venv (
    echo   .venv\ already exists - reusing
) else (
    python -m venv .venv
    if errorlevel 1 (
        echo   ERROR: venv creation failed
        exit /b 1
    )
    echo   .venv\ created
)

REM [3/5] dependencies
echo [3/5] Installing dependencies
call .venv\Scripts\activate.bat
set "HAS_WHEELS="
if exist wheels\*.whl set "HAS_WHEELS=1"
if exist wheels\*.tar.gz set "HAS_WHEELS=1"
if defined HAS_WHEELS (
    echo   offline-first mode ^(wheels\ + PyPI fallback^)
    pip install --find-links wheels -r requirements.txt
) else (
    echo   PyPI mode
    python -m pip install --upgrade pip >nul
    pip install -r requirements.txt
)
if errorlevel 1 (
    echo   ERROR: pip install failed
    echo   Fully offline with an ABI mismatch? Install the same Python minor version as the build host.
    exit /b 1
)

REM [4/5] smoke test
echo [4/5] Verifying installation
python -c "import fastapi, uvicorn, jinja2, httpx"
if errorlevel 1 (
    echo   ERROR: required package import failed
    exit /b 1
)
python -c "import config; print('  tshark detected:', config.detect_tshark() or 'NOT FOUND')"
if errorlevel 1 (
    echo   WARN: tshark detection failed ^(continuing^)
)

REM [5/5] done
echo [5/5] Done
echo.
echo Next step:
echo   run.bat
endlocal
