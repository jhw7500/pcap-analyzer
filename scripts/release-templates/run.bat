@echo off
REM pcap-analyzer runner (Windows, foreground)
REM Usage: run.bat
REM NOTE: keep this file ASCII-only. cmd.exe misparses batch lines that
REM       contain multibyte (Korean) characters, eating parts of lines.
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

REM cd to script location
cd /d "%~dp0"

if not exist .venv (
    echo ERROR: .venv not found. Run install.bat first.
    exit /b 1
)

call .venv\Scripts\activate.bat

if exist .env (
    for /f "usebackq tokens=1,* delims==" %%a in (".env") do (
        if not "%%a"=="" set "%%a=%%b"
    )
)

REM production run: reload off
set PCAP_DEV_RELOAD=false

set "VERSION=unknown"
if exist VERSION set /p VERSION=<VERSION

if not defined PCAP_HOST set PCAP_HOST=0.0.0.0
if not defined PCAP_PORT set PCAP_PORT=8000

set "LAN_IP="
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4"') do (
    if not defined LAN_IP (
        set "_ip=%%a"
        set "LAN_IP=!_ip: =!"
    )
)

echo -----------------------------------------
echo  pcap-analyzer !VERSION!
echo  URL:
echo    http://localhost:!PCAP_PORT!
if defined LAN_IP echo    http://!LAN_IP!:!PCAP_PORT!  ^(LAN^)
echo  Stop: Ctrl+C
echo -----------------------------------------

python app.py
endlocal
