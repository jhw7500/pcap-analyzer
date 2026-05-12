@echo off
REM pcap-analyzer 실행 (Windows, 포그라운드)
REM Usage: run.bat
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

REM 스크립트 위치를 cwd로
cd /d "%~dp0"

if not exist .venv (
    echo ERROR: .venv가 없습니다. install.bat를 먼저 실행하세요.
    exit /b 1
)

call .venv\Scripts\activate.bat

if exist .env (
    for /f "usebackq tokens=1,* delims==" %%a in (".env") do (
        if not "%%a"=="" set "%%a=%%b"
    )
)

REM 배포 실행은 reload off
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
echo  pcap-analyzer v!VERSION!
echo  접속 URL:
echo    http://localhost:!PCAP_PORT!
if defined LAN_IP echo    http://!LAN_IP!:!PCAP_PORT!  ^(LAN^)
echo  종료: Ctrl+C
echo -----------------------------------------

python app.py
endlocal
