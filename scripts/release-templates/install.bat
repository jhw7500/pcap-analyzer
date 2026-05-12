@echo off
REM pcap-analyzer 설치 스크립트 (Windows)
REM Usage: install.bat
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

REM 스크립트 위치를 cwd로
cd /d "%~dp0"

set "VERSION=unknown"
if exist VERSION set /p VERSION=<VERSION
echo === pcap-analyzer v%VERSION% 설치 ===

REM [1/5] 시스템 의존성
echo [1/5] 시스템 의존성 확인
where python >nul 2>&1
if errorlevel 1 (
    echo   ERROR: python이 필요합니다.
    echo     설치: https://www.python.org/downloads/  ^(3.10 이상^)
    exit /b 1
)
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set "PYV=%%i"
for /f "tokens=1,2 delims=." %%a in ("!PYV!") do (
    set "MAJOR=%%a"
    set "MINOR=%%b"
)
if !MAJOR! LSS 3 (
    echo   ERROR: Python 3.10 이상 필요 ^(현재: !PYV!^)
    exit /b 1
)
if !MAJOR! EQU 3 if !MINOR! LSS 10 (
    echo   ERROR: Python 3.10 이상 필요 ^(현재: !PYV!^)
    exit /b 1
)
echo   python: !PYV!

where tshark >nul 2>&1
if errorlevel 1 (
    echo   ERROR: tshark가 필요합니다.
    echo     설치: https://www.wireshark.org/  ^(설치 시 PATH 등록 옵션 체크^)
    exit /b 1
)
for /f "delims=" %%i in ('where tshark') do set "TSHARK=%%i"
echo   tshark: !TSHARK!

REM [2/5] Python venv
echo [2/5] Python 가상환경 생성
if exist .venv (
    echo   .venv\ 이미 존재 — 재사용
) else (
    python -m venv .venv
    if errorlevel 1 (
        echo   ERROR: venv 생성 실패
        exit /b 1
    )
    echo   .venv\ 생성됨
)

REM [3/5] 의존성 설치
echo [3/5] 의존성 설치
call .venv\Scripts\activate.bat
set "HAS_WHEELS="
if exist wheels\*.whl set "HAS_WHEELS=1"
if exist wheels\*.tar.gz set "HAS_WHEELS=1"
if defined HAS_WHEELS (
    echo   오프라인 모드 ^(wheels\ 사용^)
    pip install --no-index --find-links wheels -r requirements.txt
) else (
    echo   PyPI 모드
    python -m pip install --upgrade pip >nul
    pip install -r requirements.txt
)
if errorlevel 1 (
    echo   ERROR: pip install 실패
    exit /b 1
)

REM [4/5] Smoke test
echo [4/5] 설치 확인
python -c "import fastapi, uvicorn, jinja2, httpx"
if errorlevel 1 (
    echo   ERROR: 필수 패키지 import 실패
    exit /b 1
)
python -c "import config; print('  tshark 감지:', config.detect_tshark() or '미감지')"
if errorlevel 1 (
    echo   WARN: tshark 감지 실패 ^(계속 진행^)
)

REM [5/5] 완료
echo [5/5] 완료
echo.
echo 다음 단계:
echo   run.bat
endlocal
