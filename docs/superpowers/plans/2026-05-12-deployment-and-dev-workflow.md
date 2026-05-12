# 배포 & 개발 워크플로우 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** pcap-analyzer를 단일 빌드 명령으로 `dist/*.tar.gz`/`*.zip` 압축물로 패키징하고, 사용자가 압축 해제 후 한 줄 install + run으로 사용 가능하게 하며, Linux 호스트 + Windows 원격 접속 개발 워크플로우를 문서화한다.

**Architecture:** `scripts/build-release.sh`가 소스/벤더/wheel을 단일 staging 디렉토리에 모은 뒤 tar/zip으로 압축. 압축 안에는 OS별 `install.sh`/`install.bat`과 `run.sh`/`run.bat`이 동봉되어 venv 생성·의존성 설치·smoke test 후 포그라운드 실행한다. `app.py`는 env override를 위해 작은 헬퍼 함수로 리팩터링한다.

**Tech Stack:** Bash, Windows cmd batch, Python 3.10+ venv, pip wheel, rsync, tar, zip, sha256sum, FastAPI/uvicorn (기존)

**Reference Spec:** `docs/superpowers/specs/2026-05-12-deployment-and-dev-workflow-design.md`

---

## File Structure

### Created
| Path | Responsibility |
|---|---|
| `scripts/build-release.sh` | 빌드 오케스트레이션 — staging→vendor→wheel→압축→체크섬 |
| `scripts/release-exclude.txt` | rsync 제외 패턴 |
| `scripts/release-templates/install.sh` | Linux/macOS 설치 (5단계) |
| `scripts/release-templates/install.bat` | Windows 설치 (5단계) |
| `scripts/release-templates/run.sh` | Linux/macOS 실행 (배너 + python app.py) |
| `scripts/release-templates/run.bat` | Windows 실행 |
| `scripts/release-templates/INSTALL.md` | 사용자용 설치 가이드 (압축 동봉) |
| `docs/RELEASE.md` | 개발자용 빌드 가이드 |
| `docs/DEV.md` | LAN 원격 접속 개발 가이드 |
| `tests/test_app_entrypoint.py` | `app.py` env override 단위 테스트 |

### Modified
| Path | 변경 |
|---|---|
| `app.py` | `_run_dev_server()` 헬퍼 분리 + env override |
| `.gitignore` | `dist/` 추가 |
| `README.md` | "배포" / "개발 모드" 섹션 링크 |

---

## Task 1: `app.py` env override 리팩터링 (TDD)

**Files:**
- Modify: `/home/jhw/ai/opencode/projects/pcap-analyzer/app.py`
- Create: `/home/jhw/ai/opencode/projects/pcap-analyzer/tests/test_app_entrypoint.py`

### Step 1.1: 실패 테스트 작성

- [ ] Create `tests/test_app_entrypoint.py`:

```python
"""app.py __main__ 블록 env override 동작 검증."""
from unittest import mock


def test_run_dev_server_defaults(monkeypatch):
    """env 미설정 시 host=0.0.0.0, port=8000, reload=True."""
    monkeypatch.delenv("PCAP_HOST", raising=False)
    monkeypatch.delenv("PCAP_PORT", raising=False)
    monkeypatch.delenv("PCAP_DEV_RELOAD", raising=False)

    import app
    with mock.patch.object(app.uvicorn, "run") as mock_run:
        app._run_dev_server()
        kwargs = mock_run.call_args.kwargs
        assert kwargs["host"] == "0.0.0.0"
        assert kwargs["port"] == 8000
        assert kwargs["reload"] is True


def test_run_dev_server_env_override(monkeypatch):
    """PCAP_HOST/PORT/DEV_RELOAD가 우선."""
    monkeypatch.setenv("PCAP_HOST", "127.0.0.1")
    monkeypatch.setenv("PCAP_PORT", "9000")
    monkeypatch.setenv("PCAP_DEV_RELOAD", "false")

    import app
    with mock.patch.object(app.uvicorn, "run") as mock_run:
        app._run_dev_server()
        kwargs = mock_run.call_args.kwargs
        assert kwargs["host"] == "127.0.0.1"
        assert kwargs["port"] == 9000
        assert kwargs["reload"] is False


def test_run_dev_server_reload_case_insensitive(monkeypatch):
    """PCAP_DEV_RELOAD는 대소문자 무관."""
    monkeypatch.setenv("PCAP_DEV_RELOAD", "FALSE")
    import app
    with mock.patch.object(app.uvicorn, "run") as mock_run:
        app._run_dev_server()
        assert mock_run.call_args.kwargs["reload"] is False
```

### Step 1.2: 테스트 실행 → 실패 확인

- [ ] Run:
```bash
cd /home/jhw/ai/opencode/projects/pcap-analyzer
python3 -m pytest tests/test_app_entrypoint.py -v
```
Expected: 3 FAIL — `AttributeError: module 'app' has no attribute '_run_dev_server'`

### Step 1.3: `app.py` 최소 변경

- [ ] Modify `app.py` — 파일 끝의 `if __name__ == "__main__"` 블록을 다음으로 교체:

```python
import os


def _run_dev_server():
    """개발/배포 공용 엔트리: env override 지원."""
    uvicorn.run(
        "app:app",
        host=os.getenv("PCAP_HOST", "0.0.0.0"),
        port=int(os.getenv("PCAP_PORT", "8000")),
        reload=os.getenv("PCAP_DEV_RELOAD", "true").lower() == "true",
    )


if __name__ == "__main__":
    _run_dev_server()
```

`import os`는 파일 상단 import 블록(현재 `import uvicorn` 다음 줄)으로 이동시킨다. 다른 코드는 건드리지 않는다.

### Step 1.4: 테스트 통과 확인

- [ ] Run:
```bash
python3 -m pytest tests/test_app_entrypoint.py -v
```
Expected: 3 PASS

### Step 1.5: 전체 회귀 테스트

- [ ] Run:
```bash
python3 -m pytest tests/ -v -x --ignore=tests/e2e
```
Expected: 기존 테스트 + 신규 3개 모두 PASS

### Step 1.6: Commit

- [ ] Commit:
```bash
git add app.py tests/test_app_entrypoint.py
git commit -m "feat(app): __main__ 블록을 env override 헬퍼로 분리

- _run_dev_server(): PCAP_HOST/PORT/DEV_RELOAD 환경변수 우선
- 기본값(0.0.0.0:8000, reload=True)은 현재 동작과 동일
- 배포 run.sh에서 reload=false로 강제 가능"
```

---

## Task 2: `.gitignore` + `scripts/release-exclude.txt`

**Files:**
- Modify: `/home/jhw/ai/opencode/projects/pcap-analyzer/.gitignore`
- Create: `/home/jhw/ai/opencode/projects/pcap-analyzer/scripts/release-exclude.txt`

### Step 2.1: `.gitignore`에 `dist/` 추가

- [ ] 현재 `.gitignore` 내용을 읽고, 마지막에 다음 두 줄을 추가:

```
# 배포 산출물 (scripts/build-release.sh 출력)
dist/
```

### Step 2.2: rsync 제외 목록 생성

- [ ] Create `scripts/release-exclude.txt` with content:

```
# VCS
.git/
.gitignore
.gitattributes

# Python / virtualenv / caches
.venv/
venv/
__pycache__/
*.pyc
*.pyo
.pytest_cache/
.ruff_cache/
.mypy_cache/
.coverage
htmlcov/

# Tool state (Claude Code / OMC / Playwright / Bkit / Gstack)
.bkit/
.omc/
.playwright-mcp/
.claude/
.gstack/

# Runtime data & secrets
data/
tmp/
config.local.json
.env
.env.*

# Capture files (pcap-analyzer 특성상 PII 포함 — release에 절대 포함 금지)
*.pcap
*.pcapng
*.cap

# Logs
*.log
nohup.out

# OS / editor noise
.DS_Store
Thumbs.db
*.swp
*.swo
*~

# Internal docs (user-facing INSTALL.md은 build-release.sh가 별도로 작성)
docs/01-plan/
docs/03-analysis/
docs/04-report/
docs/archive/
docs/superpowers/

# Screenshot/scratch PNGs (root 한정 — static/img/*.png 같은 미래 자산 보호)
/*.png

# Build artifacts
node_modules/
dist/

# Root scratch test scripts (gitignore의 /test_*.py와 동일 anchor)
/test_*.py
```

### Step 2.3: 동작 검증 (dry-run)

- [ ] Run (스테이지 디렉토리 만들지 않고 무엇이 복사될지만 확인):
```bash
cd /home/jhw/ai/opencode/projects/pcap-analyzer
rsync -an --exclude-from=scripts/release-exclude.txt ./ /tmp/pcap-release-dryrun/ | head -40
```
Expected: `analyzer/`, `routes/`, `ai/`, `templates/`, `static/`, `app.py`, `config.py`, `requirements.txt`, `Makefile`, `README.md`, `AGENTS.md` 등은 보이고, `.git/`, `data/`, `dist/`, `.bkit/`, 루트 `*.png`는 보이지 않음.

### Step 2.4: Commit

- [ ] Commit:
```bash
git add .gitignore scripts/release-exclude.txt
git commit -m "chore: 배포 산출물 git 제외 + rsync 제외 목록 추가"
```

---

## Task 3: `install.sh` + `install.bat` (OS 페어)

**Files:**
- Create: `/home/jhw/ai/opencode/projects/pcap-analyzer/scripts/release-templates/install.sh`
- Create: `/home/jhw/ai/opencode/projects/pcap-analyzer/scripts/release-templates/install.bat`

### Step 3.1: `install.sh` 생성

- [ ] Create file with content:

```bash
#!/usr/bin/env bash
# pcap-analyzer 설치 스크립트 (Linux/macOS)
# Usage: ./install.sh
set -euo pipefail

# 스크립트 위치를 cwd로 (어디서 실행해도 동일)
cd "$(dirname "$0")"

LOG="install.log"
: > "${LOG}"
exec > >(tee -a "${LOG}") 2>&1

VERSION=$(cat VERSION 2>/dev/null || echo "unknown")
echo "=== pcap-analyzer v${VERSION} 설치 ==="

# [1/5] 시스템 의존성
echo "[1/5] 시스템 의존성 확인"
if ! command -v python3 >/dev/null 2>&1; then
    echo "  ERROR: python3가 필요합니다."
    case "$(uname -s)" in
        Linux*)  echo "    설치: sudo apt install python3 python3-venv python3-pip" ;;
        Darwin*) echo "    설치: brew install python@3.11" ;;
    esac
    exit 1
fi
PYV=$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
MAJOR=$(echo "${PYV}" | cut -d. -f1)
MINOR=$(echo "${PYV}" | cut -d. -f2)
if [ "${MAJOR}" -lt 3 ] || { [ "${MAJOR}" -eq 3 ] && [ "${MINOR}" -lt 10 ]; }; then
    echo "  ERROR: Python 3.10 이상 필요 (현재: ${PYV})"
    exit 1
fi
echo "  python3: $(command -v python3) (${PYV})"

if ! command -v tshark >/dev/null 2>&1; then
    echo "  ERROR: tshark가 필요합니다."
    case "$(uname -s)" in
        Linux*)  echo "    설치: sudo apt install tshark" ;;
        Darwin*) echo "    설치: brew install wireshark" ;;
    esac
    exit 1
fi
echo "  tshark:  $(command -v tshark)"

# [2/5] Python venv
echo "[2/5] Python 가상환경 생성"
if [ -d .venv ]; then
    echo "  .venv/ 이미 존재 — 재사용"
else
    python3 -m venv .venv
    echo "  .venv/ 생성됨"
fi

# [3/5] 의존성 설치
echo "[3/5] 의존성 설치"
# shellcheck disable=SC1091
source .venv/bin/activate
if [ -d wheels ] && [ -n "$(ls -A wheels 2>/dev/null)" ]; then
    echo "  오프라인 모드 (wheels/ 사용)"
    # 오프라인 환경에서는 pip upgrade 생략 (venv 기본 pip로 충분)
    pip install --no-index --find-links wheels -r requirements.txt
else
    echo "  PyPI 모드"
    python -m pip install --upgrade pip >/dev/null
    pip install -r requirements.txt
fi

# [4/5] Smoke test
echo "[4/5] 설치 확인"
python -c "import fastapi, uvicorn, jinja2, httpx" \
    || { echo "  ERROR: 필수 패키지 import 실패"; exit 1; }
TSHARK_DETECTED=$(python -c "import config; print(config.detect_tshark() or '미감지')")
echo "  import OK"
echo "  tshark 감지: ${TSHARK_DETECTED}"

# [5/5] 완료
echo "[5/5] 완료"
echo ""
echo "다음 단계:"
echo "  ./run.sh"
```

### Step 3.2: `install.bat` 생성

- [ ] Create file with content:

```batch
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
```

### Step 3.3: 실행 권한

- [ ] Run:
```bash
chmod +x /home/jhw/ai/opencode/projects/pcap-analyzer/scripts/release-templates/install.sh
```

### Step 3.4: install.sh 단독 동작 검증 (격리 환경)

- [ ] Run (현재 소스 트리에서 install.sh를 실행해보면 venv는 만들어지지만 wheels/는 없으니 PyPI 모드로 진행):
```bash
cd /tmp
mkdir -p pcap-install-test
cd pcap-install-test
cp -r /home/jhw/ai/opencode/projects/pcap-analyzer/analyzer .
cp -r /home/jhw/ai/opencode/projects/pcap-analyzer/routes .
cp -r /home/jhw/ai/opencode/projects/pcap-analyzer/ai .
cp -r /home/jhw/ai/opencode/projects/pcap-analyzer/templates .
cp -r /home/jhw/ai/opencode/projects/pcap-analyzer/static .
cp /home/jhw/ai/opencode/projects/pcap-analyzer/{app.py,config.py,requirements.txt} .
echo "test-version" > VERSION
cp /home/jhw/ai/opencode/projects/pcap-analyzer/scripts/release-templates/install.sh .
bash install.sh
```
Expected:
- 모든 5단계가 OK
- `.venv/`, `install.log` 생성
- 마지막 줄: `다음 단계: ./run.sh`

검증 후 정리:
```bash
cd /tmp && rm -rf pcap-install-test
```

### Step 3.5: Commit

- [ ] Commit:
```bash
cd /home/jhw/ai/opencode/projects/pcap-analyzer
git add scripts/release-templates/install.sh scripts/release-templates/install.bat
git commit -m "feat(release): OS별 install 스크립트 (5단계, 오프라인/PyPI 자동 분기)"
```

---

## Task 4: `run.sh` + `run.bat` (OS 페어)

**Files:**
- Create: `/home/jhw/ai/opencode/projects/pcap-analyzer/scripts/release-templates/run.sh`
- Create: `/home/jhw/ai/opencode/projects/pcap-analyzer/scripts/release-templates/run.bat`

### Step 4.1: `run.sh` 생성

- [ ] Create file with content:

```bash
#!/usr/bin/env bash
# pcap-analyzer 실행 (Linux/macOS, 포그라운드)
# Usage: ./run.sh
set -euo pipefail

if [ ! -d .venv ]; then
    echo "ERROR: .venv가 없습니다. ./install.sh를 먼저 실행하세요."
    exit 1
fi

# shellcheck disable=SC1091
source .venv/bin/activate

if [ -f .env ]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
fi

# 배포 실행은 reload off (개발은 python app.py 직접 호출)
export PCAP_DEV_RELOAD=false

VERSION=$(cat VERSION 2>/dev/null || echo "unknown")
HOST="${PCAP_HOST:-0.0.0.0}"
PORT="${PCAP_PORT:-8000}"
LAN_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || true)

echo "─────────────────────────────────────────"
echo " pcap-analyzer v${VERSION}"
echo " 접속 URL:"
echo "   http://localhost:${PORT}"
if [ -n "${LAN_IP}" ]; then
    echo "   http://${LAN_IP}:${PORT}  (LAN)"
fi
echo " 종료: Ctrl+C"
echo "─────────────────────────────────────────"

trap 'deactivate 2>/dev/null || true' EXIT
exec python app.py
```

### Step 4.2: `run.bat` 생성

- [ ] Create file with content:

```batch
@echo off
REM pcap-analyzer 실행 (Windows, 포그라운드)
REM Usage: run.bat
setlocal enabledelayedexpansion

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
```

### Step 4.3: 실행 권한

- [ ] Run:
```bash
chmod +x /home/jhw/ai/opencode/projects/pcap-analyzer/scripts/release-templates/run.sh
```

### Step 4.4: run.sh 동작 검증 (수동)

- [ ] Run in foreground briefly (5초 후 Ctrl+C):
```bash
cd /tmp/pcap-install-test  # Task 3.4의 디렉토리 (.venv가 있어야 함)
# 만약 정리했다면 Task 3.4 재실행 후 진행
cp /home/jhw/ai/opencode/projects/pcap-analyzer/scripts/release-templates/run.sh .
chmod +x run.sh
timeout 5 ./run.sh || true
```
Expected:
- "─────" 배너 출력
- `pcap-analyzer v test-version`
- `http://localhost:8000` + (LAN IP가 잡히면) LAN URL
- uvicorn 시작 로그 (Application startup complete)
- timeout 5초 후 종료

검증 후 정리:
```bash
cd /tmp && rm -rf pcap-install-test
```

### Step 4.5: Commit

- [ ] Commit:
```bash
cd /home/jhw/ai/opencode/projects/pcap-analyzer
git add scripts/release-templates/run.sh scripts/release-templates/run.bat
git commit -m "feat(release): OS별 run 스크립트 (LAN 배너 + reload off 강제)"
```

---

## Task 5: 사용자용 `INSTALL.md` (압축 동봉)

**Files:**
- Create: `/home/jhw/ai/opencode/projects/pcap-analyzer/scripts/release-templates/INSTALL.md`

### Step 5.1: 파일 생성

- [ ] Create file with content:

````markdown
# pcap-analyzer 설치 가이드

이 문서는 압축 해제 후 함께 들어있는 사용자용 설치 가이드입니다.

## 1. 시스템 요구사항

| 항목 | 최소 사양 |
|---|---|
| OS | Linux (Ubuntu/Debian 권장), macOS, Windows 10/11 |
| Python | 3.10 이상 |
| tshark | Wireshark CLI (필수) |
| 디스크 | 약 500MB (venv + wheels + vendor 포함) |
| 메모리 | 2GB 이상 권장 (대용량 pcap 분석 시 4GB+) |

### tshark 설치

- **Linux (Ubuntu/Debian)**: `sudo apt install tshark`
- **macOS**: `brew install wireshark`
- **Windows**: https://www.wireshark.org/ 에서 설치 (설치 옵션에서 "Install TShark" + "Add path" 체크)

## 2. 다운로드 & 압축 해제

### Linux/macOS
```bash
tar -xzf pcap-analyzer-<VERSION>.tar.gz
cd pcap-analyzer-<VERSION>
```

### Windows
1. `pcap-analyzer-<VERSION>.zip` 우클릭 → "압축 풀기"
2. 풀린 폴더 안으로 이동

**주의(Windows)**: 한글이 포함된 경로(`바탕 화면` 등)에서 가끔 venv 생성이 실패합니다. 영문 경로(`C:\pcap` 등) 권장.

## 3. 설치

### Linux/macOS
```bash
./install.sh
```

### Windows
```cmd
install.bat
```

5단계가 모두 OK로 끝나면 설치 완료. 상세 로그는 `install.log`에 저장됩니다.

### 오프라인(폐쇄망) 환경

압축에 `wheels/` 디렉토리가 동봉되어 있으면 자동으로 오프라인 모드로 설치됩니다. 인터넷 없이도 동작합니다.

## 4. 실행 & 접속

### Linux/macOS
```bash
./run.sh
```

### Windows
```cmd
run.bat
```

시작 후 출력되는 배너의 URL로 브라우저 접속:
```
 접속 URL:
   http://localhost:8000
   http://192.168.x.x:8000  (LAN)
```

종료: `Ctrl+C`

### 옵션: 포트/호스트 변경

```bash
PCAP_PORT=9000 ./run.sh        # Linux/macOS
```
```cmd
set PCAP_PORT=9000 && run.bat  # Windows
```

## 5. 트러블슈팅

| 증상 | 해결 |
|---|---|
| `install.sh: tshark가 필요합니다` | tshark 미설치. 위 1. 시스템 요구사항 참조 |
| `address already in use` | 8000 포트 점유 중. `PCAP_PORT=9000`으로 재실행 |
| LAN URL 접속 불가 | 호스트 방화벽(`sudo ufw allow 8000` / Windows Defender 인바운드 허용) 확인 |
| `tshark 감지: 미감지` (Windows) | tshark 경로가 PATH에 없음. 설정 페이지(`/settings`)에서 `tshark.exe` 절대 경로 지정 |
| 분석 진행률 멈춤 | 수백만 프레임 pcap은 분 단위 소요. `/api/progress`로 진행 상태 확인 |
| Python 3.10 미만 | Python 업그레이드 필요 |

## 6. AI 리뷰 사용 (선택)

분석 결과를 Claude/OpenAI로 자동 해석하려면 환경변수 또는 `config.local.json`에 다음 지정:

```bash
export PCAP_AI_PROVIDER=claude
export PCAP_AI_API_KEY=sk-ant-...
export PCAP_AI_MODEL=claude-sonnet-4-6
./run.sh
```

자세한 설정 키는 압축에 포함된 `README.md` 참조.
````

### Step 5.2: 시각 검토

- [ ] Read the file and verify:
  - 5개 섹션 모두 채워짐
  - `<VERSION>` 자리표시자가 의도된 곳에만 있음 (사용자가 실제 버전 번호로 읽음)
  - 코드 블록의 OS 분기가 명확

### Step 5.3: Commit

- [ ] Commit:
```bash
git add scripts/release-templates/INSTALL.md
git commit -m "docs(release): 사용자용 INSTALL.md (압축 동봉용)"
```

---

## Task 6: `scripts/build-release.sh`

**Files:**
- Create: `/home/jhw/ai/opencode/projects/pcap-analyzer/scripts/build-release.sh`

### Step 6.1: 파일 생성

- [ ] Create file with content:

```bash
#!/usr/bin/env bash
# pcap-analyzer 배포 빌더
# Usage:
#   bash scripts/build-release.sh
#   VERSION=1.2.3 bash scripts/build-release.sh
#   SKIP_WHEELS=1 SKIP_VENDOR=1 bash scripts/build-release.sh
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

# [1] 사전 체크
echo "[1] 사전 체크"
for cmd in python3 pip git tar zip rsync curl sha256sum; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "  ERROR: ${cmd} 명령이 필요합니다."
        exit 1
    fi
done
echo "  OK"

# [2] 버전 결정
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "0.0.0-$(git rev-parse --short HEAD 2>/dev/null || echo nogit)")}"
echo "[2] 버전: ${VERSION}"

# [3] 스테이징 준비
DIST="${ROOT}/dist"
BUILD="${DIST}/build"
STAGE="${BUILD}/pcap-analyzer-${VERSION}"
rm -rf "${BUILD}"
mkdir -p "${STAGE}"
echo "[3] 스테이징: ${STAGE}"

# [4] 소스 복사
echo "[4] 소스 복사 (rsync)"
rsync -a --exclude-from="${ROOT}/scripts/release-exclude.txt" \
    "${ROOT}/" "${STAGE}/"

# [5] vendor 다운로드
if [ "${SKIP_VENDOR:-0}" != "1" ]; then
    echo "[5] vendor 에셋 다운로드"
    (cd "${STAGE}" && make fetch-vendor)
else
    echo "[5] vendor 다운로드 skip (SKIP_VENDOR=1)"
fi

# [6] wheel 빌드
if [ "${SKIP_WHEELS:-0}" != "1" ]; then
    echo "[6] wheel 빌드"
    mkdir -p "${STAGE}/wheels"
    pip wheel -r "${STAGE}/requirements.txt" -w "${STAGE}/wheels/" --quiet
    echo "  $(ls "${STAGE}/wheels/" | wc -l)개 wheel 생성"
else
    echo "[6] wheel 빌드 skip (SKIP_WHEELS=1)"
fi

# [7] 설치/실행 템플릿 복사
echo "[7] 설치/실행 스크립트 복사"
cp "${ROOT}/scripts/release-templates/install.sh" "${STAGE}/"
cp "${ROOT}/scripts/release-templates/install.bat" "${STAGE}/"
cp "${ROOT}/scripts/release-templates/run.sh"     "${STAGE}/"
cp "${ROOT}/scripts/release-templates/run.bat"    "${STAGE}/"
mkdir -p "${STAGE}/docs"
cp "${ROOT}/scripts/release-templates/INSTALL.md" "${STAGE}/docs/"
chmod +x "${STAGE}/install.sh" "${STAGE}/run.sh"

# [8] VERSION 파일
echo "${VERSION}" > "${STAGE}/VERSION"
echo "[8] VERSION 파일 작성: ${VERSION}"

# [9] 압축 생성
echo "[9] 압축 생성"
(cd "${BUILD}" && tar -czf "${DIST}/pcap-analyzer-${VERSION}.tar.gz" "pcap-analyzer-${VERSION}")
(cd "${BUILD}" && zip -qr "${DIST}/pcap-analyzer-${VERSION}.zip" "pcap-analyzer-${VERSION}")

# [10] 체크섬
echo "[10] 체크섬"
(cd "${DIST}" && sha256sum "pcap-analyzer-${VERSION}.tar.gz" "pcap-analyzer-${VERSION}.zip" > SHA256SUMS.txt)

# [11] 정리
rm -rf "${BUILD}"

echo ""
echo "[*] 완료. 산출물:"
ls -lh "${DIST}/"
```

### Step 6.2: 실행 권한

- [ ] Run:
```bash
chmod +x /home/jhw/ai/opencode/projects/pcap-analyzer/scripts/build-release.sh
```

### Step 6.3: 빌드 실행 (실제 산출물 생성)

- [ ] Run:
```bash
cd /home/jhw/ai/opencode/projects/pcap-analyzer
bash scripts/build-release.sh
```
Expected (5~10분 소요, wheel 빌드 단계가 가장 느림):
- 11개 단계 모두 OK
- 마지막에 `dist/`의 파일 목록 출력
- `dist/pcap-analyzer-<VERSION>.tar.gz`, `dist/pcap-analyzer-<VERSION>.zip`, `dist/SHA256SUMS.txt` 존재

### Step 6.4: 산출물 검증

- [ ] Run:
```bash
cd /home/jhw/ai/opencode/projects/pcap-analyzer/dist
ls -lh
sha256sum -c SHA256SUMS.txt
tar -tzf pcap-analyzer-*.tar.gz | head -20
tar -tzf pcap-analyzer-*.tar.gz | grep -E "(\.git/|data/|config\.local|\.bkit/|dist/)" && echo "FAIL: 제외 파일이 포함됨" || echo "OK: 제외 목록 정상"
tar -tzf pcap-analyzer-*.tar.gz | grep -E "(VERSION|install\.sh|install\.bat|run\.sh|run\.bat|wheels/|static/vendor/)" | head -10
```
Expected:
- 체크섬 OK
- `.git/`, `data/`, `config.local.json`, `.bkit/`, `dist/` 없음 (FAIL 메시지 안 나옴)
- `VERSION`, `install.sh`, `install.bat`, `run.sh`, `run.bat`, `wheels/*.whl`, `static/vendor/*` 다수 존재

### Step 6.5: Commit

- [ ] Commit:
```bash
cd /home/jhw/ai/opencode/projects/pcap-analyzer
git add scripts/build-release.sh
git commit -m "feat(release): build-release.sh — staging+vendor+wheel+tar/zip+체크섬"
```

`dist/` 자체는 `.gitignore`에 있어 자동 제외됨.

---

## Task 7: End-to-end smoke test (build → extract → install → run → 접속)

**Files:**
- None (실제 산출물로 검증만)

### Step 7.1: 격리 디렉토리에서 압축 풀기

- [ ] Run:
```bash
mkdir -p /tmp/pcap-e2e
cd /tmp/pcap-e2e
tar -xzf /home/jhw/ai/opencode/projects/pcap-analyzer/dist/pcap-analyzer-*.tar.gz
cd pcap-analyzer-*
ls -la
```
Expected: `app.py`, `install.sh`, `run.sh`, `wheels/`, `static/vendor/`, `VERSION` 등 확인

### Step 7.2: 설치 실행

- [ ] Run:
```bash
./install.sh
```
Expected: 5단계 모두 OK, `.venv/` 생성, "다음 단계: ./run.sh" 출력. 오프라인 모드 메시지("오프라인 모드 (wheels/ 사용)")가 떠야 함.

### Step 7.3: 실행 + HTTP 접속 검증

- [ ] Run (백그라운드로 띄우고 curl로 검증):
```bash
./run.sh > run.log 2>&1 &
RUN_PID=$!
sleep 5
curl -fsS -o /dev/null -w "HTTP %{http_code}\n" http://localhost:8000/
kill ${RUN_PID} 2>/dev/null || true
wait ${RUN_PID} 2>/dev/null || true
cat run.log | head -20
```
Expected:
- `HTTP 200`
- `run.log`에 배너 + uvicorn startup 로그

### Step 7.4: 정리

- [ ] Run:
```bash
cd /tmp && rm -rf /tmp/pcap-e2e
```

### Step 7.5: 결과 기록 (커밋 없음)

- [ ] 이 Task는 코드 변경이 없으므로 커밋 생략. 결과를 콘솔에 요약 출력:
  - `HTTP 200 / 오프라인 설치 OK / 5단계 완료` 형태로 1줄

검증 실패 시 해당 Task의 install/run/build 스크립트로 돌아가 수정 후 재실행.

---

## Task 8: `docs/RELEASE.md` (개발자용 빌드 가이드)

**Files:**
- Create: `/home/jhw/ai/opencode/projects/pcap-analyzer/docs/RELEASE.md`

### Step 8.1: 파일 생성

- [ ] Create file with content:

````markdown
# 배포 빌드 가이드 (개발자용)

> 사용자용 설치 가이드는 압축 안에 동봉된 `docs/INSTALL.md` 참조.

## 빌드 한 줄

```bash
bash scripts/build-release.sh
```

`dist/` 아래에 다음이 생성됩니다:

```
dist/
├── pcap-analyzer-<VERSION>.tar.gz       # Linux 권장
├── pcap-analyzer-<VERSION>.zip          # Windows 권장
└── SHA256SUMS.txt
```

## 버전 규칙

- 기본: `git describe --tags --always --dirty` 결과 사용
- 명시 override: `VERSION=1.2.3 bash scripts/build-release.sh`
- 태그가 없으면 `0.0.0-<shorthash>` 형태로 자동 생성
- 작업트리에 미커밋 변경이 있으면 `-dirty` 접미사

## 환경변수 옵션

| 변수 | 기본 | 효과 |
|---|---|---|
| `VERSION` | git describe | 명시적 버전 |
| `SKIP_WHEELS` | `0` | `1`이면 wheel 빌드 생략 (slim 배포, 온라인 전용) |
| `SKIP_VENDOR` | `0` | `1`이면 vendor 다운로드 생략 (CDN 사용 가정) |

예시 — wheel/vendor 없이 슬림 빌드:
```bash
SKIP_WHEELS=1 SKIP_VENDOR=1 bash scripts/build-release.sh
```

## 빌드 호스트 요구사항

- Linux (Ubuntu 22.04 이상 권장)
- Python 3.10+ (설치 대상과 동일 마이너 버전 권장 — wheel ABI 일치)
- 명령: `git`, `rsync`, `tar`, `zip`, `sha256sum`, `curl`, `python3`, `pip`
- 인터넷 연결 (vendor + wheel 다운로드용 — 빌드 시점에만)

## 산출물 검증

```bash
cd dist
sha256sum -c SHA256SUMS.txt
tar -tzf pcap-analyzer-*.tar.gz | head -20
```

## 자주 마주치는 이슈

| 증상 | 원인/해결 |
|---|---|
| `pip wheel` 실패 | requirements.txt에 시스템 헤더 필요 패키지. `apt install python3-dev build-essential` |
| `make fetch-vendor` 실패 | 인터넷 차단 또는 CDN 차단. `SKIP_VENDOR=1`로 우회 후 사용자가 직접 vendor 채움 |
| `git describe` 빈 결과 | 태그 없음 (정상 — `0.0.0-<hash>`로 자동 생성됨) |
| wheel 호환 안 됨 | 빌드 호스트와 설치 대상의 Python 버전/OS 다름. 동일 환경에서 빌드 또는 `SKIP_WHEELS=1`로 PyPI fallback |

## 빌드 산출물 배포

`dist/`는 `.gitignore`에 의해 git 추적 제외. 다음 중 한 방식으로 사용자에게 전달:

- GitHub Releases 업로드 (SHA256SUMS.txt 함께)
- 사내 파일 서버 / SMB / scp
- USB로 폐쇄망 머신에 운반

## release 체크리스트

- [ ] 작업트리 깨끗 (`git status` 깨끗 또는 의도된 변경만)
- [ ] 태그 부여 (`git tag v0.1.0`) — 선택
- [ ] `bash scripts/build-release.sh` 성공
- [ ] `sha256sum -c dist/SHA256SUMS.txt` 통과
- [ ] tar 안에 `.git/`, `data/`, `config.local.json` 없음 (Task 7.1 검증과 동일)
- [ ] 로컬에서 E2E (압축 풀기 → install → run → curl 200) OK
````

### Step 8.2: Commit

- [ ] Commit:
```bash
git add docs/RELEASE.md
git commit -m "docs: 개발자용 빌드 가이드 RELEASE.md 추가"
```

---

## Task 9: `docs/DEV.md` (LAN 원격 접속 개발 가이드)

**Files:**
- Create: `/home/jhw/ai/opencode/projects/pcap-analyzer/docs/DEV.md`

### Step 9.1: 파일 생성

- [ ] Create file with content:

````markdown
# 개발 워크플로우 — 호스트 수정 + Windows PC 원격 접속

호스트(Linux dev box)에서 코드를 수정하면서 Windows PC 브라우저로 LAN 원격 접속하여 테스트하는 워크플로우.

> 배포(설치 가능한 압축물 만들기)는 `docs/RELEASE.md`, `docs/INSTALL.md` 참조.

## 0. 한눈에 보기

```
[호스트 (Linux dev box)]                  [Windows PC]
  python3 app.py                            브라우저
  │ host=0.0.0.0, port=8000                 │
  │ uvicorn --reload                        │
  │ (코드 저장 → 자동 재시작)                  │
  └─ 시작 배너:                              │
       http://localhost:8000                │
       http://<자동감지 IP>:8000  ◄─────────┘ 이 URL로 접속
```

## 1. 사전 준비

### 호스트(Linux)
```bash
# Python 3.10+ + tshark
sudo apt install python3 python3-venv python3-pip tshark

# 의존성
cd <pcap-analyzer 디렉토리>
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 방화벽 (선택 — ufw 사용 시)
sudo ufw allow 8000/tcp

# 호스트 IP 확인
hostname -I | awk '{print $1}'
```

### Windows PC
- 최신 브라우저(Chrome / Edge / Firefox) 외 별도 설치 불필요
- 호스트와 같은 LAN(같은 WiFi 또는 같은 사내 네트워크)에 있어야 함

### 연결 확인
Windows의 `cmd` 또는 PowerShell에서:
```cmd
ping <Linux IP>
```
응답이 오면 OK.

## 2. 시작 / 종료

호스트에서:
```bash
source .venv/bin/activate
python3 app.py
```

기본 동작:
- `host=0.0.0.0` (LAN 노출)
- `port=8000`
- `reload=True` (코드 저장 시 자동 재시작)

종료: `Ctrl+C`

## 3. LAN 접속

호스트 IP가 `192.168.10.5`인 예시:

| 머신 | 접속 URL |
|---|---|
| 호스트 자신 | http://localhost:8000 |
| Windows PC | http://192.168.10.5:8000 |

## 4. 코드 수정 워크플로우

1. 호스트에서 `.py` 파일 저장 → uvicorn이 감지 → 자동 재시작 (1~2초)
2. Windows 브라우저 새로고침(F5) → 변경 반영
3. `templates/`, `static/`은 캐시 헤더가 no-cache라 즉시 반영 (uvicorn 재시작 없이도)

**주의**: 분석 진행 중에 코드 저장하면 uvicorn 재시작으로 분석이 끊깁니다. 분석 끝낸 뒤 수정 권장.

## 5. pcap 파일 전달 경로

### (A) 브라우저 업로드 (가장 단순)
Windows에서 pcap 파일을 브라우저 드래그&드롭으로 업로드. 호스트의 `data/uploads/`로 저장됨.

### (B) 호스트에 미리 두기 (대용량/반복 분석)
Windows에서 호스트로 scp:
```cmd
scp capture.pcap user@192.168.10.5:~/pcap-analyzer/data/pcap/
```
또는 rsync / SMB 공유. 호스트의 어떤 경로에 두든 브라우저 업로드 페이지에서 다시 선택해야 분석 대상이 됨 (현재 구현은 업로드 디렉토리 기반).

## 6. 옵션 환경변수

```bash
PCAP_PORT=9000 python3 app.py                # 포트 변경
PCAP_HOST=127.0.0.1 python3 app.py           # localhost only (LAN 노출 끔)
PCAP_DEV_RELOAD=false python3 app.py         # 자동 리로드 끔 (분석 중 안정성)
```

## 7. 트러블슈팅

| 증상 | 해결 |
|---|---|
| Windows에서 ping은 되는데 브라우저 접속 안 됨 | 호스트 방화벽(`sudo ufw status`) + 8000/tcp 허용 여부 |
| `address already in use` | 8000 점유 중. `ss -ltn \| grep 8000`으로 점유 PID 확인, 또는 `PCAP_PORT=9000` |
| reload가 안 됨 | uvicorn은 `.py` 변경만 감지. `templates/`, `static/`은 재시작 없이 즉시 반영됨 |
| LAN URL 줄이 안 보임 | `hostname -I`가 빈 결과. 네트워크 인터페이스 IP 미할당 — `ip addr` 확인 |
| 분석 진행률 멈춤 | 대용량 pcap의 tshark 추출 단계는 분 단위. `/api/progress`로 진행 확인 |
| Windows에서 도메인 이름으로 접속하고 싶음 | Windows의 `hosts` 파일(`C:\Windows\System32\drivers\etc\hosts`)에 `192.168.10.5 pcap.local` 추가 |

## 8. `scripts/sync-from-linux.sh`와의 관계

기존 `scripts/sync-from-linux.sh`는 **Windows 머신에 별도 클론을 두고 rsync로 갱신**하는 패턴(코드도 Windows에 복사). 본 가이드는 **호스트 단일 인스턴스 + 브라우저 원격 접속** 패턴.

두 방식은 배타적입니다:
- **sync 방식**: Windows에서도 직접 실행/디버깅 필요 시
- **원격 접속(본 가이드)**: 단일 dev box에서 모든 개발, Windows는 단순 클라이언트

팀 합의 후 한쪽만 사용하길 권장합니다.
````

### Step 9.2: Commit

- [ ] Commit:
```bash
git add docs/DEV.md
git commit -m "docs: LAN 원격 접속 개발 워크플로우 가이드 DEV.md 추가"
```

---

## Task 10: `README.md`에 배포/개발 모드 링크 추가

**Files:**
- Modify: `/home/jhw/ai/opencode/projects/pcap-analyzer/README.md`

### Step 10.1: README에 두 섹션 추가

- [ ] Read current README.md and find the line immediately before `## 개발` (현재 README의 끝부분 직전).

- [ ] Edit `README.md` — `## 트러블슈팅` 섹션과 `## 개발` 섹션 사이에 다음 두 섹션을 삽입:

```markdown
## 배포

압축 파일(`pcap-analyzer-<VERSION>.tar.gz` 또는 `.zip`)로 배포하려면:

```bash
bash scripts/build-release.sh
```

`dist/`에 OS별 압축 파일이 생성됨. 사용자용 설치 가이드는 `docs/INSTALL.md`(압축 동봉), 개발자용 빌드 옵션은 `docs/RELEASE.md` 참조.

## 개발 모드 (LAN 원격 접속 테스트)

호스트(Linux dev box)에서 코드 수정 + Windows PC 브라우저로 원격 접속 테스트하는 워크플로우는 `docs/DEV.md` 참조.
```

### Step 10.2: 변경 확인

- [ ] Run:
```bash
cd /home/jhw/ai/opencode/projects/pcap-analyzer
grep -n "^## " README.md
```
Expected: 기존 섹션들 + "배포", "개발 모드 (LAN 원격 접속 테스트)" 두 섹션이 "개발" 섹션 앞에 위치

### Step 10.3: Commit

- [ ] Commit:
```bash
git add README.md
git commit -m "docs(readme): 배포/개발 모드 가이드 링크 추가"
```

---

## 최종 검증

### 전체 회귀 테스트
- [ ] Run:
```bash
cd /home/jhw/ai/opencode/projects/pcap-analyzer
python3 -m pytest tests/ -v -x --ignore=tests/e2e
```
Expected: 기존 모든 테스트 + 신규 3개 (test_app_entrypoint.py) PASS

### 빌드 + E2E 재현 (Task 7과 동일)
- [ ] 전체 플로우 한 번 더 돌려서 깨끗한 상태에서도 OK인지 확인.

### 결과 요약
- 신규 파일: 10개
- 변경 파일: 3개 (app.py, .gitignore, README.md)
- 신규 테스트: 3개
- 커밋: 9~10개 (Task별)

---

## Self-Review (작성 후 점검)

**Spec coverage** (spec 섹션 → 구현 Task 매핑):
- spec §4 (산출물 구조) → Task 6
- spec §5 (build-release.sh) → Task 6
- spec §6 (install.sh/install.bat) → Task 3
- spec §7 (run.sh/run.bat) → Task 4
- spec §8 (app.py 변경) → Task 1
- spec §9 (DEV.md) → Task 9
- spec §10 (신규/변경 파일 목록) → Task 1~10 전체
- spec §11 (검증 기준) → Task 7 + 최종 검증

**Type/이름 일관성**:
- `_run_dev_server` (Task 1) — 다른 Task에서 이 이름 사용 안 함, 일관됨
- 환경변수: `PCAP_HOST`, `PCAP_PORT`, `PCAP_DEV_RELOAD` — Task 1, 4, 9 모두 동일 키 사용
- 산출물 명명: `pcap-analyzer-${VERSION}.tar.gz` — Task 6, 7, 8 모두 일치
- `scripts/release-templates/` 경로 — Task 3, 4, 5, 6 모두 일치

**Placeholder**: `<VERSION>` 자리표시자만 의도된 곳에 존재 (INSTALL.md 사용자 안내, RELEASE.md, 산출물 파일명). 진짜 placeholder("TBD", "TODO") 없음.

**누락 점검**: 
- spec §5.3 "실패 처리" → Task 6의 `set -euo pipefail`로 커버
- spec §6.4 "실패 시 .venv 정리" → install.sh의 `set -euo pipefail` + venv가 부분 생성된 경우 다음 실행 시 재사용/덮어쓰기 (명시적 정리 없음 — venv는 멱등성이 있어 재실행이 안전, YAGNI)
- spec §11.6 "기존 pytest PASS" → 최종 검증에 포함

Self-review 통과.
