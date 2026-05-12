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
    echo "  오프라인 우선 모드 (wheels/ + 필요 시 PyPI)"
    # wheels/와 PyPI를 모두 인덱스로 — 호환 wheel은 wheels/에서, 누락/ABI 불일치는 PyPI에서
    # (완전 폐쇄망 환경에서 wheels/만으로 충분하면 PyPI는 한 번도 호출되지 않음)
    if ! pip install --find-links wheels -r requirements.txt; then
        echo "  ERROR: 의존성 설치 실패"
        echo "  완전 폐쇄망에서 ABI 불일치(예: 빌드 호스트와 다른 Python 버전)면"
        echo "  빌드 호스트와 동일한 Python 마이너 버전(예: 3.10)을 설치 후 재시도하세요."
        exit 1
    fi
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
