#!/usr/bin/env bash
# pcap-analyzer 개발 환경 부트스트랩 + 실행
# Usage:
#   bash scripts/dev-run.sh                 # venv 준비 후 app.py 실행
#   bash scripts/dev-run.sh --setup-only    # 설치만 (실행 안 함)
#   PCAP_PORT=9000 bash scripts/dev-run.sh  # 포트 변경
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
VENV="${ROOT}/.venv"
REQ="${ROOT}/requirements.txt"
STAMP="${VENV}/.requirements.sha256"

SETUP_ONLY=0
for arg in "$@"; do
    case "${arg}" in
        --setup-only) SETUP_ONLY=1 ;;
        -h|--help)
            sed -n '2,7p' "$0"
            exit 0
            ;;
        *)
            echo "  ERROR: 알 수 없는 인자: ${arg}"
            exit 2
            ;;
    esac
done

# [1] python3 / tshark 사전 체크
echo "[1] 사전 체크"
if ! command -v python3 >/dev/null 2>&1; then
    echo "  ERROR: python3 가 필요합니다."
    exit 1
fi
if ! command -v tshark >/dev/null 2>&1; then
    echo "  WARNING: tshark 미감지. 'sudo apt install tshark' 권장 (없어도 설치는 진행)."
fi
echo "  OK ($(python3 --version))"

# [2] venv 준비 (없으면 생성)
echo "[2] venv: ${VENV}"
if [[ ! -d "${VENV}" ]]; then
    if ! python3 -m venv "${VENV}" 2>/tmp/venv-err.log; then
        echo "  ERROR: venv 생성 실패. 'sudo apt install python3-venv python3-full' 후 재시도."
        cat /tmp/venv-err.log
        exit 1
    fi
    echo "  생성 완료"
else
    echo "  재사용"
fi

# shellcheck disable=SC1091
source "${VENV}/bin/activate"

# [3] requirements.txt 해시가 변했을 때만 pip install
echo "[3] 의존성 동기화"
CUR_HASH="$(sha256sum "${REQ}" | awk '{print $1}')"
PREV_HASH="$(cat "${STAMP}" 2>/dev/null || echo "")"
if [[ "${CUR_HASH}" != "${PREV_HASH}" ]]; then
    python3 -m pip install --upgrade pip >/dev/null
    python3 -m pip install -r "${REQ}"
    echo "${CUR_HASH}" > "${STAMP}"
    echo "  설치/업데이트 완료"
else
    echo "  최신 상태 (skip)"
fi

if [[ "${SETUP_ONLY}" == "1" ]]; then
    echo "[4] --setup-only: 종료"
    echo "    실행하려면:  source .venv/bin/activate && python3 app.py"
    exit 0
fi

# [4] 서버 실행
HOST="${PCAP_HOST:-0.0.0.0}"
PORT="${PCAP_PORT:-8000}"
echo "[4] 서버 시작 → http://${HOST}:${PORT}  (Ctrl+C 로 종료)"
exec python3 app.py
