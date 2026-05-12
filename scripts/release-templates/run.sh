#!/usr/bin/env bash
# pcap-analyzer 실행 (Linux/macOS, 포그라운드)
# Usage: ./run.sh
set -euo pipefail

# 스크립트 위치를 cwd로
cd "$(dirname "$0")"

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
# shellcheck disable=SC2034
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
