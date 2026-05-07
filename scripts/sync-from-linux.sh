#!/usr/bin/env bash
# pcap-analyzer 소스를 Linux 빌드 서버에서 Windows로 rsync (pull).
#
# 환경: Windows + Git Bash(mingw64) 또는 WSL.
# 방향: Linux dev box → 현재 디렉토리 (이 스크립트가 있는 클론).
#
# 사전 준비
#   1) rsync 설치 확인:        rsync --version
#   2) SSH 접근 가능 확인:     ssh "$PCAP_SYNC_HOST" exit
#      (비밀번호 매번 묻기 싫으면 ssh-keygen + ssh-copy-id 권장)
#   3) 필요시 환경변수 오버라이드 — 아래 SETTINGS 블록 참조
#
# 사용
#   bash scripts/sync-from-linux.sh                # 동기화 실행
#   DRY_RUN=1 bash scripts/sync-from-linux.sh      # 변경 사항 미리보기
#   DELETE=1  bash scripts/sync-from-linux.sh      # Linux에서 삭제된 파일도 반영
#   PCAP_SYNC_HOST=user@192.168.0.2 bash scripts/sync-from-linux.sh
#
# rsync가 Git Bash에 없을 경우
#   - MSYS2(pacman 사용 가능): pacman -S rsync
#   - 또는 WSL 사용: wsl bash scripts/sync-from-linux.sh
#   - 또는 cwRsync 등 별도 rsync 바이너리를 PATH에 추가

set -euo pipefail

# ── SETTINGS (환경변수로 오버라이드 가능) ─────────────────────────────
SRC_HOST="${PCAP_SYNC_HOST:-jhw@cantopsbuildserver}"
SRC_PATH="${PCAP_SYNC_SRC:-/home/jhw/ai/opencode/projects/pcap-analyzer/}"
SSH_PORT="${PCAP_SYNC_PORT:-22}"

# 스크립트가 클론 루트(scripts/ 상위)에서 실행됐다고 가정.
# 다른 위치라면 PCAP_SYNC_DEST 로 명시적으로 지정.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_DEST="$(cd "${SCRIPT_DIR}/.." && pwd)/"
DEST_PATH="${PCAP_SYNC_DEST:-${DEFAULT_DEST}}"

# ── rsync 존재 확인 ──────────────────────────────────────────────────
if ! command -v rsync >/dev/null 2>&1; then
    cat >&2 <<'EOF'
[ERROR] rsync 미설치.
  Git Bash(mingw64)에는 기본적으로 rsync가 포함돼 있지 않을 수 있습니다.

해결 방법
  1) MSYS2 사용 시:  pacman -S rsync
  2) WSL 설치 후:    wsl bash scripts/sync-from-linux.sh
  3) 외부 rsync 바이너리(cwRsync 등) 다운로드 후 PATH 등록
EOF
    exit 1
fi

# ── rsync 옵션 ───────────────────────────────────────────────────────
RSYNC_FLAGS=(
    --archive              # -rlptgoD: 권한/심볼릭링크/타임스탬프 보존
    --compress             # -z: 네트워크 전송 압축
    --human-readable       # -h: 사람 친화적 크기 표시
    --info=progress2,stats1
    --rsh="ssh -p ${SSH_PORT}"
)

[ "${DRY_RUN:-0}" = "1" ] && RSYNC_FLAGS+=(--dry-run --itemize-changes)
[ "${DELETE:-0}" = "1" ] && RSYNC_FLAGS+=(--delete)

# ── 필터 ─────────────────────────────────────────────────────────────
# include는 exclude보다 먼저 매칭되므로 순서 중요.
# tests/fixtures/*.pcap 은 회귀 테스트용이라 살림.
FILTERS=(
    --include=tests/
    --include=tests/fixtures/
    --include=tests/fixtures/*.pcap
    --include=tests/fixtures/*.pcapng
    # 이하 제외 항목
    --exclude=.git/
    --exclude=__pycache__/
    --exclude=*.pyc
    --exclude=.pytest_cache/
    --exclude=.ruff_cache/
    --exclude=.coverage
    --exclude=htmlcov/
    --exclude=data/analyses/
    --exclude=tmp/
    --exclude=static/vendor/
    --exclude=.bkit/
    --exclude=.omc/
    --exclude=.gstack/
    --exclude=.claude/
    --exclude=node_modules/
    --exclude=*.pcap
    --exclude=*.pcapng
    --exclude=config.local.json   # 로컬 설정 (Windows 측 자체 보존)
)

# ── 실행 ─────────────────────────────────────────────────────────────
echo "── pcap-analyzer sync ─────────────────────────"
echo "from : ${SRC_HOST}:${SRC_PATH}"
echo "to   : ${DEST_PATH}"
echo "flags: DRY_RUN=${DRY_RUN:-0} DELETE=${DELETE:-0}"
echo "──────────────────────────────────────────────"

rsync "${RSYNC_FLAGS[@]}" "${FILTERS[@]}" "${SRC_HOST}:${SRC_PATH}" "${DEST_PATH}"

echo
echo "[OK] 동기화 완료."
[ "${DRY_RUN:-0}" = "1" ] && echo "(DRY_RUN — 실제 적용은 DRY_RUN=0 또는 옵션 제거 후 재실행)"
