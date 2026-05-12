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
