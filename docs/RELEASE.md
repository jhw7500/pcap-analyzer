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
- VERSION에 `/` 가 포함되면 자동으로 `-`로 치환 (`release/1.2.3` → `release-1.2.3`)

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

- Linux (Ubuntu 22.04 이상 권장; macOS/Windows는 미지원)
- Python 3.10+ (설치 대상과 동일 마이너 버전 권장 — wheel ABI 일치)
- 명령: `python3`, `pip`, `tar`, `zip`, `sha256sum`, `curl`, `rsync` (`git`은 선택 — 없으면 `0.0.0-nogit` 버전 사용)
- 인터넷 연결 (vendor + wheel 다운로드용 — 빌드 시점에만)
- (선택) `python3-dev`, `build-essential` — wheel 빌드 시 시스템 헤더 필요한 패키지가 있을 경우

## 산출물 검증

```bash
cd dist
sha256sum -c SHA256SUMS.txt
tar -tzf pcap-analyzer-*.tar.gz | head -20
```

### 제외 항목 누설 점검
```bash
tar -tzf pcap-analyzer-*.tar.gz | grep -E "(\.git/|/data/|/dist/|/\.bkit/|config\.local|\.pcap$|\.pcapng$|/test_iter|/test_playwright)" \
  && echo "FAIL: 제외 파일이 포함됨" \
  || echo "OK: 제외 목록 정상"
```

### 필수 항목 존재 점검
```bash
for f in VERSION app.py install.sh install.bat run.sh run.bat docs/INSTALL.md wheels/ static/vendor/; do
    tar -tzf pcap-analyzer-*.tar.gz | grep -qE "^pcap-analyzer-[^/]+/${f}" \
        && echo "  ${f}: OK" \
        || echo "  ${f}: MISSING"
done
```

## 자주 마주치는 이슈

| 증상 | 원인/해결 |
|---|---|
| `pip wheel` 실패 | requirements.txt에 시스템 헤더가 필요한 패키지. `sudo apt install python3-dev build-essential` |
| `make fetch-vendor` 실패 | 인터넷 차단 또는 CDN 차단. `SKIP_VENDOR=1`로 우회 후 사용자가 직접 vendor 채움 |
| `git describe` 빈 결과 | 태그 없음 (정상 — `0.0.0-<hash>`로 자동 생성됨) |
| wheel 호환 안 됨 | 빌드 호스트와 설치 대상의 Python 버전/OS 다름. 동일 환경에서 빌드하거나 `SKIP_WHEELS=1`로 PyPI 직접 설치 |
| `python3-venv` 없음 (설치 시) | 빌드는 OK지만 설치 대상에 패키지 누락. INSTALL.md에 안내됨 (`sudo apt install python3-venv`) |
| 한글 폴더 경로에서 venv 실패 (Windows 설치) | INSTALL.md에 영문 경로 권장 안내 있음 |

## 빌드 산출물 배포

`dist/`는 `.gitignore`에 의해 git 추적 제외. 다음 중 한 방식으로 사용자에게 전달:

- GitHub Releases 업로드 (SHA256SUMS.txt 함께)
- 사내 파일 서버 / SMB / scp
- USB로 폐쇄망 머신에 운반

## 재현성 (Reproducibility)

현재 빌드는 **바이트 단위 재현 불가**합니다 (이유):
- `make fetch-vendor`가 매번 fresh 다운로드 → vendor 파일 mtime 달라짐
- tar가 mtime을 보존 → 동일 커밋에서 SHA256 다를 수 있음

바이트 단위 재현이 필요하면 vendor를 한 번 다운로드한 뒤 staging 직전에 mtime을 고정하거나 `tar --mtime` 옵션을 추가하는 patch가 필요합니다 (현재 미구현).

## release 체크리스트

- [ ] 작업트리 깨끗 (`git status` 깨끗 또는 의도된 변경만)
- [ ] 태그 부여 (`git tag v0.1.0`) — 선택, 미부여 시 commit hash 사용
- [ ] `bash scripts/build-release.sh` 성공
- [ ] `sha256sum -c dist/SHA256SUMS.txt` 통과
- [ ] tar 안에 `.git/`, `data/`, `config.local.json`, `*.pcap` 없음 (위 "제외 항목 누설 점검")
- [ ] 로컬에서 E2E 1회: 압축 풀기 → install → run → `curl http://localhost:<port>/` 200 OK
- [ ] (선택) Windows에서 install.bat / run.bat 실제 동작 검증 (Linux 빌드 호스트에서는 visual inspection만 가능)
