# pcap-analyzer 배포 & 개발 워크플로우 설계

- **작성일**: 2026-05-12
- **대상**: pcap-analyzer (WLAN 802.11 pcap 분석 도구)
- **목적**: (1) 단일 명령으로 배포 압축물을 만들고 (2) 사용자가 압축을 풀어 한 줄로 설치·실행 가능하게 하며 (3) Linux 호스트 1대 + Windows PC 원격 접속 개발 워크플로우를 문서화한다.

## 1. 배경 & 동기

현재 프로젝트에는 README의 Quickstart 외에 배포 가이드가 없다. 운영/테스트 환경에서 다음 사용자 시나리오를 지원해야 한다.

1. **사용자 배포** — 엔지니어가 Linux 또는 Windows 머신에 도구를 설치하여 본인 PC에서 단발 분석 수행.
2. **개발 테스트** — 개발자가 Linux dev box에서 코드를 수정하면서 Windows PC 브라우저로 원격 접속 테스트.

두 시나리오 모두 인터넷 가능/폐쇄망 환경 모두에서 동작해야 하며, tshark 시스템 의존성은 자동 설치하지 않고 안내만 한다.

## 2. 비-스코프 (Not in scope)

- Docker 이미지, docker-compose
- systemd unit, Windows Service, nssm 등 서비스 등록
- 리버스 프록시(nginx) / HTTPS / 인증
- 다중 워커, 다중 인스턴스, 로드 밸런싱
- 자동 업데이트 메커니즘
- 데이터 마이그레이션
- Windows에서 tshark 자동 설치
- 임베디드/ARM 타깃 (현재는 x86_64 Linux + Windows만)

## 3. 결정사항 요약

| 항목 | 결정 |
|---|---|
| 대상 OS | Linux + Windows |
| 인터넷 | 온라인/오프라인 둘 다 (wheel + vendor 동봉, PyPI fallback) |
| tshark | 존재 여부 체크 + OS별 설치 명령 안내 (자동 설치 없음) |
| 실행 방식 | 단발 포그라운드 (`run.sh` / `run.bat`), Ctrl+C 종료 |
| 산출물 | `dist/` 디렉토리에 tar.gz + zip 동시 생성, git 제외 |
| 버전 | `git describe --tags --always --dirty` 자동 |
| Python 격리 | 압축 풀린 디렉토리 안에 `.venv/` 생성 (시스템 오염 방지) |
| dev 가이드 | `docs/DEV.md` 별도 문서 + README 링크 |

## 4. 산출물 구조

### 4.1 빌드 결과 (`dist/`)

```
dist/
├── pcap-analyzer-<VERSION>.tar.gz       # Linux 권장
├── pcap-analyzer-<VERSION>.zip          # Windows 권장
└── SHA256SUMS.txt                       # 무결성 검증
```

두 압축 파일의 **내용물은 동일**하다. 형식만 OS native 친화로 분리한다.

### 4.2 압축 해제 후 디렉토리

```
pcap-analyzer-<VERSION>/
├── app.py
├── config.py
├── requirements.txt
├── README.md
├── AGENTS.md
├── Makefile
├── VERSION                              # git describe 결과 1줄
├── analyzer/
├── routes/
├── ai/
├── templates/
├── static/
│   └── vendor/                          # Tailwind, Plotly 사전 다운로드
├── tests/
├── wheels/                              # pip wheel 산출물 (오프라인용)
├── install.sh                           # Linux/macOS 설치
├── install.bat                          # Windows 설치
├── run.sh                               # Linux/macOS 실행
├── run.bat                              # Windows 실행
└── docs/
    └── INSTALL.md                       # 사용자 설치 가이드
```

### 4.3 빌드 시 제외 (`scripts/release-exclude.txt`)

```
.git/
.gitignore
.venv/
__pycache__/
*.pyc
.pytest_cache/
.ruff_cache/
.coverage
htmlcov/
.bkit/
.omc/
.playwright-mcp/
data/
tmp/
config.local.json
docs/01-plan/
docs/03-analysis/
docs/04-report/
docs/archive/
docs/superpowers/
*.png                                   # 루트의 스크린샷 PNG
dist/
```

## 5. 빌드 스크립트 (`scripts/build-release.sh`)

### 5.1 동작 흐름

```
[1] 사전 체크
    ├── 명령 존재: python3, pip, git, tar, zip, rsync, curl, sha256sum
    └── 빌드 호스트가 인터넷 접근 가능 (vendor + wheel 다운로드용)

[2] 버전 결정
    └── VERSION = $(git describe --tags --always --dirty)

[3] 작업 디렉토리 준비
    ├── rm -rf dist/build/
    └── mkdir -p dist/build/pcap-analyzer-${VERSION}/

[4] 소스 복사
    └── rsync -a --exclude-from=scripts/release-exclude.txt ./ \
        dist/build/pcap-analyzer-${VERSION}/

[5] vendor 에셋 다운로드
    └── (cd dist/build/pcap-analyzer-${VERSION} && make fetch-vendor)

[6] wheel 빌드
    └── pip wheel -r dist/build/pcap-analyzer-${VERSION}/requirements.txt \
        -w dist/build/pcap-analyzer-${VERSION}/wheels/

[7] 설치/실행 스크립트 + INSTALL.md 복사
    └── cp scripts/release-templates/{install.sh,install.bat,run.sh,run.bat} \
          dist/build/pcap-analyzer-${VERSION}/
        cp scripts/release-templates/INSTALL.md \
          dist/build/pcap-analyzer-${VERSION}/docs/

[8] VERSION 파일
    └── echo "${VERSION}" > dist/build/pcap-analyzer-${VERSION}/VERSION

[9] 압축 생성
    ├── (cd dist/build && tar -czf ../pcap-analyzer-${VERSION}.tar.gz \
    │     pcap-analyzer-${VERSION})
    └── (cd dist/build && zip -qr ../pcap-analyzer-${VERSION}.zip \
          pcap-analyzer-${VERSION})

[10] 체크섬
    └── (cd dist && sha256sum *.tar.gz *.zip > SHA256SUMS.txt)

[11] staging 정리
    └── rm -rf dist/build/
```

### 5.2 옵션

| 환경변수 | 기본 | 설명 |
|---|---|---|
| `VERSION` | `git describe --tags --always --dirty` | 명시적 버전 override |
| `SKIP_WHEELS` | `0` | `1`이면 wheel 빌드 생략 (온라인 전용 배포 시) |
| `SKIP_VENDOR` | `0` | `1`이면 vendor 다운로드 생략 (CDN 사용 환경) |

### 5.3 실패 처리

- 각 단계 실패 시 즉시 `exit` + 어느 단계에서 실패했는지 한 줄 출력
- `set -euo pipefail` 사용
- staging 디렉토리는 다음 빌드 시작 시점에 정리되므로 잔존 허용

## 6. 설치 스크립트 (`install.sh` / `install.bat`)

### 6.1 동작 흐름 (두 스크립트 공통)

```
[1/5] 시스템 의존성 확인
      ├── Python 3.10+ 존재? (python3 --version)
      │    없으면 → OS별 설치 안내 후 exit 1
      └── tshark 존재? (tshark --version)
           없으면 →
              Linux:   "sudo apt install tshark" 안내
              macOS:   "brew install wireshark" 안내
              Windows: "https://www.wireshark.org/" 안내
           후 exit 1

[2/5] Python 가상환경
      ├── .venv/ 존재 → 재사용 (사용자에게 알림)
      └── 없으면 → python3 -m venv .venv

[3/5] 의존성 설치
      ├── wheels/ 비어있지 않음?
      │    YES → pip install --no-index --find-links wheels \
      │           -r requirements.txt           (오프라인 모드)
      │    NO  → pip install -r requirements.txt
      │                                         (PyPI 모드)
      └── pip 자체는 venv의 것 사용

[4/5] Smoke test
      ├── python -c "import fastapi, uvicorn, jinja2, httpx"
      └── python -c "import config; print(config.detect_tshark())"

[5/5] 완료
      ├── VERSION 출력
      ├── Python 경로 출력
      ├── tshark 경로 출력
      └── "다음 단계: ./run.sh  (Windows: run.bat)" 안내
```

### 6.2 로그

- 화면: 단계별 1줄 진행 메시지 (`[1/5] Python 확인 중...`)
- 파일: `install.log`에 상세 (pip stdout/stderr 포함) tee

### 6.3 비-대화형

- 사용자 입력 요구 없음
- tshark 비표준 경로는 설치 후 `config.local.json`에서 수동 지정 (INSTALL.md에 명시)

### 6.4 실패 시

- 단계별 실패 시 즉시 exit 1 + `install.log` 위치 안내
- `.venv/` 생성 도중 실패 시 부분 디렉토리 정리

## 7. 실행 스크립트 (`run.sh` / `run.bat`)

### 7.1 동작 흐름

```
[1] .venv/ 존재 확인
    └── 없으면 "install부터 실행하세요" 안내 후 exit 1

[2] venv 활성화
    ├── Linux: source .venv/bin/activate
    └── Windows: .venv\Scripts\activate.bat

[3] (선택) .env 로드
    └── 파일 있으면 환경변수로 source

[4] reload 끄기
    └── export PCAP_DEV_RELOAD=false

[5] 시작 배너 출력
    ─────────────────────────────────────────
    pcap-analyzer v<VERSION>
    접속 URL:
      http://localhost:8000
      http://<자동감지 IP>:8000   (LAN)
    종료: Ctrl+C
    ─────────────────────────────────────────

[6] python app.py  (포그라운드)

[7] 종료 시
    └── trap으로 venv deactivate
```

### 7.2 환경변수

| 변수 | 기본 | 설명 |
|---|---|---|
| `PCAP_HOST` | `0.0.0.0` | 바인딩 호스트 |
| `PCAP_PORT` | `8000` | 포트 |
| `PCAP_DEV_RELOAD` | `false` (run.sh에서 강제) | uvicorn reload (배포에선 끔) |
| `PCAP_TSHARK_PATH` | (자동 감지) | tshark 비표준 경로 |
| `PCAP_AI_PROVIDER` | (없음) | claude / openai |
| `PCAP_AI_API_KEY` | (없음) | AI API 키 |
| `PCAP_AI_MODEL` | (없음) | 예: claude-sonnet-4-6 |
| `PCAP_UI_OFFLINE_ASSETS` | `true` (vendor 있을 때) | CDN 대신 로컬 vendor 사용 |

### 7.3 자동감지 IP

- Linux: `hostname -I | awk '{print $1}'`
- Windows: `for /f "tokens=2 delims=:" %a in ('ipconfig ^| findstr "IPv4"') do @echo %a` 첫 결과
- 감지 실패 시 LAN URL 줄만 생략

### 7.4 포트 충돌

- 별도 사전 체크 없이 uvicorn의 `address already in use` 메시지 그대로 노출
- INSTALL.md에 "다른 프로세스가 8000을 점유 중이면 `PCAP_PORT=9000 ./run.sh`" 안내

## 8. `app.py` 변경

### 8.1 현재 상태

```python
if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
```

문제: `reload=True`가 배포에서도 켜져 있다. 포트/호스트도 하드코딩.

### 8.2 변경 후

```python
import os

if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host=os.getenv("PCAP_HOST", "0.0.0.0"),
        port=int(os.getenv("PCAP_PORT", "8000")),
        reload=os.getenv("PCAP_DEV_RELOAD", "true").lower() == "true",
    )
```

### 8.3 영향

- **dev (`python3 app.py`)**: 환경변수 미설정 → 현재와 100% 동일 (0.0.0.0:8000, reload=True)
- **배포 (`run.sh`)**: `PCAP_DEV_RELOAD=false`를 export 한 뒤 `python app.py` → reload만 off
- **테스트**: 신규 케이스 1개 추가 — env override가 uvicorn.run 인자에 반영되는지 확인 (모킹)

## 9. 개발 워크플로우 가이드 (`docs/DEV.md`)

### 9.1 시나리오

호스트(Linux dev box)에서 코드 수정 + 즉시 실행, Windows PC 브라우저로 LAN 접속하여 테스트.

### 9.2 문서 섹션

1. **사전 준비**
   - Linux: Python 3.10+, tshark, 8000 포트 방화벽 허용(`sudo ufw allow 8000`)
   - Windows: 최신 브라우저 (Chrome/Edge/Firefox)
   - 같은 LAN에 두 머신이 ping 가능해야 함
2. **시작 / 종료**
   - `python3 app.py` (포그라운드, Ctrl+C 종료)
   - venv는 선택 (시스템 pip로도 동작)
3. **LAN 접속**
   - Linux IP 확인: `hostname -I | awk '{print $1}'`
   - Windows에서 `ping <IP>` → `http://<IP>:8000`
4. **코드 수정 워크플로우**
   - 파일 저장 → uvicorn이 자동 감지 → 재시작 → Windows 브라우저 새로고침
   - 분석 진행 중 코드 수정 시 재시작 위험 — 분석은 끝낸 뒤 수정 권장
5. **pcap 파일 전달**
   - (A) Windows 브라우저에서 드래그&드롭 업로드 (가장 단순)
   - (B) 호스트 `data/pcap/` 디렉토리에 scp/rsync로 미리 둠
6. **트러블슈팅**
   - 접속 불가: 방화벽 / IP 오타 / 8000 점유 / `host="0.0.0.0"` 확인
   - reload 안 됨: uvicorn은 디렉토리 구조 변경에만 반응. `.py` 저장은 즉시 반영
   - 진행률 멈춤: tshark 단계는 분 단위 소요 가능 (`/api/progress` 확인)
7. **`sync-from-linux.sh`와의 관계**
   - 기존 스크립트는 "Windows에 별도 클론을 두고 rsync로 갱신"하는 패턴
   - 본 가이드는 "Linux 서버 단일 인스턴스 + 원격 접속"
   - 둘은 배타적 — 팀 합의 후 한쪽만 사용

### 9.3 README 변경

README에 두 줄 추가:

```markdown
## 배포

압축 산출물 만들기·설치·실행은 `docs/INSTALL.md` 및 빌드 스크립트 안내는 `docs/RELEASE.md` 참조.

## 개발 모드 (LAN 원격 접속 테스트)

호스트에서 수정 + Windows PC 접속 테스트 흐름은 `docs/DEV.md` 참조.
```

## 10. 신규/변경 파일 목록

### 10.1 신규

| 경로 | 내용 |
|---|---|
| `scripts/build-release.sh` | 빌드 오케스트레이션 (실행 권한 `+x`) |
| `scripts/release-exclude.txt` | rsync 제외 목록 |
| `scripts/release-templates/install.sh` | Linux/macOS 설치 (실행 권한 `+x`) |
| `scripts/release-templates/install.bat` | Windows 설치 |
| `scripts/release-templates/run.sh` | Linux/macOS 실행 (실행 권한 `+x`) |
| `scripts/release-templates/run.bat` | Windows 실행 |
| `scripts/release-templates/INSTALL.md` | 사용자용 설치 가이드 (압축 동봉) |
| `docs/RELEASE.md` | 개발자용 빌드 가이드 |
| `docs/DEV.md` | LAN 원격 접속 개발 가이드 |

### 10.2 변경

| 경로 | 변경 |
|---|---|
| `app.py` | `__main__` 블록을 환경변수 override로 변경 (3줄) |
| `.gitignore` | `dist/` 추가 |
| `README.md` | "배포" / "개발 모드" 섹션 2개 추가 (각 2~3줄) |
| `tests/` | `app.py` env override 동작 테스트 1개 추가 |

## 11. 검증 기준 (acceptance criteria)

### 11.1 빌드

- [ ] `bash scripts/build-release.sh`가 clean 작업트리에서 무오류 종료
- [ ] `dist/` 안에 tar.gz, zip, SHA256SUMS.txt 3종 생성
- [ ] tar.gz와 zip의 SHA256가 각각 SHA256SUMS.txt와 일치
- [ ] 두 압축의 콘텐츠 파일 목록이 동일 (`tar tzf` vs `unzip -l` 정렬 비교)
- [ ] 압축 안에 `.git/`, `data/`, `.bkit/`, `config.local.json`이 없음
- [ ] 압축 안에 `wheels/`, `static/vendor/`, `VERSION`이 있음

### 11.2 설치 (Linux)

- [ ] `tar -xzf dist/pcap-analyzer-*.tar.gz && cd pcap-analyzer-*`
- [ ] `./install.sh`가 5단계 모두 OK 출력하며 종료
- [ ] `.venv/`, `install.log` 생성됨
- [ ] tshark 없는 환경에서 install.sh가 step 1에서 안내 후 exit 1
- [ ] 폐쇄망(인터넷 차단) 환경에서도 `wheels/`만으로 설치 완료

### 11.3 설치 (Windows)

- [ ] `unzip` 또는 탐색기로 압축 풀기 → `install.bat` 더블클릭 또는 실행
- [ ] 동일하게 5단계 진행, `.venv\` 생성
- [ ] tshark 없으면 wireshark.org 안내 후 종료

### 11.4 실행

- [ ] `./run.sh` 또는 `run.bat` 실행 시 배너에 LAN URL 표시
- [ ] `curl http://localhost:8000/` → 200 OK + HTML 응답
- [ ] Windows PC에서 LAN URL로 접속 → 메인 페이지 정상 표시
- [ ] `Ctrl+C`로 종료, venv 활성화 흔적 없음 (`which python3`가 시스템 Python)

### 11.5 dev 워크플로우

- [ ] `python3 app.py` 직접 실행 → reload=True, host=0.0.0.0, port=8000 (현재와 동일)
- [ ] `PCAP_DEV_RELOAD=false python3 app.py` → reload off
- [ ] `PCAP_PORT=9000 python3 app.py` → 9000 포트 바인딩
- [ ] `docs/DEV.md` 절차대로 진행 시 Windows PC에서 정상 접속

### 11.6 회귀

- [ ] 기존 pytest 스위트 PASS
- [ ] `app.py` 단위 테스트 1개 추가 PASS

## 12. 리스크 & 완화

| 리스크 | 완화 |
|---|---|
| 빌드 호스트의 Python ABI/플랫폼이 설치 대상과 다르면 wheel 호환 안 됨 | INSTALL.md에 "빌드 호스트와 동일 OS/Python 마이너 버전 권장" 명시. 다르면 `pip install -r requirements.txt`(PyPI) fallback 자동 동작 |
| Windows 8.3 short path / 한글 경로 이슈 | INSTALL.md에 "영문 경로 권장" 안내 |
| LAN 접속 시 사내 방화벽 차단 | DEV.md 트러블슈팅에 ufw / Windows Defender 방화벽 안내 |
| `reload=True` 기본값 변경으로 기존 dev 워크플로우 영향 | 기본값을 `true`로 유지 (현재 동작과 동일), run.sh에서만 명시적 `false` |
| 큰 wheel 디렉토리로 압축 크기 증가 | `SKIP_WHEELS=1` 환경변수로 온라인 전용 슬림 배포 옵션 |

## 13. 향후 확장 (out of scope, 참고만)

- systemd unit / Windows Service 등록 스크립트
- Docker 이미지 (멀티스테이지 빌드)
- 자동 업데이트 (체크섬 비교 + 재설치)
- HTTPS 리버스 프록시 가이드
- 다중 사용자 인증
