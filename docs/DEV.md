# 개발 워크플로우 — 호스트 수정 + Windows PC 원격 접속

호스트(Linux dev box)에서 코드를 수정하면서 Windows PC 브라우저로 LAN 원격 접속하여 테스트하는 워크플로우.

> 배포(설치 가능한 압축물 만들기)는 `docs/RELEASE.md`, 압축 안 사용자용 안내는 `docs/INSTALL.md` (압축 안 / 소스에서는 `scripts/release-templates/INSTALL.md`) 참조.

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

# 의존성 (venv 권장)
cd <pcap-analyzer 디렉토리>
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 방화벽 허용 (ufw 사용 시)
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

**주의**: 분석 진행 중에 코드 저장하면 uvicorn 재시작으로 분석이 끊깁니다. 분석 끝낸 뒤 수정 권장. 또는 `PCAP_DEV_RELOAD=false python3 app.py`로 reload 끔.

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

## 9. dev vs 배포 차이 한눈에

| 측면 | 개발 (본 가이드) | 배포 (`docs/RELEASE.md`) |
|---|---|---|
| 실행 명령 | `python3 app.py` | `./run.sh` 또는 `run.bat` |
| reload | True (자동 재시작) | False (안정성) |
| venv | 직접 만들거나 생략 | install.sh가 자동 생성 |
| 의존성 | `pip install -r requirements.txt` | `wheels/`에서 오프라인 설치 |
| vendor | CDN 또는 `make fetch-vendor` | 압축에 동봉 |
