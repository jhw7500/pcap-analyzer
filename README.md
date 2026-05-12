# WLAN Pcap Analyzer

WLAN(802.11) pcap 파일을 업로드하면 `tshark`로 프레임을 추출하고, AP/STA 역할 자동 감지 → 11개 분석 모듈 실행 → 웹 대시보드에서 시각화하는 네트워크 디버깅 도구. 자동차 WiFi(88Q9098 칩셋) 환경을 주요 타겟으로 한다.

## 주요 기능

- **자동 역할 감지**: Beacon/ProbeResp/BSSID 휴리스틱으로 AP와 STA 분리
- **11개 분석 모듈**: 개요, Retry MCS/Burst, 로밍, Ping RTT/Loss, 제어 트래픽, 신호 품질, 초당 통계, 로밍 영향, 종합 진단
- **종합 진단 탭**: 네트워크 건강도 점수 + 문제점 우선순위 리스트 + STA별 상세 진단
- **AI 리뷰**: Claude 또는 OpenAI API로 분석 결과 자동 해석 (선택)
- **진행률/취소**: 대용량 pcap 분석 중 실시간 진행률, tshark 프로세스 즉시 종료 가능

## Quickstart

### 1. 시스템 의존성

```bash
sudo apt install tshark                # Debian/Ubuntu
# 또는 brew install wireshark          # macOS
# 또는 https://www.wireshark.org/      # Windows
```

### 2. Python 의존성

```bash
git clone <this-repo>
cd pcap-analyzer
pip install -r requirements.txt
```

### 3. 실행

```bash
python3 app.py
```

브라우저에서 `http://localhost:8000` 열기.

### 4. 분석

1. 메인 페이지에서 `.pcap`/`.pcapng`/`.cap` 파일 드래그 또는 선택
2. (선택) WPA 암호화 해제용 SSID/passphrase, 필터(MAC/IP/시간) 입력
3. "분석 시작" 클릭 → 진행률 표시 → 결과 페이지 자동 이동
4. (선택) 결과 페이지에서 "AI 리뷰" 버튼으로 자동 해석

## 설정

설정 페이지(`/settings`)에서 GUI로 변경하거나 환경변수/`config.local.json`으로 지정.

| 키 | 환경변수 | 설명 |
|---|---|---|
| `tshark_path` | `PCAP_TSHARK_PATH` | tshark 바이너리 경로 (자동 감지됨) |
| `ai_provider` | `PCAP_AI_PROVIDER` | `claude` / `openai` / 빈 값(비활성화) |
| `ai_api_key` | `PCAP_AI_API_KEY` | API 키 (환경변수 권장) |
| `ai_model` | `PCAP_AI_MODEL` | 예: `claude-sonnet-4-6` |
| `ai_auto_review` | `PCAP_AI_AUTO_REVIEW` | 분석 완료 시 자동 AI 리뷰 |
| `ui_offline_assets` | `PCAP_UI_OFFLINE_ASSETS` | `true`면 CDN 대신 `static/vendor/` 사용 |

## 오프라인 환경(폐쇄망)

Tailwind/Plotly CDN을 못 쓰는 환경:

```bash
make fetch-vendor          # curl로 static/vendor/에 다운로드
# 그다음 설정 페이지에서 "오프라인 에셋 사용" 체크
```

## 트러블슈팅

| 증상 | 원인/해결 |
|------|-----------|
| 설정 페이지에 "tshark: 미감지" | `tshark` 바이너리가 `PATH`에 없음. 설정 페이지에 절대 경로 입력 또는 `apt install tshark`. |
| 업로드 시 "유효한 pcap/pcapng 포맷이 아닙니다." | 파일이 실제 pcap이 아니거나 헤더 손상. `file`/`tshark -r` 로 먼저 검증. |
| 업로드 시 413 | `MAX_UPLOAD_SIZE`(기본 200MB) 초과. `config.py`에서 조정 가능. |
| "프레임을 추출하지 못했습니다" | tshark 버전 호환성 문제 가능. 결과 JSON의 `tshark_version` 확인. 4.x 권장. |
| 분석이 멈춰 보임 | 수백만 프레임 pcap은 시간이 걸림. `/api/progress`로 확인. |
| 로밍이 감지되지 않음 | 캡처 시작 시점이 AP 전환 뒤라 Auth 프레임이 없을 수 있음. |

## 배포

압축 파일(`pcap-analyzer-<VERSION>.tar.gz` 또는 `.zip`)로 배포하려면:

```bash
bash scripts/build-release.sh
```

`dist/`에 OS별 압축 파일이 생성됨. 사용자용 설치 가이드는 `scripts/release-templates/INSTALL.md`(release 압축 안에서는 `docs/INSTALL.md`), 개발자용 빌드 옵션은 `docs/RELEASE.md` 참조.

## 개발 모드 (LAN 원격 접속 테스트)

호스트(Linux dev box)에서 코드 수정 + Windows PC 브라우저로 원격 접속 테스트하는 워크플로우는 `docs/DEV.md` 참조.

## 개발

```bash
make test             # 기본 테스트 (e2e/tshark/slow 제외)
make test-all         # 전체 테스트
make test-e2e         # Playwright e2e (서버 실행 필요)
make cov              # 커버리지 (목표 ≥80%)
```

## 디렉토리 구조

```
analyzer/
  core/       프레임 추출, 역할 감지, 인덱싱, 분석 모듈
  web/        웹 시각화용 structured 데이터 생성
routes/       FastAPI 라우트 핸들러
ai/           Claude/OpenAI API 호출
templates/    Jinja2 HTML
static/       CSS/JS/(vendor)
tests/        pytest (fixtures/ 포함)
```

자세한 내부 구조는 각 디렉토리의 `AGENTS.md` 참조.

## 라이선스

내부 도구. 외부 배포는 별도 협의.
