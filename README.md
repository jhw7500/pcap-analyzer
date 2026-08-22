# WLAN Pcap Analyzer

<!-- reviewer-canary: automation v1.45.2; intentionally unmerged -->

WLAN(802.11) pcap 파일을 업로드하면 `tshark`로 프레임을 추출하고, AP/STA 역할 자동 감지 → 11개 분석 모듈 실행 → 웹 대시보드에서 시각화하는 네트워크 디버깅 도구. 자동차 WiFi(88Q9098 칩셋) 환경을 주요 타겟으로 한다.

유선(포트 미러) pcap을 함께 업로드하면 ping 손실의 ground truth를 계산해 무선 관측 손실과 병기하고, 확정 손실 구간을 무선 이벤트(로밍·재전송)와 자동 대조한다. 설계: `docs/superpowers/specs/2026-08-03-multi-pcap-analysis-design.md`

동일 AP를 여러 위치에서 캡처한 무선 pcap을 최대 4개까지 함께 업로드하면(웹 폼 또는 CLI `--wireless` 반복 지정), 비콘 TSF 기반으로 캡처 간 시계 오프셋을 추정해 정렬한 뒤 중복 프레임을 제거하고 단일 타임라인으로 병합해 분석한다. 스니퍼별 초당 프레임·RSSI·재전송 시계열과 커버리지 분해(양쪽/단독 포착 비율), 프레임 출처 배지(w1/w2)로 스니퍼 배치를 평가할 수 있다.

## 주요 기능

- **자동 역할 감지**: Beacon/ProbeResp/BSSID 휴리스틱으로 AP와 STA 분리
- **11개 분석 모듈**: 개요, Retry MCS/Burst, 로밍, Ping RTT/Loss, 제어 트래픽, 신호 품질, 초당 통계, 로밍 영향, 종합 진단
- **Ping timeout 분류**: 업로드 화면에서 제한시간(기본 1초)을 설정하고 정상 응답,
  제한시간 이후 지연 응답, 끝까지 무응답을 각각 표시
- **종합 진단 탭**: 네트워크 건강도 점수 + 문제점 우선순위 리스트 + STA별 상세 진단
- **AI 리뷰**: Claude 또는 OpenAI API로 분석 결과 자동 해석 (선택)
- **리포트 export**: 마크다운 / 인쇄용 HTML / PDF(선택)로 분석 결과 외부 공유
- **진행률/취소**: 대용량 pcap 분석 중 실시간 진행률, tshark 프로세스 즉시 종료 가능
- **독립 로밍 교차검증**: 업로드 시 선택하면 analyzer를 재사용하지 않는 별도
  tshark·STA 로그 원장으로 로밍 건수와 150ms 판정을 재검산

## Quickstart

### 1. 시스템 의존성

```bash
sudo apt install tshark wireshark-common   # Debian/Ubuntu
# 또는 brew install wireshark              # macOS
# 또는 https://www.wireshark.org/          # Windows
```

- `tshark` — 프레임 추출(필수).
- `mergecap` — **분할 캡처 이어붙이기에만** 필요(선택). 스니퍼 로테이션으로 쪼개진
  조각을 한 번에 올릴 때 쓴다. 없으면 조각 여러 개 업로드가 `MERGECAP_MISSING`으로
  거부되지만, 파일 하나 업로드는 영향이 없다. Wireshark가 tshark와 함께 설치하므로
  대개 이미 있고(Debian/Ubuntu는 `wireshark-common` 패키지), 감지 시 tshark와 같은
  디렉터리를 먼저 본다.

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
2. (선택) WPA 암호화 해제용 SSID/passphrase, 필터(MAC/IP/시간), Ping timeout 입력
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
| `ui_offline_assets` | `PCAP_UI_OFFLINE_ASSETS` | **기본 `true`**(오프라인) — 로컬 `static/vendor/` 사용. `false`면 CDN(`cdn.tailwindcss.com`·`cdn.plot.ly`) |

## 리포트 export

분석 결과 페이지 상단 버튼으로 외부 공유용 리포트를 받을 수 있다.

| 버튼 | 경로 | 비고 |
|---|---|---|
| 📄 마크다운 리포트 | `/api/analysis/{id}/report.md` | 표준 GFM — pandoc/typora로 추가 변환 가능 |
| 🖨️ 인쇄용 리포트 | `/analysis/{id}/report` | 브라우저 인쇄(Ctrl+P)로 PDF 저장 — 모든 환경에서 동작 |
| 📑 PDF 다운로드 | `/api/analysis/{id}/report.pdf` | 서버측 PDF 생성 — playwright 설치 시에만 노출 (선택 기능) |

서버측 PDF는 선택 기능 (배포 산출물에 미포함):

```bash
pip install -r requirements-pdf.txt
playwright install chromium        # ~150MB 다운로드, 인터넷 필요
```

폐쇄망에서는 설치 불가 — 인쇄용 리포트로 동일 내용의 PDF를 저장하면 된다.
Linux 서버에서 PDF 한글이 깨지면 `fonts-noto-cjk` 설치.

## 캡처 시각 동기화 (timesync)

여러 장비에서 따로 뜬 pcap끼리, 그리고 pcap과 장비 로그 사이의 시계가 어긋나 있으면
같은 타임라인에서 볼 수 없다. NTP 프레임을 기준으로 어긋난 양을 측정하고 pcap
타임스탬프를 보정하는 CLI 도구가 `scripts/timesync-*.py`에 있다.

```bash
python3 scripts/timesync-batch.py <캠페인디렉터리> --out <출력루트> \
    --ssid <SSID> --psk <passphrase>
```

원본은 수정하지 않고 출력 디렉터리에 보정된 pcap을 만든다. 자세한 사용법·원리·
트러블슈팅은 `docs/TIMESYNC.md` 참조.

## EXPING 로그 도구 (exping)

시험에 쓰는 ping 도구 EXPING의 CSV/xlsx를 다루는 CLI 도구가 `scripts/exping-*.py`에 있다.

```bash
# CSV -> xlsx 무손실 변환 (원본 로그가 온전할 때)
python3 scripts/exping-csv-to-xlsx.py <csv...> --theme-from <기준xlsx>

# 로그가 잘렸거나 시계가 어긋났으면 보정된 pcap에서 재구성
python3 scripts/exping-from-pcap.py <pcap> --out-dir <디렉터리>
```

xlsx 출력에는 `pip install -r requirements-exping.txt`가 필요하다(csv만 쓰면 불필요).
역공학한 형식 규칙과 한계는 `docs/EXPING.md` 참조.

## 오프라인 환경(폐쇄망)

UI는 **기본이 오프라인 모드**(`ui_offline_assets=true`)라 Tailwind/Plotly를 로컬 `static/vendor/`에서 로드한다 — 인터넷 없이도 대시보드가 정상 렌더링된다.

- **배포본(release)**: `static/vendor/` 에셋이 포함되어 추가 작업 불필요.
- **소스에서 직접 실행**: 에셋을 먼저 받아둬야 화면이 깨지지 않는다.

```bash
make fetch-vendor          # curl로 static/vendor/에 tailwind.js·plotly.min.js 다운로드
```

CDN을 쓰려면(온라인 전용) 설정 페이지에서 "오프라인 에셋 사용"을 **해제**하거나 `PCAP_UI_OFFLINE_ASSETS=false`로 지정한다.

## 트러블슈팅

| 증상 | 원인/해결 |
|------|-----------|
| 설정 페이지에 "tshark: 미감지" | `tshark` 바이너리가 `PATH`에 없음. 설정 페이지에 절대 경로 입력 또는 `apt install tshark`. |
| 업로드 시 "유효한 pcap/pcapng 포맷이 아닙니다." | 파일이 실제 pcap이 아니거나 헤더 손상. `file`/`tshark -r` 로 먼저 검증. |
| 업로드 시 413 (상한 초과) | 파일별 기본 상한 1GB. `PCAP_MAX_UPLOAD_MB` 환경변수 또는 `config.local.json`의 `max_upload_mb`로 조정. |
| 업로드 시 413 (요청 합계 상한) | 한 요청의 임시 파일 합계가 8GB를 넘음(조각·다중 스니퍼·STA 로그 합산). 조각을 나눠 올리거나 `routes/upload._MAX_REQUEST_TOTAL_BYTES` 조정. |
| 분할 캡처 업로드가 "mergecap이 필요합니다"로 거부 | `mergecap` 미설치. `apt install wireshark-common` 또는 설정 페이지에서 경로 지정. 파일 하나만 올리면 필요 없다. |
| 디스크 여유가 적은 호스트 | 분석 중 임시 pcap이 최대 8GB(요청 합계 상한)까지 쓰인다. 여유가 적으면 `max_upload_mb`를 낮춰 잡을 것. |
| "프레임을 추출하지 못했습니다" | tshark 버전 호환성 문제 가능. 결과 JSON의 `tshark_version` 확인. 4.x 권장. |
| 분석이 멈춰 보임 | 수백만 프레임 pcap은 시간이 걸림. `/api/progress`로 확인. |
| 로밍이 감지되지 않음 | 캡처 시작 시점이 AP 전환 뒤라 Auth 프레임이 없을 수 있음. |

## 배포

압축 파일(`pcap-analyzer-<VERSION>.tar.gz` 또는 `.zip`)로 배포하려면:

```bash
bash scripts/build-release.sh
```

`dist/`에 OS별 압축 파일이 생성됨. 사용자용 설치 가이드는 `scripts/release-templates/INSTALL.md`(release 압축 안에서는 `docs/INSTALL.md`), 개발자용 빌드 옵션은 `docs/RELEASE.md` 참조.

### 상시 서비스 등록 (Linux, systemd user 서비스)

저장소 루트의 `pcap-analyzer.service`를 사용한다 — **파일 안의 절대 경로 2곳(`WorkingDirectory`, `ExecStart`)을 설치 경로에 맞게 수정한 뒤** 등록:

```bash
systemctl --user enable --now /절대/경로/pcap-analyzer.service   # 심볼릭 링크 등록 + 시작
loginctl enable-linger $USER                                     # 부팅 자동시작 (로그인 불필요)
```

관리: `systemctl --user {status|restart} pcap-analyzer`, 로그: `journalctl --user -u pcap-analyzer -f`. 유닛 수정 후에는 `systemctl --user daemon-reload && systemctl --user restart pcap-analyzer`.

## 개발 모드 (LAN 원격 접속 테스트)

호스트(Linux dev box)에서 코드 수정 + Windows PC 브라우저로 원격 접속 테스트하는 워크플로우는 `docs/DEV.md` 참조.

## 개발

```bash
make test             # 기본 테스트 (e2e/tshark/slow 제외)
make test-all         # 전체 테스트
make test-e2e         # Playwright e2e (서버 실행 필요)
make cov              # 커버리지 (목표 ≥80%)
```

실측 pcap과 STA `wpa.log`로 로밍 결과를 분석기와 별도 구현에서 교차 검증하려면
`scripts/roaming_independent_verify.py`를 사용한다. 사용법과 TEST14 기준값은
[`docs/ROAMING_INDEPENDENT_VERIFY.md`](docs/ROAMING_INDEPENDENT_VERIFY.md) 참조.
같은 기능은 웹 업로드의 분석 옵션에서 **독립 로밍 교차검증 실행**을 선택해 사용할
수 있으며, 완료 화면에서 일치 여부와 JSON/Markdown 보고서를 확인할 수 있다.
현재까지 실측 TEST별로 pcap-analyzer가 실제 출력한 모듈 요약·종합 진단·입력 예외는
[`docs/REAL_LOG_ANALYZER_RESULTS.md`](docs/REAL_LOG_ANALYZER_RESULTS.md)에 기록한다.

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

## 기여

커밋 메시지는 Conventional Commits 규약을 따른다 (`.github/commitlint.config.mjs` 참조).

## 라이선스

내부 도구. 외부 배포는 별도 협의.
