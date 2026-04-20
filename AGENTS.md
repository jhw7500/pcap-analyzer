<!-- Generated: 2026-04-09 | Updated: 2026-04-20 -->

# WLAN Pcap Analyzer

## Purpose
WLAN(802.11) pcap 파일을 업로드하면 tshark로 프레임을 추출하고, 자동으로 AP/STA 역할 감지, Retry/로밍/Ping/신호 품질 등 11개 분석 모듈을 실행하여 웹 대시보드에서 시각화하는 네트워크 디버깅 도구. 자동차 WiFi(88Q9098 칩셋) 환경을 주요 타겟으로 한다.

사용자용 Quickstart는 `README.md` 참조.

## Key Files

| File | Description |
|------|-------------|
| `app.py` | FastAPI 앱 진입점 — 라우터 등록, static/templates 마운트, startup 시 tshark 경로+버전 로깅 |
| `config.py` | 설정 관리 — JSON + 환경변수 폴백, tshark 경로 감지, 업로드 상한, `safe_analysis_path()` (path traversal 방어), `mask_secret()`, `is_offline_assets()` |
| `README.md` | 사용자용 문서 — 설치/실행/설정 키/트러블슈팅 |
| `Makefile` | `make test/test-all/cov/fetch-vendor` |
| `requirements.txt` | Python 의존성 (fastapi, uvicorn, jinja2, httpx, sse-starlette) |
| `test_iterate.py` / `test_iter2.py` | 반복 테스트 스크립트 |
| `test_playwright.py` | Playwright 브라우저 테스트 |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `analyzer/` | 핵심 분석 엔진 — tshark 추출, 프레임 인덱싱, 11개 분석 모듈, 웹 시각화 데이터 생성 (see `analyzer/AGENTS.md`) |
| `routes/` | FastAPI 라우트 핸들러 — 업로드, 분석 결과 조회, AI 리뷰, 설정 (see `routes/AGENTS.md`) |
| `ai/` | AI 리뷰 모듈 — Claude/OpenAI API를 통한 분석 결과 자동 리뷰 (see `ai/AGENTS.md`) |
| `templates/` | Jinja2 HTML 템플릿 — 대시보드 레이아웃, 분석 결과 시각화 (see `templates/AGENTS.md`) |
| `static/` | 정적 파일 — CSS, JavaScript (차트 렌더링, 업로드 UI, 타임라인) (see `static/AGENTS.md`) |
| `data/` | 분석 결과 JSON 저장소 |
| `tmp/` | 임시 파일 (스크린샷, pcap 등) — git에 포함하지 않음 |

## For AI Agents

### Working In This Directory
- Python 3.10+ 환경. FastAPI + Uvicorn 기반.
- `tshark`(Wireshark CLI)가 시스템에 설치되어 있어야 pcap 분석 가능.
- 설정은 `config.local.json` 파일 또는 `PCAP_*` 환경변수로 관리.
- 분석 결과는 `data/analyses/` 디렉토리에 JSON으로 저장.

### Testing Requirements
- `python -m pytest` 로 테스트 실행.
- Playwright 테스트: `python test_playwright.py`.
- tshark가 설치된 환경에서만 실제 pcap 분석 테스트 가능.

### Common Patterns
- 분석 모듈은 `analyze(frames, roles, index) -> AnalysisSection` 시그니처를 따름.
- `pipeline.py`는 오케스트레이션만 담당. `structured` 데이터 생성은 `analyzer/web/structured.py`.
- 웹 시각화 데이터는 `structured` 딕셔너리에 중첩 구조로 저장.
- API 에러 응답은 `analyzer/errors.py`의 `error_payload()`로 `{error, code, hint}` 3필드 통일.
- analysis_id는 `config.safe_analysis_path()`로 반드시 검증 (path traversal 방어).
- 한국어 UI/메시지 사용.

## Dependencies

### External
- `fastapi` — 웹 프레임워크
- `uvicorn` — ASGI 서버
- `jinja2` — HTML 템플릿 엔진
- `httpx` — AI API 비동기 HTTP 클라이언트
- `plotly.js` (CDN 또는 `static/vendor/` 로컬) — 차트 렌더링
- `tailwindcss` (CDN 또는 `static/vendor/` 로컬) — CSS 프레임워크
- `tshark` (시스템) — pcap 파싱. `detect_tshark_version()`으로 버전을 분석 메타데이터에 기록.
- `scapy` (dev only) — 테스트 fixture pcap 생성

<!-- MANUAL: -->
