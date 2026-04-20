<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-09 | Updated: 2026-04-20 -->

# analyzer

## Purpose
pcap 분석의 핵심 엔진. `pipeline.py`가 전체 분석 흐름을 오케스트레이션하며, `core/`에서 프레임 추출·인덱싱·역할 감지를 수행하고, `core/modules/`의 11개 분석 모듈이 각 관점(Retry, 로밍, Ping, 신호 등)을 분석한다. `web/`은 웹 시각화 전용 추가 분석(지연 구간, 이상 프레임, RSSI cliff, structured 데이터)을 제공한다. `errors.py`는 API 에러 코드 카탈로그.

## Key Files

| File | Description |
|------|-------------|
| `pipeline.py` | 분석 파이프라인 오케스트레이터 — `extract_frames` → `detect_roles` → `FrameIndex` → 11개 모듈 → structured 생성. `run_analysis()` 진입점. 진행률 콜백 + `cancel_event` (tshark 프로세스 kill 포함). 반환 dict에 `tshark_version`/`tshark_path` 메타 포함. |
| `errors.py` | `ErrorCode` enum + `ERROR_CATALOG` + `error_payload(code, extra_message="")` — API 에러 응답의 단일 출처. |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `core/` | 핵심 컴포넌트 — 데이터 모델, tshark 추출, 프레임 인덱싱, AP/STA 감지, 리포터, 로그 병합, pcap magic byte (see `core/AGENTS.md`) |
| `web/` | 웹 시각화 — structured 데이터 생성(`structured.py`), 지연/이상/cliff 분석 (see `web/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- `pipeline.py`의 `run_analysis()`가 유일한 공개 진입점. CLI와 웹 라우트 모두 이 함수를 호출.
- structured 함수들(`_structured_overview` 등)은 `analyzer/web/structured.py`에 있음. `pipeline.py`에서 re-export되어 `from analyzer.pipeline import _structured_ping` 경로도 유효 (하위호환).
- 새 분석 모듈 추가 시: `core/modules/`에 모듈 생성 → `pipeline.py`의 `analyzer_list`에 등록 → 필요시 `web/structured.py`에 structured 함수 추가.
- API 에러 메시지는 하드코딩하지 말고 `errors.py`의 `ErrorCode`에 항목 추가 후 `error_payload(code)` 사용.

### Testing Requirements
- tshark가 설치된 환경에서 `tests/fixtures/sample_basic.pcap` (scapy 합성)으로 golden 회귀 테스트 (`tests/test_golden.py`, `@pytest.mark.tshark`).
- `run_analysis()`의 반환 딕셔너리 구조가 변경되면 `routes/analysis.py`와 `templates/analysis.html`에 영향.

### Common Patterns
- 분석 모듈 시그니처: `analyze(frames: List[Frame], roles: Dict, index=None) -> AnalysisSection`
- `FrameIndex`를 통해 O(1)~O(log N) 프레임 접근. 반복 순회 대신 인덱스 사용 권장.
- structured 함수는 프론트엔드 차트가 직접 소비하는 데이터 구조를 생성.
- Ping 매칭은 `(src,dst,seq)` FIFO 큐 + `PING_MATCH_WINDOW_SEC` (기본 30초) 시간 윈도우. seq 재사용/중복 reply 대응.

## Dependencies

### Internal
- `core/extractor` — tshark로 프레임 추출
- `core/detector` — AP/STA 역할 감지
- `core/indexer` — 프레임 사전 인덱싱
- `core/models` — Frame, AnalysisSection 데이터클래스
- `core/modules/*` — 11개 분석 모듈
- `web/*` — 웹 시각화 전용 분석 3개

<!-- MANUAL: -->
