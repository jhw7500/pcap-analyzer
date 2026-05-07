# Test Coverage & E2E — Follow-up Report

**Features**: `tests`, `e2e` (combined)
**Period**: 2026-04-09 ~ 2026-05-07
**Status**: Completed
**Predecessor**: [2026-04 test-infrastructure](../../2026-04/test-infrastructure/test-infrastructure.report.md)

---

## 1. Background

[2026-04 test-infrastructure archive](../../2026-04/test-infrastructure/test-infrastructure.report.md)에서
미해결로 남긴 두 항목을 후속 사이클에서 정리:

| Predecessor Item | Priority (당시) | 본 사이클 결과 |
|---|---|---|
| 커버리지 85% 목표 — `routes/upload.py` 51% 보강 | Low | upload.py 96%, 전체 81.78%로 게이트 재확보 |
| E2E 실행 환경 검증 (Playwright + 서버 자동 시작) | Low | uvicorn + chromium headless로 9/9 PASS 실증 |

이전 사이클이 정식 Plan→Do→Check→Iterate→Report 흐름이었던 반면, 본 사이클은
이미 정의된 미해결 항목을 직접 처리한 형태라 **Plan/Design 산출물 없이 Do→Check**로 진행됨.

---

## 2. Results

### 2.1 `tests` 피처

| Metric | Before | After |
|---|---|---|
| 단위 테스트 | 213 통과 | **229 통과** (+16) |
| `tshark` 마커 | 7 통과 | 7 통과 (변동 없음) |
| 전체 커버리지 | 78.28% (FAIL) | **81.78% (PASS)** |
| `routes/upload.py` | 43% | **96%** |
| `analyzer/casefile_*` (신규) | — | 80%/100%/86% |
| `analyzer/core/ping_matching.py` (신규) | — | 100% |

추가 테스트 위치: `tests/test_routes_upload.py` (신규 16개).

### 2.2 `e2e` 피처

| Suite | 결과 |
|---|---|
| `test_api.py` (3) | PASSED — progress, analysis_not_found, cancel_no_running |
| `test_tabs.py` (3) | PASSED — settings, nav links, settings form |
| `test_upload_flow.py` (3) | PASSED — index, upload zone, invalid file 거부 |
| **합계** | **9/9 in 2.67s** |

서버 자동 시작 fixture(`tests/e2e/conftest.py`)가 의도대로 동작 — 포트 8000이 비어 있으면
uvicorn을 백그라운드로 띄우고 종료 시 정상 종료. 이미 떠 있으면 재사용.

---

## 3. Key Learnings (재사용 가치)

| # | 학습 | 적용 시점 |
|---|---|---|
| L-1 | **pytest-playwright 미설치 환경에서도 `playwright.sync_api` 직접 사용 가능** — conftest에서 `pytest.importorskip("playwright")` + `from playwright.sync_api import sync_playwright`로 충분. 의존성 1개 줄임. | E2E 테스트 인프라 도입 시 |
| L-2 | **커버리지 게이트는 한 파일 집중 보강이 효율적** — 전체 78.28%→81.78% 상승의 거의 전부가 `routes/upload.py` 1개 파일(43%→96%) 커버에서 나옴. 모듈별 1~2% 보강을 흩뿌리는 것보다 ROI 명확. | 커버리지 게이트 미달 시 |
| L-3 | **bkit `.bkit/` 같은 PDCA state는 .omc/와 동일하게 .gitignore** — transient state(audit 로그, 세션 히스토리)가 매 세션마다 변경되어 git status를 오염시킴. 기존 `.omc/` 정책과 일관되게 처리. | 외부 도구의 작업 디렉토리 도입 시 |

---

## 4. Decisions

| Decision | Rationale |
|---|---|
| 두 피처를 단일 report로 통합 | 둘 다 테스트 인프라 관련 + 같은 사이클 내 진행 + 산출물 양 적음. 별개 report 분리 비용 > 통합 가치. |
| Plan/Design 단계 생략 | 이전 archive에서 이미 미해결 항목으로 정의돼 있어 새 spec 불필요. |
| 커버리지 보강을 `routes/upload.py`에 집중 | 미커버 라인 수가 가장 많고(85), 모킹으로 외부 의존(tshark) 우회 가능 → 빠른 게이트 통과. |
| 케이스파일 도입 작업은 별도 추적 대상으로 분리 | 본 후속 사이클의 범위를 벗어남(별도 commit `b58f7f0`). 향후 별도 PDCA 피처로 등록 여부 결정 필요. |

---

## 5. PDCA Process Review

| Phase | Notes |
|---|---|
| Plan | (생략 — predecessor에서 정의된 항목 후속 처리) |
| Do | 16개 단위 테스트 추가, 케이스파일 모듈 함께 작성 |
| Check | 220 단위 + 9 e2e PASS, coverage 81.78% (게이트 +1.78%p 여유) |
| Act | 본 보고서 작성 (학습 3건) |

---

## 6. Future Items

| Item | Priority | Notes |
|---|---|---|
| 케이스파일 기능을 정식 PDCA 피처로 등록 | Medium | `b58f7f0`는 plan/design 산출물 없이 들어감. 향후 변경 시 회귀 추적 어려움. |
| `ai/provider.py` (21%), `ai/reviewer.py` (38%) 커버리지 보강 | Low | 외부 API 호출이라 모킹 필요. 게이트는 통과했으나 신뢰도 낮음. |
| `analyzer/pipeline.py` 커버리지 (default 측정 26%) | Low | 실 tshark 실행 경로라 default 마커에서 제외됨. CI에서 `-m ""`로 전체 측정 시 대폭 상승 예상. |
| FastAPI `on_event` deprecation 경고 해소 | Low | `lifespan` 핸들러로 마이그레이션. 동작에 영향 없음. |
