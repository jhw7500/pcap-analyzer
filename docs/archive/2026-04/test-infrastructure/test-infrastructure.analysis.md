# Test Infrastructure — Gap Analysis

**Feature**: test-infrastructure
**Analyzed**: 2026-04-09
**Plan**: `docs/01-plan/features/test-infrastructure.plan.md`

## Context Anchor

| Key | Value |
|-----|-------|
| **WHY** | pcap 분석기의 11개 모듈 변경 시 회귀 버그를 자동 감지하기 위해 |
| **WHO** | 이 프로젝트 개발자 (1인 개발) |
| **RISK** | tshark 의존 테스트의 환경 이식성, E2E 테스트의 서버 의존성 |
| **SUCCESS** | 커버리지 80%+, 모든 분석 모듈 테스트 존재, `make test` 30초 이내 완료 |
| **SCOPE** | pytest 테스트 체계화. CI/CD 파이프라인은 이번 범위에 포함하지 않음. |

---

## 1. Success Criteria 평가

| ID | 기준 | 상태 | 근거 |
|----|------|------|------|
| SC-1 | 모든 분석 모듈(11개)에 최소 3개 이상 단위 테스트 | ⚠️ Partial | `test_modules.py`에 12개 모듈 26개 테스트 존재. overview(3), retry_mcs(2), retry_burst(2), roaming(2), ping_rtt(2), control_traffic(2), signal_quality(2), per_second(2), roaming_impact(2), ping_loss(2), diagnosis(3), compare_ap(2). **4개 모듈이 최소 3개 미달 (2개씩).** |
| SC-2 | 코드 커버리지 80% 이상 | ⚠️ Partial | 79.55% (TOTAL 1878 stmts, 384 miss). threshold 79%로 조정하여 통과 중이나 원래 목표 80%에 0.45% 부족. |
| SC-3 | conftest.py 공통 fixture, 중복 헬퍼 제거 | ✅ Met | `conftest.py`에 `make_frame` 1곳만 정의. `test_models.py`(0), `test_detector.py`(0), `test_indexer.py`(0) 중복 제거 확인. |
| SC-4 | Playwright E2E 테스트 pytest 통합 | ❌ Not Met | `tests/e2e/` 디렉토리 미생성. 마커 등록만 되어 있고 실제 E2E 테스트 파일 없음. |
| SC-5 | `make test`, `make test-all`, `make cov` 동작 | ✅ Met | Makefile에 5개 타겟 (test, test-all, test-e2e, cov, cov-html). `make test` → 158 passed (0.58s), `make cov` → 79.55% 정상 동작. |
| SC-6 | 전체 단위 테스트 30초 이내 | ✅ Met | 0.58초 (목표 30초의 2%). |

**Success Rate: 3/6 Met, 2/6 Partial, 1/6 Not Met**

---

## 2. Structural Match (구조 일치도)

| Plan 요구 파일 | 존재 여부 | 상태 |
|---------------|----------|------|
| `pyproject.toml` (pytest 설정) | ✅ | 마커 3개 등록, coverage 설정 포함 |
| `tests/conftest.py` | ✅ | make_frame, sample_frames, sample_roles, sample_index |
| `tests/test_modules.py` | ✅ | 12개 모듈 테스트 클래스 |
| `tests/test_pipeline.py` | ✅ | 8개 테스트 (구조화 함수) |
| `tests/test_reporter.py` | ✅ | 3+2 테스트 (reporter + log_merger) |
| `tests/test_ai.py` | ✅ | (Plan 미명시, 추가 구현) |
| `tests/test_routes_extended.py` | ✅ | (Plan 미명시, 추가 구현) |
| `tests/test_extractor_extended.py` | ✅ | (Plan 미명시, 추가 구현) |
| `tests/test_log_merger.py` | ✅ | (Plan 미명시, 추가 구현) |
| `tests/e2e/conftest.py` | ❌ | 미생성 |
| `tests/e2e/test_upload_flow.py` | ❌ | 미생성 |
| `tests/e2e/test_tabs.py` | ❌ | 미생성 |
| `tests/e2e/test_api.py` | ❌ | 미생성 |
| `Makefile` | ✅ | 5개 타겟 |
| `requirements-dev.txt` | ✅ | pytest, pytest-cov, pytest-asyncio |
| `.gitignore` (htmlcov/) | ✅ | htmlcov/, .coverage, .pytest_cache/ 추가 |

**Structural Match: 12/16 = 75%**

---

## 3. Functional Depth (기능 완성도)

| 요구사항 | 구현 상태 | 점수 |
|---------|----------|------|
| R-1: 공통 Fixture | ✅ make_frame + 3 fixtures, 중복 제거 완료 | 100% |
| R-2: 분석 모듈 테스트 | ⚠️ 12개 모듈 모두 테스트 존재, 일부 3개 미만 | 85% |
| R-3: 커버리지 측정 | ⚠️ 설정 완료, 79.55% (목표 80% 미달) | 90% |
| R-4: E2E 테스트 통합 | ❌ 디렉토리/파일 미생성, 마커만 등록 | 10% |
| R-5: 마커 및 설정 | ⚠️ 마커 3개 등록, addopts 설정. 실제 사용처(e2e) 없음 | 70% |
| R-6: 실행 자동화 | ✅ Makefile 5개 타겟 모두 동작 | 100% |

**Functional Match: 76%**

---

## 4. Gap List

| # | Severity | Gap | Action |
|---|----------|-----|--------|
| G-1 | Important | `tests/e2e/` 디렉토리 및 E2E 테스트 파일 4개 미생성 (SC-4 ❌) | E2E conftest + 3개 테스트 파일 생성 |
| G-2 | Minor | 4개 분석 모듈 테스트가 3개 미만 (retry_mcs, retry_burst, roaming, ping_rtt 각 2개) | 각 모듈에 1개씩 테스트 추가 |
| G-3 | Minor | 커버리지 79.55% (목표 80%, 0.45% 부족) | `routes/upload.py` 또는 `ai/` 테스트 보강 |

---

## 5. Match Rate

```
Structural:  75% (12/16 files)
Functional:  76% (weighted requirements)
─────────────────────────────
Overall:     76% (static only: Structural × 0.4 + Functional × 0.6)
```

**Match Rate: 76%** (< 90% threshold)

---

## 6. Recommendation

G-1 (E2E 통합)이 가장 큰 Gap이지만, Playwright 의존성과 서버 실행이 필요한 환경 제약이 있습니다.

- **G-2, G-3**: 즉시 해결 가능 (테스트 추가로 ~85% 도달)
- **G-1**: 환경 의존적 — Playwright 설치 + 서버 fixture 구현 필요
