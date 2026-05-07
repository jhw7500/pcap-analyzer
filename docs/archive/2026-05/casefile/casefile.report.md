# Casefile Abstraction — Retroactive Report

**Feature**: `casefile`
**Commit**: [`b58f7f0`](../../../../) — `feat(casefile): incident 기반 casefile 추상화 도입`
**Period**: 2026-05-07
**Status**: Completed (retroactive registration)
**Note**: 본 보고서는 사후 등록(retroactive) — Plan/Design 산출물 없이 구현이 먼저 들어간
케이스를 추적·재사용 목적으로 archive에 남기기 위해 작성.

---

## 1. Why retroactive?

`b58f7f0` 커밋은 PDCA 사이클 외부에서 직접 들어갔다. 즉시 동작하고 테스트도
포함됐기 때문에 정식 사이클을 회복할 동기는 약하지만, 다음 두 이유로 archive에는
남길 가치가 있다고 판단:

1. **회귀 위험 추적** — 케이스파일 스키마는 외부 도구(AI 리뷰, 외부 분석 파이프라인)와의
   계약이 될 수 있어, 향후 변경 시 호환성 검증 포인트가 필요.
2. **재사용 가치** — pydantic 기반 layered evidence 구조는 다른 분석 영역(로밍, 신호 등)에도
   적용 가능. 등록해 두면 나중에 패턴 참조 가능.

---

## 2. What was added

### 2.1 신규 모듈

| File | Role |
|---|---|
| `analyzer/casefile_schema.py` | pydantic 모델 — `CasefileV1`, `IncidentWindow`, `Layers`, `EvidenceItem`, `PingData`, `Summary` |
| `analyzer/casefile_builder.py` | structured 분석 결과 → `CasefileV1` 변환 (incident 단위 묶음) |
| `analyzer/casefile_serializer.py` | JSON / 사람 친화 텍스트 직렬화 |
| `analyzer/core/ping_matching.py` | ping pair 매칭 + 통계 산출 (구 `web/structured` 내부에서 분리) |

### 2.2 기존 코드 변경

| File | Change |
|---|---|
| `analyzer/web/structured.py` | ping 매칭 로직을 `core/ping_matching`으로 위임 |
| `analyzer/core/modules/{ping_rtt,ping_loss,diagnosis}.py` | 분리된 매칭 헬퍼 사용으로 리팩터 |
| `analyzer/errors.py` | `INCIDENT_NOT_FOUND`, `CASEFILE_UNAVAILABLE` 코드 추가 |
| `routes/analysis.py` | `/api/analysis/{id}/casefile`, `/casefile/text` 엔드포인트 + `incident_id` 검증 |
| `templates/analysis.html` | `Casefile 보기` 링크 추가 |

### 2.3 검증 (사후)

| 검증 | 결과 |
|---|---|
| 단위 테스트 | `casefile_builder` 80%, `casefile_schema` 100%, `casefile_serializer` 86%, `ping_matching` 100% |
| 라우트 테스트 | `tests/test_routes_extended.py::TestAnalysisWithData::test_api_casefile_*` (4 케이스) |
| 통합 회귀 | 220 단위 + 9 e2e PASS, 코드 변경으로 인한 기존 분석 흐름 회귀 없음 |

---

## 3. Design Decisions (사후 정리)

| Decision | Rationale |
|---|---|
| pydantic v1 BaseModel 사용 | 프로젝트 다른 곳과 일관성. v2 마이그레이션은 별도 작업. |
| `Layers` 구조: `observed/derived/heuristic/unknown` | AI 리뷰가 evidence 신뢰도를 구분해 다룰 수 있도록. heuristic은 룰 기반 추정. |
| `Confidence` 4단계 (`high/medium/low/n/a`) | 외부 도구가 결정을 내릴 때 임계값을 자체 정의 가능하게 함. |
| ping pair 매칭 로직을 `core/`로 승격 | 구 `web/structured` 내부 함수였으나 모듈 여러 군데에서 호출돼 단일 출처가 필요. |
| `INCIDENT_NOT_FOUND`, `CASEFILE_UNAVAILABLE` 신규 에러 코드 | 기존 `error_payload` 카탈로그 패턴 유지. UI/API 일관성. |

---

## 4. Risks & Future Items

| Item | Risk Level | Notes |
|---|---|---|
| 스키마 외부 계약화 | Medium | `CasefileV1.schema_version="1.0"` 고정. 변경 시 v2 추가 + 호환 레이어 필요. |
| pydantic v1 → v2 마이그레이션 | Low | 프로젝트 전반 마이그레이션과 함께 진행. |
| Layers `unknown` 비중 | Low | 현재 evidence 분류 룰 기반 — 데이터 늘어나면 분류 정확도 점검 필요. |
| 다른 분석 영역(로밍/신호) 으로 확장 | — (기회) | 현재 incident 단위는 ping에 한정. 로밍 sequence 단위로도 케이스파일 만들 여지 있음. |

---

## 5. References

- Commit: `b58f7f0`
- 관련 라우트: `/api/analysis/{id}/casefile`, `/api/analysis/{id}/casefile/text`
- 후속 사이클(테스트 보강)에서 케이스파일 모듈도 함께 검증됨: [`test-infrastructure-followup`](../test-infrastructure-followup/test-infrastructure-followup.report.md)
