# Test Infrastructure Plan

**Feature**: test-infrastructure
**Created**: 2026-04-09
**Status**: Draft

## Executive Summary

| 관점 | 설명 |
|------|------|
| **Problem** | 체계적인 테스트 인프라 부재로 코드 변경 시 회귀 버그 감지 불가. 분석 모듈 11개 중 테스트가 없는 모듈 존재, 커버리지 측정 없음, Playwright E2E가 pytest와 분리됨. |
| **Solution** | pytest 기반 통합 테스트 인프라 구축 — conftest fixture, 분석 모듈 테스트 보완, 커버리지 측정, E2E 통합, Makefile 자동화. |
| **Function UX Effect** | `make test` 한 줄로 전체 검증 가능. 커버리지 리포트로 취약 지점 즉시 파악. 마커로 빠른 테스트/느린 테스트 분리. |
| **Core Value** | 코드 변경에 대한 신뢰성 확보. 회귀 버그 조기 감지. 개발 속도와 품질의 동시 향상. |

## Context Anchor

| Key | Value |
|-----|-------|
| **WHY** | pcap 분석기의 11개 모듈 변경 시 회귀 버그를 자동 감지하기 위해 |
| **WHO** | 이 프로젝트 개발자 (1인 개발) |
| **RISK** | tshark 의존 테스트의 환경 이식성, E2E 테스트의 서버 의존성 |
| **SUCCESS** | 커버리지 80%+, 모든 분석 모듈 테스트 존재, `make test` 30초 이내 완료 |
| **SCOPE** | pytest 테스트 체계화. CI/CD 파이프라인은 이번 범위에 포함하지 않음. |

---

## 1. 배경 및 문제 정의

### 1.1 현재 상태
- `tests/` 디렉토리: 7개 파일, 78개 pytest 테스트 (이번 세션에서 생성)
  - `test_models.py` (15) — Frame 프로퍼티
  - `test_extractor.py` (12) — tshark 명령어, TSV 파싱
  - `test_detector.py` (10) — AP/STA 역할 감지
  - `test_indexer.py` (9) — FrameIndex
  - `test_web_modules.py` (13) — 지연/이상/cliff 분석
  - `test_config.py` (5) — 설정 관리
  - `test_routes.py` (14) — FastAPI 엔드포인트
- 루트 E2E 테스트: 3개 파일 (Playwright, pytest 미통합)
  - `test_iterate.py` — 전체 기능 검증
  - `test_iter2.py` — Ping/진단 카드 검증
  - `test_playwright.py` — 탭별 스크린샷

### 1.2 문제점
1. **분석 모듈 테스트 부재**: `analyzer/core/modules/`의 11개 모듈 중 개별 테스트 없음 (pipeline 통합만 존재)
2. **공통 fixture 없음**: 각 테스트 파일마다 `_frame()`, `_make_frame()` 헬퍼를 중복 정의
3. **커버리지 측정 없음**: 어느 코드가 테스트되지 않는지 파악 불가
4. **E2E 테스트 분리**: Playwright 테스트가 pytest 프레임워크와 통합되지 않아 `pytest` 한 번에 전체 실행 불가
5. **마커 없음**: 빠른 단위 테스트와 느린 E2E/tshark 테스트를 구분 실행할 수 없음
6. **실행 스크립트 없음**: 테스트 실행 방법이 문서화/자동화되지 않음

## 2. 목표

### 2.1 성공 기준 (Success Criteria)

| ID | 기준 | 측정 방법 |
|----|------|----------|
| SC-1 | 모든 분석 모듈(11개)에 최소 3개 이상 단위 테스트 존재 | `pytest --co -q` 로 모듈별 테스트 수 확인 |
| SC-2 | 코드 커버리지 80% 이상 | `pytest --cov=analyzer --cov=ai --cov=routes --cov=config` |
| SC-3 | `conftest.py`에 공통 fixture 통합, 개별 파일의 헬퍼 중복 제거 | 파일 diff 확인 |
| SC-4 | Playwright E2E 테스트가 `pytest -m e2e`로 실행 가능 | 실행 결과 확인 |
| SC-5 | `make test` (단위), `make test-all` (전체), `make cov` (커버리지) 동작 | Makefile 실행 |
| SC-6 | 전체 단위 테스트 30초 이내 완료 | `time pytest tests/` |

### 2.2 비목표 (Out of Scope)
- CI/CD 파이프라인 (GitHub Actions 등)
- 성능/부하 테스트
- tshark 통합 테스트 (실제 pcap 파싱) — 별도 feature로 분리
- 코드 커버리지 100% 목표 아님

## 3. 요구사항

### 3.1 공통 Fixture (R-1)
- `tests/conftest.py`에 `make_frame()` fixture 정의
- 기본값 포함, `**kwargs`로 오버라이드 가능
- 기존 `test_models.py`, `test_detector.py`, `test_indexer.py`의 중복 헬퍼 제거
- 자주 쓰이는 fixture 추가:
  - `sample_frames` — 5~10개 프레임 리스트 (AP 1대 + STA 2대)
  - `sample_roles` — AP/STA 역할 딕셔너리
  - `sample_index` — FrameIndex 인스턴스

### 3.2 분석 모듈 테스트 (R-2)
- `tests/test_modules.py` 또는 `tests/modules/test_{module}.py` 구조
- 대상 11개 모듈:

| # | 모듈 | 최소 테스트 |
|---|------|-----------|
| 1 | overview | 빈 프레임, 정상 프레임, 프로토콜 분포 |
| 2 | retry_mcs | MCS별 retry 비율 |
| 3 | retry_burst | burst 탐지 |
| 4 | roaming | Auth→Assoc 시퀀스 매칭 |
| 5 | ping_rtt | ICMP 매칭, RTT 계산 |
| 6 | control_traffic | ARP/ICMP/TCP ACK 분류 |
| 7 | signal_quality | RSSI 통계, 약신호 탐지 |
| 8 | per_second | 초당 카운트 |
| 9 | roaming_impact | 로밍 전후 변화 |
| 10 | ping_loss | loss 탐지 |
| 11 | diagnosis | 종합 진단 WARNING 생성 |
| 12 | compare_ap | AP 비교 (AP 2대 이상) |

### 3.3 커버리지 측정 (R-3)
- `pytest-cov` 패키지 도입
- `pyproject.toml`에 pytest + coverage 설정
- HTML 커버리지 리포트 생성 (`htmlcov/`)
- `.gitignore`에 `htmlcov/` 추가

### 3.4 E2E 테스트 통합 (R-4)
- `tests/e2e/` 디렉토리에 Playwright 테스트 이동/재구성
- `@pytest.mark.e2e` 마커 등록
- 기본 `pytest` 실행 시 e2e 제외 (`-m "not e2e"` 기본값)
- 서버 자동 시작/종료 fixture (`e2e_server`)

### 3.5 마커 및 설정 (R-5)
- pytest 마커 정의:
  - `e2e` — Playwright E2E (서버 필요)
  - `slow` — 5초 이상 걸리는 테스트
  - `tshark` — tshark 설치 필요
- `pyproject.toml`에 통합 설정

### 3.6 실행 자동화 (R-6)
- `Makefile` 타겟:
  - `test` — 단위 테스트만 (`pytest tests/ -m "not e2e and not slow"`)
  - `test-all` — 전체 (`pytest tests/`)
  - `test-e2e` — E2E만 (`pytest tests/ -m e2e`)
  - `cov` — 커버리지 리포트 생성
  - `cov-html` — HTML 커버리지 리포트

## 4. 기술 결정

### 4.1 테스트 구조

```
tests/
├── conftest.py              # 공통 fixture (make_frame, sample_frames 등)
├── test_config.py           # (기존)
├── test_models.py           # (기존, fixture 리팩토링)
├── test_extractor.py        # (기존)
├── test_detector.py         # (기존, fixture 리팩토링)
├── test_indexer.py          # (기존, fixture 리팩토링)
├── test_routes.py           # (기존)
├── test_web_modules.py      # (기존)
├── test_modules.py          # (신규) 분석 모듈 11개 테스트
├── test_pipeline.py         # (신규) pipeline 구조화 함수 테스트
├── test_reporter.py         # (신규) 리포터/로그 병합 테스트
└── e2e/
    ├── conftest.py          # e2e fixture (서버 시작/종료)
    ├── test_upload_flow.py  # 업로드→분석 플로우
    ├── test_tabs.py         # 탭별 UI 검증
    └── test_api.py          # API 엔드포인트 E2E
```

### 4.2 의존성 추가

```
# requirements-dev.txt (신규)
pytest>=8.0
pytest-cov>=5.0
pytest-asyncio>=0.23
playwright>=1.40
```

## 5. 리스크

| 리스크 | 영향 | 대응 |
|--------|------|------|
| 분석 모듈 테스트가 내부 구현에 과도하게 결합 | 리팩토링 시 테스트 깨짐 | 입/출력 계약만 테스트, 내부 구현 의존 최소화 |
| E2E 테스트의 서버 시작/종료 불안정 | 테스트 실패 오탐 | fixture에 타임아웃 + 포트 재시도 로직 |
| Playwright 미설치 환경에서 import 에러 | 전체 테스트 수집 실패 | `pytest.importorskip("playwright")` 사용 |

## 6. 구현 순서

| 단계 | 작업 | 의존성 |
|------|------|--------|
| 1 | `pyproject.toml` pytest 설정 + 마커 등록 | 없음 |
| 2 | `tests/conftest.py` 공통 fixture 생성 | 없음 |
| 3 | 기존 테스트 파일에서 중복 헬퍼 제거, fixture 사용으로 전환 | 단계 2 |
| 4 | `tests/test_modules.py` — 분석 모듈 12개 테스트 작성 | 단계 2 |
| 5 | `tests/test_pipeline.py` — pipeline 구조화 함수 테스트 | 단계 2 |
| 6 | `tests/test_reporter.py` — reporter + log_merger 테스트 | 단계 2 |
| 7 | 커버리지 측정 설정 + 80% 달성 확인 | 단계 4-6 |
| 8 | `tests/e2e/` E2E 테스트 통합 | 단계 1 |
| 9 | `Makefile` + `requirements-dev.txt` | 단계 7-8 |
| 10 | 전체 검증 및 문서 정리 | 전체 |
