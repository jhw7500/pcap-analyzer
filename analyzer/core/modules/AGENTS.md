<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-09 | Updated: 2026-04-09 -->

# modules

## Purpose
11개 독립 분석 모듈. 각 모듈은 동일한 시그니처 `analyze(frames, roles, index) -> AnalysisSection`을 따르며, 특정 관점에서 프레임을 분석하여 텍스트 리포트 섹션을 생성한다. `pipeline.py`의 `analyzer_list`에 등록된 순서대로 실행된다.

## Key Files

| File | Description |
|------|-------------|
| `overview.py` | 1. 개요 — 시간 범위, 프레임 수, 프로토콜/서브타입 분포, Retry율, 감지된 디바이스 목록 |
| `retry_mcs.py` | 2. Retry MCS — MCS 인덱스별 Retry 비율 분석 |
| `retry_burst.py` | 3. Retry Burst — Retry 폭증 구간 탐지 |
| `roaming.py` | 4. 로밍 — Auth→Assoc/ReassocReq 시퀀스 탐지, 로밍 갭 시간 측정 |
| `ping_rtt.py` | 5. Ping RTT — ICMP Request/Reply 매칭, RTT 통계 |
| `control_traffic.py` | 6. 제어 트래픽 — ARP, ICMP, TCP ACK 등 제어 프레임 비율 분석 |
| `signal_quality.py` | 7. 신호 품질 — STA별 RSSI 통계, 약신호 구간 탐지 |
| `per_second.py` | 8. 초당 통계 — 초당 프레임 수/Retry 수 시계열 |
| `roaming_impact.py` | 9. 로밍 영향 — 로밍 전후 Retry/신호 변화 분석 |
| `ping_loss.py` | 10. Ping Loss — 미응답 ICMP 탐지, loss 원인 추정 |
| `diagnosis.py` | 11. 종합 진단 — STA별 교차 분석(Retry+RSSI+로밍+Ping), WARNING 생성, 현장 제안 |
| `compare_ap.py` | 12. AP 비교 — AP 간 성능/프레임 분포 비교, BSSID 기반 불균형 분석, Beacon RSSI 비교 |

## For AI Agents

### Working In This Directory
- 새 모듈 추가 절차:
  1. 이 디렉토리에 `{name}.py` 생성
  2. `analyze(frames: List[Frame], roles: Dict, index=None) -> AnalysisSection` 함수 구현
  3. `pipeline.py`의 `analyzer_list`에 `("표시명", module)` 튜플 등록
  4. 웹 시각화가 필요하면 `pipeline.py`에 `_structured_*` 함수 추가
- 모든 모듈은 `index` 파라미터가 `None`일 수 있으므로 폴백 로직 필요.
- `FrameIndex`를 활용하면 전체 프레임 순회 대신 O(1) 접근 가능.

### Common Patterns
- `analyze()` 시그니처 고정: `(frames: List[Frame], roles: Dict, index=None) -> AnalysisSection`
- `AnalysisSection(title=, lines=, summary=)` 반환. `lines`는 텍스트 줄 리스트, `summary`는 1줄 요약.
- `mac_name(mac, roles)` — MAC을 "AP1(xxxx)" 형태로 변환.
- STA 필터: `[m for m, r in roles.items() if r["role"] == "STA"]`
- AP 필터: `[m for m, r in roles.items() if r["role"] == "AP"]`

## Dependencies

### Internal
- `../models` — `Frame`, `AnalysisSection`, `SUBTYPE_NAMES`
- `../detector` — `mac_name()`
- `../indexer` — `FrameIndex` (index 파라미터로 전달)

<!-- MANUAL: -->
