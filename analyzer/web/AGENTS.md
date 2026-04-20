<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-09 | Updated: 2026-04-20 -->

# web

## Purpose
웹 시각화 전용 분석 모듈. `structured.py`가 raw Frame → 대시보드용 중첩 dict 변환을 담당하고, `delay_analysis`/`anomaly_frames`/`signal_cliff`가 추가 분석을 수행한다. 모든 결과는 프론트엔드 차트에서 직접 소비된다.

## Key Files

| File | Description |
|------|-------------|
| `structured.py` | raw Frame → dashboard용 structured dict 변환. `_structured_overview/signal/ping/roaming/per_second/device_stats/diagnosis` 7개 함수 + `PING_MATCH_WINDOW_SEC` 상수. `pipeline.py`가 이 모듈을 호출하며 backward-compat을 위해 re-export. |
| `delay_analysis.py` | Ping RTT/loss 데이터에서 지연 구간(delay zone) 탐지. 이동 평균 기반 고RTT 탐지 + loss 포인트 그룹화 + 원인 추정(로밍/고retry/불명). |
| `anomaly_frames.py` | DeAuth/DisAssoc, 과도한 ProbeReq, ARP storm 등 이상 프레임 이벤트 탐지. 심각도(high/medium/low) 분류. |
| `signal_cliff.py` | STA별 RSSI 급변(cliff) 탐지 (5초 내 10dBm 이상 하락) + 이동 평균(window=20) 계산. |

## For AI Agents

### Working In This Directory
- 이 모듈들은 raw Frame이 아닌 `pipeline.py`의 `structured` 딕셔너리를 입력으로 받음.
- 반환 데이터는 `structured["delay_zones"]`, `structured["anomaly_frames"]`, `structured["signal_cliffs"]`에 저장.
- 새 웹 분석 추가 시: 이 디렉토리에 모듈 생성 → `pipeline.py`의 구조화 데이터 섹션에서 호출.

### Common Patterns
- 입력/출력 모두 `Dict[str, Any]` 타입의 JSON 직렬화 가능한 딕셔너리.
- 각 모듈은 `summary` 키로 요약 통계를 포함.

## Dependencies

### Internal
- `pipeline.py`의 구조화 데이터 (ping, roaming, per_second, signal, overview)

<!-- MANUAL: -->
