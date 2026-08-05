# 유선 RTT 1차 전환 설계 — ICMP 분석의 유선 우선 체계

> 상태: 설계 확정 대기 → 구현은 plans/ 문서로 태스크화
> 선행: 멀티 pcap 1~3단계 (docs/superpowers/specs/2026-08-03-multi-pcap-analysis-design.md, 전부 머지됨)

## 배경과 목적

무선 캡처는 모니터 누락 때문에 ICMP 관측이 구조적으로 왜곡될 수 있다 —
TEST1 실측에서 cantops 스니퍼 단독은 관측 합집합의 66%를 놓쳤다(커버리지
분해 양쪽 포착 28.5%). 손실률은 1단계에서 유선 ground truth로 확정 기준을
옮겼지만, **RTT는 여전히 무선 관측이 유일한 소스**다.

유선 포트미러는 요청·응답이 같은 지점을 통과하므로 RTT도 누락 없이 측정할
수 있고, 실제로 유선 매칭 코어(`analyzer/core/exping.py::Exchange`)는 이미
`rtt: float | None`을 계산하고 있다 — 현재 `wired_ping.build_ground_truth`가
집계(손실)만 노출하고 exchange별 RTT를 버릴 뿐이다. 이 설계는 그 값을
노출해 **ICMP 분석 전체를 "판정은 유선 1차, 해석은 무선 보조" 체계로
완성**한다.

## 확정된 전제 (사용자 결정)

- 손실에 이어 RTT도 **유선이 1차**, 무선은 원인 해석(Retry·RSSI·로밍 대조) 보조.
- ping 탭 UI는 **소스 토글**(유선 기본, 무선 전환) — 오버레이 아님.
- report.md의 ping 섹션에 GT 요약(확정 손실 + 유선 RTT 통계) 포함 —
  기존 백로그("report GT 반영") 해소.

## 1. GT 스키마 확장 (`analyzer/core/wired_ping.py`)

`build_ground_truth` 반환 dict에 **optional 필드 2개** 추가. 기존 필드
(total/ok/ng/loss_pct/sender/targets/streaks/ng_epochs/trailing_dropped/
warnings)는 불변.

```python
"exchanges": [            # 시간창·필터 적용 후 최종 모집단 그대로 (loss 집계와 동일)
    {"epoch": 1753..., "target": "192.168.0.31", "rtt_ms": 3.2},   # 응답 있음
    {"epoch": 1753..., "target": "192.168.0.31", "rtt_ms": None},  # 손실
    ...
],
"rtt_stats": {"n": 10006, "min_ms": 1.1, "avg_ms": 3.4, "max_ms": 210.5, "p95_ms": 9.8},
```

- `exchanges[].epoch` = 요청 프레임의 캡처 epoch(`Exchange.time`),
  `rtt_ms` = `Exchange.rtt * 1000` (소수 3자리 반올림) 또는 None.
- `rtt_stats`는 응답 있는 exchange만 집계. **응답이 0건이면 `rtt_stats`
  자체를 생략**(정직한 공백 원칙 — 0이나 가짜 값 금지). p95는
  정렬 후 `ceil(0.95 * n) - 1` 인덱스 방식(외부 의존성 없이).
- exchanges 개수 상한 없음 — 유선 exping은 초당 ~10건 수준이라 20분에
  ~1.2만 건(JSON ~600KB)이고, 기존 `ng_epochs`도 무상한 선례.
  손실률 집계 모집단과 exchanges가 **정확히 같은 집합**이어야 한다
  (`total == len(exchanges)`, `ok == rtt_ms non-null 수` — 골든에서 등식 고정).
- `trailing_dropped`로 제외된 꼬리 요청은 exchanges에도 포함하지 않는다
  (loss 집계와 동일 모집단 원칙의 따름정리).

## 2. 구조화·파이프라인

변경 없음 — GT dict는 이미 `structured["ping"]["ground_truth"]`로 부착된다
(`analyzer/pipeline.py`). 신규 필드는 그 안에 실려 그대로 직렬화된다.

## 3. UI — ping 탭 소스 토글 (`templates/analysis.html`, `static/js/charts.js`)

- **토글 표시 조건**: `ping.ground_truth.exchanges`가 비어 있지 않을 때만.
  구버전 결과(신규 필드 없음)·유선 미업로드·GT 에러 시 토글 자체가 없고
  기존 무선 뷰 그대로 — 하위 호환.
- 토글 UI: RTT 시계열 카드 헤더에 `[유선 (확정)] [무선 (관측)]` 세그먼트
  버튼, **기본 유선**. 토글은 다음 4개 위젯에 연동:
  1. **Ping KPI** — 유선: 총 요청/성공/손실(GT 값)/평균 RTT(rtt_stats.avg_ms),
     라벨에 "유선 확정" 표기. 무선: 기존 값 + "무선 관측" 표기.
  2. **RTT 시계열** — 유선: 초록=응답(y=rtt_ms), 빨강X=손실(무선 뷰와
     동일 관례로 차트 상단 `maxRtt×1.1` 위치에 X 마커 — charts.js 기존
     구현 참조). 유선에는 Retry 개념이 없으므로 노랑 마커 없음.
     무선: 기존 그대로(초록/노랑/빨강X).
  3. **RTT 분포 히스토그램** — 선택된 소스의 RTT만.
  4. **Ping 통계** — 유선: rtt_stats(min/avg/max/p95) + 손실. 무선: 기존.
- **무선 전용 위젯은 토글과 무관하게 유지**: 장치별 연속 실패 구간(streak),
  전체 ping 목록 테이블, 관찰된 ICMP 목록 — 프레임 근거(frame_refs)와
  Retry 해석은 무선에만 존재하기 때문. GT 카드(손실 병기 비교)도 불변.
- XSS: target 등 사용자 유래 문자열은 기존 관례대로 `escapeHtml`.

## 4. report.md (`analyzer/web/report.py::_ping_section`)

- GT가 있으면 섹션 서두에 **유선 확정 블록** 추가: 확정 손실률(총/성공/손실),
  유선 RTT 통계(min/avg/max/p95), 손실 구간(streaks) 요약. 이어지는 기존
  무선 통계에는 "무선 관측 (보조지표)" 라벨을 붙인다.
- GT 없으면 기존 출력 그대로 (byte-identical — 회귀 고정).

## 5. 에러 처리

| 상황 | 동작 |
|---|---|
| GT에 exchanges 없음 (구버전 결과·GT 에러) | 토글 미표시, 무선 뷰 기존 그대로 |
| 응답 0건 (단방향 미러 등) | rtt_stats 생략 → KPI RTT "—", 시계열은 손실 마커만, 기존 GT warnings 배너 체계 유지 |
| rtt_ms 0 또는 음수(캡처 순서 이상) | exping 매칭 계약상 발생하지 않음(요청 이후 응답만 짝짓기) — 방어 불필요, 골든에서 `rtt_ms > 0` 전수 확인 |

## 6. 테스트

- **wired_ping 단위**: 합성 exchange로 ① exchanges/rtt_stats 스키마·값
  ② p95 경계(n=1, n=20) ③ 전부 무응답 → rtt_stats 생략 ④ trailing_dropped
  제외 시 exchanges도 동수 제외.
- **파이프라인 통합**: 기존 GT mock 테스트에 신규 필드 통과 확인.
- **골든(dual, 실 pcap)**: `total == len(exchanges)`,
  `ok == rtt_ms non-null 수`, `rtt_stats.n == ok`, 모든 rtt_ms > 0.
- **하위 호환 회귀**: ① 유선 없는 분석 결과 byte-identical ② 신규 필드
  없는 구버전 GT 렌더 스모크(토글 미표시) ③ GT 없는 report 출력 불변.
- **report 단위**: GT 있음/없음 두 케이스 출력 검증.

## 7. 구현 단계 (plans/에서 태스크화)

| 단계 | 범위 |
|---|---|
| 1 | wired_ping GT 스키마 확장 + 단위 테스트 |
| 2 | ping 탭 소스 토글 UI |
| 3 | report.py GT 블록 |
| 4 | 골든 확장 + 하위 호환 회귀 + 문서 |

## 범위 밖 (명시적 제외)

- exping CSV(장비 자체 기록 RTT)와의 대조 — 기존 CLI 소관.
- 유선 RTT 기반 신규 진단 issue 생성 — 진단 연동은 손실(1단계 기존) 유지.
- 스니퍼 비교 섹션과 유선 RTT 연동.
- 유선 RTT의 시간동기 보정 표시(이미 exchange epoch은 캡처 기준 그대로).
