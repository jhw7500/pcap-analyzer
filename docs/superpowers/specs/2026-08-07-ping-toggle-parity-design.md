# ping 탭 토글 완전성 + 손실 클릭 내비게이션 설계

> 선행: 유선 RTT 1차 전환 (docs/superpowers/specs/2026-08-05-wired-rtt-primary-design.md, PR #25 머지됨)
> 범위: **프론트 전용** (`templates/analysis.html`, `static/js/charts.js`) — 백엔드·직렬화 무변경

## 배경과 목적

PR #25의 소스 토글은 상단 4위젯(KPI·RTT 시계열·히스토그램·통계)만 전환하고
하단 3위젯(장치별 연속 실패 구간·전체 목록·관찰된 ICMP)은 무선 고정이다 —
유선 뷰에서 상단은 "손실 21건"인데 하단 목록은 무선 관측 기준이라 수치가
어긋나 보인다. 또한 RTT 시계열의 손실 X 마커는 클릭해도 아무 동작이 없어,
"이 손실이 언제·어느 target이었나"를 목록에서 다시 찾아야 한다.

## 확정된 전제 (사용자 결정)

- 하단 3위젯도 토글 연동: streak·전체 목록은 유선 데이터로 전환,
  **관찰된 ICMP는 유선 뷰에서 섹션 숨김**(유선엔 "관찰됐지만 측정 불가"
  개념이 없음 — 정직한 공백).
- 손실 X 마커 클릭 → **전체 목록의 해당 행으로 점프**(스크롤+하이라이트,
  필요 시 상태 필터 자동 전환). 유선·무선 양쪽 뷰 공통.

## 1. 하단 3위젯 토글 연동 (`renderPingSource` 확장)

### 1-1. 장치별 연속 실패 구간
- 기존 무선 렌더(1회성 inline `if (streakTbody) {...}` 블록)를
  `renderPingStreaksWireless()`로 함수화 — **코드 이동만, 내용 무수정**.
- 신규 `renderPingStreaksWired()`: `gt.streaks[]`
  (`{target, start_epoch, end_epoch, count, duration_sec}`) 렌더.
  컬럼 매핑 — 장치=`target`(IP), 시각 구간=epoch→`toLocaleTimeString('en-GB')`,
  건수, 지속(초). 유선에 없는 근거 프레임·seq 범위 컬럼은 `—` 표시
  (thead는 무선과 공유 — 6컬럼 유지). 비어 있으면
  "유선 연속 손실 구간 없음 (산발적 발생)".
- 섹션 제목 옆에 소스 라벨 병기: 유선 뷰 `(유선 확정)`, 무선 뷰 기존 그대로.

### 1-2. 전체 목록 (전수검사)
- 기존 `renderPingFullTable()`은 무선 전용으로 유지(무수정).
- 신규 `renderPingFullTableWired()`: `gt.exchanges[]` 렌더 —
  컬럼 `# / 시각 / target / RTT(ms) / 상태(OK|LOSS)` 5개.
  무선(10컬럼)과 다르므로 **thead를 뷰별로 교체**한다: `analysis.html`의
  기존 thead에 id를 주고, 유선 thead 템플릿은 JS 문자열로 생성.
- 필터: 유선 뷰에서는 **상태 필터만 유효**(전체|응답|손실 — 기존 select의
  matched/loss 값을 재해석). flow 선택·Retry 체크박스는 유선 뷰에서 숨김
  (컨테이너에 hidden 토글), 무선 복원 시 원상복구.
- 카운트 표기(`ping-full-count`)는 동일 형식 `표시 / 전체건`.
- 각 행에 `data-ex-idx="<exchanges 배열 인덱스>"` (유선) /
  `data-fl-idx="<fullList 배열 인덱스>"` (무선) 속성 부여 — 클릭 내비의
  조인 키. 무선 행 속성 추가는 기존 rows.map 내 `<tr ...>`에 속성 1개
  추가 수준으로 최소 수정(내용 로직 무변경).

### 1-3. 관찰된 ICMP 프레임
- 유선 뷰: `#ping-observations-details`에 `hidden` 클래스 추가.
- 무선 뷰: 제거(원상복구). 데이터·렌더 로직 무변경.

### 1-4. `renderPingSource(src)` 통합
- 기존 상단 4위젯 호출에 이어 streak/전체 목록/관찰 ICMP 전환 호출 추가.
- GT 없는 결과(토글 미표시)는 `renderPingSource('wireless')` 1회 경로
  그대로 — 기존과 동일 렌더 + 신규 클릭 내비만 추가(§2, 직렬화 무관 UI
  개선이라 하위 호환 원칙 위반 아님).

## 2. 손실 X 마커 클릭 → 전체 목록 행 점프

- 손실 trace에 `customdata` 부여:
  - 유선(`renderPingRttWired`): `loss.map(e => gtExchanges.indexOf(e))` —
    exchanges 배열 인덱스.
  - 무선(기존 RTT 렌더의 손실 trace): `losses`가 `fullList`의 부분집합이므로
    fullList 인덱스를 customdata로. (loss_gap 포함 — fullList에 존재)
- `plotly_click` 핸들러(차트 렌더 직후 바인딩, 뷰 전환 재렌더 시마다
  재바인딩): 클릭 포인트가 손실 trace가 아니면 무시. 손실이면:
  1. 상태 필터(select)를 `loss`로 설정 후 해당 뷰의 전체 목록 재렌더
     (행이 필터에 가려 없는 상황 제거 — 항상 예측 가능한 동작).
  2. `querySelector('[data-ex-idx="N"]')`(뷰별 키)로 행 탐색 →
     `scrollIntoView({block:'center'})` + 하이라이트 클래스
     (`ring-2 ring-yellow-400` 계열) 부여, 2.5초 후 제거.
  3. 전체 목록 카드가 접혀 있거나 화면 밖이면 scrollIntoView가 함께 해결
     (details 아님 — 항상 펼쳐진 카드).
- 응답(초록) 포인트 클릭은 동작 없음 (범위 밖).

## 3. 에러·하위 호환

| 상황 | 동작 |
|---|---|
| GT 없음(구버전 포함) | 토글 없음 — 하단 위젯 기존 그대로 + 무선 클릭 내비만 활성 |
| gt.streaks 없음/빈 배열 | 유선 streak 테이블에 "없음" 안내 |
| gt.exchanges 없음 | 토글 자체가 안 뜨므로(기존 게이트) 유선 하단 렌더 도달 불가 |
| 클릭한 손실 행 탐색 실패(이론상) | 무동작 (throw 금지) |

## 4. 검증

- 코드 레벨: `node --check`, 기존 pytest 전체(백엔드 무변경 — 수치 불변), ruff.
- 브라우저(컨트롤러): ① 유선 뷰 — streak가 GT streaks와 일치, 전체 목록
  카운트=total, 관찰 ICMP 숨김 ② 무선 전환 — 3위젯 원상복구 ③ X 클릭 —
  양쪽 뷰에서 필터 전환+스크롤+하이라이트 ④ 구버전 분석 — 변화 없음
  + 무선 클릭 내비 동작 ⑤ 콘솔 에러 0.

## 범위 밖

- streak 테이블 클릭 내비(구간→목록), 관찰 ICMP의 유선 대응물, 백엔드 변경 일체.
