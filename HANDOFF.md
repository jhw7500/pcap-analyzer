# Handoff — pcap-analyzer
_Last updated: 2026-08-10T17:20:00+09:00 · Tool: claude-code · Session: default_

## Active Task
**없음 — PR #28 머지 완료** (`5a3acba`, 2026-08-11). 커밋 13개가 `main`에 반영됐다.
https://github.com/jhw7500/pcap-analyzer/pull/28

2시간 대용량 pcap 개통 + 분할 캡처 이어붙이기 + 로밍 측정 정확화 + STA 로그 상관.
머지 시점 검증: **1110 passed / tshark golden 19 / ruff clean**.

| 커밋 | 내용 |
|---|---|
| `044da0a` | 성능·페이로드·서버 경로 (440.9초→65.7초, JSON 120.8→33.7MB, 홈 9.32→0.004초) |
| `670435c` | 분할 캡처 이어붙이기 (mergecap 병합) |
| `d2b4950` | 로밍 gap 허위 보고 수정 + `total_roam_ms` + STA 로그 |
| `547f3db` | CI mergecap 의존 제거 |
| `4462297`~`30afd2b` | 리뷰 1~5R + 최종 9건 (아래) |

### 리뷰 6라운드 — 반영 29건
봇 3종(Codex·Claude·Gemini). **지적을 코드로 재현·검증한 뒤** 실재하는 것만 반영했다.
Claude가 준 줄번호가 틀린 경우도 있었고(`station_match.py:1371` → 실제 267),
Gemini는 diff 5만 자 절단으로 **이미 반영된 것을 매 라운드 반복 지적**했다.

| R | 반영 | 실측 산출 수치 변화 |
|---|---|---|
| 1R | 9건 | cliff 미탐 복원 (+1%) |
| 2R | 4건 | 없음 |
| 3R | 5건 | 없음 |
| 4R | 6건 | 없음 |
| 5R | 5건 | 없음 |

**즉 1R 이후 20건은 전부 방어·정확성 보강이고 산출 수치를 바꾸지 않았다**
(로밍 858 / 느린 로밍 4 / cliff 2,446·2,407·2,394·88·57 / 건강도 63·18·99 고정).

### 이 PR에서 배운 것 (재발 방지)
1. **지표를 바꾸는 수정은 단위 테스트로 부족하다.** 버킷 내부 cliff를 기존 루프에
   끼워 넣었더니 skip-ahead가 죽어 cliff가 **2배**로 부풀었다(2,419→4,310). 단위
   테스트는 두 구현 모두 통과했고, 실측 캡처 전/후 대조로만 잡혔다.
2. **즉석 스크립트 수치를 근거로 쓰지 말 것.** "스킵 때문에 로밍 14건에 낡은 근거"
   → 실제 파서 대조로는 **0건**이었다(`0d90c92`에서 정정). "STA 로그 부착 0→837"도
   BEFORE를 worktree에서 돌려 `tmp/` 데이터가 없던 **테스트 설정 문제**였다.
3. **봇 지적을 그대로 받아쓰지 말 것.** 5라운드 동안 매번 실재 결함이 하나씩
   나왔지만, 반복·오독·이미 반영된 것도 섞여 있었다. 특히 Claude가 4라운드 요구한
   `attach_station_to_sequences` 방어적 복사는 **얕은 복사여도 기능이 깨진다**
   (그 dict들이 곧 결과에 실리는 객체다).

## Current State

### 타깃 실측 기준
`mergecap`으로 TEST9 무선 3파일을 합친 단일 2시간 캡처
(`1,434,737프레임 / 311MB / span 7,183초 / 밀도 200fps`). 유선 2시간은
`374,564프레임 / 133MB / 52fps`로 훨씬 가볍다 — **밀도가 4배 차이**나므로
"2시간"의 부하는 항상 무선 기준으로 잡아야 한다.

### ① CPU 병목 (385초 → 10초)
- **`analyzer/web/structured.py` `_device_entry_stats`** — 10초 버킷 루프를 버킷별 전체
  재스캔 O(span/10 × frames)에서 **단일 패스** O(frames + 버킷수)로 (315.6초 → 8.2초,
  백로그 ⑥ 소진). **출력 동일성을 무작위 400회 차분 검증으로 확인(불일치 0)** — 빈 버킷
  출력, 경계 프레임 귀속, 손상 epoch, Counter 삽입 순서(most_common 동점 순서)까지 보존.
  회귀 고정: `tests/test_structured_aggregations.py`의 exact-value 단언 3건.
- **`analyzer/web/evidence.py` `cliff_evidence`** — 프레임 × cliff 전수 `any()` O(N×K)를
  정렬 + `bisect_left` 좌우 이웃 조회로 (69.4초 → 1.6초). 미확인 병목이었다.

### ② 페이로드 (120.8MB → 33.7MB)
- **`signal_cliff.py` `moving_avg` 제거** — JS·리포트·AI 어디서도 읽지 않는 26MB dead
  payload였다(소비자 0건 전수 확인).
- **`structured.py` `_bucket_rssi_timeline` (신규)** — `signal.*.rssi_timeline`을 프레임당
  원샘플에서 **1초 버킷 집계**로 (53.2MB → 5.9MB).
  `{epoch, rssi(평균), rssi_min, rssi_max, n, mcs}`.
  **`epoch`/`rssi` 키와 의미를 구버전과 동일하게 유지**한 게 핵심 — timeline.js,
  `timeline_series.project_rssi_series`, signal_cliff, evidence 축 계산이 **분기 없이**
  구·신 결과를 모두 읽어 **프론트 수정이 0줄**이다.
- **ping `pairs`/`losses` 중복 제거** (32.8MB → 18.79MB) — 아래 별도 항목.

### ③ ping (JSON 32.8MB + DOM 41,667행 → 18.79MB + 500행)
- `build_ping_matches`는 **같은 entry 객체**를 `full_list`와 `pairs`/`losses`에 동시
  append한 뒤 각각 안정 정렬한다(lockstep 불변식) — 메모리에선 참조 공유라 공짜지만
  JSON에서는 `full_list`가 통째로 두 번 더 직렬화됐다.
- `_structured_ping`이 두 키를 빼고, 공용 헬퍼 **`ping_matching.ping_pairs()` /
  `ping_losses()`** 가 `full_list`에서 파생한다. 소비자 4곳을 이 헬퍼로 모았다:
  `web/delay_analysis.py`, `web/structured.py`(`_structured_diagnosis`), `ai/prompts.py`,
  `static/js/charts.js`. (`ping_loss.py`·`diagnosis.py`·`ping_rtt.py`는 `build_ping_matches`를
  직접 호출해 무관.)
- **lockstep이 오히려 견고해졌다** — 파생이 곧 원래 부분수열이라 인덱스 조인이 정의상
  정확하다. 별개 배열 두 개의 순서를 맞춰야 하던 문제 자체가 사라졌다. 기존 `lossOrderOk`
  가드는 구버전 result용으로 그대로 남겼다.
- **전수 목록 표 500행 페이지네이션** (`templates/analysis.html` 페이저 + `charts.js`).
  손실 마커 클릭 내비게이션이 **대상 행이 있는 페이지로 먼저 이동**한 뒤 스크롤한다.
  행 번호는 전역 기준 유지(2쪽 첫 행 = 501).

### ④ 분할 캡처 이어붙이기 (신규 기능)
스니퍼 파일 로테이션으로 쪼개진 **연속 캡처** 조각을 한 번에 올리면 하나로 합쳐 분석한다.
- **`analyzer/core/split_merge.py` (신규)** — `merge_split_captures()`(mergecap 시간순 병합,
  exit code/빈 산출물/타임아웃 방어) + `merged_display_name()`.
- **`config.detect_mergecap()`** — 감지된 tshark와 같은 디렉터리를 먼저 보고(PATH에 없는
  Windows 설치 경로·사용자 지정 경로 대응) 그다음 PATH.
- **`routes/upload.py` `_save_capture_group()`** — `file`/`wired_file`이 조각 리스트를 받는다.
  **조각 1개면 mergecap을 부르지 않고 기존 경로 그대로**라 동작이 바뀌지 않는다.
  조각 상한 32개. 실패 시 앞서 저장한 조각 임시파일까지 전부 정리.
- **`wireless_files`(추가 무선)와 성격이 정반대**라 UI 문구를 분리했다 — 이쪽은 같은 구간을
  다른 위치에서 **동시에** 관측한 별개 스니퍼로 TSF 정렬 + dedup 경로를 탄다.
  분할 조각을 거기 올리면 겹치지도 않는 구간에 정렬·dedup을 시도하게 된다.
- 전용 에러 코드 `MERGECAP_MISSING` / `MERGE_FAILED`(실패 사유 그대로 노출).

### ⑤ 서버 경로 최적화 (홈 9.32초 → 0.004초, 전송 34MB → 3.4MB)
- **홈 메타 사이드카** (`config.analysis_meta_path` + `routes/upload.write_analysis_meta`) —
  저장 시 `{id}.meta.json`(4필드, 130바이트)을 함께 쓰고 홈은 그것만 읽는다. 사이드카가
  없는 구버전 결과는 **1회 파싱 후 사이드카를 만들어** 다음부터 빠른 경로를 탄다.
  실측: 사이드카 없는 상태(47건 926MB) 첫 로드 **8.791초** → 이후 **0.004초** (약 2,100배).
  사이드카 47개 총 188KB(본 결과의 0.02%). `index()`를 `async def` → **`def`** 로 바꿔
  threadpool로 내보냈다 — 동기 I/O·파싱이 이벤트 루프를 잡지 않는다.
  삭제 라우트가 사이드카도 함께 지운다. `*.json` 글롭에서 사이드카를 반드시 걸러야 한다
  (`config.is_analysis_meta`).
- **결과 파싱 캐시** (`routes/analysis._read_result_cached`) — `(경로, mtime_ns, size)` 키,
  최대 2개. 분석 페이지 하나를 열면 페이지·report·casefile이 같은 파일을 여러 번 읽는다.
  **계약: 캐시된 dict를 변형하지 말 것** — 파일을 다시 쓰는 `routes/ai_review.py`는 이
  헬퍼를 쓰지 않고 자체 로드하며, 그쪽이 파일을 갱신하면 mtime/size가 바뀌어 자동 무효화된다.
- **GZipMiddleware** (`app.py`, minimum_size=1024, compresslevel=6) — 분석 페이지
  34.1MB → **3.4MB**(1/10.0). 초당 시계열·ping 전수목록처럼 반복 구조라 압축률이 높다.
  참고: localhost에서는 압축 CPU(ttfb 0.36→0.98초)와 전송 절감이 거의 상쇄되지만,
  원격 접속에서는 30MB를 아끼는 결정적 차이다.
- **관찰 프레임 표 페이지네이션** — `ping-observations-table` 7,503행 → 500행(16쪽).
  전수 목록과 `PING_PAGE_SIZE`를 공유한다. **선언 위치 주의**: 관찰 프레임 블록이 전수
  목록 블록보다 **먼저 실행**되므로 상수는 ping 섹션 최상단에 둬야 한다(const TDZ —
  실제로 이 순서를 어겨 한 번 깨졌다).
- **테스트 누수 수정** — 실제 `data/analyses`를 쓰는 기존 테스트 2곳이 결과 `.json`만
  정리해 사이드카가 고아로 남았다. `tests/conftest.remove_analysis_files()`로 둘을 함께
  지우도록 17곳을 교체했다.

### ⑥ 로밍 gap 허위 보고 버그 수정 (사용자 제보)
`tmp/sync2/TEST9` 분석에서 로밍 gap이 수십 초로 나온다는 제보 → **허위 확진**.

**증상**: 로밍 861건 중 10건이 16~32.7초 gap, 전부 `ReassocReq`, 전부 느린 로밍으로 오분류.
(`ROAM_GAP_DANGER_MS`=100ms이라 진단 왜곡)

**원인 3단계** (프레임 42763/42765로 직접 확인):
1. 모니터는 한 채널만 듣는다 — STA가 대상 AP 채널에서 보낸 **Auth 요청이 캡처에 없다**.
   해당 프레임의 `ta`는 AP2로, **AP의 Auth 응답만** 잡혀 있었다.
2. 코드는 **STA 송신 Auth만** 앵커로 인정해 이 로밍의 시작점을 찾지 못했다.
3. 앵커를 **소비 후 지우지 않아** 수십 초 전 다른 로밍의 Auth가 그대로 짝지어졌다.
17건 전수 조사 결과 **16건은 Reassoc 3.4~6.2ms 전에 AP Auth 응답이 실재** — 실제 로밍은
정상 속도였고 보고된 지연은 전부 허구였다.

**측정 불가 표시 (사용자 요청)**: 앵커를 못 찾아도 **시퀀스는 남기고** gap만
`None`으로 두며, **어떤 프레임이 없어서 못 쟀는지**를 함께 담는다. 신규 필드:
`gap_basis`(auth_request=정확 / auth_response=하한값 / null=측정불가),
`missing`+`missing_labels`(없는 프레임 종류), `gap_note`(사유 문장).
화면은 "측정불가 + STA→AP Auth 요청, AP→STA Auth 응답 미포착"(+툴팁 전문), 차트는
막대를 0이 아니라 **null로 비우고** hover에 사유, 리포트는 "측정불가 (… 미포착)".
AP 응답 기준으로 잰 건 `4.9 (하한)`으로 표시해 하한값임을 숨기지 않는다.

**gap_ms=None 도입 시 깨진 소비자** (워크플로우 감사 35 에이전트 + 실측):
- `delay_analysis.py:33` **실제 500 발생** — `seq.get("auth_epoch", 0)`은 키가 있고 값이
  None이면 0이 아니라 None을 준다 → `abs(None - float)` TypeError로 분석 전체가 죽었다.
  단위 테스트 1035건이 전부 통과했는데도 죽었다 — 소비자를 개별로 보는 것만으로는
  부족하고 데이터를 파이프라인에 흘려야 잡힌다.
- `ai/prompts.py:138` 정렬 키 `-x.get("gap_ms", 0)` TypeError (AI 리뷰 3개 라우트 500)
- `static/js/charts.js:433` `null.toFixed` — charts.js는 단일 IIFE라 로밍 표뿐 아니라
  **그 뒤 전 탭(장치별·Ping·진단·증거점프)이 통째로 죽는다**
- `static/js/timeline.js:352` `epochToDate(null)`→1970 shape → 공유 x축 autorange 붕괴
- `thresholds.roam_gap_severity(None)` → `"unknown"` 신설(good으로 낙관 금지)
- **건강도 분모 오염**(감사가 찾음, 예외 없이 조용히 틀림): 측정 불가를 "느리지 않음"으로
  세면 느린 비율이 희석된다. 로밍 10건 중 6건 측정불가·나머지 4건 중 2건 느림이면
  실제 50%인데 20%로 계산돼 점수가 60 부풀려지고, **전량 측정 불가면 만점**이 나와
  "캡처가 나쁠수록 건강해 보이는" 역전이 생긴다. 측정된 것만 분모로 쓰고 하나도 없으면
  컴포넌트를 `None`으로 두어 기존 `loss_score` 재정규화 경로에 태웠다(STA별은 계수 200이라
  왜곡 폭 2배). `roaming_measurable`/`roaming_unmeasured`를 summary에 노출.
- 로밍 발생 시각은 **`assoc_epoch`으로 항상 알 수 있으므로** auth_epoch이 없을 때 그쪽으로
  폴백한다 — 측정 불가라고 로밍이 타임라인·원인 후보·casefile에서 사라지면 안 된다.

**수정**: 짝짓기 로직이 `roaming.py`(텍스트)와 `structured._structured_roaming`(화면)에
**복제**돼 있어 버그도 양쪽에 동일했다 → `roaming.pair_roaming_sequences()` **단일 소스**로
통합하고 규칙 정리:
1. 앵커는 **소비 즉시 폐기** (낡은 Auth 재사용 불가 — 핵심)
2. **AP의 Auth 응답을 폴백 앵커**로 인정 (STA 요청을 놓쳐도 실제 gap 복원)
3. 같은 Auth 교환이면 **STA 요청 우선** (`_SAME_AUTH_EXCHANGE_SEC`=1초)
4. `ROAM_PAIR_MAX_GAP_SEC`=10초 상한 — 앵커를 못 찾으면 **건너뛴다**(gap을 지어내지 않음)

앵커 부재 시 `gap_ms=None` 대신 시퀀스를 건너뛴 이유: `static/js/charts.js:433`이
`s.gap_ms.toFixed(1)`을 호출해 None이면 깨진다. Auth가 아예 없을 때 건너뛰던 기존 동작과도
일치한다.

**실측 검증** — 사용자와 **완전히 동일한 입력**(무선 3조각 이어붙임 + DFK 스니퍼 3대 +
유선 GT, frame_count 1,464,643 동일 확인):
| 지표 | 수정 전 | 수정 후 |
|---|---|---|
| **시퀀스** | 861 | **861 (보존)** |
| 최대 gap | 32,687.9ms (32.69초) | **104.0ms** |
| 1초 초과 | 10건 | **0건** |
| 느린 로밍 | 13건 | **3건** |
| 하한값(AP응답 기준) | 0 | 10건 |
| 측정 불가 | 0 | 0건 |
| 건강도 roaming | 97 | 99 |

**주의(비교 함정)**: 처음엔 무선 3조각만 올려 재분석해 "861→857"로 보고했는데 이는
사과-오렌지였다. 사용자는 DFK 스니퍼 3대와 유선 GT를 함께 썼고, 시퀀스 3건 차이는 그
스니퍼들이 추가로 잡은 Reassoc이었다. 원본 캡처의 STA 송신 Assoc은 정확히 858건으로
별도 검증했다. **다중 스니퍼는 앵커 확보에 유리하다** — 무선 단독에선 측정 불가 1건이
다중 스니퍼 구성에선 0건이 된다(다른 스니퍼가 그 Auth를 잡았다).

브라우저 확인: 측정 불가 행이 "측정불가 / STA→AP Auth 요청, AP→STA Auth 응답 미포착"으로
표시되고 툴팁에 사유 전문, 차트는 해당 막대만 null(hover에 사유), 시각은 Assoc 기준으로
채워짐. 하한값 10건은 `4.9 (하한)`. Plotly 21~22개·콘솔 오류 0으로 전 탭 정상.

회귀 테스트 `tests/test_roaming_pairing.py` **29건** — 앵커 소비·AP 폴백·교환 내 우선순위·
상한·측정불가 유지·텍스트↔화면 등가성·**소비자 None 통과**(report/prompts/thresholds)·
**파이프라인 통합**(analyze_delays→diagnosis→debug 관통)·**건강도 분모 오염**.

### ⑦ 로밍 구간 분리 표시 — gap이 로밍 비용을 5배 과소평가하던 문제
"장치 로그는 로밍 50ms인데 pcap 분석은 10ms 언더"라는 사용자 질문에서 출발.
**버그가 아니라 측정 구간이 달랐다.** 프레임 단위 실측(858건):

| 구간 | p50 | p90 |
|---|---|---|
| Auth 요청 → Auth 응답 | 0.0ms | 0.0ms |
| Auth 응답 → Reassoc 요청 | 5.2ms | 7.4ms |
| Reassoc 요청 → Reassoc 응답 | 0.0ms | 0.0ms |
| **Reassoc 응답 → 4-way 완료** | **19.5ms** | 25.7ms |
| **Auth 요청 → 4-way 완료(전체)** | **25.1ms** | 32.2ms |

`gap_ms`는 **Auth→Reassoc 구간만** 재는데 그게 전체 25.1ms 중 5.3ms다 — 나머지
대부분인 4-way가 지표에서 빠져 있었다. 50ms와의 잔여 차이는 전파에 안 나타나는
부분(스캔·로밍 판단·드라이버 처리·키 설치)으로 모니터 캡처로는 측정 불가.

이 캡처는 **로밍 조건이 가장 유리한 경우**임에 주의: 861건 전부 `48→48` 같은 채널,
밴드 전환 0건이라 채널 스위치 비용이 없다(AP1↔AP2 왕복 429/432회).

**대응(사용자 선택: 구간 분리 표시)** — 기존 지표를 깨지 않고 전체 그림을 추가:
- **`total_roam_ms` 신설** = Auth 요청 → 4-way 완료. `gap + four_way` **단순 합이
  아니라** 핸드셰이크 실제 종료 시각에서 계산한다(Reassoc 요청 ~ 4-way 시작 대기
  ~2ms가 빠지기 때문). 실측 검증: gap 4.0 + 4way 11.6 = 15.6이지만 전체는 17.6.
- `eapol.match_four_way()` 신설(매칭된 핸드셰이크 반환), `match_four_way_ms`는 이를
  재사용 — 두 값이 같은 매칭 규칙을 쓰도록 단일 소스화.
- 4-way 미포착이면 `total_roam_ms=None` + `total_note`("FT로 생략됐거나 EAPOL 놓침").
  Auth 앵커가 없으면 "시작 시각을 몰라 계산 불가". 지어내지 않는다.
- **차트를 구간 누적 막대로**: `Auth→Reassoc`(파랑/느리면 빨강) + `Reassoc→4-way
  시작`(보라) + `4-way`(초록). 실측 5.3+2.0+17.7=25.0으로 전체와 일치.
- 표에 `전체(ms)` 열 + 열별 툴팁, report.md 열 + 각주, AI 프롬프트에 total 통계와
  "gap_ms는 일부 구간 — 로밍 빠르기 판단은 total_roam_ms로 할 것" 경고.
- **느린 로밍 임계를 `total_roam_ms` 기준으로 이전**(후속 요청). gap에만 걸린 100ms는
  사실상 발동하지 않는 임계였다(gap p90이 7.5ms라 13배 여유). 판정은 3갈래:
  `slow_basis="total"`(전체를 알아 정확 판정) / `"gap_lower_bound"`(전체는 모르나
  **total ≥ gap 이 항상 성립**하므로 gap이 이미 임계를 넘으면 확정적으로 느림 —
  아는 정보를 버리지 않는다) / `None`(판정 불가 = '정상'이 아니라 '모름', 건강도
  분모에서 제외). 텍스트 모듈(`roaming.analyze`)도 같은 규칙으로 맞췄다 —
  화면과 텍스트가 다른 건수를 말하면 안 된다(이 버그의 근원이 로직 복제였다).
  표시 문구를 전부 "느린 로밍(전체 소요 >100ms)"로 바꿔 임계 위치를 드러냈다.

  실측 영향(사용자 파일 861건): 느린 로밍 **3건 → 4건**, 판정 분모 861 → 820,
  건강도 roaming 99.30 → 99.02. 새로 잡힌 1건이 문제를 정확히 보여준다 —
  `gap 6.3ms / 4-way 41.7ms / 전체 105.0ms`로, Auth→Reassoc은 매우 빠른데 4-way가
  길어 전체는 임계를 넘긴 로밍이 "정상"으로 분류되고 있었다.
  판정 근거 분포: total 820 / gap_lower_bound 0 / 판정불가 41.
  느린 4건의 전체값: 113.5 / 117.4 / **105.0(신규)** / 119.3ms.

  **이 전환 중 낸 크래시(3번째 같은 실수)**: STA별 `s_roam`이 None이 될 수 있는데
  `round(s_roam)`을 그대로 호출해 `TypeError: type NoneType doesn't define __round__`
  로 분석 전체가 죽었다. **일반 테스트 1054건은 통과했고 tshark 골든에서만 5건
  실패**했다 — 내 테스트가 `device_stats`를 비워둬 `sta_diags`가 아예 안 만들어졌기
  때문. 교훈: `None`을 새로 도입하면 소비자를 전수 추적하고, **그 코드 경로가 실제로
  생성되는 입력**으로 테스트해야 한다(빈 fixture는 경로를 우회한다).
  함께 고친 표시 문제 2건:
  - `charts.js` STA 카드 `scores.roaming || 0` → 판정 불가를 **0점(최악)** 으로 표시할
    뻔했다(분모 오염 때는 반대로 만점이었다). "측정불가" 표기로 교체.
  - report.py `느린 로밍 0회`가 판정 불가일 때도 정상처럼 읽혀 **판정 분모를 병기**
    (`느린 로밍 0회 (판정 0/3회)`).

실측(사용자 파일 861건): gap p50 5.3ms / 4-way p50 17.6ms / **전체 p50 25.2ms**
(p90 32.1, max 119.3). 전체 측정 820건·불가 41건(4-way 미포착). `전체 ≤ gap` 이상치 0건.
회귀 테스트 6건 추가(단순 합이 아님·전체>gap 불변·미포착 시 None·리포트/프롬프트 노출).

### ⑧ STA 로그 첨부 — pcap이 못 보는 74%를 복원 (신규 기능)
"장치 로그는 로밍 50ms인데 pcap은 10ms 언더"라는 질문의 최종 답. pcap은 **전파에
나온 프레임만** 본다 — 실측 776건 대조로 로밍 전체 97.0ms 중 pcap이 보는 건
25.1ms뿐이고 **74.1%가 전파 밖**(스캔·로밍 판단·드라이버 처리·키 설치)이다.

**입력**: 호기(STA 1대) 폴더를 통째로 선택하면 `wpa.log`·`kern.log`·`logger.log`
3종만 전송한다(cpu/stat 등은 무시). 브라우저 디렉터리 업로드는 basename만 보내
호기 구분이 사라지므로, 클라이언트가 FormData filename에 `webkitRelativePath`를
넣고 서버가 `<호기>/<파일>`로 그룹핑한다.

**신규 모듈**
- `analyzer/core/station_log.py` — 로그 3종 파서
- `analyzer/core/station_match.py` — STA 매칭 + 시계 오프셋 + 시퀀스 부착
- `pipeline.run_analysis(station_logs=...)` → `structured["station_logs"]`,
  각 로밍 시퀀스에 `sta_log`(total_ms/assoc_ms/scan_ms/reason/score/trigger/residual)

**조사에서 나온 함정 (전부 반영, 하나라도 놓치면 조용히 틀린다)**
- 로밍은 **`ROAM` 명령**으로 센다. `CTRL-EVENT-CONNECTED`는 307건으로 1건 많다
  (ROAM 없는 자동 재접속) — 그걸로 세면 과대계상.
- 스캔 페어링은 **정방향 단일 슬롯**. 역방향("COMPLETED 직전 START")이면 고아
  COMPLETED(호기당 3~4건) 때문에 **4,607ms짜리 가짜 스캔**이 생겨 max/p99 오염.
- STA IP는 `bridge: wlan IPv4 updated` 614줄 중 **절반이 0.0.0.0**(로밍마다 쌍으로
  찍힘). 필터 없이 첫 값을 쓰면 세 호기 모두 0.0.0.0이라 매칭 전멸.
- 스캔 소요는 **커널 monotonic**으로 잰다. 벽시계는 지터가 ±수백 ms.
  단 monotonic은 호기마다 부팅 기준이 달라 **호기 간 비교 금지**.
- `Roaming: A → B`가 wifi_roam.py 두 지점에서 찍혀 306건이 612건이 된다 — 중복 제거.
- **호기 번호 ≠ STA 번호**(1호기=STA2, 2호기=STA3, 3호기=STA1). 폴더명으로 STA를
  추론하는 코드는 절대 금지. pcap ARP에서 MAC↔IP를 떠서 자동 매칭한다(하드코딩 없음).

**시계 정렬**: 로그는 타임존 없는 벽시계라 보정 없이는 상관 불가. NTP 프레임 추출
같은 외부 의존 없이 **로밍 시각 상호상관**으로 오프셋을 추정한다(정답쌍 MAD 20ms vs
오답쌍 4.7~9.5초로 500배 분리). 실측 오프셋 +0.110~0.130s / MAD 13.8~20.7ms.
※ 이 값이 감사가 보고한 +2.744s와 다른 건 `sync2`(시계 보정 완료본)를 썼기 때문이다.
남은 0.11s는 "로그 스탬프 → 실제 공중 전송" 물리 지연(감사 실측 ~109ms)과 일치한다.
원본 pcap을 쓰면 +2.85s가 나온다.

**차트는 누적이 아니라 중첩(범위)**: pcap 전파구간은 STA 체감 로밍의 **부분집합**이라
연회색 배경 영역(STA 체감 97ms) 안에 색 막대(pcap 25ms 3구간)를 그린다.
**스캔은 막대에 넣지 않는다** — ROAM 명령보다 정확히 1,044ms 앞서 끝나는 별개
이벤트다(겹침 0건). 쌓으면 로밍이 그만큼 더 걸린 것처럼 보인다.
**세부 구간을 개별 막대에 넣지 않은 이유**: `AUTHENTICATING → 첫 Auth 프레임`이
실측 **−22.9ms(음수)** 다. 로그 스탬프가 실제 송신보다 늦게 찍히기 때문이라
20ms짜리 구간을 ±23ms 오차로 그릴 근거가 없다 → 분포(p50)로 요약 카드에만 낸다.

**실측 검증** (사용자 파일 + 호기 3대, 실서비스 업로드 경로):
| 호기 | STA IP | → pcap STA | 방법 | 부착/로밍 | 체감 p50 | 스캔 p50 | MAD |
|---|---|---|---|---|---|---|---|
| 1호기 | .21 | **STA2**(18fe01) | IP | 281/306 | 96.5ms | 61.7ms | 20.7ms |
| 2호기 | .22 | **STA3**(19fe01) | IP | 278/306 | 96.0ms | 61.7ms | 13.8ms |
| 3호기 | .23 | **STA1**(1afe01) | IP | 278/306 | 97.0ms | 61.7ms | 18.9ms |

로밍 858건 중 837건 부착, 같은 로밍 776건 대조 → **pcap 25.1ms vs STA 체감 97.0ms
(전파 밖 74.1%)**. 유선 GT 동시 사용 정상, 결과 JSON 33.8 → 38.5MB.
회귀 테스트 `tests/test_station_log.py` 16건(경계·고아스캔·0.0.0.0·중복제거·
오프셋 복원·IP 바인딩·허용오차 밖 미부착·부분 파일).

### cliff 판정 변화 (실측, 같은 2시간 캡처)
| STA | 원샘플 | 구 cliff | 버킷 | 신 cliff |
|---|---|---|---|---|
| STA1 | 133,225 | 7,011 | 7,079 | 2,419 |
| STA2 | 127,267 | 6,898 | 7,058 | 2,376 |
| STA3 | 124,705 | 6,694 | 7,075 | 2,378 |
| STA4 | 20,938 | 117 | 660 | 79 |
| STA5 | 18,755 | 73 | 667 | 53 |

**누락이 아니라 중복 계상 감소다.** 원샘플 쌍 (i,j)에 5초 내 10dB 하락이 있으면
`rssi_max[b_i] ≥ rssi_i`, `rssi_min[b_j] ≤ rssi_j`라 부등식이 버킷에서도 성립한다.
유일한 미탐은 **같은 1초 안에서만 일어난 하락**(멀티패스 순간 변동). 감소분은 구
알고리즘이 조밀한 원샘플을 1샘플씩 전진하며 같은 절벽 구간을 반복 계상하던 몫이다.
(cliff가 2,400건 나오는 것 자체는 탐지 규칙의 과다 탐지로, 이번 변경 이전부터 있던 문제다.)

### end-to-end 검증 (systemd 서비스에 반영 후 실측)
등록된 검증 결과 2건:
- `1786328958_wl_2h_19ca392f.json` (32.1MB, **신 포맷** — pairs/losses 없음)
- `1786327058_wl_2h_19ca392f.json` (45.5MB, **구 포맷** — pairs/losses 보존, 호환성 검증용)

확인 내역:
- 분석 페이지: 로드 **6.7초**, 전송 **3.4MB**(디코딩 34.1MB), DOM **70,126노드**,
  JS 힙 **199MB**, **콘솔 오류 0건**, Plotly 21개 정상
- RSSI 시계열: 노드 8개 각 측정점 787점(7,182버킷 → `RSSI_SCATTER_MAX` 800 상한)·평균선
  150점, −36~−73dBm, 2시간 전 구간
- 파생 정확성: 38,235 matched / 3,432 loss = `stats.count`/`stats.loss_count` **정확히 일치**,
  화면 KPI도 동일(8.24%)
- 페이지네이션: 1쪽(1–500) ↔ 2쪽(501–1,000), 경계 버튼 비활성화, 행 번호 전역 유지
- **페이지 넘김 클릭 내비**: 손실 마커 클릭 → 필터 자동 전환 → 1/7쪽에서 **3/7쪽 자동 이동**
  → #1201 행 정확히 하이라이트
- **구버전 result 호환**: 구 포맷에서도 KPI·건수·페이지·점프가 **완전히 동일**하게 동작
- **분할 업로드 e2e**(HTTP 실경로, TEST9 3조각 311MB): 수동 mergecap 병합본과
  frame_count(1,434,737)·ping.full_list(41,667)·per_second(7,184)·roaming(858)·device(8)
  **전 지표 일치**. `pcap_name` = "Rail_fxa3000_test9_1.pcapng 외 2개 (이어붙임)",
  sources는 **단일 무선 소스**. 업로드+병합+분석 61.6초, 임시파일 누수 없음.
- `report.md` 17KB / 인쇄뷰 23KB / casefile 133KB / text 4.3MB — 전부 200, 0.4초 내
- 관찰 프레임 표: 1쪽(1–500) ↔ 2쪽(501–1,000)/16쪽, 필터 변경 시 1쪽 복귀
- 홈 화면: 사이드카 없는 상태 8.791초 → 이후 0.004초, 고아 사이드카 0건
- 테스트: **1073 passed** (baseline 971 + 신규 102), ruff clean, **tshark golden 19 passed**
  (골든은 실제 pcap을 돌려 sta_diags 등 빈 fixture가 우회하는 경로를 덮는다 — 반드시 함께 돌릴 것).
  수행 시간도 38초 → **4.9초** (홈 전량 파싱 제거 효과)

**In flight:** 없음.

## Next Steps

### 0. 종합 진단의 두 공백 (이번 PR 범위 밖 — 별도 PR 권장)
`_structured_diagnosis`가 실제로 읽는 입력은 `overview`/`ping`/`roaming`/`signal`/
`device_stats`/`delay_zones`/`anomaly_frames` + `signal_cliffs` + `frames`/`index`뿐이다.
건강도는 `retry 0.3 / loss 0.4 / roaming 0.3` 가중 평균(측정 불가 컴포넌트는 None으로
빼고 재정규화)이고, `build_correlations`는 진단 결과만 입력으로 받는다.

- [ ] **STA 로그가 진단에 전혀 연결돼 있지 않다.** `structured["station_logs"]`와
      시퀀스별 `sta_log`는 표·차트·요약 카드에만 쓰이고 건강도·issues·report.md·
      AI 프롬프트 어디서도 읽지 않는다(`grep station_logs\|sta_log`가 structured.py·
      causality.py·report.py·ai/prompts.py에서 0건). 로그에는 로밍 **사유**
      (`RSSI diff: 17dB`, score)와 스캔 소요가 있어 "왜 이 로밍이 느렸나"를 근거와
      함께 말할 수 있다.
- [ ] **건강도의 loss(가중치 0.4)가 유선 GT가 아니라 무선 관측치를 쓴다.**
      `ping.stats.loss_pct`(무선 관측)를 쓰고 `ping.ground_truth`(유선 확정)는 읽지
      않는다. 실측 유선 0.38% vs 무선 8.24%로 **20배** 차이라 점수가 크게 달라진다.
      프로젝트 대원칙 "판정은 유선 1차"와 어긋나는 지점 — 둘 중 영향이 더 크다.

그 외 진단이 읽지 않는 것: `eapol`(four_way_ms는 로밍 시퀀스 안에만), `merge`,
`sniffer_compare`.

### 1~3. 기존 보류 항목 (데이터 계약 변경이라 의도적으로 미룸)

1. **`ping.full_list` 자체가 14MB** (structured 34MB의 41%) — 실측 336B/건 × 41,667건.
   필드별 기여: `reply_time` 29.9B + `req_time` 29.0B = **2.46MB**,
   `src_mac` 25.0 + `dst_mac` 24.0 + `src` 21.0 + `dst` 21.0 = **3.79MB**(소수 문자열이
   4만 번 반복), 나머지는 건별 고유값.
   - `req_time`/`reply_time` 제거는 **시간대 의미가 바뀐다** — 지금 값은 tshark가
     **캡처 호스트 시간대**로 렌더한 문자열인데, 프론트가 epoch에서 만들면 **브라우저
     시간대**가 된다. 로컬 실행이면 같지만 원격 접속에서 달라지고, 서버에서 만드는
     `report.md`와도 어긋난다.
   - `src/dst/*_mac` 룩업 테이블화는 `casefile_builder`가 full_list entry를 그대로 복사해
     casefile에 싣고, `_ping_per_sec`·`_ping_loss_streaks`가 `src_mac`/`dst_mac`으로 장치를
     귀속하므로 해석 지점이 여러 곳으로 늘어난다.
   - gzip 도입으로 **전송 측면 이득은 이미 확보**됐고(3.4MB), 남는 비용은 V8 파싱과 힙이다.
     이득 11% 대비 위험이 커서 사용자 판단이 필요하다.
2. (선택) **inline → fetch 분리** — structured를 HTML `<script>`에 심는 대신
   `/api/analysis/{id}/structured`로 받으면 셸이 먼저 뜨고, 문자열 `JSON.parse`가 객체
   리터럴 파싱보다 빠르며 브라우저 캐시도 쓸 수 있다. charts.js/timeline.js 초기화를
   비동기로 바꿔야 해 초기화 순서 회귀 위험이 있다.
3. (참고) 백로그 ⑤ 대시보드 sniffer-series 다운샘플링은 여전히 미발생 — `TIMELINE_MAX`가
   3시간이라 2시간 초당 시계열은 무손실 통과한다.

## Key Decisions
- **범위 B 선택** (사용자 승인): 개통 + 페이로드 감축. 인프라 정리(범위 C: 홈 인덱스·캐시·
  이벤트루프·Frame `__slots__`)는 제외 — Next Steps 1~3으로 남김.
- **RSSI 시계열은 서버 1초 버킷 집계** (사용자 승인): 줌인해도 원샘플이 아니라 집계점이
  보인다. 프론트가 어차피 장치당 800점으로 솎아 그리고 있어 전송량의 99.9%가 버려지던
  구조였다. `epoch`/`rssi` 키 유지로 프론트 수정 0줄 + 구버전 결과 자동 호환.
- **"다중 파일 업로드"는 분할 캡처 이어붙이기** (사용자 확인): 동시 관측 스니퍼 확대나
  배치 분석이 아니라, 로테이션으로 쪼개진 연속 캡처를 하나로 합치는 것. 두 개념을 UI에서
  명확히 분리했다.
- **pcap 레벨(mergecap)에서 합친다**: 프레임 리스트를 파이썬에서 이어붙이는 대신 파일을
  합쳐 파이프라인에 **단일 캡처**로 넘긴다 — 분석 로직이 "원래 한 파일이었던 캡처"와
  완전히 같은 경로를 타고 frame.number도 일관되게 매겨진다. 변경이 업로드 경계에 갇혀
  회귀 위험이 최소다.
- **`ping.full_list`는 유지, 중복만 제거**: 전수 목록의 완전성(모든 ping 행)은 진단 근거라
  샘플링하지 않는다. 대신 파생 가능한 `pairs`/`losses`만 뺐다.
- **사이드카는 파생 캐시로만 취급**: 사라져도 본 결과에서 언제든 복구되고(폴백+백필),
  손상돼도 본 파일로 자동 복구한다. 진실의 원천은 항상 `{id}.json`이다.
- **`req_time`/`reply_time`은 유지**: epoch에서 재생성 가능하지만 시간대 의미(캡처 호스트
  vs 브라우저)가 달라져 report.md와 어긋난다 — 2.46MB를 아끼자고 표시 값의 일관성을
  깨지 않는다(Next Steps 1).
- 기존 대원칙 유지: 판정 유선 1차·해석 무선 보조 / 모집단 동일성 / GT 없는 결과는 출력 불변 /
  정직한 공백.

## Open Questions
- [ ] 종합 진단 공백 2건(Next Steps 0) 중 어느 쪽부터 볼지. 영향은 **유선 GT를
      건강도 loss에 반영**하는 쪽이 더 크고 프로젝트 대원칙과도 맞는다.
- [ ] 검증용 결과 2건(`1786328958`=신 포맷 32.1MB, `1786327058`=구 포맷 45.5MB)을 남길지.
      홈 화면이 이제 사이드카를 읽어 **로드 비용은 없어졌고** 디스크(4.9GB 여유)만 쓴다.
      구 포맷 쪽은 하위호환 회귀 확인용으로 가치가 있다.
- [ ] Next Steps 1(`full_list` 슬림화)을 진행할지 — 11% 감축 대비 시간대·casefile 계약 변경.
- [ ] `ROAM_GAP_DANGER_MS`(100ms) 상수명이 이제 gap이 아니라 전체 소요에 걸린다 —
      `ROAM_TOTAL_DANGER_MS` 류로 개명할지(호출부 5곳 + 테스트).

## Working Environment
- Branch: `main` (PR #28 머지 완료, feature 브랜치 삭제됨)
- CI: Tests **success**(31374075619) · Commitlint **skipped**(`COMMITLINT_ENABLED`
  변수 미설정) · Gemini Dispatch success · Claude/Gemini 리뷰 진행 중
- **CI 함정**: 러너에 mergecap이 없다. 분할 캡처 라우트 테스트는 `merge_split_captures`만
  patch하면 부족하고 **`config.detect_mergecap`도 고정**해야 한다 — 라우트가 병합 호출
  전에 감지를 하므로 patch한 가짜 병합에 도달하지 못한다(로컬은 Wireshark가 깔려 있어
  통과, CI에서만 3건 실패). `547f3db`에서 autouse 픽스처로 고정. 러너 환경 재현은
  `config.detect_mergecap`을 None으로 만드는 pytest 플러그인 한 장이면 된다.
- Commands: `python3 -m pytest tests/ -q` (1073), `ruff check .`,
  tshark golden: `python3 -m pytest tests/ -q -m tshark` (19),
  app: systemd user service on :8000 (`systemctl --user restart pcap-analyzer`)
- **디스크 주의**: `/`가 사용률 100%, 여유 4.9GB. 업로드 상한이 1GB이고 분할 조각은
  **조각마다** 그 상한이 적용되며 병합본이 한 벌 더 생긴다(조각 합계 + 병합본).
- 재현용 픽스처(세션 scratchpad, 영구 아님):
  `mergecap -w wl_2h.pcapng tmp/20260722_CFI/TEST9/wireshark/무선/Rail_fxa3000_test9_{1,2,3}.pcapng`
  — 또는 이제는 그 3파일을 대시보드 드롭존에 그대로 올리면 된다.
- Changed files (`git diff --stat` + untracked):
  ```
  ai/prompts.py                          |   8 +-
  analyzer/core/ping_matching.py         |  47 +++++++++
  analyzer/errors.py                     |  10 ++
  analyzer/web/delay_analysis.py         |   7 +-
  analyzer/web/evidence.py               |  13 ++-
  analyzer/web/signal_cliff.py           |  51 +++++----
  analyzer/web/structured.py             | 190 +++++++++++++++++++++++++-------
  config.py                              |  30 +++++-
  routes/upload.py                       |  75 ++++++++++---
  static/js/charts.js                    | 110 +++++++++++++++----
  static/js/upload.js                    |  60 ++++++++---
  templates/analysis.html                |  12 ++-
  templates/index.html                   |  16 ++-
  tests/… (test_config, test_pipeline, test_ping_matching,
           test_structured_aggregations, test_web_modules)
  (untracked) analyzer/core/split_merge.py
  (untracked) tests/test_routes_upload_split.py
  ```

## Context for the next tool (3-5 sentences)
이 저장소는 WLAN pcap을 분석해(tshark 추출 → 분석 모듈 → FastAPI 대시보드) 유선 캡처를
ICMP 판정의 1차 소스로, 무선을 해석 보조로 쓴다. 이번 세션은 "2시간 대용량 pcap 분석"
요구를 143만 프레임 실측 픽스처로 병목을 특정해 처리하고(분석 440.9초→63.1초, 결과 JSON
120.8MB→33.7MB, 페이지 로드 10.4초→7.9초), 이어서 스니퍼 로테이션 조각을 한 번에 올려
하나의 캡처로 분석하는 기능을 추가했다. 변경의 핵심 설계는 "직렬화 형태만 줄이고 소비자
계약은 헬퍼/키 유지로 보존" — 그래서 구버전 result가 분기 없이 그대로 렌더된다.
모두 미커밋 상태이고, 남은 병목은 서버 인프라 쪽(홈 화면 전량 파싱, gzip 부재, 결과 캐시
없음)으로 Next Steps에 정리돼 있다.
