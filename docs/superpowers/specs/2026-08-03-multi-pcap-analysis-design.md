# 멀티 pcap 분석 설계 — 무선 N + 유선 ground truth

- 날짜: 2026-08-03
- 상태: 사용자 설계 승인 완료, 구현 계획 작성 전
- 대상: 웹 대시보드 파이프라인 (`analyzer/pipeline.py` + `routes/upload.py` + 프론트)

## 배경과 목적

시험 구성이 다음과 같다:

- **유선 pcap 1개** — 스위치 포트 미러링으로 캡처. ping 손실의 ground truth.
  모니터 캡처 누락이 없어 손실률이 정확하다 (실측: 유선 0.16% vs 무선 15.65%,
  `docs/EXPING.md` 참조).
- **무선 pcap 2개** — 모니터 모드 스니퍼 2대. **같은 채널을 서로 다른 위치**에서
  캡처(커버리지 보완 목적). 같은 802.11 프레임이 양쪽에 중복으로 잡힌다.

현재 대시보드는 1 분석 = 1 pcap 구조라 이 구성을 담을 수 없다. 이 설계는
대시보드가 세 파일을 한 분석으로 받아 다음 세 질문에 답하게 한다:

1. **손실 원인 규명** — 유선 기준 확정 손실 구간에서 무선에 무슨 일이 있었나
   (로밍·Deauth·재전송 폭주·RSSI 절벽).
2. **누락 프레임 보완 통합 뷰** — 한 스니퍼가 놓친 프레임을 다른 캡처로 보완한
   중복 제거 통합 타임라인.
3. **스니퍼 위치별 비교** — 두 위치의 수신 품질(RSSI·캡처율·재전송률) 비교.

## 확정된 전제 (사용자 결정)

| 항목 | 결정 |
|---|---|
| 스니퍼 구성 | 같은 채널, 위치만 다름 — 프레임 중복 다수 발생 |
| 시간 동기 | 입력 pcap은 `timesync-shift-pcap.py`로 **사전 보정 완료** — 대시보드는 pcap 시각을 그대로 신뢰 |
| 접근 방식 | A안: 파이프라인 확장 (다중 입력 → 출처 태깅 → 병합 분석), 3단계 분할 |
| 하위 호환 | 단일 pcap 업로드·분석은 기존과 완전히 동일하게 동작 |

## 1. 입력 계약

### 업로드 API (`routes/upload.py`)

- `POST /api/upload`에 폼 필드 추가:
  - `wireless_files`: 무선 pcap 1~N개 (N 상한 4, 서버 검증)
  - `wired_file`: 유선 pcap 0~1개
  - 기존 `file` 필드는 **단일 무선 파일과 동의어**로 유지 — 기존 UI·스크립트
    하위 호환. `file`과 `wireless_files` 동시 제공 시 400.
- 파일별 검사(확장자·magic·크기 상한)는 기존 로직을 파일 수만큼 적용.
  파일별 상한은 기존 `config.max_upload_size()` 그대로.
- 임시 파일 수명 관리(`_jobs[job_id]["tmp"]`)는 단일 경로 → 경로 목록으로 확장.

### 업로드 폼 (`templates/index.html`)

- "무선 pcap (복수 선택 가능)" multi-file input + "유선 pcap (선택사항)" file input.
- 기존 단일 입력 흐름은 무선 1개 선택과 동일하게 처리.

### CLI (`scripts/analyze-cli.py`)

- 기존 위치 인자(단일 pcap)는 무선 1개로 유지. `--wireless <pcap>` 반복 지정과
  `--wired <pcap>` 옵션 추가 — `run_analysis` kwargs로 그대로 전달하는 thin
  passthrough.

## 2. 파이프라인 데이터 흐름 (`analyzer/pipeline.py`)

```
무선 pcap × N ──extract_frames()──▶ Frame[] (source="w1","w2",…)
                                      │
                     ① 캡처 간 미세 오프셋 추정 (비콘 TSF 매칭)   ┐
                     ② dedup ──▶ 통합 무선 Frame[]               │ analyzer/core/merge.py (신규)
                          │                                      ┘
                          ├──▶ 기존 roles 감지·11개 분석 모듈 (수정 없음)
                          └──▶ 원본 태그별 Frame[] ──▶ sniffer_compare 섹션
유선 pcap ──exping 추출·매칭 재사용──▶ ping ground truth (OK/NG/RTT)
                                      │
                     ③ structured["ping"]["ground_truth"] + 진단 대조
```

- `run_analysis(pcap_path, ...)` 시그니처 유지. 키워드 인자
  `wireless_paths: List[str] = []`, `wired_path: str = ""` 추가.
  `pcap_path` 단독 호출은 기존과 동일 동작 (무선 1개로 정규화).
- `Frame`(`analyzer/core/models.py`)에 `source: str = ""` 필드 추가.
  기본값이 있어 기존 생성 코드 무영향. 분석 결과 JSON에 Frame 원본은 저장하지
  않으므로 직렬화 크기 영향 없음.
- 진행률 콜백: 추출 구간(10→28%)을 파일 수로 등분해 파일별 진행 표시.

### 유선 경로는 경량 추출

유선 pcap은 `TSHARK_FIELDS` 전체 추출을 거치지 않는다. 검증된
`analyzer/core/exping.py`의 ICMP 전용 추출·매칭(`build_tshark_cmd`,
`parse_icmp_tsv`, `pick_sender`, `pair_exchanges`, `drop_trailing_unanswered`,
타임아웃 1초)을 그대로 재사용해 OK/NG 테이블만 만든다. EXPING xlsx 재현 규칙
(RTT_OFFSET_MS 보정, 전각 문자열)은 대시보드에 불필요 — Exchange 수준에서 소비.

## 3. 캡처 간 정렬·중복 제거 (`analyzer/core/merge.py` 신규)

순수 함수 모듈. 입력: 태그된 무선 Frame 리스트들. 출력: (통합 리스트, 스니퍼별
원본, 추정 오프셋, 경고 목록).

### 미세 오프셋 추정

사전 보정 후에도 캡처 간 잔여 오차(수십 ms)가 남을 수 있다.

1. **1차 — 비콘 TSF**: `wlan.fixed.timestamp`(TSF, AP가 프레임에 찍는 값이라
   두 캡처에서 동일)를 `TSHARK_FIELDS`에 추가 추출. 같은 `(BSSID, TSF)` 비콘
   쌍의 epoch 차이 **중앙값**을 기준 캡처(w1) 대비 오프셋으로 사용.
2. **2차 폴백 — 관리/데이터 프레임 매칭**: 비콘 쌍이 부족하면(< 10쌍)
   `(TA, wlan.seq, subtype)` 매칭 쌍의 시각차 중앙값.
3. **최종 폴백**: 매칭 실패 시 오프셋 0 적용 + `warnings[]`에 기록.

`wlan.fixed.timestamp`는 기존 `_filter_unsupported_fields` 메커니즘 대상이라
구버전 tshark에서 자동 제외 → 그 경우 2차 폴백으로 진행.

### dedup 규칙

- 키: `(TA, wlan.seq, subtype, retry비트)` + 오프셋 보정 후 시각 창 **±50ms**
  (모듈 상수, 설정 가능).
- retry비트를 키에 포함해 **실제 802.11 재전송을 캡처 중복으로 오인하지 않는다**
  (재전송은 같은 seq에 retry=1로 도착 — 별개 프레임으로 남긴다).
- seq가 없는 제어 프레임(ACK/RTS/CTS 등)은 `(subtype, TA/RA, 시각 창)`으로
  근사 dedup. 한계로 문서화: 제어 프레임 카운트는 ±수 % 오차 가능.
- **대표 프레임**: 먼저 잡힌 쪽. 양쪽 RSSI는 모두 보존해 비교 섹션에서 사용
  (대표 Frame의 `rssi`는 대표 출처 값 유지 — 기존 모듈 의미 불변).

## 4. 유선 ground truth와 진단 대조

- `structured["ping"]["ground_truth"]` 블록 신설: 총 요청/OK/NG/손실률,
  손실 구간(streak) 목록, 무선 관측 손실과의 병기 비교치.
- ping 섹션 UI에 **무선 관측 손실 vs 유선 확정 손실**을 나란히 표시 — 모니터
  누락으로 인한 과대 계상이 한눈에 보이게.
- `_structured_diagnosis` 확장: 유선 확정 손실 구간(±2초 창)마다 통합 무선
  타임라인에서 다음 이벤트를 탐색해 issue 생성:
  - 로밍 시퀀스(Auth/Reassoc), Deauth/Disassoc(+사유코드)
  - 재전송 폭주(retry_burst 결과 재사용), RSSI 절벽(signal_cliffs 재사용)
- 기존 원칙 유지: **frame_refs 증거를 부착할 수 없는 issue는 드롭** (근거 없는
  결론 0건). 유선 ground truth issue의 frame_refs는 유선 exchange의 request
  frame number + 대조된 무선 프레임 번호를 함께 담되, 출처 구분자를 포함한다.

## 5. 스니퍼 비교 섹션 (`structured["sniffer_compare"]` 신규)

- 초당 시계열 (스니퍼별): 프레임 수, 평균 RSSI, 재전송률.
- 커버리지 분해: dedup 그룹 기준 w1만/w2만/양쪽 포착 비율 — 스니퍼 배치 평가의
  핵심 수치.
- 프레임 테이블·debug 증거 타임라인에 출처 배지(w1/w2) 표시
  (`analyzer/web/frame_table.py`, `evidence.py`).
- 무선 1개 분석에서는 섹션 자체를 생략 (프론트는 키 부재 시 미표시).

## 6. 결과 스키마·메타

- `structured["sources"]` 신설: 파일별 `{name, role(wireless|wired), frame_count,
  applied_offset_ms, warnings[]}`.
- 최상위 `pcap_name`은 대표 파일명(첫 무선 파일) 유지 + `pcap_names[]` 추가
  (목록 화면 표시용).
- **모든 신규 필드는 optional** — 구버전 결과 JSON(`data/analyses/*.json`)
  재로드·리포트(`report.py`)·프론트 렌더가 깨지지 않는다
  (프로젝트 하위 호환 원칙, 메모리 `serialized-result-backward-compat` 참조).

## 7. 에러 처리

| 상황 | 동작 |
|---|---|
| 무선 1개만 업로드 | 오프셋/dedup/비교 스킵 — 기존과 동일 결과 |
| 유선 없음 | ground_truth 생략, 진단은 기존 무선 기준 |
| 유선 파일에 802.11 프레임 다수 (`count_wireless_requests` 재사용) | 경고 배너, 분석은 진행 |
| 무선 파일에 wlan 프레임 0건 | 해당 파일 제외 + 경고 (전부 0건이면 NO_FRAMES 에러) |
| 오프셋 추정 실패 | 오프셋 0 + 경고 |
| `file` + `wireless_files` 동시 제공 | 400 (모호한 입력 거부) |
| 무선 파일 5개 이상 | 400 (상한 4) |

경고는 `structured["sources"][i]["warnings"]`와 분석 페이지 상단 배너로 노출.

## 8. 테스트

- **merge.py 단위**: 합성 Frame으로 ① 비콘 TSF 오프셋 추정(정상/부족/실패)
  ② dedup(중복 제거·재전송 보존·제어 프레임 근사) ③ 경계(빈 입력, 한쪽만).
- **유선 ground truth**: 기존 exping 테스트 픽스처 재사용, ping.ground_truth
  블록 스키마 검증.
- **파이프라인 통합**: 소형 pcap 픽스처(무선 2 + 유선 1)로 end-to-end,
  `make test` 편입.
- **하위 호환 회귀**: ① 단일 pcap 결과가 변경 전과 동일(스냅샷 비교)
  ② 구버전 결과 JSON 로드·렌더 스모크.

## 9. 구현 단계

| 단계 | 범위 | 산출 가치 |
|---|---|---|
| 1 | 업로드 확장(무선 1 + 유선 1) + ground truth ping/진단 대조 | 손실 원인 규명 — dedup 없이 독립 배포 가능 |
| 2 | 무선 N개 수용 + TSF 정렬 + dedup 통합 뷰 (merge.py) | 누락 보완 통합 타임라인 |
| 3 | 스니퍼 비교 섹션 + 출처 배지 UI | 위치별 커버리지 평가 |

각 단계는 독립적으로 머지 가능하며 기존 단일 pcap 동작을 깨지 않는다.

## 범위 밖 (명시적 제외)

- 대시보드 내 자동 시간동기(NTP/공통 트래픽 기반) — 사전 보정 전제로 제외.
- 무선+유선을 한 pcap으로 병합 업로드(mergecap) 지원 — ICMP 이중 카운트
  왜곡 때문에 비권장 경로로 문서화만.
- EXPING xlsx 출력 — 기존 CLI(`exping-from-pcap.py`) 소관.
