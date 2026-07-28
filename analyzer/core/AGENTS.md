<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-09 | Updated: 2026-04-20 -->

# core

## Purpose
pcap 분석의 핵심 컴포넌트. 데이터 모델 정의, tshark를 통한 프레임 추출(취소/버전 감지 포함), AP/STA 역할 자동 감지, 프레임 사전 인덱싱, 텍스트 리포트 포맷팅, 외부 로그 병합, pcap magic byte 검증을 담당한다.

## Key Files

| File | Description |
|------|-------------|
| `models.py` | `Frame` 데이터클래스 (25+ 필드, RSSI/MCS/ICMP/로밍 등 프로퍼티), `AnalysisSection` 데이터클래스, 서브타입 상수(`SUBTYPE_NAMES`, `DATA_SUBTYPES` 등) |
| `extractor.py` | tshark 실행 + TSV 파싱. `build_tshark_cmd(..., tshark_path=...)` / `extract_frames(..., tshark_path=None, cancel_event=None)`. watcher 스레드가 cancel_event 감지 시 tshark 프로세스를 terminate → kill. `detect_tshark_version(path)`로 버전 감지. |
| `pcap_magic.py` | pcap/pcapng magic byte 검증 — `has_valid_pcap_magic(head: bytes) -> bool`. 5종 magic (pcap μs/ns × LE/BE + pcapng SHB). 업로드 스트리밍 경로의 첫 청크 검사에 사용. |
| `indexer.py` | `FrameIndex` 클래스 — O(N) 한 번 구축, 이후 O(1)~O(log N) 접근. STA/AP/TA/RA별 인덱스, bisect 기반 시간 윈도우 조회. |
| `detector.py` | AP/STA MAC 역할 자동 감지. Beacon/ProbeResp 송신자를 AP로, Data 프레임 통신 대상을 STA로 판별. `mac_name()` 유틸리티. |
| `reporter.py` | 텍스트 리포트 포맷팅. 전체/간결 모드 지원. |
| `log_merger.py` | 외부 로그 파일(syslog, wpa_supplicant 등) 파싱 + 로밍 키워드 필터링. |
| `exping.py` | EXPING(시험용 ping 도구) 로그 형식 입출력 + pcap 재구성. `read_csv()`/`write_csv()`/`write_xlsx()`, `extract_exchanges()` → `exchanges_to_rows()`. 웹 파이프라인이 아니라 `scripts/exping-*.py` CLI 전용. 손실 통계용 `ping_matching.py`와 목적이 다르다 — 이쪽은 추론 없이 EXPING의 기록 규칙만 재현한다. 사용법·근거는 `docs/EXPING.md`. |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `modules/` | 11개 분석 모듈 — 각각 독립적인 관점에서 프레임을 분석하여 `AnalysisSection` 반환 (see `modules/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- `Frame` 데이터클래스 변경 시 `extractor.py`의 `parse_tsv_line()`과 `TSHARK_FIELDS`도 함께 수정 필요.
- `FrameIndex`는 모든 분석 모듈에 `index` 파라미터로 전달됨. 새 인덱스 추가 시 `__init__`에서 구축.
- `detector.py`의 역할 감지 로직은 Beacon/AssocResp 없는 캡처에서도 동작하도록 폴백 처리됨.

### Common Patterns
- `Frame.rssi_first`, `Frame.mcs_int` — 쉼표 구분 다중값에서 첫 번째 값만 추출하는 프로퍼티.
- `Frame.is_*` 프로퍼티로 프레임 유형 판별 (ICMP, 로밍, ARP 등).
- `mac_name(mac, roles)` — MAC을 사람이 읽을 수 있는 이름으로 변환.

## Dependencies

### External
- `tshark` (시스템) — `extractor.py`가 subprocess로 호출

<!-- MANUAL: -->
