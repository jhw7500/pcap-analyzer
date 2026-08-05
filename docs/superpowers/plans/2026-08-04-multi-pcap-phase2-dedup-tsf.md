# 멀티 pcap 2단계 — 무선 N개 TSF 정렬·dedup 통합 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 대시보드가 무선 pcap 1~N개를 받아, 비콘 TSF 교차 매칭으로 캡처 간 시계 오프셋을 추정·정렬하고, 중복 프레임을 제거한 통합 타임라인으로 기존 11개 분석을 수행한다.

**Architecture:** 신규 순수 모듈 `analyzer/core/merge.py`가 (오프셋 추정 → epoch 보정 → dedup → 재번호)를 담당하고, `run_analysis(wireless_paths=[...])`가 파일별 추출·태깅 후 merge를 호출해 통합 Frame 리스트를 기존 파이프라인(roles/11모듈/구조화)에 그대로 공급한다. 원본(소스별) 리스트는 3단계(스니퍼 비교)용으로 보존한다. 단일 무선 경로는 merge를 건너뛰어 기존과 완전 동일.

**Tech Stack:** Python 3.10 / tshark(radiotap TSF) / pytest / scapy(픽스처 생성 전용)

**스펙:** `docs/superpowers/specs/2026-08-03-multi-pcap-analysis-design.md` §2·§3·§9 (2단계 범위. 스니퍼 비교 섹션은 3단계)

**실데이터 검증(2026-08-04, tmp/20260721_CFI/TEST1):** DFK(로테이션 pcap 2개, 암호화, ICMP 0건) + cantops(TEST1.pcapng, ICMP 가시) — 동일 채널 5240MHz·동일 BSSID 쌍. `(BSSID, TSF)` 정확 일치 비콘 12,298쌍, 오프셋 median +183.510s, IQR 3.4ms, 전량 ±50ms 내. 이 결과가 본 계획의 세 가지 설계 결정(TSF 매칭이 대형 원시 오프셋 처리 / 대표 프레임은 복호화 우선 / 로테이션 파일 flat 입력)의 근거다.

## Global Constraints

- Python 3.10 문법, 커밋 전 `ruff check .` 클린, 새 외부 의존성 금지(요구사항에 scapy 추가 금지 — 픽스처 생성 스크립트 전용, 생성물 pcap을 커밋), 주석·메시지 한국어.
- 기본 테스트 스위트는 tshark 실물 없이 통과 (`addopts = "-m 'not e2e and not slow and not tshark'"`). tshark 의존 테스트는 `pytestmark = [pytest.mark.slow, pytest.mark.tshark]` + 런타임 skip 이중 방어.
- **단일 무선 하위 호환**: `run_analysis(pcap_path)` 단독 호출은 프레임 번호·결과 구조 모두 기존과 완전 동일(merge 미실행). 결과 JSON 신규 키는 전부 optional.
- dedup 창 `MERGE_DEDUP_WINDOW_SEC = 0.05`(±50ms), TSF 최소 쌍 `MERGE_MIN_TSF_PAIRS = 10` — 모듈 상수.
- 1단계에서 확립된 원칙 유지: 근거 없는 결론 금지, 필터 대칭(시간/IP/MAC — 다중 무선에도 각 파일에 동일 적용됨: extract_frames가 파일별로 같은 필터를 받으므로 자동), 임시파일 수명, 취소 전파(파일별 추출 사이 cancel 체크).
- 커밋: `type(scope): 한국어 요약`, 본문 끝에 테스트 개수. 트레일러 2줄:
  ```
  Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01WqZ8df5huZ3tRzWPwhbW5q
  ```
- 작업 브랜치: `feat/multi-wireless-dedup` (main `8b11deb`에서 분기 — 이미 생성됨).
- 커버리지 게이트 75%.

---

### Task 1: 추출기 TSF 필드 + Frame 확장

**Files:**
- Modify: `analyzer/core/extractor.py` (TSHARK_FIELDS 끝에 추가, parse_tsv_line), `analyzer/core/models.py` (Frame 필드 2개)
- Test: `tests/test_extractor.py` (기존 파일에 추가), `tests/test_models.py`

**Interfaces:**
- Produces: `Frame.tsf: str = ""` (wlan.fixed.timestamp — 비콘의 AP TSF µs, cols[30]), `Frame.source: str = ""` (캡처 출처 태그 w1/w2/…, 추출기가 아니라 pipeline이 채움). `TSHARK_FIELDS`에 `"wlan.fixed.timestamp"` 추가 — 구버전 tshark는 기존 `_filter_unsupported_fields`가 자동 제외.

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_extractor.py`에 추가 (기존 parse_tsv_line 테스트 스타일 준용 — 파일 상단의 기존 헬퍼/컬럼 규약 확인 후 동일 방식):

```python
def test_parse_tsv_line_tsf_column():
    """cols[30] = wlan.fixed.timestamp → Frame.tsf. 없으면 빈 문자열."""
    cols = ["7", "1000.5", "2026-01-01 00:00:00", "0", "8", "802.11", "100"] + [""] * 23 + ["9893376059"]
    frame = parse_tsv_line("\t".join(cols))
    assert frame is not None
    assert frame.tsf == "9893376059"

def test_parse_tsv_line_tsf_absent_backward_compat():
    cols = ["7", "1000.5", "2026-01-01 00:00:00", "0", "8", "802.11", "100"] + [""] * 23
    frame = parse_tsv_line("\t".join(cols))
    assert frame is not None
    assert frame.tsf == ""

def test_tshark_fields_contains_tsf_last():
    assert TSHARK_FIELDS[30] == "wlan.fixed.timestamp"
```

`tests/test_models.py`에 추가:

```python
def test_frame_source_and_tsf_defaults():
    """신규 필드는 기본값이 있어 기존 생성 코드 무영향."""
    f = make_frame()
    assert f.source == "" and f.tsf == ""
```

- [ ] **Step 2: 실패 확인**

Run: `python3 -m pytest tests/test_extractor.py -k tsf -q; python3 -m pytest tests/test_models.py -k source -q`
Expected: FAIL (IndexError/AttributeError — 필드 없음)

- [ ] **Step 3: 구현**

(a) `analyzer/core/models.py`의 Frame 필드 끝에:
```python
    tsf: str = ""  # wlan.fixed.timestamp — 비콘의 AP TSF(µs). 캡처 간 오프셋 추정용 (merge.py)
    source: str = ""  # 캡처 출처 태그 (w1/w2/… — 다중 무선 병합 시 pipeline이 채움)
```

(b) `analyzer/core/extractor.py` TSHARK_FIELDS 끝에:
```python
    "wlan.fixed.timestamp",  # cols[30] — 비콘 TSF(µs). 캡처 간 시계 오프셋 추정 (merge.py)
```

(c) `parse_tsv_line`의 Frame 생성에 `tsf=cols[30] if len(cols) > 30 else "",` 추가.

주의: 기존 테스트 중 "필드 수 가드" 회귀(`tests/test_extractor_compat.py`류 — PR #21에서 고정)가 TSHARK_FIELDS 길이를 검사할 수 있다 — 길이 상수를 쓰는 테스트가 있으면 파생 방식인지 확인하고, 하드코딩이면 갱신하되 커밋 본문에 명시.

- [ ] **Step 4: 통과 확인**

Run: `python3 -m pytest tests/test_extractor.py tests/test_extractor_compat.py tests/test_extractor_extended.py tests/test_models.py -q`
Expected: 전부 통과

- [ ] **Step 5: 전체 회귀 + 커밋**

Run: `python3 -m pytest tests/ -q && ruff check .`

```bash
git add analyzer/core/extractor.py analyzer/core/models.py tests/test_extractor.py tests/test_models.py
git commit -m "feat(merge): Frame에 tsf·source 필드 — 캡처 간 정렬·출처 태깅 기반"
```

---

### Task 2: merge.py — 오프셋 추정

**Files:**
- Create: `analyzer/core/merge.py`
- Test: `tests/test_merge_offset.py`

**Interfaces:**
- Consumes: `Frame.tsf`/`bssid`/`epoch`/`subtype`/`ta`/`seq` (Task 1)
- Produces:
  ```python
  MERGE_MIN_TSF_PAIRS = 10
  FALLBACK_MATCH_WINDOW_SEC = 5.0

  @dataclass
  class OffsetResult:
      offset_sec: float      # 이 소스 epoch에 더하면 기준(w1) 타임라인이 되는 값
      method: str            # "tsf" | "seq-fallback" | "none"
      pairs: int             # 사용한 매칭 쌍 수
      spread_sec: float      # IQR — 품질 지표
      warnings: list[str]

  def estimate_offset(reference: List[Frame], other: List[Frame]) -> OffsetResult: ...
  ```
  Task 3(dedup)·Task 4(pipeline)가 이 계약을 소비한다.

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_merge_offset.py` (conftest의 `make_frame` 사용):

```python
"""merge.estimate_offset — 비콘 TSF 교차 매칭 오프셋 추정."""
import pytest

from analyzer.core.merge import estimate_offset, MERGE_MIN_TSF_PAIRS
from tests.conftest import make_frame

AP = "00:80:4c:e1:09:cb"


def _beacons(epoch0, tsf0, n, source):
    """102.4ms 간격 비콘 n개 — 실캡처(TEST1)와 동일한 TSF 보폭."""
    return [
        make_frame(number=i + 1, epoch=epoch0 + i * 0.1024, subtype="8",
                   ta=AP, bssid=AP, tsf=str(tsf0 + i * 102400), source=source)
        for i in range(n)
    ]


def test_tsf_offset_recovers_large_raw_offset():
    """실측 시나리오: DFK가 +183.51초 앞선 원시 시계 — TSF 매칭은 창 없이 복원한다."""
    ref = _beacons(1000.0, 9_893_376_059, 30, "w1")
    other = _beacons(1000.0 - 183.51, 9_893_376_059, 30, "w2")  # 같은 비콘, 시계만 뒤짐
    r = estimate_offset(ref, other)
    assert r.method == "tsf"
    assert r.pairs == 30
    assert r.offset_sec == pytest.approx(183.51, abs=0.001)
    assert r.spread_sec < 0.01


def test_tsf_offset_ignores_unmatched_bssid():
    ref = _beacons(1000.0, 100_000, 20, "w1")
    other = _beacons(998.0, 100_000, 20, "w2")
    noise = [make_frame(number=99, epoch=1500.0, subtype="8", ta="aa:aa:aa:aa:aa:01",
                        bssid="aa:aa:aa:aa:aa:01", tsf="100000", source="w2")]
    r = estimate_offset(ref, other + noise)
    assert r.pairs == 20 and r.offset_sec == pytest.approx(2.0, abs=0.001)


def test_insufficient_tsf_pairs_falls_back_to_seq_match():
    """TSF 쌍 < 10 → (ta, seq, subtype) 매칭 폴백 (±5초 창 — 사전 보정 전제)."""
    ref = [make_frame(number=i + 1, epoch=1000.0 + i, subtype="40", seq=str(100 + i),
                      source="w1") for i in range(20)]
    other = [make_frame(number=i + 1, epoch=999.7 + i, subtype="40", seq=str(100 + i),
                        source="w2") for i in range(20)]
    r = estimate_offset(ref, other)
    assert r.method == "seq-fallback"
    assert r.offset_sec == pytest.approx(0.3, abs=0.001)


def test_no_match_returns_zero_with_warning():
    ref = [make_frame(number=1, epoch=1000.0, subtype="40", seq="1", source="w1")]
    other = [make_frame(number=1, epoch=5000.0, subtype="40", seq="999", source="w2")]
    r = estimate_offset(ref, other)
    assert r.method == "none" and r.offset_sec == 0.0
    assert any("오프셋" in w for w in r.warnings)


def test_tsf_non_numeric_skipped():
    ref = _beacons(1000.0, 100_000, 12, "w1")
    broken = _beacons(1000.0, 100_000, 12, "w2")
    broken[0].tsf = "0x깨진값"
    r = estimate_offset(ref, broken)
    assert r.method == "tsf" and r.pairs == 11
```

- [ ] **Step 2: 실패 확인**

Run: `python3 -m pytest tests/test_merge_offset.py -q`
Expected: ModuleNotFoundError

- [ ] **Step 3: 구현**

`analyzer/core/merge.py` 신설:

```python
"""다중 무선 캡처의 시계 정렬과 중복 제거.

같은 채널을 두 위치에서 캡처하면 같은 802.11 프레임이 양쪽에 잡힌다. 비콘의
TSF(wlan.fixed.timestamp)는 AP가 프레임에 찍는 값이라 어느 캡처에서 봐도
동일하다 — (BSSID, TSF) 정확 일치 쌍의 epoch 차 중앙값이 곧 캡처 간 시계
오프셋이다. 실측(2026-07-21 TEST1, DFK↔cantops): 12,298쌍, 오프셋 +183.510s,
IQR 3.4ms — 사전 timesync 보정 없이도 무선 간 정렬이 가능함을 확인했다.

TSF 폴백((TA, seq, subtype) 매칭)은 ±5초 창을 쓰므로 사전 보정된 입력을
전제한다(스펙 §3). 그것도 실패하면 오프셋 0 + 경고.
"""
import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from .models import Frame

MERGE_MIN_TSF_PAIRS = 10
FALLBACK_MATCH_WINDOW_SEC = 5.0
MERGE_DEDUP_WINDOW_SEC = 0.05  # Task 3에서 사용


@dataclass
class OffsetResult:
    offset_sec: float
    method: str
    pairs: int
    spread_sec: float
    warnings: List[str] = field(default_factory=list)


def _tsf_table(frames: List[Frame]) -> Dict[Tuple[str, int], float]:
    out: Dict[Tuple[str, int], float] = {}
    for f in frames:
        if f.subtype != "8" or not f.bssid or not f.tsf:
            continue
        try:
            out[(f.bssid, int(f.tsf))] = f.epoch
        except ValueError:
            continue  # 비정상 TSF 값은 무시
    return out


def _median_iqr(diffs: List[float]) -> Tuple[float, float]:
    s = sorted(diffs)
    n = len(s)
    return statistics.median(s), (s[(3 * n) // 4] - s[n // 4] if n >= 4 else 0.0)


def estimate_offset(reference: List[Frame], other: List[Frame]) -> OffsetResult:
    """other의 epoch에 더하면 reference 타임라인이 되는 오프셋을 추정한다."""
    ref_t, oth_t = _tsf_table(reference), _tsf_table(other)
    common = set(ref_t) & set(oth_t)
    if len(common) >= MERGE_MIN_TSF_PAIRS:
        med, iqr = _median_iqr([ref_t[k] - oth_t[k] for k in common])
        return OffsetResult(med, "tsf", len(common), iqr)

    # 폴백: (TA, seq, subtype) 매칭 — 사전 보정 전제의 ±5초 창
    ref_keys: Dict[Tuple[str, str, str], List[float]] = {}
    for f in reference:
        if f.ta and f.seq:
            ref_keys.setdefault((f.ta, f.seq, f.subtype), []).append(f.epoch)
    diffs: List[float] = []
    for f in other:
        if not (f.ta and f.seq):
            continue
        for ref_epoch in ref_keys.get((f.ta, f.seq, f.subtype), []):
            d = ref_epoch - f.epoch
            if abs(d) <= FALLBACK_MATCH_WINDOW_SEC:
                diffs.append(d)
                break
    if len(diffs) >= MERGE_MIN_TSF_PAIRS:
        med, iqr = _median_iqr(diffs)
        return OffsetResult(med, "seq-fallback", len(diffs), iqr)

    return OffsetResult(
        0.0, "none", 0, 0.0,
        warnings=["캡처 간 오프셋을 추정하지 못해 0으로 가정 — 타임라인이 어긋날 수 있다 "
                  "(비콘 TSF 쌍 부족·공통 프레임 없음)"],
    )
```

- [ ] **Step 4: 통과 확인**

Run: `python3 -m pytest tests/test_merge_offset.py -v`
Expected: 6 passed

- [ ] **Step 5: 커밋**

```bash
git add analyzer/core/merge.py tests/test_merge_offset.py
git commit -m "feat(merge): 비콘 TSF 교차 매칭 오프셋 추정 — 실측 183.5s 오프셋 복원 검증"
```

---

### Task 3: merge.py — dedup·재번호·병합

**Files:**
- Modify: `analyzer/core/merge.py`
- Test: `tests/test_merge_dedup.py`

**Interfaces:**
- Consumes: Task 2의 `estimate_offset`, `MERGE_DEDUP_WINDOW_SEC`
- Produces:
  ```python
  @dataclass
  class MergeResult:
      frames: List[Frame]              # 통합·정렬·재번호된 리스트 (기존 파이프라인 입력)
      per_source: Dict[str, List[Frame]]  # 소스별 원본(epoch 보정됨) — 3단계용
      offsets: Dict[str, OffsetResult]    # 소스 태그 → 추정 결과 (w1 제외)
      stats: Dict[str, Any]            # {"window_ms", "duplicates", "kept",
                                       #  "by_source_raw": {tag: n},
                                       #  "coverage": {"both": n, "only": {tag: n}}}
      warnings: List[str]

  def merge_captures(sources: "OrderedDict[str, List[Frame]]") -> MergeResult: ...
  # sources: 태그 → 프레임 리스트. 첫 항목이 기준(w1). 각 Frame.source는 이미 태깅됨.
  ```

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_merge_dedup.py`:

```python
"""merge.merge_captures — 캡처 간 dedup·재번호."""
from collections import OrderedDict

import pytest

from analyzer.core.merge import merge_captures
from tests.conftest import make_frame, AP1, STA1


def _src(tag, *frames):
    for f in frames:
        f.source = tag
    return list(frames)


def _pair(tag_frames):
    return OrderedDict(tag_frames)


def test_cross_source_duplicate_merged_once():
    """같은 (TA, seq, subtype, retry) 프레임이 두 캡처에 잡히면 1개로."""
    a = _src("w1",
             make_frame(number=1, epoch=1000.000, seq="100", subtype="40"),
             make_frame(number=2, epoch=1001.000, seq="101", subtype="40"))
    b = _src("w2",
             make_frame(number=1, epoch=1000.020, seq="100", subtype="40"),  # 중복(+20ms)
             make_frame(number=2, epoch=1002.000, seq="102", subtype="40"))  # w2 단독
    r = merge_captures(_pair([("w1", a), ("w2", b)]))
    assert len(r.frames) == 3
    assert r.stats["duplicates"] == 1
    assert r.stats["coverage"]["both"] == 1
    assert r.stats["coverage"]["only"] == {"w1": 1, "w2": 1}


def test_retry_bit_not_deduped():
    """재전송(retry=1)은 원본(retry=0)과 다른 프레임 — 병합 금지."""
    a = _src("w1", make_frame(number=1, epoch=1000.0, seq="100", retry=False))
    b = _src("w2", make_frame(number=1, epoch=1000.01, seq="100", retry=True))
    r = merge_captures(_pair([("w1", a), ("w2", b)]))
    assert len(r.frames) == 2 and r.stats["duplicates"] == 0


def test_outside_window_not_deduped():
    a = _src("w1", make_frame(number=1, epoch=1000.0, seq="100"))
    b = _src("w2", make_frame(number=1, epoch=1000.2, seq="100"))  # +200ms > 창
    r = merge_captures(_pair([("w1", a), ("w2", b)]))
    assert len(r.frames) == 2


def test_representative_prefers_decoded_copy():
    """실측 근거(DFK 암호화): 대표는 IP 필드가 채워진 쪽 — 먼저 잡힌 쪽이 아니라."""
    a = _src("w1", make_frame(number=1, epoch=1000.000, seq="100", ip_src=""))       # 암호화 사본(선행)
    b = _src("w2", make_frame(number=7, epoch=1000.030, seq="100", ip_src="10.0.0.1",
                              ip_dst="10.0.0.2", icmp_type="8"))                      # 복호화 사본
    r = merge_captures(_pair([("w1", a), ("w2", b)]))
    assert len(r.frames) == 1
    kept = r.frames[0]
    assert kept.ip_src == "10.0.0.1" and kept.source == "w2"


def test_representative_tie_earlier_epoch():
    a = _src("w1", make_frame(number=1, epoch=1000.000, seq="100", ip_src="10.0.0.1"))
    b = _src("w2", make_frame(number=1, epoch=1000.030, seq="100", ip_src="10.0.0.1"))
    r = merge_captures(_pair([("w1", a), ("w2", b)]))
    assert r.frames[0].source == "w1"


def test_offset_applied_before_dedup():
    """w2가 -2.0초 뒤진 시계여도 TSF 정렬 후 dedup이 잡는다."""
    beac_a = [make_frame(number=i + 10, epoch=1000.0 + i * 0.1024, subtype="8", ta=AP1,
                         bssid=AP1, tsf=str(500_000 + i * 102400)) for i in range(12)]
    beac_b = [make_frame(number=i + 10, epoch=998.0 + i * 0.1024, subtype="8", ta=AP1,
                         bssid=AP1, tsf=str(500_000 + i * 102400)) for i in range(12)]
    dat_a = make_frame(number=1, epoch=1001.000, seq="200", subtype="40")
    dat_b = make_frame(number=1, epoch=999.005, seq="200", subtype="40")  # 보정 후 +5ms
    a = _src("w1", *(beac_a + [dat_a]))
    b = _src("w2", *(beac_b + [dat_b]))
    r = merge_captures(_pair([("w1", a), ("w2", b)]))
    assert r.offsets["w2"].method == "tsf"
    assert r.offsets["w2"].offset_sec == pytest.approx(2.0, abs=0.001)
    # 비콘 12쌍 + 데이터 1쌍 전부 dedup → 13
    assert r.stats["duplicates"] == 13
    assert len(r.frames) == 13


def test_control_frame_approx_dedup():
    """seq 없는 제어 프레임(ACK 등)은 (subtype, ta/ra, 창) 근사 dedup."""
    a = _src("w1", make_frame(number=1, epoch=1000.000, seq="", subtype="29", ta="", ra=STA1))
    b = _src("w2", make_frame(number=1, epoch=1000.010, seq="", subtype="29", ta="", ra=STA1))
    r = merge_captures(_pair([("w1", a), ("w2", b)]))
    assert len(r.frames) == 1


def test_same_source_never_deduped():
    """같은 캡처(로테이션 연속 파일 포함) 안에서는 dedup하지 않는다."""
    a = _src("w1",
             make_frame(number=1, epoch=1000.000, seq="100"),
             make_frame(number=2, epoch=1000.010, seq="100"))  # 같은 소스 — 유지
    r = merge_captures(_pair([("w1", a)]))
    assert len(r.frames) == 2 and r.stats["duplicates"] == 0


def test_renumbered_sequential_and_sorted():
    a = _src("w1", make_frame(number=50, epoch=1002.0, seq="1"),
             make_frame(number=51, epoch=1000.0, seq="2"))
    b = _src("w2", make_frame(number=50, epoch=1001.0, seq="3"))
    r = merge_captures(_pair([("w1", a), ("w2", b)]))
    assert [f.number for f in r.frames] == [1, 2, 3]
    assert [f.epoch for f in r.frames] == sorted(f.epoch for f in r.frames)


def test_single_source_passthrough_numbers_untouched():
    """단일 소스는 재번호 없이 그대로 — 하위 호환."""
    a = _src("w1", make_frame(number=7, epoch=1000.0), make_frame(number=9, epoch=1001.0))
    r = merge_captures(_pair([("w1", a)]))
    assert [f.number for f in r.frames] == [7, 9]
    assert r.offsets == {} and r.stats["duplicates"] == 0
```

- [ ] **Step 2: 실패 확인**

Run: `python3 -m pytest tests/test_merge_dedup.py -q`
Expected: ImportError (merge_captures 없음)

- [ ] **Step 3: 구현**

`merge.py`에 추가. 알고리즘(주석 포함 요약 — 코드는 이 명세를 그대로 구현):

1. 소스 태그 순서 유지. 첫 태그가 기준. 각 비-기준 소스에 `estimate_offset(reference, src)` → `offsets[tag]`; 해당 소스 모든 프레임의 `epoch += offset_sec` (timestamp 문자열은 원본 유지 — epoch만 통합 타임라인. 주석 명시).
2. 소스가 1개면: frames 그대로(정렬만 안전하게 epoch 기준 stable sort), offsets/duplicates 없음, per_source/coverage만 채워 반환 — **재번호 금지**.
3. 다중 소스: 전 프레임을 (보정 epoch, source, number)로 stable 정렬 후 순회하며 dedup:
   - 키: seq 있으면 `("s", ta, seq, subtype, retry)`; 없으면 `("c", subtype, ta or ra, retry)` (제어 근사 — 한계 주석).
   - `last: Dict[key, List[group]]` — group은 `{"rep": Frame, "sources": set, "epoch": float}`. 현재 프레임 키의 기존 group 중 `|epoch - group.epoch| <= MERGE_DEDUP_WINDOW_SEC`이고 **자기 source가 group.sources에 없는** 것이 있으면 중복: `duplicates += 1`, group.sources에 추가, 대표 교체 판정 — **`bool(ip_src)`가 우세한 쪽 우선, 동률이면 epoch 이른 쪽**(실측 근거: DFK 암호화 사본은 IP 필드가 비어 ping 분석 불가). group.epoch는 대표의 epoch로 유지.
   - 매칭 없으면 새 group 생성·merged에 대표 추가. 오래된 group은 epoch가 창을 벗어나면 버킷에서 제거(선형 스캔 방지 — deque 또는 정렬 순회 특성 이용).
4. coverage: 각 group의 sources 크기로 both/only 집계 (2개 초과 소스면 `len(sources) >= 2`를 both로).
5. 재번호: merged를 epoch 기준 정렬 후 `f.number = i+1`. per_source 리스트의 프레임 번호는 원본 유지(같은 객체가 아니라 **대표 교체와 무관하게 소스별 전체 원본**을 담는다 — dedup 전 리스트).
6. warnings: 각 OffsetResult.warnings 병합 + method=="none"인 소스 명시.

- [ ] **Step 4: 통과 확인**

Run: `python3 -m pytest tests/test_merge_dedup.py tests/test_merge_offset.py -v`
Expected: 전부 통과

- [ ] **Step 5: 커밋**

```bash
git add analyzer/core/merge.py tests/test_merge_dedup.py
git commit -m "feat(merge): 캡처 간 dedup·재번호 — 복호화 우선 대표 선정(실측 근거)"
```

---

### Task 4: pipeline 통합 — wireless_paths

**Files:**
- Modify: `analyzer/pipeline.py`
- Test: `tests/test_pipeline_multi_wireless.py`

**Interfaces:**
- Consumes: Task 3의 `merge_captures`/`MergeResult`
- Produces: `run_analysis(pcap_path, ..., wireless_paths: Optional[List[str]] = None)` — pcap_path가 기준(w1), wireless_paths는 추가 무선(w2, w3, …). 다중일 때:
  - `structured["sources"]`의 무선 항목이 파일별로 생성: `{name, role: "wireless", frame_count(원본), applied_offset_ms, offset_method, warnings}`
  - `structured["merge"] = {"window_ms": 50, "duplicates": n, "kept": n, "coverage": {...}}` (optional 키)
  - 이후 파이프라인(roles/모듈/구조화/유선 GT/진단)은 통합 frames로 기존과 동일 동작
  - 취소: 파일별 추출 사이 `_cancelled()` 체크

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_pipeline_multi_wireless.py` — 기존 `tests/test_pipeline_wired.py`의 `_patch_common` 패턴 준용(extract_frames·detect_tshark_version·config.detect_tshark·os.path.getsize monkeypatch). 핵심 케이스:

```python
def test_two_wireless_files_merged(monkeypatch):
    """extract_frames가 경로별로 다른 프레임 세트를 반환하도록 side_effect —
    결과 frames가 병합·dedup되고 sources가 파일별 2개."""
    # w1: 비콘12 + 데이터1(seq=200), w2: 같은 비콘12(시계 -2s) + 같은 데이터1 + w2단독 1
    # (test_merge_dedup의 test_offset_applied_before_dedup 픽스처 재사용 구성)
    ...
    result = pipeline.run_analysis("w1.pcapng", wireless_paths=["w2.pcapng"])
    sources = result["structured"]["sources"]
    wireless = [s for s in sources if s["role"] == "wireless"]
    assert len(wireless) == 2
    assert wireless[1]["applied_offset_ms"] == pytest.approx(2000.0, abs=1.0)
    assert result["structured"]["merge"]["duplicates"] == 13
    assert result["frame_count"] == 14  # 통합 후

def test_single_wireless_no_merge_key(monkeypatch):
    """단일 경로는 merge 키 없음 + 프레임 번호 원본 유지 (하위 호환)."""
    ...
    assert "merge" not in result["structured"]

def test_extraction_cancelled_between_files(monkeypatch):
    """첫 파일 추출 후 cancel set → {"cancelled": True}, 두 번째 파일 추출 안 함."""
    ...

def test_wireless_file_with_zero_frames_warned_and_skipped(monkeypatch):
    """스펙 §7: 무선 파일 wlan 프레임 0건 → 해당 파일 제외 + 경고. 전부 0건이면 error."""
    ...

def test_wired_gt_composes_with_multi_wireless(monkeypatch):
    """유선 GT(1단계)와 다중 무선이 동시 동작 — sources = w1, w2, wired 3항목."""
    ...
```

(각 `...`은 `_patch_common` 스타일의 완전한 픽스처로 작성 — extract_frames side_effect가 경로 인자별 리스트 반환, build_ground_truth mock은 tests/test_pipeline_wired.py의 GT_OK 재사용.)

- [ ] **Step 2: 실패 확인** — `python3 -m pytest tests/test_pipeline_multi_wireless.py -q` → TypeError(kwarg 없음)

- [ ] **Step 3: 구현**

`analyzer/pipeline.py`:
1. 시그니처에 `wireless_paths: Optional[List[str]] = None` 추가 (`wired_path` 앞).
2. 추출 루프: `paths = [pcap_path] + list(wireless_paths or [])`; 파일별 `extract_frames(...)` 호출(동일 필터 인자 전달 — 필터 대칭 자동), 태그 `w{i+1}`를 각 프레임 `f.source`에 설정, 진행률 10→28%를 파일 수로 분할, 각 파일 후 `_cancelled()` 체크. 프레임 0건 파일은 sources에 경고와 함께 기록하고 제외(전부 0건이면 기존 NO_FRAMES error).
3. 다중 소스면 `merge_captures(OrderedDict(...))` 호출 → `frames = mr.frames`; sources 무선 항목에 `applied_offset_ms = round(offsets[tag].offset_sec * 1000, 3)`(w1은 0.0)·`offset_method`; `structured["merge"]` 채움; mr.warnings는 각 소스 warnings로 분배. 단일 소스면 기존 경로 그대로(merge 미호출).
4. 기존 sources 생성 블록과 병합(1단계 코드 위치) — 무선 항목이 1개→N개가 되는 것 외에 유선 항목 로직 불변.

- [ ] **Step 4: 통과 확인** — `python3 -m pytest tests/test_pipeline_multi_wireless.py tests/test_pipeline_wired.py tests/test_pipeline.py -q` (하위 호환 회귀 포함)

- [ ] **Step 5: 커밋** — `feat(merge): run_analysis 다중 무선 통합 — 파일별 태깅·정렬·dedup 후 기존 파이프라인 공급`

---

### Task 5: 업로드 라우트·CLI — 다중 무선 수용

**Files:**
- Modify: `routes/upload.py`, `scripts/analyze-cli.py`
- Test: `tests/test_routes_upload_multi.py`, `tests/test_analyze_cli_wired.py`(추가)

**Interfaces:**
- Produces: `POST /api/upload` 폼 필드 `wireless_files`(0~3개 — 기존 `file`이 w1이므로 총 4). 각 파일 `_save_pcap_upload` 재사용 검증, 에러 시 앞서 저장된 모든 tmp 정리, finally에서 전부 unlink, `run_analysis(..., wireless_paths=[...])` 전달. `pcap_names`에 전 파일명, sources name 치환 확장. CLI: `--wireless PATH` 반복 지정.

- [ ] **Step 1: 테스트** — `tests/test_routes_upload_multi.py` (test_routes_upload_wired.py 패턴): ① wireless_files 2개 전달 → run_analysis kwargs `wireless_paths` 길이 2 ② 총 무선 5개(file+wireless_files 4) → 400 ③ wireless_files 중 1개 magic 불량 → 400 + 먼저 저장된 tmp 전부 삭제(경로 캡처 후 exists 확인) ④ 미지정 → `wireless_paths == []`. CLI: `--wireless` 값 누락 exit 2, usage 표기, 반복 지정 수용(파싱 단위 테스트 — subprocess).
- [ ] **Step 2: RED 확인**
- [ ] **Step 3: 구현** — upload.py: `wireless_files: List[UploadFile] = File([])`, 빈 filename 파트 가드, 상한 검사(`1 + len(valid_wireless) > 4` → 400, ErrorCode는 기존 INVALID_EXT 재사용 대신 message로 — 새 코드 추가 없이 `error_payload(ErrorCode.INVALID_EXT, "(무선 파일은 최대 4개)")`가 아니라 적절한 기존 코드 검토 후 결정, 없으면 FILE_TOO_LARGE 오용 금지·새 ErrorCode `TOO_MANY_FILES` 추가+카탈로그+테스트). 저장 루프에서 실패 시 지금까지의 tmp 전부 unlink. `_jobs`에 `"wireless_tmps": [...]` 기록. finally 순회 정리. CLI는 `--wired` 파싱과 동일 패턴으로 `--wireless` 반복 수집.
- [ ] **Step 4: 통과 확인** — 신규 + `tests/test_routes_upload.py` + `tests/test_routes_upload_wired.py` 무손상
- [ ] **Step 5: 커밋** — `feat(upload): 무선 pcap 다중 업로드(최대 4) + CLI --wireless 반복 지정`

---

### Task 6: 프론트 — 폼 multiple·오프셋/병합 표시

**Files:**
- Modify: `templates/index.html`, `static/js/upload.js`, `templates/analysis.html`, `static/js/charts.js`
- Test: `tests/test_routes_multi_banner.py`

**Interfaces:**
- Produces: ① 업로드 폼에 "추가 무선 pcap (최대 3개)" `<input type="file" name="wireless_files" multiple data-max-mb="{{ max_upload_mb }}">` + upload.js 크기 검증 루프 ② 분석 페이지 상단(기존 경고 배너 아래)에 다중 소스 메타 라인 — Jinja로 sources 순회: `w2: +183.510s (tsf, 비콘 12,298쌍)` 형태 ③ Overview 탭에 병합 요약 카드(`structured.merge` 있을 때만): 중복 제거 N건, 양쪽 포착 비율.

- [ ] **Step 1: 테스트** — 배너/메타 라인은 Jinja 서버 렌더라 pytest 검증: sources 2개+offset 있는 결과 JSON 저장 → GET → offset 문자열 존재; merge 키 없는 구버전 결과 → 200 + 메타 라인 없음.
- [ ] **Step 2~4: RED → 구현 → GREEN** (JS는 node --check + 로직 발췌 시뮬레이션, 관례대로 보고서에 명시)
- [ ] **Step 5: 커밋** — `feat(ui): 다중 무선 업로드 폼·오프셋 메타·병합 요약 카드`

---

### Task 7: 이중 캡처 골든 픽스처·문서·최종 회귀

**Files:**
- Create: `tests/fixtures/generate_sample_dual.py`, `tests/fixtures/sample_dual_a.pcap`, `tests/fixtures/sample_dual_b.pcap`(커밋 — 각 ≤5KB), `tests/test_golden_dual.py`
- Modify: `README.md`, `docs/EXPING.md`는 무변경 — 대신 스펙 §9 상태 갱신은 PR 본문으로

**Interfaces:**
- Produces: scapy 생성기 — 두 "캡처"가 공유하는 비콘(RadioTap+Dot11Beacon, `timestamp` 필드로 TSF 설정) 12개 + 공통 데이터 프레임 + 각자 단독 프레임, B는 고정 오프셋 -2.5s. `tests/test_golden_dual.py`(`pytestmark = [pytest.mark.slow, pytest.mark.tshark]` + FIXTURE/tshark 런타임 skip — test_pipeline_smoke.py 템플릿): `run_analysis(a, wireless_paths=[b])` → offset ≈ 2.5s(method tsf), duplicates == 예상값, frame_count == 예상값, sources 2개.

- [ ] **Step 1: 생성기 작성·실행** — `generate_sample_basic.py` 패턴(BASE_EPOCH 고정, 결정론). scapy의 `Dot11Beacon(timestamp=...)`으로 TSF 주입. 생성물 pcap을 커밋(CI에는 scapy 없음 — 생성물 커밋 방식은 기존 관례).
- [ ] **Step 2: 골든 테스트 작성 → 로컬 tshark로 실행** — `python3 -m pytest tests/test_golden_dual.py -m tshark -v` 통과 확인 (이 호스트 tshark 4.4.9).
- [ ] **Step 3: 실데이터 수동 검증 1회** — `python3 scripts/analyze-cli.py 'tmp/20260721_CFI/TEST1/wireshark/무선/TEST1.pcapng' '' '' /tmp/claude-1003/-home-jhw-ai-opencode-projects-pcap-analyzer/e9ecbf31-d917-4db9-bae3-518ca1946c1d/scratchpad/test1-dual.json --wireless 'tmp/20260721_CFI/TEST1/DFK/mon1_00001_20260721145213.pcap' --wireless 'tmp/20260721_CFI/TEST1/DFK/mon1_00002_20260721150755.pcap' --wired 'tmp/20260721_CFI/TEST1/wireshark/유선/FXE3000_1번테스트_1515.pcapng'` 실행 — DFK 소스 오프셋이 **약 -183.51s**(cantops 기준)로 보고되는지, duplicates·coverage가 비상식적이지 않은지 결과 JSON에서 확인해 보고서에 기록. (대형 파일 — 수 분 소요 가능, 실패해도 태스크 차단 아님: 발견 사항을 보고.)
- [ ] **Step 4: README 1줄 갱신 + 전체 회귀** — `python3 -m pytest tests/ -q && ruff check .` + `-m tshark` 로컬 실행(골든 기존+dual).
- [ ] **Step 5: 커밋** — `test(merge): 이중 캡처 골든 픽스처·실데이터 검증 — 2단계 마무리`

---

## 계획 자가 리뷰 결과

- **스펙 §3 커버리지**: 1차 TSF(§3-1)=T2, 2차 seq 폴백(§3-2)=T2, 최종 폴백 0+경고(§3-3)=T2, dedup 키·retry 보존·제어 근사(§3 dedup 규칙)=T3, 대표 프레임=T3(실데이터 근거로 스펙의 "먼저 잡힌 쪽"을 "복호화 우선, 동률 시 이른 쪽"으로 개정 — 개정 사유가 계획 서두 실측 절에 기록됨), 무선 N 수용(§1·§9)=T4·T5, wlan.fixed.timestamp 추출(§3)=T1, 진행률 분할(§2)=T4, 프레임 0건 파일 경고(§7)=T4.
- **하위 호환**: 단일 무선 경로는 merge 미호출·재번호 금지(T3 passthrough 테스트 + T4 no-merge-key 테스트)로 이중 고정.
- **타입 일관성**: OffsetResult(T2)를 T3 MergeResult.offsets와 T4 sources.applied_offset_ms가 소비; merge_captures의 OrderedDict 계약을 T4가 사용; per_source는 3단계 예약(이번 단계 소비자 없음 — YAGNI 위반 아님: 스펙 §2가 명시 보존 요구).
- **알려진 한계(의도)**: 다중 소스 시 frame.number 재번호(원본 번호는 per_source에 보존 — evidence frame_refs 유일성 우선, 근거 주석 의무), timestamp 문자열은 원본 유지(epoch만 통합 타임라인), 제어 프레임 근사 dedup ±수% 오차.
