# 멀티 pcap 3단계 — 스니퍼 비교 섹션 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 다중 무선 병합 분석에 스니퍼별 비교 섹션(`structured["sniffer_compare"]`: 초당 시계열 + 커버리지 분해)과 프레임 테이블 출처 배지(w1/w2)를 추가한다 — 스펙 §5 (`docs/superpowers/specs/2026-08-03-multi-pcap-analysis-design.md`).

**Architecture:** 2단계에서 병합 시 이미 계산되는 `MergeResult`(per_source·stats.coverage)를 재활용한다. 스키마 생성은 `analyzer/web/structured.py`에 새 함수 `_structured_sniffer_compare(mr)`로 두고 pipeline은 호출만 한다(오케스트레이션 전용 원칙). 출처 배지는 `frame_to_row(include_source=)`의 opt-in 9번째 키로 실어 debug 프레임 테이블/증거 타임라인 양쪽에 흘려보낸다. 프론트는 Overview 탭에 카드 1개(커버리지 라인 + Plotly 3단 시계열)와 debug 표의 출처 컬럼을 추가하며, 키 부재 시(단일 무선·구버전 결과) 아무것도 렌더하지 않는다.

**Tech Stack:** Python 3 (FastAPI 백엔드), Plotly.js + Tailwind (프론트, `static/js/charts.js`·`timeline.js`), pytest.

## Global Constraints

- **모든 신규 필드는 optional** — 구버전 결과 JSON(`data/analyses/*.json`) 재로드·리포트·프론트 렌더가 깨지지 않는다 (스펙 §6, 메모리 `serialized-result-backward-compat`).
- **단일 무선 분석 결과는 변경 전과 byte-identical** (스펙 §8 스냅샷 회귀). 따라서 `sniffer_compare` 키, `sources[].tag` 키, debug 프레임 행의 `source` 키는 **다중 무선일 때만** 나타난다. 판별 기준: `sources[].tag`는 `len(paths) > 1`, `sniffer_compare`는 `len(mr.per_source) >= 2`, 행 `source`는 `structured.get("sniffer_compare")` 존재 여부.
- **무선 1개 분석에서는 섹션 자체를 생략** — 프론트는 키 부재 시 미표시 (스펙 §5).
- **스키마 생성은 `analyzer/web/structured.py` 소관, `analyzer/pipeline.py`는 오케스트레이션만** (AGENTS.md, PR #23 리뷰 Finding B — `_structured_merge` 선례).
- **per_source 소비 계약** (`analyzer/core/merge.py` `MergeResult` 주석): 소비 필드는 `epoch`(보정됨)·`retry`·`rssi`만 — 셋 다 `_MERGEABLE_DECODED_FIELDS`에 없어 대표 필드 차용 오염이 없고, 재번호된 `number`는 사용하지 않으므로 병합 전 deepcopy 스냅샷이 필요 없다. 이 전제는 가드 테스트로 고정한다 (Task 1 Step 1).
- **시계열·커버리지는 시간 창 적용 전 전체 구간 기준** — `_structured_merge`와 동일 원칙(정렬·병합 통계는 창과 무관하게 전체 구간에서 수행됨).
- 검증 명령: `python3 -m pytest tests/ -q` (938 + 신규 모두 통과), `ruff check .`, tshark 골든: `python3 -m pytest tests/ -q -m tshark`.

---

### Task 1: `_structured_sniffer_compare` — 스키마 생성 함수

**Files:**
- Modify: `analyzer/web/structured.py` (`_structured_merge` 바로 아래, 현재 line 71 부근)
- Test: `tests/test_sniffer_compare.py` (신규)

**Interfaces:**
- Consumes: `analyzer.core.merge.MergeResult` (필드: `per_source: Dict[str, List[Frame]]`, `stats: Dict[str, Any]` — `stats["coverage"] = {"both": int, "only": {tag: int}}`, `stats["kept"] = int`)
- Produces: `_structured_sniffer_compare(mr: MergeResult) -> Optional[Dict[str, Any]]` — 반환 스키마:
  ```python
  {
      "tags": ["w1", "w2"],                       # per_source 삽입 순서 = 업로드 순서
      "series": {                                  # tag → 초당 시계열 (해당 tag의 min~max 초, 갭은 0 채움)
          "w1": [{"epoch": 1000, "frames": 2, "retry": 1, "rssi_avg": -50.0}, ...],
      },
      "coverage": {"both": 1, "only": {"w1": 2, "w2": 1}, "groups_total": 4},
  }
  ```
  소스가 2개 미만이면 `None` (섹션 생략 신호).

`structured.py`의 기존 import(`Counter`, `Optional`, `MergeResult`)로 충분하다 — 새 import 불필요.

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_sniffer_compare.py` 신규 파일:

```python
"""_structured_sniffer_compare — 스니퍼별 초당 시계열 + 커버리지 스키마 (스펙 §5)."""
from analyzer.core.merge import MergeResult, _MERGEABLE_DECODED_FIELDS
from analyzer.web.structured import _structured_sniffer_compare
from tests.conftest import make_frame


def _mr(per_source, stats=None):
    return MergeResult(
        frames=[], per_source=per_source, offsets={},
        stats=stats or {"window_ms": 50, "duplicates": 0, "kept": 0,
                        "coverage": {"both": 0, "only": {}}},
        warnings=[],
    )


def test_two_sources_series_and_coverage():
    w1 = [
        make_frame(number=1, epoch=1000.2, retry=False, rssi="-60"),
        make_frame(number=2, epoch=1000.7, retry=True, rssi="-40"),
        make_frame(number=3, epoch=1002.1, retry=False, rssi=""),
    ]
    w2 = [make_frame(number=1, epoch=1001.5, retry=False, rssi="-70,-72")]
    stats = {"window_ms": 50, "duplicates": 0, "kept": 4,
             "coverage": {"both": 1, "only": {"w1": 2, "w2": 1}}}
    sc = _structured_sniffer_compare(_mr({"w1": w1, "w2": w2}, stats))

    assert sc["tags"] == ["w1", "w2"]
    # w1: 1000초(2건, retry 1, 평균 (-60 + -40)/2 = -50.0) / 1001초(갭 → 0건)
    #     / 1002초(1건, rssi 없음 → None)
    assert sc["series"]["w1"] == [
        {"epoch": 1000, "frames": 2, "retry": 1, "rssi_avg": -50.0},
        {"epoch": 1001, "frames": 0, "retry": 0, "rssi_avg": None},
        {"epoch": 1002, "frames": 1, "retry": 0, "rssi_avg": None},
    ]
    # w2: rssi_first는 첫 안테나 값(-70)만 취한다
    assert sc["series"]["w2"] == [
        {"epoch": 1001, "frames": 1, "retry": 0, "rssi_avg": -70.0},
    ]
    assert sc["coverage"] == {"both": 1, "only": {"w1": 2, "w2": 1},
                              "groups_total": 4}


def test_single_source_returns_none():
    w1 = [make_frame(number=1, epoch=1000.0)]
    assert _structured_sniffer_compare(_mr({"w1": w1})) is None


def test_consumed_fields_are_not_borrowable():
    """per_source 소비 필드(epoch/retry/rssi)가 대표 필드 차용
    (_merge_decoded_fields) 대상에 편입되면 이 시계열은 소스별 순수 관측이
    아니게 된다 — 계약 위반을 여기서 즉시 잡는다 (MergeResult 주석의
    '차용 오염' 지뢰, PR #23 리뷰 4라운드 재리뷰)."""
    assert not {"epoch", "retry", "rssi"} & set(_MERGEABLE_DECODED_FIELDS)
```

- [ ] **Step 2: 실패 확인**

Run: `python3 -m pytest tests/test_sniffer_compare.py -q`
Expected: FAIL — `ImportError: cannot import name '_structured_sniffer_compare'` (가드 테스트만 PASS 가능)

- [ ] **Step 3: 구현**

`analyzer/web/structured.py`, `_structured_merge` 함수 바로 아래에 추가:

```python
def _structured_sniffer_compare(mr: MergeResult) -> Optional[Dict[str, Any]]:
    """스니퍼 비교 스키마(structured["sniffer_compare"]) 생성 — 스펙 §5.

    소스가 2개 미만이면 None — 비교 대상이 없으니 섹션 자체를 생략한다
    (alignment 전용 merge로 생존 소스가 1개인 경우 포함). 시계열은
    per_source(보정된 epoch) 기준 **시간 창 적용 전** 전체 구간이다 —
    _structured_merge와 같은 원칙(정렬·병합 통계는 창과 무관하게 전체 구간
    기준)이고, coverage도 같은 mr.stats에서 그대로 재노출한다.

    per_source 계약(analyzer/core/merge.py MergeResult 주석): 여기서 소비하는
    필드는 epoch·retry·rssi뿐 — 셋 다 _MERGEABLE_DECODED_FIELDS에 없어 대표
    필드 차용 오염을 받지 않고, 재번호되는 number는 쓰지 않으므로 병합 전
    스냅샷이 필요 없다(tests/test_sniffer_compare.py의 가드 테스트로 고정).
    """
    if len(mr.per_source) < 2:
        return None
    series: Dict[str, List[Dict[str, Any]]] = {}
    for tag, frames in mr.per_source.items():
        counts: "Counter[int]" = Counter()
        retries: "Counter[int]" = Counter()
        rssi_sum: Dict[int, int] = {}
        rssi_n: Dict[int, int] = {}
        for f in frames:
            sec = int(f.epoch)
            counts[sec] += 1
            if f.retry:
                retries[sec] += 1
            r = f.rssi_first
            if r is not None:
                rssi_sum[sec] = rssi_sum.get(sec, 0) + r
                rssi_n[sec] = rssi_n.get(sec, 0) + 1
        timeline: List[Dict[str, Any]] = []
        if counts:
            for sec in range(min(counts), max(counts) + 1):
                n = rssi_n.get(sec, 0)
                timeline.append({
                    "epoch": sec,
                    "frames": counts.get(sec, 0),
                    "retry": retries.get(sec, 0),
                    "rssi_avg": round(rssi_sum[sec] / n, 1) if n else None,
                })
        series[tag] = timeline
    cov = mr.stats.get("coverage") or {}
    return {
        "tags": list(mr.per_source.keys()),
        "series": series,
        "coverage": {
            "both": cov.get("both", 0),
            "only": dict(cov.get("only", {})),
            "groups_total": mr.stats.get("kept", 0),
        },
    }
```

- [ ] **Step 4: 통과 확인**

Run: `python3 -m pytest tests/test_sniffer_compare.py -q`
Expected: 3 passed

- [ ] **Step 5: 커밋**

```bash
git add tests/test_sniffer_compare.py analyzer/web/structured.py
git commit -m "feat(web): 스니퍼 비교 스키마 생성 함수 — 초당 시계열 + 커버리지 (스펙 §5)"
```

---

### Task 2: pipeline 연결 — `structured["sniffer_compare"]` + `sources[].tag`

**Files:**
- Modify: `analyzer/pipeline.py` (import 블록 line 28~51, 소스 루프 line 233~236, merge 블록 line 254·312, structured 초기화 line 363~365)
- Test: `tests/test_pipeline_multi_wireless.py` (기존 파일에 추가)

**Interfaces:**
- Consumes: Task 1의 `_structured_sniffer_compare(mr)`
- Produces: `result["structured"]["sniffer_compare"]` (다중 무선 병합 시에만), `structured["sources"]`의 무선 항목에 `"tag": "w1"` 키(다중 업로드 시에만 — 프론트가 tag→파일명 매핑에 사용. `routes/upload.py:333~346`이 분석 후 `sources[].name`을 원본 파일명으로 치환하므로 tag가 유일한 안정 조인 키다)

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_pipeline_multi_wireless.py` 끝에 추가 (기존 `_w1_frames`/`_w2_frames`/`_patch_common`/`FILE_W1`/`FILE_W2`/`GT_OK` 재사용):

```python
def test_sniffer_compare_block_for_two_sources(monkeypatch):
    """다중 무선이면 sniffer_compare가 생성되고, 소스별 시계열 합계는
    그 소스의 raw 프레임 수와 일치하며, sources에 tag가 붙는다."""
    frames_by_path = {FILE_W1: _w1_frames(), FILE_W2: _w2_frames()}
    _patch_common(monkeypatch, dict(GT_OK), frames_by_path)

    result = pipeline.run_analysis(FILE_W1, wireless_paths=[FILE_W2])

    sc = result["structured"]["sniffer_compare"]
    assert sc["tags"] == ["w1", "w2"]
    assert sum(p["frames"] for p in sc["series"]["w1"]) == len(_w1_frames())
    assert sum(p["frames"] for p in sc["series"]["w2"]) == len(_w2_frames())
    cov = sc["coverage"]
    assert cov["both"] + sum(cov["only"].values()) == cov["groups_total"]

    wireless = [s for s in result["structured"]["sources"]
                if s["role"] == "wireless"]
    assert [s["tag"] for s in wireless] == ["w1", "w2"]


def test_single_wireless_has_no_sniffer_compare_and_no_tag(monkeypatch):
    """단일 무선은 스냅샷 불변 — sniffer_compare 키도 tag 키도 없다."""
    frames_by_path = {FILE_W1: _w1_frames()}
    _patch_common(monkeypatch, dict(GT_OK), frames_by_path)

    result = pipeline.run_analysis(FILE_W1)

    assert "sniffer_compare" not in result["structured"]
    (src,) = [s for s in result["structured"]["sources"]
              if s["role"] == "wireless"]
    assert "tag" not in src
```

- [ ] **Step 2: 실패 확인**

Run: `python3 -m pytest tests/test_pipeline_multi_wireless.py -q`
Expected: 신규 2건 FAIL (`KeyError: 'sniffer_compare'`, `KeyError: 'tag'`), 기존 테스트는 PASS 유지

- [ ] **Step 3: 구현 (4곳 수정)**

① import 블록 — `analyzer/pipeline.py:36` `_structured_merge,` 다음 줄에 `_structured_sniffer_compare,` 추가, `__all__`(line 50 `"_structured_merge",` 다음)에도 `"_structured_sniffer_compare",` 추가.

② 소스 루프 — line 233~236의 `src_entry` 생성 직후에 추가:

```python
        src_entry = {
            "name": Path(path).name, "role": "wireless",
            "frame_count": len(file_frames), "warnings": [],
        }
        if len(paths) > 1:
            # tag는 프론트가 sniffer_compare/배지와 sources를 조인하는 키 —
            # 단일 업로드 결과의 직렬화를 바꾸지 않도록 다중일 때만 싣는다.
            src_entry["tag"] = tag
```

③ merge 블록 — line 254 `merge_summary: Optional[Dict[str, Any]] = None` 다음 줄에 `sniffer_summary: Optional[Dict[str, Any]] = None` 추가, line 312 `merge_summary = _structured_merge(mr)` 다음 줄에 `sniffer_summary = _structured_sniffer_compare(mr)` 추가 (생존 소스 1개인 alignment 전용 merge에서는 함수가 None을 돌려줘 자연히 생략된다).

④ structured 초기화 — line 363~365를 다음으로 확장:

```python
    if merge_summary is not None:
        structured["merge"] = merge_summary
    if sniffer_summary is not None:
        structured["sniffer_compare"] = sniffer_summary
```

- [ ] **Step 4: 통과 확인**

Run: `python3 -m pytest tests/test_pipeline_multi_wireless.py tests/test_pipeline.py -q`
Expected: 전부 PASS (기존 단일 pcap 테스트 포함)

- [ ] **Step 5: 커밋**

```bash
git add analyzer/pipeline.py tests/test_pipeline_multi_wireless.py
git commit -m "feat(pipeline): sniffer_compare 연결 + sources[].tag — 다중 무선에서만"
```

---

### Task 3: 출처 배지 데이터 — `frame_to_row(include_source=)` + debug 블록 연결

**Files:**
- Modify: `analyzer/web/frame_table.py` (`frame_to_row`, line 28~52)
- Modify: `analyzer/web/evidence.py` (`build_debug_block` 내 행 직렬화 루프, line 448~454)
- Test: `tests/test_frame_table.py` (기존 파일에 추가)

**Interfaces:**
- Consumes: `Frame.source` (`analyzer/core/models.py:52` — pipeline이 무선 파일별로 w1/w2… 태깅, 단일 파일도 "w1"이 채워지므로 **키 노출은 include_source 플래그로만 제어**한다), Task 2의 `structured["sniffer_compare"]` 존재 여부
- Produces: `frame_to_row(frame, include_source=False)` — `include_source=True`면 9번째 키 `"source"`(str) 추가. `build_debug_block`의 `frames` 행에 다중 무선일 때만 `source` 키가 실린다.

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_frame_table.py`에 추가 (기존 import에 `build_debug_block` 추가: `from analyzer.web.evidence import build_debug_block`):

```python
class TestSourceBadge:
    def test_default_excludes_source(self):
        f = make_frame(source="w2")
        assert "source" not in frame_to_row(f)

    def test_include_source_adds_ninth_key(self):
        f = make_frame(source="w2")
        row = frame_to_row(f, include_source=True)
        assert set(row) == set(FRAME_ROW_KEYS) | {"source"}
        assert row["source"] == "w2"

    def test_debug_block_rows_carry_source_only_with_sniffer_compare(self):
        frames = [make_frame(number=1, source="w1"),
                  make_frame(number=2, epoch=1000.5, source="w2")]
        diag = {"diagnosis": {"issues": [{"frame_refs": [1, 2]}]}}

        multi = build_debug_block(
            {**diag, "sniffer_compare": {"tags": ["w1", "w2"]}},
            frames, index=None, roles=None)
        assert [r["source"] for r in multi["frames"]] == ["w1", "w2"]

        single = build_debug_block(dict(diag), frames, index=None, roles=None)
        assert all("source" not in r for r in single["frames"])
```

(`make_frame`은 `tests/conftest.py:18` — `source` kwarg는 `Frame(source=...)`로 그대로 전달된다.)

- [ ] **Step 2: 실패 확인**

Run: `python3 -m pytest tests/test_frame_table.py -q`
Expected: 신규 3건 FAIL (`TypeError: frame_to_row() got an unexpected keyword argument`), 기존 5건 PASS

- [ ] **Step 3: 구현**

① `analyzer/web/frame_table.py` — 시그니처와 반환을 다음으로 교체 (docstring에는 "include_source=True면 9번째 키 `source`(캡처 출처 태그 w1/w2…)를 추가한다 — 단일 pcap 직렬화를 바꾸지 않기 위해 기본은 8키" 한 줄 추가):

```python
def frame_to_row(frame: Frame, include_source: bool = False) -> Dict[str, Any]:
    ...
    reason_code: Optional[str] = frame.reason_code or None
    row = {
        "number": frame.number,
        "timestamp": frame.timestamp,
        "type_subtype": f"{frame.frame_type}/{frame.subtype_name}",
        "retry": frame.retry,
        "mcs": frame.mcs_int,
        "rssi": frame.rssi_first,
        "reason_code": reason_code,
        "seq": frame.seq,
    }
    if include_source:
        row["source"] = frame.source
    return row
```

`FRAME_ROW_KEYS`는 8개 그대로 둔다(표의 고정 컬럼 계약 — source는 opt-in 부가 컬럼). 상수 주석에 "다중 무선 병합 시 `source`가 9번째 키로 추가될 수 있다(frame_to_row include_source)" 명시.

② `analyzer/web/evidence.py` — line 452 `frame_rows: List[Dict[str, Any]] = []` 직전에 플래그 계산을 추가하고 line 454를 수정:

```python
    # 출처 배지(w1/w2)는 다중 무선 병합에서만 — 단일 pcap 직렬화 불변(스펙 §8).
    include_source = bool(structured.get("sniffer_compare"))
    frame_rows: List[Dict[str, Any]] = []
    for f in ordered:
        row = frame_to_row(f, include_source=include_source)
```

(호출 순서 보장: `build_debug_block`은 `analyzer/pipeline.py:480`에서 호출되고 `sniffer_compare`는 line ~365에서 이미 삽입돼 있다.)

- [ ] **Step 4: 통과 확인**

Run: `python3 -m pytest tests/test_frame_table.py tests/test_pipeline.py tests/test_pipeline_multi_wireless.py -q`
Expected: 전부 PASS (`tests/test_pipeline.py:620`의 `FRAME_ROW_KEYS ⊆ 행` 가드는 부분집합 검사라 그대로 성립)

- [ ] **Step 5: 커밋**

```bash
git add analyzer/web/frame_table.py analyzer/web/evidence.py tests/test_frame_table.py
git commit -m "feat(web): debug 프레임 행 출처 키 — 다중 무선 병합에서만 opt-in"
```

---

### Task 4: 프론트 — 스니퍼 비교 카드 + 출처 배지 렌더

**Files:**
- Modify: `templates/analysis.html` (Overview 탭 line 92 아래 카드 컨테이너, debug 표 헤더 line 235)
- Modify: `static/js/charts.js` (병합 카드 블록 line 73~93 아래)
- Modify: `static/js/timeline.js` (debug 표 렌더 line 855~975)

**Interfaces:**
- Consumes: `DATA.sniffer_compare`(Task 1 스키마), `DATA.sources[].tag`(Task 2), debug 행의 `r.source`(Task 3), 기존 `DARK` 레이아웃(`charts.js:13`)·`escapeHtml`(양쪽 파일에 존재)
- Produces: 사용자 화면 — Overview 카드(커버리지 라인 + frames/s·평균 RSSI·retry% 3단 시계열), debug 표 "출처" 컬럼(배지). 키 부재 시 완전 무표시.

- [ ] **Step 1: analysis.html — 카드 컨테이너 추가**

line 92 `<div class="grid grid-cols-4 gap-4 mb-6" id="kpi-cards"></div>` 바로 다음에:

```html
    <!-- 스니퍼 비교 (스펙 §5) — 다중 무선 병합 시에만 charts.js가 unhide -->
    <div class="bg-gray-800 rounded-lg p-4 border border-gray-700 mb-6 hidden" id="sniffer-compare-card">
        <h3 class="text-sm font-semibold text-gray-400 mb-1">스니퍼 비교</h3>
        <p class="text-sm text-gray-300" id="sniffer-coverage-line"></p>
        <div id="sniffer-compare-chart" class="mt-3" style="height:420px"></div>
    </div>
```

(병합 카드는 JS가 `kpi-cards` afterend로 삽입하므로 화면 순서는 KPI → 무선 병합 → 스니퍼 비교가 된다.)

- [ ] **Step 2: analysis.html — debug 표 헤더에 출처 컬럼**

line 235 `<th class="text-left py-2 px-1">Seq</th>` 다음에:

```html
                        <th class="text-left py-2 px-1 hidden" id="debug-col-source">출처</th>
```

- [ ] **Step 3: charts.js — 스니퍼 비교 카드 렌더**

병합 카드 블록(line 73~93, `kpiContainer.insertAdjacentHTML(...)` 닫힌 뒤) 바로 아래에:

```js
    /* ── 스니퍼 비교 카드 ── 다중 무선 병합 시(DATA.sniffer_compare)만 표시, 구버전 결과는 무동작 */
    const sniffer = DATA.sniffer_compare;
    const snifferCard = document.getElementById('sniffer-compare-card');
    if (snifferCard && sniffer && Array.isArray(sniffer.tags) && sniffer.tags.length >= 2) {
        snifferCard.classList.remove('hidden');
        const tagNames = {};
        (DATA.sources || []).forEach(s => { if (s.tag) tagNames[s.tag] = s.name; });
        const label = t => tagNames[t] ? `${t} (${tagNames[t]})` : t;

        /* 커버리지 분해 — dedup 그룹 기준 양쪽/단독 비율 (스니퍼 배치 평가 핵심 수치) */
        const cov = sniffer.coverage || {};
        const totalGroups = cov.groups_total || 0;
        const pct = n => totalGroups ? (100 * n / totalGroups).toFixed(1) : '0.0';
        const only = cov.only || {};
        const parts = [`양쪽 포착 <span class="font-semibold text-white">${(cov.both || 0).toLocaleString()}</span>건 (${pct(cov.both || 0)}%)`]
            .concat(sniffer.tags.filter(t => only[t]).map(t =>
                `${escapeHtml(label(t))} 단독 <span class="font-semibold text-white">${only[t].toLocaleString()}</span>건 (${pct(only[t])}%)`));
        document.getElementById('sniffer-coverage-line').innerHTML = parts.join(' · ');

        /* 초당 시계열 3단: Frames/s · 평균 RSSI · Retry% — 소스별 trace */
        const SRC_COLORS = { w1: '#3b82f6', w2: '#f59e0b', w3: '#10b981', w4: '#a855f7' };
        const traces = [];
        sniffer.tags.forEach(tag => {
            const tl = (sniffer.series || {})[tag] || [];
            const x = tl.map(p => new Date(p.epoch * 1000));
            const color = SRC_COLORS[tag] || '#9ca3af';
            const line = { color, width: 1.5 };
            traces.push({ x, y: tl.map(p => p.frames), name: label(tag), legendgroup: tag,
                          type: 'scatter', mode: 'lines', line, yaxis: 'y' });
            traces.push({ x, y: tl.map(p => p.rssi_avg), name: label(tag), legendgroup: tag,
                          showlegend: false, type: 'scatter', mode: 'lines', line,
                          connectgaps: false, yaxis: 'y2' });
            traces.push({ x, y: tl.map(p => p.frames ? +(100 * p.retry / p.frames).toFixed(1) : null),
                          name: label(tag), legendgroup: tag, showlegend: false,
                          type: 'scatter', mode: 'lines', line, connectgaps: false, yaxis: 'y3' });
        });
        Plotly.newPlot('sniffer-compare-chart', traces, {
            ...DARK,
            margin: { t: 10, r: 10, b: 30, l: 50 },
            showlegend: true,
            legend: { orientation: 'h', y: 1.08 },
            xaxis: { anchor: 'y3', gridcolor: '#374151' },
            yaxis: { domain: [0.72, 1.0], title: { text: 'Frames/s', font: { size: 10 } }, gridcolor: '#374151', rangemode: 'tozero' },
            yaxis2: { domain: [0.38, 0.66], title: { text: '평균 RSSI (dBm)', font: { size: 10 } }, gridcolor: '#374151' },
            yaxis3: { domain: [0.0, 0.3], title: { text: 'Retry %', font: { size: 10 } }, gridcolor: '#374151', rangemode: 'tozero' },
        }, { responsive: true, displayModeBar: false });
    }
```

- [ ] **Step 4: timeline.js — debug 표 출처 배지 컬럼**

① line 861 `const debugFrames = debug.frames || [];` 다음에:

```js
    /* 출처 배지(w1/w2) — 다중 무선 병합 행에만 source 키가 있다(구버전/단일은 컬럼 자체 미표시) */
    const hasSource = debugFrames.some(r => r.source);
    const srcTh = document.getElementById('debug-col-source');
    if (srcTh && hasSource) srcTh.classList.remove('hidden');
    const SRC_BADGE_CLS = {
        w1: 'bg-blue-900/60 text-blue-300', w2: 'bg-amber-900/60 text-amber-300',
        w3: 'bg-emerald-900/60 text-emerald-300', w4: 'bg-purple-900/60 text-purple-300',
    };
    const srcBadge = tag => tag
        ? `<span class="px-1 rounded text-xs ${SRC_BADGE_CLS[tag] || 'bg-gray-700 text-gray-300'}">${escapeHtml(tag)}</span>`
        : '';
```

② line 931의 빈 행 안내 `colspan="8"` → `` colspan="${hasSource ? 9 : 8}" `` (템플릿 리터럴로 변경).

③ 행 템플릿(line 943~952)의 마지막 `<td ...>${escapeHtml(r.seq)}</td>` 다음, `</tr>` 앞에:

```js
                ${hasSource ? `<td class="py-1 px-1">${srcBadge(r.source)}</td>` : ''}
```

- [ ] **Step 5: 수동 검증 (JS 테스트 하니스 없음 — Phase 2 Task 6과 동일 방식)**

```bash
python3 app.py
```

1. **하위 호환**: 기존 저장 분석(단일 무선, `data/analyses/`) 열기 → 스니퍼 비교 카드 미표시, debug 표 8컬럼, 콘솔 에러 0건.
2. **다중 무선**: `tmp/20260721_CFI/TEST1/`의 cantops + DFK 무선 2개(+유선) 재분석 → Overview에 스니퍼 비교 카드(커버리지 라인 %·3단 차트, DFK는 미복호 구간에서 RSSI만 유의미해야 정상), 통합 타임라인 debug 표에 출처 컬럼+배지, finding 증거 하이라이트 행에도 배지 표시 확인.
3. 창 크기 변경 시 차트 responsive 동작 확인.

- [ ] **Step 6: 커밋**

```bash
git add templates/analysis.html static/js/charts.js static/js/timeline.js
git commit -m "feat(front): 스니퍼 비교 카드 + debug 표 출처 배지 (스펙 §5)"
```

---

### Task 5: 골든 회귀 확장 + 문서 + 전체 회귀

**Files:**
- Modify: `tests/test_golden_dual.py` (스니퍼 비교 골든 추가)
- Modify: `README.md` (line 5 부근 — 다중 무선 문단에 스니퍼 비교 한 줄)
- Test: 전체 스위트

**Interfaces:**
- Consumes: Task 1~3의 산출 전부 (실 pcap 이중 캡처 경로로 통합 검증)

- [ ] **Step 1: 골든 테스트 추가**

`tests/test_golden_dual.py` 끝에 추가 (모듈의 기존 result 픽스처 — `run_analysis(str(FIXTURE_A), wireless_paths=[str(FIXTURE_B)])` — 를 그대로 사용, 파일 상단의 tshark 마커 관례 유지):

```python
def test_sniffer_compare_golden(result):
    """스니퍼 비교 블록 — 시계열 합계는 소스 raw 수와, 커버리지 합은 dedup
    그룹 총수와 정확히 일치해야 한다(뮤테이션 내성: 어느 한 쪽 집계가
    바뀌면 즉시 깨진다)."""
    sc = result["structured"]["sniffer_compare"]
    assert sc["tags"] == ["w1", "w2"]

    cov = sc["coverage"]
    assert cov["groups_total"] == result["structured"]["merge"]["kept"]
    assert cov["both"] + sum(cov["only"].values()) == cov["groups_total"]

    by_tag = {s["tag"]: s for s in result["structured"]["sources"]
              if s.get("tag")}
    for tag in sc["tags"]:
        assert sum(p["frames"] for p in sc["series"][tag]) \
            == by_tag[tag]["frame_count"]

    # debug 행 출처 배지 — 값은 반드시 실제 태그 집합 안에 있어야 한다
    rows = result["structured"]["debug"]["frames"]
    assert rows and all(r.get("source") in ("w1", "w2") for r in rows)
```

(주의: `result` 픽스처 이름·범위는 기존 파일 관례를 따른다 — 파일에서 픽스처명이 다르면 그 이름을 쓴다.)

- [ ] **Step 2: 골든 실행 확인**

Run: `python3 -m pytest tests/test_golden_dual.py -q -m tshark`
Expected: 전부 PASS (로컬 tshark 4.4.x 필요)

- [ ] **Step 3: README 갱신**

`README.md` line 5 문단(유선 ground truth 설명) 뒤에 한 줄 추가:

```markdown
무선 pcap을 여러 개(최대 4) 올리면 비콘 TSF로 시계를 정렬해 중복을 제거한 통합 타임라인을 만들고, 스니퍼별 초당 프레임·RSSI·재전송 시계열과 커버리지 분해(양쪽/단독 포착 비율), 프레임 출처 배지(w1/w2)로 스니퍼 배치를 평가할 수 있다.
```

- [ ] **Step 4: 전체 회귀**

```bash
python3 -m pytest tests/ -q          # 938 + 신규 전부 PASS
ruff check .
python3 -m pytest tests/ -q -m tshark  # 골든 17 + 신규
```

Expected: 전부 green. 특히 단일 pcap 스냅샷·구버전 JSON 로드 스모크(기존 하위 호환 테스트)가 그대로 통과해야 한다.

- [ ] **Step 5: 커밋**

```bash
git add tests/test_golden_dual.py README.md
git commit -m "test(golden): 스니퍼 비교 골든 + README 다중 무선 안내"
```

---

## 계획 자가 리뷰 결과

- **스펙 §5 커버리지**: 초당 시계열(Task 1·4) ✓ / 커버리지 분해(Task 1·4 — `mr.stats["coverage"]` 재노출 + % 표시) ✓ / 프레임 테이블·debug 증거 출처 배지(Task 3·4 — 두 화면 모두 `build_debug_block`→`frame_to_row` 단일 경로라 한 변경으로 충족) ✓ / 무선 1개 시 섹션 생략(Task 1 None 게이트 + 프론트 키 부재 무동작) ✓
- **플레이스홀더 스캔**: 코드 블록 전부 실제 값·실제 시그니처. TBD 없음.
- **타입 일관성**: `_structured_sniffer_compare(mr: MergeResult) -> Optional[Dict[str, Any]]`가 Task 1(정의)·2(호출)에서 동일. `frame_to_row(frame, include_source: bool = False)`가 Task 3(정의)·evidence 호출에서 동일. 스키마 키(`tags/series/coverage`, `frames/retry/rssi_avg/epoch`)가 Task 1 테스트·Task 4 JS 소비 코드에서 동일.
- **하위 호환 검증 경로**: 단일 무선 무변경(Task 2·3 테스트로 고정), 구버전 JSON 렌더(Task 4 수동 검증 1번), 기존 스냅샷·스모크(Task 5 전체 회귀).
