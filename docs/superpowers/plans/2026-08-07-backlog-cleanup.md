# 백로그 정비 구현 계획 — 토글 왕복 정리·per_second 가드·report 다중무선

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 누적 백로그 4건 처리 — ① ping 토글 왕복 상태 정리(무선 빈 상태 purge/height/el.on) ② `GT_OK` mock 주석 ③ `_structured_per_second` epoch 가드+span 폴백 ④ report.md 다중 무선 병합 섹션. (⑤ sniffer-series 다운샘플링은 실측 근거 부재로 이연 유지 — 1시간+ 캡처가 실제로 등장하면 재론.)

**Architecture:** 각 항목의 출처는 PR #24~#26 리뷰 기록. ①은 pre-existing 무선 빈 상태 분기의 순수 정리(프론트), ③은 PR #24에서 신규 코드에만 넣었던 방어를 형제 함수에 미러링(백엔드), ④는 `_ping_section` 선례를 따르는 신규 report 섹션. 전 항목 공통 불변식: **해당 데이터가 없는 결과(단일 무선·정상 epoch)는 출력 불변**.

**Tech Stack:** Python 3 + pytest, Plotly.js (`static/js/charts.js`).

## Global Constraints

- **단일 무선/정상 입력 출력 불변**: ③은 정상 epoch 캡처에서 timeline 결과가 기존과 동일해야 하고(기존 테스트 회귀 0), ④는 `structured["merge"]` 부재 시 report 출력 byte-identical.
- ①의 높이 복원 기준값은 템플릿 인라인 스타일(RTT 400px / 히스토그램 300px — `templates/analysis.html`에서 구현 시 실측 확인)과 일치해야 한다.
- ③의 span 상한은 기존 `_SNIFFER_FILL_MAX_SPAN_SEC`(6h)를 **재사용**한다 — 이름이 도입처(sniffer) 기준일 뿐 동일 원칙이므로 상수 주석만 보강, 이름 변경 금지(불필요 churn).
- XSS(④): report 인라인 삽입 문자열은 기존 관례대로 `_clean_inline` 경유.
- 검증: `python3 -m pytest tests/ -q` (958+신규), `ruff check .`, `node --check static/js/charts.js`. 브라우저 검증(①)은 컨트롤러 수행.

---

### Task 1: ping 토글 왕복 상태 정리 (백로그 ①, 프론트)

**Files:**
- Modify: `static/js/charts.js` — 무선 빈 상태 분기 2곳(RTT ~line 960-966 `pingRttEl.style.height = 'auto'` 부근, 히스토그램 ~line 1048-1052) + 플롯 경로 4곳(무선 RTT 2분기·유선 RTT·무선/유선 히스토그램)

**Interfaces:**
- Consumes: 기존 빈 상태 분기와 plot 경로들. 템플릿 기본 높이(RTT 400px/hist 300px — 구현 시 analysis.html에서 확인).
- Produces: 어떤 토글 순서(유선⇄무선, 빈 상태 경유 포함)에서도 ⓐ Plotly 인스턴스가 명시적으로 purge되고 ⓑ 차트 높이가 plot 시 기본값으로 복원되며 ⓒ `el.on` stale 가드 괴리가 사라진다(purge가 expando 제거).

- [ ] **Step 1: 무선 빈 상태 분기에 purge 추가 (2곳)**

- RTT: `if (pingRttEl && pairs.length === 0 && losses.length === 0) {` 분기 안, `pingRttEl.innerHTML = ...` **앞**에 `Plotly.purge('chart-ping-rtt');` 추가.
- 히스토그램: 대응 빈 상태 분기(`pingHistEl.style.height = 'auto'` 부근)에 같은 패턴으로 `Plotly.purge('chart-ping-hist');` 추가.
- 각 추가에 한 줄 주석: `// 이전 소스의 Plotly 인스턴스·expando(.on 등) 명시 해제 — 토글 왕복 리소스/stale 가드 정리 (백로그 ①)`

- [ ] **Step 2: plot 경로에 높이 복원 (4곳)**

빈 상태가 `style.height='auto'`로 바꾼 것을 plot 시 되돌린다 — `Plotly.newPlot('chart-ping-rtt', ...)` 직전에 `pingRttEl.style.height = '400px';`(무선 RTT 두 분기 — losses-only 마커 차트와 일반 차트), `renderPingRttWired`에도 동일(`const el = document.getElementById('chart-ping-rtt'); if (el) el.style.height = '400px';` — 기존 지역 변수 있으면 재사용). 히스토그램 두 경로(무선 plot 분기·`renderPingHistWired`)는 `'300px'`. 값은 Step 0에서 템플릿 실측값으로 확정(400/300과 다르면 템플릿 값을 따른다).

- [ ] **Step 3: 검증 + 커밋**

Run: `node --check static/js/charts.js && ruff check .`
브라우저 검증은 컨트롤러가 수행(유선⇄무선 왕복 + 빈 상태 시나리오는 관찰 ICMP 없는 구버전/합성 분석으로).

```bash
git add static/js/charts.js
git commit -m "fix(front): ping 차트 토글 왕복 상태 정리 — 빈 상태 purge + 높이 복원 (백로그 ①)"
```

---

### Task 2: `_structured_per_second` epoch 가드 + span 폴백, GT_OK 주석 (백로그 ③+②)

**Files:**
- Modify: `analyzer/web/structured.py::_structured_per_second` (line ~558-587)
- Modify: `tests/test_pipeline_wired.py` (`GT_OK` dict 주석 1줄)
- Test: `tests/test_per_second_timeline.py` (신규)

**Interfaces:**
- Consumes: `_SNIFFER_FILL_MAX_SPAN_SEC`(동일 모듈), `math`(이미 import됨 — PR #25에서 추가)
- Produces: 손상 epoch(None/NaN/Inf) 프레임 스킵, span 초과 시 관측 초만 담는 희소 timeline. 정상 입력 출력 불변.

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_per_second_timeline.py` 신규:

```python
"""_structured_per_second 방어 가드 — 손상 epoch·거대 span (백로그 ③, PR #24 공통 이슈)."""
from analyzer.web.structured import _structured_per_second
from tests.conftest import make_frame


def test_invalid_epochs_are_skipped():
    """None/NaN/Inf epoch 프레임은 집계에서 제외 — int() 변환 예외로 분석이 죽지 않는다."""
    frames = [
        make_frame(number=1, epoch=1000.2, retry=True),
        make_frame(number=2, epoch=None),
        make_frame(number=3, epoch=float("nan")),
        make_frame(number=4, epoch=float("inf")),
    ]
    tl = _structured_per_second(frames)["timeline"]
    assert [(p["epoch"], p["total"], p["retry"]) for p in tl] == [(1000, 1, 1)]


def test_all_invalid_epochs_returns_empty():
    frames = [make_frame(number=1, epoch=None)]
    assert _structured_per_second(frames) == {"timeline": []}


def test_huge_span_falls_back_to_sparse():
    """zero-fill 상한 초과 시 관측 초만 담는 희소 timeline — range() 팽창 차단."""
    frames = [
        make_frame(number=1, epoch=0.0),
        make_frame(number=2, epoch=100_000_000.0),
    ]
    tl = _structured_per_second(frames)["timeline"]
    assert [p["epoch"] for p in tl] == [0, 100_000_000]
    assert all(p["total"] == 1 for p in tl)
```

Run: `python3 -m pytest tests/test_per_second_timeline.py -q` → Expected: 3 FAIL (`TypeError: int() ... NoneType` 등)

- [ ] **Step 2: 구현**

`_structured_per_second` 본문을 다음으로 교체(반환 스키마·필드 산식 불변 — 가드와 순회 구조만 변경):

```python
def _structured_per_second(frames: List[Frame]) -> Dict[str, Any]:
    """초당 프레임 수 시계열.

    손상 epoch(None/NaN/Inf) 프레임은 집계에서 제외하고, zero-fill 구간이
    _SNIFFER_FILL_MAX_SPAN_SEC를 넘으면 관측된 초만 담는 희소 timeline로
    폴백한다 — _structured_sniffer_compare와 동일 방어(PR #24 리뷰에서
    공통 이슈로 기록된 형제 함수 미러링, 백로그 ③).
    """
    sec_counts: "Counter[int]" = Counter()
    retry_counts: "Counter[int]" = Counter()
    byte_counts: "Counter[int]" = Counter()
    data_byte_counts: "Counter[int]" = Counter()
    for f in frames:
        if f.epoch is None or not math.isfinite(f.epoch):
            continue
        sec = int(f.epoch)
        sec_counts[sec] += 1
        if f.retry:
            retry_counts[sec] += 1
        # throughput용 바이트 집계 — bytes는 전체(frame.len 합), data_bytes는
        # Data 타입만. Mbps 환산은 소비자(프론트/리포트)가 ×8/1e6으로 수행.
        byte_counts[sec] += f.length
        if f.is_data:
            data_byte_counts[sec] += f.length
    if not sec_counts:
        return {"timeline": []}
    lo, hi = min(sec_counts), max(sec_counts)
    secs = range(lo, hi + 1) if hi - lo <= _SNIFFER_FILL_MAX_SPAN_SEC else sorted(sec_counts)
    timeline = [
        {
            "epoch": sec,
            "total": sec_counts.get(sec, 0),
            "retry": retry_counts.get(sec, 0),
            "bytes": byte_counts.get(sec, 0),
            "data_bytes": data_byte_counts.get(sec, 0),
        }
        for sec in secs
    ]
    return {"timeline": timeline}
```

`_SNIFFER_FILL_MAX_SPAN_SEC` 상수 주석에 한 줄 추가: `#: (_structured_per_second도 같은 상한을 공유한다 — 백로그 ③)`

- [ ] **Step 3: GT_OK 주석 (백로그 ②)**

`tests/test_pipeline_wired.py`의 `GT_OK = {` 바로 위에:

```python
# 주의: 이 mock은 "파이프라인 통과"만 검증한다 — 모집단 등식(total==len(exchanges)
# 등)은 producer(build_ground_truth) 소관이라 여기선 일부러 맞추지 않는다.
# 스키마 유효한 GT 예시로 복사하지 말 것 (PR #25 최종 재검증 관찰).
```

- [ ] **Step 4: 통과 확인 + 커밋**

Run: `python3 -m pytest tests/test_per_second_timeline.py tests/test_eapol.py tests/test_pipeline.py tests/test_pipeline_wired.py -q` 전부 PASS → 전체 `python3 -m pytest tests/ -q` (958+3) + `ruff check .`

```bash
git add analyzer/web/structured.py tests/test_per_second_timeline.py tests/test_pipeline_wired.py
git commit -m "fix(web): per_second epoch 가드 + span 희소 폴백 — sniffer_compare 방어 미러링 (백로그 ③·②)"
```

---

### Task 3: report.md 다중 무선 병합 섹션 (백로그 ④)

**Files:**
- Modify: `analyzer/web/report.py` (신규 `_multi_wireless_section` + 조립부 line ~681 `_meta_section` 직후 삽입)
- Test: `tests/test_report.py` (기존 파일에 추가)

**Interfaces:**
- Consumes: `structured["merge"]` (`{window_ms, duplicates, kept, coverage:{both, only:{tag:n}}}`), `structured["sources"]` (무선 항목: `{name, role, frame_count, tag?, applied_offset_ms?, offset_method?}`), `_clean_inline`(기존 헬퍼)
- Produces: merge 있을 때만 "## 다중 무선 병합" 섹션(소스별 프레임·오프셋 + 병합/커버리지 요약). 없으면 `[]` — 단일 무선 report byte-identical.

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_report.py`에 추가 (기존 `_ping_section` 테스트 관례를 따라 직접 함수 호출):

```python
def test_multi_wireless_section_with_merge():
    structured = {
        "merge": {"window_ms": 50.0, "duplicates": 100, "kept": 400,
                  "coverage": {"both": 100, "only": {"w1": 120, "w2": 180}}},
        "sources": [
            {"name": "a.pcapng", "role": "wireless", "frame_count": 220,
             "tag": "w1", "applied_offset_ms": 0.0, "offset_method": "reference"},
            {"name": "b.pcap", "role": "wireless", "frame_count": 280,
             "tag": "w2", "applied_offset_ms": -183510.362, "offset_method": "tsf"},
            {"name": "wired.pcapng", "role": "wired", "frame_count": None},
        ],
    }
    text = "\n".join(_multi_wireless_section(structured))
    assert "다중 무선 병합" in text
    assert "w1" in text and "a.pcapng" in text and "기준 시계" in text
    assert "w2" in text and "-183,510.362ms" in text and "(tsf)" in text
    assert "중복 제거 100건" in text and "통합 400건" in text
    assert "양쪽 포착 100건(25.0%)" in text
    assert "w2 단독 180건(45.0%)" in text
    # wired 소스는 무선 목록에 나오지 않는다
    assert "wired.pcapng" not in text


def test_multi_wireless_section_absent_without_merge():
    assert _multi_wireless_section({}) == []
    assert _multi_wireless_section({"sources": [{"role": "wireless", "name": "x"}]}) == []
```

Run: FAIL (`ImportError`/`NameError`) 확인.

- [ ] **Step 2: 구현**

`report.py`에 `_ping_section` 부근에 추가:

```python
def _multi_wireless_section(structured: Dict[str, Any]) -> List[str]:
    """다중 무선 병합 요약 — structured["merge"]가 있을 때만 (단일 무선 report
    출력 불변, 백로그 ④: Phase 2부터 report에 병합 맥락이 통째로 빠져 있었다)."""
    merge = structured.get("merge")
    if not isinstance(merge, dict) or not merge:
        return []
    lines = ["## 다중 무선 병합", ""]
    for s in structured.get("sources") or []:
        if not isinstance(s, dict) or s.get("role") != "wireless":
            continue
        parts = [f"{s.get('frame_count') or 0:,} 프레임"]
        off = s.get("applied_offset_ms")
        if isinstance(off, (int, float)):
            method = s.get("offset_method") or ""
            parts.append("기준 시계" if method == "reference"
                         else f"오프셋 {off:+,.3f}ms ({_clean_inline(str(method))})")
        tag = s.get("tag")
        prefix = f"{_clean_inline(str(tag))} " if tag else ""
        lines.append(f"- {prefix}`{_clean_inline(str(s.get('name', '?')))}` — {' · '.join(parts)}")
    kept = merge.get("kept") or 0
    cov = merge.get("coverage") or {}

    def _pct(n: int) -> str:
        return f"{100 * n / kept:.1f}%" if kept else "0%"

    cov_parts = [f"양쪽 포착 {cov.get('both', 0):,}건({_pct(cov.get('both', 0))})"]
    for t, n in (cov.get("only") or {}).items():
        cov_parts.append(f"{_clean_inline(str(t))} 단독 {n:,}건({_pct(n)})")
    lines.append(f"- 병합: 중복 제거 {merge.get('duplicates') or 0:,}건 · "
                 f"통합 {kept:,}건 — {' · '.join(cov_parts)}")
    lines.append("")
    return lines
```

조립부(line ~681)의 `out.extend(_meta_section(result))` 바로 다음 줄에 `out.extend(_multi_wireless_section(structured))` 삽입.

- [ ] **Step 3: 통과 확인 + 커밋**

Run: `python3 -m pytest tests/test_report.py tests/test_reporter.py tests/test_report_html.py -q` → 전체 suite + ruff.

```bash
git add analyzer/web/report.py tests/test_report.py
git commit -m "feat(report): 다중 무선 병합 섹션 — 소스별 오프셋·커버리지 요약 (백로그 ④)"
```

---

## 계획 자가 리뷰 결과

- **백로그 커버리지**: ①(Task 1 — purge 2곳·높이 복원 4곳·el.on은 purge로 자연 해소) ②(Task 2 Step 3) ③(Task 2 — 가드+폴백+테스트 3종) ④(Task 3 — 섹션+무-merge 불변 테스트) ✓. ⑤는 헤더에 이연 근거 명시.
- **플레이스홀더**: 없음. Task 1의 좌표는 라인 앵커+코드 인용(구현 시 실측 확인 지시 포함).
- **타입 일관성**: `_multi_wireless_section(structured) -> List[str]`이 정의(Task 3 Step 2)·테스트(Step 1)·조립부 삽입에서 일관. per_second 반환 스키마 5키 불변.
- **불변 검증 경로**: ③ 정상 입력 — 기존 test_eapol/test_pipeline의 per_second 소비 테스트가 회귀 가드. ④ merge 부재 — 명시 테스트. ① — 컨트롤러 브라우저 왕복 검증.
