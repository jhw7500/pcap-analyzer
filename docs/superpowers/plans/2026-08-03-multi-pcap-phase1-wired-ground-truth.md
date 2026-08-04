# 멀티 pcap 1단계 — 유선 Ground Truth 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 대시보드가 무선 pcap 1개 + 유선 pcap 1개(포트 미러)를 한 분석으로 받아, 유선 기준 ping 확정 손실을 ground truth로 표시하고 손실 구간을 무선 이벤트와 자동 대조한다.

**Architecture:** 검증된 `analyzer/core/exping.py`의 ICMP 추출·매칭을 감싸는 신규 순수 모듈 `analyzer/core/wired_ping.py`가 ground truth dict를 만들고, `run_analysis()`가 `wired_path` 키워드 인자로 받아 `structured["ping"]["ground_truth"]`와 `structured["sources"]`에 부착한다. 진단은 streak별 대조 이슈를 기존 evidence 게이트(`_add_net_issue`)로 추가한다. 업로드 라우트·폼·CLI는 optional 입력만 추가하며 기존 단일 pcap 흐름은 그대로다.

**Tech Stack:** Python 3.10 / FastAPI / tshark 서브프로세스 / pytest / Jinja2 + vanilla JS (Plotly)

**스펙:** `docs/superpowers/specs/2026-08-03-multi-pcap-analysis-design.md` (1단계 범위만. dedup·Frame.source·다중 무선은 2단계)

## Global Constraints

- Python 3.10 문법 (`pyproject.toml` ruff `target-version = "py310"`) — `float | None` 스타일 허용, 커밋 전 `ruff check .` 클린.
- 새 외부 의존성 추가 금지 — 표준 라이브러리 + 기존 requirements만.
- 주석·에러 메시지·테스트 docstring은 기존 컨벤션대로 한국어.
- 결과 JSON의 **신규 키는 전부 optional** — 구버전 결과(`data/analyses/*.json`) 로드·리포트·프론트가 깨지면 안 된다 (`.get` 소비 확인 완료: `analyzer/web/report.py`, `analyzer/web/delay_analysis.py`는 알려진 키만 읽음).
- 기본 테스트 스위트는 tshark 실물 없이 통과해야 한다 (`addopts = "-m 'not e2e and not slow and not tshark'"`). tshark 의존 테스트는 `pytestmark = [pytest.mark.slow, pytest.mark.tshark]` + 런타임 skip 이중 방어(`tests/test_pipeline_smoke.py:16-28` 패턴).
- 커밋: `type(scope): 한국어 요약` (commitlint `type-enum`: feat/fix/chore/refactor/docs/test/build/ci/perf/style, header ≤100자). 본문 끝에 테스트 통과 개수 기록. 트레일러 2줄:
  ```
  Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01WqZ8df5huZ3tRzWPwhbW5q
  ```
- 작업 브랜치: `feat/wired-ground-truth` (현재 `docs/multi-pcap-analysis-spec`에서 분기 — 스펙 커밋 `f23632c`를 포함해야 한다).
- 커버리지 게이트 `fail_under = 75` — 새 모듈은 반드시 단위 테스트 동반.

---

### Task 1: `analyzer/core/wired_ping.py` — 유선 ground truth 빌더

**Files:**
- Create: `analyzer/core/wired_ping.py`
- Test: `tests/test_wired_ping.py`

**Interfaces:**
- Consumes: `analyzer.core.exping.extract_exchanges(pcap, tshark=, timeout=) -> tuple[list[Exchange], str]` (Exchange: `time: float, target: str, rtt: float | None`, property `answered`; 예외: `FileNotFoundError`(tshark 없음), `ValueError`(tshark 실패/무선 캡처/ICMP 없음), `TimeoutError`), `exping.drop_trailing_unanswered(exchanges) -> tuple[list[Exchange], int]`, `exping.DEFAULT_REPLY_TIMEOUT`(=1.0), `analyzer.core.ping_matching.find_time_streaks(epochs, gap_sec=2.0, min_len=2) -> List[Tuple[int, int]]`
- Produces: `build_ground_truth(pcap_path: str, tshark_path: str = "tshark", reply_timeout: float = 1.0) -> Dict[str, Any]` — 성공 시 키 `total, ok, ng, loss_pct, sender, targets, streaks, ng_epochs, trailing_dropped, warnings`; 실패 시 `{"error": str, "warnings": [...]}`. Task 2·3·6이 이 스키마를 그대로 소비한다.

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_wired_ping.py` 생성. `tests/test_exping.py:292-296`의 가짜 tshark 패턴을 그대로 쓴다 (TSV 7필드: epoch, ip.src, ip.dst, icmp.type, icmp.ident, icmp.seq, wlan.fc.type — 유선은 마지막 필드가 빈 칸):

```python
"""wired_ping.build_ground_truth — 유선 pcap ping ground truth 빌더."""
import pytest

from analyzer.core import wired_ping


def _fake_tshark(tmp_path, body: str) -> str:
    """TSV를 뱉는 가짜 tshark 실행파일 (tests/test_exping.py 패턴)."""
    fake = tmp_path / "fake-tshark"
    fake.write_text("#!/bin/sh\n" + body)
    fake.chmod(0o755)
    return str(fake)


def test_counts_ok_ng_and_loss_pct(tmp_path):
    """요청 3건 중 가운데 1건 무응답 → total 3 / ok 2 / ng 1 / 33.33%."""
    body = (
        "printf '100.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        "printf '100.002\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
        "printf '101.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t2\\t\\n'\n"  # 무응답
        "printf '102.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t3\\t\\n'\n"
        "printf '102.003\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t3\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=_fake_tshark(tmp_path, body))
    assert "error" not in gt
    assert gt["total"] == 3 and gt["ok"] == 2 and gt["ng"] == 1
    assert gt["loss_pct"] == pytest.approx(33.33)
    assert gt["sender"] == "10.0.0.1"
    assert gt["targets"] == {"10.0.0.2": {"total": 3, "ng": 1}}
    assert gt["ng_epochs"] == [101.0]
    assert gt["trailing_dropped"] == 0


def test_streaks_grouped_per_target(tmp_path):
    """NG 3연속(간격 1초) → streak 1개 count 3. 단독 NG는 streak 아님(min_len 2)."""
    body = (
        # 성공 1건으로 시작 (꼬리 제거 회피용 앵커는 마지막에 둔다)
        "printf '100.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        "printf '100.002\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
        # NG 3연속
        "printf '101.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t2\\t\\n'\n"
        "printf '102.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t3\\t\\n'\n"
        "printf '103.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t4\\t\\n'\n"
        # 5초 뒤 단독 NG 1건
        "printf '108.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t5\\t\\n'\n"
        # 마지막은 성공 — 꼬리 무응답 제거가 NG를 지우지 않게
        "printf '109.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t6\\t\\n'\n"
        "printf '109.001\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t6\\t\\n'\n"
    )
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=_fake_tshark(tmp_path, body))
    assert gt["ng"] == 4
    assert len(gt["streaks"]) == 1
    st = gt["streaks"][0]
    assert st["target"] == "10.0.0.2"
    assert st["start_epoch"] == pytest.approx(101.0)
    assert st["end_epoch"] == pytest.approx(103.0)
    assert st["count"] == 3
    assert st["duration_sec"] == pytest.approx(2.0)


def test_trailing_unanswered_dropped_with_warning(tmp_path):
    """캡처가 응답보다 먼저 끊긴 꼬리 무응답은 NG로 세지 않는다 (EXPING 규칙)."""
    body = (
        "printf '100.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t\\n'\n"
        "printf '100.002\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t\\n'\n"
        "printf '101.0\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t2\\t\\n'\n"  # 꼬리 무응답
    )
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=_fake_tshark(tmp_path, body))
    assert gt["total"] == 1 and gt["ng"] == 0
    assert gt["trailing_dropped"] == 1
    assert any("꼬리" in w for w in gt["warnings"])


def test_wireless_capture_returns_error(tmp_path):
    """무선(802.11) 캡처는 exping 가드가 거부 → error dict로 변환."""
    body = (
        "printf '1.5\\t10.0.0.1\\t10.0.0.2\\t8\\t7\\t1\\t2\\n'\n"
        "printf '1.502\\t10.0.0.2\\t10.0.0.1\\t0\\t7\\t1\\t2\\n'\n"
    )
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=_fake_tshark(tmp_path, body))
    assert "무선" in gt["error"]


def test_missing_tshark_returns_error():
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path="/nonexistent/tshark-xyz")
    assert "tshark" in gt["error"]


def test_no_icmp_returns_error(tmp_path):
    """ICMP echo request가 없으면 pick_sender ValueError → error dict."""
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=_fake_tshark(tmp_path, ":\n"))
    assert "error" in gt
```

- [ ] **Step 2: 실패 확인**

Run: `python3 -m pytest tests/test_wired_ping.py -v`
Expected: 전부 FAIL — `ModuleNotFoundError: No module named 'analyzer.core.wired_ping'`

- [ ] **Step 3: 최소 구현**

`analyzer/core/wired_ping.py` 생성:

```python
"""유선(포트 미러) pcap에서 ping ground truth를 만든다.

검증된 exping의 ICMP 추출·매칭 규칙(응답 인정 상한 1초, 꼬리 무응답 제거)을
그대로 재사용한다 — 대시보드용으로 EXPING xlsx 재현 규칙(RTT 정수 보정,
전각 문자열)은 쓰지 않고 Exchange 수준에서 소비한다. docs/EXPING.md 참조.
"""
from typing import Any, Dict, List

from . import exping
from .ping_matching import find_time_streaks

#: streaks 항목 수 상한 — 비정상 캡처(수천 구간)로 결과 JSON이 비대해지는 것 방지
MAX_STREAKS = 100
#: ng_epochs 상한 — 타임라인 마커용 샘플
MAX_NG_EPOCHS = 1000


def build_ground_truth(
    pcap_path: str,
    tshark_path: str = "tshark",
    reply_timeout: float = exping.DEFAULT_REPLY_TIMEOUT,
) -> Dict[str, Any]:
    """유선 pcap → ping ground truth dict. 실패 시 {"error": str, "warnings": [...]}.

    취소 이벤트는 지원하지 않는다 — exping.extract_exchanges에 취소 훅이 없고
    child_timeout(기본 3600초) 상한만 있다. ICMP 디스플레이 필터라 대체로 빠르다.
    """
    warnings: List[str] = []
    try:
        exchanges, sender = exping.extract_exchanges(
            pcap_path, tshark=tshark_path, timeout=reply_timeout
        )
    except FileNotFoundError:
        return {"error": f"tshark 를 찾을 수 없다: {tshark_path}", "warnings": warnings}
    except (ValueError, TimeoutError) as exc:
        return {"error": str(exc), "warnings": warnings}

    exchanges, dropped = exping.drop_trailing_unanswered(exchanges)
    if dropped:
        warnings.append(
            f"꼬리 무응답 요청 {dropped}건 제외 — 캡처가 응답보다 먼저 끊긴 구간"
        )
    if not exchanges:
        return {"error": f"{sender} 가 보낸 echo request 가 없다", "warnings": warnings}

    ng = [x for x in exchanges if not x.answered]
    targets: Dict[str, Dict[str, int]] = {}
    for x in exchanges:
        t = targets.setdefault(x.target, {"total": 0, "ng": 0})
        t["total"] += 1
        t["ng"] += 0 if x.answered else 1

    streaks: List[Dict[str, Any]] = []
    for target in sorted(targets):
        epochs = sorted(x.time for x in ng if x.target == target)
        for si, ei in find_time_streaks(epochs):
            streaks.append({
                "target": target,
                "start_epoch": epochs[si],
                "end_epoch": epochs[ei],
                "count": ei - si + 1,
                "duration_sec": round(epochs[ei] - epochs[si], 3),
            })
    streaks.sort(key=lambda s: s["start_epoch"])
    if len(streaks) > MAX_STREAKS:
        warnings.append(f"연속 손실 구간 {len(streaks)}곳 중 {MAX_STREAKS}곳만 기록")
        streaks = streaks[:MAX_STREAKS]

    total = len(exchanges)
    return {
        "total": total,
        "ok": total - len(ng),
        "ng": len(ng),
        "loss_pct": round(len(ng) * 100 / total, 2) if total else 0.0,
        "sender": sender,
        "targets": targets,
        "streaks": streaks,
        "ng_epochs": [x.time for x in ng][:MAX_NG_EPOCHS],
        "trailing_dropped": dropped,
        "warnings": warnings,
    }
```

- [ ] **Step 4: 통과 확인**

Run: `python3 -m pytest tests/test_wired_ping.py -v`
Expected: 6 passed

- [ ] **Step 5: 전체 회귀 + lint 후 커밋**

Run: `python3 -m pytest tests/ -q && ruff check .`
Expected: 기존 755개 + 신규 6개 통과, ruff 클린

```bash
git add analyzer/core/wired_ping.py tests/test_wired_ping.py
git commit -m "feat(wired): 유선 pcap ping ground truth 빌더 — exping 매칭 규칙 재사용"
```

---

### Task 2: `run_analysis` 통합 — `wired_path` 인자·sources·ground_truth 부착

**Files:**
- Modify: `analyzer/pipeline.py` (시그니처 `:54-64`, ping 블록 뒤 `:159-162`)
- Test: `tests/test_pipeline_wired.py`

**Interfaces:**
- Consumes: Task 1의 `build_ground_truth(pcap_path, tshark_path=, reply_timeout=)`
- Produces: `run_analysis(pcap_path, ..., wired_path: str = "")`. 결과에 `structured["sources"]`(항상, 항목 `{name, role: "wireless"|"wired", frame_count: int|None, warnings: [str]}`)와, 유선 성공 시 `structured["ping"]["ground_truth"]`(Task 1 스키마) 추가. 실패 시 ground_truth 없음 + 해당 source의 warnings에 에러 문자열. Task 3·4·6이 이 계약을 소비한다.

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_pipeline_wired.py` 생성. `extract_frames`·`build_ground_truth`·tshark 감지를 전부 monkeypatch — 기본 스위트에서 tshark 없이 돈다:

```python
"""run_analysis의 wired_path 통합 — sources·ground_truth 부착."""
import config
import analyzer.pipeline as pipeline
from tests.conftest import make_frame, STA1, AP1

GT_OK = {
    "total": 100, "ok": 97, "ng": 3, "loss_pct": 3.0, "sender": "10.0.0.1",
    "targets": {"10.0.0.2": {"total": 100, "ng": 3}},
    "streaks": [{"target": "10.0.0.2", "start_epoch": 1004.5,
                 "end_epoch": 1006.5, "count": 3, "duration_sec": 2.0}],
    "ng_epochs": [1004.5, 1005.5, 1006.5], "trailing_dropped": 0, "warnings": [],
}


def _frames():
    # ICMP 쌍 포함 — ping 통계가 비지 않게. Auth(roaming)·retry 프레임은 Task 3 대조용.
    return [
        make_frame(number=1, epoch=1000.0, subtype="40", ip_src="10.0.0.1",
                   ip_dst="10.0.0.2", icmp_type="8", icmp_seq="1", seq="100"),
        make_frame(number=2, epoch=1000.005, ta=AP1, ra=STA1, subtype="40",
                   ip_src="10.0.0.2", ip_dst="10.0.0.1", icmp_type="0",
                   icmp_seq="1", seq="200"),
        make_frame(number=3, epoch=1005.0, subtype="11"),               # Auth
        make_frame(number=4, epoch=1005.5, subtype="40", retry=True),   # 재전송
        make_frame(number=5, epoch=1009.0, subtype="40"),
    ]


def _patch_common(monkeypatch, gt):
    monkeypatch.setattr(pipeline, "extract_frames", lambda *a, **kw: _frames())
    monkeypatch.setattr(pipeline, "detect_tshark_version",
                        lambda *a, **kw: {"version": "test", "path": "tshark"})
    monkeypatch.setattr(config, "detect_tshark", lambda: "tshark")
    monkeypatch.setattr(pipeline, "build_ground_truth", lambda *a, **kw: gt)


def test_wired_path_attaches_ground_truth_and_sources(monkeypatch):
    _patch_common(monkeypatch, dict(GT_OK))
    result = pipeline.run_analysis("wireless.pcapng", wired_path="wired.pcapng")
    ping = result["structured"]["ping"]
    assert ping["ground_truth"]["ng"] == 3
    sources = result["structured"]["sources"]
    assert [s["role"] for s in sources] == ["wireless", "wired"]
    assert sources[0]["frame_count"] == 5


def test_wired_error_becomes_source_warning(monkeypatch):
    _patch_common(monkeypatch, {"error": "무선(802.11) 캡처다 — 유선 캡처를 넣어라: x", "warnings": []})
    result = pipeline.run_analysis("wireless.pcapng", wired_path="wired.pcapng")
    assert "ground_truth" not in result["structured"]["ping"]
    wired_src = result["structured"]["sources"][1]
    assert any("무선" in w for w in wired_src["warnings"])


def test_no_wired_path_keeps_existing_shape(monkeypatch):
    _patch_common(monkeypatch, dict(GT_OK))
    result = pipeline.run_analysis("wireless.pcapng")
    assert "ground_truth" not in result["structured"]["ping"]
    sources = result["structured"]["sources"]
    assert len(sources) == 1 and sources[0]["role"] == "wireless"
```

- [ ] **Step 2: 실패 확인**

Run: `python3 -m pytest tests/test_pipeline_wired.py -v`
Expected: FAIL — `AttributeError: ... has no attribute 'build_ground_truth'` 또는 `TypeError: run_analysis() got an unexpected keyword argument 'wired_path'`

- [ ] **Step 3: 구현**

`analyzer/pipeline.py` 수정 3곳:

(a) import 추가 (`:8` 부근):
```python
from .core.wired_ping import build_ground_truth
```

(b) 시그니처에 인자 추가 (`:54-64`, `ip_filter: str = ""` 뒤):
```python
    ip_filter: str = "",
    wired_path: str = "",
```

(c) `structured["ping"] = _structured_ping(frames, roles)` 블록(`:159-162`) 바로 뒤에 삽입:
```python
    # 입력 파일 메타 — 유선 ground truth가 있으면 ping에 부착 (스펙 §4·§6)
    sources = [{
        "name": Path(pcap_path).name, "role": "wireless",
        "frame_count": len(frames), "warnings": [],
    }]
    if wired_path:
        _progress("유선 ground truth 분석 중...", 93)
        gt = build_ground_truth(wired_path, tshark_path=_tshark_path or "tshark")
        wired_src = {
            "name": Path(wired_path).name, "role": "wired",
            "frame_count": None, "warnings": list(gt.get("warnings", [])),
        }
        if "error" in gt:
            wired_src["warnings"].append(gt["error"])
        else:
            structured["ping"]["ground_truth"] = gt
        sources.append(wired_src)
    structured["sources"] = sources
    if _cancelled():
        return {"cancelled": True}
```

- [ ] **Step 4: 통과 확인**

Run: `python3 -m pytest tests/test_pipeline_wired.py tests/test_pipeline.py -q`
Expected: 신규 3개 포함 전부 통과 (기존 pipeline 테스트 무손상 = 하위 호환 회귀 확인)

- [ ] **Step 5: 커밋**

```bash
git add analyzer/pipeline.py tests/test_pipeline_wired.py
git commit -m "feat(wired): run_analysis에 wired_path 통합 — sources·ping.ground_truth 부착"
```

---

### Task 3: 진단 대조 — 유선 손실 streak ↔ 무선 이벤트

**Files:**
- Modify: `analyzer/web/structured.py` (`_structured_diagnosis` 내부, 네트워크 이슈 헬퍼 `_add_net_issue` 정의부 `:948-955` 부근과 severity 정렬 `:1063-1064` 사이)
- Test: `tests/test_diagnosis_wired.py`

**Interfaces:**
- Consumes: Task 2가 넣은 `structured["ping"]["ground_truth"]["streaks"]`, `Frame.is_roaming_related`/`subtype`/`retry`/`epoch`/`number` (`analyzer/core/models.py`), 기존 `_add_net_issue(issue, refs, window, signal_type=None)` (evidence 게이트 — refs 비면 드롭)
- Produces: `_ground_truth_issue_candidates(gt: Dict, frames: List[Frame]) -> List[Dict]` (모듈 레벨 함수, 항목 `{"issue": {...}, "refs": [int], "window": {...}, "signal_type": "wired_loss"}`), diagnosis `issues[]`에 `signal_type == "wired_loss"` 항목 추가

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_diagnosis_wired.py` 생성:

```python
"""유선 확정 손실 구간 ↔ 무선 이벤트 대조 이슈."""
from analyzer.web.structured import _ground_truth_issue_candidates
from tests.conftest import make_frame

GT = {"streaks": [{"target": "10.0.0.2", "start_epoch": 1005.0,
                   "end_epoch": 1006.0, "count": 3, "duration_sec": 1.0}]}


def test_candidate_with_roaming_and_retry_evidence():
    frames = [
        make_frame(number=1, epoch=1004.0, subtype="11"),              # Auth — 창(±2s) 안
        make_frame(number=2, epoch=1005.5, subtype="40", retry=True),  # 재전송 — 창 안
        make_frame(number=3, epoch=1030.0, subtype="40"),              # 창 밖
    ]
    cands = _ground_truth_issue_candidates(GT, frames)
    assert len(cands) == 1
    c = cands[0]
    assert c["refs"] == [1, 2]
    assert c["window"] == {"start_epoch": 1003.0, "end_epoch": 1008.0}
    assert c["signal_type"] == "wired_loss"
    assert c["issue"]["severity"] == "high"
    assert "로밍/해제 1건" in c["issue"]["msg"] and "재전송 1건" in c["issue"]["msg"]


def test_candidate_without_anomaly_uses_normal_traffic_as_refs():
    """이상 징후가 없으면 구간 내 일반 프레임을 근거로 '무선 외 원인 가능성' 이슈."""
    frames = [make_frame(number=7, epoch=1005.2, subtype="40")]
    cands = _ground_truth_issue_candidates(GT, frames)
    assert len(cands) == 1
    assert cands[0]["refs"] == [7]
    assert "이상 징후 없음" in cands[0]["issue"]["msg"]


def test_no_frames_in_window_drops_candidate():
    """구간에 무선 프레임이 아예 없으면(캡처 구멍) 근거를 못 대므로 후보 없음."""
    frames = [make_frame(number=9, epoch=2000.0)]
    assert _ground_truth_issue_candidates(GT, frames) == []


def test_empty_ground_truth_no_candidates():
    assert _ground_truth_issue_candidates({}, [make_frame()]) == []
    assert _ground_truth_issue_candidates({"streaks": []}, []) == []
```

- [ ] **Step 2: 실패 확인**

Run: `python3 -m pytest tests/test_diagnosis_wired.py -v`
Expected: FAIL — ImportError (`_ground_truth_issue_candidates` 없음)

- [ ] **Step 3: 구현**

`analyzer/web/structured.py`에 모듈 레벨 함수 추가 (`_structured_diagnosis` 정의 위):

```python
#: 유선 손실 구간 대조 창 (streak 앞뒤 초) — 로밍·재전송이 손실보다 약간 앞설 수 있다
_WIRED_LOSS_WINDOW_SEC = 2.0
#: 대조하는 streak 수 상한 — 이슈 목록 폭주 방지
_WIRED_LOSS_MAX_STREAKS = 20


def _ground_truth_issue_candidates(gt, frames):
    """유선 확정 손실 streak별 무선 대조 이슈 후보. 근거 프레임이 없으면 후보 제외.

    frame_refs는 무선 pcap의 frame.number다 — 유선 프레임 번호를 섞으면 프레임
    테이블 조회가 깨진다. 캡처 구멍(창 안에 무선 프레임 0건)은 근거를 댈 수
    없어 이슈를 만들지 않는다(근거 없는 결론 금지) — 알려진 한계.
    """
    out = []
    for streak in (gt.get("streaks") or [])[:_WIRED_LOSS_MAX_STREAKS]:
        start, end = streak.get("start_epoch"), streak.get("end_epoch")
        if not isinstance(start, (int, float)) or not isinstance(end, (int, float)):
            continue
        win = {"start_epoch": start - _WIRED_LOSS_WINDOW_SEC,
               "end_epoch": end + _WIRED_LOSS_WINDOW_SEC}
        in_win = [f for f in frames if win["start_epoch"] <= f.epoch <= win["end_epoch"]]
        if not in_win:
            continue
        roam = [f for f in in_win if f.is_roaming_related or f.subtype in ("10", "12")]
        retry = [f for f in in_win if f.retry]
        anomaly = sorted({f.number for f in roam} | {f.number for f in retry})
        head = (f"유선 확정 손실 {streak.get('count')}건 "
                f"({streak.get('target', '?')}, {streak.get('duration_sec')}초)")
        if anomaly:
            issue = {
                "severity": "high", "category": "유선 손실",
                "msg": f"{head} — 구간 내 무선: 로밍/해제 {len(roam)}건, 재전송 {len(retry)}건",
                "action": "통합 타임라인에서 해당 구간의 로밍·재전송·RSSI를 확인하세요.",
            }
            refs = anomaly
        else:
            issue = {
                "severity": "medium", "category": "유선 손실",
                "msg": f"{head} — 구간 내 무선 이상 징후 없음 (트래픽 {len(in_win)}건 정상)",
                "action": "무선 구간 외 원인(유선/AP 상위단)을 의심하세요.",
            }
            refs = [f.number for f in in_win]
        out.append({"issue": issue, "refs": refs, "window": win,
                    "signal_type": "wired_loss"})
    return out
```

`_structured_diagnosis` 안, 네트워크 이슈 추가가 끝난 지점(severity 정렬 `severity_order` 직전)에 삽입:

```python
    # 유선 ground truth 손실 구간 ↔ 무선 이벤트 대조 (스펙 §4)
    for cand in _ground_truth_issue_candidates(ping.get("ground_truth") or {}, frames or []):
        _add_net_issue(cand["issue"], cand["refs"], cand["window"],
                       signal_type=cand["signal_type"])
```

(`ping` 변수는 `_structured_diagnosis` 상단에서 이미 `structured["ping"]`으로 바인딩돼 있다 — `ping_available` 계산부 참조. `_add_net_issue`가 이미 severity 정렬 앞에서 정의돼 있으므로 시그니처 변경 없음.)

- [ ] **Step 4: 통과 확인 + 파이프라인 관통 확인**

Run: `python3 -m pytest tests/test_diagnosis_wired.py -v`
Expected: 4 passed

`tests/test_pipeline_wired.py`에 관통 assert 1개 추가 (GT_OK의 streak 1004.5~1006.5 창 안에 Auth(1005.0)·retry(1005.5)가 있다):

```python
def test_wired_loss_issue_reaches_diagnosis(monkeypatch):
    _patch_common(monkeypatch, dict(GT_OK))
    result = pipeline.run_analysis("wireless.pcapng", wired_path="wired.pcapng")
    issues = result["structured"]["diagnosis"]["issues"]
    wired = [i for i in issues if i.get("signal_type") == "wired_loss"]
    assert len(wired) == 1
    assert wired[0]["frame_refs"] == [3, 4]
```

Run: `python3 -m pytest tests/test_pipeline_wired.py tests/test_diagnosis_wired.py -v`
Expected: 전부 통과

- [ ] **Step 5: 커밋**

```bash
git add analyzer/web/structured.py tests/test_diagnosis_wired.py tests/test_pipeline_wired.py
git commit -m "feat(wired): 진단에 유선 손실 구간 대조 이슈 — evidence 게이트 유지"
```

---

### Task 4: 업로드 라우트 — `wired_file` 수용

**Files:**
- Modify: `routes/upload.py` (`upload_pcap` `:121-237`, 저장 루프 `:136-171`을 헬퍼로 추출)
- Test: `tests/test_routes_upload_wired.py`

**Interfaces:**
- Consumes: Task 2의 `run_analysis(..., wired_path=)`
- Produces: `POST /api/upload` 폼 필드 `wired_file`(optional). 성공 응답·저장 JSON에 `pcap_names: [무선명, 유선명]`(유선 있을 때만), `structured["sources"][*]["name"]`을 원본 업로드 파일명으로 치환. 내부 헬퍼 `async _save_pcap_upload(file) -> tuple[str | None, JSONResponse | None]`.

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_routes_upload_wired.py` 생성 (기존 `tests/test_routes_upload.py`의 `patch("routes.upload.run_analysis")` 방식):

```python
"""POST /api/upload의 wired_file 처리."""
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import app

client = TestClient(app)

PCAP_MAGIC = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20  # little-endian pcap


def _ok_result(pcap_path, **kwargs):
    return {
        "id": "t1", "pcap_name": "x", "pcap_size": 1, "frame_count": 1,
        "analyzed_at": "now", "tshark_version": "t", "tshark_path": "t",
        "structured": {"sources": [
            {"name": "tmpA", "role": "wireless", "frame_count": 1, "warnings": []},
            {"name": "tmpB", "role": "wired", "frame_count": None, "warnings": []},
        ]},
        "text_sections": [],
    }


@patch("routes.upload.config.detect_tshark", return_value="tshark")
@patch("routes.upload.run_analysis")
def test_wired_file_passed_to_pipeline(mock_run, _tshark, tmp_path, monkeypatch):
    import config
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    mock_run.side_effect = _ok_result
    resp = client.post("/api/upload", files={
        "file": ("w.pcapng", PCAP_MAGIC, "application/octet-stream"),
        "wired_file": ("cable.pcapng", PCAP_MAGIC, "application/octet-stream"),
    })
    assert resp.status_code == 200
    assert mock_run.call_args.kwargs["wired_path"]  # 임시 경로가 전달됨
    saved = (tmp_path / "t1.json").read_text(encoding="utf-8")
    assert "cable.pcapng" in saved and '"pcap_names"' in saved


@patch("routes.upload.config.detect_tshark", return_value="tshark")
@patch("routes.upload.run_analysis")
def test_without_wired_file_wired_path_empty(mock_run, _tshark, tmp_path, monkeypatch):
    import config
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    mock_run.side_effect = _ok_result
    resp = client.post("/api/upload", files={
        "file": ("w.pcapng", PCAP_MAGIC, "application/octet-stream"),
    })
    assert resp.status_code == 200
    assert mock_run.call_args.kwargs["wired_path"] == ""


@patch("routes.upload.config.detect_tshark", return_value="tshark")
def test_wired_file_invalid_magic_rejected(_tshark):
    resp = client.post("/api/upload", files={
        "file": ("w.pcapng", PCAP_MAGIC, "application/octet-stream"),
        "wired_file": ("bad.pcapng", b"NOTPCAP" + b"\x00" * 20, "application/octet-stream"),
    })
    assert resp.status_code == 400
    assert resp.json()["code"] == "INVALID_MAGIC"
```

- [ ] **Step 2: 실패 확인**

Run: `python3 -m pytest tests/test_routes_upload_wired.py -v`
Expected: FAIL — `wired_path` kwarg 미전달(KeyError) / wired_file 무시

- [ ] **Step 3: 구현**

`routes/upload.py` 수정:

(a) 기존 저장 루프(`:136-171`)를 헬퍼로 추출 (동작 동일 — 확장자→스트리밍 저장→magic→크기→빈 파일 검사):

```python
async def _save_pcap_upload(file: UploadFile):
    """업로드 파일 검증·임시 저장. 반환 (tmp_path, error_response) — 하나만 non-None."""
    name = file.filename or "unknown.pcap"
    if not name.endswith((".pcap", ".pcapng", ".cap")):
        return None, JSONResponse(error_payload(ErrorCode.INVALID_EXT), status_code=400)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=Path(name).suffix)
    total = 0
    first_chunk = True
    try:
        while True:
            chunk = await file.read(_UPLOAD_CHUNK_SIZE)
            if not chunk:
                break
            if first_chunk:
                if not has_valid_pcap_magic(chunk):
                    tmp.close()
                    Path(tmp.name).unlink(missing_ok=True)
                    return None, JSONResponse(
                        error_payload(ErrorCode.INVALID_MAGIC), status_code=400)
                first_chunk = False
            total += len(chunk)
            if total > config.max_upload_size():
                tmp.close()
                Path(tmp.name).unlink(missing_ok=True)
                limit_mb = config.max_upload_size() // (1024 * 1024)
                return None, JSONResponse(
                    error_payload(ErrorCode.FILE_TOO_LARGE, f"(상한 {limit_mb}MB)"),
                    status_code=413)
            tmp.write(chunk)
    except Exception:
        tmp.close()
        Path(tmp.name).unlink(missing_ok=True)
        raise
    tmp.close()
    if first_chunk:
        Path(tmp.name).unlink(missing_ok=True)
        return None, JSONResponse(error_payload(ErrorCode.EMPTY_FILE), status_code=400)
    return tmp.name, None
```

(b) `upload_pcap` 시그니처에 `wired_file: UploadFile | None = File(None)` 추가, 본문을 헬퍼 사용으로 교체:

```python
    tmp_name, err = await _save_pcap_upload(file)
    if err is not None:
        return err

    wired_tmp = ""
    wired_name = ""
    # 브라우저는 미선택 file input도 빈 filename 파트로 보낸다 — filename으로 판별
    if wired_file is not None and (wired_file.filename or ""):
        wired_tmp_name, werr = await _save_pcap_upload(wired_file)
        if werr is not None:
            Path(tmp_name).unlink(missing_ok=True)
            return werr
        wired_tmp = wired_tmp_name
        wired_name = wired_file.filename
```

(c) `_jobs` 등록의 `"tmp": tmp.name`을 `"tmp": tmp_name`으로, `_run()`에 `wired_path=wired_tmp` 추가, `finally`에서 두 임시 파일 모두 unlink:

```python
    def _run():
        return run_analysis(
            tmp_name,
            ssid=ssid,
            passphrase=passphrase,
            time_start=time_start,
            time_end=time_end,
            mac_filter=mac_filter,
            ip_filter=ip_filter,
            wired_path=wired_tmp,
            cancel_event=cancel_event,
            progress_cb=progress_cb,
        )
    ...
    finally:
        for p in (tmp_name, wired_tmp):
            if p:
                try:
                    Path(p).unlink(missing_ok=True)
                except OSError:
                    pass
        _set_progress(job_id, "완료", 100, active=False)
```

(d) 성공 경로에서 원본 파일명 반영 (`result["pcap_name"] = name` 뒤):

```python
    # sources의 임시 파일명을 원본 업로드 파일명으로 치환
    for src in result.get("structured", {}).get("sources") or []:
        if src.get("role") == "wireless":
            src["name"] = name
        elif src.get("role") == "wired" and wired_name:
            src["name"] = wired_name
    if wired_name:
        result["pcap_names"] = [name, wired_name]
```

- [ ] **Step 4: 통과 확인**

Run: `python3 -m pytest tests/test_routes_upload_wired.py tests/test_routes_upload.py -v`
Expected: 신규 3개 + 기존 라우트 테스트 전부 통과 (헬퍼 추출이 기존 단일 업로드를 깨지 않음)

- [ ] **Step 5: 커밋**

```bash
git add routes/upload.py tests/test_routes_upload_wired.py
git commit -m "feat(upload): wired_file 폼 필드 — 검증 헬퍼 추출·임시파일 수명 관리"
```

---

### Task 5: CLI `--wired` 옵션

**Files:**
- Modify: `scripts/analyze-cli.py` (38줄 전체 구조 유지, sys.argv 파싱만 확장)
- Test: `tests/test_analyze_cli_wired.py`

**Interfaces:**
- Consumes: Task 2의 `run_analysis(..., wired_path=)`
- Produces: `analyze-cli.py <pcap> <ssid> <passphrase> [out.json] [--wired wired.pcapng]`

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_analyze_cli_wired.py` 생성 (스크립트는 subprocess로 검증 — 기존 usage 계약 보존 확인 포함):

```python
"""analyze-cli.py --wired 인자 계약."""
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "analyze-cli.py"


def _run(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args], capture_output=True, text=True)


def test_usage_mentions_wired():
    p = _run()
    assert p.returncode == 2
    assert "--wired" in p.stderr


def test_wired_without_value_exits_2():
    p = _run("a.pcap", "ssid", "pw", "--wired")
    assert p.returncode == 2
    assert "wired" in p.stderr


def test_positional_contract_unchanged():
    """인자 2개면 여전히 usage 에러 (기존 계약)."""
    p = _run("a.pcap", "ssid")
    assert p.returncode == 2
```

- [ ] **Step 2: 실패 확인**

Run: `python3 -m pytest tests/test_analyze_cli_wired.py -v`
Expected: `test_usage_mentions_wired`·`test_wired_without_value_exits_2` FAIL (usage에 --wired 없음 / --wired가 위치 인자로 오파싱)

- [ ] **Step 3: 구현**

`scripts/analyze-cli.py`의 `main()` 앞부분을 교체:

```python
def main():
    argv = sys.argv[1:]
    wired = ""
    if "--wired" in argv:
        i = argv.index("--wired")
        if i + 1 >= len(argv):
            print("ERROR: --wired 뒤에 유선 pcap 경로가 필요하다", file=sys.stderr)
            sys.exit(2)
        wired = argv[i + 1]
        del argv[i:i + 2]
    if len(argv) < 3:
        print(
            "Usage: analyze-cli.py <pcap> <ssid> <passphrase> [out.json] [--wired wired.pcapng]",
            file=sys.stderr,
        )
        sys.exit(2)
    pcap, ssid, pw = argv[0], argv[1], argv[2]
    out = argv[3] if len(argv) >= 4 else None
```

그리고 호출부에 전달:

```python
    result = run_analysis(pcap, ssid=ssid, passphrase=pw, progress_cb=_p, wired_path=wired)
```

- [ ] **Step 4: 통과 확인**

Run: `python3 -m pytest tests/test_analyze_cli_wired.py -v`
Expected: 3 passed

- [ ] **Step 5: 커밋**

```bash
git add scripts/analyze-cli.py tests/test_analyze_cli_wired.py
git commit -m "feat(cli): analyze-cli에 --wired 옵션 — 유선 ground truth 경로 전달"
```

---

### Task 6: 프론트 — 업로드 폼·GT 카드·경고 배너

**Files:**
- Modify: `templates/index.html` (옵션 필드 영역 `:33-53`), `static/js/upload.js` (submit 핸들러 `:120-167`), `templates/analysis.html` (`{% block content %}` 직후 `:4`, ping 탭 `#ping-kpi` 앞 `:225`), `static/js/charts.js` (ping 탭 진입부 `:762-767` 뒤)
- Test: `tests/test_routes_wired_banner.py`

**Interfaces:**
- Consumes: Task 2·4가 저장한 `structured["sources"][*].warnings`, `structured["ping"]["ground_truth"]` (Task 1 스키마)
- Produces: 업로드 폼 `wired_file` input(`new FormData(form)`이 자동 포함), 분석 페이지 상단 경고 배너(Jinja), ping 탭 GT 카드(`#ping-ground-truth`)

- [ ] **Step 1: 실패하는 테스트 작성 (배너 — 서버 렌더라 pytest로 검증 가능)**

`tests/test_routes_wired_banner.py` 생성:

```python
"""분석 페이지 상단 입력 파일 경고 배너 (Jinja 서버 렌더)."""
import json

from fastapi.testclient import TestClient

import config
from app import app

client = TestClient(app)


def _store(tmp_path, monkeypatch, sources):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    result = {
        "id": "warn1", "pcap_name": "w.pcapng", "pcap_size": 1, "frame_count": 1,
        "analyzed_at": "now", "tshark_version": "t", "tshark_path": "t",
        "structured": {"sources": sources}, "text_sections": [],
    }
    (tmp_path / "warn1.json").write_text(
        json.dumps(result, ensure_ascii=False), encoding="utf-8")


def test_banner_shown_when_source_has_warning(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch, [
        {"name": "cable.pcapng", "role": "wired", "frame_count": None,
         "warnings": ["무선(802.11) 캡처다 — 유선 캡처를 넣어라: x"]},
    ])
    html = client.get("/analysis/warn1").text
    assert "입력 파일 경고" in html and "cable.pcapng" in html


def test_no_banner_without_warnings(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch, [
        {"name": "w.pcapng", "role": "wireless", "frame_count": 1, "warnings": []},
    ])
    html = client.get("/analysis/warn1").text
    assert "입력 파일 경고" not in html


def test_old_result_without_sources_renders(tmp_path, monkeypatch):
    """구버전 결과(sources 없음)도 분석 페이지가 그대로 뜬다 (하위 호환)."""
    _store(tmp_path, monkeypatch, None)  # sources 키 자체를 지운다
    p = tmp_path / "warn1.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    data["structured"].pop("sources")
    p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    assert client.get("/analysis/warn1").status_code == 200
```

- [ ] **Step 2: 실패 확인**

Run: `python3 -m pytest tests/test_routes_wired_banner.py -v`
Expected: `test_banner_shown_when_source_has_warning` FAIL (배너 미구현), 나머지 2개는 PASS여도 무방

- [ ] **Step 3: 구현 — 4개 파일**

(a) `templates/analysis.html` — `{% block content %}` 직후(`:4`)에 배너 (index.html:5-13의 tshark 배너 스타일 준용, 노랑):

```html
{% set src_list = result.structured.get('sources') or [] %}
{% set src_warnings = [] %}
{% for s in src_list %}{% for w in s.get('warnings', []) %}{% set _ = src_warnings.append(s.get('name', '?') ~ ': ' ~ w) %}{% endfor %}{% endfor %}
{% if src_warnings %}
<div class="bg-yellow-900/50 border border-yellow-700 rounded-lg p-4 mb-4">
    <p class="text-yellow-300 font-semibold">입력 파일 경고</p>
    {% for w in src_warnings %}
    <p class="text-yellow-400 text-sm mt-1">{{ w }}</p>
    {% endfor %}
</div>
{% endif %}
```

(b) `templates/analysis.html` — ping 탭 `#ping-kpi`(`:225`) 바로 앞에:

```html
<div id="ping-ground-truth" class="hidden mb-4"></div>
```

(c) `static/js/charts.js` — ping 탭 진입부(`const pingStatsData = ping.stats || {};` 뒤)에:

```js
/* 유선 ground truth 카드 — ping.ground_truth 있을 때만 (스펙 §4) */
const gt = ping.ground_truth || null;
const gtDiv = document.getElementById('ping-ground-truth');
if (gt && gtDiv && typeof gt.ng === 'number') {
    const s = pingStatsData;
    const wirelessLoss = (s.loss_count != null && s.loss_pct != null)
        ? `${s.loss_count.toLocaleString()}건 (${s.loss_pct}%)` : '—';
    gtDiv.classList.remove('hidden');
    gtDiv.innerHTML = `
      <div class="bg-gray-800 border border-emerald-700 rounded-lg p-4">
        <div class="text-emerald-300 font-semibold mb-2">유선 Ground Truth (포트 미러 캡처)</div>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
          <div><div class="text-gray-400">확정 손실</div>
            <div class="${gt.ng > 0 ? 'text-red-400' : 'text-green-400'}">${gt.ng.toLocaleString()}건 (${gt.loss_pct}%)</div></div>
          <div><div class="text-gray-400">전체 요청</div><div>${gt.total.toLocaleString()}건</div></div>
          <div><div class="text-gray-400">무선 관측 손실</div><div>${wirelessLoss}</div></div>
          <div><div class="text-gray-400">연속 손실 구간</div><div>${(gt.streaks || []).length}곳</div></div>
        </div>
        <p class="text-gray-500 text-xs mt-2">
          무선 관측 손실이 유선 확정 손실보다 크면 모니터 캡처 누락이 손실로 과대 계상된 것입니다
          (docs/EXPING.md 실측: 0.16% 대 15.65%).</p>
      </div>`;
}
```

(d) `templates/index.html` — 옵션 필드 그리드(`:33-53`)에 항목 추가:

```html
<div>
    <label class="block text-sm text-gray-400 mb-1">유선 pcap (선택 — ping ground truth)</label>
    <input type="file" name="wired_file" id="wired-file" accept=".pcap,.pcapng,.cap"
           class="w-full text-sm text-gray-300 file:mr-2 file:py-1 file:px-2 file:rounded file:border-0 file:bg-gray-700 file:text-gray-300">
    <p class="text-gray-500 text-xs mt-1">포트 미러링 유선 캡처 — 확정 손실률(ground truth) 계산에 사용</p>
</div>
```

(e) `static/js/upload.js` — submit 핸들러의 파일 검증부(`:122-125` 뒤)에 크기 검증 추가 (`new FormData(form)`이 `wired_file`을 자동 포함하므로 전송 코드는 수정 불필요):

```js
const wiredInput = document.getElementById('wired-file');
if (wiredInput && wiredInput.files.length) {
    const maxMb = parseInt(fileInput.dataset.maxMb || '200', 10);
    if (wiredInput.files[0].size > maxMb * 1024 * 1024) {
        alert(`유선 pcap이 업로드 상한(${maxMb}MB)을 초과합니다.`);
        return;
    }
}
```

- [ ] **Step 4: 통과 확인**

Run: `python3 -m pytest tests/test_routes_wired_banner.py tests/test_routes.py -q`
Expected: 전부 통과

수동 확인 (tshark 있는 로컬에서): `python3 app.py` → 무선+유선 pcap 업로드 → ping 탭 GT 카드·배너 확인. e2e 자동화는 기존 `tests/e2e/`가 마커로 분리돼 있어 이번 단계 범위 밖.

- [ ] **Step 5: 커밋**

```bash
git add templates/index.html templates/analysis.html static/js/upload.js static/js/charts.js tests/test_routes_wired_banner.py
git commit -m "feat(ui): 유선 pcap 업로드 폼·ping GT 카드·입력 경고 배너"
```

---

### Task 7: 문서·최종 회귀

**Files:**
- Modify: `README.md` (`:3` 소개문 부근), `docs/EXPING.md` (대시보드 연동 언급 — "무엇을 해결하나" 표 아래)

**Interfaces:**
- Consumes: 전체 완성 상태
- Produces: 사용자 문서 + 전체 스위트 그린

- [ ] **Step 1: README 갱신**

`README.md:3`의 소개문 문단 뒤에 추가:

```markdown
유선(포트 미러) pcap을 함께 업로드하면 ping 손실의 ground truth를 계산해
무선 관측 손실과 병기하고, 확정 손실 구간을 무선 이벤트(로밍·재전송)와
자동 대조한다. 설계: `docs/superpowers/specs/2026-08-03-multi-pcap-analysis-design.md`
```

`docs/EXPING.md`의 "무엇을 해결하나" 표 아래에 한 줄:

```markdown
> 웹 대시보드도 같은 매칭 규칙을 재사용한다 — 업로드 폼에 유선 pcap을 함께
> 넣으면 `analyzer/core/wired_ping.py`가 ground truth를 계산한다.
```

- [ ] **Step 2: 전체 회귀 + lint**

Run: `python3 -m pytest tests/ -q && ruff check .`
Expected: 기존 755 + 신규 약 20개 전부 통과, ruff 클린

tshark 있는 로컬이면 추가로: `python3 -m pytest tests/ -q -m "tshark"`
Expected: golden/smoke 통과 (단일 pcap 하위 호환 실증)

- [ ] **Step 3: 커밋 + PR**

```bash
git add README.md docs/EXPING.md
git commit -m "docs(readme): 유선 ground truth 업로드 사용법 — 1단계 마무리"
git push -u origin feat/wired-ground-truth
gh pr create --base main --title "feat: 유선 pcap ground truth — 멀티 pcap 1단계" --body "..."
```

PR 본문에는 스펙 링크·테스트 개수·하위 호환 확인(기존 테스트 무손상, 구버전 JSON 렌더 테스트)을 명시한다.

---

## 계획 자가 리뷰 결과

- **스펙 커버리지 (1단계 범위)**: 입력 계약(§1)=Task 4·5·6, 파이프라인(§2)=Task 2, 유선 경량 추출(§2)=Task 1, ground truth·진단 대조(§4)=Task 1·3, 스키마/sources(§6)=Task 2·4, 에러 처리(§7)=Task 1(무선 가드·tshark 부재)·4(magic/확장자/크기)·6(배너), 테스트(§8)=각 Task+7. dedup·TSF·sniffer_compare·다중 무선은 스펙 §9대로 2·3단계로 이월.
- **타입 일관성**: `build_ground_truth` 반환 키(total/ok/ng/loss_pct/streaks/ng_epochs/...)를 Task 2 GT_OK 픽스처·Task 3 streak 소비·Task 6 JS 렌더가 동일하게 사용. `wired_path=""` 기본값이 Task 2·4·5에서 일치.
- **알려진 한계 (의도)**: 유선 분석 중 취소 이벤트 미전파(child_timeout 3600 상한만), 캡처 구멍 구간은 근거 부재로 이슈 생략(코드 주석에 명시), GT 카드 JS는 수동/e2e 확인.
