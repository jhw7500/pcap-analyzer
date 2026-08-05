# 유선 RTT 1차 전환 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** ICMP 분석을 "판정 유선 1차·해석 무선 보조" 체계로 완성 — GT에 exchange별 RTT 노출, ping 탭 소스 토글(유선 기본), report.md GT 블록 (스펙: `docs/superpowers/specs/2026-08-05-wired-rtt-primary-design.md`).

**Architecture:** `exping.Exchange(time, target, rtt)`가 이미 계산한 RTT를 `wired_ping.build_ground_truth`의 GT dict에 optional 필드(`exchanges`/`rtt_stats`)로 노출만 한다(집계 모집단과 동일 집합). 프론트는 기존 무선 렌더 4블록을 함수로 감싸고(코드 이동만) 유선 렌더 4개 + 토글을 추가한다. report는 `_ping_section` 서두에 유선 확정 블록을 붙인다.

**Tech Stack:** Python 3 (FastAPI), Plotly.js + Tailwind, pytest (`_fake_tshark` 하니스 재사용).

## Global Constraints

- **모든 신규 필드는 optional** — 구버전 결과 JSON(`data/analyses/*.json`) 재로드·리포트·프론트 렌더 무결 (메모리 `serialized-result-backward-compat`).
- **GT 없는 결과는 어디서도 출력 불변**: 유선 미업로드 분석 결과 JSON·report.md 출력 byte-identical, ping 탭은 기존 무선 뷰 그대로(토글 미표시). 토글 표시 조건은 `ping.ground_truth.exchanges`가 비어 있지 않을 때뿐.
- **모집단 동일성**: `exchanges`는 손실 집계와 정확히 같은 집합 — `total == len(exchanges)`, `ok == rtt_ms non-null 수`, `rtt_stats.n == ok` (골든에서 등식 고정). trailing_dropped 제외분은 exchanges에도 없다.
- **정직한 공백**: 응답 0건이면 `rtt_stats` 필드 자체 생략 (0·가짜값 금지).
- `rtt_ms`/통계는 ms 단위 소수 3자리 반올림. p95는 정렬 후 `ceil(0.95*n)-1` 인덱스(nearest-rank, 외부 의존성 없음).
- 유선 뷰에는 Retry(노랑) 개념 없음. 손실 X마커는 무선 관례(`maxRtt*1.1` 상단, `#ef4444` symbol x) 재사용.
- XSS: target 등 사용자 유래 문자열은 innerHTML 삽입 시 `escapeHtml` 필수.
- 검증: `python3 -m pytest tests/ -q` (949+신규), `ruff check .`, tshark 골든 `-m tshark` (18+신규).

---

### Task 1: GT 스키마 확장 — `exchanges` + `rtt_stats`

**Files:**
- Modify: `analyzer/core/wired_ping.py` (`build_ground_truth` 반환 블록 line ~533-545, 헬퍼는 `build_ground_truth` 정의 직전)
- Test: `tests/test_wired_ping.py` (기존 파일에 추가)

**Interfaces:**
- Consumes: `exping.Exchange` — `time: float`, `target: str`, `rtt: float | None` (`analyzer/core/exping.py:90-100`)
- Produces: GT dict 신규 키 —
  `exchanges: [{"epoch": float, "target": str, "rtt_ms": float|None}, ...]`,
  `rtt_stats: {"n": int, "min_ms": float, "avg_ms": float, "max_ms": float, "p95_ms": float}` (응답 0건이면 키 생략).
  `_rtt_stats(exchanges) -> Optional[Dict[str, Any]]` 모듈 헬퍼(테스트가 직접 호출).

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_wired_ping.py`에 추가 (파일의 기존 import/`_fake_tshark` 관례 재사용, `from analyzer.core.exping import Exchange` import 추가):

```python
def test_rtt_stats_p95_boundaries():
    """p95 = 정렬 후 ceil(0.95*n)-1 인덱스 (nearest-rank)."""
    one = wired_ping._rtt_stats([Exchange(1.0, "t", 0.005)])
    assert one == {"n": 1, "min_ms": 5.0, "avg_ms": 5.0, "max_ms": 5.0, "p95_ms": 5.0}

    xs = [Exchange(float(i), "t", (i + 1) / 1000) for i in range(20)]  # 1..20ms
    st = wired_ping._rtt_stats(xs)
    assert st["n"] == 20
    assert st["min_ms"] == 1.0 and st["max_ms"] == 20.0 and st["avg_ms"] == 10.5
    assert st["p95_ms"] == 19.0  # ceil(0.95*20)-1 = idx 18 → 19ms


def test_rtt_stats_none_when_no_answers():
    """정직한 공백 — 응답이 하나도 없으면 통계 대신 None."""
    assert wired_ping._rtt_stats([]) is None
    assert wired_ping._rtt_stats([Exchange(1.0, "t", None)]) is None


def test_exchanges_and_rtt_stats_exposed(tmp_path):
    """GT dict에 exchange별 RTT가 노출되고 손실 집계와 모집단이 일치한다."""
    # 기존 test_counts_ok_ng_and_loss_pct와 동일한 body 픽스처를 그대로 재사용한다.
    body = _BODY_OK  # ← 그 테스트의 body 문자열을 모듈 상수로 승격해 공유 (아래 Step 3 ③)
    gt = wired_ping.build_ground_truth("x.pcapng", tshark_path=_fake_tshark(tmp_path, body))

    assert len(gt["exchanges"]) == gt["total"]
    answered = [e for e in gt["exchanges"] if e["rtt_ms"] is not None]
    assert len(answered) == gt["ok"]
    assert all(e["rtt_ms"] > 0 for e in answered)
    assert all(set(e) == {"epoch", "target", "rtt_ms"} for e in gt["exchanges"])

    rs = gt["rtt_stats"]
    assert rs["n"] == gt["ok"]
    assert rs["min_ms"] <= rs["avg_ms"] <= rs["max_ms"]
    assert rs["min_ms"] <= rs["p95_ms"] <= rs["max_ms"]


def test_all_unanswered_omits_rtt_stats(tmp_path, monkeypatch):
    """전부 무응답이면 rtt_stats 키 자체가 없다 — 기존 100% 손실 픽스처 재사용."""
    # 기존 test_all_requests_unanswered_100_loss의 body·monkeypatch를 그대로 복제한다.
    ...  # (구현 시 그 테스트의 준비 코드를 복사하고, 아래 단언만 추가)
    assert "rtt_stats" not in gt
    assert all(e["rtt_ms"] is None for e in gt["exchanges"])
```

또한 기존 `test_trailing_unanswered_dropped_with_warning`에 단언 1줄 추가:

```python
    assert len(gt["exchanges"]) == gt["total"]  # 꼬리 제외분은 exchanges에도 없다
```

(주: `...` 표기는 기존 테스트의 준비 코드를 **복사**하라는 뜻이며 구현 단계에서 실제 코드로 채운다 — 이 파일 안에 이미 존재하는 코드라 여기 중복 인용하지 않는다.)

- [ ] **Step 2: 실패 확인**

Run: `python3 -m pytest tests/test_wired_ping.py -q`
Expected: 신규 4건 FAIL (`AttributeError: _rtt_stats` / `KeyError: 'exchanges'`), 기존 전부 PASS

- [ ] **Step 3: 구현 (3곳)**

① `analyzer/core/wired_ping.py` 상단 import 블록에 `import math` 추가(이미 있으면 생략).

② `build_ground_truth` 정의 직전에 헬퍼 추가:

```python
def _rtt_stats(exchanges: List["exping.Exchange"]) -> Optional[Dict[str, Any]]:
    """응답 있는 exchange의 RTT 통계(ms). 응답 0건이면 None — 정직한 공백
    원칙(스펙 §1): 0이나 가짜 값으로 채우면 '무손실·0ms'로 오독된다.

    p95는 정렬 후 nearest-rank(ceil(0.95*n)-1 인덱스) — 외부 의존성 없이
    n=1에서도 안전하다.
    """
    rtts = sorted(x.rtt for x in exchanges if x.rtt is not None)
    if not rtts:
        return None
    n = len(rtts)
    p95 = rtts[max(0, math.ceil(0.95 * n) - 1)]
    return {
        "n": n,
        "min_ms": round(rtts[0] * 1000, 3),
        "avg_ms": round(sum(rtts) / n * 1000, 3),
        "max_ms": round(rtts[-1] * 1000, 3),
        "p95_ms": round(p95 * 1000, 3),
    }
```

③ `result: Dict[str, Any] = {...}` 리터럴(line ~534) 직후, `if time_end:` 분기 앞에 추가:

```python
    # 유선 RTT 1차 노출(스펙 2026-08-05-wired-rtt-primary §1): exchanges는
    # 위 손실 집계와 정확히 같은 최종 모집단이다 — 시간창·필터·꼬리 제외가
    # 모두 반영된 뒤의 리스트라 total == len(exchanges)가 항상 성립한다.
    result["exchanges"] = [
        {"epoch": x.time, "target": x.target,
         "rtt_ms": round(x.rtt * 1000, 3) if x.rtt is not None else None}
        for x in exchanges
    ]
    rtt_stats = _rtt_stats(exchanges)
    if rtt_stats is not None:
        result["rtt_stats"] = rtt_stats
```

추가로 Step 1의 공유를 위해 `test_counts_ok_ng_and_loss_pct`의 body 문자열을 모듈 상수 `_BODY_OK`로 승격하고 그 테스트가 상수를 쓰도록 바꾼다(값 변경 없음 — 이동만).

- [ ] **Step 4: 통과 확인**

Run: `python3 -m pytest tests/test_wired_ping.py tests/test_pipeline_wired.py -q`
Expected: 전부 PASS

- [ ] **Step 5: 커밋**

```bash
git add analyzer/core/wired_ping.py tests/test_wired_ping.py
git commit -m "feat(wired): GT에 exchange별 RTT·통계 노출 — 손실 집계와 동일 모집단 (스펙 §1)"
```

---

### Task 2: ping 탭 소스 토글 — 유선 기본, 무선 전환

**Files:**
- Modify: `templates/analysis.html` (RTT 카드 헤더 line ~279)
- Modify: `static/js/charts.js` (ping 렌더 4블록 함수화 + 유선 렌더 + 토글, line ~918-1182)

**Interfaces:**
- Consumes: `DATA.ping.ground_truth.exchanges/rtt_stats`(Task 1), 기존 `DARK`·`escapeHtml`·무선 렌더 블록(KPI 918-934 / RTT 936-1015 / 히스토그램 1017-1052 / 통계 1054-~1182)
- Produces: `#ping-source-toggle` 세그먼트 버튼(유선 기본), 토글 연동 위젯 4개. GT 없으면 완전 무변화.

- [ ] **Step 1: analysis.html — RTT 카드 헤더에 토글 추가**

line ~279의 `<h3 class="text-sm font-semibold text-gray-400 mb-2">Ping RTT 시계열 (초록=정상, 노랑=Retry, 빨강X=Loss)</h3>` 를 다음으로 교체:

```html
            <div class="flex items-center justify-between mb-2">
                <h3 class="text-sm font-semibold text-gray-400">Ping RTT 시계열 <span id="ping-rtt-legend">(초록=정상, 노랑=Retry, 빨강X=Loss)</span></h3>
                <!-- 소스 토글 — 유선 GT exchanges 있을 때만 charts.js가 unhide (스펙 §3) -->
                <div id="ping-source-toggle" class="hidden flex text-xs rounded overflow-hidden border border-gray-600">
                    <button data-src="wired" class="px-2 py-1 bg-blue-600 text-white">유선 (확정)</button>
                    <button data-src="wireless" class="px-2 py-1 bg-gray-700 text-gray-300">무선 (관측)</button>
                </div>
            </div>
```

- [ ] **Step 2: charts.js — 무선 렌더 4블록 함수화 (코드 이동만, 수정 금지)**

같은 IIFE 스코프 안에서 아래 4블록을 각각 함수로 감싼다(내용은 그대로, 들여쓰기만 조정):

- `const pingKpi = ...` 블록(line ~918-934) → `function renderPingKpiWireless() { ... }`
- RTT 시계열 블록(`const pingRttEl = ...`부터 `Plotly.newPlot('chart-ping-rtt', traces_ping, ...)` 닫힘까지, line ~936-1015) → `function renderPingRttWireless() { ... }`
- 히스토그램 블록(line ~1017-1052) → `function renderPingHistWireless() { ... }`
- 통계 블록(`const pingStats = ...` 선언과 `crossValidationRows` 정의는 **바깥에 그대로 두고**, `if (pingStats && !pingStatsData.count) { ... } else if (pingStats && pingStatsData.count) { ... }` 체인만, `const pingFullTable` 직전까지) → `function renderPingStatsWireless() { ... }`

- [ ] **Step 3: charts.js — 유선 렌더 4개 + 토글 초기화 추가**

Step 2의 함수들 뒤에 추가 (`gt`는 기존 GT 카드 블록의 `const gt = ping.ground_truth || null;` 재사용):

```js
    /* ── ping 소스 토글 (스펙 2026-08-05-wired-rtt-primary §3) ──
       유선 GT exchanges 있을 때만 표시. 판정(손실·RTT)은 유선이 1차,
       Retry·frame_refs 해석은 무선 뷰 전용. */
    const gtExchanges = (gt && Array.isArray(gt.exchanges) && gt.exchanges.length > 0)
        ? gt.exchanges : null;

    function renderPingKpiWired() {
        const rs = gt.rtt_stats || null;
        pingKpi.innerHTML = [
            { label: '총 요청 (유선 확정)', value: (gt.total ?? 0).toLocaleString() + '건', color: '' },
            { label: '손실 (유선 확정)', value: (gt.ng ?? 0).toLocaleString() + '건 (' + (gt.loss_pct ?? 0) + '%)',
              color: (gt.ng ?? 0) > 0 ? 'text-red-400' : '' },
            { label: '평균 RTT (유선)', value: rs ? rs.avg_ms + 'ms' : '—', color: rs ? '' : 'text-gray-500' },
            { label: 'P95 RTT (유선)', value: rs ? rs.p95_ms + 'ms' : '—',
              color: rs ? (rs.p95_ms > 10 ? 'text-yellow-400' : '') : 'text-gray-500' },
        ].map(k =>
            `<div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <p class="text-xs text-gray-500">${k.label}</p>
                <p class="text-xl font-bold ${k.color}">${k.value}</p>
            </div>`
        ).join('');
    }

    function renderPingRttWired() {
        const ok = gtExchanges.filter(e => e.rtt_ms != null);
        const loss = gtExchanges.filter(e => e.rtt_ms == null);
        const maxRtt = ok.length ? Math.max(...ok.map(e => e.rtt_ms)) : 1;
        const traces = [];
        if (ok.length) traces.push({
            x: ok.map(e => new Date(e.epoch * 1000)), y: ok.map(e => e.rtt_ms),
            type: 'scattergl', mode: 'markers', name: '응답 (유선)',
            marker: { color: '#10b981', size: 4 },
            text: ok.map(e => escapeHtml(e.target)),
            hovertemplate: '%{text}<br>RTT: %{y:.2f}ms<br>%{x}<extra></extra>',
        });
        if (loss.length) traces.push({
            x: loss.map(e => new Date(e.epoch * 1000)), y: loss.map(() => maxRtt * 1.1),
            type: 'scattergl', mode: 'markers', name: 'Loss (유선 확정)',
            marker: { color: '#ef4444', size: 10, symbol: 'x', line: { width: 2 } },
            text: loss.map(e => escapeHtml(e.target) + ' LOSS'),
            hovertemplate: '%{text}<br>%{x}<extra></extra>',
        });
        Plotly.newPlot('chart-ping-rtt', traces, {
            ...DARK,
            xaxis: { gridcolor: '#374151' },
            yaxis: { title: { text: 'RTT (ms)', font: { size: 12 } }, gridcolor: '#374151', rangemode: 'tozero' },
            legend: { orientation: 'h', x: 0, y: 1.12, font: { size: 12 } },
        }, { responsive: true, displayModeBar: false });
    }

    function renderPingHistWired() {
        const rtts = gtExchanges.filter(e => e.rtt_ms != null).map(e => e.rtt_ms);
        if (!rtts.length) { Plotly.purge('chart-ping-hist'); document.getElementById('chart-ping-hist').innerHTML = '<p class="text-sm text-gray-500 py-8 text-center">응답이 없어 분포를 계산할 수 없습니다.</p>'; return; }
        document.getElementById('chart-ping-hist').innerHTML = '';
        Plotly.newPlot('chart-ping-hist', [{
            x: rtts, type: 'histogram', marker: { color: '#10b981' }, nbinsx: 50,
        }], {
            ...DARK,
            xaxis: { title: { text: 'RTT (ms)', font: { size: 12 } }, gridcolor: '#374151' },
            yaxis: { title: { text: '건수', font: { size: 12 } }, gridcolor: '#374151' },
        }, { responsive: true, displayModeBar: false });
    }

    function renderPingStatsWired() {
        const rs = gt.rtt_stats || null;
        const rows = [
            ['총 요청', (gt.total ?? 0).toLocaleString() + '건'],
            ['손실 (확정)', (gt.ng ?? 0).toLocaleString() + '건 (' + (gt.loss_pct ?? 0) + '%)'],
        ];
        if (rs) rows.push(
            ['최소 RTT', rs.min_ms + 'ms'], ['평균 RTT', rs.avg_ms + 'ms'],
            ['P95 RTT', rs.p95_ms + 'ms'], ['최대 RTT', rs.max_ms + 'ms']);
        pingStats.innerHTML = `<table class="w-full text-sm">` + rows.map(r =>
            `<tr><td class="text-gray-400 py-1">${r[0]}</td><td class="text-right text-white font-mono">${r[1]}</td></tr>`
        ).join('') + `</table>
        <p class="text-xs text-gray-500 mt-2">판정은 유선 확정 기준. Retry·프레임 근거 해석은 무선 (관측) 뷰에서.</p>`;
    }

    function renderPingSource(src) {
        const legend = document.getElementById('ping-rtt-legend');
        if (src === 'wired' && gtExchanges) {
            renderPingKpiWired(); renderPingRttWired(); renderPingHistWired(); renderPingStatsWired();
            if (legend) legend.textContent = '(초록=응답, 빨강X=손실 — 유선 확정)';
        } else {
            renderPingKpiWireless(); renderPingRttWireless(); renderPingHistWireless(); renderPingStatsWireless();
            if (legend) legend.textContent = '(초록=정상, 노랑=Retry, 빨강X=Loss)';
        }
        document.querySelectorAll('#ping-source-toggle button').forEach(b => {
            const active = b.dataset.src === src;
            b.classList.toggle('bg-blue-600', active); b.classList.toggle('text-white', active);
            b.classList.toggle('bg-gray-700', !active); b.classList.toggle('text-gray-300', !active);
        });
    }

    const srcToggle = document.getElementById('ping-source-toggle');
    if (gtExchanges && srcToggle) {
        srcToggle.classList.remove('hidden');
        srcToggle.querySelectorAll('button').forEach(b =>
            b.addEventListener('click', () => renderPingSource(b.dataset.src)));
        renderPingSource('wired');
    } else {
        renderPingSource('wireless');
    }
```

주의: 기존에 4블록이 즉시 실행되던 자리는 위 토글 초기화가 대체한다(GT 없으면 `renderPingSource('wireless')`가 기존과 동일 렌더). `scattergl`은 exchanges 1만+ 포인트 성능용.

- [ ] **Step 4: 코드 레벨 검증**

Run: `node --check static/js/charts.js && python3 -m pytest tests/ -q && ruff check .`
Expected: 문법 OK, 기존 테스트 전부 PASS (프론트 변경이라 수치 불변). 브라우저 검증은 컨트롤러가 수행.

- [ ] **Step 5: 커밋**

```bash
git add templates/analysis.html static/js/charts.js
git commit -m "feat(front): ping 탭 소스 토글 — 유선 확정 기본, 무선 관측 전환 (스펙 §3)"
```

---

### Task 3: report.md — 유선 확정 블록

**Files:**
- Modify: `analyzer/web/report.py` (`_ping_section`, line 567-596)
- Test: `tests/test_report.py` (기존 파일에 추가)

**Interfaces:**
- Consumes: `structured["ping"]["ground_truth"]` (Task 1 필드 포함 가능)
- Produces: GT 있으면 "유선 확정" 줄 + 손실 구간 요약 줄이 섹션 서두에, 무선 통계 줄에는 "무선 관측 (보조지표)" 라벨. GT 없으면 출력 byte-identical.

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_report.py`에 추가 (파일의 기존 build/렌더 헬퍼 관례 재사용):

```python
def test_ping_section_with_ground_truth():
    structured = {
        "ping": {
            "stats": {"count": 90, "loss_pct": 10.0, "loss_count": 10, "avg": 5.2, "p95": 9.9},
            "ground_truth": {
                "total": 100, "ok": 98, "ng": 2, "loss_pct": 2.0,
                "rtt_stats": {"n": 98, "min_ms": 1.0, "avg_ms": 3.4, "max_ms": 50.0, "p95_ms": 9.8},
                "streaks": [{"target": "10.0.0.2", "start_epoch": 1.0, "end_epoch": 2.0,
                             "count": 2, "duration_sec": 1.0}],
            },
        },
    }
    lines = report._ping_section(structured)
    text = "\n".join(lines)
    assert "유선 확정" in text and "요청 100" in text and "(2.0%)" in text
    assert "평균 RTT 3.4ms" in text and "P95 RTT 9.8ms" in text
    assert "손실 구간 1곳" in text
    assert "무선 관측 (보조지표)" in text
    # 유선 블록이 무선 줄보다 먼저
    assert text.index("유선 확정") < text.index("무선 관측")


def test_ping_section_without_ground_truth_unchanged():
    structured = {"ping": {"stats": {"count": 90, "loss_pct": 10.0, "loss_count": 10,
                                     "avg": 5.2, "p95": 9.9}}}
    lines = report._ping_section(structured)
    text = "\n".join(lines)
    assert "유선" not in text and "보조지표" not in text  # 기존 출력 형태 유지
    assert "응답 90" in text
```

(주: `report` import 이름·헬퍼 접근 방식은 tests/test_report.py의 기존 관례를 따른다.)

- [ ] **Step 2: 실패 확인**

Run: `python3 -m pytest tests/test_report.py -q`
Expected: 신규 2건 중 1건 FAIL ("유선 확정" 부재), without-GT 케이스는 PASS일 수 있음(현행 유지 확인용)

- [ ] **Step 3: 구현**

`_ping_section`에서 `stats = ping.get("stats")` 직전에 GT 블록 생성을 추가하고, 반환부를 확장:

```python
    # 유선 확정 블록(스펙 2026-08-05-wired-rtt-primary §4) — GT 있으면 서두에.
    gt = ping.get("ground_truth") or {}
    gt_lines: List[str] = []
    if isinstance(gt, dict) and isinstance(gt.get("total"), int) and gt["total"] > 0:
        gparts = [f"요청 {gt['total']:,}",
                  f"손실 {gt.get('ng', 0):,}건 ({gt.get('loss_pct', 0.0)}%)"]
        rs = gt.get("rtt_stats")
        if isinstance(rs, dict):
            gparts.append(f"평균 RTT {rs['avg_ms']}ms")
            gparts.append(f"P95 RTT {rs['p95_ms']}ms")
        gt_lines.append(f"- **유선 확정**: {' · '.join(gparts)}")
        streaks = gt.get("streaks") or []
        if streaks:
            worst = max(streaks, key=lambda s: s.get("count", 0))
            gt_lines.append(
                f"- 유선 손실 구간 {len(streaks)}곳 — 최장 {worst.get('count', 0)}건"
                f"/{worst.get('duration_sec', 0)}초 ({_clean_inline(str(worst.get('target', '?')))})"
            )
```

기존 무선 줄 반환부는 다음 규칙으로 수정:
- `gt_lines`가 있으면: 무선 줄 접두를 `f"- 무선 관측 (보조지표): {' · '.join(parts)}"`로 바꾸고, `["## Ping / RTT", ""] + gt_lines + [무선 줄, ""]` 반환. `stats`가 없거나 `parts`가 비면 무선 줄 없이 `["## Ping / RTT", ""] + gt_lines + [""]` 반환.
- `gt_lines`가 없으면: **기존 코드 경로 그대로** (byte-identical — 조기 return들 포함 변경 금지).

- [ ] **Step 4: 통과 확인**

Run: `python3 -m pytest tests/test_report.py tests/test_reporter.py tests/test_report_html.py -q`
Expected: 전부 PASS

- [ ] **Step 5: 커밋**

```bash
git add analyzer/web/report.py tests/test_report.py
git commit -m "feat(report): ping 섹션 유선 확정 블록 — 무선은 보조지표 라벨 (스펙 §4)"
```

---

### Task 4: 유선 골든 픽스처 + 정확값 골든 + 하위 호환 회귀

주의: 기존 골든 픽스처(sample_dual_a/b)는 **유선을 포함하지 않는다** — 이 태스크가 결정적 유선 픽스처를 신설한다.

**Files:**
- Modify: `tests/fixtures/generate_sample_dual.py` (유선 pcap 생성 함수 추가)
- Create: `tests/fixtures/sample_wired.pcap` (생성기로 재생성 — 커밋 포함)
- Modify: `tests/test_golden_dual.py` (유선 포함 골든 추가)
- Test: 전체 스위트

**Interfaces:**
- Consumes: Task 1~3 산출 전부, scapy(`Ether/IP/ICMP`, 생성기 기존 의존성), `run_analysis(..., wired_path=)`
- Produces: `sample_wired.pcap` — sender 10.0.0.1 → target 10.0.0.2, echo request 5건(ICMP id=1, seq=1..5) 중 4건 응답. 시각은 dual 픽스처와 같은 epoch 대역. RTT는 정확히 2ms/3ms/4ms/5ms, **seq=3만 무응답(중간 손실 — 마지막 프레임은 reply여야 trailing_dropped 미발동)**. 기대 GT: total 5, ok 4, ng 1, loss_pct 20.0, rtt_stats {n:4, min_ms:2.0, avg_ms:3.5, max_ms:5.0, p95_ms:5.0}.

- [ ] **Step 1: 생성기 확장 + 픽스처 생성**

`generate_sample_dual.py`에 유선 생성 추가 (scapy import에 `Ether` 추가):

```python
def build_wired(base_epoch: float):
    """유선(EN10MB) ICMP 픽스처 — 유선 RTT 골든용 (스펙 2026-08-05 §6).

    request 5건(seq 1..5) 중 seq=3만 무응답. RTT는 seq*1ms — 결정적이라
    골든이 rtt_stats를 정확값으로 고정할 수 있다. 마지막 프레임은 seq=5의
    reply라 trailing_dropped(캡처 끝 경계 드롭)가 발동하지 않는다.
    """
    frames = []
    for i in range(1, 6):
        t_req = base_epoch + i * 1.0
        req = (Ether(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02")
               / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=8, id=1, seq=i))
        _stamp(req, t_req)
        frames.append(req)
        if i != 3:
            rep = (Ether(src="aa:bb:cc:00:00:02", dst="aa:bb:cc:00:00:01")
                   / IP(src="10.0.0.2", dst="10.0.0.1") / ICMP(type=0, id=1, seq=i))
            _stamp(rep, t_req + i / 1000.0)  # RTT = i ms (2,4는 응답, 1,5도 — 3만 제외)
            frames.append(rep)
    return frames
```

RTT가 2/3/4/5ms가 되도록 응답 있는 seq 집합이 {1,2,4,5}이므로 RTT = {1,2,4,5}ms가 된다 — **기대값을 {1.0, 2.0, 4.0, 5.0}, avg 3.0, p95 5.0으로 정정해 생성기·골든에 일관 반영한다** (min 1.0 / max 5.0). `main()`에서 `wrpcap(str(out_dir / "sample_wired.pcap"), build_wired(BASE_EPOCH))` 추가(기존 BASE 상수 재사용, 링크타입은 Ether라 자동 EN10MB).

실행: `python3 tests/fixtures/generate_sample_dual.py` → `sample_wired.pcap` 생성 확인 (`capinfos`로 EN10MB·프레임 9개).

- [ ] **Step 2: 골든 테스트 추가 (실패 확인 포함)**

`tests/test_golden_dual.py`에 추가 — 상단에 `FIXTURE_WIRED = Path(__file__).parent / "fixtures" / "sample_wired.pcap"`, 모듈 픽스처:

```python
@pytest.fixture(scope="module")
def result_wired():
    if not (FIXTURE_A.exists() and FIXTURE_B.exists() and FIXTURE_WIRED.exists()):
        pytest.skip("fixture pcap not found")
    return run_analysis(str(FIXTURE_A), wireless_paths=[str(FIXTURE_B)],
                        wired_path=str(FIXTURE_WIRED))


def test_wired_rtt_golden_exact(result_wired):
    """유선 RTT 골든 — 결정적 픽스처라 통계를 정확값으로 고정한다(스펙 §1·§6)."""
    gt = result_wired["structured"]["ping"]["ground_truth"]
    assert (gt["total"], gt["ok"], gt["ng"], gt["loss_pct"]) == (5, 4, 1, 20.0)
    ex = gt["exchanges"]
    assert len(ex) == gt["total"]
    assert [e["rtt_ms"] for e in ex] == [1.0, 2.0, None, 4.0, 5.0]
    assert gt["rtt_stats"] == {"n": 4, "min_ms": 1.0, "avg_ms": 3.0,
                               "max_ms": 5.0, "p95_ms": 5.0}
```

Run: `python3 -m pytest tests/test_golden_dual.py -q -m tshark`
Expected: Task 1 구현이 이미 머지된 브랜치 상태이므로 PASS. (rtt_ms 부동소수 오차가 나면 pcap 타임스탬프 µs 정밀도 문제 — 생성기 `_stamp`가 µs 정렬을 보장하는지 확인하고, 그래도 어긋나면 `pytest.approx(..., abs=1e-3)`로 완화하되 사유를 주석으로 남긴다.)

- [ ] **Step 3: 전체 회귀**

```bash
python3 -m pytest tests/ -q            # 949 + 신규 전부 PASS
python3 -m pytest tests/ -q -m tshark  # 18 + 신규
ruff check .
```

특히 유선 없는 분석 불변(기존 스냅샷·스모크)과 report 무-GT 출력 불변(Task 3 테스트)이 그대로 통과해야 한다.

- [ ] **Step 4: 커밋**

```bash
git add tests/fixtures/generate_sample_dual.py tests/fixtures/sample_wired.pcap tests/test_golden_dual.py
git commit -m "test(golden): 결정적 유선 픽스처 + 유선 RTT 정확값 골든"
```

---

## 계획 자가 리뷰 결과

- **스펙 커버리지**: §1 스키마(Task 1) ✓ / §3 토글 4위젯·표시조건·무선전용 위젯 불변(Task 2) ✓ / §4 report(Task 3) ✓ / §5 에러(응답 0건 rtt_stats 생략 — Task 1·2의 rs null 처리) ✓ / §6 테스트 5종(단위·통합은 Task 1, 골든 Task 4, 하위 호환 Task 3 without-GT + 기존 회귀, report 단위 Task 3) ✓
- **플레이스홀더**: Task 1 Step 1의 `...` 2곳은 "같은 파일의 기존 코드를 복사"라는 명시적 지시(대상 테스트명 지정)로, 새로 창작할 내용이 아님 — 허용 범위로 판단.
- **타입 일관성**: `_rtt_stats(List[Exchange]) -> Optional[Dict]`가 정의(Task 1 Step 3)·테스트(Step 1)에서 동일. `exchanges[].{epoch,target,rtt_ms}` 키가 Task 1 테스트·Task 2 JS(`e.rtt_ms`, `e.epoch`, `e.target`)·Task 4 골든에서 동일. `rtt_stats.{n,min_ms,avg_ms,max_ms,p95_ms}`가 전 태스크 동일.
- **하위 호환 경로**: 토글 게이트(`gtExchanges` null → 기존 무선 렌더), report 무-GT 경로 불변 명시, GT 없는 결과 JSON 불변(신규 필드는 build_ground_truth 내부에서만 생성).
