# ping 탭 토글 완전성 + 손실 클릭 내비게이션 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** ping 탭 하단 3위젯(연속 실패 구간·전체 목록·관찰 ICMP)을 소스 토글에 연동하고, RTT 시계열의 손실 X 마커 클릭 시 전체 목록 해당 행으로 점프한다 (스펙: `docs/superpowers/specs/2026-08-07-ping-toggle-parity-design.md`).

**Architecture:** 프론트 전용 — `static/js/charts.js`의 `renderPingSource(src)`에 하단 위젯 전환을 통합하고, 무선 streak/전체 목록 렌더는 함수화(이동만) 후 유선 대응 렌더러를 추가한다. 클릭 내비는 손실 trace `customdata`(배열 인덱스) + `plotly_click` + 행 `data-*` 속성 조인으로 구현. 백엔드·직렬화 무변경.

**Tech Stack:** Plotly.js + Tailwind (`static/js/charts.js`, `templates/analysis.html`), 검증은 node --check + 기존 pytest 회귀 + 컨트롤러 Playwright.

## Global Constraints

- **백엔드·직렬화 무변경** — 수정 파일은 `static/js/charts.js`, `templates/analysis.html` 둘뿐. pytest 수치 불변(957).
- **GT 없는 결과(구버전)**: 토글 없음 경로에서 하단 위젯 렌더 결과가 기존과 동일해야 한다(무선 렌더러 함수화는 이동만). 신규로 허용되는 변화는 ① 무선 전체 목록 행의 `data-fl-idx` 속성 ② 무선 손실 클릭 내비 활성 — 둘 다 표시 내용 무변경.
- 기존 무선 렌더 블록 함수화는 **코드 이동만** (PR #25의 4블록 함수화와 동일 원칙, `--ignore-all-space` diff로 검증 가능해야 함).
- 방어성: `gt.streaks` 부재/빈 배열, 행 탐색 실패 등 어떤 경우에도 throw 금지.
- XSS: `target` 등 사용자 유래 문자열 innerHTML 삽입 시 `escapeHtml` 필수.
- 검증: `node --check static/js/charts.js` · `python3 -m pytest tests/ -q` (957) · `ruff check .`. 브라우저 검증은 컨트롤러 수행.

---

### Task 1: 하단 3위젯 토글 연동

**Files:**
- Modify: `static/js/charts.js` (streak 블록 ~line 1393 함수화 + 유선 렌더러 2개 + `renderPingSource` 확장 + 무선 전체 목록 행 속성 1개)
- Modify: `templates/analysis.html` (전체 목록 thead에 id 부여, 필터 컨테이너 id 부여 — 구조 무변경)

**Interfaces:**
- Consumes: `gt.streaks[]` (`{target, start_epoch, end_epoch, count, duration_sec}`), `gt.exchanges[]` (`{epoch, target, rtt_ms|null}`), 기존 `renderPingSource(src)`/`gtExchanges`/`escapeHtml`/`fullList`/`renderPingFullTable`
- Produces: `renderPingStreaksWireless()`(이동), `renderPingStreaksWired()`, `renderPingFullTableWired()`, 확장된 `renderPingSource(src)`. 행 속성: 유선 `data-ex-idx`, 무선 `data-fl-idx` (Task 2의 조인 키)

- [ ] **Step 1: analysis.html — id 부여 (구조 무변경)**

전체 목록 테이블(`#ping-full-table`)의 `<thead>`에 `id="ping-full-thead"`, flow 셀렉트를 감싸는 label 요소에 `id="ping-filter-flow-wrap"`, Retry 체크 label에 `id="ping-filter-retry-wrap"` 추가 (기존 마크업 이동·삭제 없음 — 속성만).

- [ ] **Step 2: charts.js — 무선 streak 블록 함수화 (이동만)**

`const streakTbody = ...` 선언은 밖에 두고, `if (streakTbody) { ... }` 블록 전체를 `function renderPingStreaksWireless() { ... }`로 감싼다(내용 무수정). 기존 즉시 실행 자리는 Step 5의 renderPingSource 통합이 대체한다.

- [ ] **Step 3: charts.js — 유선 렌더러 2개 추가**

```js
    function renderPingStreaksWired() {
        if (!streakTbody) return;
        const streaks = (gt && gt.streaks) || [];
        if (!streaks.length) {
            streakTbody.innerHTML = '<tr><td colspan="6" class="text-gray-500 text-center py-6">유선 연속 손실 구간 없음 (산발적 발생)</td></tr>';
            return;
        }
        const fmtE = e => (typeof e === 'number') ? new Date(e * 1000).toLocaleTimeString('en-GB') : '-';
        streakTbody.innerHTML = streaks.map(s => `<tr class="border-b border-gray-700/30 text-red-400 bg-red-900/10 hover:bg-gray-700/30">
            <td class="py-1 px-1 text-gray-200">${escapeHtml(String(s.target ?? '?'))}</td>
            <td class="py-1 px-1">${fmtE(s.start_epoch)} ~ ${fmtE(s.end_epoch)}</td>
            <td class="py-1 px-1 text-right font-bold">${s.count ?? 0}건</td>
            <td class="py-1 px-1 text-right">${Number(s.duration_sec || 0).toFixed(1)}초</td>
            <td class="py-1 px-1 text-gray-600">—</td>
            <td class="py-1 px-1 text-gray-600">—</td>
        </tr>`).join('');
    }
```

(주: 마지막 두 `—` 셀은 무선 thead의 seq 범위·근거 프레임 컬럼 자리 — **기존 무선 streak 행의 컬럼 수·순서를 먼저 확인해 동일하게 맞춘다.** 6컬럼이 아니면 그 수에 맞출 것.)

```js
    const WIRED_FULL_THEAD = `<tr class="text-gray-400 border-b border-gray-700">
        <th class="text-left py-2 px-1">#</th>
        <th class="text-left py-2 px-1">시각</th>
        <th class="text-left py-2 px-1">Target</th>
        <th class="text-right py-2 px-1">RTT (ms)</th>
        <th class="text-left py-2 px-1">상태</th>
    </tr>`;
    let wirelessFullTheadHtml = null;   // 최초 유선 전환 시 원본 백업

    function renderPingFullTableWired() {
        if (!pingFullTable) return;
        const thead = document.getElementById('ping-full-thead');
        if (thead) {
            if (wirelessFullTheadHtml === null) wirelessFullTheadHtml = thead.innerHTML;
            thead.innerHTML = WIRED_FULL_THEAD;
        }
        const fStatus = pingStatusSel ? pingStatusSel.value : '';
        const rows = [];
        gtExchanges.forEach((e, idx) => {
            const isLoss = e.rtt_ms == null;
            if (fStatus === 'loss' && !isLoss) return;
            if (fStatus === 'matched' && isLoss) return;
            rows.push({ e, idx });
        });
        if (pingFullCount) pingFullCount.textContent = `${rows.length.toLocaleString()} / ${gtExchanges.length.toLocaleString()}건`;
        if (!rows.length) {
            pingFullTable.innerHTML = '<tr><td colspan="5" class="text-gray-500 text-center py-6">조건에 맞는 항목이 없습니다.</td></tr>';
            return;
        }
        pingFullTable.innerHTML = rows.map(({ e, idx }, i) => {
            const isLoss = e.rtt_ms == null;
            const badge = isLoss
                ? '<span class="bg-red-900 text-red-300 px-1.5 py-0.5 rounded text-xs font-bold">LOSS</span>'
                : '<span class="bg-green-900 text-green-300 px-1.5 py-0.5 rounded text-xs">OK</span>';
            return `<tr data-ex-idx="${idx}" class="border-b border-gray-700/30 ${isLoss ? 'text-red-400 bg-red-900/20' : ''} hover:bg-gray-700/30">
                <td class="py-1 px-1">${i + 1}</td>
                <td class="py-1 px-1">${new Date(e.epoch * 1000).toLocaleTimeString('en-GB')}.${String(Math.floor((e.epoch % 1) * 1000)).padStart(3, '0')}</td>
                <td class="py-1 px-1 font-mono">${escapeHtml(String(e.target ?? '?'))}</td>
                <td class="py-1 px-1 text-right font-mono">${isLoss ? '-' : e.rtt_ms.toFixed(2)}</td>
                <td class="py-1 px-1">${badge}</td>
            </tr>`;
        }).join('');
    }
```

- [ ] **Step 4: charts.js — 무선 전체 목록 행에 조인 키 추가 + 복원 훅**

`renderPingFullTable()`의 rows.map에서 원본 fullList 인덱스가 필요하다 — 필터 전 인덱스를 보존하도록 `fullList.filter(...)`를 인덱스 보존 형태로 최소 수정(예: `fullList.map((p, fi) => ({p, fi})).filter(...)`) 하고 `<tr ...>`에 `data-fl-idx="${fi}"` 속성을 추가한다. **표시 내용·필터 로직은 무변경** — 구조 변환만. 또한 무선 복원 시 thead 원복: `renderPingFullTable` 시작부에 `if (wirelessFullTheadHtml !== null) { document.getElementById('ping-full-thead').innerHTML = wirelessFullTheadHtml; wirelessFullTheadHtml = null; }` — 또는 renderPingSource의 무선 분기에서 처리 (구현 시 한 곳으로 통일).

- [ ] **Step 5: charts.js — renderPingSource 통합 + 필터·관찰 ICMP 가시성**

`renderPingSource(src)`의 유선/무선 분기에 추가:

```js
        const flowWrap = document.getElementById('ping-filter-flow-wrap');
        const retryWrap = document.getElementById('ping-filter-retry-wrap');
        const obsDetailsEl = document.getElementById('ping-observations-details');
        if (src === 'wired' && gtExchanges) {
            renderPingStreaksWired();
            renderPingFullTableWired();
            if (flowWrap) flowWrap.classList.add('hidden');
            if (retryWrap) retryWrap.classList.add('hidden');
            if (obsDetailsEl) obsDetailsEl.classList.add('hidden');
        } else {
            renderPingStreaksWireless();
            renderPingFullTable();
            if (flowWrap) flowWrap.classList.remove('hidden');
            if (retryWrap) retryWrap.classList.remove('hidden');
            if (obsDetailsEl) obsDetailsEl.classList.remove('hidden');
        }
```

주의: ① 관찰 ICMP 섹션은 데이터 없으면 원래 `style.display='none'` 유지 로직이 있다(`ping-observations-details`의 기존 표시 조건) — hidden 클래스 토글이 그 로직과 충돌하지 않는지 확인하고, 충돌하면 유선 분기에서만 숨기고 무선 분기에서는 **기존 표시 조건을 재평가**하는 방식으로. ② 상태 필터 select의 change 리스너가 현재 `renderPingFullTable`만 호출한다면, 현재 소스에 맞는 렌더러를 호출하도록 분기(현재 활성 소스를 모듈 변수 `currentPingSource`로 추적).

- [ ] **Step 6: 코드 레벨 검증 + 커밋**

Run: `node --check static/js/charts.js && python3 -m pytest tests/ -q && ruff check .`
Expected: 문법 OK, 957 passed, ruff clean.

```bash
git add static/js/charts.js templates/analysis.html
git commit -m "feat(front): ping 하단 3위젯 소스 토글 연동 — 유선 streak/전수 목록, 관찰 ICMP 숨김 (스펙 §1)"
```

---

### Task 2: 손실 X 마커 클릭 → 전체 목록 행 점프

**Files:**
- Modify: `static/js/charts.js` (손실 trace customdata 2곳 + plotly_click 핸들러 + 점프 헬퍼)

**Interfaces:**
- Consumes: Task 1의 행 속성(`data-ex-idx`/`data-fl-idx`)·`currentPingSource`·상태 필터 select, 유선 손실 trace(`renderPingRttWired`), 무선 손실 trace(기존 RTT 렌더의 losses)
- Produces: 손실 X 클릭 시 필터 '손실' 전환 → 해당 행 스크롤+2.5초 하이라이트. 응답 포인트 클릭은 무동작.

- [ ] **Step 1: customdata 부여**

- 유선: `renderPingRttWired`의 loss trace에 `customdata: loss.map(e => gtExchanges.indexOf(e))` — 단, `indexOf`는 O(n²)이므로 loss 구성 시점에 인덱스를 함께 만들도록 `gtExchanges.map((e, i) => ({e, i})).filter(x => x.e.rtt_ms == null)` 형태로 변경해 `customdata: loss.map(x => x.i)`. (ok trace는 변경 불요)
- 무선: 기존 RTT 렌더에서 `losses` 배열의 각 항목이 fullList의 어느 인덱스인지 — `losses` 구성부를 확인해 fullList 인덱스를 병행 보존(동일 패턴)하고 loss trace에 `customdata` 추가. **기존 표시 로직(text/marker/y값) 무수정** — customdata 필드 추가만.

- [ ] **Step 2: 점프 헬퍼 + 핸들러**

```js
    function jumpToPingRow(attrName, idx) {
        const sel = document.getElementById('ping-filter-status');
        if (sel && sel.value !== 'loss') {
            sel.value = 'loss';
            if (currentPingSource === 'wired') renderPingFullTableWired(); else renderPingFullTable();
        }
        const row = document.querySelector(`#ping-full-table tbody tr[${attrName}="${idx}"]`);
        if (!row) return;   // 탐색 실패 시 무동작 (throw 금지)
        row.scrollIntoView({ block: 'center', behavior: 'smooth' });
        row.classList.add('outline', 'outline-2', 'outline-yellow-400');
        setTimeout(() => row.classList.remove('outline', 'outline-2', 'outline-yellow-400'), 2500);
    }

    function bindPingRttClick() {
        const el = document.getElementById('chart-ping-rtt');
        if (!el || !el.on) return;   // Plotly 미렌더(빈 상태 innerHTML 교체) 시 무동작
        el.on('plotly_click', ev => {
            const pt = ev.points && ev.points[0];
            if (!pt || pt.customdata == null) return;   // 손실 trace만 customdata 보유
            jumpToPingRow(currentPingSource === 'wired' ? 'data-ex-idx' : 'data-fl-idx', pt.customdata);
        });
    }
```

- 바인딩 시점: `renderPingSource(src)`에서 RTT 차트 렌더 호출 **직후** `bindPingRttClick()` 호출 (newPlot이 노드를 재사용하므로 뷰 전환마다 재바인딩 — 중복 리스너 방지를 위해 Plotly의 `.removeAllListeners && el.removeAllListeners('plotly_click')`를 바인딩 전에 호출).
- 응답 trace에는 customdata가 없으므로 `pt.customdata == null` 가드로 자연 무시.

- [ ] **Step 3: 코드 레벨 검증 + 커밋**

Run: `node --check static/js/charts.js && ruff check .`

```bash
git add static/js/charts.js
git commit -m "feat(front): RTT 손실 X 클릭 → 전수 목록 행 점프 — 필터 전환+하이라이트 (스펙 §2)"
```

---

## 계획 자가 리뷰 결과

- **스펙 커버리지**: §1-1(streak 함수화+유선) Task 1 Step 2·3 ✓ / §1-2(전체 목록 유선+thead 교체+필터 가시성+조인 키) Step 1·3·4·5 ✓ / §1-3(관찰 숨김) Step 5 ✓ / §1-4(통합) Step 5 ✓ / §2(클릭 내비) Task 2 ✓ / §3 에러 표(streaks 없음·행 탐색 실패·Plotly 미렌더 가드) 반영 ✓
- **플레이스홀더**: 없음. 단 "기존 무선 streak 행 컬럼 수 확인" 등 2곳은 기존 코드 확인 지시(창작 아님).
- **타입 일관성**: `data-ex-idx`/`data-fl-idx` 속성명이 Task 1(생성)·Task 2(소비)에서 동일. `currentPingSource` 모듈 변수는 Task 1 Step 5(도입)·Task 2(소비) 일관.
- **알려진 리스크**: ① 관찰 ICMP의 기존 display 로직과 hidden 클래스 상호작용(Step 5 주의로 명시) ② 상태 필터 리스너의 소스 분기(Step 5 주의로 명시) — 구현자가 기존 코드를 확인해 정합 처리, 모호하면 질문.
