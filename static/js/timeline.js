/* 통합 타임라인 — RSSI + Retry + Ping RTT 동기화 서브플롯 */
(function () {
    if (typeof DATA === 'undefined') return;

    const signal = DATA.signal || {};
    const ping = DATA.ping || {};
    const perSec = DATA.per_second || {};
    const roaming = DATA.roaming || {};

    const timelineEl = document.getElementById('chart-timeline');
    if (!timelineEl) return;

    const traces = [];

    /* 패널 매핑 — checkbox dataset.panel 과 yaxis 키 연결 */
    const PANELS = ['rssi', 'retry', 'rtt', 'frames'];
    const PANEL_AXIS = { rssi: 'yaxis', retry: 'yaxis2', rtt: 'yaxis3', frames: 'yaxis4' };

    /* ── LTTB 다운샘플링 ── (라인용, 형태 보존) */
    function downsample(data, maxPoints) {
        if (data.length <= maxPoints) return data;
        const step = Math.ceil(data.length / maxPoints);
        const result = [data[0]];
        for (let i = 1; i < data.length - 1; i += step) {
            let maxArea = -1, maxIdx = i;
            for (let j = i; j < Math.min(i + step, data.length - 1); j++) {
                const area = Math.abs(
                    (data[j].x - result[result.length - 1].x) * (data[Math.min(j + step, data.length - 1)].y - result[result.length - 1].y) -
                    (data[Math.min(j + step, data.length - 1)].x - result[result.length - 1].x) * (data[j].y - result[result.length - 1].y)
                );
                if (area > maxArea) { maxArea = area; maxIdx = j; }
            }
            result.push(data[maxIdx]);
        }
        result.push(data[data.length - 1]);
        return result;
    }

    /* 단순 step 다운샘플 (마커 점들 — 형태 의미가 없을 때) */
    function downsampleStep(arr, maxPoints) {
        if (arr.length <= maxPoints) return arr;
        const step = Math.ceil(arr.length / maxPoints);
        return arr.filter((_, i) => i % step === 0);
    }

    function epochToDate(epoch) {
        return new Date(epoch * 1000);
    }

    /* ── 서브플롯 1: RSSI ──
     * STA 와 AP 둘 다 표시. 양쪽의 송신 frame에 대한 monitor adapter 수신 세기.
     * STA: 파란 계열, AP: 초록 계열로 색을 분리해 한눈에 구분.
     */
    const staColors = ['#3b82f6', '#60a5fa', '#a78bfa', '#8b5cf6'];  // 파란~보라
    const apColors  = ['#10b981', '#34d399', '#fbbf24', '#f59e0b'];  // 초록~노랑
    const staNames = Object.keys(signal.stas || {});
    const apNames  = Object.keys(signal.aps  || {});
    function rssiTrace(node, name, color) {
        const raw = (node.rssi_timeline || []).map(p => ({ x: p.epoch, y: p.rssi }));
        const sampled = downsample(raw, 2000);
        return {
            x: sampled.map(p => epochToDate(p.x)),
            y: sampled.map(p => p.y),
            type: 'scatter', mode: 'lines',
            name: name + ' RSSI',
            line: { color: color, width: 1 },
            xaxis: 'x', yaxis: 'y',
            hovertemplate: '%{x|%H:%M:%S} · %{y:.0f} dBm<extra></extra>',
            _panel: 'rssi',
        };
    }
    staNames.forEach((name, i) => {
        traces.push(rssiTrace(signal.stas[name], name, staColors[i % staColors.length]));
    });
    apNames.forEach((name, i) => {
        traces.push(rssiTrace(signal.aps[name], name, apColors[i % apColors.length]));
    });

    /* ── 서브플롯 2: Retry/sec ── */
    const timeline = perSec.timeline || [];
    if (timeline.length > 0) {
        const sampled = downsample(
            timeline.map(p => ({ x: p.epoch, y: p.retry })), 2000
        );
        traces.push({
            x: sampled.map(p => epochToDate(p.x)),
            y: sampled.map(p => p.y),
            type: 'scatter', mode: 'lines',
            name: 'Retry/sec',
            line: { color: '#ef4444', width: 1 },
            fill: 'tozeroy', fillcolor: 'rgba(239,68,68,0.1)',
            xaxis: 'x2', yaxis: 'y2',
            hovertemplate: '%{x|%H:%M:%S} · %{y:.0f} pkt/s<extra></extra>',
            _panel: 'retry',
        });
    }

    /* ── 서브플롯 3: Ping RTT ── 정상은 숨김(legendonly), 지연·loss만 강조 */
    const allPairs = ping.pairs || [];
    const rttsSorted = allPairs
        .map(p => p.rtt_ms).filter(v => v != null && v > 0)
        .sort((a, b) => a - b);
    // 임계값: P90(상위 10%) — 단 너무 낮으면 시각적 의미 없으니 50ms 하한
    const p90 = rttsSorted.length > 0
        ? rttsSorted[Math.floor(rttsSorted.length * 0.9)]
        : 50;
    const PING_DELAY_THRESHOLD = Math.max(p90, 50);
    const normalPairs  = downsampleStep(allPairs.filter(p => p.rtt_ms != null && p.rtt_ms <  PING_DELAY_THRESHOLD), 2000);
    const delayedPairs = allPairs.filter(p => p.rtt_ms != null && p.rtt_ms >= PING_DELAY_THRESHOLD);
    if (normalPairs.length > 0) {
        traces.push({
            x: normalPairs.map(p => epochToDate(p.epoch)),
            y: normalPairs.map(p => p.rtt_ms),
            type: 'scatter', mode: 'markers',
            name: `Ping 정상 (<${PING_DELAY_THRESHOLD.toFixed(0)}ms)`,
            marker: { color: 'rgba(16,185,129,0.6)', size: 2 },  // 살짝 투명한 녹색
            xaxis: 'x3', yaxis: 'y3',
            hovertemplate: '%{x|%H:%M:%S} · %{y:.1f} ms<extra></extra>',
            _panel: 'rtt',
        });
    }
    if (delayedPairs.length > 0) {
        traces.push({
            x: delayedPairs.map(p => epochToDate(p.epoch)),
            y: delayedPairs.map(p => p.rtt_ms),
            type: 'scatter', mode: 'markers',
            name: `Ping 지연 (≥${PING_DELAY_THRESHOLD.toFixed(0)}ms)`,
            marker: { color: '#f97316', size: 5 },
            xaxis: 'x3', yaxis: 'y3',
            hovertemplate: '%{x|%H:%M:%S} · %{y:.1f} ms<extra></extra>',
            _panel: 'rtt',
        });
    }
    // Ping loss 마커 — 항상 × 마커로 표시 (막대는 저-RTT pair 영역을 가려 오해 유발)
    // 손실 위치는 차트 상단(rtt_max * 1.1)에 찍어 RTT trace 위에 떠 있게 함.
    const losses = downsampleStep(ping.losses || [], 1000);
    if (losses.length > 0) {
        const rttMax = rttsSorted.length > 0 ? rttsSorted[rttsSorted.length - 1] : 1;
        const lossY = rttMax > 0 ? rttMax * 1.1 : 1;
        traces.push({
            x: losses.map(p => epochToDate(p.epoch)),
            y: losses.map(() => lossY),
            type: 'scatter', mode: 'markers',
            name: `Ping Loss (${losses.length}건)`,
            marker: { symbol: 'x', color: '#ef4444', size: 10, line: { width: 2 } },
            xaxis: 'x3', yaxis: 'y3',
            hovertemplate: '%{x|%H:%M:%S} · loss seq=%{customdata}<extra></extra>',
            customdata: losses.map(p => p.seq || '?'),
            _panel: 'rtt',
        });
    }

    /* ── 서브플롯 4: 프레임/sec ── */
    if (timeline.length > 0) {
        const sampled = downsample(
            timeline.map(p => ({ x: p.epoch, y: p.total })), 2000
        );
        traces.push({
            x: sampled.map(p => epochToDate(p.x)),
            y: sampled.map(p => p.y),
            type: 'scatter', mode: 'lines',
            name: 'Frames/sec',
            line: { color: '#6b7280', width: 1 },
            fill: 'tozeroy', fillcolor: 'rgba(107,114,128,0.1)',
            xaxis: 'x4', yaxis: 'y4',
            hovertemplate: '%{x|%H:%M:%S} · %{y:.0f} pkt/s<extra></extra>',
            _panel: 'frames',
        });
    }

    /* ── 로밍 이벤트 세로 점선 ── (그룹 토글용 _kind 메타 부여) */
    const allShapes = [];
    const seqs = roaming.sequences || [];
    seqs.forEach(s => {
        const t = epochToDate(s.auth_epoch);
        allShapes.push({
            _kind: 'roaming',
            type: 'line', x0: t, x1: t, y0: 0, y1: 1, yref: 'paper',
            line: { color: 'rgba(245,158,11,0.3)', dash: 'dot', width: 1 },
        });
    });

    /* ── 이상 구간 하이라이트 (빨간 배경) ── */
    const delays = DATA.delay_zones || {};
    const zones = delays.delay_zones || [];
    zones.forEach(z => {
        allShapes.push({
            _kind: 'zone',
            type: 'rect',
            x0: epochToDate(z.start_epoch), x1: epochToDate(z.end_epoch),
            y0: 0, y1: 1, yref: 'paper',
            fillcolor: 'rgba(239,68,68,0.1)',
            line: { width: 0 },
            layer: 'below',
        });
    });

    /* ── RSSI cliff 마커 ── (그룹 토글용 _overlay 메타 부여) */
    const cliffs = DATA.signal_cliffs || {};
    const cliffColors = ['#f97316', '#ec4899', '#8b5cf6'];
    let ci = 0;
    for (const [staName, cliffData] of Object.entries(cliffs)) {
        const events = cliffData.cliffs || [];
        if (events.length > 0) {
            traces.push({
                x: events.map(e => epochToDate(e.epoch)),
                y: events.map(e => e.rssi_before),
                type: 'scatter', mode: 'markers',
                name: staName + ' RSSI Cliff',
                marker: { color: cliffColors[ci % cliffColors.length], size: 7, symbol: 'triangle-down' },
                xaxis: 'x', yaxis: 'y',
                text: events.map(e => `${e.drop_db}dB drop in ${e.duration_sec}s`),
                hovertemplate: '%{x|%H:%M:%S} · %{text}<extra></extra>',
                _panel: 'rssi',
                _overlay: 'cliff',
            });
            ci++;
        }
    }

    const GRID = 'rgba(255,255,255,0.05)';
    const SPIKE = { showspikes: true, spikemode: 'across', spikethickness: 1, spikecolor: '#9ca3af', spikedash: 'dot' };
    const HOVERLABEL = {
        bgcolor: 'rgba(15,23,42,0.95)',  // slate-900 + 알파
        bordercolor: '#64748b',           // slate-500
        font: { color: '#f1f5f9', size: 12 },  // slate-100 (밝은 흰)
        namelength: -1,  // trace name truncate 방지 (기본 15자)
    };
    const HOVER_X = { hoverformat: '%Y-%m-%d %H:%M:%S' };  // 박스 상단에 날짜 + 시각
    const layout = {
        paper_bgcolor: 'rgba(0,0,0,0)',
        plot_bgcolor: 'rgba(0,0,0,0)',
        font: { color: '#9ca3af', size: 10 },
        showlegend: false,  // 외부 사이드바로 대체
        dragmode: 'pan',
        hovermode: 'x unified',
        hoverlabel: HOVERLABEL,
        uirevision: 'keep',  // pan/zoom 후 사용자 axis 상태 유지
        xaxis:  { anchor: 'y',  domain: [0, 1], showticklabels: false, gridcolor: GRID, ...SPIKE, ...HOVER_X },
        xaxis2: { anchor: 'y2', domain: [0, 1], showticklabels: false, matches: 'x', gridcolor: GRID, ...SPIKE, ...HOVER_X },
        xaxis3: { anchor: 'y3', domain: [0, 1], showticklabels: false, matches: 'x', gridcolor: GRID, ...SPIKE, ...HOVER_X },
        xaxis4: { anchor: 'y4', domain: [0, 1], matches: 'x', gridcolor: GRID, ...SPIKE, ...HOVER_X },
        yaxis:  { title: 'RSSI (dBm)', domain: [0.78, 1.0], gridcolor: GRID },
        yaxis2: { title: 'Retry/s',    domain: [0.53, 0.75], gridcolor: GRID },
        yaxis3: { title: 'RTT (ms)',   domain: [0.28, 0.50], gridcolor: GRID },
        yaxis4: { title: 'Frames/s',   domain: [0.00, 0.25], gridcolor: GRID },
        shapes: allShapes.map(({ _kind, ...rest }) => rest),
        margin: { t: 20, r: 20, b: 40, l: 60 },
    };

    if (traces.length === 0) {
        timelineEl.innerHTML = '<p class="text-gray-500 text-center py-20">시계열 데이터가 없습니다.</p>';
        return;
    }

    Plotly.newPlot(timelineEl, traces, layout, {
        responsive: true,
        displayModeBar: true,
        scrollZoom: true,
        doubleClick: 'reset+autosize',
        modeBarButtonsToRemove: ['lasso2d', 'select2d'],
    });

    /* ── 패널 토글 ── 체크박스 변경 시 도메인 재배치 + trace visible ── */
    function applyPanelLayout(enabled) {
        if (enabled.length === 0) return;
        const order = PANELS.filter(p => enabled.includes(p));
        const gap = 0.04;
        const each = (1 - gap * Math.max(0, order.length - 1)) / order.length;
        const updates = {};
        let top = 1.0;
        order.forEach(p => {
            const axis = PANEL_AXIS[p];
            const bot = top - each;
            updates[`${axis}.domain`] = [Number(bot.toFixed(4)), Number(top.toFixed(4))];
            updates[`${axis}.visible`] = true;
            top = bot - gap;
        });
        PANELS.filter(p => !enabled.includes(p)).forEach(p => {
            const axis = PANEL_AXIS[p];
            updates[`${axis}.visible`] = false;
            updates[`${axis}.domain`] = [0, 0.001];
        });
        Plotly.relayout(timelineEl, updates);
        // 트레이스 visible: 비활성 패널 트레이스만 숨김. 사이드바 체크박스 상태는 보존.
        const visibleArr = timelineEl.data.map(t => {
            if (!t._panel) return t.visible !== false ? true : false;
            if (!enabled.includes(t._panel)) return false;
            // 패널은 켜져 있고 — 사이드바 상태대로
            return t._userVisible !== false;
        });
        Plotly.restyle(timelineEl, { visible: visibleArr });
        renderTraceLegend();  // 사이드바 활성/비활성 갱신
    }

    const toggleBoxes = document.querySelectorAll('.timeline-toggle');
    toggleBoxes.forEach(cb => {
        cb.addEventListener('change', () => {
            const enabled = Array.from(toggleBoxes).filter(x => x.checked).map(x => x.dataset.panel);
            if (enabled.length === 0) {
                cb.checked = true;
                return;
            }
            applyPanelLayout(enabled);
        });
    });

    /* ── 단독 보기 버튼 ── 그 패널만 켜고 나머지 끔 ── */
    document.querySelectorAll('.timeline-solo').forEach(btn => {
        btn.addEventListener('click', e => {
            e.preventDefault();
            const target = btn.dataset.panel;
            toggleBoxes.forEach(cb => { cb.checked = cb.dataset.panel === target; });
            applyPanelLayout([target]);
        });
    });

    /* ── 전체 표시 버튼 ── */
    const showAllBtn = document.querySelector('.timeline-show-all');
    if (showAllBtn) {
        showAllBtn.addEventListener('click', e => {
            e.preventDefault();
            toggleBoxes.forEach(cb => { cb.checked = true; });
            applyPanelLayout(PANELS.slice());
        });
    }

    /* ── 오버레이 토글 ── 로밍 점선 / 이상 구간 / RSSI Cliff ── */
    function applyOverlayToggle() {
        const want = {
            roaming: document.querySelector('.timeline-overlay[data-overlay="roaming"]')?.checked ?? true,
            zone:    document.querySelector('.timeline-overlay[data-overlay="zone"]')?.checked    ?? true,
            cliff:   document.querySelector('.timeline-overlay[data-overlay="cliff"]')?.checked   ?? true,
        };
        const filteredShapes = allShapes
            .filter(s => want[s._kind])
            .map(({ _kind, ...rest }) => rest);
        Plotly.relayout(timelineEl, { shapes: filteredShapes });
        // cliff trace는 panel toggle과 별개 — _overlay 기준으로도 토글
        const visibleArr = timelineEl.data.map(t => {
            if (t._overlay === 'cliff' && !want.cliff) return false;
            if (t._panel) {
                const cb = document.querySelector(`.timeline-toggle[data-panel="${t._panel}"]`);
                return !cb || cb.checked;
            }
            return true;
        });
        Plotly.restyle(timelineEl, { visible: visibleArr });
    }
    document.querySelectorAll('.timeline-overlay').forEach(cb => {
        cb.addEventListener('change', applyOverlayToggle);
    });
    // 첫 로드 시 체크박스 상태(default: 로밍 OFF) 즉시 반영
    applyOverlayToggle();

    /* ── 외부 사이드바 범례 ── 트레이스별 체크박스 ── */
    function traceColor(t) {
        return (t.line && t.line.color) || (t.marker && t.marker.color) || '#888';
    }
    function renderTraceLegend() {
        const lg = document.getElementById('timeline-legend');
        if (!lg) return;
        const groups = {};
        timelineEl.data.forEach((t, idx) => {
            const p = t._panel || 'misc';
            (groups[p] = groups[p] || []).push({ t, idx });
        });
        const PANEL_LABELS = { rssi: 'RSSI', retry: 'Retry/s', rtt: 'Ping RTT', frames: 'Frames/s', misc: '기타' };
        const html = PANELS.concat(['misc']).filter(p => groups[p]).map(p => {
            const enabled = !document.querySelector(`.timeline-toggle[data-panel="${p}"]`)
                || document.querySelector(`.timeline-toggle[data-panel="${p}"]`).checked;
            const items = groups[p].map(({ t, idx }) => {
                const visible = t.visible !== false && t.visible !== 'legendonly';
                const c = traceColor(t);
                return `<label class="flex items-center gap-2 py-0.5 px-2 hover:bg-gray-700 rounded cursor-pointer text-xs ${visible && enabled ? '' : 'opacity-40'}" data-trace-idx="${idx}">
                    <input type="checkbox" ${visible ? 'checked' : ''} ${enabled ? '' : 'disabled'} class="trace-toggle accent-blue-500" data-trace-idx="${idx}">
                    <span class="inline-block w-3 h-3 rounded flex-shrink-0" style="background:${c}"></span>
                    <span class="truncate" title="${t.name}">${t.name}</span>
                </label>`;
            }).join('');
            return `<div class="mb-2">
                <div class="text-[10px] uppercase tracking-wide text-gray-500 px-2 mb-1">${PANEL_LABELS[p] || p}</div>
                ${items}
            </div>`;
        }).join('');
        lg.innerHTML = html;
        lg.querySelectorAll('.trace-toggle').forEach(cb => {
            cb.addEventListener('change', () => {
                const idx = parseInt(cb.dataset.traceIdx, 10);
                timelineEl.data[idx]._userVisible = cb.checked;
                Plotly.restyle(timelineEl, { visible: cb.checked }, [idx]);
                cb.closest('label').classList.toggle('opacity-40', !cb.checked);
            });
        });
    }
    renderTraceLegend();

    /* ── 패널 높이 슬라이더 ── */
    const heightSlider = document.getElementById('timeline-height');
    const heightLabel = document.getElementById('timeline-height-label');
    if (heightSlider) {
        heightSlider.addEventListener('input', () => {
            const h = heightSlider.value + 'px';
            timelineEl.style.height = h;
            const lg = document.getElementById('timeline-legend');
            if (lg) lg.style.maxHeight = h;
            if (heightLabel) heightLabel.textContent = heightSlider.value + 'px';
            Plotly.Plots.resize(timelineEl);
        });
    }

    /* ── 종합 진단 텍스트 로드 ── */
    const diagEl = document.getElementById('diagnosis-text');
    if (diagEl) {
        const result = window.__RESULT_FULL;
        if (result && result.text_sections) {
            const diag = result.text_sections.find(s => s.title.includes('진단'));
            if (diag) diagEl.textContent = diag.lines.join('\n');
        }
    }

    /* ══════════════════════════════════════════════════════════════════
     * 디버그 미니차트 — debug.axis 공유 시간축 위에 debug.series 정렬 표시
     *
     * 메인 4-panel 타임라인은 raw + LTTB 다운샘플로 그리지만, 진단 결론은
     * build_debug_block이 만든 공유 bin(axis)에 다운샘플된 series로부터
     * frame_refs/time_window를 도출한다. 이 미니차트는 그 공유 bin 위에
     * RSSI band+mean / Retry% / Ping Loss% / Roaming 마커를 모두 같은
     * x축으로 정렬해 보여줘서, 진단 결론과 시계열 시간 위치가 시각적으로
     * 일치한다는 점을 검증·탐색할 수 있게 한다.
     * ════════════════════════════════════════════════════════════════ */
    const debug = DATA.debug || {};
    const debugAxis = debug.axis || {};
    const debugSeries = debug.series || {};
    const debugMiniEl = document.getElementById('chart-debug-mini');
    const debugMetaEl = document.getElementById('debug-series-meta');
    // sync 호출이 타겟할 master x-axis 키. buildDebugMini에서 활성 panel 첫 번째의
    // xaxis 키로 갱신된다. RSSI가 비활성이면 'xaxis2' 등이 되며, 그래야 zoom sync가
    // 보이는 축을 타겟해 동작한다.
    let debugMiniMasterKey = 'xaxis';

    function buildDebugMini() {
        if (!debugMiniEl) return;
        // 매 빌드 시작 시 안전한 기본값으로 리셋. early-return으로 차트가 비어
        // 그려지지 못해도, 이전 빌드의 masterKey가 stale로 남아 sync 호출이
        // 사라진 축을 타겟하는 일을 막는다. innerHTML='...' 후에도 Plotly가
        // 노드에 저장한 .data 프로퍼티가 truthy로 살아남을 수 있음에 유의.
        debugMiniMasterKey = 'xaxis';
        if (!debugAxis.bin_count || debugAxis.empty) {
            debugMiniEl.innerHTML = '<p class="text-gray-500 text-center py-12 text-xs">디버그 시계열 데이터 없음 (공유 시간축 비어있음).</p>';
            if (debugMetaEl) debugMetaEl.textContent = '';
            return;
        }

        const rssiPts = debugSeries.rssi || [];
        const retryPts = debugSeries.retry || [];
        const pingPts = debugSeries.ping || [];
        const roamingPts = debugSeries.roaming || [];

        if (debugMetaEl) {
            const dur = debugAxis.duration_sec || 0;
            const binSize = debugAxis.bin_size_sec || 0;
            debugMetaEl.textContent = `${debugAxis.bin_count} bins · ${binSize.toFixed(2)}s/bin · 총 ${dur.toFixed(1)}s`;
        }

        const dTraces = [];

        // RSSI: min/max 영역(fill) + mean line
        if (rssiPts.length) {
            const xs = rssiPts.map(p => epochToDate(p.epoch));
            dTraces.push({
                x: xs, y: rssiPts.map(p => p.rssi_max),
                type: 'scatter', mode: 'lines',
                name: 'RSSI max',
                line: { width: 0 },
                xaxis: 'x', yaxis: 'y',
                hoverinfo: 'skip', showlegend: false,
            });
            dTraces.push({
                x: xs, y: rssiPts.map(p => p.rssi_min),
                type: 'scatter', mode: 'lines',
                name: 'RSSI min/max',
                line: { width: 0 },
                fill: 'tonexty', fillcolor: 'rgba(96,165,250,0.18)',
                xaxis: 'x', yaxis: 'y',
                hoverinfo: 'skip',
            });
            dTraces.push({
                x: xs, y: rssiPts.map(p => p.rssi),
                type: 'scatter', mode: 'lines',
                name: 'RSSI mean',
                line: { color: '#3b82f6', width: 1.6 },
                xaxis: 'x', yaxis: 'y',
                customdata: rssiPts.map(p => [p.rssi_min, p.rssi_max, p.count]),
                hovertemplate: '%{x|%H:%M:%S} · mean %{y:.1f} dBm · min %{customdata[0]} / max %{customdata[1]} · n=%{customdata[2]}<extra></extra>',
            });
        }

        // Retry %: per-bin bar
        if (retryPts.length) {
            dTraces.push({
                x: retryPts.map(p => epochToDate(p.epoch)),
                y: retryPts.map(p => p.retry_pct),
                type: 'bar', name: 'Retry %',
                marker: { color: 'rgba(239,68,68,0.75)' },
                xaxis: 'x2', yaxis: 'y2',
                customdata: retryPts.map(p => [p.retry, p.total]),
                hovertemplate: '%{x|%H:%M:%S} · %{y:.1f}% (%{customdata[0]}/%{customdata[1]} frames)<extra></extra>',
            });
        }

        // Ping Loss %: per-bin bar
        if (pingPts.length) {
            dTraces.push({
                x: pingPts.map(p => epochToDate(p.epoch)),
                y: pingPts.map(p => p.loss_pct),
                type: 'bar', name: 'Loss %',
                marker: { color: 'rgba(249,115,22,0.8)' },
                xaxis: 'x3', yaxis: 'y3',
                customdata: pingPts.map(p => [p.loss, p.total]),
                hovertemplate: '%{x|%H:%M:%S} · %{y:.1f}% (loss %{customdata[0]} / total %{customdata[1]})<extra></extra>',
            });
        }

        // Roaming markers — auth=▼(y=1), assoc=▽(y=2)
        // strict mode에서 블록 안 function 선언은 동작이 미묘하므로 arrow 사용.
        const roamTrace = (pts, name, yLevel, color) => {
            if (!pts.length) return null;
            return {
                x: pts.map(p => epochToDate(p.epoch)),
                y: pts.map(() => yLevel),
                type: 'scatter', mode: 'markers',
                name: name,
                marker: { symbol: 'triangle-down', color: color, size: 10, line: { color: '#92400e', width: 1 } },
                xaxis: 'x4', yaxis: 'y4',
                text: pts.map(p => `STA=${p.sta || '?'} → AP=${p.ap || '?'} · frame#${p.frame_number != null ? p.frame_number : '?'}`),
                hovertemplate: `%{x|%H:%M:%S} · ${name} · %{text}<extra></extra>`,
            };
        };
        if (roamingPts.length) {
            const authPts = roamingPts.filter(p => p.kind === 'auth');
            const assocPts = roamingPts.filter(p => p.kind === 'assoc');
            const tA = roamTrace(authPts, 'Auth', 1, '#f59e0b');
            const tB = roamTrace(assocPts, 'Assoc', 2, '#f97316');
            if (tA) dTraces.push(tA);
            if (tB) dTraces.push(tB);
        }

        if (!dTraces.length) {
            debugMiniEl.innerHTML = '<p class="text-gray-500 text-center py-12 text-xs">공유 축은 있으나 시계열 데이터가 비어있습니다.</p>';
            return;
        }

        const retryMax = retryPts.reduce((m, p) => Math.max(m, p.retry_pct || 0), 0);
        const lossMax = pingPts.reduce((m, p) => Math.max(m, p.loss_pct || 0), 0);

        // 빈 panel 자동 collapse — 활성 panel만 도메인 분배 (메인 applyPanelLayout 패턴).
        // roaming has: roamingPts.length > 0이어도 모든 kind가 unknown이면 trace가 안
        // 생성되므로 실제 roamTrace 생성 조건과 일치시킴.
        const panelSpecs = [
            { xaxis: 'xaxis', yaxis: 'yaxis', yAnchor: 'y', has: rssiPts.length > 0,
              yspec: { title: 'RSSI (dBm)' } },
            { xaxis: 'xaxis2', yaxis: 'yaxis2', yAnchor: 'y2', has: retryPts.length > 0,
              yspec: { title: 'Retry %', range: [0, Math.max(10, retryMax * 1.1)] } },
            { xaxis: 'xaxis3', yaxis: 'yaxis3', yAnchor: 'y3', has: pingPts.length > 0,
              yspec: { title: 'Loss %', range: [0, Math.max(10, lossMax * 1.1)] } },
            { xaxis: 'xaxis4', yaxis: 'yaxis4', yAnchor: 'y4',
              has: roamingPts.some(p => p.kind === 'auth' || p.kind === 'assoc'),
              yspec: { title: 'Roam', showticklabels: false, range: [0.4, 2.6] } },
        ];
        const activePanels = panelSpecs.filter(p => p.has);
        const N = activePanels.length;
        // !dTraces.length 조기 return으로 N >= 1 보장됨.
        const gap = 0.04;
        const each = (1 - gap * (N - 1)) / N;

        // master x-axis = 첫 번째 활성 panel. RSSI가 비활성이면 xaxis가 visible:false라
        // 다른 활성 panel이 matches:'x' 고정하면 hidden 축 참조로 동기화가 깨진다.
        // sync 호출도 같은 키를 타겟해야 메인↔미니 zoom이 유지된다.
        const masterKey = activePanels[0].xaxis;
        // 'xaxis' → 'x', 'xaxis2' → 'x2' (xaxis 케이스도 replace 결과가 'x'라 분기 불필요).
        const masterX = masterKey.replace('xaxis', 'x');
        debugMiniMasterKey = masterKey;

        const dLayout = {
            paper_bgcolor: 'rgba(0,0,0,0)',
            plot_bgcolor: 'rgba(0,0,0,0)',
            font: { color: '#9ca3af', size: 10 },
            showlegend: true,
            legend: { orientation: 'h', y: 1.12, font: { size: 10 } },
            dragmode: 'pan',
            hovermode: 'x unified',
            hoverlabel: HOVERLABEL,
            uirevision: 'keep-debug',
            margin: { t: 30, r: 20, b: 30, l: 60 },
        };

        let top = 1.0;
        activePanels.forEach((p, idx) => {
            const bot = top - each;
            const isLast = idx === activePanels.length - 1;
            dLayout[p.xaxis] = {
                anchor: p.yAnchor,
                domain: [0, 1],
                showticklabels: isLast,
                gridcolor: GRID,
                ...SPIKE,
                ...HOVER_X,
                ...(p.xaxis !== activePanels[0].xaxis ? { matches: masterX } : {}),
            };
            dLayout[p.yaxis] = {
                ...p.yspec,
                domain: [Math.max(0, +bot.toFixed(4)), +top.toFixed(4)],
                gridcolor: GRID,
            };
            top = bot - gap;
        });

        // 비활성 panel: visible:false + 작은 domain. matches 지정 없음(보이지 않으므로).
        panelSpecs.filter(p => !p.has).forEach(p => {
            dLayout[p.xaxis] = { visible: false, domain: [0, 0.001] };
            dLayout[p.yaxis] = { visible: false, domain: [0, 0.001] };
        });
        Plotly.newPlot(debugMiniEl, dTraces, dLayout, {
            responsive: true,
            displayModeBar: false,
            scrollZoom: true,
            doubleClick: 'reset+autosize',
        });
    }
    buildDebugMini();

    /* ══════════════════════════════════════════════════════════════════
     * 증거 프레임 테이블 + 타임라인 양방향 동기화 (디버그 모드)
     *
     * - structured.debug.frames(8개 컬럼)로 표를 채운다.
     * - 타임라인 x축 범위가 바뀌면(드래그/휠/relayout) 표를 그 epoch 범위로 필터.
     * - 표 상단 시간범위 입력을 적용하면 타임라인 x축을 그 범위로 줌(역방향).
     * - 진단 탭의 "증거 보기" 점프(window.TimelineDebug.focus)는 타임라인을
     *   time_window로 줌 + 해당 frame_refs를 표에서 하이라이트.
     * ════════════════════════════════════════════════════════════════ */
    const debugFrames = debug.frames || [];
    const tbody = document.querySelector('#debug-frames-table tbody');
    const countEl = document.getElementById('debug-frames-count');
    const startInput = document.getElementById('debug-range-start');
    const endInput = document.getElementById('debug-range-end');

    // frame.number → epoch 매핑 (필터/하이라이트용). debug.axis로 epoch 추정 불가한
    // 행은 timestamp 문자열만 있고 epoch이 없을 수 있어, ping/roaming series의 epoch도
    // 참고하지 않고 frame_to_row의 timestamp는 표시용으로만 쓴다. 필터는 행의 epoch이
    // 필요하므로 debug.frames 각 행에 epoch을 함께 싣지 않은 경우 전체만 보여준다.
    let highlightSet = new Set();

    function escapeHtml(s) {
        return String(s == null ? '' : s).replace(/[<&>]/g, c => (
            { '<': '&lt;', '&': '&amp;', '>': '&gt;' }[c]
        ));
    }

    function rowEpoch(row) {
        // frame_to_row는 epoch을 직접 싣지 않지만, pipeline이 debug.frames에 epoch을
        // 부가하면 사용. 없으면 null(필터 시 항상 포함).
        return (typeof row.epoch === 'number') ? row.epoch : null;
    }

    function renderFrameTable(rangeStart, rangeEnd) {
        if (!tbody) return;
        let rows = debugFrames;
        if (rangeStart != null && rangeEnd != null) {
            rows = debugFrames.filter(r => {
                const e = rowEpoch(r);
                if (e == null) return true;  // epoch 미상 행은 항상 표시
                return e >= rangeStart && e <= rangeEnd;
            });
        }
        if (countEl) {
            countEl.textContent = `${rows.length.toLocaleString()} / ${debugFrames.length.toLocaleString()} 프레임`
                + (highlightSet.size ? ` · 증거 ${highlightSet.size}건` : '');
        }
        if (rows.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-gray-500 text-center py-6">선택 구간에 프레임이 없습니다.</td></tr>';
            return;
        }
        tbody.innerHTML = rows.map(r => {
            const hl = highlightSet.has(r.number);
            const retry = r.retry ? '<span class="text-red-400">R</span>' : '';
            const mcs = (r.mcs == null) ? '' : r.mcs;
            const rssi = (r.rssi == null) ? '' : r.rssi;
            const reason = r.reason_code ? escapeHtml(r.reason_code) : '';
            const cls = hl
                ? 'bg-yellow-900/40 border-l-2 border-yellow-500'
                : 'hover:bg-gray-700/40';
            return `<tr class="${cls}" data-fnum="${r.number}">
                <td class="py-1 px-1">${r.number}</td>
                <td class="py-1 px-1 text-gray-400">${escapeHtml(r.timestamp)}</td>
                <td class="py-1 px-1">${escapeHtml(r.type_subtype)}</td>
                <td class="py-1 px-1 text-center">${retry}</td>
                <td class="py-1 px-1 text-right">${mcs}</td>
                <td class="py-1 px-1 text-right ${rssi !== '' && rssi < -70 ? 'text-orange-400' : ''}">${rssi}</td>
                <td class="py-1 px-1">${reason}</td>
                <td class="py-1 px-1 text-gray-400">${escapeHtml(r.seq)}</td>
            </tr>`;
        }).join('');
    }
    renderFrameTable(null, null);

    /* ── 타임라인 x축 범위 변경 → 표 필터 (브러시/줌/팬) ── */
    let _syncingFromTable = false;
    timelineEl.on && timelineEl.on('plotly_relayout', (ev) => {
        if (_syncingFromTable) return;
        let r0, r1;
        if (ev['xaxis.range[0]'] != null && ev['xaxis.range[1]'] != null) {
            r0 = ev['xaxis.range[0]'];
            r1 = ev['xaxis.range[1]'];
        } else if (ev['xaxis.range'] && ev['xaxis.range'].length === 2) {
            r0 = ev['xaxis.range'][0];
            r1 = ev['xaxis.range'][1];
        } else if (ev['xaxis.autorange']) {
            renderFrameTable(null, null);
            if (startInput) startInput.value = '';
            if (endInput) endInput.value = '';
            // 메인이 autorange면 미니차트도 같이 풀어준다 (양방향 동기화).
            if (debugMiniEl && debugMiniEl.data) {
                Plotly.relayout(debugMiniEl, { [`${debugMiniMasterKey}.autorange`]: true })
                    .catch(err => console.debug('[debug-mini]', err));
            }
            return;
        } else {
            return;
        }
        // Plotly date axis는 ms 문자열/Date → epoch(초)로 변환
        const s = new Date(r0).getTime() / 1000;
        const e = new Date(r1).getTime() / 1000;
        // invalid range(예: new Date(undefined) → NaN)는 표 필터를 깨뜨리므로 방어
        if (isNaN(s) || isNaN(e)) return;
        if (startInput) startInput.value = s.toFixed(1);
        if (endInput) endInput.value = e.toFixed(1);
        renderFrameTable(s, e);
        // 메인 차트를 마우스로 직접 줌/팬할 때도 미니차트가 같이 움직이도록 동기화.
        // (applyRangeToTimeline 경로와는 별개 — 이 핸들러는 메인→미니 단방향 동기화 담당)
        if (debugMiniEl && debugMiniEl.data) {
            Plotly.relayout(debugMiniEl, { [`${debugMiniMasterKey}.range`]: [r0, r1] })
                .catch(err => console.debug('[debug-mini]', err));
        }
    });

    /* ── 표 상단 시간범위 입력 → 타임라인 줌 (역방향) ── */
    function applyRangeToTimeline(s, e) {
        if (s == null || e == null || isNaN(s) || isNaN(e)) return;
        _syncingFromTable = true;
        const range = [epochToDate(s), epochToDate(e)];
        // finally — relayout이 실패해도 _syncingFromTable 플래그를 반드시 해제하여
        // 영구 잠금(table→timeline 동기화 영구 차단)을 방지.
        Plotly.relayout(timelineEl, { 'xaxis.range': range })
            .finally(() => { _syncingFromTable = false; });
        // 디버그 미니차트도 같은 범위로 줌 (Plotly.newPlot 호출됐는지 확인)
        if (debugMiniEl && debugMiniEl.data) {
            Plotly.relayout(debugMiniEl, { [`${debugMiniMasterKey}.range`]: range })
                .catch(err => console.debug('[debug-mini]', err));
        }
        renderFrameTable(s, e);
    }
    const applyBtn = document.getElementById('debug-range-apply');
    if (applyBtn) {
        applyBtn.addEventListener('click', () => {
            const s = parseFloat(startInput.value);
            const e = parseFloat(endInput.value);
            applyRangeToTimeline(s, e);
        });
    }
    const clearBtn = document.getElementById('debug-range-clear');
    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            highlightSet = new Set();
            if (startInput) startInput.value = '';
            if (endInput) endInput.value = '';
            _syncingFromTable = true;
            Plotly.relayout(timelineEl, { 'xaxis.autorange': true })
                .finally(() => { _syncingFromTable = false; });
            if (debugMiniEl && debugMiniEl.data) {
                Plotly.relayout(debugMiniEl, { [`${debugMiniMasterKey}.autorange`]: true })
                    .catch(err => console.debug('[debug-mini]', err));
            }
            renderFrameTable(null, null);
        });
    }

    /* ── 진단 탭 → 타임라인 점프 API (cross-tab) ──
     * window.TimelineDebug.focus({start, end, frameRefs}) 호출 시:
     *   1) 통합 타임라인 탭으로 전환
     *   2) 타임라인 x축을 time_window로 줌 (±패딩)
     *   3) frame_refs를 표에서 하이라이트 + 그 구간으로 필터
     */
    window.TimelineDebug = {
        focus(opts) {
            opts = opts || {};
            const refs = opts.frameRefs || [];
            highlightSet = new Set(refs);

            // 탭 전환
            const tabBtn = document.querySelector('.tab-btn[data-tab="timeline"]');
            if (tabBtn) tabBtn.click();

            let s = opts.start, e = opts.end;
            if (s == null || e == null) {
                // window가 없으면 frame_refs의 행 epoch로 대체
                const eps = debugFrames
                    .filter(r => highlightSet.has(r.number))
                    .map(rowEpoch).filter(v => v != null);
                if (eps.length) { s = Math.min(...eps); e = Math.max(...eps); }
            }
            if (s != null && e != null) {
                const pad = Math.max((e - s) * 0.25, 1.0);  // 가독성 ±패딩
                const ps = s - pad, pe = e + pad;
                if (startInput) startInput.value = ps.toFixed(1);
                if (endInput) endInput.value = pe.toFixed(1);
                // 탭 전환 직후 차트 resize 타이밍을 고려해 다음 프레임에 적용
                requestAnimationFrame(() => applyRangeToTimeline(ps, pe));
                // 하이라이트는 줌과 무관하게 전체 범위에서도 보이도록 즉시 렌더
                renderFrameTable(ps, pe);
            } else {
                renderFrameTable(null, null);
            }
            // 증거 행으로 스크롤
            requestAnimationFrame(() => {
                const first = tbody && tbody.querySelector('tr.bg-yellow-900\\/40');
                if (first) first.scrollIntoView({ block: 'center', behavior: 'smooth' });
            });
        },
    };
})();
