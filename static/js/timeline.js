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

    /* ── 서브플롯 1: RSSI ── */
    const staNames = Object.keys(signal.stas || {});
    const colors = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6'];
    staNames.forEach((name, i) => {
        const sta = signal.stas[name];
        const raw = (sta.rssi_timeline || []).map(p => ({ x: p.epoch, y: p.rssi }));
        const sampled = downsample(raw, 2000);
        traces.push({
            x: sampled.map(p => epochToDate(p.x)),
            y: sampled.map(p => p.y),
            type: 'scatter', mode: 'lines',
            name: name + ' RSSI',
            line: { color: colors[i % colors.length], width: 1 },
            xaxis: 'x', yaxis: 'y',
            _panel: 'rssi',
        });
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
            _panel: 'retry',
        });
    }

    /* ── 서브플롯 3: Ping RTT ── */
    const pairs = downsampleStep(ping.pairs || [], 2000);
    if (pairs.length > 0) {
        traces.push({
            x: pairs.map(p => epochToDate(p.epoch)),
            y: pairs.map(p => p.rtt_ms),
            type: 'scatter', mode: 'markers',
            name: 'Ping RTT',
            marker: { color: '#10b981', size: 3 },
            xaxis: 'x3', yaxis: 'y3',
            _panel: 'rtt',
        });
    }
    // Ping loss 마커
    const losses = downsampleStep(ping.losses || [], 1000);
    if (losses.length > 0) {
        traces.push({
            x: losses.map(p => epochToDate(p.epoch)),
            y: losses.map(() => 0),
            type: 'scatter', mode: 'markers',
            name: 'Ping Loss',
            marker: { color: '#ef4444', symbol: 'x', size: 6 },
            xaxis: 'x3', yaxis: 'y3',
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
            _panel: 'frames',
        });
    }

    /* ── 로밍 이벤트 세로 점선 ── */
    const shapes = [];
    const seqs = roaming.sequences || [];
    seqs.forEach(s => {
        const t = epochToDate(s.auth_epoch);
        shapes.push({
            type: 'line', x0: t, x1: t, y0: 0, y1: 1, yref: 'paper',
            line: { color: 'rgba(245,158,11,0.5)', dash: 'dot', width: 1 },
        });
    });

    /* ── 이상 구간 하이라이트 (빨간 배경) ── */
    const delays = DATA.delay_zones || {};
    const zones = delays.delay_zones || [];
    zones.forEach(z => {
        shapes.push({
            type: 'rect',
            x0: epochToDate(z.start_epoch), x1: epochToDate(z.end_epoch),
            y0: 0, y1: 1, yref: 'paper',
            fillcolor: 'rgba(239,68,68,0.1)',
            line: { width: 0 },
            layer: 'below',
        });
    });

    /* ── RSSI cliff 마커 ── */
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
                marker: { color: cliffColors[ci % cliffColors.length], size: 10, symbol: 'triangle-down' },
                xaxis: 'x', yaxis: 'y',
                text: events.map(e => `${e.drop_db}dB drop in ${e.duration_sec}s`),
                hovertemplate: '%{text}<extra></extra>',
                _panel: 'rssi',
            });
            ci++;
        }
    }

    const GRID = 'rgba(255,255,255,0.05)';
    const SPIKE = { showspikes: true, spikemode: 'across', spikethickness: 1, spikecolor: '#9ca3af', spikedash: 'dot' };
    const layout = {
        paper_bgcolor: 'rgba(0,0,0,0)',
        plot_bgcolor: 'rgba(0,0,0,0)',
        font: { color: '#9ca3af', size: 10 },
        showlegend: false,  // 외부 사이드바로 대체
        dragmode: 'pan',
        hovermode: 'x unified',
        uirevision: 'keep',  // pan/zoom 후 사용자 axis 상태 유지
        xaxis:  { anchor: 'y',  domain: [0, 1], showticklabels: false, gridcolor: GRID, ...SPIKE },
        xaxis2: { anchor: 'y2', domain: [0, 1], showticklabels: false, matches: 'x', gridcolor: GRID, ...SPIKE },
        xaxis3: { anchor: 'y3', domain: [0, 1], showticklabels: false, matches: 'x', gridcolor: GRID, ...SPIKE },
        xaxis4: { anchor: 'y4', domain: [0, 1], matches: 'x', gridcolor: GRID, ...SPIKE },
        yaxis:  { title: 'RSSI (dBm)', domain: [0.78, 1.0], gridcolor: GRID },
        yaxis2: { title: 'Retry/s',    domain: [0.53, 0.75], gridcolor: GRID },
        yaxis3: { title: 'RTT (ms)',   domain: [0.28, 0.50], gridcolor: GRID },
        yaxis4: { title: 'Frames/s',   domain: [0.00, 0.25], gridcolor: GRID },
        shapes,
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
})();
