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
    const annotations = [];

    /* 패널 매핑 — checkbox dataset.panel 과 yaxis 키 연결 */
    const PANELS = ['rssi', 'retry', 'rtt', 'frames'];
    const PANEL_AXIS = { rssi: 'yaxis', retry: 'yaxis2', rtt: 'yaxis3', frames: 'yaxis4' };

    /* ── LTTB 다운샘플링 ── */
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

    function epochToDate(epoch) {
        return new Date(epoch * 1000);
    }

    /* ── 서브플롯 1: RSSI ── */
    const staNames = Object.keys(signal.stas || {});
    const colors = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6'];
    staNames.forEach((name, i) => {
        const sta = signal.stas[name];
        const raw = (sta.rssi_timeline || []).map(p => ({ x: p.epoch, y: p.rssi }));
        const sampled = downsample(raw, 3000);
        traces.push({
            x: sampled.map(p => epochToDate(p.x)),
            y: sampled.map(p => p.y),
            type: 'scattergl', mode: 'lines',
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
            timeline.map(p => ({ x: p.epoch, y: p.retry })), 3000
        );
        traces.push({
            x: sampled.map(p => epochToDate(p.x)),
            y: sampled.map(p => p.y),
            type: 'scattergl', mode: 'lines',
            name: 'Retry/sec',
            line: { color: '#ef4444', width: 1 },
            fill: 'tozeroy', fillcolor: 'rgba(239,68,68,0.1)',
            xaxis: 'x2', yaxis: 'y2',
            _panel: 'retry',
        });
    }

    /* ── 서브플롯 3: Ping RTT ── */
    const pairs = ping.pairs || [];
    if (pairs.length > 0) {
        traces.push({
            x: pairs.map(p => epochToDate(p.epoch)),
            y: pairs.map(p => p.rtt_ms),
            type: 'scattergl', mode: 'markers',
            name: 'Ping RTT',
            marker: { color: '#10b981', size: 3 },
            xaxis: 'x3', yaxis: 'y3',
            _panel: 'rtt',
        });
    }
    // Ping loss 마커
    const losses = ping.losses || [];
    if (losses.length > 0) {
        traces.push({
            x: losses.map(p => epochToDate(p.epoch)),
            y: losses.map(() => 0),
            type: 'scattergl', mode: 'markers',
            name: 'Ping Loss',
            marker: { color: '#ef4444', symbol: 'x', size: 6 },
            xaxis: 'x3', yaxis: 'y3',
            _panel: 'rtt',
        });
    }

    /* ── 서브플롯 4: 프레임/sec ── */
    if (timeline.length > 0) {
        const sampled = downsample(
            timeline.map(p => ({ x: p.epoch, y: p.total })), 3000
        );
        traces.push({
            x: sampled.map(p => epochToDate(p.x)),
            y: sampled.map(p => p.y),
            type: 'scattergl', mode: 'lines',
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
                type: 'scattergl', mode: 'markers',
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
        showlegend: true,
        legend: {
            orientation: 'v',
            x: 1.01, xanchor: 'left',
            y: 1, yanchor: 'top',
            font: { size: 10 },
            bgcolor: 'rgba(0,0,0,0)',
        },
        dragmode: 'pan',
        hovermode: 'x unified',
        xaxis:  { anchor: 'y',  domain: [0, 1], showticklabels: false, gridcolor: GRID, ...SPIKE },
        xaxis2: { anchor: 'y2', domain: [0, 1], showticklabels: false, matches: 'x', gridcolor: GRID, ...SPIKE },
        xaxis3: { anchor: 'y3', domain: [0, 1], showticklabels: false, matches: 'x', gridcolor: GRID, ...SPIKE },
        xaxis4: { anchor: 'y4', domain: [0, 1], matches: 'x', gridcolor: GRID, ...SPIKE },
        yaxis:  { title: 'RSSI (dBm)', domain: [0.78, 1.0], gridcolor: GRID },
        yaxis2: { title: 'Retry/s',    domain: [0.53, 0.75], gridcolor: GRID },
        yaxis3: { title: 'RTT (ms)',   domain: [0.28, 0.50], gridcolor: GRID },
        yaxis4: { title: 'Frames/s',   domain: [0.00, 0.25], gridcolor: GRID },
        shapes,
        margin: { t: 30, r: 160, b: 40, l: 60 },
    };

    if (traces.length > 0) {
        Plotly.newPlot(timelineEl, traces, layout, {
            responsive: true,
            displayModeBar: true,
            scrollZoom: true,
            doubleClick: 'reset+autosize',
            modeBarButtonsToRemove: ['lasso2d', 'select2d'],
        });
    } else {
        timelineEl.innerHTML = '<p class="text-gray-500 text-center py-20">시계열 데이터가 없습니다.</p>';
        return;
    }

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
        const visibleArr = timelineEl.data.map(t =>
            t._panel ? enabled.includes(t._panel) : true
        );
        Plotly.restyle(timelineEl, { visible: visibleArr });
    }

    const toggleBoxes = document.querySelectorAll('.timeline-toggle');
    function syncFromBoxes() {
        const enabled = Array.from(toggleBoxes).filter(x => x.checked).map(x => x.dataset.panel);
        if (enabled.length === 0) return null;
        applyPanelLayout(enabled);
        return enabled;
    }
    toggleBoxes.forEach(cb => {
        cb.addEventListener('change', () => {
            if (syncFromBoxes() === null) cb.checked = true; // 전체 OFF 방지
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
