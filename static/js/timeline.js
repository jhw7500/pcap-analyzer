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
            xaxis: 'x', yaxis: 'y2',
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
            xaxis: 'x', yaxis: 'y3',
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
            xaxis: 'x', yaxis: 'y3',
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
            xaxis: 'x', yaxis: 'y4',
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

    const layout = {
        paper_bgcolor: 'rgba(0,0,0,0)',
        plot_bgcolor: 'rgba(0,0,0,0)',
        font: { color: '#9ca3af', size: 10 },
        showlegend: true,
        legend: { orientation: 'h', y: 1.02, x: 0 },
        grid: { rows: 4, columns: 1, subplots: [['xy'], ['xy2'], ['xy3'], ['xy4']], roworder: 'top to bottom' },
        xaxis: { matches: 'x', showticklabels: false },
        xaxis2: { matches: 'x', showticklabels: false },
        xaxis3: { matches: 'x', showticklabels: false },
        xaxis4: { matches: 'x' },
        yaxis: { title: 'RSSI (dBm)', domain: [0.78, 1.0] },
        yaxis2: { title: 'Retry/s', domain: [0.53, 0.75] },
        yaxis3: { title: 'RTT (ms)', domain: [0.28, 0.50] },
        yaxis4: { title: 'Frames/s', domain: [0.0, 0.25] },
        shapes,
        margin: { t: 30, r: 20, b: 40, l: 60 },
    };

    if (traces.length > 0) {
        Plotly.newPlot(timelineEl, traces, layout, {
            responsive: true,
            displayModeBar: true,
            modeBarButtonsToRemove: ['lasso2d', 'select2d'],
        });
    } else {
        timelineEl.innerHTML = '<p class="text-gray-500 text-center py-20">시계열 데이터가 없습니다.</p>';
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
