/* 분석 결과 차트 렌더링 — Overview, 로밍, 장치별 */
(function () {
    if (typeof DATA === 'undefined') return;

    const DARK = {
        paper_bgcolor: 'rgba(0,0,0,0)',
        plot_bgcolor: 'rgba(0,0,0,0)',
        font: { color: '#9ca3af', size: 11 },
        margin: { t: 10, r: 10, b: 30, l: 40 },
    };

    const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6',
                    '#ec4899', '#06b6d4', '#84cc16', '#f97316', '#6366f1'];

    const SUBTYPE_NAMES = {
        '0': 'AssocReq', '1': 'AssocResp', '2': 'ReassocReq', '3': 'ReassocResp',
        '4': 'ProbeReq', '5': 'ProbeResp', '8': 'Beacon', '10': 'DisAssoc',
        '11': 'Auth', '12': 'DeAuth', '13': 'Action', '14': 'ActionNoAck',
        '18': 'Trigger', '24': 'BAR', '25': 'BA',
        '27': 'RTS', '28': 'CTS', '29': 'ACK', '30': 'CF-End',
        '32': 'Data', '40': 'QoS Data', '44': 'QoS Null',
    };

    /* ── 탭 전환 ── */
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
            btn.classList.add('active');
            document.getElementById('tab-' + btn.dataset.tab).classList.remove('hidden');
            /* Plotly 차트가 hidden→visible 될 때 리사이즈 필요 */
            setTimeout(() => window.dispatchEvent(new Event('resize')), 50);
        });
    });

    /* ── Overview KPI ── */
    const ov = DATA.overview || {};
    const kpiContainer = document.getElementById('kpi-cards');
    if (kpiContainer && ov.total_frames) {
        const kpis = [
            { label: '총 프레임', value: ov.total_frames.toLocaleString() },
            { label: '캡처 시간', value: ov.duration_sec + 's' },
            { label: 'Retry', value: ov.retry_pct + '%' },
            { label: '디바이스', value: (ov.devices || []).length + '대' },
        ];
        kpiContainer.innerHTML = kpis.map(k =>
            `<div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <p class="text-xs text-gray-500">${k.label}</p>
                <p class="text-2xl font-bold">${k.value}</p>
            </div>`
        ).join('');
    }

    /* ── 프로토콜 분포 (도넛) ── */
    if (ov.protocol_dist && Object.keys(ov.protocol_dist).length > 0) {
        const labels = Object.keys(ov.protocol_dist);
        const values = Object.values(ov.protocol_dist);
        Plotly.newPlot('chart-protocol', [{
            type: 'pie', hole: 0.5, labels, values,
            textinfo: 'label+percent', textposition: 'outside',
            marker: { colors: COLORS },
        }], { ...DARK }, { responsive: true, displayModeBar: false });
    }

    /* ── 서브타입 분포 (수평 바) ── */
    if (ov.subtype_dist && Object.keys(ov.subtype_dist).length > 0) {
        const entries = Object.entries(ov.subtype_dist).sort((a, b) => b[1] - a[1]).slice(0, 15);
        const labels = entries.map(e => SUBTYPE_NAMES[e[0]] || ('type=' + e[0]));
        const values = entries.map(e => e[1]);
        Plotly.newPlot('chart-subtype', [{
            type: 'bar', orientation: 'h', x: values, y: labels,
            marker: { color: '#3b82f6' },
        }], { ...DARK, yaxis: { autorange: 'reversed' } }, { responsive: true, displayModeBar: false });
    }

    /* ── 디바이스 테이블 ── */
    const devTable = document.querySelector('#device-table tbody');
    if (devTable && ov.devices && ov.devices.length > 0) {
        devTable.innerHTML = ov.devices.map(d =>
            `<tr class="border-b border-gray-700/50">
                <td class="py-2 font-mono">${d.name}</td>
                <td class="py-2 text-gray-400 font-mono text-xs">${d.mac}</td>
                <td class="py-2"><span class="px-2 py-0.5 rounded text-xs ${d.role === 'AP' ? 'bg-green-900 text-green-300' : 'bg-blue-900 text-blue-300'}">${d.role}</span></td>
                <td class="py-2 text-right">${d.count.toLocaleString()}</td>
            </tr>`
        ).join('');
    }

    /* ── 로밍 Gap 바 차트 ── */
    const roaming = DATA.roaming || {};
    if (roaming.sequences && roaming.sequences.length > 0) {
        const seqs = roaming.sequences;
        Plotly.newPlot('chart-roaming-gap', [{
            type: 'bar',
            x: seqs.map((_, i) => i + 1),
            y: seqs.map(s => s.gap_ms),
            marker: {
                color: seqs.map(s => s.is_slow ? '#ef4444' : '#3b82f6'),
            },
            text: seqs.map(s => s.sta_name + ' \u2192 ' + s.ap_name),
            hovertemplate: '%{text}<br>%{y:.1f}ms<extra></extra>',
        }], {
            ...DARK,
            xaxis: { title: '\ub85c\ubc0d \uc2dc\ud000\uc2a4 #' },
            yaxis: { title: 'Auth\u2192Assoc Gap (ms)' },
            shapes: [{
                type: 'line', x0: 0, x1: seqs.length + 1, y0: 100, y1: 100,
                line: { color: '#ef4444', dash: 'dash', width: 1 },
            }],
        }, { responsive: true, displayModeBar: false });

        // 로밍 테이블
        const rTable = document.querySelector('#roaming-table tbody');
        if (rTable) {
            rTable.innerHTML = seqs.map((s, i) =>
                `<tr class="border-b border-gray-700/50 ${s.is_slow ? 'text-red-400' : ''}">
                    <td class="py-1">${i + 1}</td>
                    <td class="py-1 font-mono text-xs">${s.sta_name}</td>
                    <td class="py-1 font-mono text-xs">${s.ap_name}</td>
                    <td class="py-1 text-right">${s.gap_ms.toFixed(1)}</td>
                    <td class="py-1">${s.assoc_type}</td>
                </tr>`
            ).join('');
        }
    }

    /* ── 장치별 탭 ── */
    const deviceStats = DATA.device_stats || {};
    const allDevNames = Object.keys(deviceStats);
    const apNames = allDevNames.filter(n => deviceStats[n].role === 'AP');
    const staNames_dev = allDevNames.filter(n => deviceStats[n].role === 'STA');

    // AP별 프레임 비교 (스택 바)
    if (apNames.length > 0 && document.getElementById('chart-ap-compare')) {
        const types = ['Management', 'Control', 'Data'];
        const typeColors = { Management: '#3b82f6', Control: '#f59e0b', Data: '#10b981' };
        const traces_ap = types.map(t => ({
            name: t, type: 'bar',
            x: apNames,
            y: apNames.map(n => (deviceStats[n].type_dist || {})[t] || 0),
            marker: { color: typeColors[t] },
            text: apNames.map(n => ((deviceStats[n].type_dist || {})[t] || 0).toLocaleString()),
            textposition: 'inside',
        }));
        Plotly.newPlot('chart-ap-compare', traces_ap, {
            ...DARK, barmode: 'stack',
            xaxis: { tickfont: { size: 12 } },
            yaxis: { title: '프레임 수' },
            legend: { font: { size: 11 } },
        }, { responsive: true, displayModeBar: false });
    }

    // STA별 프레임 비교 (스택 바)
    if (staNames_dev.length > 0 && document.getElementById('chart-sta-compare')) {
        const types = ['Management', 'Control', 'Data'];
        const typeColors = { Management: '#3b82f6', Control: '#f59e0b', Data: '#10b981' };
        const traces_sta = types.map(t => ({
            name: t, type: 'bar',
            x: staNames_dev,
            y: staNames_dev.map(n => (deviceStats[n].type_dist || {})[t] || 0),
            marker: { color: typeColors[t] },
            text: staNames_dev.map(n => ((deviceStats[n].type_dist || {})[t] || 0).toLocaleString()),
            textposition: 'inside',
        }));
        Plotly.newPlot('chart-sta-compare', traces_sta, {
            ...DARK, barmode: 'stack',
            xaxis: { tickfont: { size: 12 } },
            yaxis: { title: '프레임 수' },
            legend: { font: { size: 11 } },
        }, { responsive: true, displayModeBar: false });
    }

    // 장치별 Retry율 + RSSI 비교 (그룹 바)
    if (allDevNames.length > 0 && document.getElementById('chart-device-retry-compare')) {
        Plotly.newPlot('chart-device-retry-compare', [
            {
                name: 'Retry율 (%)', type: 'bar',
                x: allDevNames,
                y: allDevNames.map(n => deviceStats[n].retry_pct),
                marker: { color: allDevNames.map(n => deviceStats[n].retry_pct > 20 ? '#ef4444' : deviceStats[n].retry_pct > 10 ? '#f59e0b' : '#3b82f6') },
                text: allDevNames.map(n => deviceStats[n].retry_pct + '%'),
                textposition: 'outside',
                yaxis: 'y',
            },
            {
                name: 'RSSI avg (dBm)', type: 'scatter', mode: 'markers+text',
                x: allDevNames.filter(n => deviceStats[n].rssi_stats && deviceStats[n].rssi_stats.avg),
                y: allDevNames.filter(n => deviceStats[n].rssi_stats && deviceStats[n].rssi_stats.avg)
                    .map(n => deviceStats[n].rssi_stats.avg),
                text: allDevNames.filter(n => deviceStats[n].rssi_stats && deviceStats[n].rssi_stats.avg)
                    .map(n => deviceStats[n].rssi_stats.avg + 'dBm'),
                textposition: 'top center',
                marker: { color: '#ec4899', size: 12 },
                yaxis: 'y2',
            },
        ], {
            ...DARK,
            yaxis: { title: 'Retry율 (%)', side: 'left' },
            yaxis2: { title: 'RSSI (dBm)', side: 'right', overlaying: 'y', showgrid: false },
            xaxis: { tickfont: { size: 12 } },
            legend: { font: { size: 11 } },
        }, { responsive: true, displayModeBar: false });
    }

    // 개별 장치 상세
    const deviceSelect = document.getElementById('device-select');
    if (deviceSelect) {
        deviceSelect.innerHTML = allDevNames.map(n => {
            const s = deviceStats[n];
            return `<option value="${n}">${n} (${s.role}) - ${s.total_frames.toLocaleString()} frames, Retry ${s.retry_pct}%</option>`;
        }).join('');
        deviceSelect.addEventListener('change', renderDeviceDetail);
        if (allDevNames.length > 0) renderDeviceDetail();
    }

    function renderDeviceDetail() {
        const name = deviceSelect.value;
        const s = deviceStats[name];
        if (!s) return;

        // 요약 KPI
        const detailEl = document.getElementById('device-detail-stats');
        if (detailEl) {
            const rssi = s.rssi_stats || {};
            detailEl.innerHTML = `
                <div class="grid grid-cols-5 gap-3 text-sm">
                    <div class="bg-gray-700/50 rounded p-2"><span class="text-xs text-gray-500">총 프레임</span><br><span class="font-bold">${s.total_frames.toLocaleString()}</span></div>
                    <div class="bg-gray-700/50 rounded p-2"><span class="text-xs text-gray-500">TX 프레임</span><br><span class="font-bold">${(s.tx_frames || 0).toLocaleString()}</span></div>
                    <div class="bg-gray-700/50 rounded p-2"><span class="text-xs text-gray-500">Retry</span><br><span class="font-bold ${s.retry_pct > 15 ? 'text-red-400' : ''}">${s.retry_count.toLocaleString()} (${s.retry_pct}%)</span></div>
                    <div class="bg-gray-700/50 rounded p-2"><span class="text-xs text-gray-500">RSSI avg</span><br><span class="font-bold">${rssi.avg || '-'} dBm</span></div>
                    <div class="bg-gray-700/50 rounded p-2"><span class="text-xs text-gray-500">RSSI range</span><br><span class="font-bold">${rssi.min || '-'} ~ ${rssi.max || '-'}</span></div>
                </div>`;
        }

        // 프레임 타입 파이
        Plotly.newPlot('chart-device-type', [{
            type: 'pie', labels: Object.keys(s.type_dist), values: Object.values(s.type_dist),
            marker: { colors: ['#3b82f6', '#10b981', '#f59e0b', '#6b7280'] },
            textinfo: 'label+percent', textposition: 'inside',
        }], { ...DARK }, { responsive: true, displayModeBar: false });

        // MCS 분포
        const mcs = s.mcs_dist || {};
        if (Object.keys(mcs).length > 0) {
            Plotly.newPlot('chart-device-mcs', [{
                type: 'bar', x: Object.keys(mcs), y: Object.values(mcs),
                marker: { color: '#8b5cf6' },
                text: Object.values(mcs).map(v => v.toLocaleString()),
                textposition: 'outside',
            }], { ...DARK, xaxis: { title: 'MCS Index', dtick: 1 }, yaxis: { title: '프레임 수' } },
            { responsive: true, displayModeBar: false });
        } else {
            document.getElementById('chart-device-mcs').innerHTML = '<p class="text-gray-500 text-center py-10">MCS 데이터 없음</p>';
        }

        // 서브타입 Top 10
        const subEntries = Object.entries(s.subtype_dist).sort((a, b) => b[1] - a[1]).slice(0, 10);
        Plotly.newPlot('chart-device-subtype', [{
            type: 'bar', orientation: 'h',
            x: subEntries.map(e => e[1]), y: subEntries.map(e => e[0]),
            marker: { color: '#3b82f6' },
            text: subEntries.map(e => e[1].toLocaleString()), textposition: 'outside',
        }], { ...DARK, yaxis: { autorange: 'reversed' }, margin: { l: 80 } },
        { responsive: true, displayModeBar: false });

        // 구간별 프레임/Retry 시계열
        const buckets = s.per_bucket || [];
        if (buckets.length > 0) {
            Plotly.newPlot('chart-device-timeline', [
                {
                    x: buckets.map(b => new Date(b.epoch * 1000)),
                    y: buckets.map(b => b.total),
                    type: 'bar', name: '총 프레임/10s',
                    marker: { color: 'rgba(59,130,246,0.5)' },
                },
                {
                    x: buckets.map(b => new Date(b.epoch * 1000)),
                    y: buckets.map(b => b.retry),
                    type: 'bar', name: 'Retry/10s',
                    marker: { color: 'rgba(239,68,68,0.7)' },
                },
                {
                    x: buckets.map(b => new Date(b.epoch * 1000)),
                    y: buckets.map(b => b.retry_pct),
                    type: 'scatter', mode: 'lines', name: 'Retry율 (%)',
                    line: { color: '#f59e0b', width: 2 },
                    yaxis: 'y2',
                },
            ], {
                ...DARK, barmode: 'overlay',
                xaxis: { title: '시간' },
                yaxis: { title: '프레임 수' },
                yaxis2: { title: 'Retry율 (%)', side: 'right', overlaying: 'y', showgrid: false, range: [0, 100] },
                legend: { font: { size: 11 } },
            }, { responsive: true, displayModeBar: true });
        }
    }

    /* ── Ping 분석 탭 ── */
    const ping = DATA.ping || {};
    const pairs = ping.pairs || [];
    const losses = ping.losses || [];
    const fullList = ping.full_list || [];
    const pingStatsData = ping.stats || {};

    // Ping KPI
    const pingKpi = document.getElementById('ping-kpi');
    if (pingKpi && pingStatsData.count !== undefined) {
        const s = pingStatsData;
        pingKpi.innerHTML = [
            { label: 'Ping 응답', value: s.count + '건', color: '' },
            { label: 'Ping Loss', value: s.loss_count + '건 (' + s.loss_pct + '%)',
              color: s.loss_count > 0 ? 'text-red-400' : '' },
            { label: '평균 RTT', value: s.avg + 'ms', color: '' },
            { label: 'P95 RTT', value: s.p95 + 'ms', color: s.p95 > 10 ? 'text-yellow-400' : '' },
        ].map(k =>
            `<div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <p class="text-xs text-gray-500">${k.label}</p>
                <p class="text-xl font-bold ${k.color}">${k.value}</p>
            </div>`
        ).join('');
    }

    // Ping RTT 시계열 (큰 차트)
    if (pairs.length > 0 && document.getElementById('chart-ping-rtt')) {
        const normalPairs = pairs.filter(p => !p.has_retry);
        const retryPairs = pairs.filter(p => p.has_retry);
        const traces_ping = [];
        if (normalPairs.length > 0) {
            traces_ping.push({
                x: normalPairs.map(p => new Date(p.epoch * 1000)),
                y: normalPairs.map(p => p.rtt_ms),
                type: 'scattergl', mode: 'markers+lines',
                name: 'RTT (정상)',
                line: { color: '#10b981', width: 1 },
                marker: { color: '#10b981', size: 5 },
                text: normalPairs.map(p => 'Seq ' + p.seq + '  #' + p.req_num + '\u2192#' + p.reply_num),
                hovertemplate: '%{text}<br>RTT: %{y:.2f}ms<br>%{x}<extra></extra>',
            });
        }
        if (retryPairs.length > 0) {
            traces_ping.push({
                x: retryPairs.map(p => new Date(p.epoch * 1000)),
                y: retryPairs.map(p => p.rtt_ms),
                type: 'scattergl', mode: 'markers',
                name: 'RTT (Retry)',
                marker: { color: '#f59e0b', size: 7, symbol: 'diamond' },
                text: retryPairs.map(p => 'Seq ' + p.seq + ' RETRY  #' + p.req_num + '\u2192#' + p.reply_num),
                hovertemplate: '%{text}<br>RTT: %{y:.2f}ms<extra></extra>',
            });
        }
        if (losses.length > 0) {
            const maxRtt = pairs.length > 0 ? Math.max(...pairs.map(p => p.rtt_ms)) : 10;
            traces_ping.push({
                x: losses.map(p => new Date(p.epoch * 1000)),
                y: losses.map(() => maxRtt * 1.1),
                type: 'scattergl', mode: 'markers',
                name: 'LOSS (미응답)',
                marker: { color: '#ef4444', size: 10, symbol: 'x', line: { width: 2 } },
                text: losses.map(p => 'Seq ' + p.seq + ' LOSS  #' + p.req_num + '  ' + p.src + '\u2192' + p.dst),
                hovertemplate: '%{text}<extra></extra>',
            });
        }
        Plotly.newPlot('chart-ping-rtt', traces_ping, {
            ...DARK,
            xaxis: { title: { text: '시간', font: { size: 12 } }, gridcolor: '#374151' },
            yaxis: { title: { text: 'RTT (ms)', font: { size: 12 } }, gridcolor: '#374151' },
            legend: { font: { size: 12 } },
            margin: { t: 10, r: 20, b: 50, l: 60 },
        }, { responsive: true, displayModeBar: true });
    }

    // RTT 히스토그램
    if (pairs.length > 0 && document.getElementById('chart-ping-hist')) {
        Plotly.newPlot('chart-ping-hist', [{
            x: pairs.map(p => p.rtt_ms), type: 'histogram',
            marker: { color: '#3b82f6' },
            nbinsx: 40,
        }], {
            ...DARK,
            xaxis: { title: { text: 'RTT (ms)', font: { size: 12 } }, gridcolor: '#374151' },
            yaxis: { title: { text: '빈도', font: { size: 12 } }, gridcolor: '#374151' },
            margin: { t: 10, r: 10, b: 50, l: 50 },
        }, { responsive: true, displayModeBar: false });
    }

    // Ping 통계 (서버에서 계산된 값 사용)
    const pingStats = document.getElementById('ping-stats');
    if (pingStats && pingStatsData.count) {
        const s = pingStatsData;
        pingStats.innerHTML = `
            <table class="w-full text-sm">
                <tr><td class="text-gray-400 py-1">총 Ping</td><td class="text-right text-white font-bold">${s.count + s.loss_count}건</td></tr>
                <tr><td class="text-gray-400 py-1">응답</td><td class="text-right text-green-400">${s.count}건</td></tr>
                <tr><td class="text-gray-400 py-1">미응답 (Loss)</td><td class="text-right text-red-400">${s.loss_count}건 (${s.loss_pct}%)</td></tr>
                <tr class="border-t border-gray-700"><td class="text-gray-400 py-1">Min RTT</td><td class="text-right text-white">${s.min}ms</td></tr>
                <tr><td class="text-gray-400 py-1">Max RTT</td><td class="text-right text-white">${s.max}ms</td></tr>
                <tr><td class="text-gray-400 py-1">Avg RTT</td><td class="text-right text-white font-bold">${s.avg}ms</td></tr>
                <tr class="border-t border-gray-700"><td class="text-gray-400 py-1">P50 (중앙값)</td><td class="text-right text-white">${s.p50}ms</td></tr>
                <tr><td class="text-gray-400 py-1">P95</td><td class="text-right ${s.p95 > 10 ? 'text-yellow-400' : 'text-white'}">${s.p95}ms</td></tr>
                <tr><td class="text-gray-400 py-1">P99</td><td class="text-right ${s.p99 > 20 ? 'text-red-400' : 'text-white'}">${s.p99}ms</td></tr>
            </table>`;
    }

    // Ping 전수검사 테이블
    const pingFullTable = document.querySelector('#ping-full-table tbody');
    if (pingFullTable && fullList.length > 0) {
        pingFullTable.innerHTML = fullList.map((p, i) => {
            const isLoss = p.status === 'loss';
            const rowClass = isLoss ? 'text-red-400 bg-red-900/20' : (p.has_retry ? 'text-yellow-400' : '');
            const statusBadge = isLoss
                ? '<span class="bg-red-900 text-red-300 px-1.5 py-0.5 rounded text-xs font-bold">LOSS</span>'
                : (p.has_retry
                    ? '<span class="bg-yellow-900 text-yellow-300 px-1.5 py-0.5 rounded text-xs">RETRY</span>'
                    : '<span class="bg-green-900 text-green-300 px-1.5 py-0.5 rounded text-xs">OK</span>');
            const rttStr = p.rtt_ms !== null ? p.rtt_ms.toFixed(2) : '-';
            const replyStr = p.reply_num !== null ? '#' + p.reply_num : '-';
            const replyTime = p.reply_time || '-';
            return `<tr class="border-b border-gray-700/30 ${rowClass} hover:bg-gray-700/30">
                <td class="py-1 px-1">${i + 1}</td>
                <td class="py-1 px-1">${p.seq || '-'}</td>
                <td class="py-1 px-1">${statusBadge}</td>
                <td class="py-1 px-1">#${p.req_num}</td>
                <td class="py-1 px-1">${p.req_time || ''}</td>
                <td class="py-1 px-1">${replyStr}</td>
                <td class="py-1 px-1">${replyTime}</td>
                <td class="py-1 px-1 text-right ${isLoss ? '' : (p.rtt_ms > 10 ? 'text-yellow-400 font-bold' : '')}">${rttStr}</td>
                <td class="py-1 px-1">${p.src} \u2192 ${p.dst}</td>
                <td class="py-1 px-1">${p.has_retry ? 'R' : ''}</td>
            </tr>`;
        }).join('');
    }

    /* ── 종합 진단 — 구조화된 카드 ── */
    const diagCards = document.getElementById('diagnosis-cards');
    const diagEl = document.getElementById('diagnosis-text');
    if (window.TEXT_SECTIONS) {
        const diagSection = window.TEXT_SECTIONS.find(s => s.title.includes('진단'));
        if (diagSection) {
            // 원본 텍스트
            if (diagEl) diagEl.textContent = diagSection.lines.join('\n');

            // 구조화된 카드 파싱
            if (diagCards) {
                const lines = diagSection.lines;
                let cards = [];
                let current = null;
                for (const line of lines) {
                    if (line.startsWith('--- ')) {
                        if (current) cards.push(current);
                        current = { name: line.replace(/---/g, '').trim(), lines: [], warnings: [] };
                    } else if (current) {
                        current.lines.push(line);
                        if (line.includes('[WARNING]')) current.warnings.push(line.trim());
                    }
                }
                if (current) cards.push(current);

                diagCards.innerHTML = cards.map(c => {
                    const isOk = c.warnings.length === 0;
                    const border = isOk ? 'border-green-700' : 'border-red-700';
                    const badge = isOk
                        ? '<span class="bg-green-900 text-green-300 px-2 py-0.5 rounded text-xs">OK</span>'
                        : '<span class="bg-red-900 text-red-300 px-2 py-0.5 rounded text-xs">WARNING ' + c.warnings.length + '</span>';
                    const detail = c.lines.filter(l => l.trim() && !l.startsWith('='))
                        .map(l => `<div class="text-xs text-gray-400">${l}</div>`).join('');
                    return `<div class="bg-gray-800 rounded-lg p-4 border ${border}">
                        <div class="flex justify-between items-center mb-2">
                            <span class="font-semibold text-sm">${c.name}</span>${badge}
                        </div>${detail}</div>`;
                }).join('');
            }
        }
    }
})();

