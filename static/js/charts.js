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
    const deviceSelect = document.getElementById('device-select');
    if (deviceSelect) {
        const names = Object.keys(deviceStats);
        deviceSelect.innerHTML = names.map(n =>
            `<option value="${n}">${n} (${deviceStats[n].role}) - ${deviceStats[n].total_frames.toLocaleString()} frames</option>`
        ).join('');
        deviceSelect.addEventListener('change', renderDeviceCharts);
        if (names.length > 0) renderDeviceCharts();
    }

    function renderDeviceCharts() {
        const name = deviceSelect.value;
        const stats = deviceStats[name];
        if (!stats) return;

        // 프레임 타입 파이
        Plotly.newPlot('chart-device-type', [{
            type: 'pie', labels: Object.keys(stats.type_dist), values: Object.values(stats.type_dist),
            marker: { colors: ['#3b82f6', '#10b981', '#f59e0b', '#6b7280'] },
            textinfo: 'label+percent',
        }], { ...DARK, title: { text: `${name} - Retry ${stats.retry_pct}%`, font: { size: 12, color: '#9ca3af' } } },
        { responsive: true, displayModeBar: false });

        // 서브타입 바
        const entries = Object.entries(stats.subtype_dist).sort((a, b) => b[1] - a[1]).slice(0, 10);
        Plotly.newPlot('chart-device-subtype', [{
            type: 'bar', orientation: 'h',
            x: entries.map(e => e[1]), y: entries.map(e => e[0]),
            marker: { color: '#3b82f6' },
            text: entries.map(e => e[1].toLocaleString()),
            textposition: 'outside',
        }], { ...DARK, yaxis: { autorange: 'reversed' } }, { responsive: true, displayModeBar: false });
    }

    /* ── 종합 진단 텍스트 ── */
    const diagEl = document.getElementById('diagnosis-text');
    if (diagEl && window.TEXT_SECTIONS) {
        const diagSection = window.TEXT_SECTIONS.find(s => s.title.includes('진단'));
        if (diagSection) {
            diagEl.textContent = diagSection.lines.join('\n');
        }
    }
})();
