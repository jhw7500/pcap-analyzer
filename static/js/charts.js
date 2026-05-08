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

    /* ── 802.11 카테고리 분류 ── 표준 type_subtype 기반 ── */
    function categorizeSubtype(sub) {
        const n = parseInt(sub, 10);
        if (isNaN(n)) return 'other';
        if (n >= 0 && n <= 15)  return 'mgmt';
        if (n >= 16 && n <= 31) return 'ctrl';
        if (n >= 32 && n <= 47) return 'data';
        return 'other';
    }
    const CAT_LABELS = { mgmt: '관리 프레임', ctrl: '제어 프레임', data: '데이터 프레임', other: '기타' };
    const CAT_COLORS = { mgmt: '#3b82f6', ctrl: '#f59e0b', data: '#10b981', other: '#6b7280' };

    /* ── 트래픽 종류 도넛 (Mgmt/Ctrl/Data/기타) ── */
    if (ov.subtype_dist && Object.keys(ov.subtype_dist).length > 0) {
        const totals = { mgmt: 0, ctrl: 0, data: 0, other: 0 };
        Object.entries(ov.subtype_dist).forEach(([sub, count]) => {
            totals[categorizeSubtype(sub)] += count;
        });
        const order = ['mgmt', 'ctrl', 'data', 'other'].filter(k => totals[k] > 0);
        Plotly.newPlot('chart-frame-category', [{
            type: 'pie', hole: 0.5,
            labels: order.map(k => CAT_LABELS[k]),
            values: order.map(k => totals[k]),
            marker: { colors: order.map(k => CAT_COLORS[k]) },
            textinfo: 'percent', textposition: 'inside',
            insidetextorientation: 'horizontal',
            hovertemplate: '%{label}: %{value:,} (%{percent})<extra></extra>',
            sort: false,
        }], {
            ...DARK,
            showlegend: true,
            legend: { font: { size: 11 }, x: 1, xanchor: 'right', y: 0.5 },
        }, { responsive: true, displayModeBar: false });
    }

    /* ── 페이로드 프로토콜 카테고리 분류 ── (Wireshark 표시명 기준)  */
    function categorizeProto(p) {
        const u = (p || '').toUpperCase();
        // 802.11 헤더 자체 — 페이로드 도넛/탭에서 제외 (프레임 종류 도넛에 이미 표시)
        if (/^(802\.11|WLAN|MNGT|CTRL)$/.test(u)) return 'header_only';
        // 연결 인증 (802.1X 프레임워크)
        if (/^(EAPOL|EAP|RSN|WPS|EAP-TLS|EAP-PEAP|EAP-TTLS|EAP-MD5|EAP-MSCHAPV2)$/.test(u)) return 'auth';
        // L2/L3 제어 (ARP, ICMP, 라우팅/스위칭/터널 제어)
        if (/^(ARP|RARP|LLC|ICMP|ICMPV6|IGMP|IGMPV3|STP|RSTP|MSTP|LLDP|CDP|VTP|DTP|OAM|GRE|ESP|AH|PIM|OSPF|EIGRP|ISIS|BGP|RIP|HSRP|VRRP|MPLS|VXLAN|GENEVE)$/.test(u)) return 'l2l3';
        // TCP 기반 응용 (NetBIOS Session, Web, DB, Messaging 등)
        if (/^(TCP|HTTP|HTTPS|HTTP2|SSH|SSHV2|TLS|SSL|FTP|FTP-DATA|SMTP|SMTPS|POP|POP3|IMAP|IMAPS|RDP|VNC|TELNET|HTTP\/JSON|HTTP\/XML|MSRPC|SMB|SMB2|SMB3|NBSS|WEBSOCKET|IRC|NNTP|MYSQL|PGSQL|POSTGRES|REDIS|MONGO|MONGODB|MSSQL|ORACLE|KAFKA|RTMP|AMQP|MQTT|XMPP|STOMP|GIT|RSYNC|SVN|GRAPHQL|GRPC|TDS)$/.test(u)) return 'tcp';
        // UDP 기반 응용 (이름 해석/검색/시간/멀티미디어/IoT/VPN-UDP)
        if (/^(UDP|QUIC|DNS|MDNS|NBNS|BROWSER|NETBIOS|DHCP|DHCPV6|NTP|SNTP|SNMP|TFTP|RTP|RTCP|SSDP|LLMNR|WSD|COAP|BACNET|OPENVPN|WIREGUARD|L2TP|IPSEC|RADIUS|TACACS\+?|SIP|RTSP|SRTP)$/.test(u)) return 'udp';
        return 'other';
    }
    const PROTO_CAT_LABELS = {
        auth: '연결 인증',
        l2l3: '네트워크 제어',
        tcp: 'TCP 통신',
        udp: 'UDP 통신',
        other: '기타',
    };
    const PROTO_CAT_COLORS = {
        auth: '#fbbf24',
        l2l3: '#ec4899',
        tcp: '#84cc16',
        udp: '#a855f7',
        other: '#6b7280',
    };
    const PROTO_CAT_ORDER = ['auth', 'l2l3', 'tcp', 'udp', 'other'];

    /* ── 데이터 프레임 페이로드 카테고리 도넛 ── (802.11 헤더는 프레임 종류 도넛에 이미 있음) */
    if (ov.protocol_dist && Object.keys(ov.protocol_dist).length > 0) {
        const totals = { auth: 0, l2l3: 0, tcp: 0, udp: 0, other: 0 };
        Object.entries(ov.protocol_dist).forEach(([p, c]) => {
            const cat = categorizeProto(p);
            if (cat === 'header_only') return;
            totals[cat] += c;
        });
        const order = PROTO_CAT_ORDER.filter(k => totals[k] > 0);
        Plotly.newPlot('chart-protocol-category', [{
            type: 'pie', hole: 0.5,
            labels: order.map(k => PROTO_CAT_LABELS[k]),
            values: order.map(k => totals[k]),
            marker: { colors: order.map(k => PROTO_CAT_COLORS[k]) },
            textinfo: 'percent', textposition: 'inside',
            insidetextorientation: 'horizontal',
            hovertemplate: '%{label}: %{value:,} (%{percent})<extra></extra>',
            sort: false,
        }], {
            ...DARK,
            showlegend: true,
            legend: { font: { size: 11 }, x: 1, xanchor: 'right', y: 0.5 },
        }, { responsive: true, displayModeBar: false });
    }

    /* ── 페이로드 세부 (카테고리 탭별 가로 막대) ── */
    function renderProtoDetail(cat) {
        const el = document.getElementById('chart-protocol-detail');
        if (!el) return;
        const entries = Object.entries(ov.protocol_dist || {})
            .filter(([p]) => categorizeProto(p) === cat)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 15);
        if (entries.length === 0) {
            el.innerHTML = '<p class="text-gray-500 text-center py-12">이 카테고리에 해당하는 프로토콜이 없습니다.</p>';
            return;
        }
        const labels = entries.map(e => e[0]);
        const values = entries.map(e => e[1]);
        const total = values.reduce((a, b) => a + b, 0);
        Plotly.newPlot(el, [{
            type: 'bar', orientation: 'h', x: values, y: labels,
            marker: { color: PROTO_CAT_COLORS[cat] },
            text: values.map(v => `${v.toLocaleString()} (${(v / total * 100).toFixed(1)}%)`),
            textposition: 'outside',
            hovertemplate: '%{y}: %{x:,}<extra></extra>',
        }], {
            ...DARK,
            margin: { t: 10, r: 80, b: 30, l: 10 },
            yaxis: { autorange: 'reversed', automargin: true },
            xaxis: { automargin: true },
        }, { responsive: true, displayModeBar: false });
    }
    if (ov.protocol_dist && Object.keys(ov.protocol_dist).length > 0) {
        renderProtoDetail('auth');
        document.querySelectorAll('.proto-tab').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.proto-tab').forEach(b => {
                    b.classList.remove('bg-blue-600', 'text-white');
                    b.classList.add('bg-gray-700', 'text-gray-300');
                });
                btn.classList.remove('bg-gray-700', 'text-gray-300');
                btn.classList.add('bg-blue-600', 'text-white');
                renderProtoDetail(btn.dataset.cat);
            });
        });
    }

    /* ── 서브타입 세부 (카테고리 탭별 가로 막대) ── */
    function subtypeLabel(sub) {
        if (sub === undefined || sub === null || sub === '') return '비-802.11 / 미분류';
        return SUBTYPE_NAMES[sub] || ('type=' + sub);
    }
    function renderSubtypeDetail(cat) {
        const subtypeEl = document.getElementById('chart-subtype');
        if (!subtypeEl) return;
        const entries = Object.entries(ov.subtype_dist || {})
            .filter(([sub]) => categorizeSubtype(sub) === cat)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 15);
        if (entries.length === 0) {
            subtypeEl.innerHTML = '<p class="text-gray-500 text-center py-12">이 카테고리에 해당하는 서브타입이 없습니다.</p>';
            return;
        }
        const labels = entries.map(e => subtypeLabel(e[0]));
        const values = entries.map(e => e[1]);
        const total = values.reduce((a, b) => a + b, 0);
        Plotly.newPlot(subtypeEl, [{
            type: 'bar', orientation: 'h', x: values, y: labels,
            marker: { color: CAT_COLORS[cat] },
            text: values.map(v => `${v.toLocaleString()} (${(v / total * 100).toFixed(1)}%)`),
            textposition: 'outside',
            hovertemplate: '%{y}: %{x:,}<extra></extra>',
        }], {
            ...DARK,
            margin: { t: 10, r: 60, b: 30, l: 10 },
            yaxis: { autorange: 'reversed', automargin: true },
            xaxis: { automargin: true },
        }, { responsive: true, displayModeBar: false });
    }
    if (ov.subtype_dist && Object.keys(ov.subtype_dist).length > 0) {
        renderSubtypeDetail('mgmt');
        document.querySelectorAll('.subtype-tab').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.subtype-tab').forEach(b => {
                    b.classList.remove('bg-blue-600', 'text-white');
                    b.classList.add('bg-gray-700', 'text-gray-300');
                });
                btn.classList.remove('bg-gray-700', 'text-gray-300');
                btn.classList.add('bg-blue-600', 'text-white');
                renderSubtypeDetail(btn.dataset.cat);
            });
        });
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

    /* ── 종합 진단 — 고급 UI ── */
    const diag = DATA.diagnosis || {};
    const health = diag.health || {};
    const compScores = diag.component_scores || {};
    const stadiags = diag.sta_diags || [];
    const issues = diag.issues || [];

    // 원본 텍스트 (접이식)
    const diagEl = document.getElementById('diagnosis-text');
    if (diagEl && window.TEXT_SECTIONS) {
        const diagSection = window.TEXT_SECTIONS.find(s => s.title.includes('진단'));
        if (diagSection) diagEl.textContent = diagSection.lines.join('\n');
    }

    // 건강도 게이지
    const gaugeEl = document.getElementById('health-gauge');
    if (gaugeEl && health.score !== undefined) {
        const colorMap = { green: '#10b981', yellow: '#f59e0b', red: '#ef4444' };
        const c = colorMap[health.color] || '#6b7280';
        gaugeEl.innerHTML = `
            <div class="relative w-28 h-28">
                <svg viewBox="0 0 120 120" class="w-full h-full">
                    <circle cx="60" cy="60" r="50" fill="none" stroke="#374151" stroke-width="10"/>
                    <circle cx="60" cy="60" r="50" fill="none" stroke="${c}" stroke-width="10"
                        stroke-dasharray="${Math.PI * 100}" stroke-dashoffset="${Math.PI * 100 * (1 - health.score / 100)}"
                        transform="rotate(-90 60 60)" stroke-linecap="round"/>
                    <text x="60" y="55" text-anchor="middle" fill="${c}" font-size="28" font-weight="bold">${health.score}</text>
                    <text x="60" y="75" text-anchor="middle" fill="#9ca3af" font-size="13">${health.grade}</text>
                </svg>
            </div>
            <p class="text-xs text-gray-500 mt-1">네트워크 건강도</p>`;
    }

    // 지표별 점수 바
    function scoreBar(label, score, icon) {
        const c = score >= 80 ? '#10b981' : score >= 60 ? '#f59e0b' : '#ef4444';
        return `<div class="flex items-center gap-3">
            <span class="text-xs text-gray-400 w-20">${icon} ${label}</span>
            <div class="flex-1 bg-gray-700 rounded-full h-4 relative">
                <div class="h-4 rounded-full transition-all" style="width:${score}%; background:${c}"></div>
                <span class="absolute inset-0 flex items-center justify-center text-xs font-bold text-white">${score}/100</span>
            </div>
        </div>`;
    }
    const barsEl = document.getElementById('health-bars');
    if (barsEl) {
        const sm = diag.summary || {};
        barsEl.innerHTML = [
            scoreBar('Retry', compScores.retry || 0, '\u{1F504}') + `<p class="text-xs text-gray-500 ml-24">전체 ${sm.retry_pct || 0}%</p>`,
            scoreBar('Ping Loss', compScores.loss || 0, '\u{1F4E1}') + `<p class="text-xs text-gray-500 ml-24">Loss ${sm.loss_pct || 0}%</p>`,
            scoreBar('로밍', compScores.roaming || 0, '\u{1F6DC}') + `<p class="text-xs text-gray-500 ml-24">총 ${sm.roaming_total || 0}회, 느린 ${sm.roaming_slow || 0}회</p>`,
        ].join('');
    }

    // 문제점 목록
    const issuesEl = document.getElementById('issues-list');
    if (issuesEl) {
        if (issues.length === 0) {
            issuesEl.innerHTML = '<div class="text-green-400 text-sm py-4 text-center">특별한 문제가 발견되지 않았습니다.</div>';
        } else {
            issuesEl.innerHTML = issues.map((iss, i) => {
                const sevStyle = {
                    high: 'bg-red-900/50 border-red-700 text-red-300',
                    medium: 'bg-yellow-900/50 border-yellow-700 text-yellow-300',
                    low: 'bg-blue-900/50 border-blue-700 text-blue-300',
                };
                const sevBadge = {
                    high: '<span class="bg-red-700 text-white px-2 py-0.5 rounded text-xs font-bold">HIGH</span>',
                    medium: '<span class="bg-yellow-700 text-white px-2 py-0.5 rounded text-xs font-bold">MED</span>',
                    low: '<span class="bg-blue-700 text-white px-2 py-0.5 rounded text-xs font-bold">LOW</span>',
                };
                const style = sevStyle[iss.severity] || sevStyle.low;
                const badge = sevBadge[iss.severity] || sevBadge.low;
                return `<div class="rounded-lg p-3 border ${style}">
                    <div class="flex items-center gap-2 mb-1">
                        ${badge}
                        <span class="text-xs text-gray-400">${iss.category}</span>
                        <span class="text-sm font-medium">${iss.msg}</span>
                    </div>
                    <div class="text-xs text-gray-400 ml-16">\u{1F527} 조치: ${iss.action}</div>
                </div>`;
            }).join('');
        }
    }

    // STA별 진단 카드
    const staCardsEl = document.getElementById('sta-diag-cards');
    if (staCardsEl && stadiags.length > 0) {
        staCardsEl.innerHTML = stadiags.map(sd => {
            const c = sd.score >= 80 ? 'green' : sd.score >= 60 ? 'yellow' : 'red';
            const borderC = { green: 'border-green-700', yellow: 'border-yellow-700', red: 'border-red-700' }[c];
            const textC = { green: 'text-green-400', yellow: 'text-yellow-400', red: 'text-red-400' }[c];
            const m = sd.metrics || {};
            const scores = sd.scores || {};

            function miniBar(label, val) {
                const barC = val >= 80 ? '#10b981' : val >= 60 ? '#f59e0b' : '#ef4444';
                return `<div class="flex items-center gap-1 text-xs">
                    <span class="w-12 text-gray-500">${label}</span>
                    <div class="flex-1 bg-gray-700 rounded-full h-2">
                        <div class="h-2 rounded-full" style="width:${val}%;background:${barC}"></div>
                    </div>
                    <span class="w-8 text-right">${val}</span>
                </div>`;
            }

            const issueHtml = (sd.issues || []).map(iss => {
                const ic = iss.severity === 'high' ? 'text-red-400' : 'text-yellow-400';
                return `<div class="${ic} text-xs">\u26A0 ${iss.msg}</div>`;
            }).join('') || '<div class="text-green-400 text-xs">\u2713 정상</div>';

            return `<div class="bg-gray-800 rounded-lg p-4 border ${borderC}">
                <div class="flex justify-between items-center mb-3">
                    <span class="font-semibold">${sd.name}</span>
                    <span class="text-2xl font-bold ${textC}">${sd.score}</span>
                </div>
                <div class="space-y-1.5 mb-3">
                    ${miniBar('Retry', scores.retry || 0)}
                    ${miniBar('RSSI', scores.rssi || 0)}
                    ${miniBar('\ub85c\ubc0d', scores.roaming || 0)}
                </div>
                <div class="grid grid-cols-2 gap-1 text-xs text-gray-400 mb-3">
                    <div>Retry: ${m.retry_pct || 0}%</div>
                    <div>RSSI: ${m.rssi_avg || '-'}dBm</div>
                    <div>\ub85c\ubc0d: ${m.roaming_count || 0}\ud68c</div>
                    <div>\ub290\ub9b0: ${m.slow_roaming || 0}\ud68c</div>
                </div>
                <div class="border-t border-gray-700 pt-2">${issueHtml}</div>
            </div>`;
        }).join('');
    }
})();

