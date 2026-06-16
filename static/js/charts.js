/* 분석 결과 차트 렌더링 — Overview, 로밍, 장치별 */
(function () {
    if (typeof DATA === 'undefined') return;

    // pcap에서 파싱된 문자열(IP·sta_name 등)을 innerHTML/Plotly에 주입하기 전 HTML
    // 특수문자 escape — 악의적 pcap 문자열이 XSS로 번지지 않도록 boundary 방어.
    // 전역에서 쓰도록 IIFE 상단에 정의. (gemini security-high 권고 반영)
    const escapeHtml = (str) => String(str == null ? '' : str)
        .replace(/[&<>"']/g, m => (
            { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]
        ));

    const DARK = {
        paper_bgcolor: 'rgba(0,0,0,0)',
        plot_bgcolor: 'rgba(0,0,0,0)',
        font: { color: '#9ca3af', size: 11 },
        margin: { t: 10, r: 10, b: 30, l: 40 },
        hoverlabel: {
            bgcolor: 'rgba(15,23,42,0.95)',  // slate-900 + 알파
            bordercolor: '#64748b',           // slate-500
            font: { color: '#f1f5f9', size: 12 },  // slate-100
        },
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
            const activePane = document.getElementById('tab-' + btn.dataset.tab);
            activePane.classList.remove('hidden');
            /* hidden→visible 시 plotly 차트 명시 resize (이전 패널 위에 그려지는 현상 회피) */
            requestAnimationFrame(() => {
                activePane.querySelectorAll('.js-plotly-plot').forEach(el => {
                    try { Plotly.Plots.resize(el); } catch (e) { /* ignore */ }
                });
                window.dispatchEvent(new Event('resize'));
            });
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
            textinfo: 'percent', textposition: 'auto',
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
            textinfo: 'percent', textposition: 'auto',
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
            textposition: 'auto',
            constraintext: 'none',
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
            textposition: 'auto',
            constraintext: 'none',
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
        devTable.innerHTML = ov.devices.map(d => {
            // ips는 빈도순. 첫번째 = 가장 신뢰할 만한 self IP. 나머지는 보조 관찰.
            let ipCell;
            if (!d.ips || d.ips.length === 0) {
                ipCell = '<span class="text-gray-600">-</span>';
            } else {
                const primary = `<span class="text-white">${d.ips[0]}</span>`;
                const secondary = d.ips.length > 1
                    ? ` <span class="text-gray-500 text-xs" title="추가 관찰된 IP (broadcast/forwarded 가능)">+${d.ips.length - 1}</span>`
                    : '';
                ipCell = primary + secondary;
            }
            return `<tr class="border-b border-gray-700/50">
                <td class="py-2 font-mono">${d.name}</td>
                <td class="py-2 text-gray-400 font-mono text-xs">${d.mac}</td>
                <td class="py-2 font-mono text-xs" title="${(d.ips || []).join(', ')}">${ipCell}</td>
                <td class="py-2"><span class="px-2 py-0.5 rounded text-xs ${d.role === 'AP' ? 'bg-green-900 text-green-300' : 'bg-blue-900 text-blue-300'}">${d.role}</span></td>
                <td class="py-2 text-right">${d.count.toLocaleString()}</td>
            </tr>`;
        }).join('');
    }

    /* ── 로밍 Gap 바 차트 ── */
    const roaming = DATA.roaming || {};
    const roamingChartEl = document.getElementById('chart-roaming-gap');
    const roamingTableEl = document.getElementById('roaming-table');
    if (!roaming.sequences || roaming.sequences.length === 0) {
        if (roamingChartEl) {
            roamingChartEl.style.height = 'auto';
            roamingChartEl.innerHTML = '<div class="text-center text-gray-500 text-sm py-12">로밍 이벤트가 감지되지 않았습니다.<br><span class="text-xs text-gray-600">단일 AP 환경이거나 캡처 구간 내 AP 전환 없음</span></div>';
        }
        if (roamingTableEl) roamingTableEl.style.display = 'none';
    } else if (roaming.sequences && roaming.sequences.length > 0) {
        if (roamingTableEl) roamingTableEl.style.display = '';
        const seqs = roaming.sequences;
        // AP 라벨: 로밍 전 AP(prev_ap_name) → 로밍 후 AP(ap_name). 직전 AP가 없으면
        // (최초 연결 또는 재분석 전 데이터) 후 AP만 표시.
        const roamAp = s => (s.prev_ap_name ? `${s.prev_ap_name} → ${s.ap_name}` : s.ap_name);
        Plotly.newPlot('chart-roaming-gap', [{
            type: 'bar',
            x: seqs.map((_, i) => i + 1),
            y: seqs.map(s => s.gap_ms),
            marker: {
                color: seqs.map(s => s.is_slow ? '#ef4444' : '#3b82f6'),
            },
            text: seqs.map(s => s.sta_name + ': ' + roamAp(s)),
            hovertemplate: '%{text}<br>%{y:.1f}ms<extra></extra>',
        }], {
            ...DARK,
            dragmode: 'zoom',
            xaxis: { title: '\ub85c\ubc0d \uc2dc\ud000\uc2a4 #' },
            yaxis: { title: 'Auth\u2192Assoc Gap (ms)' },
            shapes: [{
                type: 'line', x0: 0, x1: seqs.length + 1, y0: 100, y1: 100,
                line: { color: '#ef4444', dash: 'dash', width: 1 },
            }],
        }, {
            responsive: true,
            displayModeBar: true,
            displaylogo: false,
            modeBarButtonsToRemove: ['lasso2d', 'select2d'],
            scrollZoom: true,
        });

        // 로밍 테이블
        const rTable = document.querySelector('#roaming-table tbody');
        if (rTable) {
            const fmtTime = epoch => {
                const d = new Date(epoch * 1000);
                const pad = n => String(n).padStart(2, '0');
                const ms = String(Math.floor((d.getMilliseconds()))).padStart(3, '0');
                return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${ms}`;
            };
            rTable.innerHTML = seqs.map((s, i) =>
                `<tr class="border-b border-gray-700/50 ${s.is_slow ? 'text-red-400' : ''}">
                    <td class="py-1">${i + 1}</td>
                    <td class="py-1 font-mono text-xs">${fmtTime(s.auth_epoch)}</td>
                    <td class="py-1 font-mono text-xs">${s.sta_name}</td>
                    <td class="py-1 font-mono text-xs">${roamAp(s)}</td>
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

        // MCS / 레거시 레이트 분포 (PHY 모드별 grouped bar)
        const byPhy = s.mcs_by_phy || {};
        const PHY_COLORS = { HT: '#facc15', VHT: '#06b6d4', HE: '#8b5cf6', EHT: '#ec4899', Legacy: '#9ca3af' };
        const PHY_ORDER = ['HT', 'VHT', 'HE', 'EHT', 'Legacy'];
        const phyTraces = [];
        for (const phy of PHY_ORDER) {
            const dist = byPhy[phy];
            if (!dist || Object.keys(dist).length === 0) continue;
            const sortedKeys = Object.keys(dist).sort((a, b) => parseFloat(a) - parseFloat(b));
            const labels = sortedKeys.map(k => phy === 'Legacy' ? `Legacy ${k}Mbps` : `${phy} MCS${k}`);
            phyTraces.push({
                type: 'bar',
                name: phy,
                x: labels,
                y: sortedKeys.map(k => dist[k]),
                marker: { color: PHY_COLORS[phy] },
                text: sortedKeys.map(k => dist[k].toLocaleString()),
                textposition: 'outside',
                hovertemplate: '%{x}<br>프레임 %{y:,}<extra></extra>',
            });
        }
        if (phyTraces.length > 0) {
            const summary = s.phy_summary || {};
            const summaryStr = PHY_ORDER
                .filter(p => summary[p])
                .map(p => `${p}=${summary[p].toLocaleString()}`)
                .join(' / ');
            Plotly.newPlot('chart-device-mcs', phyTraces, {
                ...DARK,
                title: { text: summaryStr, font: { size: 11, color: '#9ca3af' }, x: 0.02, xanchor: 'left' },
                xaxis: { title: 'PHY 모드 · MCS / Legacy Mbps', tickangle: -30, tickfont: { size: 10 } },
                yaxis: { title: '프레임 수' },
                barmode: 'group',
                showlegend: true,
                legend: { orientation: 'h', y: 1.12 },
                margin: { t: 50 },
            }, { responsive: true, displayModeBar: false });
        } else {
            document.getElementById('chart-device-mcs').innerHTML = '<p class="text-gray-500 text-center py-10">MCS / 레거시 레이트 데이터 없음</p>';
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

        // PHY 모드 시간 분포 + Retry율 overlay (선택 장치)
        const bucketsM = s.per_bucket || [];
        const phyModes = ['HE', 'EHT', 'VHT', 'HT', 'Legacy'];
        const PHY_TIME_COLORS = { HE: '#8b5cf6', EHT: '#ec4899', VHT: '#06b6d4', HT: '#facc15', Legacy: '#6b7280' };
        if (bucketsM.length > 0 && document.getElementById('chart-device-mcs-time')) {
            const xt = bucketsM.map(b => new Date(b.epoch * 1000));
            const stackTraces = phyModes
                .filter(p => bucketsM.some(b => (b.phy_mode_dist || {})[p]))
                .map(p => ({
                    x: xt,
                    y: bucketsM.map(b => (b.phy_mode_dist || {})[p] || 0),
                    name: p, type: 'bar',
                    marker: { color: PHY_TIME_COLORS[p] },
                    hovertemplate: `<b>%{x|%H:%M:%S}</b><br>${p}: %{y:,}<extra></extra>`,
                }));
            const retryLine = {
                x: xt,
                y: bucketsM.map(b => b.retry_pct || 0),
                name: 'Retry율 (%)', type: 'scatter', mode: 'lines+markers',
                line: { color: '#f59e0b', width: 2 },
                marker: { color: '#f59e0b', size: 4 },
                yaxis: 'y2',
                hovertemplate: '<b>%{x|%H:%M:%S}</b><br>Retry: %{y}%<extra></extra>',
            };
            Plotly.newPlot('chart-device-mcs-time', [...stackTraces, retryLine], {
                ...DARK,
                barmode: 'stack',
                xaxis: { title: '시간' },
                yaxis: { title: '송신 프레임 수 (PHY 모드별)' },
                yaxis2: { title: 'Retry율 (%)', side: 'right', overlaying: 'y', showgrid: false, range: [0, 100] },
                legend: { orientation: 'h', y: 1.12, font: { size: 11 } },
                margin: { t: 40 },
            }, { responsive: true, displayModeBar: true });
        }

        // Retry 피크 zoom-in (선택 장치)
        const peaksContainer = document.getElementById('chart-device-retry-peaks');
        if (peaksContainer) {
            peaksContainer.innerHTML = '';
            const peaks = s.retry_peaks || [];
            if (peaks.length === 0) {
                peaksContainer.innerHTML = '<p class="text-gray-500 text-xs py-3">Retry 피크 구간 없음 (10% 이상 + 50프레임 이상 bucket 없음)</p>';
            } else {
                peaks.forEach((pk, idx) => {
                    const wrap = document.createElement('div');
                    wrap.className = 'bg-gray-700/30 rounded p-2 border border-gray-700';
                    const head = document.createElement('div');
                    const startStr = new Date(pk.start * 1000).toISOString().substr(11, 8);
                    head.className = 'text-xs text-gray-400 mb-1';
                    head.textContent = `Peak ${idx + 1}: ${startStr} ~ +${pk.duration}s, ` +
                        `프레임 ${(pk.total || 0).toLocaleString()}, ` +
                        `retry ${(pk.retry || 0).toLocaleString()} (${pk.retry_pct}%)`;
                    wrap.appendChild(head);
                    const div = document.createElement('div');
                    div.style.height = '180px';
                    const divId = `chart-device-retry-peak-${idx}`;
                    div.id = divId;
                    wrap.appendChild(div);
                    peaksContainer.appendChild(wrap);
                    const subs = pk.sub_buckets || [];
                    if (subs.length === 0) return;
                    Plotly.newPlot(divId, [
                        {
                            x: subs.map(b => new Date(b.epoch * 1000)),
                            y: subs.map(b => b.total || 0),
                            type: 'bar', name: '프레임 수',
                            marker: { color: '#3b82f6' },
                            customdata: subs.map(b => [
                                b.retry || 0, b.retry_pct || 0, b.tx_total || 0, b.mcs_breakdown || '-',
                            ]),
                            hovertemplate:
                                '<b>%{x|%H:%M:%S}</b><br>' +
                                '프레임: %{y:,} (retry %{customdata[0]:,} / %{customdata[1]}%)<br>' +
                                '송신: %{customdata[2]:,}<br>' +
                                'MCS 분포: %{customdata[3]}' +
                                '<extra></extra>',
                        },
                        {
                            x: subs.map(b => new Date(b.epoch * 1000)),
                            y: subs.map(b => b.retry_pct || 0),
                            type: 'scatter', mode: 'lines+markers', name: 'Retry율 (%)',
                            line: { color: '#f59e0b', width: 2 },
                            marker: { color: '#f59e0b', size: 4 },
                            yaxis: 'y2',
                            hovertemplate: 'Retry: %{y}%<extra></extra>',
                        },
                    ], {
                        ...DARK,
                        xaxis: { title: '시간 (1초)' },
                        yaxis: { title: '프레임 수' },
                        yaxis2: { title: 'Retry율 (%)', side: 'right', overlaying: 'y', showgrid: false, range: [0, 100] },
                        showlegend: false,
                        margin: { t: 10, b: 30, l: 50, r: 50 },
                    }, { responsive: true, displayModeBar: false });
                });
            }
        }

        // 구간별 프레임 수 시계열 (단일 색 막대, hover에 MCS 분포)
        const buckets = s.per_bucket || [];
        if (buckets.length > 0) {
            Plotly.newPlot('chart-device-frames', [{
                x: buckets.map(b => new Date(b.epoch * 1000)),
                y: buckets.map(b => b.total || 0),
                type: 'bar', marker: { color: '#3b82f6' },
                customdata: buckets.map(b => [
                    b.retry || 0,
                    b.retry_pct || 0,
                    b.tx_total || 0,
                    b.mcs_breakdown || '-',
                    (b.avg_mcs ?? '-'),
                    (b.legacy_pct ?? 0),
                ]),
                hovertemplate:
                    '<b>%{x|%H:%M:%S}</b><br>' +
                    '프레임: <b>%{y:,}</b> (retry %{customdata[0]:,} / %{customdata[1]}%)<br>' +
                    '송신: %{customdata[2]:,}<br>' +
                    'MCS 분포: %{customdata[3]}<br>' +
                    '평균 MCS: %{customdata[4]} / Legacy 비율: %{customdata[5]}%' +
                    '<extra></extra>',
            }], {
                ...DARK,
                xaxis: { title: '시간' },
                yaxis: { title: '프레임 수' },
                margin: { t: 20 },
            }, { responsive: true, displayModeBar: true });
        }

        // 구간별 Retry율 시계열 (라인만, hover에 프레임수/MCS 정보 포함)
        if (buckets.length > 0) {
            Plotly.newPlot('chart-device-timeline', [{
                x: buckets.map(b => new Date(b.epoch * 1000)),
                y: buckets.map(b => b.retry_pct),
                type: 'scatter', mode: 'lines+markers',
                name: 'Retry율 (%)',
                line: { color: '#f59e0b', width: 2 },
                marker: { color: '#f59e0b', size: 5 },
                customdata: buckets.map(b => [
                    b.total || 0,
                    b.retry || 0,
                    b.mcs_breakdown || '-',
                    (b.avg_mcs ?? '-'),
                    (b.legacy_pct ?? 0),
                    b.tx_total || 0,
                ]),
                hovertemplate:
                    '<b>%{x|%H:%M:%S}</b><br>' +
                    'Retry율: <b>%{y}%</b><br>' +
                    '프레임: %{customdata[0]:,} (retry %{customdata[1]:,})<br>' +
                    '송신: %{customdata[5]:,}<br>' +
                    'MCS 분포: %{customdata[2]}<br>' +
                    '평균 MCS: %{customdata[3]} / Legacy 비율: %{customdata[4]}%' +
                    '<extra></extra>',
            }], {
                ...DARK,
                xaxis: { title: '시간' },
                yaxis: { title: 'Retry율 (%)', range: [0, 100] },
                hovermode: 'x unified',
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
            { label: '평균 RTT', value: s.avg != null ? s.avg + 'ms' : '—', color: s.avg == null ? 'text-gray-500' : '' },
            { label: 'P95 RTT', value: s.p95 != null ? s.p95 + 'ms' : '—', color: s.p95 == null ? 'text-gray-500' : (s.p95 > 10 ? 'text-yellow-400' : '') },
        ].map(k =>
            `<div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <p class="text-xs text-gray-500">${k.label}</p>
                <p class="text-xl font-bold ${k.color}">${k.value}</p>
            </div>`
        ).join('');
    }

    // Ping RTT 시계열 (큰 차트) — pairs가 없어도 losses만 있으면 마커로 표시
    const pingRttEl = document.getElementById('chart-ping-rtt');
    if (pingRttEl && pairs.length === 0 && losses.length === 0) {
        pingRttEl.style.height = 'auto';
        pingRttEl.innerHTML = '<div class="text-center text-gray-500 text-sm py-12">매칭된 RTT 페어가 없습니다.<br><span class="text-xs text-gray-600">단방향 캡처(STA 다운링크만 보임)이거나 ICMP 트래픽이 없는 캡처</span></div>';
    } else if (pingRttEl && pairs.length === 0 && losses.length > 0) {
        // 단방향 캡처에서 seq gap loss만 있는 경우 — 마커만 표시
        Plotly.newPlot('chart-ping-rtt', [{
            x: losses.map(p => new Date(p.epoch * 1000)),
            y: losses.map(() => 1),
            type: 'scatter', mode: 'markers',
            name: 'LOSS (seq gap)',
            marker: { color: '#ef4444', size: 12, symbol: 'x', line: { width: 2 } },
            text: losses.map(p => 'Seq ' + p.seq + ' LOSS  ' + p.src + '→' + p.dst),
            hovertemplate: '%{text}<extra></extra>',
        }], {
            ...DARK,
            xaxis: { title: { text: '시간', font: { size: 12 } }, gridcolor: '#374151' },
            yaxis: { title: { text: 'Loss', font: { size: 12 } }, gridcolor: '#374151', range: [0, 2], tickvals: [1], ticktext: ['loss'] },
            legend: { orientation: 'h', x: 0, y: 1.12, font: { size: 12 } },
            margin: { t: 60, r: 20, b: 50, l: 60 },
            annotations: [{
                xref: 'paper', yref: 'paper', x: 0.5, y: 0.92, showarrow: false,
                text: 'RTT 측정 불가 (단방향 캡처) — 손실 발생 시점만 표시',
                font: { size: 11, color: '#9ca3af' },
            }],
        }, { responsive: true, displayModeBar: true, displaylogo: false, modeBarButtonsToRemove: ['lasso2d', 'select2d'] });
    }
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
                text: losses.map(p => 'Seq ' + p.seq + (p.status === 'loss_gap' ? ' LOSS (seq gap)  ' : ' LOSS  ' + (p.req_num != null ? '#' + p.req_num + '  ' : '')) + p.src + '\u2192' + p.dst),
                hovertemplate: '%{text}<extra></extra>',
            });
        }
        Plotly.newPlot('chart-ping-rtt', traces_ping, {
            ...DARK,
            xaxis: { title: { text: '시간', font: { size: 12 } }, gridcolor: '#374151' },
            yaxis: { title: { text: 'RTT (ms)', font: { size: 12 } }, gridcolor: '#374151' },
            legend: { orientation: 'h', x: 0, y: 1.12, font: { size: 12 } },
            margin: { t: 60, r: 20, b: 50, l: 60 },
        }, {
            responsive: true,
            displayModeBar: true,
            displaylogo: false,
            modeBarButtonsToRemove: ['lasso2d', 'select2d'],
        });
    }

    // RTT 히스토그램
    const pingHistEl = document.getElementById('chart-ping-hist');
    if (pingHistEl && pairs.length === 0) {
        pingHistEl.style.height = 'auto';
        pingHistEl.innerHTML = '<div class="text-center text-gray-500 text-sm py-12">RTT 데이터 없음</div>';
    }
    if (pairs.length > 0 && document.getElementById('chart-ping-hist')) {
        // RTT 분포는 0~1ms에 극단적으로 쏠리고(모니터 캡처 시각차) 드문 이상치(수백 ms)가
        // 긴 꼬리를 만든다. 0~max 전체에 균등 bin을 적용하면 첫 막대 하나에 대부분이 몰려
        // 분포가 안 보인다. → 표시 범위를 p99로 클립하고 bin을 세밀화해 본체 분포를 펼치고,
        // p99 초과 이상치는 데이터에서 빼지 않고 축만 잘라 카운트로 안내한다.
        const rtts = pairs.map(p => p.rtt_ms).filter(v => typeof v === 'number');
        const sorted = [...rtts].sort((a, b) => a - b);
        // pairs는 있으나 유효 RTT(rtt_ms 숫자)가 하나도 없으면 sorted가 비어
        // p99=undefined→hi=NaN이 되어 Plotly 렌더가 깨진다. 빈 경우 1ms로 폴백.
        const p99 = sorted.length ? sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.99))] : 1;
        const hi = Math.max(p99, 1);                 // 표시 상한 (최소 1ms)
        const outliers = rtts.filter(v => v > hi).length;
        const maxRtt = sorted[sorted.length - 1];
        const annotations = outliers > 0 ? [{
            xref: 'paper', yref: 'paper', x: 1, y: 1, xanchor: 'right', yanchor: 'top',
            text: `+${outliers.toLocaleString()}건 > ${hi.toFixed(1)}ms (최대 ${maxRtt.toFixed(1)}ms)`,
            showarrow: false, font: { size: 10, color: '#9ca3af' },
        }] : [];
        Plotly.newPlot('chart-ping-hist', [{
            x: rtts, type: 'histogram',
            xbins: { start: 0, end: hi, size: (hi / 40) || 0.1 },
            marker: { color: '#3b82f6' },
        }], {
            ...DARK,
            xaxis: { title: { text: 'RTT (ms)', font: { size: 12 } }, gridcolor: '#374151', range: [0, hi] },
            yaxis: { title: { text: '빈도', font: { size: 12 } }, gridcolor: '#374151' },
            margin: { t: 10, r: 10, b: 50, l: 50 },
            annotations,
        }, { responsive: true, displayModeBar: false });
    }

    // Ping 통계 (서버에서 계산된 값 사용)
    const pingStats = document.getElementById('ping-stats');
    // Phase 2b 교차 검증 요약 (양방향 흐름에 의미 있음)
    function crossValidationRows(s) {
        const verified = s.verified_cycle ?? 0;
        const replyMissing = s.reply_missing ?? 0;
        const reqMissing = s.request_missing ?? 0;
        const fullyUnobs = s.fully_unobserved ?? 0;
        if (verified + replyMissing + reqMissing + fullyUnobs === 0) return '';
        return `
            <tr class="border-t border-gray-700"><td class="text-gray-400 py-1" colspan="2"><span class="text-xs text-gray-500">— 교차 검증 (seq 집합 분석) —</span></td></tr>
            <tr><td class="text-gray-400 py-1">검증된 사이클</td><td class="text-right text-green-400" title="req와 reply 둘 다 같은 seq로 관측 — 무선 손실 없음">${verified.toLocaleString()}건</td></tr>
            <tr><td class="text-gray-400 py-1">확정 무선 손실 후보</td><td class="text-right ${replyMissing > 0 ? 'text-red-400 font-bold' : 'text-gray-300'}" title="req는 보였는데 같은 seq의 reply가 캡처 어디에도 없음">${replyMissing.toLocaleString()}건</td></tr>
            <tr><td class="text-gray-400 py-1">캡처 누락 (request만 미관측)</td><td class="text-right text-yellow-400" title="reply는 보였는데 같은 seq의 request가 캡처 안 됨 — 무선은 OK, 캡처 품질 이슈">${reqMissing.toLocaleString()}건</td></tr>
            <tr><td class="text-gray-400 py-1">양쪽 미관측 (seq gap)</td><td class="text-right text-gray-400" title="seq 범위에 둘 다 안 보이는 갭 — 캡처 누락 또는 무선 손실 (구분 불가)">${fullyUnobs.toLocaleString()}건</td></tr>
        `;
    }

    if (pingStats && !pingStatsData.count) {
        // 매칭된 RTT 페어가 없을 때 — 캡처 모드 + 손실 요약 안내
        const mode = pingStatsData.capture_mode || 'none';
        const modeLabel = { bidirectional: '양방향', unidirectional: '단방향', mixed: '혼합', none: '없음' }[mode] || mode;
        pingStats.innerHTML = `<div class="text-sm text-gray-400 leading-relaxed">
            <p class="mb-2">매칭된 RTT 페어가 없어 통계를 계산할 수 없습니다.</p>
            <table class="w-full text-sm">
                <tr><td class="text-gray-400 py-1">캡처 모드</td><td class="text-right text-white font-mono">${modeLabel}</td></tr>
                ${crossValidationRows(pingStatsData)}
                <tr class="border-t border-gray-700"><td class="text-gray-400 py-1">측정 불가 (unmeasurable)</td><td class="text-right text-gray-500">${pingStatsData.unmeasurable_count ?? 0}건</td></tr>
                <tr><td class="text-gray-400 py-1">전체 request</td><td class="text-right text-white">${pingStatsData.req_total_raw ?? 0}건</td></tr>
                <tr><td class="text-gray-400 py-1">전체 reply</td><td class="text-right text-white">${pingStatsData.reply_total_raw ?? 0}건</td></tr>
            </table>
        </div>`;
    } else if (pingStats && pingStatsData.count) {
        const s = pingStatsData;
        const reqRaw = s.req_total_raw ?? 0;
        const reqRetryBit = s.req_retry_bit ?? 0;
        const reqFirst = s.req_first_send ?? (reqRaw - reqRetryBit);
        const reqSkip = s.req_retry_skipped ?? 0;
        const replyRaw = s.reply_total_raw ?? 0;
        const replyRetryBit = s.reply_retry_bit ?? 0;
        const replyUnique = s.reply_unique_count ?? 0;
        const replyDup = replyRaw - replyUnique;
        pingStats.innerHTML = `
            <table class="w-full text-sm">
                <tr><td class="text-gray-400 py-1">총 Ping (unique req)</td><td class="text-right text-white font-bold">${(s.count + s.loss_count).toLocaleString()}건</td></tr>
                <tr><td class="text-gray-400 py-1">응답 (match)</td><td class="text-right text-green-400">${s.count.toLocaleString()}건</td></tr>
                <tr><td class="text-gray-400 py-1">미응답 (Loss)</td><td class="text-right text-red-400">${s.loss_count.toLocaleString()}건 (${s.loss_pct}%)</td></tr>
                <tr class="border-t border-gray-700"><td class="text-gray-400 py-1">Min RTT</td><td class="text-right text-white">${s.min}ms</td></tr>
                <tr><td class="text-gray-400 py-1">Avg RTT</td><td class="text-right text-white font-bold">${s.avg != null ? s.avg + 'ms' : '—'}</td></tr>
                <tr><td class="text-gray-400 py-1">Max RTT</td><td class="text-right text-white">${s.max}ms</td></tr>
                <tr class="border-t border-gray-700"><td class="text-gray-400 py-1">P50 (중앙값)</td><td class="text-right text-white">${s.p50}ms</td></tr>
                <tr><td class="text-gray-400 py-1">P95</td><td class="text-right ${s.p95 == null ? 'text-gray-500' : (s.p95 > 10 ? 'text-yellow-400' : 'text-white')}">${s.p95 != null ? s.p95 + 'ms' : '—'}</td></tr>
                <tr><td class="text-gray-400 py-1">P99</td><td class="text-right ${s.p99 > 20 ? 'text-red-400' : 'text-white'}">${s.p99}ms</td></tr>
            </table>
            <details class="mt-2 group">
                <summary class="cursor-pointer select-none text-xs text-gray-500 hover:text-gray-300 py-1 flex items-center gap-1">
                    <span class="group-open:rotate-90 inline-block transition-transform">▶</span> 세부 — Raw 캡처 카운트 · 교차 검증
                </summary>
                <table class="w-full text-sm mt-1">
                    <tr><td class="text-gray-400 py-1" colspan="2"><span class="text-xs text-gray-500">— Raw 캡처 카운트 (모니터 sniffer 기준) —</span></td></tr>
                    <tr><td class="text-gray-400 py-1">Request 캡처 (raw)</td><td class="text-right text-white">${reqRaw.toLocaleString()}건</td></tr>
                    <tr><td class="text-gray-400 py-1 pl-3 text-xs">└ 첫 송신 (retry 비트 X)</td><td class="text-right text-green-400 text-xs">${reqFirst.toLocaleString()}건</td></tr>
                    <tr><td class="text-gray-400 py-1 pl-3 text-xs">└ 재전송 (retry 비트 O)</td><td class="text-right text-yellow-400 text-xs">${reqRetryBit.toLocaleString()}건</td></tr>
                    <tr><td class="text-gray-400 py-1 pl-3 text-xs">└ 동일 seq dedup (매칭 제외)</td><td class="text-right text-gray-500 text-xs">${reqSkip.toLocaleString()}건</td></tr>
                    <tr><td class="text-gray-400 py-1">Reply 캡처 (raw)</td><td class="text-right text-white">${replyRaw.toLocaleString()}건</td></tr>
                    <tr><td class="text-gray-400 py-1 pl-3 text-xs">└ retry 비트 O</td><td class="text-right text-yellow-400 text-xs">${replyRetryBit.toLocaleString()}건</td></tr>
                    <tr><td class="text-gray-400 py-1 pl-3 text-xs">└ unique seq</td><td class="text-right text-gray-300 text-xs">${replyUnique.toLocaleString()}건</td></tr>
                    <tr><td class="text-gray-400 py-1 pl-3 text-xs">└ 다중 캡처 중복</td><td class="text-right text-gray-500 text-xs">${replyDup.toLocaleString()}건</td></tr>
                    ${crossValidationRows(s)}
                </table>
            </details>`;
    }

    // 관찰된 ICMP 프레임 (RTT 측정 불가, 단방향 캡처에서만)
    const observations = ping.observations || [];
    const obsDetails = document.getElementById('ping-observations-details');
    const obsTable = document.querySelector('#ping-observations-table tbody');
    const obsCount = document.getElementById('ping-observations-count');
    if (obsDetails && observations.length > 0) {
        obsDetails.style.display = '';
        if (obsCount) obsCount.textContent = `(${observations.length}건)`;
        const obsDirSel = document.getElementById('ping-obs-filter-dir');
        const obsFlowSel = document.getElementById('ping-obs-filter-flow');
        const obsFilterCount = document.getElementById('ping-obs-filter-count');
        // 흐름 표시 정규화 — reply 프레임의 src/dst가 tshark multi-value(콤마 결합)로
        // 잡히면 첫 IP만 취해 흐름 라벨·옵션·필터를 하나로 합친다.
        const firstIp = ip => String(ip || '').split(',')[0].trim();
        function renderObsTable() {
            if (!obsTable) return;
            const fDir = obsDirSel ? obsDirSel.value : '';      // ''=전체 | reply(응답) | request(요청)
            const fFlow = obsFlowSel ? obsFlowSel.value : '';   // ''=전체 | "src → dst"
            const rows = observations.filter(o => {
                if (fDir && o.direction !== fDir) return false;
                if (fFlow && `${firstIp(o.src)} → ${firstIp(o.dst)}` !== fFlow) return false;
                return true;
            });
            if (obsFilterCount) obsFilterCount.textContent = `${rows.length.toLocaleString()} / ${observations.length.toLocaleString()}건`;
            if (rows.length === 0) {
                obsTable.innerHTML = '<tr><td colspan="9" class="text-gray-500 text-center py-6">조건에 맞는 항목이 없습니다.</td></tr>';
                return;
            }
            obsTable.innerHTML = rows.map((o, i) => {
                const dirBadge = o.direction === 'request'
                    ? '<span class="bg-blue-900 text-blue-300 px-1.5 py-0.5 rounded text-xs">req</span>'
                    : '<span class="bg-purple-900 text-purple-300 px-1.5 py-0.5 rounded text-xs">reply</span>';
                const typeBadge = o.icmp_type === '8' ? 'type=8 (echo req)' : (o.icmp_type === '0' ? 'type=0 (echo reply)' : 'type=' + o.icmp_type);
                return `<tr class="border-b border-gray-700/30 text-gray-400 hover:bg-gray-700/30">
                    <td class="py-1 px-1">${i + 1}</td>
                    <td class="py-1 px-1">${dirBadge}</td>
                    <td class="py-1 px-1 text-xs text-gray-500">${typeBadge}</td>
                    <td class="py-1 px-1">${o.seq || '-'}</td>
                    <td class="py-1 px-1 text-gray-500">${o.ident || '-'}</td>
                    <td class="py-1 px-1">#${o.frame_num}</td>
                    <td class="py-1 px-1">${o.time || ''}</td>
                    <td class="py-1 px-1">${firstIp(o.src)} → ${firstIp(o.dst)}</td>
                    <td class="py-1 px-1">${o.has_retry ? 'R' : ''}</td>
                </tr>`;
            }).join('');
        }
        if (obsFlowSel) {
            const flows = [...new Set(observations.map(o => `${firstIp(o.src)} → ${firstIp(o.dst)}`))].sort();
            obsFlowSel.insertAdjacentHTML('beforeend',
                flows.map(f => `<option value="${escapeHtml(f)}">${escapeHtml(f)}</option>`).join(''));
        }
        [obsDirSel, obsFlowSel].forEach(el => { if (el) el.addEventListener('change', renderObsTable); });
        renderObsTable();
    } else if (obsDetails) {
        obsDetails.style.display = 'none';
    }

    // Ping 전수검사 테이블
    const pingFullTable = document.querySelector('#ping-full-table tbody');
    const pingStatusSel = document.getElementById('ping-filter-status');
    const pingFlowSel = document.getElementById('ping-filter-flow');
    const pingRetryChk = document.getElementById('ping-filter-retry');
    const pingFullCount = document.getElementById('ping-full-count');

    function renderPingFullTable() {
        if (!pingFullTable) return;
        const fStatus = pingStatusSel ? pingStatusSel.value : '';   // ''=전체 | matched | loss
        const fFlow = pingFlowSel ? pingFlowSel.value : '';         // ''=전체 | "src → dst"
        const fRetry = pingRetryChk ? pingRetryChk.checked : false;
        const rows = fullList.filter(p => {
            // 손실은 loss + loss_gap(단방향 seq gap) 둘 다 포함.
            if (fStatus === 'loss' && !(p.status === 'loss' || p.status === 'loss_gap')) return false;
            if (fStatus === 'matched' && p.status !== 'matched') return false;
            if (fFlow && `${p.src} → ${p.dst}` !== fFlow) return false;
            if (fRetry && !p.has_retry) return false;
            return true;
        });
        if (pingFullCount) pingFullCount.textContent = `${rows.length.toLocaleString()} / ${fullList.length.toLocaleString()}건`;
        if (rows.length === 0) {
            pingFullTable.innerHTML = '<tr><td colspan="10" class="text-gray-500 text-center py-6">조건에 맞는 항목이 없습니다.</td></tr>';
            return;
        }
        pingFullTable.innerHTML = rows.map((p, i) => {
            const isLoss = p.status === 'loss' || p.status === 'loss_gap';
            const isGap = p.status === 'loss_gap';
            const rowClass = isLoss ? 'text-red-400 bg-red-900/20' : (p.has_retry ? 'text-yellow-400' : '');
            const statusBadge = isLoss
                ? (isGap
                    ? '<span class="bg-red-900 text-red-300 px-1.5 py-0.5 rounded text-xs font-bold" title="seq \uac2d\uc73c\ub85c \uac80\ucd9c\ub41c \uc9c4\uc9dc \ubb34\uc120 \uc190\uc2e4">LOSS (seq gap)</span>'
                    : '<span class="bg-red-900 text-red-300 px-1.5 py-0.5 rounded text-xs font-bold">LOSS</span>')
                : (p.has_retry
                    ? '<span class="bg-yellow-900 text-yellow-300 px-1.5 py-0.5 rounded text-xs">RETRY</span>'
                    : '<span class="bg-green-900 text-green-300 px-1.5 py-0.5 rounded text-xs">OK</span>');
            const rttStr = p.rtt_ms !== null ? p.rtt_ms.toFixed(2) : '-';
            const reqStr = p.req_num != null ? '#' + p.req_num : '-';
            const replyStr = p.reply_num != null ? '#' + p.reply_num : '-';
            const replyTime = p.reply_time || '-';
            return `<tr class="border-b border-gray-700/30 ${rowClass} hover:bg-gray-700/30">
                <td class="py-1 px-1">${i + 1}</td>
                <td class="py-1 px-1">${p.seq || '-'}</td>
                <td class="py-1 px-1">${statusBadge}</td>
                <td class="py-1 px-1">${reqStr}</td>
                <td class="py-1 px-1">${p.req_time || ''}</td>
                <td class="py-1 px-1">${replyStr}</td>
                <td class="py-1 px-1">${replyTime}</td>
                <td class="py-1 px-1 text-right ${isLoss ? '' : (p.rtt_ms > 10 ? 'text-yellow-400 font-bold' : '')}">${rttStr}</td>
                <td class="py-1 px-1">${p.src} \u2192 ${p.dst}</td>
                <td class="py-1 px-1">${p.has_retry ? 'R' : ''}</td>
            </tr>`;
        }).join('');
    }
    // 흐름(Src→Dst) 드롭다운 옵션 — 데이터에 등장한 흐름만 채운다.
    if (pingFlowSel && fullList.length > 0) {
        const flows = [...new Set(fullList.map(p => `${p.src} → ${p.dst}`))].sort();
        pingFlowSel.insertAdjacentHTML('beforeend',
            flows.map(f => `<option value="${escapeHtml(f)}">${escapeHtml(f)}</option>`).join(''));
    }
    [pingStatusSel, pingFlowSel, pingRetryChk].forEach(el => {
        if (el) el.addEventListener('change', renderPingFullTable);
    });
    if (fullList.length > 0) renderPingFullTable();

    /* ── 종합 진단 — 고급 UI ── */
    const diag = DATA.diagnosis || {};
    const health = diag.health || {};
    const compScores = diag.component_scores || {};
    const stadiags = diag.sta_diags || [];
    const issues = diag.issues || [];
    const correlations = diag.correlations || [];

    // 종합 진단 (다중 신호 결합 결론) — 단일 결론은 그대로 두고 추가 표시.
    //
    // 키 동기화: analyzer/core/modules/causality.py 의 SIG_* 상수와
    // 1:1 매핑돼야 한다. 새 signal_type을 추가할 때 이 맵을 함께 갱신하지
    // 않으면 미등록 key는 raw 영문 키(escapeHtml 처리)로 fallback 노출돼
    // UI에서 어색하게 보인다. (PR #5 검토: claude info-level 권고)
    const SIGNAL_TYPE_LABEL = {
        weak_rssi: '약신호',
        high_retry: 'retry 폭증',
        slow_roaming: '슬로우 로밍',
        frequent_roaming: '잦은 로밍',
        high_loss: 'Ping Loss',
        delay_zone: '지연 구간',
        anomaly: '이상 프레임',
    };
    const corrCountEl = document.getElementById('correlations-count');
    if (corrCountEl) {
        corrCountEl.textContent = correlations.length
            ? `${correlations.length}건`
            : '결합 결론 없음';
    }
    const corrListEl = document.getElementById('correlations-list');
    if (corrListEl) {
        if (correlations.length === 0) {
            corrListEl.innerHTML =
                '<div class="text-gray-500 text-xs text-center py-3">' +
                '단일 결론이 시간적으로 결합되지 않았습니다. 아래 단일 결론을 독립적으로 확인하세요.' +
                '</div>';
        } else {
            corrListEl.innerHTML = correlations.map(c => {
                const confPct = Math.round((c.confidence || 0) * 100);
                const confColor = confPct >= 80 ? 'bg-red-700'
                    : confPct >= 60 ? 'bg-yellow-700' : 'bg-blue-700';
                const confBadge = `<span class="${confColor} text-white px-2 py-0.5 rounded text-xs font-bold tabular-nums" title="결합 신호 수와 시간 윈도우 겹침으로 산출한 신뢰도">${confPct}% conf</span>`;
                const sigChips = (c.signals || []).map(s => {
                    const label = SIGNAL_TYPE_LABEL[s.type] || escapeHtml(s.type);
                    return `<span class="inline-block bg-purple-900/60 border border-purple-700 text-purple-200 text-xs px-2 py-0.5 rounded">${label}</span>`;
                }).join(' ');
                const refs = c.frame_refs || [];
                const tw = c.time_window;
                const evidenceBtn = (refs.length && tw)
                    ? `<button type="button"
                            class="evidence-jump ml-auto text-xs px-2 py-0.5 rounded bg-purple-700 hover:bg-purple-600 text-white"
                            data-start="${tw.start_epoch}" data-end="${tw.end_epoch}"
                            data-refs="${refs.join(',')}"
                            title="결합된 모든 신호의 증거 프레임 ${refs.length}건">\u{1F50D} 증거 보기 (${refs.length})</button>`
                    : '';
                const staLabel = escapeHtml(c.sta_name || c.sta_mac || '?');
                return `<div class="bg-slate-800 rounded-lg p-3 border border-purple-800/50">
                    <div class="flex items-center gap-2 mb-2 flex-wrap">
                        ${confBadge}
                        <span class="text-sm font-medium text-purple-100">${escapeHtml(c.title)}</span>
                        <span class="text-xs text-gray-500">STA ${staLabel}</span>
                        ${evidenceBtn}
                    </div>
                    <div class="flex items-center gap-1.5 flex-wrap text-xs ml-1 mb-1">
                        <span class="text-gray-500">결합 신호:</span>
                        ${sigChips}
                    </div>
                    <div class="text-xs text-gray-400 ml-1">${escapeHtml(c.explanation)}</div>
                </div>`;
            }).join('');
        }
    }

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
                const refs = iss.frame_refs || [];
                const tw = iss.time_window;
                // 근거가 있으면 "증거 보기" 버튼 — 타임라인 탭으로 점프 + 하이라이트
                const evidenceBtn = (refs.length && tw)
                    ? `<button type="button"
                            class="evidence-jump ml-auto text-xs px-2 py-0.5 rounded bg-gray-700 hover:bg-blue-600 text-gray-200 hover:text-white border border-gray-600"
                            data-start="${tw.start_epoch}" data-end="${tw.end_epoch}"
                            data-refs="${refs.join(',')}"
                            title="통합 타임라인에서 증거 프레임 ${refs.length}건 보기">\u{1F50D} 증거 보기 (${refs.length})</button>`
                    : '';
                return `<div class="rounded-lg p-3 border ${style}">
                    <div class="flex items-center gap-2 mb-1">
                        ${badge}
                        <span class="text-xs text-gray-400">${iss.category}</span>
                        <span class="text-sm font-medium">${iss.msg}</span>
                        ${evidenceBtn}
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
                const refs = iss.frame_refs || [];
                const tw = iss.time_window;
                const evidenceBtn = (refs.length && tw)
                    ? `<button type="button"
                            class="evidence-jump ml-1 text-[10px] px-1.5 py-0.5 rounded bg-gray-700 hover:bg-blue-600 text-gray-300 hover:text-white border border-gray-600"
                            data-start="${tw.start_epoch}" data-end="${tw.end_epoch}"
                            data-refs="${refs.join(',')}"
                            title="증거 프레임 ${refs.length}건 보기">\u{1F50D}</button>`
                    : '';
                return `<div class="${ic} text-xs flex items-center gap-1">\u26A0 <span>${iss.msg}</span>${evidenceBtn}</div>`;
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

    /* ── 접이식 <details>가 펼쳐질 때 Plotly 차트 리사이즈 ──
     * <details>가 닫힌 상태에서 Plotly.newPlot이 호출되면 컨테이너 폭이
     * 0이므로 차트가 깨진다. open 이벤트에서 내부 모든 차트를 리사이즈. */
    document.addEventListener('click', (e) => {
        const btn = e.target.closest('.evidence-jump');
        if (!btn) return;
        e.preventDefault();
        const start = parseFloat(btn.dataset.start);
        const end = parseFloat(btn.dataset.end);
        const refs = (btn.dataset.refs || '')
            .split(',').map(s => parseInt(s, 10)).filter(n => !isNaN(n));
        if (window.TimelineDebug && typeof window.TimelineDebug.focus === 'function') {
            window.TimelineDebug.focus({ start, end, frameRefs: refs });
        }
    });

    document.querySelectorAll('#tab-devices details').forEach(d => {
        d.addEventListener('toggle', () => {
            if (!d.open) return;
            d.querySelectorAll('.js-plotly-plot').forEach(el => {
                try { Plotly.Plots.resize(el); } catch (_) { /* ignore */ }
            });
        });
    });
})();

