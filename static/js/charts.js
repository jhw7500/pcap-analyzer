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

    /* ── 무선 병합 요약 카드 ── 다중 무선 dedup 시(DATA.merge)만 표시, 구버전 결과는 무동작 */
    const mergeInfo = DATA.merge;
    if (kpiContainer && mergeInfo && typeof mergeInfo.duplicates === 'number') {
        const coverage = mergeInfo.coverage || {};
        const both = typeof coverage.both === 'number' ? coverage.both : 0;
        const only = coverage.only || {};
        const onlyParts = Object.entries(only)
            .filter(([, n]) => typeof n === 'number' && n > 0)
            .map(([tag, n]) => `${escapeHtml(tag)}: ${n.toLocaleString()}`)
            .join(', ');
        const onlyLine = onlyParts
            ? `<p class="text-xs text-gray-500 mt-1">단독 포착 — ${onlyParts}</p>`
            : '';
        kpiContainer.insertAdjacentHTML('afterend',
            `<div class="bg-gray-800 rounded-lg p-4 border border-gray-700 mb-6">
                <h3 class="text-sm font-semibold text-gray-400 mb-1">무선 병합</h3>
                <p class="text-sm text-gray-300">중복 제거 <span class="font-semibold text-white">${mergeInfo.duplicates.toLocaleString()}</span>건 · 2개 이상 포착 <span class="font-semibold text-white">${both.toLocaleString()}</span>건</p>
                ${onlyLine}
            </div>`
        );
    }

    /* ── 스니퍼 비교 카드 ── 다중 무선 병합 시(DATA.sniffer_compare)만 표시, 구버전 결과는 무동작 */
    const sniffer = DATA.sniffer_compare;
    const snifferCard = document.getElementById('sniffer-compare-card');
    if (snifferCard && sniffer && Array.isArray(sniffer.tags) && sniffer.tags.length >= 2) {
        snifferCard.classList.remove('hidden');
        const tagNames = {};
        (DATA.sources || []).forEach(s => { if (s.tag) tagNames[s.tag] = s.name; });
        const label = t => tagNames[t] ? `${t} (${tagNames[t]})` : t;

        /* 커버리지 분해 — dedup 그룹 기준 양쪽/단독 비율 (스니퍼 배치 평가 핵심 수치) */
        const cov = sniffer.coverage || {};
        const totalGroups = cov.groups_total || 0;
        const pct = n => totalGroups ? (100 * n / totalGroups).toFixed(1) : '0.0';
        const only = cov.only || {};
        const parts = [`2개 이상 포착 <span class="font-semibold text-white">${(cov.both || 0).toLocaleString()}</span>건 (${pct(cov.both || 0)}%)`]
            .concat(sniffer.tags.filter(t => only[t]).map(t =>
                `${escapeHtml(label(t))} 단독 <span class="font-semibold text-white">${only[t].toLocaleString()}</span>건 (${pct(only[t])}%)`));
        document.getElementById('sniffer-coverage-line').innerHTML = parts.join(' · ');

        /* 초당 시계열 3단: Frames/s · 평균 RSSI · Retry% — 소스별 trace */
        const SRC_COLORS = { w1: '#3b82f6', w2: '#f59e0b', w3: '#10b981', w4: '#a855f7' };
        const traces = [];
        sniffer.tags.forEach(tag => {
            const tl = (sniffer.series || {})[tag] || [];
            const x = tl.map(p => new Date(p.epoch * 1000));
            const color = SRC_COLORS[tag] || '#9ca3af';
            const line = { color, width: 1.5 };
            traces.push({ x, y: tl.map(p => p.frames), name: label(tag), legendgroup: tag,
                          type: 'scatter', mode: 'lines', line, yaxis: 'y' });
            traces.push({ x, y: tl.map(p => p.rssi_avg), name: label(tag), legendgroup: tag,
                          showlegend: false, type: 'scatter', mode: 'lines', line,
                          connectgaps: false, yaxis: 'y2' });
            traces.push({ x, y: tl.map(p => p.frames ? +(100 * p.retry / p.frames).toFixed(1) : null),
                          name: label(tag), legendgroup: tag, showlegend: false,
                          type: 'scatter', mode: 'lines', line, connectgaps: false, yaxis: 'y3' });
        });
        Plotly.newPlot('sniffer-compare-chart', traces, {
            ...DARK,
            margin: { t: 10, r: 10, b: 30, l: 50 },
            showlegend: true,
            legend: { orientation: 'h', y: 1.08 },
            xaxis: { anchor: 'y3', gridcolor: '#374151' },
            yaxis: { domain: [0.72, 1.0], title: { text: 'Frames/s', font: { size: 10 } }, gridcolor: '#374151', rangemode: 'tozero' },
            yaxis2: { domain: [0.38, 0.66], title: { text: '평균 RSSI (dBm)', font: { size: 10 } }, gridcolor: '#374151' },
            yaxis3: { domain: [0.0, 0.3], title: { text: 'Retry %', font: { size: 10 } }, gridcolor: '#374151', rangemode: 'tozero' },
        }, { responsive: true, displayModeBar: false });
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

    /* ── 채널/밴드 테이블 ── 구버전 JSON엔 overview.channels가 없어 카드 숨김 유지 */
    const channelCard = document.getElementById('channel-card');
    const channels = ov.channels || {};
    const byChannel = channels.by_channel || [];
    if (channelCard && byChannel.length > 0) {
        channelCard.style.display = '';
        const chTable = document.querySelector('#channel-table tbody');
        if (chTable) {
            chTable.innerHTML = byChannel.map(c =>
                `<tr class="border-b border-gray-700/50">
                    <td class="py-2 font-mono">CH ${c.channel != null ? c.channel : '?'}</td>
                    <td class="py-2">${c.band || '-'}</td>
                    <td class="py-2 text-gray-400">${c.freq} MHz</td>
                    <td class="py-2 text-right">${(c.frames || 0).toLocaleString()}</td>
                </tr>`
            ).join('');
        }
        const apLine = document.getElementById('channel-ap-line');
        const apChannels = channels.ap_channels || {};
        const apStrs = Object.values(apChannels).map(a =>
            `${a.name}: CH ${a.channel != null ? a.channel : '?'} (${a.band || '-'})`);
        if (apLine && apStrs.length > 0) apLine.textContent = 'AP 채널 (beacon 기준) — ' + apStrs.join(' · ');
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
        const staSlowPolicy = roaming.slow_policy === 'sta_log_total_preferred_v1';
        const slowThresholds = roaming.slow_thresholds_ms || {};
        const pcapSlowMs = typeof slowThresholds.pcap_total === 'number'
            ? slowThresholds.pcap_total : 100;
        const staSlowMs = typeof slowThresholds.sta_log_total === 'number'
            ? slowThresholds.sta_log_total : 150;
        // AP 라벨: 로밍 전 AP(prev_ap_name) → 로밍 후 AP(ap_name). 직전 AP가 없으면
        // (최초 연결 또는 재분석 전 데이터) 후 AP만 표시.
        const roamAp = s => (s.prev_ap_name ? `${s.prev_ap_name} → ${s.ap_name}` : s.ap_name);
        /* gap_ms는 null(측정 불가)일 수 있다 — 그 로밍의 Auth 프레임이 캡처에
           없어 시작 시각을 모르는 경우다. 0으로 찍으면 "지연 없음"으로 오독되므로
           막대를 그리지 않고(null) hover에 사유를 노출한다. */
        const gapMeasured = s => typeof s.gap_ms === 'number';
        const missingText = s => {
            const labels = s.missing_labels || [];
            return labels.length ? labels.join(', ') + ' 미포착' : 'Auth 프레임 미포착';
        };
        /* 로밍을 **구간별 누적 막대**로 그린다. gap_ms(Auth→Reassoc)만 그리면
           로밍 비용이 실제의 1/5로 보인다 — 실측 중앙값 기준 전체 25.1ms 중
           gap은 5.3ms이고 나머지 대부분이 4-way다.
           중간 구간(Reassoc 요청 → 4-way 시작)은 total에서 나머지를 빼서 얻는다.
           total이 없으면(4-way 미포착) gap만 그린다. */
        const xs = seqs.map((_, i) => i + 1);
        const label = seqs.map(s => s.sta_name + ': ' + roamAp(s));
        const segGap = seqs.map(s => gapMeasured(s) ? s.gap_ms : null);
        const segWait = seqs.map(s => {
            if (!gapMeasured(s) || typeof s.total_roam_ms !== 'number'
                || typeof s.four_way_ms !== 'number') return null;
            return Math.max(0, s.total_roam_ms - s.gap_ms - s.four_way_ms);
        });
        const segFour = seqs.map(s => typeof s.four_way_ms === 'number' ? s.four_way_ms : null);
        const slowBasisText = s => s.slow_basis === 'sta_log_total'
            ? `STA 체감 ${staSlowMs}ms 기준`
            : (s.slow_basis === 'total' || s.slow_basis === 'gap_lower_bound')
                ? `pcap 전체 ${pcapSlowMs}ms 기준` : '판정불가';
        const hoverOf = s => ((gapMeasured(s)
            ? ((s.gap_ms).toFixed(1) + 'ms' + (s.gap_basis === 'auth_response' ? ' (하한)' : '')
               + (typeof s.total_roam_ms === 'number' ? ' · 전체 ' + s.total_roam_ms.toFixed(1) + 'ms' : ''))
            : ('측정불가 — ' + missingText(s)))
            + (staSlowPolicy ? ' · ' + slowBasisText(s) : ''));
        /* STA 로그가 있으면 '체감 로밍 전체'를 **배경 영역**으로 깔고 그 안에 pcap
           구간 막대를 그린다. 누적(stack)이 아니라 **중첩**인 게 핵심 —
           pcap 전파구간은 STA 체감 로밍의 부분집합이지 옆에 붙는 별개 구간이
           아니다(실측: 전체 97ms 안에 pcap 25ms가 들어간다).
           스캔은 여기 넣지 않는다 — ROAM 명령보다 1,044ms 앞서 끝나는 별개
           이벤트라 같은 막대에 쌓으면 로밍이 그만큼 더 걸린 것처럼 보인다. */
        const staTotals = seqs.map(s => (s.sta_log && typeof s.sta_log.total_ms === 'number')
            ? s.sta_log.total_ms : null);
        const hasStaLog = staTotals.some(v => v !== null);
        const roamTraces = [];
        if (hasStaLog) {
            roamTraces.push({
                type: 'scatter', mode: 'none', name: 'STA 체감 로밍 전체',
                x: xs, y: staTotals, fill: 'tozeroy',
                fillcolor: 'rgba(148,163,184,0.22)',
                hovertemplate: 'STA 체감 %{y:.1f}ms<extra></extra>',
            });
        }
        roamTraces.push(
            {
                type: 'bar', name: 'Auth→Reassoc', x: xs, y: segGap,
                marker: { color: seqs.map(s => s.is_slow ? '#ef4444' : '#3b82f6') },
                text: label, customdata: seqs.map(hoverOf),
                hovertemplate: '%{text}<br>Auth→Reassoc %{y:.1f}ms<br>%{customdata}<extra></extra>',
            },
            {
                type: 'bar', name: 'Reassoc→4-way 시작', x: xs, y: segWait,
                marker: { color: '#8b5cf6' }, text: label,
                hovertemplate: '%{text}<br>연결 대기 %{y:.1f}ms<extra></extra>',
            },
            {
                type: 'bar', name: '4-way', x: xs, y: segFour,
                marker: { color: '#22c55e' }, text: label,
                hovertemplate: '%{text}<br>4-way %{y:.1f}ms<extra></extra>',
            },
        );
        Plotly.newPlot('chart-roaming-gap', roamTraces, {
            barmode: 'stack',
            showlegend: true,
            legend: { orientation: 'h', y: 1.12, font: { color: '#9ca3af', size: 10 } },
            ...DARK,
            dragmode: 'zoom',
            xaxis: { title: '\ub85c\ubc0d \uc2dc\ud000\uc2a4 #' },
            yaxis: { title: hasStaLog ? '\ub85c\ubc0d \uc18c\uc694 (ms) — \ud68c\uc0c9=STA \uccb4\uac10 \uc804\uccb4, \uc0c9=pcap \uad6c\uac04' : '\ub85c\ubc0d \uc18c\uc694 (ms) — \uad6c\uac04 \ub204\uc801' },
            shapes: [{
                type: 'line', x0: 0, x1: seqs.length + 1,
                y0: pcapSlowMs, y1: pcapSlowMs,
                line: { color: '#ef4444', dash: 'dash', width: 1 },
            }].concat(staSlowPolicy && hasStaLog ? [{
                type: 'line', x0: 0, x1: seqs.length + 1, y0: staSlowMs, y1: staSlowMs,
                line: { color: '#f59e0b', dash: 'dot', width: 1 },
            }] : []),
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
            // 4-way(ms): 구버전 JSON엔 four_way_ms 키가 없음 — null/undefined 모두 '-'
            // gap 셀: 측정 불가면 숫자 대신 사유를 보여준다. 여기서 s.gap_ms를
            // 그대로 toFixed하면 null에서 TypeError로 표 전체가 렌더되지 않는다.
            const gapCell = s => {
                if (gapMeasured(s)) {
                    const lower = s.gap_basis === 'auth_response'
                        ? ` <span class="text-amber-400" title="${escapeHtml(s.gap_note || '')}">(하한)</span>`
                        : '';
                    return s.gap_ms.toFixed(1) + lower;
                }
                return `<span class="text-gray-500" title="${escapeHtml(s.gap_note || '')}">측정불가</span>`
                     + `<span class="block text-[10px] text-gray-600">${escapeHtml(missingText(s))}</span>`;
            };
            rTable.innerHTML = seqs.map((s, i) =>
                `<tr class="border-b border-gray-700/50 ${s.is_slow ? 'text-red-400' : ''}">
                    <td class="py-1">${i + 1}</td>
                    <td class="py-1 font-mono text-xs">${typeof s.auth_epoch === 'number' ? fmtTime(s.auth_epoch) : (typeof s.assoc_epoch === 'number' ? fmtTime(s.assoc_epoch) : '-')}</td>
                    <td class="py-1 font-mono text-xs">${s.sta_name}</td>
                    <td class="py-1 font-mono text-xs">${roamAp(s)}</td>
                    <td class="py-1 text-right">${gapCell(s)}</td>
                    <td class="py-1 text-right">${typeof s.four_way_ms === 'number' ? s.four_way_ms.toFixed(1) : '-'}</td>
                    <td class="py-1 text-right font-semibold">${typeof s.total_roam_ms === 'number'
                        ? s.total_roam_ms.toFixed(1)
                        : `<span class="text-gray-500 font-normal" title="${escapeHtml(s.total_note || '')}">-</span>`}</td>
                    <td class="py-1 text-right">${(s.sta_log && typeof s.sta_log.total_ms === 'number')
                        ? `<span class="text-sky-300 font-semibold" title="${escapeHtml(
                              'ROAM 명령 → CONNECTED · 출처 ' + (s.sta_log.source || '') +
                              (s.sta_log.reason ? ' · 사유 ' + s.sta_log.reason : '') +
                              (typeof s.sta_log.scan_ms === 'number' ? ' · 직전 스캔 ' + s.sta_log.scan_ms + 'ms' : '') +
                              ' · 정렬 잔차 ' + s.sta_log.residual_ms + 'ms')}">${s.sta_log.total_ms.toFixed(1)}</span>`
                        : '<span class="text-gray-600">-</span>'}</td>
                    <td class="py-1">${s.assoc_type}</td>
                </tr>`
            ).join('');
        }

        /* STA 로그 상관 요약 — 어느 로그가 어느 STA에 붙었는지, 그리고 pcap이
           못 보는 비중이 얼마인지. 개별 로밍의 세부 구간(드라이버 20ms 등)은
           로그 스탬프 정밀도(±20ms대)를 넘어서므로 분포로만 낸다. */
        const stCard = document.getElementById('station-log-card');
        const stBody = document.getElementById('station-log-body');
        const stInfo = DATA.station_logs;
        if (stCard && stBody && stInfo && (stInfo.stations || []).length) {
            const rows = stInfo.stations.map(st => {
                const warn = (st.warnings || []).length
                    ? `<div class="text-yellow-400 mt-0.5">${st.warnings.map(escapeHtml).join('<br>')}</div>` : '';
                const matched = st.sta_name
                    ? `<span class="text-sky-300">${escapeHtml(st.sta_name)}</span>
                       <span class="text-gray-500">(${escapeHtml(st.match_method === 'ip' ? 'IP 매칭' : '시각 상관')})</span>`
                    : '<span class="text-yellow-400">매칭 실패</span>';
                return `<tr class="border-b border-gray-700/40">
                    <td class="py-1 pr-3">${escapeHtml(st.name)}</td>
                    <td class="py-1 pr-3 font-mono">${escapeHtml(st.sta_ip || '-')}</td>
                    <td class="py-1 pr-3">${matched}${warn}</td>
                    <td class="py-1 pr-3 text-right">${st.attached}/${st.roam_total}</td>
                    <td class="py-1 pr-3 text-right">${st.total_ms_p50 ?? '-'}</td>
                    <td class="py-1 pr-3 text-right">${st.scan_ms_p50 ?? '-'}</td>
                    <td class="py-1 text-right text-gray-500">${st.residual_mad_ms ?? '-'}</td>
                </tr>`;
            }).join('');
            /* pcap이 못 보는 비중 — 같은 로밍끼리 대조한 중앙값 기준.
               같은 비율을 화면과 백엔드가 따로 계산하면 중앙값 정의 차이(짝수일 때
               평균 vs 상위값)로 두 수치가 갈린다. 신규 결과는 진단 summary가 실어
               보내는 값을 그대로 쓰고, 그 키가 없는 구버전 result에서만 아래
               폴백으로 계산한다 — 리포트·AI와 같은 숫자를 말하게 하는 지점이다. */
            const covSum = (DATA.diagnosis && DATA.diagnosis.summary) || {};
            let pairedN = covSum.roaming_sta_log_matched;
            let p = covSum.roaming_pcap_total_ms_p50;
            let t = covSum.roaming_sta_total_ms_p50;
            let visiblePct = covSum.roaming_pcap_visible_pct;
            /* 표본이 적으면 비율을 단정하지 않는다. 백엔드가 같은 술어
               (structured.coverage_is_reportable)로 판단한 결과를 실어 보내므로
               화면이 따로 세지 않는다 — 화면·리포트가 `> 0`으로 각자 판단해
               진단("표본 부족, 주장 안 함")과 갈라진 것이 PR #31 Codex P2였다. */
            let reportable = covSum.roaming_coverage_reportable;
            if (typeof pairedN !== 'number') {
                const paired = seqs.filter(s => s.sta_log && typeof s.sta_log.total_ms === 'number'
                                                && typeof s.total_roam_ms === 'number');
                const med = arr => { const v = arr.slice().sort((a, b) => a - b); return v[Math.floor(v.length / 2)]; };
                pairedN = paired.length;
                p = paired.length ? med(paired.map(s => s.total_roam_ms)) : null;
                t = paired.length ? med(paired.map(s => s.sta_log.total_ms)) : null;
                visiblePct = (t > 0) ? (p / t) * 100 : null;
                /* 구버전 result엔 플래그가 없다. 백엔드 ROAM_COVERAGE_MIN_PAIRS(=3)와
                   같은 값이며, 바꿀 일이 생기면 두 곳을 함께 고쳐야 한다. */
                reportable = pairedN >= 3 && typeof visiblePct === 'number';
            }
            let note = '';
            if (reportable && typeof p === 'number' && typeof t === 'number') {
                /* 체감 로밍 중앙값이 0이면 비율이 Infinity/NaN으로 찍힌다. 로그 스탬프
                   정밀도가 ms라 극단적으로 짧은 로밍에서 0이 나올 수 있다 — 값을
                   지어내지 않고 '측정불가'로 둔다.
                   체감은 pcap 구간의 상위집합이라 정상이면 100%를 넘을 수 없다. 넘으면
                   (다른 시계로 잰 두 값이라 정렬이 틀어진 경우) 여기서 '전파 밖'이
                   음수로 찍힌다 — 캡핑해 숨기지 않고 정렬 이상으로 알린다. */
                const tail = (typeof visiblePct === 'number' && visiblePct > 100)
                    ? `계산상 <span class="text-yellow-400">${visiblePct.toFixed(1)}%</span>로 100%를 초과했다 —
                       체감이 pcap 구간을 포함하므로 정상이면 나올 수 없는 값이다.
                       위 표의 <span class="text-gray-200">정렬 MAD</span>를 먼저 확인할 것
                       (이 상태의 비율은 근거로 쓸 수 없다).`
                    : `<span class="text-gray-200">${typeof visiblePct === 'number'
                          ? (100 - visiblePct).toFixed(1) + '%' : '측정불가'}</span>가 전파에 나타나지 않는 구간
                       (스캔·로밍 판단·드라이버 처리·키 설치).`;
                note = `<p class="mt-2 text-gray-400">같은 로밍 ${pairedN.toLocaleString()}건 대조 —
                    pcap 전파구간 <span class="text-gray-200">${p.toFixed(1)}ms</span> vs
                    STA 체감 <span class="text-sky-300">${t.toFixed(1)}ms</span>.
                    ${tail}</p>
                    <p class="text-gray-500 mt-1">스캔은 ROAM 명령보다 약 1초 앞서 끝나는 별개 이벤트라 로밍 소요에 합산하지 않는다.
                    개별 로밍의 세부 구간은 로그 스탬프 정밀도(±20ms대)를 넘어서므로 분포로만 표기한다.</p>`;
            }
            stBody.innerHTML = `<table class="w-full">
                <thead class="text-gray-400"><tr>
                    <th class="text-left py-1 pr-3">로그</th>
                    <th class="text-left py-1 pr-3">STA IP</th>
                    <th class="text-left py-1 pr-3">매칭된 STA</th>
                    <th class="text-right py-1 pr-3">부착/로밍</th>
                    <th class="text-right py-1 pr-3">체감 p50</th>
                    <th class="text-right py-1 pr-3">스캔 p50</th>
                    <th class="text-right py-1">정렬 MAD</th>
                </tr></thead><tbody>${rows}</tbody></table>${note}`;
            stCard.classList.remove('hidden');
        }
    }

    /* ── 장치별 탭 ── */
    const deviceStats = DATA.device_stats || {};
    const allDevNames = Object.keys(deviceStats);
    const apNames = allDevNames.filter(n => deviceStats[n].role === 'AP');
    const staNames_dev = allDevNames.filter(n => deviceStats[n].role === 'STA');

    // AP별 프레임 비교 (스택 바)
    // 장치 비교(AP/STA 프레임 + retry/RSSI) — 전체 시스템 뷰에서만 렌더(renderDeviceDetail이 제어).
    function renderDeviceCompare() {
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
    }

    // 개별 장치 상세
    const deviceSelect = document.getElementById('device-select');
    if (deviceSelect) {
        // 전체 시스템(모든 송신 프레임)을 가상 장치처럼 맨 위 옵션으로. system_stats 있을 때만.
        const sysStat = DATA.system_stats;
        const sysOpt = (sysStat && sysStat.total_frames)
            ? `<option value="__system__">🌐 전체 시스템 - ${sysStat.total_frames.toLocaleString()} frames, Retry ${sysStat.retry_pct}%</option>`
            : '';
        deviceSelect.innerHTML = sysOpt + allDevNames.map(n => {
            const s = deviceStats[n];
            return `<option value="${n}">${n} (${s.role}) - ${s.total_frames.toLocaleString()} frames, Retry ${s.retry_pct}%</option>`;
        }).join('');
        deviceSelect.addEventListener('change', renderDeviceDetail);
        if (allDevNames.length > 0 || (sysStat && sysStat.total_frames)) renderDeviceDetail();
    }

    function renderDeviceDetail() {
        const name = deviceSelect.value;
        const s = (name === '__system__') ? (DATA.system_stats || {}) : deviceStats[name];
        if (!s) return;

        // "장치 비교"는 비교할 장치(allDevNames)가 있을 때만 의미가 있다.
        // - system_stats가 있는(신규) 결과: 전체 시스템 뷰에서만 표시(개별 장치 선택 시 숨김).
        // - system_stats가 없는(구버전 직렬화) 결과: __system__ 옵션이 없으므로 과거처럼 항상 표시.
        const cmpSection = document.getElementById('device-compare-section');
        if (cmpSection) {
            const hasSystem = !!(DATA.system_stats && DATA.system_stats.total_frames);
            const showCompare = allDevNames.length > 0 &&
                (hasSystem ? name === '__system__' : true);
            if (showCompare) {
                cmpSection.style.display = '';
                if (name === '__system__') cmpSection.open = true;
                renderDeviceCompare();
            } else {
                cmpSection.style.display = 'none';
            }
        }

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
        // 802.11 세대순: Legacy(b/g/a) → HT(11n) → VHT(11ac) → HE(11ax) → EHT(11be).
        // 데이터 없는 PHY는 아래 루프에서 자동 생략된다.
        const PHY_ORDER = ['Legacy', 'HT', 'VHT', 'HE', 'EHT'];
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
        // MCS별 retry% overlay (보조축 y2) — 각 PHY+MCS의 retry_pct를 마커+선으로.
        // 빈도(막대)와 retry%(점)를 함께 봐 "많이 쓴 MCS인데 retry도 높은가"를 판단.
        // 표본이 적은 MCS(total<MIN_SAMPLE)는 retry%가 통계적으로 불안정하므로(예: 6개
        // 중 5개=83%는 노이즈) 마커를 작고 흐리게 처리하고 hover에 표본 부족을 표기한다.
        const MIN_SAMPLE = 30;
        const byPhyRetry = s.mcs_retry_by_phy || {};
        const retryX = [], retryY = [], retryText = [], retryColor = [], retrySize = [];
        for (const phy of PHY_ORDER) {
            const dist = byPhy[phy];
            if (!dist || Object.keys(dist).length === 0) continue;
            const rmap = byPhyRetry[phy] || {};
            Object.keys(dist).sort((a, b) => parseFloat(a) - parseFloat(b)).forEach(k => {
                const r = rmap[k] || { total: dist[k], retry: 0, retry_pct: 0 };
                const weak = r.total < MIN_SAMPLE;
                retryX.push(phy === 'Legacy' ? `Legacy ${k}Mbps` : `${phy} MCS${k}`);
                retryY.push(r.retry_pct);
                retryText.push(`retry ${r.retry_pct}% (${r.retry.toLocaleString()}/${r.total.toLocaleString()})${weak ? ' ⚠ 표본 부족' : ''}`);
                retryColor.push(weak ? 'rgba(239,68,68,0.25)' : '#ef4444');
                retrySize.push(weak ? 4 : 8);
            });
        }
        if (retryX.length) {
            phyTraces.push({
                type: 'scatter', mode: 'markers+lines', name: `Retry% (표본<${MIN_SAMPLE}은 흐림)`,
                x: retryX, y: retryY, yaxis: 'y2',
                marker: { color: retryColor, size: retrySize, symbol: 'diamond' },
                line: { color: 'rgba(239,68,68,0.2)', width: 1 },
                text: retryText,
                hovertemplate: '%{x}<br>%{text}<extra></extra>',
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
                yaxis2: {
                    title: 'Retry %', overlaying: 'y', side: 'right',
                    range: [0, Math.max(10, (retryY.length ? Math.max(...retryY) : 0) * 1.15)],
                    color: '#ef4444', showgrid: false,
                },
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
    /* 전수 목록·관찰 프레임 표의 페이지 크기(공용).
       2시간 캡처는 전수 목록 41,667행 + 관찰 7,503행이라 한 번에 그리면 DOM이
       60만 노드를 넘는다(실측) — 두 표 모두 이 크기로 나눠 그린다.
       **선언 위치 주의**: 관찰 프레임 블록이 전수 목록 블록보다 앞에서
       실행되므로 상수는 반드시 그보다 앞에 있어야 한다(const TDZ). */
    const PING_PAGE_SIZE = 500;
    const ping = DATA.ping || {};
    const fullList = ping.full_list || [];
    // pairs/losses는 full_list와 같은 entry를 담은 부분수열이라 결과 JSON에서
    // 제거됐다(2시간 캡처에서 ping 32.8MB의 절반이 이 중복이었다 —
    // analyzer/web/structured.py `_structured_ping`). 여기서 full_list를 status로
    // 걸러 파생한다. 구버전 result에는 두 키가 남아 있으므로 있으면 그대로 쓴다.
    const isLossStatus = s => s === 'loss' || s === 'loss_gap';
    const pairs = ping.pairs || fullList.filter(p => p.status === 'matched' || p.status === 'late');
    const latePairs = pairs.filter(p => p.status === 'late');
    const losses = ping.losses || fullList.filter(p => isLossStatus(p.status));
    const pingStatsData = ping.stats || {};

    // RTT 손실 X 클릭 시 전체 목록 행으로 점프하기 위한 인덱스 병행 보존.
    // losses와 fullList는 analyzer/core/ping_matching.py에서 같은 loss entry를
    // 동시에 append한 뒤 각각 독립적으로 epoch 기준 안정 정렬되므로, fullList를
    // status로 필터링한 순서가 losses 배열의 순서와 정확히 일치한다. 길이가
    // 어긋나면(구버전 result 등) 매핑을 신뢰할 수 없으므로 customdata를 비워
    // 클릭 무동작으로 안전하게 폴백한다.
    const lossFlIdx = fullList
        .map((p, fi) => ({ p, fi }))
        .filter(x => x.p.status === 'loss' || x.p.status === 'loss_gap')
        .map(x => x.fi);
    // 순서 이중 확인: losses ↔ full_list loss 부분수열의 lockstep 불변식
    // (ping_matching.py — 동일 객체 원자적 append + 독립 안정 정렬, 회귀 테스트
    // tests/test_ping_matching.py::TestLossesFullListLockstep로 고정)을 길이 +
    // 양끝 필드 대조로 재확인한다. JSON 직렬화 후에는 두 배열 항목이 별개
    // 객체라 참조 비교(===)는 항상 false — 반드시 필드로 비교해야 한다
    // (PR #26 리뷰 3R 제안 코드의 정정). 불일치 시 클릭 내비만 조용히 비활성.
    const lossOrderOk = lossFlIdx.length === losses.length && (losses.length === 0 || (
        fullList[lossFlIdx[0]].epoch === losses[0].epoch
        && String(fullList[lossFlIdx[0]].seq) === String(losses[0].seq)
        && fullList[lossFlIdx[lossFlIdx.length - 1]].epoch === losses[losses.length - 1].epoch
    ));
    const lossCustomdata = lossOrderOk ? lossFlIdx : undefined;

    /* 유선 ground truth 카드 — ping.ground_truth 있을 때만 (스펙 §4) */
    const gt = ping.ground_truth || null;
    const gtDiv = document.getElementById('ping-ground-truth');
    if (gt && gtDiv && typeof gt.ng === 'number' && typeof gt.total === 'number'
        && typeof gt.loss_pct === 'number') {
        // GT는 gt.sender 1개 호스트의 ping만 집계한다(pick_sender). 카드의
        // "무선 관측 손실"에 pingStatsData(전체 ICMP 흐름 집계)를 그대로 쓰면
        // 배경 호스트의 ping까지 섞여 서로 다른 모집단을 비교하게 된다 — GT와
        // 같은 송신원(src===gt.sender)의 request만 걸러 동일 모집단으로 맞춘다.
        const compareTimeout = gt.reply_timeout_sec != null;
        let wirelessLoss = '—';
        let wirelessLossLabel = compareTimeout ? '무선 관측 Timeout(전체)' : '무선 관측 손실(전체)';
        if (gt.sender) {
            wirelessLossLabel = compareTimeout ? '무선 관측 Timeout(동일 송신원)' : '무선 관측 손실(동일 송신원)';
            const senderItems = fullList.filter(p => p.src === gt.sender &&
                (p.status === 'matched' || p.status === 'late' || p.status === 'loss' || p.status === 'loss_gap'))
                .filter(p => {
                    // 유선 GT의 time_end 경계 배제(13라운드: 응답 창이 time_end를
                    // 넘어갈 여지가 있고 실제 응답도 경계 밖인 요청 제외)를 무선
                    // 비교에도 미러링한다 — 그러지 않으면 그 요청이 무선
                    // full_list에는 loss로 남아 GT 분모(제외됨)와 다른 모집단을
                    // 비교해 인위적 초과 무선 손실이 생긴다(PR #22 14라운드 —
                    // Finding B, 유선 술어의 정확한 미러). matched는 그대로
                    // 유지한다 — 무선이 matched라는 건 응답이 실제로 관측됐다는
                    // 뜻이라, 유선의 "응답이 구간 안이면 유지" 판정과 대응한다.
                    // strict `<`(14라운드 마무리): 유선 near_boundary가
                    // `x.time >= threshold`(제외 쪽)라 그 정확한 보수(complement,
                    // 유지 쪽)는 `p.epoch < cutoff`다 — `<=`였다면 knife-edge
                    // (p.epoch === cutoff)에서 유선은 배제하는데 무선은 유지해
                    // 다시 어긋난다. loss_gap의 epoch는 실손실 프레임이 없어
                    // 근접 anchor 프레임(ping_matching._record_phantom_loss)의
                    // 시각을 빌린 근사값이다 — reply-only 흐름(gap_direction ===
                    // 'reply')에서는 그 anchor가 request가 아니라 reply 프레임일
                    // 수 있어, 유선 Exchange.time(항상 요청 시각)과 정확히
                    // 같은 기준이 아닐 수 있다(근사 비교로 감수).
                    if (typeof gt.boundary_cutoff_epoch !== 'number') return true;
                    if (p.status === 'matched' || p.status === 'late') return true;
                    return p.epoch < gt.boundary_cutoff_epoch;
                });
            // sender가 걸린 짝 없는 관측이 **방향과 무관하게** 하나라도 있으면
            // 모집단이 어긋난다 — 그 흐름의 정상 관측이 분모에서 통째로 빠져
            // 손실률이 과대 표시된다. observations(ping_matching의
            // _observation_entry)는 애초에 "관측됐지만 RTT 측정 불가"만 담으므로
            // 존재 자체가 모집단 불완전의 증거다. 방향을 가리지 않는 이유:
            //   - 요청-only: sender가 보낸 request가 관측(src === sender)
            //   - 응답-only: 모니터가 sender로 오는 reply만 관측(dst === sender)
            //   - 혼합: 한 target은 양방향이라 matched가 존재 → "matched 0건"
            //     같은 단방향 조건이나 요청 방향만 보는 조건으로는 못 걸러진다.
            const unpairedSenderObs = (ping.observations || []).some(o =>
                o.src === gt.sender || o.dst === gt.sender);
            if (unpairedSenderObs) {
                wirelessLoss = '— (단방향/혼합 캡처 — 비교 불가)';
            } else if (senderItems.length) {
                const lossN = senderItems.filter(p => p.status === 'loss' || p.status === 'loss_gap'
                    || (compareTimeout && p.status === 'late')).length;
                const pct = (lossN * 100 / senderItems.length).toFixed(2);
                wirelessLoss = `${lossN.toLocaleString()}건 (${pct}%)`;
            }
        } else {
            const s = pingStatsData;
            const count = compareTimeout ? s.timeout_count : s.loss_count;
            const pct = compareTimeout ? s.timeout_pct : s.loss_pct;
            wirelessLoss = (count != null && pct != null)
                ? `${count.toLocaleString()}건 (${pct}%)` : '—';
        }
        gtDiv.classList.remove('hidden');
        gtDiv.innerHTML = `
          <div class="bg-gray-800 border border-emerald-700 rounded-lg p-4">
            <div class="text-emerald-300 font-semibold mb-2">유선 Ground Truth (포트 미러 캡처)</div>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
              <div><div class="text-gray-400">${compareTimeout ? 'Timeout/NG' : '확정 손실'}</div>
                <div class="${gt.ng > 0 ? 'text-red-400' : 'text-green-400'}">${gt.ng.toLocaleString()}건 (${gt.loss_pct}%)</div></div>
              <div><div class="text-gray-400">전체 요청</div><div>${gt.total.toLocaleString()}건</div></div>
              <div><div class="text-gray-400">${wirelessLossLabel}</div><div>${wirelessLoss}</div></div>
              <div><div class="text-gray-400">${compareTimeout ? '연속 Timeout/NG 구간' : '연속 손실 구간'}</div><div>${(gt.streaks || []).length}곳</div></div>
            </div>
            <p class="text-gray-500 text-xs mt-2">
              ${compareTimeout
                ? '무선 관측 Timeout이 유선 Timeout/NG보다 크면 모니터 캡처 누락이 무응답으로 과대 계상됐을 수 있습니다'
                : '무선 관측 손실이 유선 확정 손실보다 크면 모니터 캡처 누락이 손실로 과대 계상된 것입니다'}
              (docs/EXPING.md 실측: 0.16% 대 15.65%).</p>
          </div>`;
    }

    // Ping KPI
    const pingKpi = document.getElementById('ping-kpi');
    function renderPingKpiWireless() {
        if (pingKpi && pingStatsData.count !== undefined) {
            const s = pingStatsData;
            const late = s.late_count ?? 0;
            const onTime = s.on_time_count ?? (s.count - late);
            const timeoutLabel = s.reply_timeout_sec != null ? `정상 응답 (≤${s.reply_timeout_sec}초)` : 'Ping 응답';
            const cards = s.reply_timeout_sec != null ? [
                { label: timeoutLabel, value: onTime + '건', color: '' },
                { label: '지연 응답', value: late + '건', color: late > 0 ? 'text-orange-400' : '' },
                { label: '무응답 (Loss)', value: s.loss_count + '건 (' + s.loss_pct + '%)',
                  color: s.loss_count > 0 ? 'text-red-400' : '' },
                { label: '평균 관측 RTT', value: s.avg != null ? s.avg + 'ms' : '—', color: s.avg == null ? 'text-gray-500' : '' },
                { label: 'P95 관측 RTT', value: s.p95 != null ? s.p95 + 'ms' : '—', color: s.p95 == null ? 'text-gray-500' : (s.p95 > 10 ? 'text-yellow-400' : '') },
            ] : [
                { label: 'Ping 응답', value: s.count + '건', color: '' },
                { label: 'Ping Loss', value: s.loss_count + '건 (' + s.loss_pct + '%)', color: s.loss_count > 0 ? 'text-red-400' : '' },
                { label: '평균 RTT', value: s.avg != null ? s.avg + 'ms' : '—', color: s.avg == null ? 'text-gray-500' : '' },
                { label: 'P95 RTT', value: s.p95 != null ? s.p95 + 'ms' : '—', color: s.p95 == null ? 'text-gray-500' : (s.p95 > 10 ? 'text-yellow-400' : '') },
            ];
            pingKpi.innerHTML = cards.map(k =>
                `<div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                    <p class="text-xs text-gray-500">${k.label}</p>
                    <p class="text-xl font-bold ${k.color}">${k.value}</p>
                </div>`
            ).join('');
        }
    }

    // Ping RTT 시계열 (큰 차트) — pairs가 없어도 losses만 있으면 마커로 표시
    function renderPingRttWireless() {
        const pingRttEl = document.getElementById('chart-ping-rtt');
        if (pingRttEl && pairs.length === 0 && losses.length === 0) {
            // 이전 소스의 Plotly 인스턴스·expando(.on 등) 명시 해제 — 토글 왕복 리소스/stale 가드 정리 (백로그 ①)
            Plotly.purge('chart-ping-rtt');
            pingRttEl.style.height = 'auto';
            pingRttEl.innerHTML = '<div class="text-center text-gray-500 text-sm py-12">매칭된 RTT 페어가 없습니다.<br><span class="text-xs text-gray-600">단방향 캡처(STA 다운링크만 보임)이거나 ICMP 트래픽이 없는 캡처</span></div>';
        } else if (pingRttEl && pairs.length === 0 && losses.length > 0) {
            // 단방향 캡처에서 seq gap loss만 있는 경우 — 마커만 표시
            // 이전 소스의 Plotly 인스턴스·expando(.on 등) 명시 해제 — 토글 왕복 리소스/stale 가드 정리 (백로그 ①)
            Plotly.purge('chart-ping-rtt');
            pingRttEl.style.height = '400px';
            Plotly.newPlot('chart-ping-rtt', [{
                x: losses.map(p => new Date(p.epoch * 1000)),
                y: losses.map(() => 1),
                type: 'scatter', mode: 'markers',
                name: 'LOSS (seq gap)',
                marker: { color: '#ef4444', size: 12, symbol: 'x', line: { width: 2 } },
                text: losses.map(p => 'Seq ' + p.seq + ' LOSS  ' + p.src + '→' + p.dst),
                customdata: lossCustomdata,
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
            const normalPairs = pairs.filter(p => p.status !== 'late' && !p.has_retry);
            const retryPairs = pairs.filter(p => p.status !== 'late' && p.has_retry);
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
            if (latePairs.length > 0) {
                traces_ping.push({
                    x: latePairs.map(p => new Date(p.epoch * 1000)),
                    y: latePairs.map(p => p.rtt_ms),
                    type: 'scattergl', mode: 'markers',
                    name: `지연 응답 (>${pingStatsData.reply_timeout_sec ?? 1}초)`,
                    marker: { color: '#f97316', size: 8, symbol: 'triangle-up' },
                    text: latePairs.map(p => 'Seq ' + p.seq + ' LATE  #' + p.req_num + '\u2192#' + p.reply_num),
                    hovertemplate: '%{text}<br>RTT: %{y:.2f}ms<extra></extra>',
                });
            }
            if (losses.length > 0) {
                // reduce 사용: 스프레드(Math.max(...arr))는 배열 전체가 인수 스택에
                // 올라가 장시간 캡처(수만 페어)에서 RangeError 가능 (PR #25 리뷰).
                const maxRtt = pairs.length > 0 ? pairs.reduce((m, p) => Math.max(m, p.rtt_ms), 0) : 10;
                traces_ping.push({
                    x: losses.map(p => new Date(p.epoch * 1000)),
                    y: losses.map(() => maxRtt * 1.1),
                    type: 'scattergl', mode: 'markers',
                    name: 'LOSS (미응답)',
                    marker: { color: '#ef4444', size: 10, symbol: 'x', line: { width: 2 } },
                    text: losses.map(p => 'Seq ' + p.seq + (p.status === 'loss_gap' ? ' LOSS (seq gap)  ' : ' LOSS  ' + (p.req_num != null ? '#' + p.req_num + '  ' : '')) + p.src + '\u2192' + p.dst),
                    customdata: lossCustomdata,
                    hovertemplate: '%{text}<extra></extra>',
                });
            }
            // 빈 상태에서 복귀 시 높이 복원 (백로그 ①)
            if (pingRttEl) pingRttEl.style.height = '400px';
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
    }

    // RTT 히스토그램
    function renderPingHistWireless() {
        const pingHistEl = document.getElementById('chart-ping-hist');
        if (pingHistEl && pairs.length === 0) {
            // 이전 소스의 Plotly 인스턴스·expando(.on 등) 명시 해제 — 토글 왕복 리소스/stale 가드 정리 (백로그 ①)
            Plotly.purge('chart-ping-hist');
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
            // 빈 상태에서 복귀 시 높이 복원 (백로그 ①)
            if (pingHistEl) pingHistEl.style.height = '300px';
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

    function renderPingStatsWireless() {
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
                    ${s.reply_timeout_sec != null ? `<tr><td class="text-gray-400 py-1">Timeout 기준</td><td class="text-right text-white">${s.reply_timeout_sec}초</td></tr>
                    <tr><td class="text-gray-400 py-1">정상 응답</td><td class="text-right text-green-400">${(s.on_time_count ?? 0).toLocaleString()}건</td></tr>
                    <tr><td class="text-gray-400 py-1">지연 응답</td><td class="text-right text-orange-400">${(s.late_count ?? 0).toLocaleString()}건</td></tr>
                    <tr><td class="text-gray-400 py-1">Timeout 합계</td><td class="text-right text-orange-300">${(s.timeout_count ?? 0).toLocaleString()}건 (${s.timeout_pct ?? 0}%)</td></tr>` : ''}
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
    }

    /* ── ping 소스 토글 (스펙 2026-08-05-wired-rtt-primary §3) ──
       유선 GT exchanges 있을 때만 표시. 판정(손실·RTT)은 유선이 1차,
       Retry·frame_refs 해석은 무선 뷰 전용. */
    const gtExchanges = (gt && Array.isArray(gt.exchanges) && gt.exchanges.length > 0)
        ? gt.exchanges : null;

    function renderPingKpiWired() {
        if (!pingKpi) return;
        const rs = gt.observed_rtt_stats || gt.rtt_stats || null;
        const observedLabel = gt.observed_rtt_stats ? '관측 ' : '';
        const late = gt.late_count ?? 0;
        const unanswered = gt.unanswered_count ?? (gt.ng ?? 0);
        const cards = gt.reply_timeout_sec != null ? [
            { label: `정상 응답 (≤${gt.reply_timeout_sec ?? 1}초)`, value: (gt.ok ?? 0).toLocaleString() + '건', color: '' },
            { label: '지연 응답', value: late.toLocaleString() + '건', color: late > 0 ? 'text-orange-400' : '' },
            { label: '무응답', value: unanswered.toLocaleString() + '건', color: unanswered > 0 ? 'text-red-400' : '' },
            { label: `평균 ${observedLabel}RTT (유선)`, value: rs ? rs.avg_ms + 'ms' : '—', color: rs ? '' : 'text-gray-500' },
            { label: `P95 ${observedLabel}RTT (유선)`, value: rs ? rs.p95_ms + 'ms' : '—',
              color: rs ? (rs.p95_ms > 10 ? 'text-yellow-400' : '') : 'text-gray-500' },
        ] : [
            { label: '총 요청 (유선 확정)', value: (gt.total ?? 0).toLocaleString() + '건', color: '' },
            { label: '손실 (유선 확정)', value: (gt.ng ?? 0).toLocaleString() + '건 (' + (gt.loss_pct ?? 0) + '%)', color: (gt.ng ?? 0) > 0 ? 'text-red-400' : '' },
            { label: '평균 RTT (유선)', value: rs ? rs.avg_ms + 'ms' : '—', color: rs ? '' : 'text-gray-500' },
            { label: 'P95 RTT (유선)', value: rs ? rs.p95_ms + 'ms' : '—', color: rs ? (rs.p95_ms > 10 ? 'text-yellow-400' : '') : 'text-gray-500' },
        ];
        pingKpi.innerHTML = cards.map(k =>
            `<div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <p class="text-xs text-gray-500">${k.label}</p>
                <p class="text-xl font-bold ${k.color}">${k.value}</p>
            </div>`
        ).join('');
    }

    function renderPingRttWired() {
        const ok = gtExchanges.filter(e => e.rtt_ms != null);
        const late = gtExchanges.filter(e => e.late_rtt_ms != null);
        // 클릭 시 전체 목록 행(data-ex-idx) 점프를 위해 gtExchanges 인덱스를
        // 병행 보존 — indexOf 재탐색(O(n²))을 피한다.
        const loss = gtExchanges.map((e, i) => ({ e, i }))
            .filter(x => x.e.rtt_ms == null && x.e.late_rtt_ms == null);
        // 유선 exchanges는 1만+ 건이 일상 규모 — 스프레드 대신 reduce (PR #25 리뷰).
        const maxRtt = Math.max(1, gtExchanges.reduce(
            (m, e) => Math.max(m, e.rtt_ms ?? e.late_rtt_ms ?? 0), 0));
        const traces = [];
        if (ok.length) traces.push({
            x: ok.map(e => new Date(e.epoch * 1000)), y: ok.map(e => e.rtt_ms),
            type: 'scattergl', mode: 'markers', name: '응답 (유선)',
            marker: { color: '#10b981', size: 4 },
            text: ok.map(e => escapeHtml(e.target)),
            hovertemplate: '%{text}<br>RTT: %{y:.2f}ms<br>%{x}<extra></extra>',
        });
        if (late.length) traces.push({
            x: late.map(e => new Date(e.epoch * 1000)), y: late.map(e => e.late_rtt_ms),
            type: 'scattergl', mode: 'markers', name: '지연 응답 (유선)',
            marker: { color: '#f97316', size: 8, symbol: 'triangle-up' },
            text: late.map(e => escapeHtml(e.target)),
            hovertemplate: '%{text}<br>RTT: %{y:.2f}ms<br>%{x}<extra></extra>',
        });
        if (loss.length) traces.push({
            x: loss.map(x => new Date(x.e.epoch * 1000)), y: loss.map(() => maxRtt * 1.1),
            type: 'scattergl', mode: 'markers', name: 'Loss (유선 확정)',
            marker: { color: '#ef4444', size: 10, symbol: 'x', line: { width: 2 } },
            text: loss.map(x => escapeHtml(x.e.target) + ' LOSS'),
            customdata: loss.map(x => x.i),
            hovertemplate: '%{text}<br>%{x}<extra></extra>',
        });
        // 옵션은 무선 RTT 시계열과 미러링 — 유선이 기본 뷰이고 1만+ 포인트로
        // 밀집하므로 zoom/pan이 오히려 더 필요하다 (PR #25 리뷰 2라운드).
        // 빈 상태에서 복귀 시 높이 복원 (백로그 ①)
        const el = document.getElementById('chart-ping-rtt');
        if (el) el.style.height = '400px';
        Plotly.newPlot('chart-ping-rtt', traces, {
            ...DARK,
            xaxis: { title: { text: '시간', font: { size: 12 } }, gridcolor: '#374151' },
            yaxis: { title: { text: 'RTT (ms)', font: { size: 12 } }, gridcolor: '#374151', rangemode: 'tozero' },
            legend: { orientation: 'h', x: 0, y: 1.12, font: { size: 12 } },
            margin: { t: 60, r: 20, b: 50, l: 60 },
        }, {
            responsive: true,
            displayModeBar: true,
            displaylogo: false,
            modeBarButtonsToRemove: ['lasso2d', 'select2d'],
        });
    }

    function renderPingHistWired() {
        const histEl = document.getElementById('chart-ping-hist');
        if (!histEl) return;
        const rtts = gtExchanges
            .map(e => e.rtt_ms ?? e.late_rtt_ms)
            .filter(v => v != null);
        if (!rtts.length) { Plotly.purge('chart-ping-hist'); histEl.innerHTML = '<p class="text-sm text-gray-500 py-8 text-center">응답이 없어 분포를 계산할 수 없습니다.</p>'; return; }
        histEl.innerHTML = '';
        // 무선 히스토그램(renderPingHistWireless)과 동일한 롱테일 대응 — 이상치 1건만
        // 있어도 0~max 균등 bin에서는 본체 분포가 첫 막대로 붕괴한다. 표시 범위를
        // p99로 클립하고 bin을 세밀화해 본체를 펼치고, 잘린 이상치는 카운트로 안내한다.
        const sorted = [...rtts].sort((a, b) => a - b);
        const p99 = sorted.length ? sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.99))] : 1;
        const hi = Math.max(p99, 1);                 // 표시 상한 (최소 1ms)
        const outliers = rtts.filter(v => v > hi).length;
        const maxRtt = sorted[sorted.length - 1];
        const annotations = outliers > 0 ? [{
            xref: 'paper', yref: 'paper', x: 1, y: 1, xanchor: 'right', yanchor: 'top',
            text: `+${outliers.toLocaleString()}건 > ${hi.toFixed(1)}ms (최대 ${maxRtt.toFixed(1)}ms)`,
            showarrow: false, font: { size: 10, color: '#9ca3af' },
        }] : [];
        // 빈 상태에서 복귀 시 높이 복원 (백로그 ①)
        histEl.style.height = '300px';
        Plotly.newPlot('chart-ping-hist', [{
            x: rtts, type: 'histogram',
            xbins: { start: 0, end: hi, size: (hi / 40) || 0.1 },
            marker: { color: '#10b981' },
        }], {
            ...DARK,
            xaxis: { title: { text: 'RTT (ms)', font: { size: 12 } }, gridcolor: '#374151', range: [0, hi] },
            yaxis: { title: { text: '건수', font: { size: 12 } }, gridcolor: '#374151' },
            margin: { t: 10, r: 10, b: 50, l: 50 },
            annotations,
        }, { responsive: true, displayModeBar: false });
    }

    function renderPingStatsWired() {
        if (!pingStats) return;
        const rs = gt.observed_rtt_stats || gt.rtt_stats || null;
        const observedLabel = gt.observed_rtt_stats ? '관측 ' : '';
        const rows = gt.reply_timeout_sec != null ? [
            ['총 요청', (gt.total ?? 0).toLocaleString() + '건'],
            ['Timeout 기준', (gt.reply_timeout_sec ?? 1) + '초'],
            ['정상 응답', (gt.ok ?? 0).toLocaleString() + '건'],
            ['지연 응답', (gt.late_count ?? 0).toLocaleString() + '건'],
            ['무응답', (gt.unanswered_count ?? gt.ng ?? 0).toLocaleString() + '건'],
            ['Timeout/NG', (gt.ng ?? 0).toLocaleString() + '건 (' + (gt.loss_pct ?? 0) + '%)'],
        ] : [
            ['총 요청', (gt.total ?? 0).toLocaleString() + '건'],
            ['손실 (확정)', (gt.ng ?? 0).toLocaleString() + '건 (' + (gt.loss_pct ?? 0) + '%)'],
        ];
        if (rs) rows.push(
            [`최소 ${observedLabel}RTT`, rs.min_ms + 'ms'],
            [`평균 ${observedLabel}RTT`, rs.avg_ms + 'ms'],
            [`P95 ${observedLabel}RTT`, rs.p95_ms + 'ms'],
            [`최대 ${observedLabel}RTT`, rs.max_ms + 'ms']);
        pingStats.innerHTML = `<table class="w-full text-sm">` + rows.map(r =>
            `<tr><td class="text-gray-400 py-1">${r[0]}</td><td class="text-right text-white font-mono">${r[1]}</td></tr>`
        ).join('') + `</table>
        <p class="text-xs text-gray-500 mt-2">판정은 유선 확정 기준. Retry·프레임 근거 해석은 무선 (관측) 뷰에서.</p>`;
    }

    let currentPingSource = null;

    // RTT 손실 X 마커 클릭 → 전체 목록의 해당 행으로 점프 (스펙 §2).
    let pingHighlightRow = null;   // 직전 하이라이트 행/타이머 — 연속 클릭 정리용
    let pingHighlightTimer = null;

    function jumpToPingRow(attrName, idx) {
        const sel = document.getElementById('ping-filter-status');
        let needRender = false;
        if (sel && sel.value !== 'loss') { sel.value = 'loss'; needRender = true; }
        // 무선 뷰의 flow/Retry 필터가 켜져 있으면 상태만 'loss'로 바꿔도 클릭한
        // 손실 행이 계속 걸러져 점프가 조용히 무동작이 된다 — 클릭 내비는 항상
        // 행을 보여줘야 하므로 함께 초기화한다 (PR #26 Codex P2 = 최종 리뷰 Minor 1).
        if (currentPingSource !== 'wired') {
            if (pingFlowSel && pingFlowSel.value !== '') { pingFlowSel.value = ''; needRender = true; }
            if (pingRetryChk && pingRetryChk.checked) { pingRetryChk.checked = false; needRender = true; }
        }
        if (needRender) renderCurrentPingTable();   // 필터 초기화분 먼저 반영
        // 전수 목록은 페이지 단위로만 그려지므로(4만 행 DOM 방지) 대상 행이
        // 현재 페이지 밖일 수 있다 — 그 행이 있는 페이지로 먼저 이동한다.
        // pingRowsCache는 방금 렌더가 채운 "현재 필터 적용 행 목록"이고,
        // 유선/무선이 각각 idx/fi 키로 원본 인덱스를 들고 있다.
        const keyOf = currentPingSource === 'wired' ? (r => r.idx) : (r => r.fi);
        const pos = pingRowsCache.findIndex(r => keyOf(r) === idx);
        if (pos < 0) return;   // 현재 필터에서 사라진 행 — 무동작 (throw 금지)
        const targetPage = Math.floor(pos / PING_PAGE_SIZE);
        if (targetPage !== pingPage) {
            pingPage = targetPage;
            renderCurrentPingTable();
        }
        const row = document.querySelector(`#ping-full-table tbody tr[${attrName}="${idx}"]`);
        if (!row) return;   // 탐색 실패 시 무동작 (throw 금지)
        row.scrollIntoView({ block: 'center', behavior: 'smooth' });
        // 연속 클릭 시 이전 타이머가 새 하이라이트를 조기 제거하지 않도록
        // 타이머·행을 추적해 정리한다 (PR #26 리뷰 LOW).
        if (pingHighlightRow) pingHighlightRow.classList.remove('outline', 'outline-2', 'outline-yellow-400');
        if (pingHighlightTimer) clearTimeout(pingHighlightTimer);
        row.classList.add('outline', 'outline-2', 'outline-yellow-400');
        pingHighlightRow = row;
        pingHighlightTimer = setTimeout(() => {
            row.classList.remove('outline', 'outline-2', 'outline-yellow-400');
            pingHighlightRow = null; pingHighlightTimer = null;
        }, 2500);
    }

    // newPlot이 노드를 재사용하므로 뷰 전환마다 재바인딩 필요 — 중복 리스너
    // 방지를 위해 바인딩 전 기존 리스너를 제거한다.
    function bindPingRttClick() {
        const el = document.getElementById('chart-ping-rtt');
        if (!el || !el.on) return;   // Plotly 미렌더(빈 상태 innerHTML 교체) 시 무동작
        if (el.removeAllListeners) el.removeAllListeners('plotly_click');
        el.on('plotly_click', ev => {
            const pt = ev.points && ev.points[0];
            if (!pt || pt.customdata == null) return;   // 손실 trace만 customdata 보유(응답 포인트는 무동작)
            jumpToPingRow(currentPingSource === 'wired' ? 'data-ex-idx' : 'data-fl-idx', pt.customdata);
        });
    }

    function renderPingSource(src) {
        // 게이트 봉인: gtExchanges 없는 'wired' 요청은 무선으로 정규화 —
        // currentPingSource와 아래 모든 분기가 이 값 하나만 본다 (PR #26 리뷰 3R).
        const isWired = src === 'wired' && !!gtExchanges;
        currentPingSource = isWired ? 'wired' : 'wireless';
        const legend = document.getElementById('ping-rtt-legend');
        if (isWired) {
            renderPingKpiWired(); renderPingRttWired(); bindPingRttClick(); renderPingHistWired(); renderPingStatsWired();
            if (legend) legend.textContent = gt.reply_timeout_sec != null
                ? '(초록=정상 응답, 주황=지연 응답, 빨강X=무응답 — 유선 확정)'
                : '(초록=응답, 빨강X=손실 — 유선 확정)';
        } else {
            renderPingKpiWireless(); renderPingRttWireless(); bindPingRttClick(); renderPingHistWireless(); renderPingStatsWireless();
            if (legend) legend.textContent = pingStatsData.reply_timeout_sec != null
                ? '(초록=정상, 노랑=Retry, 주황=지연 응답, 빨강X=Loss)'
                : '(초록=정상, 노랑=Retry, 빨강X=Loss)';
        }
        document.querySelectorAll('#ping-source-toggle button').forEach(b => {
            const active = b.dataset.src === src;
            b.classList.toggle('bg-blue-600', active); b.classList.toggle('text-white', active);
            b.classList.toggle('bg-gray-700', !active); b.classList.toggle('text-gray-300', !active);
        });
        const flowWrap = document.getElementById('ping-filter-flow-wrap');
        const retryWrap = document.getElementById('ping-filter-retry-wrap');
        const obsDetailsEl = document.getElementById('ping-observations-details');
        const streakSrcLabel = document.getElementById('ping-streak-src-label');
        const streakDescription = document.getElementById('ping-streak-description');
        if (isWired) {
            renderPingStreaksWired();
            renderPingFullTableWired();
            if (streakSrcLabel) streakSrcLabel.textContent = ' (유선 확정)';
            if (streakDescription) streakDescription.textContent = gt.reply_timeout_sec != null
                ? '인접 Timeout/NG 간격 ≤2초로 2건 이상 이어진 구간을 대상별로 분리합니다.'
                : '인접 손실 간격 ≤2초로 2건 이상 이어진 구간을 대상별로 분리합니다.';
            if (flowWrap) flowWrap.classList.add('hidden');
            if (retryWrap) retryWrap.classList.add('hidden');
            if (obsDetailsEl) obsDetailsEl.classList.add('hidden');
        } else {
            renderPingStreaksWireless();
            renderPingFullTable();
            if (streakSrcLabel) streakSrcLabel.textContent = '';
            if (streakDescription) streakDescription.textContent =
                '인접 손실 간격 ≤2초로 2건 이상 이어진 구간을 장치(흐름)별로 분리 — 전역 타임라인과 달리 장치가 섞이지 않습니다.';
            if (flowWrap) flowWrap.classList.remove('hidden');
            if (retryWrap) retryWrap.classList.remove('hidden');
            if (obsDetailsEl) obsDetailsEl.classList.remove('hidden');
        }
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
        /* 전수 목록과 동일한 이유로 페이지 단위 렌더 — 2시간 캡처는 관찰
           프레임만 7,503건이라 한 번에 그리면 그만큼 DOM이 늘어난다. */
        const obsPager = document.getElementById('ping-obs-pager');
        const obsPagePrev = document.getElementById('ping-obs-page-prev');
        const obsPageNext = document.getElementById('ping-obs-page-next');
        const obsPageLabel = document.getElementById('ping-obs-page-label');
        const obsScroll = document.getElementById('ping-obs-scroll');
        let obsPage = 0;
        let obsRowsCache = [];

        function obsPageCount() {
            return Math.max(1, Math.ceil(obsRowsCache.length / PING_PAGE_SIZE));
        }
        function updateObsPager() {
            if (!obsPager) return;
            const total = obsRowsCache.length;
            if (total <= PING_PAGE_SIZE) { obsPager.classList.add('hidden'); return; }
            obsPager.classList.remove('hidden');
            const from = obsPage * PING_PAGE_SIZE + 1;
            const to = Math.min(total, (obsPage + 1) * PING_PAGE_SIZE);
            if (obsPageLabel) {
                obsPageLabel.textContent =
                    `${from.toLocaleString()}–${to.toLocaleString()} (${obsPage + 1}/${obsPageCount()}쪽)`;
            }
            if (obsPagePrev) obsPagePrev.disabled = obsPage <= 0;
            if (obsPageNext) obsPageNext.disabled = obsPage >= obsPageCount() - 1;
        }
        function moveObsPage(delta) {
            const next = Math.min(Math.max(0, obsPage + delta), obsPageCount() - 1);
            if (next === obsPage) return;
            obsPage = next;
            renderObsTable();
            if (obsScroll) obsScroll.scrollTop = 0;
        }
        if (obsPagePrev) obsPagePrev.addEventListener('click', () => moveObsPage(-1));
        if (obsPageNext) obsPageNext.addEventListener('click', () => moveObsPage(1));

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
            obsRowsCache = rows;
            if (obsPage > obsPageCount() - 1) obsPage = obsPageCount() - 1;
            updateObsPager();
            if (rows.length === 0) {
                obsTable.innerHTML = '<tr><td colspan="9" class="text-gray-500 text-center py-6">조건에 맞는 항목이 없습니다.</td></tr>';
                return;
            }
            const obsStart = obsPage * PING_PAGE_SIZE;
            obsTable.innerHTML = rows.slice(obsStart, obsStart + PING_PAGE_SIZE).map((o, i0) => {
                const i = obsStart + i0;   // 순번은 전체 기준 유지
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
        [obsDirSel, obsFlowSel].forEach(el => { if (el) el.addEventListener('change', () => { obsPage = 0; renderObsTable(); }); });
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
    const pingPager = document.getElementById('ping-pager');
    const pingPagePrev = document.getElementById('ping-page-prev');
    const pingPageNext = document.getElementById('ping-page-next');
    const pingPageLabel = document.getElementById('ping-page-label');
    const pingScroll = document.getElementById('ping-full-scroll');

    /* 전수 목록 페이지네이션.
       2시간 캡처는 필터 없이 41,667행이라 한 번에 그리면 DOM 노드가 60만을
       넘고(실측) 페이지 로드가 그만큼 느려진다. 화면에는 한 페이지만 그리고
       나머지는 필요할 때 그린다. 손실 마커 클릭 내비(jumpToPingRow)는 대상
       행이 속한 페이지로 먼저 이동한 뒤 스크롤한다. */
    let pingPage = 0;               // 현재 페이지(0-base)
    let pingRowsCache = [];         // 현재 필터가 적용된 행 목록(페이지 계산·점프용)

    function pingPageCount() {
        return Math.max(1, Math.ceil(pingRowsCache.length / PING_PAGE_SIZE));
    }

    function updatePingPager() {
        if (!pingPager) return;
        const total = pingRowsCache.length;
        const pages = pingPageCount();
        if (total <= PING_PAGE_SIZE) {
            pingPager.classList.add('hidden');
            return;
        }
        pingPager.classList.remove('hidden');
        const from = pingPage * PING_PAGE_SIZE + 1;
        const to = Math.min(total, (pingPage + 1) * PING_PAGE_SIZE);
        if (pingPageLabel) {
            pingPageLabel.textContent =
                `${from.toLocaleString()}–${to.toLocaleString()} (${pingPage + 1}/${pages}쪽)`;
        }
        if (pingPagePrev) pingPagePrev.disabled = pingPage <= 0;
        if (pingPageNext) pingPageNext.disabled = pingPage >= pages - 1;
    }

    function renderCurrentPingTable() {
        if (currentPingSource === 'wired') renderPingFullTableWired();
        else renderPingFullTable();
    }

    function movePingPage(delta) {
        const next = Math.min(Math.max(0, pingPage + delta), pingPageCount() - 1);
        if (next === pingPage) return;
        pingPage = next;
        renderCurrentPingTable();
        if (pingScroll) pingScroll.scrollTop = 0;
    }

    if (pingPagePrev) pingPagePrev.addEventListener('click', () => movePingPage(-1));
    if (pingPageNext) pingPageNext.addEventListener('click', () => movePingPage(1));

    const WIRED_FULL_THEAD = `<tr class="text-gray-400 border-b border-gray-700">
        <th class="text-left py-2 px-1">#</th>
        <th class="text-left py-2 px-1">시각</th>
        <th class="text-left py-2 px-1">Target</th>
        <th class="text-right py-2 px-1">RTT (ms)</th>
        <th class="text-left py-2 px-1">상태</th>
    </tr>`;
    let wirelessFullTheadHtml = null;   // 최초 유선 전환 시 원본 백업

    function renderPingFullTableWired() {
        // gtExchanges 가드: 필터 change 리스너가 currentPingSource만 보고 이
        // 함수를 부를 수 있어, 외부에서 'wired'가 잘못 활성화된 잠재 경로까지
        // 소비자 측에서 봉인한다 (PR #26 리뷰 = 최종 리뷰 Minor 수렴).
        if (!pingFullTable || !gtExchanges) return;
        const thead = document.getElementById('ping-full-thead');
        if (thead) {
            if (wirelessFullTheadHtml === null) wirelessFullTheadHtml = thead.innerHTML;
            thead.innerHTML = WIRED_FULL_THEAD;
        }
        const fStatus = pingStatusSel ? pingStatusSel.value : '';
        const rows = [];
        gtExchanges.forEach((e, idx) => {
            const isLate = e.late_rtt_ms != null;
            const isLoss = e.rtt_ms == null && !isLate;
            if (fStatus === 'loss' && !isLoss) return;
            if (fStatus === 'late' && !isLate) return;
            if (fStatus === 'matched' && (isLoss || isLate)) return;
            rows.push({ e, idx });
        });
        if (pingFullCount) pingFullCount.textContent = `${rows.length.toLocaleString()} / ${gtExchanges.length.toLocaleString()}건`;
        pingRowsCache = rows;
        if (pingPage > pingPageCount() - 1) pingPage = pingPageCount() - 1;
        updatePingPager();
        if (!rows.length) {
            pingFullTable.innerHTML = '<tr><td colspan="5" class="text-gray-500 text-center py-6">조건에 맞는 항목이 없습니다.</td></tr>';
            return;
        }
        const pageStart = pingPage * PING_PAGE_SIZE;
        pingFullTable.innerHTML = rows.slice(pageStart, pageStart + PING_PAGE_SIZE).map(({ e, idx }, i0) => {
            const i = pageStart + i0;   // 표의 순번은 전체 기준을 유지
            const isLate = e.late_rtt_ms != null;
            const isLoss = e.rtt_ms == null && !isLate;
            const badge = isLoss
                ? '<span class="bg-red-900 text-red-300 px-1.5 py-0.5 rounded text-xs font-bold">LOSS</span>'
                : (isLate
                    ? '<span class="bg-orange-900 text-orange-300 px-1.5 py-0.5 rounded text-xs font-bold">LATE</span>'
                    : '<span class="bg-green-900 text-green-300 px-1.5 py-0.5 rounded text-xs">OK</span>');
            const shownRtt = isLate ? e.late_rtt_ms : e.rtt_ms;
            return `<tr data-ex-idx="${idx}" class="border-b border-gray-700/30 ${isLoss ? 'text-red-400 bg-red-900/20' : (isLate ? 'text-orange-400 bg-orange-900/10' : '')} hover:bg-gray-700/30">
                <td class="py-1 px-1">${i + 1}</td>
                <td class="py-1 px-1">${escapeHtml(new Date(e.epoch * 1000).toLocaleTimeString('en-GB') + '.' + String(Math.floor((e.epoch % 1) * 1000)).padStart(3, '0'))}</td>
                <td class="py-1 px-1 font-mono">${escapeHtml(String(e.target ?? '?'))}</td>
                <td class="py-1 px-1 text-right font-mono">${isLoss ? '-' : shownRtt.toFixed(2)}</td>
                <td class="py-1 px-1">${badge}</td>
            </tr>`;
        }).join('');
    }

    function renderPingFullTable() {
        if (!pingFullTable) return;
        if (wirelessFullTheadHtml !== null) {
            const thead = document.getElementById('ping-full-thead');
            if (thead) thead.innerHTML = wirelessFullTheadHtml;
            wirelessFullTheadHtml = null;
        }
        const fStatus = pingStatusSel ? pingStatusSel.value : '';   // ''=전체 | matched | late | loss
        const fFlow = pingFlowSel ? pingFlowSel.value : '';         // ''=전체 | "src → dst"
        const fRetry = pingRetryChk ? pingRetryChk.checked : false;
        const rows = fullList.map((p, fi) => ({ p, fi })).filter(({ p }) => {
            // 손실은 loss + loss_gap(단방향 seq gap) 둘 다 포함.
            if (fStatus === 'loss' && !(p.status === 'loss' || p.status === 'loss_gap')) return false;
            if (fStatus === 'late' && p.status !== 'late') return false;
            if (fStatus === 'matched' && p.status !== 'matched') return false;
            if (fFlow && `${p.src} → ${p.dst}` !== fFlow) return false;
            if (fRetry && !p.has_retry) return false;
            return true;
        });
        if (pingFullCount) pingFullCount.textContent = `${rows.length.toLocaleString()} / ${fullList.length.toLocaleString()}건`;
        pingRowsCache = rows;
        if (pingPage > pingPageCount() - 1) pingPage = pingPageCount() - 1;
        updatePingPager();
        if (rows.length === 0) {
            pingFullTable.innerHTML = '<tr><td colspan="10" class="text-gray-500 text-center py-6">조건에 맞는 항목이 없습니다.</td></tr>';
            return;
        }
        const pageStart = pingPage * PING_PAGE_SIZE;
        pingFullTable.innerHTML = rows.slice(pageStart, pageStart + PING_PAGE_SIZE).map(({ p, fi }, i0) => {
            const i = pageStart + i0;   // 표의 순번은 전체 기준을 유지
            const isLoss = p.status === 'loss' || p.status === 'loss_gap';
            const isGap = p.status === 'loss_gap';
            const isLate = p.status === 'late';
            const rowClass = isLoss ? 'text-red-400 bg-red-900/20' : (isLate ? 'text-orange-400 bg-orange-900/10' : (p.has_retry ? 'text-yellow-400' : ''));
            const statusBadge = isLoss
                ? (isGap
                    ? '<span class="bg-red-900 text-red-300 px-1.5 py-0.5 rounded text-xs font-bold" title="seq \uac2d\uc73c\ub85c \uac80\ucd9c\ub41c \uc9c4\uc9dc \ubb34\uc120 \uc190\uc2e4">LOSS (seq gap)</span>'
                    : '<span class="bg-red-900 text-red-300 px-1.5 py-0.5 rounded text-xs font-bold">LOSS</span>')
                : (isLate
                    ? '<span class="bg-orange-900 text-orange-300 px-1.5 py-0.5 rounded text-xs font-bold">LATE</span>'
                    : (p.has_retry
                    ? '<span class="bg-yellow-900 text-yellow-300 px-1.5 py-0.5 rounded text-xs">RETRY</span>'
                    : '<span class="bg-green-900 text-green-300 px-1.5 py-0.5 rounded text-xs">OK</span>'));
            const rttStr = p.rtt_ms !== null ? p.rtt_ms.toFixed(2) : '-';
            const reqStr = p.req_num != null ? '#' + p.req_num : '-';
            const replyStr = p.reply_num != null ? '#' + p.reply_num : '-';
            const replyTime = p.reply_time || '-';
            return `<tr data-fl-idx="${fi}" class="border-b border-gray-700/30 ${rowClass} hover:bg-gray-700/30">
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
        if (el) el.addEventListener('change', () => {
            pingPage = 0;   // 필터가 바뀌면 행 집합이 달라진다 — 1쪽부터
            renderCurrentPingTable();
        });
    });
    // 초기 전체 목록 렌더는 아래 srcToggle 초기화의 renderPingSource(...)가
    // 소스에 맞게 1회 수행한다 — 여기서 선행 렌더하면 유선 경로에서 10k+행
    // innerHTML을 두 번 쓰는 잉여 작업이 된다 (PR #26 리뷰).

    // 장치별 연속 실패 구간 표 (백엔드 ping.loss_streaks — 구버전 result엔 없어 빈 표+재분석 안내)
    const streakTbody = document.querySelector('#ping-streak-table tbody');
    function renderPingStreaksWireless() {
        if (streakTbody) {
            const streaks = ping.loss_streaks || [];
            const fmtT = (str, epoch) => str || (typeof epoch === 'number'
                ? new Date(epoch * 1000).toLocaleTimeString('en-GB') : '-');
            if (streaks.length === 0) {
                const hint = ping.loss_streaks === undefined
                    ? '이 분석엔 장치별 구간 데이터가 없습니다 (재분석 시 표시)'
                    : '장치별 연속 실패 구간 없음 (산발적 발생)';
                streakTbody.innerHTML = `<tr><td colspan="6" class="text-gray-500 text-center py-6">${hint}</td></tr>`;
            } else {
                streakTbody.innerHTML = streaks.map(s => {
                    const shown = s.frame_refs || [];
                    const refs = shown.map(n => '#' + n).join(' ');
                    // count(연속 총건)보다 표시된 근거가 적으면(20건 cap 또는 seq_gap=번호없음) 생략 수를 +N으로.
                    const moreN = Math.max(0, (s.count || 0) - shown.length);
                    const refsCell = (refs ? escapeHtml(refs) : '')
                        + (moreN > 0 ? ` <span class="text-gray-600">…+${moreN}</span>` : '');
                    const seqRange = (s.first_seq != null && s.last_seq != null)
                        ? `${escapeHtml(String(s.first_seq))} ~ ${escapeHtml(String(s.last_seq))}` : '-';
                    return `<tr class="border-b border-gray-700/30 text-red-400 bg-red-900/10 hover:bg-gray-700/30">
                        <td class="py-1 px-1 text-gray-200">${escapeHtml(String(s.device ?? '?'))}</td>
                        <td class="py-1 px-1">${escapeHtml(fmtT(s.start_time, s.start_epoch))} ~ ${escapeHtml(fmtT(s.end_time, s.end_epoch))}</td>
                        <td class="py-1 px-1 text-right font-bold">${s.count}건</td>
                        <td class="py-1 px-1 text-right">${Number(s.duration_sec || 0).toFixed(1)}초</td>
                        <td class="py-1 px-1">${seqRange}</td>
                        <td class="py-1 px-1 text-gray-400 truncate max-w-[220px]" title="${escapeHtml(refs)}">${refsCell || '-'}</td>
                    </tr>`;
                }).join('');
            }
        }
    }

    function renderPingStreaksWired() {
        if (!streakTbody) return;
        const streaks = (gt && gt.streaks) || [];
        const streakKind = gt?.reply_timeout_sec != null ? 'Timeout/NG' : '손실';
        if (!streaks.length) {
            streakTbody.innerHTML = `<tr><td colspan="6" class="text-gray-500 text-center py-6">유선 연속 ${streakKind} 구간 없음 (산발적 발생)</td></tr>`;
            return;
        }
        const fmtE = e => (typeof e === 'number') ? new Date(e * 1000).toLocaleTimeString('en-GB') : '-';
        streakTbody.innerHTML = streaks.map(s => `<tr class="border-b border-gray-700/30 text-red-400 bg-red-900/10 hover:bg-gray-700/30">
            <td class="py-1 px-1 text-gray-200">${escapeHtml(String(s.target ?? '?'))}</td>
            <td class="py-1 px-1">${escapeHtml(fmtE(s.start_epoch))} ~ ${escapeHtml(fmtE(s.end_epoch))}</td>
            <td class="py-1 px-1 text-right font-bold">${Number(s.count ?? 0)}건</td>
            <td class="py-1 px-1 text-right">${Number(s.duration_sec || 0).toFixed(1)}초</td>
            <td class="py-1 px-1 text-gray-600">—</td>
            <td class="py-1 px-1 text-gray-600">—</td>
        </tr>`).join('');
    }

    // 소스 토글 초기화 + 최초 렌더 — streak/전체 목록/관찰 ICMP 위젯이 모두
    // 선언된 뒤에 실행해야 한다 (renderPingSource가 이들을 참조).
    const srcToggle = document.getElementById('ping-source-toggle');
    if (gtExchanges && srcToggle) {
        srcToggle.classList.remove('hidden');
        srcToggle.querySelectorAll('button').forEach(b =>
            b.addEventListener('click', () => renderPingSource(b.dataset.src)));
        renderPingSource('wired');
    } else {
        renderPingSource('wireless');
    }

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
    const timeoutAwareDiagnosis = diag.summary?.loss_metric === 'timeout_ng';
    const SIGNAL_TYPE_LABEL = {
        weak_rssi: '약신호',
        high_retry: 'retry 폭증',
        slow_roaming: '슬로우 로밍',
        frequent_roaming: '잦은 로밍',
        high_loss: timeoutAwareDiagnosis ? 'Ping Timeout/NG' : 'Ping Loss',
        delay_zone: '지연 구간',
        anomaly: '이상 프레임',
        mcs_hotspot: 'MCS 핫스팟',
        signal_cliff: '신호 급강하',
        legacy_heavy: 'Legacy 과다',
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

    // 지표별 점수 바 — score가 null(측정 불가, 예: ICMP 없는 캡처의 loss)이면
    // 게이지 대신 안내 문구. 구버전 result(숫자 score)는 기존 그대로 렌더.
    function scoreBar(label, score, icon) {
        if (score == null) {
            return `<div class="flex items-center gap-3">
                <span class="text-xs text-gray-400 w-20">${icon} ${label}</span>
                <div class="flex-1 text-xs text-gray-500 italic">측정 불가 (데이터 없음)</div>
            </div>`;
        }
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
        /* 판정에 쓴 값(loss_pct_used)을 보여준다 — 유선 GT가 있으면 무선 관측과
           다르고, 점수는 그 값으로 계산됐다. 두 값이 다르면 무선 관측도 함께 적어
           캡처 커버리지 차이를 감추지 않는다. 구버전 result는 loss_pct로 폴백.
           `|| 0`을 쓰지 않는 이유: 0%가 실제 값일 수 있어 null과 구분해야 한다. */
        /* 키는 structured.LOSS_BASIS_WIRED / LOSS_BASIS_WIRELESS와 같아야 한다
           (analyzer/web/structured.py). 바꾸면 여기와 report.py도 함께 고칠 것. */
        const LOSS_BASIS_LABEL = { wired_gt: '유선 확정', wireless_observed: '무선 관측' };
        const lossUsed = (typeof sm.loss_pct_used === 'number') ? sm.loss_pct_used
            : (typeof sm.loss_pct === 'number' ? sm.loss_pct : null);
        let lossText = (lossUsed == null) ? '측정불가' : `${lossUsed}%`;
        if (LOSS_BASIS_LABEL[sm.loss_basis]) {
            lossText += ` (${LOSS_BASIS_LABEL[sm.loss_basis]})`;
        }
        if (sm.loss_basis === 'wired_gt' && typeof sm.loss_pct === 'number'
            && sm.loss_pct !== lossUsed) {
            lossText += ` · 무선 관측 ${sm.loss_pct}%`;
        }
        const lossMetricLabel = sm.loss_metric === 'timeout_ng' ? 'Ping Timeout/NG' : 'Ping Loss';
        const lossSub = (compScores.loss == null)
            ? ''
            : `<p class="text-xs text-gray-500 ml-24">${lossMetricLabel} ${escapeHtml(lossText)}</p>`;
        barsEl.innerHTML = [
            scoreBar('Retry', compScores.retry ?? 0, '\u{1F504}') + `<p class="text-xs text-gray-500 ml-24">전체 ${sm.retry_pct || 0}%</p>`,
            scoreBar(lossMetricLabel, compScores.loss ?? null, '\u{1F4E1}') + lossSub,
            scoreBar('로밍', compScores.roaming ?? 0, '\u{1F6DC}') + `<p class="text-xs text-gray-500 ml-24">총 ${sm.roaming_total || 0}회, 느린 ${sm.roaming_slow || 0}회</p>`,
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
                    ${typeof scores.roaming === 'number'
                        ? miniBar('\ub85c\ubc0d', scores.roaming)
                        : `<div class="flex items-center gap-2 text-xs"><span class="w-12 text-gray-400">\ub85c\ubc0d</span>
                             <span class="text-gray-500" title="\uc774 STA\uc758 \ub85c\ubc0d\uc774 \uc804\ubd80 \ud310\uc815 \ubd88\uac00(4-way \ubbf8\ud3ec\ucc29)">\uce21\uc815\ubd88\uac00</span></div>`}
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
