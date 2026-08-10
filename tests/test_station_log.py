"""STA 로그 파싱 + pcap 상관.

pcap은 전파에 나온 프레임만 본다 — 실측(2시간 캡처, 837건 대조)으로 로밍 전체
97.0ms 중 pcap이 보는 건 25.1ms뿐이고 **74%가 전파 밖**이다. 스캔·로밍 판단·
드라이버 상태 전이·키 설치는 STA 로그에만 남는다.
"""
import textwrap

from analyzer.core.station_log import (
    parse_kern_log,
    parse_logger_log,
    parse_station_logs,
    parse_wpa_log,
)
from analyzer.core.station_match import (
    attach_station_to_sequences,
    bind_stations,
    estimate_offset,
    pcap_ip_bindings,
)


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")
    return str(p)


WPA_ONE_ROAM = """
2026-07-23 08:50:07.855 wpa_supplicant[info] mlan0: Event SCAN_STARTED (47) received
2026-07-23 08:50:07.918 wpa_supplicant[info] mlan0: Event SCAN_RESULTS (3) received
2026-07-23 08:50:08.975 wpa_supplicant[info] mlan0: Control interface command 'ROAM 00:80:4c:e1:09:cc'
2026-07-23 08:50:09.037 wpa_supplicant[info] mlan0: State: COMPLETED -> AUTHENTICATING
2026-07-23 08:50:09.530 wpa_supplicant[info] mlan0: Event AUTH (10) received
2026-07-23 08:50:09.604 wpa_supplicant[info] mlan0: CTRL-EVENT-CONNECTED - Connection to 00:80:4c:e1:09:cc completed [id=0 id_str=]
"""


class TestParseWpaLog:
    def test_single_roam_boundaries(self, tmp_path):
        eps = parse_wpa_log(_write(tmp_path, "wpa.log", WPA_ONE_ROAM))
        assert len(eps) == 1
        e = eps[0]
        assert not e.failed
        assert e.target_bssid == "00:80:4c:e1:09:cc"
        # ROAM 명령(08.975) → CONNECTED(09.604) = 629ms
        assert round(e.total_ms) == 629
        # AUTHENTICATING(09.037) → CONNECTED(09.604) = 567ms
        assert round(e.assoc_procedure_ms) == 567

    def test_connected_without_roam_is_not_counted(self, tmp_path):
        """실측: CONNECTED는 307건인데 ROAM은 306건 — 1건은 자동 재접속이다.

        CONNECTED로 로밍을 세면 과대계상되므로 ROAM 명령을 앵커로 쓴다.
        """
        log = WPA_ONE_ROAM + (
            "2026-07-23 09:00:00.000 wpa_supplicant[info] mlan0: State: SCANNING -> AUTHENTICATING\n"
            "2026-07-23 09:00:00.100 wpa_supplicant[info] mlan0: "
            "CTRL-EVENT-CONNECTED - Connection to 00:80:4c:e1:09:cb completed [id=0 id_str=]\n"
        )
        eps = parse_wpa_log(_write(tmp_path, "wpa.log", log))
        assert len(eps) == 1        # 재접속은 로밍이 아니다

    def test_auth_timed_out_marks_failure(self, tmp_path):
        log = """
        2026-07-23 08:50:08.975 wpa_supplicant[info] mlan0: Control interface command 'ROAM 00:80:4c:e1:09:cc'
        2026-07-23 08:50:09.037 wpa_supplicant[info] mlan0: State: COMPLETED -> AUTHENTICATING
        2026-07-23 08:50:11.437 wpa_supplicant[info] mlan0: Event AUTH_TIMED_OUT (13) received
        """
        eps = parse_wpa_log(_write(tmp_path, "wpa.log", log))
        assert len(eps) == 1
        assert eps[0].failed and eps[0].total_ms is None
        assert "AUTH_TIMED_OUT" in eps[0].fail_reason

    def test_next_roam_closes_unfinished_episode(self, tmp_path):
        log = """
        2026-07-23 08:50:08.975 wpa_supplicant[info] mlan0: Control interface command 'ROAM 00:80:4c:e1:09:cc'
        2026-07-23 08:50:30.000 wpa_supplicant[info] mlan0: Control interface command 'ROAM 00:80:4c:e1:09:cb'
        2026-07-23 08:50:30.100 wpa_supplicant[info] mlan0: CTRL-EVENT-CONNECTED - Connection to 00:80:4c:e1:09:cb completed [id=0 id_str=]
        """
        eps = parse_wpa_log(_write(tmp_path, "wpa.log", log))
        assert len(eps) == 2
        assert eps[0].failed and not eps[1].failed


class TestParseKernLog:
    def test_scan_pairing_forward_single_slot(self, tmp_path):
        """고아 COMPLETED가 있어도 가짜 스캔을 만들지 않는다.

        실측 회귀: 역방향('COMPLETED 직전 가장 가까운 START') 페어링을 쓰면
        1호기에서 4,607ms짜리 가짜 스캔이 생겨 max/p99를 오염시킨다.
        """
        log = """
        2026-07-23 08:50:07.854 kernel[alert][161006.004226] wlan: mlan0 START SCAN
        2026-07-23 08:50:07.917 kernel[warning][161006.067226] wlan: SCAN COMPLETED: scanned AP count=2
        2026-07-23 08:50:12.500 kernel[warning][161010.650226] wlan: SCAN COMPLETED: scanned AP count=0
        """
        k = parse_kern_log(_write(tmp_path, "kern.log", log))
        assert len(k["scans"]) == 1
        assert k["orphan_scan_completed"] == 1
        # monotonic으로 재야 벽시계 지터를 피한다: 161006.067226-161006.004226
        assert round(k["scans"][0].duration_ms) == 63

    def test_sta_ip_ignores_zero_address(self, tmp_path):
        """실측: IPv4 갱신 614줄 중 절반이 0.0.0.0이라 필터 없으면 매칭이 전멸한다."""
        log = """
        2026-07-23 08:50:09.040 kernel[alert][161007.189330] bridge: wlan IPv4 updated = 0.0.0.0
        2026-07-23 08:50:09.140 kernel[alert][161007.289330] bridge: wlan IPv4 updated = 192.168.0.21
        2026-07-23 08:50:26.100 kernel[alert][161023.800000] bridge: wlan IPv4 updated = 0.0.0.0
        2026-07-23 08:50:26.203 kernel[alert][161023.860481] bridge: wlan IPv4 updated = 192.168.0.21
        """
        k = parse_kern_log(_write(tmp_path, "kern.log", log))
        assert k["sta_ip"] == "192.168.0.21"

    def test_ap_count_zero_is_kept(self, tmp_path):
        """count=0도 정상 값이다 — falsy로 버리면 스캔이 사라진다."""
        log = """
        2026-07-23 08:50:07.854 kernel[alert][100.000000] wlan: mlan0 START SCAN
        2026-07-23 08:50:07.917 kernel[warning][100.063000] wlan: SCAN COMPLETED: scanned AP count=0
        """
        k = parse_kern_log(_write(tmp_path, "kern.log", log))
        assert len(k["scans"]) == 1 and k["scans"][0].ap_count == 0


class TestParseLoggerLog:
    def test_duplicate_roaming_lines_deduped(self, tmp_path):
        """같은 로밍이 wifi_roam.py의 두 지점에서 로그를 남긴다(실측 612 = 306×2)."""
        log = """
        2026-07-23 08:50:08.940 ROAM[info] [wifi_roam.py:2263] [mlan0] roaming condition: -67 < -65 (base=-65, trend=stable)
        2026-07-23 08:50:08.960 ROAM[info] [wifi_roam.py:2382] [mlan0] Roam candidate: 00:80:4c:e1:09:cc, rssi=-51dB (diff=16dB), load=0.0%, reason=RSSI diff: 16dB, score=160.0
        2026-07-23 08:50:08.965 ROAM[warning] [wifi_roam.py:2401] [mlan0] Roaming: 00:80:4c:e1:09:cb → 00:80:4c:e1:09:cc, reason=RSSI diff: 16dB, score=160.0
        2026-07-23 08:50:08.967 ROAM[warning] [wifi_roam.py:1777] [mlan0] Roaming: 00:80:4c:e1:09:cb → 00:80:4c:e1:09:cc
        """
        ds = parse_logger_log(_write(tmp_path, "logger.log", log))
        assert len(ds) == 1
        d = ds[0]
        assert d.reason == "RSSI diff: 16dB" and d.score == 160.0
        assert d.trigger_rssi == -67 and d.trigger_th == -65 and d.trend == "stable"


class TestOffsetAndBinding:
    def test_estimate_offset_recovers_known_shift(self):
        log_t = [1000.0, 1020.0, 1040.0, 1060.0, 1080.0, 1100.0]
        shift = 2.744
        pcap_t = [t + shift + (0.01 if i % 2 else -0.01) for i, t in enumerate(log_t)]
        off, n, mad = estimate_offset(log_t, pcap_t)
        assert abs(off - shift) < 0.05
        assert n == len(log_t)
        assert mad < 0.05

    def test_estimate_offset_empty(self):
        assert estimate_offset([], [1.0])[0] is None
        assert estimate_offset([1.0], [])[0] is None

    def test_pcap_ip_bindings_uses_sender_only(self):
        class F:
            def __init__(self, ta, ip_src):
                self.ta, self.ip_src = ta, ip_src

        frames = [F("00:50:43:18:fe:01", "192.168.0.21")] * 3 + [
            F("00:50:43:1a:fe:01", "192.168.0.23"),
            F("00:50:43:18:fe:01,4c:e1", "192.168.0.99"),   # A-MSDU 결합 값 — 버린다
        ]
        b = pcap_ip_bindings(frames)
        assert b["192.168.0.21"] == "00:50:43:18:fe:01"
        assert b["192.168.0.23"] == "00:50:43:1a:fe:01"
        assert "192.168.0.99" not in b


class TestAttachToSequences:
    def _station(self, tmp_path):
        files = {
            "wpa.log": _write(tmp_path, "wpa.log", WPA_ONE_ROAM),
            "kern.log": _write(tmp_path, "kern.log", """
                2026-07-23 08:50:07.854 kernel[alert][100.000000] wlan: mlan0 START SCAN
                2026-07-23 08:50:07.917 kernel[warning][100.063000] wlan: SCAN COMPLETED: scanned AP count=2
                2026-07-23 08:50:09.040 kernel[alert][101.200000] bridge: wlan IPv4 updated = 192.168.0.21
            """),
            "logger.log": _write(tmp_path, "logger.log", """
                2026-07-23 08:50:08.940 ROAM[info] [wifi_roam.py:2263] [mlan0] roaming condition: -67 < -65 (base=-65, trend=stable)
                2026-07-23 08:50:08.960 ROAM[info] [wifi_roam.py:2382] [mlan0] Roam candidate: 00:80:4c:e1:09:cc, rssi=-51dB (diff=16dB), load=0.0%, reason=RSSI diff: 16dB, score=160.0
                2026-07-23 08:50:08.965 ROAM[warning] [wifi_roam.py:2401] [mlan0] Roaming: 00:80:4c:e1:09:cb → 00:80:4c:e1:09:cc, reason=RSSI diff: 16dB, score=160.0
            """),
        }
        return parse_station_logs(files, name="1호기")

    def test_binds_by_ip_and_attaches(self, tmp_path):
        st = self._station(tmp_path)
        assert st.sta_ip == "192.168.0.21"
        roam_epoch = st.roams[0].cmd_epoch

        class F:
            def __init__(self, ta, ip_src):
                self.ta, self.ip_src = ta, ip_src

        frames = [F("00:50:43:18:fe:01", "192.168.0.21")] * 5
        seqs = [{
            "sta": "00:50:43:18:fe:01", "sta_name": "STA2",
            "auth_epoch": roam_epoch + 0.05, "assoc_epoch": roam_epoch + 0.06,
            "total_roam_ms": 25.0,
        }]
        binds = bind_stations([st], frames, {"00:50:43:18:fe:01": [roam_epoch + 0.05]})
        assert binds[0].sta_mac == "00:50:43:18:fe:01"
        assert binds[0].method == "ip"

        n = attach_station_to_sequences(seqs, st, binds[0])
        assert n == 1
        L = seqs[0]["sta_log"]
        assert round(L["total_ms"]) == 629
        assert L["reason"] == "RSSI diff: 16dB" and L["score"] == 160.0
        assert L["trigger_rssi"] == -67 and L["trigger_th"] == -65
        assert round(L["scan_ms"]) == 63     # 직전 스캔
        assert L["source"] == "1호기"

    def test_out_of_tolerance_not_attached(self, tmp_path):
        """멀리 떨어진 로밍에 억지로 붙이면 다른 로밍의 값을 보고하게 된다."""
        st = self._station(tmp_path)
        roam_epoch = st.roams[0].cmd_epoch

        class F:
            def __init__(self, ta, ip_src):
                self.ta, self.ip_src = ta, ip_src

        frames = [F("00:50:43:18:fe:01", "192.168.0.21")]
        far = roam_epoch + 30.0
        seqs = [{"sta": "00:50:43:18:fe:01", "auth_epoch": far, "assoc_epoch": far}]
        binds = bind_stations([st], frames, {"00:50:43:18:fe:01": [roam_epoch + 0.05]})
        assert attach_station_to_sequences(seqs, st, binds[0]) == 0
        assert "sta_log" not in seqs[0]

    def test_unmatched_station_reports_warning(self, tmp_path):
        st = self._station(tmp_path)
        binds = bind_stations([st], [], {})     # pcap 정보 없음
        assert binds[0].sta_mac == ""
        assert any("매칭하지 못했다" in w for w in binds[0].warnings)


class TestMissingFiles:
    def test_partial_set_warns_but_parses(self, tmp_path):
        st = parse_station_logs(
            {"wpa.log": _write(tmp_path, "wpa.log", WPA_ONE_ROAM)}, name="x"
        )
        assert len(st.roams) == 1
        assert any("kern.log 없음" in w for w in st.warnings)
        assert any("logger.log 없음" in w for w in st.warnings)

    def test_empty_set(self):
        st = parse_station_logs({}, name="x")
        assert st.roams == [] and st.scans == [] and len(st.warnings) == 3
