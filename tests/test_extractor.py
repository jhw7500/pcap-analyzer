"""tshark 명령어 생성 + TSV 파싱 테스트."""
from analyzer.core.extractor import build_tshark_cmd, parse_tsv_line, detect_tshark_version


class TestBuildTsharkCmd:
    def test_basic(self):
        cmd = build_tshark_cmd("/tmp/test.pcap")
        assert cmd[0] == "tshark"
        assert "-r" in cmd
        assert "/tmp/test.pcap" in cmd
        assert "-T" in cmd
        assert "fields" in cmd

    def test_with_wpa(self):
        cmd = build_tshark_cmd("/tmp/t.pcap", wpa_passphrase="pass", ssid="net")
        joined = " ".join(cmd)
        assert "wlan.enable_decryption" in joined
        assert "pass:net" in joined

    def test_without_wpa_no_decryption(self):
        cmd = build_tshark_cmd("/tmp/t.pcap", wpa_passphrase="", ssid="net")
        joined = " ".join(cmd)
        assert "wlan.enable_decryption" not in joined

    def test_mac_filter(self):
        cmd = build_tshark_cmd("/tmp/t.pcap", mac_filter="aa:bb:cc:dd:ee:ff")
        joined = " ".join(cmd)
        assert "wlan.addr == aa:bb:cc:dd:ee:ff" in joined

    def test_ip_filter(self):
        cmd = build_tshark_cmd("/tmp/t.pcap", ip_filter="192.168.1.1")
        joined = " ".join(cmd)
        assert "ip.addr == 192.168.1.1" in joined

    def test_time_filter(self):
        cmd = build_tshark_cmd("/tmp/t.pcap", time_start="2026-01-01", time_end="2026-01-02")
        joined = " ".join(cmd)
        assert "frame.time >=" in joined
        assert "frame.time <" in joined

    def test_multi_mac_filter(self):
        cmd = build_tshark_cmd("/tmp/t.pcap", mac_filter="aa:bb:cc:dd:ee:01, aa:bb:cc:dd:ee:02")
        joined = " ".join(cmd)
        assert "||" in joined

    def test_custom_tshark_path(self):
        cmd = build_tshark_cmd("/tmp/t.pcap", tshark_path="/opt/wireshark/bin/tshark")
        assert cmd[0] == "/opt/wireshark/bin/tshark"

    def test_empty_tshark_path_fallback(self):
        cmd = build_tshark_cmd("/tmp/t.pcap", tshark_path="")
        assert cmd[0] == "tshark"

    def test_default_tshark_path(self):
        cmd = build_tshark_cmd("/tmp/t.pcap")
        assert cmd[0] == "tshark"


class TestDetectTsharkVersion:
    def test_real_tshark_returns_version(self):
        # tshark가 시스템에 있으면 실제 버전 추출, 없으면 unknown
        import shutil
        info = detect_tshark_version(shutil.which("tshark") or "tshark")
        assert "version" in info
        assert "path" in info
        assert "raw" in info

    def test_nonexistent_path_returns_unknown(self):
        info = detect_tshark_version("/nonexistent/tshark/bin")
        assert info["version"] == "unknown"
        assert info["raw"] == ""

    def test_empty_path_fallback(self):
        # 빈 문자열이면 "tshark"로 fallback
        info = detect_tshark_version("")
        # 시스템에 tshark가 있으면 감지 성공, 없으면 unknown
        assert isinstance(info["version"], str)
        assert info["path"] == ""


class TestParseTsvLine:
    def test_valid_line(self):
        # 20 fields: number, epoch, timestamp, retry, subtype, protocol, length,
        # mcs, rssi, ta, ra, bssid, ip_src, ip_dst, icmp_type, arp_opcode,
        # tcp_len, tcp_flags, seq, icmp_seq
        fields = [
            "1", "1000.123", "Jan 1 00:00:00.123", "0", "0x0028", "802.11",
            "100", "7", "-60", "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02",
            "aa:bb:cc:dd:ee:03", "", "", "", "", "", "", "10", ""
        ]
        line = "\t".join(fields)
        frame = parse_tsv_line(line)
        assert frame is not None
        assert frame.number == 1
        assert frame.epoch == 1000.123
        assert frame.retry is False
        assert frame.subtype == "40"  # 0x28 = 40
        assert frame.length == 100

    def test_retry_true(self):
        fields = ["1", "1000.0", "ts", "1", "40", "802.11", "100",
                  "", "", "", "", "", "", "", "", "", "", "", "", ""]
        frame = parse_tsv_line("\t".join(fields))
        assert frame is not None
        assert frame.retry is True

    def test_short_line_rejected(self):
        assert parse_tsv_line("1\t2\t3") is None

    def test_empty_line(self):
        assert parse_tsv_line("") is None

    def test_missing_fields_padded(self):
        # 7 fields minimum — rest should be padded
        fields = ["1", "1000.0", "ts", "0", "40", "802.11", "100"]
        frame = parse_tsv_line("\t".join(fields))
        assert frame is not None
        assert frame.ta == ""
        assert frame.ip_src == ""

    def test_all_eight_debug_fields_populated(self):
        # 27 fields incl. wlan.fixed.reason_code at cols[26].
        # 디버그 뷰 frame_row의 8개 핵심 필드가 모두 채워지는지 확인:
        # number, timestamp, subtype, retry, mcs, rssi, reason_code, seq
        fields = [
            "42",                 # 0 frame.number
            "1000.5",             # 1 frame.time_epoch
            "Jan 1 00:00:00.500", # 2 frame.time
            "1",                  # 3 wlan.fc.retry
            "0x000c",             # 4 wlan.fc.type_subtype (DeAuth = 12)
            "802.11",             # 5 _ws.col.Protocol
            "120",                # 6 frame.len
            "7",                  # 7 radiotap.mcs.index
            "-55",                # 8 radiotap.dbm_antsignal
            "aa:bb:cc:dd:ee:01",  # 9 wlan.ta
            "aa:bb:cc:dd:ee:02",  # 10 wlan.ra
            "aa:bb:cc:dd:ee:03",  # 11 wlan.bssid
            "", "",               # 12-13 ip.src/dst
            "", "",               # 14-15 icmp.type/arp.opcode
            "", "",               # 16-17 tcp.len/flags
            "1234",               # 18 wlan.seq
            "",                   # 19 icmp.seq
            "", "", "", "",       # 20-23 wlan_radio MCS variants / HE
            "", "",               # 24-25 data_rate / icmp.ident
            "7",                  # 26 wlan.fixed.reason_code
        ]
        frame = parse_tsv_line("\t".join(fields))
        assert frame is not None
        assert frame.number == 42
        assert frame.timestamp == "Jan 1 00:00:00.500"
        assert frame.subtype == "12"  # 0x000c = 12
        assert frame.retry is True
        assert frame.mcs == "7"
        assert frame.rssi == "-55"
        assert frame.reason_code == "7"
        assert frame.seq == "1234"
