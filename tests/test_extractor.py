"""tshark 명령어 생성 + TSV 파싱 테스트."""
from analyzer.core.extractor import build_tshark_cmd, parse_tsv_line


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
