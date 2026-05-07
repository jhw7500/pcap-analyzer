"""웹 시각화 분석 모듈 테스트."""
from analyzer.web.delay_analysis import analyze_delays
from analyzer.web.anomaly_frames import detect_anomalies
from analyzer.web.signal_cliff import analyze_signal_cliffs


class TestAnalyzeDelays:
    def test_empty_data(self):
        result = analyze_delays(
            {"pairs": [], "losses": []},
            {"sequences": []},
            {"timeline": []},
        )
        assert result["delay_zones"] == []
        assert result["summary"]["total_zones"] == 0

    def test_detects_high_rtt_zone(self):
        # 10 normal pings + 3 high RTT pings
        pairs = [{"epoch": 1000 + i, "rtt_ms": 5.0} for i in range(10)]
        pairs += [{"epoch": 1010 + i, "rtt_ms": 100.0} for i in range(3)]
        result = analyze_delays(
            {"pairs": pairs, "losses": []},
            {"sequences": []},
            {"timeline": []},
        )
        assert result["summary"]["total_zones"] >= 1

    def test_detects_loss_zone(self):
        pairs = [{"epoch": 1000 + i, "rtt_ms": 5.0} for i in range(5)]
        losses = [{"epoch": 1010.0}, {"epoch": 1011.0}]
        result = analyze_delays(
            {"pairs": pairs, "losses": losses},
            {"sequences": []},
            {"timeline": []},
        )
        assert result["summary"]["total_zones"] >= 1

    def test_roaming_cause_detection(self):
        pairs = [{"epoch": 1000 + i, "rtt_ms": 5.0} for i in range(10)]
        pairs += [{"epoch": 1010, "rtt_ms": 200.0}]
        roaming = {"sequences": [{"auth_epoch": 1010.5}]}
        result = analyze_delays(
            {"pairs": pairs, "losses": []},
            roaming,
            {"timeline": []},
        )
        zones = result["delay_zones"]
        if zones:
            assert zones[0]["cause"] == "roaming"


class TestDetectAnomalies:
    def test_empty(self):
        result = detect_anomalies({"total_frames": 0})
        assert result["anomalies"] == []

    def test_deauth_detected(self):
        result = detect_anomalies({
            "total_frames": 1000,
            "subtype_dist": {"12": 15},
            "protocol_dist": {},
        })
        anomalies = result["anomalies"]
        assert len(anomalies) == 1
        assert anomalies[0]["type"] == "deauth_disassoc"
        assert anomalies[0]["severity"] == "high"

    def test_excessive_probe_req(self):
        result = detect_anomalies({
            "total_frames": 100,
            "subtype_dist": {"4": 25},  # 25%
            "protocol_dist": {},
        })
        anomalies = result["anomalies"]
        types = [a["type"] for a in anomalies]
        assert "excessive_probe_req" in types

    def test_arp_storm(self):
        result = detect_anomalies({
            "total_frames": 100,
            "subtype_dist": {},
            "protocol_dist": {"ARP": 15},  # 15%
        })
        anomalies = result["anomalies"]
        types = [a["type"] for a in anomalies]
        assert "arp_storm" in types

    def test_no_anomalies_normal(self):
        result = detect_anomalies({
            "total_frames": 10000,
            "subtype_dist": {"40": 8000, "8": 1000},
            "protocol_dist": {"802.11": 9000},
        })
        assert len(result["anomalies"]) == 0


class TestSignalCliffs:
    def test_empty(self):
        result = analyze_signal_cliffs({"stas": {}})
        assert result == {}

    def test_no_cliff_stable_signal(self):
        timeline = [{"epoch": 1000 + i * 0.1, "rssi": -50, "mcs": 7} for i in range(20)]
        result = analyze_signal_cliffs({"stas": {"STA1": {"rssi_timeline": timeline}}})
        assert result["STA1"]["cliffs"] == []

    def test_cliff_detected(self):
        # Stable at -50, then drop to -70
        timeline = [{"epoch": 1000 + i * 0.1, "rssi": -50, "mcs": 7} for i in range(15)]
        timeline += [{"epoch": 1001.5 + i * 0.1, "rssi": -70, "mcs": 3} for i in range(10)]
        result = analyze_signal_cliffs({"stas": {"STA1": {"rssi_timeline": timeline}}})
        cliffs = result["STA1"]["cliffs"]
        assert len(cliffs) >= 1
        assert cliffs[0]["drop_db"] >= 10

    def test_moving_average_generated(self):
        timeline = [{"epoch": 1000 + i * 0.1, "rssi": -55 + (i % 3), "mcs": 7} for i in range(25)]
        result = analyze_signal_cliffs({"stas": {"STA1": {"rssi_timeline": timeline}}})
        assert len(result["STA1"]["moving_avg"]) > 0

    def test_few_points_skipped(self):
        timeline = [{"epoch": 1000 + i, "rssi": -50, "mcs": 7} for i in range(5)]
        result = analyze_signal_cliffs({"stas": {"STA1": {"rssi_timeline": timeline}}})
        assert result["STA1"]["cliffs"] == []
        assert result["STA1"]["moving_avg"] == []
