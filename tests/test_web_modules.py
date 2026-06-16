"""웹 시각화 분석 모듈 테스트."""
from analyzer.core.indexer import FrameIndex
from analyzer.web.delay_analysis import analyze_delays
from analyzer.web.anomaly_frames import detect_anomalies
from analyzer.web.signal_cliff import analyze_signal_cliffs
from analyzer.web.evidence import (
    cliff_evidence,
    mcs_hotspot_evidence,
    network_legacy_evidence,
)
from tests.conftest import make_frame, SAMPLE_ROLES, STA1, AP1


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


class TestMcsHotspotEvidence:
    def _index(self, frames):
        return FrameIndex(frames, dict(SAMPLE_ROLES))

    def test_modern_phy_match(self):
        # HE MCS7 retry 프레임 3건 + 비매칭 프레임.
        frames = [
            make_frame(number=1, epoch=1000.0, ta=STA1, ra=AP1, retry=True,
                       mcs="7", mcs_phy="HE"),
            make_frame(number=2, epoch=1001.0, ta=STA1, ra=AP1, retry=True,
                       mcs="7", mcs_phy="HE"),
            make_frame(number=3, epoch=1002.0, ta=STA1, ra=AP1, retry=True,
                       mcs="7", mcs_phy="HE"),
            # 비매칭: 다른 MCS / non-retry / 다른 PHY.
            make_frame(number=4, epoch=1003.0, ta=STA1, ra=AP1, retry=True,
                       mcs="3", mcs_phy="HE"),
            make_frame(number=5, epoch=1004.0, ta=STA1, ra=AP1, retry=False,
                       mcs="7", mcs_phy="HE"),
        ]
        idx = self._index(frames)
        refs, window = mcs_hotspot_evidence(STA1, "HE", "7", frames, idx)
        assert set(refs) == {1, 2, 3}
        assert window == {"start_epoch": 1000.0, "end_epoch": 1002.0}

    def test_legacy_match(self):
        frames = [
            make_frame(number=1, epoch=1000.0, ta=STA1, ra=AP1, retry=True,
                       mcs="", mcs_phy="Legacy", data_rate="6"),
            make_frame(number=2, epoch=1001.0, ta=STA1, ra=AP1, retry=True,
                       mcs="", mcs_phy="", data_rate="6"),
            make_frame(number=3, epoch=1002.0, ta=STA1, ra=AP1, retry=True,
                       mcs="", mcs_phy="Legacy", data_rate="54"),
        ]
        idx = self._index(frames)
        refs, window = mcs_hotspot_evidence(STA1, "Legacy", "6", frames, idx)
        assert set(refs) == {1, 2}
        assert window is not None

    def test_no_match_returns_empty(self):
        frames = [
            make_frame(number=1, epoch=1000.0, ta=STA1, ra=AP1, retry=False,
                       mcs="7", mcs_phy="HE"),
        ]
        idx = self._index(frames)
        assert mcs_hotspot_evidence(STA1, "HE", "7", frames, idx) == ([], None)


class TestCliffEvidence:
    def _index(self, frames):
        return FrameIndex(frames, dict(SAMPLE_ROLES))

    def test_frames_near_cliff(self):
        frames = [
            make_frame(number=1, epoch=1000.0, ta=STA1, ra=AP1),
            make_frame(number=2, epoch=1000.5, ta=STA1, ra=AP1),
            make_frame(number=3, epoch=1005.0, ta=STA1, ra=AP1),  # 멀리
        ]
        idx = self._index(frames)
        cliffs = [{"epoch": 1000.2, "drop_db": 15}]
        refs, window = cliff_evidence(STA1, cliffs, frames, idx)
        assert set(refs) == {1, 2}
        assert window == {"start_epoch": 1000.2, "end_epoch": 1000.2}

    def test_empty_cliffs_returns_empty(self):
        frames = [make_frame(number=1, epoch=1000.0, ta=STA1, ra=AP1)]
        idx = self._index(frames)
        assert cliff_evidence(STA1, [], frames, idx) == ([], None)

    def test_fallback_to_lowest_rssi(self):
        # cliff epoch 근처(±1s)엔 프레임 없지만 worst cliff ±5s 안에 RSSI 프레임 존재.
        frames = [
            make_frame(number=1, epoch=1003.0, ta=STA1, ra=AP1, rssi="-80,-82"),
            make_frame(number=2, epoch=1004.0, ta=STA1, ra=AP1, rssi="-60,-62"),
        ]
        idx = self._index(frames)
        cliffs = [{"epoch": 1000.0, "drop_db": 20}]
        refs, window = cliff_evidence(STA1, cliffs, frames, idx)
        assert refs == [1]  # 최저 RSSI(-80) 프레임
        assert window == {"start_epoch": 1000.0, "end_epoch": 1000.0}


class TestNetworkLegacyEvidence:
    def test_collects_legacy_frames(self):
        frames = [
            make_frame(number=1, epoch=1000.0, ta=STA1, ra=AP1, mcs_phy="Legacy",
                       data_rate="6"),
            make_frame(number=2, epoch=1001.0, ta=STA1, ra=AP1, mcs_phy=""),
            make_frame(number=3, epoch=1002.0, ta=STA1, ra=AP1, mcs_phy="HE", mcs="7"),
        ]
        idx = FrameIndex(frames, dict(SAMPLE_ROLES))
        refs, window = network_legacy_evidence(frames, idx)
        assert set(refs) == {1, 2}
        assert window == {"start_epoch": 1000.0, "end_epoch": 1001.0}

    def test_no_legacy_returns_empty(self):
        frames = [
            make_frame(number=1, epoch=1000.0, ta=STA1, ra=AP1, mcs_phy="HE", mcs="7"),
        ]
        idx = FrameIndex(frames, dict(SAMPLE_ROLES))
        assert network_legacy_evidence(frames, idx) == ([], None)
