"""pipeline 구조화 함수 테스트."""

from tests.conftest import make_frame, AP1, STA1, STA2, SAMPLE_ROLES
from analyzer.core.indexer import FrameIndex
from analyzer.pipeline import (
    _structured_overview,
    _structured_signal,
    _structured_ping,
    _structured_roaming,
    _structured_per_second,
    _structured_device_stats,
    _structured_diagnosis,
)
from analyzer.casefile_builder import build_casefile


def _build(frames, roles=None):
    roles = roles or SAMPLE_ROLES
    index = FrameIndex(frames, roles)
    return frames, roles, index


class TestStructuredOverview:
    def test_empty(self):
        result = _structured_overview([], {}, None)
        assert result["total_frames"] == 0

    def test_normal(self, sample_frames, sample_roles):
        result = _structured_overview(sample_frames, sample_roles, None)
        assert result["total_frames"] == 10
        assert result["duration_sec"] > 0
        assert "protocol_dist" in result
        assert "devices" in result


class TestStructuredSignal:
    def test_with_stas(self):
        frames = [
            make_frame(number=i, epoch=1000 + i, ta=STA1, ra=AP1, rssi=f"{-55 - i}")
            for i in range(10)
        ]
        f, r, idx = _build(frames)
        result = _structured_signal(f, r, idx)
        assert "STA1(0002)" in result["stas"]
        sta = result["stas"]["STA1(0002)"]
        assert sta["rssi_avg"] is not None
        assert sta["frame_count"] > 0

    def test_no_sta_frames(self):
        # STA가 있지만 RSSI 프레임이 없는 경우
        frames = [make_frame(number=1, epoch=1000, ta=AP1, ra=STA1, rssi="")]
        f, r, idx = _build(frames)
        result = _structured_signal(f, r, idx)
        for sta_info in result["stas"].values():
            assert sta_info["frame_count"] == 0 or sta_info["rssi_avg"] is None


class TestStructuredPing:
    def test_matched_pair(self):
        frames = [
            make_frame(
                number=1,
                epoch=1000,
                icmp_type="8",
                ip_src="10.0.0.1",
                ip_dst="10.0.0.2",
                icmp_seq="1",
                ta=STA1,
                ra=AP1,
            ),
            make_frame(
                number=2,
                epoch=1000.005,
                icmp_type="0",
                ip_src="10.0.0.2",
                ip_dst="10.0.0.1",
                icmp_seq="1",
                ta=AP1,
                ra=STA1,
            ),
        ]
        result = _structured_ping(frames, SAMPLE_ROLES)
        assert len(result["pairs"]) == 1
        assert len(result["losses"]) == 0
        assert result["stats"]["count"] == 1

    def test_loss(self):
        frames = [
            make_frame(
                number=1,
                epoch=1000,
                icmp_type="8",
                ip_src="10.0.0.1",
                ip_dst="10.0.0.2",
                icmp_seq="1",
                ta=STA1,
                ra=AP1,
            ),
        ]
        result = _structured_ping(frames, SAMPLE_ROLES)
        assert len(result["losses"]) == 1
        assert len(result["pairs"]) == 0

    def test_empty(self):
        result = _structured_ping([], SAMPLE_ROLES)
        assert result["full_list"] == []

    def test_seq_reuse_time_window(self):
        # 동일 (src,dst,seq)를 1분 간격으로 재사용 — 각각 매칭되어야 함
        frames = [
            make_frame(
                number=1,
                epoch=1000,
                icmp_type="8",
                ip_src="10.0.0.1",
                ip_dst="10.0.0.2",
                icmp_seq="1",
                ta=STA1,
                ra=AP1,
            ),
            make_frame(
                number=2,
                epoch=1000.005,
                icmp_type="0",
                ip_src="10.0.0.2",
                ip_dst="10.0.0.1",
                icmp_seq="1",
                ta=AP1,
                ra=STA1,
            ),
            # 60초 뒤 seq=1 재사용
            make_frame(
                number=3,
                epoch=1060,
                icmp_type="8",
                ip_src="10.0.0.1",
                ip_dst="10.0.0.2",
                icmp_seq="1",
                ta=STA1,
                ra=AP1,
            ),
            make_frame(
                number=4,
                epoch=1060.010,
                icmp_type="0",
                ip_src="10.0.0.2",
                ip_dst="10.0.0.1",
                icmp_seq="1",
                ta=AP1,
                ra=STA1,
            ),
        ]
        result = _structured_ping(frames, SAMPLE_ROLES)
        assert len(result["pairs"]) == 2
        assert len(result["losses"]) == 0
        # RTT 차이 확인 (5ms, 10ms)
        rtts = sorted(p["rtt_ms"] for p in result["pairs"])
        assert rtts[0] == 5.0
        assert rtts[1] == 10.0

    def test_request_outside_window_treated_as_loss(self):
        # req와 reply가 30초 초과 떨어짐 → 매칭 안 됨 (loss)
        frames = [
            make_frame(
                number=1,
                epoch=1000,
                icmp_type="8",
                ip_src="10.0.0.1",
                ip_dst="10.0.0.2",
                icmp_seq="99",
                ta=STA1,
                ra=AP1,
            ),
            make_frame(
                number=2,
                epoch=1031,
                icmp_type="0",
                ip_src="10.0.0.2",
                ip_dst="10.0.0.1",
                icmp_seq="99",
                ta=AP1,
                ra=STA1,
            ),
        ]
        result = _structured_ping(frames, SAMPLE_ROLES)
        assert len(result["pairs"]) == 0
        assert len(result["losses"]) == 1

    def test_duplicate_reply_only_first_matches(self):
        # 하나의 req에 reply 2개 → 첫 번째만 매칭
        frames = [
            make_frame(
                number=1,
                epoch=1000,
                icmp_type="8",
                ip_src="10.0.0.1",
                ip_dst="10.0.0.2",
                icmp_seq="7",
                ta=STA1,
                ra=AP1,
            ),
            make_frame(
                number=2,
                epoch=1000.005,
                icmp_type="0",
                ip_src="10.0.0.2",
                ip_dst="10.0.0.1",
                icmp_seq="7",
                ta=AP1,
                ra=STA1,
            ),
            make_frame(
                number=3,
                epoch=1000.010,
                icmp_type="0",
                ip_src="10.0.0.2",
                ip_dst="10.0.0.1",
                icmp_seq="7",
                ta=AP1,
                ra=STA1,
            ),
        ]
        result = _structured_ping(frames, SAMPLE_ROLES)
        assert len(result["pairs"]) == 1
        assert result["pairs"][0]["reply_num"] == 2  # 첫 reply만

    def test_reply_without_request_ignored(self):
        # reply만 있고 대응 req 없음
        frames = [
            make_frame(
                number=1,
                epoch=1000,
                icmp_type="0",
                ip_src="10.0.0.2",
                ip_dst="10.0.0.1",
                icmp_seq="5",
                ta=AP1,
                ra=STA1,
            ),
        ]
        result = _structured_ping(frames, SAMPLE_ROLES)
        assert len(result["pairs"]) == 0
        assert len(result["losses"]) == 0

    def test_no_seq_uses_fifo_fallback(self):
        frames = [
            make_frame(
                number=1,
                epoch=1000,
                icmp_type="8",
                ip_src="10.0.0.1",
                ip_dst="10.0.0.2",
                icmp_seq="",
                ta=STA1,
                ra=AP1,
            ),
            make_frame(
                number=2,
                epoch=1000.005,
                icmp_type="0",
                ip_src="10.0.0.2",
                ip_dst="10.0.0.1",
                icmp_seq="",
                ta=AP1,
                ra=STA1,
            ),
        ]
        result = _structured_ping(frames, SAMPLE_ROLES)
        assert len(result["pairs"]) == 1
        assert len(result["losses"]) == 0


class TestStructuredRoaming:
    def test_sequence(self):
        frames = [
            make_frame(number=1, epoch=1000, ta=STA1, ra=AP1, subtype="11"),  # Auth
            make_frame(
                number=2, epoch=1000.05, ta=STA1, ra=AP1, subtype="0"
            ),  # AssocReq
        ]
        result = _structured_roaming(frames, SAMPLE_ROLES)
        assert len(result["sequences"]) == 1
        assert result["sequences"][0]["gap_ms"] > 0

    def test_empty(self):
        result = _structured_roaming([], SAMPLE_ROLES)
        assert result["sequences"] == []


class TestStructuredPerSecond:
    def test_timeline(self):
        frames = [make_frame(number=i, epoch=1000 + i) for i in range(5)]
        result = _structured_per_second(frames)
        assert len(result["timeline"]) == 5

    def test_empty(self):
        result = _structured_per_second([])
        assert result["timeline"] == []


class TestStructuredDeviceStats:
    def test_stats(self, sample_frames, sample_roles, sample_index):
        result = _structured_device_stats(sample_frames, sample_roles, sample_index)
        assert len(result) > 0
        for name, stats in result.items():
            assert "total_frames" in stats
            assert "retry_pct" in stats


class TestStructuredDiagnosis:
    def test_health_score(self):
        structured = {
            "overview": {"total_frames": 1000, "retry_pct": 5},
            "ping": {"stats": {"loss_pct": 2}},
            "roaming": {"sequences": []},
            "signal": {"stas": {}},
            "device_stats": {},
            "delay_zones": {"delay_zones": []},
            "anomaly_frames": {"anomalies": []},
        }
        result = _structured_diagnosis(structured)
        assert result["health"]["score"] > 0
        assert result["health"]["grade"] in ("양호", "주의", "위험")

    def test_issues_sorted_by_severity(self):
        structured = {
            "overview": {"total_frames": 1000, "retry_pct": 30},
            "ping": {"stats": {"loss_pct": 15}},
            "roaming": {"sequences": [{"is_slow": True}] * 10},
            "signal": {"stas": {}},
            "device_stats": {},
            "delay_zones": {"delay_zones": [{}] * 5},
            "anomaly_frames": {"anomalies": []},
        }
        result = _structured_diagnosis(structured)
        issues = result["issues"]
        assert len(issues) > 0
        # high가 medium보다 먼저
        severities = [i["severity"] for i in issues]
        if "high" in severities and "medium" in severities:
            assert severities.index("high") < severities.index("medium")


class TestCasefileBuilder:
    def test_casefile_ping_parity_exact(self):
        frames = [
            make_frame(
                number=1,
                epoch=1000,
                icmp_type="8",
                ip_src="10.0.0.1",
                ip_dst="10.0.0.2",
                icmp_seq="1",
                ta=STA1,
                ra=AP1,
            ),
            make_frame(
                number=2,
                epoch=1000.005,
                icmp_type="0",
                ip_src="10.0.0.2",
                ip_dst="10.0.0.1",
                icmp_seq="1",
                ta=AP1,
                ra=STA1,
            ),
            make_frame(
                number=3,
                epoch=1001.0,
                icmp_type="8",
                ip_src="10.0.0.1",
                ip_dst="10.0.0.2",
                icmp_seq="2",
                ta=STA1,
                ra=AP1,
            ),
        ]
        structured_ping = _structured_ping(frames, SAMPLE_ROLES)
        result = {
            "id": "test-analysis",
            "pcap_name": "test.pcap",
            "structured": {
                "overview": {"total_frames": 3, "retry_pct": 0},
                "ping": structured_ping,
            },
            "text_sections": [],
        }

        casefile = build_casefile(result)

        assert casefile["analysis_id"] == "test-analysis"
        assert casefile["schema_version"] == "1.0"
        assert casefile["generator_version"] == "casefile-v1"
        assert casefile["incident_id"].startswith("test-analysis:")
        assert casefile["ping"]["full_list"] == structured_ping["full_list"]
        assert casefile["ping"]["pairs"] == structured_ping["pairs"]
        assert casefile["ping"]["losses"] == structured_ping["losses"]

    def test_casefile_requires_timeout_loss(self):
        frames = [
            make_frame(
                number=1,
                epoch=1000,
                icmp_type="8",
                ip_src="10.0.0.1",
                ip_dst="10.0.0.2",
                icmp_seq="1",
                ta=STA1,
                ra=AP1,
            ),
            make_frame(
                number=2,
                epoch=1000.005,
                icmp_type="0",
                ip_src="10.0.0.2",
                ip_dst="10.0.0.1",
                icmp_seq="1",
                ta=AP1,
                ra=STA1,
            ),
        ]
        structured_ping = _structured_ping(frames, SAMPLE_ROLES)
        result = {
            "id": "test-analysis",
            "pcap_name": "test.pcap",
            "structured": {
                "overview": {"total_frames": 2, "retry_pct": 0},
                "ping": structured_ping,
                "per_second": {"timeline": []},
                "roaming": {"sequences": []},
            },
            "text_sections": [],
        }

        import pytest

        with pytest.raises(ValueError):
            build_casefile(result)
