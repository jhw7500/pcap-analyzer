"""분석 모듈 11개 + compare_ap 단위 테스트."""
from tests.conftest import make_frame, AP1, STA1, SAMPLE_ROLES
from analyzer.core.indexer import FrameIndex
from analyzer.core.modules import (
    overview, retry_mcs, retry_burst, roaming, ping_rtt,
    control_traffic, signal_quality, per_second,
    roaming_impact, ping_loss, diagnosis,
)
from analyzer.core.modules.compare_ap import analyze as compare_ap_analyze


def _build(frames, roles=None):
    roles = roles or SAMPLE_ROLES
    index = FrameIndex(frames, roles)
    return frames, roles, index


class TestOverview:
    def test_empty(self):
        sec = overview.analyze([], {}, None)
        assert "없음" in sec.summary

    def test_normal(self, sample_frames, sample_roles, sample_index):
        sec = overview.analyze(sample_frames, sample_roles, sample_index)
        assert "10" in sec.summary  # 10 frames
        assert sec.title == "1. 개요"

    def test_protocol_distribution(self, sample_frames, sample_roles, sample_index):
        sec = overview.analyze(sample_frames, sample_roles, sample_index)
        assert any("802.11" in line for line in sec.lines)


class TestRetryMcs:
    def test_with_retry(self):
        frames = [
            make_frame(number=i, epoch=1000+i, mcs="7", retry=(i % 3 == 0))
            for i in range(20)
        ]
        f, r, idx = _build(frames)
        sec = retry_mcs.analyze(f, r, idx)
        assert sec.title is not None
        assert len(sec.lines) > 0

    def test_no_retry(self):
        frames = [make_frame(number=i, epoch=1000+i, retry=False) for i in range(5)]
        f, r, idx = _build(frames)
        sec = retry_mcs.analyze(f, r, idx)
        assert sec.lines is not None

    def test_multiple_mcs_values(self):
        frames = [make_frame(number=i, epoch=1000+i, mcs=str(i % 4), retry=(i < 3))
                  for i in range(15)]
        f, r, idx = _build(frames)
        sec = retry_mcs.analyze(f, r, idx)
        assert sec.summary != ""


class TestRetryBurst:
    def test_burst_detection(self):
        # 연속 retry 프레임으로 burst 유도
        frames = [make_frame(number=i, epoch=1000+i*0.01, retry=True) for i in range(30)]
        frames += [make_frame(number=30+i, epoch=1002+i, retry=False) for i in range(5)]
        f, r, idx = _build(frames)
        sec = retry_burst.analyze(f, r, idx)
        assert len(sec.lines) > 0

    def test_no_burst(self):
        frames = [make_frame(number=i, epoch=1000+i, retry=False) for i in range(10)]
        f, r, idx = _build(frames)
        sec = retry_burst.analyze(f, r, idx)
        assert sec.lines is not None

    def test_mixed_retry(self):
        frames = [make_frame(number=i, epoch=1000+i*0.1, retry=(i % 5 == 0)) for i in range(50)]
        f, r, idx = _build(frames)
        sec = retry_burst.analyze(f, r, idx)
        assert sec.title is not None


class TestRoaming:
    def test_roaming_sequence(self):
        frames = [
            make_frame(number=1, epoch=1000, ta=STA1, ra=AP1, subtype="11"),  # Auth
            make_frame(number=2, epoch=1000.05, ta=STA1, ra=AP1, subtype="0"),  # AssocReq
        ]
        f, r, idx = _build(frames)
        sec = roaming.analyze(f, r, idx)
        assert "로밍" in sec.title.lower() or "로밍" in sec.title

    def test_no_roaming(self):
        frames = [make_frame(number=i, epoch=1000+i, subtype="40") for i in range(5)]
        f, r, idx = _build(frames)
        sec = roaming.analyze(f, r, idx)
        assert sec.lines is not None

    def test_slow_roaming(self):
        frames = [
            make_frame(number=1, epoch=1000, ta=STA1, ra=AP1, subtype="11"),
            make_frame(number=2, epoch=1000.5, ta=STA1, ra=AP1, subtype="2"),  # ReassocReq >100ms
        ]
        f, r, idx = _build(frames)
        sec = roaming.analyze(f, r, idx)
        assert len(sec.lines) > 0


class TestPingRtt:
    def test_ping_matching(self):
        frames = [
            make_frame(number=1, epoch=1000, icmp_type="8", ip_src="10.0.0.1", ip_dst="10.0.0.2",
                       ta=STA1, ra=AP1, icmp_seq="1"),
            make_frame(number=2, epoch=1000.01, icmp_type="0", ip_src="10.0.0.2", ip_dst="10.0.0.1",
                       ta=AP1, ra=STA1, icmp_seq="1"),
        ]
        f, r, idx = _build(frames)
        sec = ping_rtt.analyze(f, r, idx)
        assert len(sec.lines) > 0

    def test_no_icmp(self):
        frames = [make_frame(number=i, epoch=1000+i) for i in range(5)]
        f, r, idx = _build(frames)
        sec = ping_rtt.analyze(f, r, idx)
        assert sec.lines is not None

    def test_multiple_pings(self):
        frames = []
        for i in range(5):
            frames.append(make_frame(number=i*2+1, epoch=1000+i, icmp_type="8",
                          ip_src="10.0.0.1", ip_dst="10.0.0.2", ta=STA1, ra=AP1, icmp_seq=str(i)))
            frames.append(make_frame(number=i*2+2, epoch=1000+i+0.005, icmp_type="0",
                          ip_src="10.0.0.2", ip_dst="10.0.0.1", ta=AP1, ra=STA1, icmp_seq=str(i)))
        f, r, idx = _build(frames)
        sec = ping_rtt.analyze(f, r, idx)
        assert len(sec.lines) > 0


class TestControlTraffic:
    def test_with_arp(self):
        frames = [
            make_frame(number=1, epoch=1000, arp_opcode="1"),
            make_frame(number=2, epoch=1001, icmp_type="8"),
            make_frame(number=3, epoch=1002, tcp_len="0", tcp_flags="0x10"),
            make_frame(number=4, epoch=1003),
        ]
        f, r, idx = _build(frames)
        sec = control_traffic.analyze(f, r, idx)
        assert len(sec.lines) > 0

    def test_empty(self):
        sec = control_traffic.analyze([], {}, None)
        assert sec.lines is not None


class TestSignalQuality:
    def test_with_rssi(self):
        frames = [
            make_frame(number=i, epoch=1000+i, ta=STA1, ra=AP1, rssi=f"{-50-i}")
            for i in range(10)
        ]
        f, r, idx = _build(frames)
        sec = signal_quality.analyze(f, r, idx)
        assert len(sec.lines) > 0

    def test_no_rssi(self):
        frames = [make_frame(number=i, epoch=1000+i, rssi="") for i in range(5)]
        f, r, idx = _build(frames)
        sec = signal_quality.analyze(f, r, idx)
        assert sec.lines is not None


class TestPerSecond:
    def test_timeline(self):
        frames = [make_frame(number=i, epoch=1000+i*0.5) for i in range(10)]
        f, r, idx = _build(frames)
        sec = per_second.analyze(f, r, idx)
        assert len(sec.lines) > 0

    def test_empty(self):
        sec = per_second.analyze([], {}, None)
        assert sec.lines is not None


class TestRoamingImpact:
    def test_with_roaming(self):
        frames = [
            make_frame(number=1, epoch=1000, ta=STA1, ra=AP1, subtype="40", retry=True),
            make_frame(number=2, epoch=1001, ta=STA1, ra=AP1, subtype="11"),  # Auth
            make_frame(number=3, epoch=1001.1, ta=STA1, ra=AP1, subtype="0"),  # Assoc
            make_frame(number=4, epoch=1002, ta=STA1, ra=AP1, subtype="40"),
        ]
        f, r, idx = _build(frames)
        sec = roaming_impact.analyze(f, r, idx)
        assert sec.lines is not None

    def test_no_roaming(self):
        frames = [make_frame(number=i, epoch=1000+i) for i in range(5)]
        f, r, idx = _build(frames)
        sec = roaming_impact.analyze(f, r, idx)
        assert sec.lines is not None


class TestPingLoss:
    def test_with_loss(self):
        frames = [
            make_frame(number=1, epoch=1000, icmp_type="8", ip_src="10.0.0.1", ip_dst="10.0.0.2",
                       ta=STA1, ra=AP1, icmp_seq="1"),
            # No reply → loss
        ]
        f, r, idx = _build(frames)
        sec = ping_loss.analyze(f, r, idx)
        assert sec.lines is not None

    def test_no_icmp(self):
        frames = [make_frame(number=i, epoch=1000+i) for i in range(5)]
        f, r, idx = _build(frames)
        sec = ping_loss.analyze(f, r, idx)
        assert sec.lines is not None


class TestDiagnosis:
    def test_with_stas(self):
        frames = [
            make_frame(number=i, epoch=1000+i, ta=STA1, ra=AP1, retry=(i % 2 == 0))
            for i in range(20)
        ]
        f, r, idx = _build(frames)
        sec = diagnosis.analyze(f, r, idx)
        assert "진단" in sec.title
        assert len(sec.lines) > 0

    def test_no_stas(self):
        roles = {AP1: {"role": "AP", "name": "AP1", "count": 10}}
        frames = [make_frame(number=1, epoch=1000, ta=AP1, ra="ff:ff:ff:ff:ff:ff")]
        idx = FrameIndex(frames, roles)
        sec = diagnosis.analyze(frames, roles, idx)
        assert "없음" in sec.summary

    def test_warning_generation(self):
        # 높은 retry → WARNING 생성
        frames = [
            make_frame(number=i, epoch=1000+i, ta=STA1, ra=AP1, retry=True)
            for i in range(50)
        ]
        f, r, idx = _build(frames)
        sec = diagnosis.analyze(f, r, idx)
        assert any("WARNING" in line for line in sec.lines)


class TestCompareAp:
    def test_single_ap(self):
        roles = {AP1: {"role": "AP", "name": "AP1", "count": 10}}
        frames = [make_frame(number=1, epoch=1000)]
        idx = FrameIndex(frames, roles)
        sec = compare_ap_analyze(frames, roles, idx)
        assert "불가" in sec.summary

    def test_two_aps(self):
        ap2 = "aa:bb:cc:00:00:99"
        roles = dict(SAMPLE_ROLES)
        roles[ap2] = {"role": "AP", "name": "AP2(0099)", "count": 50}
        frames = [
            make_frame(number=1, epoch=1000, ta=STA1, ra=AP1, bssid=AP1),
            make_frame(number=2, epoch=1001, ta=AP1, ra=STA1, bssid=AP1),
            make_frame(number=3, epoch=1002, ta=STA1, ra=ap2, bssid=ap2),
            make_frame(number=4, epoch=1003, ta=ap2, ra=STA1, bssid=ap2),
        ]
        idx = FrameIndex(frames, roles)
        sec = compare_ap_analyze(frames, roles, idx)
        assert "AP" in sec.summary
