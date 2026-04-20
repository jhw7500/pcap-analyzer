"""실제 tshark로 fixture pcap을 파싱해 회귀 검증한다.

tests/fixtures/sample_basic.pcap은 scapy로 합성된 deterministic pcap이다.
tshark가 설치된 환경에서만 실행되므로 @pytest.mark.tshark로 격리한다.
"""
from pathlib import Path

import pytest

from analyzer.core.extractor import extract_frames
from analyzer.core.detector import detect_roles
from analyzer.pipeline import run_analysis

pytestmark = pytest.mark.tshark

FIXTURE = Path(__file__).parent / "fixtures" / "sample_basic.pcap"


@pytest.fixture(scope="module")
def fixture_path():
    if not FIXTURE.exists():
        pytest.skip(f"fixture missing: {FIXTURE}")
    return str(FIXTURE)


class TestGoldenBasicPcap:
    def test_frame_count(self, fixture_path):
        frames = extract_frames(fixture_path)
        assert len(frames) == 10

    def test_subtype_distribution(self, fixture_path):
        frames = extract_frames(fixture_path)
        subtypes = [f.subtype_name for f in frames]
        assert subtypes.count("Beacon") == 2
        assert subtypes.count("Auth") == 2
        assert subtypes.count("AssocReq") == 1
        assert subtypes.count("AssocResp") == 1
        # Data 프레임 (ICMP carrier) 4개
        assert subtypes.count("Data") == 4

    def test_detect_roles_ap_and_sta(self, fixture_path):
        frames = extract_frames(fixture_path)
        roles = detect_roles(frames)
        ap_count = sum(1 for r in roles.values() if r["role"] == "AP")
        sta_count = sum(1 for r in roles.values() if r["role"] == "STA")
        assert ap_count == 1
        assert sta_count == 1
        # 예상 MAC
        assert "00:11:22:33:44:55" in roles
        assert roles["00:11:22:33:44:55"]["role"] == "AP"
        assert "aa:bb:cc:dd:ee:ff" in roles
        assert roles["aa:bb:cc:dd:ee:ff"]["role"] == "STA"

    def test_overview_structured(self, fixture_path):
        result = run_analysis(fixture_path)
        ov = result["structured"]["overview"]
        assert ov["total_frames"] == 10
        assert ov["retry_count"] == 0
        assert ov["retry_pct"] == 0.0
        assert ov["protocol_dist"].get("ICMP") == 4
        # 802.11 관리/제어 프레임 6개 (Beacon 2 + Auth 2 + Assoc 2)
        assert ov["protocol_dist"].get("802.11") == 6

    def test_ping_rtt_and_loss(self, fixture_path):
        result = run_analysis(fixture_path)
        stats = result["structured"]["ping"]["stats"]
        assert stats["count"] == 2
        assert stats["loss_count"] == 0
        assert stats["loss_pct"] == 0.0
        # fixture에 3ms 시차로 설정
        assert stats["avg"] == pytest.approx(3.0, abs=0.5)

    def test_roaming_auth_assoc_detected(self, fixture_path):
        result = run_analysis(fixture_path)
        roam = result["structured"]["roaming"]
        # Auth + AssocReq + AssocResp + (Auth response 추가) = 4 프레임
        assert roam["roaming_frame_count"] == 4
        # Auth→AssocReq 시퀀스 1건 감지
        assert len(roam["sequences"]) == 1
        seq = roam["sequences"][0]
        assert seq["sta"] == "aa:bb:cc:dd:ee:ff"
        assert seq["gap_ms"] == pytest.approx(50.0, abs=5.0)

    def test_device_stats_names(self, fixture_path):
        result = run_analysis(fixture_path)
        stats = result["structured"]["device_stats"]
        assert set(stats.keys()) == {"AP1(4455)", "STA1(eeff)"}
