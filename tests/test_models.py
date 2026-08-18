"""Frame 데이터클래스 프로퍼티 테스트."""
from analyzer.core.models import AnalysisSection
from tests.conftest import make_frame as _make_frame


class TestFrameProperties:
    def test_subtype_name_known(self):
        f = _make_frame(subtype="8")
        assert f.subtype_name == "Beacon"

    def test_subtype_name_unknown(self):
        f = _make_frame(subtype="99")
        assert "99" in f.subtype_name

    def test_is_data(self):
        assert _make_frame(subtype="40").is_data
        assert not _make_frame(subtype="8").is_data

    def test_is_mgmt(self):
        assert _make_frame(subtype="8").is_mgmt
        assert not _make_frame(subtype="40").is_mgmt

    def test_is_ctrl(self):
        assert _make_frame(subtype="29").is_ctrl  # ACK
        assert not _make_frame(subtype="40").is_ctrl

    def test_frame_type(self):
        assert _make_frame(subtype="8").frame_type == "Management"
        assert _make_frame(subtype="29").frame_type == "Control"
        assert _make_frame(subtype="40").frame_type == "Data"
        assert _make_frame(subtype="99").frame_type == "Other"

    def test_is_roaming_related(self):
        assert _make_frame(subtype="11").is_roaming_related  # Auth
        assert _make_frame(protocol="EAPOL").is_roaming_related
        assert not _make_frame(subtype="40").is_roaming_related

    def test_is_icmp(self):
        assert _make_frame(icmp_type="8").is_icmp_request
        assert _make_frame(icmp_type="0").is_icmp_reply
        assert not _make_frame(icmp_type="").is_icmp_request

    def test_is_arp(self):
        assert _make_frame(arp_opcode="1").is_arp
        assert not _make_frame(arp_opcode="").is_arp

    def test_is_pure_tcp_ack(self):
        assert _make_frame(tcp_len="0", tcp_flags="0x0010").is_pure_tcp_ack
        assert not _make_frame(tcp_len="100", tcp_flags="0x0010").is_pure_tcp_ack

    def test_rssi_first(self):
        assert _make_frame(rssi="-60,-62").rssi_first == -60
        assert _make_frame(rssi="-75").rssi_first == -75
        assert _make_frame(rssi="").rssi_first is None
        assert _make_frame(rssi="bad").rssi_first is None

    def test_mcs_int(self):
        assert _make_frame(mcs="7").mcs_int == 7
        assert _make_frame(mcs="11,9").mcs_int == 11
        assert _make_frame(mcs="").mcs_int is None

    def test_nss_int_ht_derived_from_mcs(self):
        """11n은 NSS 필드가 없어 MCS 인덱스에서 파생한다 (8개 단위)."""
        assert _make_frame(mcs="0", mcs_phy="HT").nss_int == 1
        assert _make_frame(mcs="7", mcs_phy="HT").nss_int == 1
        assert _make_frame(mcs="8", mcs_phy="HT").nss_int == 2
        assert _make_frame(mcs="15", mcs_phy="HT").nss_int == 2
        assert _make_frame(mcs="23", mcs_phy="HT").nss_int == 3
        assert _make_frame(mcs="31", mcs_phy="HT").nss_int == 4
        # MCS32는 HT duplicate(1SS), MCS33+는 unequal modulation이라 규칙 밖.
        assert _make_frame(mcs="32", mcs_phy="HT").nss_int == 1
        assert _make_frame(mcs="33", mcs_phy="HT").nss_int is None
        assert _make_frame(mcs="", mcs_phy="HT").nss_int is None
        # HT는 nss 필드가 채워져 있어도 MCS 파생이 우선 — 필드 자체가 없는 PHY다.
        assert _make_frame(mcs="8", mcs_phy="HT", nss="1").nss_int == 2

    def test_nss_int_from_capture_field(self):
        """VHT/EHT는 10진, HE(radiotap)는 hex로 온다."""
        assert _make_frame(mcs="5", mcs_phy="VHT", nss="2").nss_int == 2
        assert _make_frame(mcs="7", mcs_phy="HE", nss="0x0002").nss_int == 2
        assert _make_frame(mcs="7", mcs_phy="HE", nss="0x0001").nss_int == 1
        assert _make_frame(mcs="3", mcs_phy="EHT", nss="4").nss_int == 4
        # 다중 값은 첫 번째 (rssi/mcs와 동일 규칙)
        assert _make_frame(mcs="5", mcs_phy="VHT", nss="2,1").nss_int == 2

    def test_nss_int_unknown_cases(self):
        """미상은 None — 0(HE NSTS의 unknown)이나 파싱 실패를 1SS로 단정하지 않는다."""
        assert _make_frame(mcs="5", mcs_phy="VHT", nss="").nss_int is None
        assert _make_frame(mcs="7", mcs_phy="HE", nss="0x0000").nss_int is None
        assert _make_frame(mcs="5", mcs_phy="VHT", nss="bad").nss_int is None
        assert _make_frame(mcs="5", mcs_phy="VHT", nss="  ").nss_int is None
        # Legacy는 NSS 개념 자체가 없다
        assert _make_frame(mcs="", mcs_phy="Legacy", data_rate="6").nss_int is None

    def test_time_short(self):
        f = _make_frame(timestamp="Jan  1, 2026 12:34:56.789000")
        assert "12:34:56" in f.time_short

    def test_is_control_traffic(self):
        assert _make_frame(arp_opcode="1").is_control_traffic
        assert _make_frame(icmp_type="8").is_control_traffic
        assert _make_frame(tcp_len="0", tcp_flags="0x10").is_control_traffic


class TestAnalysisSection:
    def test_defaults(self):
        s = AnalysisSection(title="Test", lines=["line1"])
        assert s.title == "Test"
        assert s.summary == ""
        assert len(s.lines) == 1


class TestFrameNewFields:
    def test_frame_source_and_tsf_defaults(self):
        """신규 필드는 기본값이 있어 기존 생성 코드 무영향."""
        f = _make_frame()
        assert f.source == "" and f.tsf == ""
