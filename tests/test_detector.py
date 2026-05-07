"""AP/STA 역할 감지 테스트."""
from analyzer.core.detector import detect_roles, mac_name, _is_unicast
from tests.conftest import make_frame as _frame


class TestIsUnicast:
    def test_normal_mac(self):
        assert _is_unicast("aa:bb:cc:dd:ee:01")

    def test_broadcast(self):
        assert not _is_unicast("ff:ff:ff:ff:ff:ff")

    def test_multicast_33(self):
        assert not _is_unicast("33:33:00:00:00:01")

    def test_empty(self):
        assert not _is_unicast("")


class TestDetectRoles:
    def test_ap_from_beacon(self):
        ap_mac = "aa:bb:cc:dd:ee:01"
        sta_mac = "aa:bb:cc:dd:ee:02"
        frames = [
            # Beacon from AP
            _frame(subtype="8", ta=ap_mac, ra="ff:ff:ff:ff:ff:ff", bssid=ap_mac),
            # Data frames between AP and STA
            _frame(subtype="40", ta=sta_mac, ra=ap_mac, bssid=ap_mac),
            _frame(subtype="40", ta=ap_mac, ra=sta_mac, bssid=ap_mac),
            _frame(subtype="40", ta=sta_mac, ra=ap_mac, bssid=ap_mac),
            _frame(subtype="40", ta=ap_mac, ra=sta_mac, bssid=ap_mac),
            _frame(subtype="40", ta=sta_mac, ra=ap_mac, bssid=ap_mac),
        ]
        roles = detect_roles(frames)
        assert ap_mac in roles
        assert roles[ap_mac]["role"] == "AP"
        assert sta_mac in roles
        assert roles[sta_mac]["role"] == "STA"

    def test_empty_frames(self):
        roles = detect_roles([])
        assert roles == {}

    def test_sta_needs_minimum_frames(self):
        ap = "aa:bb:cc:dd:ee:01"
        sta = "aa:bb:cc:dd:ee:02"
        frames = [
            _frame(subtype="8", ta=ap, ra="ff:ff:ff:ff:ff:ff", bssid=ap),
            # Only 2 data frames — below threshold of 5
            _frame(subtype="40", ta=sta, ra=ap, bssid=ap),
            _frame(subtype="40", ta=ap, ra=sta, bssid=ap),
        ]
        roles = detect_roles(frames)
        assert sta not in roles  # below minimum count


class TestMacName:
    def test_known_role(self):
        roles = {"aa:bb:cc:dd:ee:01": {"role": "AP", "name": "AP1(ee01)", "count": 10}}
        assert mac_name("aa:bb:cc:dd:ee:01", roles) == "AP1(ee01)"

    def test_broadcast(self):
        assert mac_name("ff:ff:ff:ff:ff:ff", {}) == "BCAST"

    def test_unknown(self):
        result = mac_name("aa:bb:cc:dd:ee:99", {})
        assert "ee:99" in result

    def test_empty(self):
        assert mac_name("", {}) == "?"
