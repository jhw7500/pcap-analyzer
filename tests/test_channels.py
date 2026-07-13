"""채널 주파수 변환 + overview.channels / roaming band_change 테스트."""
from analyzer.core.channels import (
    ap_channel_map,
    channel_info,
    freq_to_band,
    freq_to_channel,
    parse_freq,
)
from analyzer.web.structured import _structured_overview, _structured_roaming
from tests.conftest import AP1, STA1, SAMPLE_ROLES, make_frame

AP2 = "aa:bb:cc:00:00:09"


class TestFreqConversion:
    def test_24ghz(self):
        assert freq_to_channel(2412) == 1
        assert freq_to_channel(2437) == 6
        assert freq_to_channel(2472) == 13
        assert freq_to_channel(2484) == 14
        assert freq_to_band(2412) == "2.4GHz"

    def test_5ghz(self):
        assert freq_to_channel(5180) == 36
        assert freq_to_channel(5240) == 48
        assert freq_to_channel(5825) == 165
        assert freq_to_band(5240) == "5GHz"

    def test_6ghz(self):
        assert freq_to_channel(5955) == 1
        assert freq_to_channel(6115) == 33
        assert freq_to_channel(5935) == 2  # ch2 특례
        assert freq_to_band(5955) == "6GHz"

    def test_unknown(self):
        assert freq_to_channel(None) is None
        assert freq_to_channel(1000) is None
        assert freq_to_band(1000) is None

    def test_parse_freq(self):
        assert parse_freq("5240") == 5240
        assert parse_freq("5240,5240") == 5240  # multi-value → 첫 값
        assert parse_freq("") is None
        assert parse_freq("abc") is None

    def test_channel_info(self):
        info = channel_info("5240")
        assert info == {"freq": 5240, "channel": 48, "band": "5GHz"}
        assert channel_info("") is None


class TestApChannelMap:
    def test_beacon_based(self):
        frames = [
            make_frame(number=1, ta=AP1, subtype="8", channel_freq="5240"),
            make_frame(number=2, ta=AP1, subtype="8", channel_freq="5240"),
            # STA 프레임의 freq는 AP 채널 판정에 안 씀
            make_frame(number=3, ta=STA1, subtype="40", channel_freq="2412"),
        ]
        m = ap_channel_map(frames, SAMPLE_ROLES)
        assert m[AP1]["channel"] == 48
        assert m[AP1]["band"] == "5GHz"

    def test_no_beacon_ap_missing(self):
        frames = [make_frame(number=1, ta=AP1, subtype="40", channel_freq="5240")]
        assert ap_channel_map(frames, SAMPLE_ROLES) == {}


class TestOverviewChannels:
    def test_channels_key(self):
        frames = [
            make_frame(number=1, ta=AP1, subtype="8", channel_freq="5240"),
            make_frame(number=2, ta=STA1, subtype="40", channel_freq="5240"),
            make_frame(number=3, ta=STA1, subtype="40", channel_freq=""),
        ]
        ov = _structured_overview(frames, SAMPLE_ROLES, None)
        ch = ov["channels"]
        assert ch["by_channel"][0]["channel"] == 48
        assert ch["by_channel"][0]["band"] == "5GHz"
        assert ch["by_channel"][0]["frames"] == 2
        assert ch["ap_channels"][AP1]["channel"] == 48

    def test_no_freq_empty(self):
        frames = [make_frame(number=1, ta=STA1, subtype="40")]
        ov = _structured_overview(frames, SAMPLE_ROLES, None)
        assert ov["channels"]["by_channel"] == []
        assert ov["channels"]["ap_channels"] == {}


class TestRoamingBandChange:
    def _roles(self):
        roles = dict(SAMPLE_ROLES)
        roles[AP2] = {"role": "AP", "name": "AP2(0009)", "count": 10}
        return roles

    def test_band_change_true(self):
        roles = self._roles()
        frames = [
            make_frame(number=1, epoch=1000.0, ta=AP1, subtype="8", channel_freq="2437"),
            make_frame(number=2, epoch=1000.1, ta=AP2, subtype="8", channel_freq="5240"),
            make_frame(number=3, epoch=1001.0, ta=STA1, ra=AP2, subtype="11"),  # Auth
            make_frame(number=4, epoch=1001.05, ta=STA1, ra=AP2, subtype="2",
                       current_ap=AP1),  # ReassocReq (이전 AP1)
        ]
        seqs = _structured_roaming(frames, roles)["sequences"]
        assert len(seqs) == 1
        s = seqs[0]
        assert s["prev_ap_band"] == "2.4GHz"
        assert s["ap_band"] == "5GHz"
        assert s["band_change"] is True
        assert s["ap_channel"] == 48

    def test_band_change_none_when_unknown(self):
        roles = self._roles()
        # beacon 없음 → 채널 정보 없음 → band_change None
        frames = [
            make_frame(number=1, epoch=1001.0, ta=STA1, ra=AP2, subtype="11"),
            make_frame(number=2, epoch=1001.05, ta=STA1, ra=AP2, subtype="2",
                       current_ap=AP1),
        ]
        seqs = _structured_roaming(frames, roles)["sequences"]
        assert seqs[0]["band_change"] is None
        assert seqs[0]["ap_channel"] is None

    def test_band_change_false_same_band(self):
        roles = self._roles()
        frames = [
            make_frame(number=1, epoch=1000.0, ta=AP1, subtype="8", channel_freq="5180"),
            make_frame(number=2, epoch=1000.1, ta=AP2, subtype="8", channel_freq="5240"),
            make_frame(number=3, epoch=1001.0, ta=STA1, ra=AP2, subtype="11"),
            make_frame(number=4, epoch=1001.05, ta=STA1, ra=AP2, subtype="2",
                       current_ap=AP1),
        ]
        seqs = _structured_roaming(frames, roles)["sequences"]
        assert seqs[0]["band_change"] is False
