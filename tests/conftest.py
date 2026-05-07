"""공통 테스트 fixture."""
import pytest
from analyzer.core.models import Frame
from analyzer.core.indexer import FrameIndex


AP1 = "aa:bb:cc:00:00:01"
STA1 = "aa:bb:cc:00:00:02"
STA2 = "aa:bb:cc:00:00:03"

SAMPLE_ROLES = {
    AP1: {"role": "AP", "name": "AP1(0001)", "count": 100},
    STA1: {"role": "STA", "name": "STA1(0002)", "count": 50},
    STA2: {"role": "STA", "name": "STA2(0003)", "count": 30},
}


def make_frame(**kw) -> Frame:
    """테스트용 Frame 생성. kwargs로 필드 오버라이드."""
    defaults = dict(
        number=1, epoch=1000.0, timestamp="2026-01-01 00:00:00.000",
        retry=False, subtype="40", protocol="802.11", length=100,
        mcs="7", rssi="-60,-62", ta=STA1, ra=AP1,
        ip_src="", ip_dst="", icmp_type="", arp_opcode="",
        tcp_len="", tcp_flags="", seq="", icmp_seq="", bssid=AP1,
    )
    defaults.update(kw)
    return Frame(**defaults)


@pytest.fixture
def frame_factory():
    """Frame 팩토리 fixture."""
    return make_frame


@pytest.fixture
def sample_roles():
    """AP1 + STA1 + STA2 역할 딕셔너리."""
    return dict(SAMPLE_ROLES)


@pytest.fixture
def sample_frames():
    """기본 프레임 세트 (AP1, STA1, STA2 간 통신)."""
    return [
        make_frame(number=1, epoch=1000.0, ta=STA1, ra=AP1, subtype="40"),
        make_frame(number=2, epoch=1001.0, ta=AP1, ra=STA1, subtype="40"),
        make_frame(number=3, epoch=1002.0, ta=STA2, ra=AP1, subtype="40"),
        make_frame(number=4, epoch=1003.0, ta=AP1, ra=STA2, subtype="40"),
        make_frame(number=5, epoch=1004.0, ta=STA1, ra=AP1, subtype="40", retry=True),
        make_frame(number=6, epoch=1005.0, ta=STA1, ra=AP1, subtype="11"),  # Auth (roaming)
        make_frame(number=7, epoch=1006.0, ta=AP1, ra=STA1, subtype="1"),   # AssocResp
        make_frame(number=8, epoch=1007.0, ta=STA1, ra=AP1, subtype="40", rssi="-75"),
        make_frame(number=9, epoch=1008.0, ta=STA2, ra=AP1, subtype="40", mcs="3", rssi="-80"),
        make_frame(number=10, epoch=1009.0, ta=AP1, ra=STA1, subtype="40"),
    ]


@pytest.fixture
def sample_index(sample_frames, sample_roles):
    """FrameIndex 인스턴스."""
    return FrameIndex(sample_frames, sample_roles)
