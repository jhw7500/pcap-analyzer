"""FrameIndex 테스트."""
from analyzer.core.indexer import FrameIndex
from tests.conftest import make_frame as _frame, AP1 as AP, STA1, STA2, SAMPLE_ROLES as ROLES


def _sample_frames():
    return [
        _frame(number=1, epoch=1000.0, ta=STA1, ra=AP, bssid=AP),
        _frame(number=2, epoch=1001.0, ta=AP, ra=STA1, bssid=AP),
        _frame(number=3, epoch=1002.0, ta=STA2, ra=AP, bssid=AP),
        _frame(number=4, epoch=1003.0, ta=AP, ra=STA2, bssid=AP),
        _frame(number=5, epoch=1004.0, ta=STA1, ra=AP, bssid=AP, subtype="11"),  # Auth (roaming)
    ]


class TestFrameIndex:
    def test_by_ta(self):
        idx = FrameIndex(_sample_frames(), ROLES)
        assert len(idx.by_ta[STA1]) == 2  # frames 1 and 5
        assert len(idx.by_ta[AP]) == 2  # frames 2 and 4

    def test_by_ra(self):
        idx = FrameIndex(_sample_frames(), ROLES)
        assert len(idx.by_ra[AP]) == 3  # frames 1, 3, 5

    def test_by_sta(self):
        idx = FrameIndex(_sample_frames(), ROLES)
        # STA1: ta in frames 1,5 + ra in frame 2
        assert len(idx.by_sta[STA1]) == 3

    def test_roaming_frames(self):
        idx = FrameIndex(_sample_frames(), ROLES)
        assert len(idx.roaming_frames) == 1  # frame 5 (Auth)

    def test_frames_in_window(self):
        idx = FrameIndex(_sample_frames(), ROLES)
        before, after = idx.frames_in_window(1002.0, before=1.5, after=1.5)
        # center=1002, before=1.5 → range [1000.5, 1002.0) → epoch 1001 only
        assert len(before) == 1
        # range [1002.0, 1003.5] → epoch 1002, 1003
        assert len(after) == 2

    def test_sta_frames_in_window(self):
        idx = FrameIndex(_sample_frames(), ROLES)
        before, after = idx.sta_frames_in_window(STA1, 1002.0, before=3.0, after=5.0)
        assert len(before) == 2  # STA1 frames at 1000, 1001
        assert len(after) == 1  # STA1 frame at 1004

    def test_nearest_roaming(self):
        idx = FrameIndex(_sample_frames(), ROLES)
        nearest = idx.nearest_roaming(1003.5)
        assert nearest is not None
        assert nearest.number == 5

    def test_nearest_roaming_none(self):
        frames = [_frame(number=1, epoch=1000.0, ta=STA1, ra=AP)]
        idx = FrameIndex(frames, ROLES)
        assert idx.nearest_roaming(1000.0) is None

    def test_empty_frames(self):
        idx = FrameIndex([], ROLES)
        assert len(idx.frames) == 0
        assert len(idx.roaming_frames) == 0
