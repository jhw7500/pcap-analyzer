"""Conclusion 데이터 모델 단위 테스트 — 근거(frame_refs) + time_window 강제."""
import pytest

from analyzer.core.modules.diagnosis import Conclusion, TimeWindow


def _window() -> TimeWindow:
    return TimeWindow(start_epoch=1000.0, end_epoch=1005.0)


class TestTimeWindow:
    def test_valid_window(self):
        tw = TimeWindow(start_epoch=1000.0, end_epoch=1005.0)
        assert tw.start_epoch == 1000.0
        assert tw.end_epoch == 1005.0

    def test_reversed_window_rejected(self):
        with pytest.raises(ValueError):
            TimeWindow(start_epoch=1005.0, end_epoch=1000.0)


class TestConclusionFrameRefs:
    def test_empty_frame_refs_rejected(self):
        """근거(frame_refs)가 없는 결론은 생성 자체가 거부된다."""
        with pytest.raises(ValueError):
            Conclusion(
                level="WARNING",
                message="Ping Loss 발생",
                frame_refs=[],
                time_window=_window(),
            )

    def test_default_frame_refs_rejected(self):
        """frame_refs를 생략(기본값 빈 리스트)해도 거부된다."""
        with pytest.raises(ValueError):
            Conclusion(
                level="INFO",
                message="정상",
                time_window=_window(),
            )

    def test_single_frame_ref_accepted(self):
        """frame_ref가 1개 이상이면 결론 생성이 허용된다."""
        c = Conclusion(
            level="WARNING",
            message="높은 Retry Rate",
            frame_refs=[42],
            time_window=_window(),
        )
        assert c.frame_refs == [42]
        assert c.time_window.start_epoch == 1000.0
        assert c.level == "WARNING"

    def test_multiple_frame_refs_accepted(self):
        c = Conclusion(
            level="INFO",
            message="잦은 로밍",
            frame_refs=[1, 2, 3],
            time_window=_window(),
        )
        assert len(c.frame_refs) == 3


class TestConclusionTimeWindow:
    def test_missing_time_window_rejected(self):
        with pytest.raises(ValueError):
            Conclusion(
                level="WARNING",
                message="근거는 있으나 시간 구간 누락",
                frame_refs=[7],
                time_window=None,
            )


class TestConclusionLevel:
    def test_invalid_level_rejected(self):
        with pytest.raises(ValueError):
            Conclusion(
                level="CRITICAL",
                message="잘못된 레벨",
                frame_refs=[1],
                time_window=_window(),
            )
