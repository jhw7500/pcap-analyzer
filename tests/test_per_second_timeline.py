"""_structured_per_second 방어 가드 — 손상 epoch·거대 span (백로그 ③, PR #24 공통 이슈)."""
from analyzer.web.structured import _structured_per_second
from tests.conftest import make_frame


def test_invalid_epochs_are_skipped():
    """None/NaN/Inf epoch 프레임은 집계에서 제외 — int() 변환 예외로 분석이 죽지 않는다."""
    frames = [
        make_frame(number=1, epoch=1000.2, retry=True),
        make_frame(number=2, epoch=None),
        make_frame(number=3, epoch=float("nan")),
        make_frame(number=4, epoch=float("inf")),
    ]
    tl = _structured_per_second(frames)["timeline"]
    assert [(p["epoch"], p["total"], p["retry"]) for p in tl] == [(1000, 1, 1)]


def test_all_invalid_epochs_returns_empty():
    frames = [make_frame(number=1, epoch=None)]
    assert _structured_per_second(frames) == {"timeline": []}


def test_huge_span_falls_back_to_sparse():
    """zero-fill 상한 초과 시 관측 초만 담는 희소 timeline — range() 팽창 차단."""
    frames = [
        make_frame(number=1, epoch=0.0),
        make_frame(number=2, epoch=100_000_000.0),
    ]
    tl = _structured_per_second(frames)["timeline"]
    assert [p["epoch"] for p in tl] == [0, 100_000_000]
    assert all(p["total"] == 1 for p in tl)
