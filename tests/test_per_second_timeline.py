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


def test_retry_per_sec_skips_invalid_epochs():
    """_retry_per_sec — per_second와 동일 방어 (PR #27 리뷰: int(nan) ValueError)."""
    from analyzer.web.structured import _retry_per_sec
    frames = [
        make_frame(number=1, epoch=1000.0, retry=True),
        make_frame(number=2, epoch=float("nan")),
        make_frame(number=3, epoch=None),
    ]
    tl = _retry_per_sec(frames)
    assert [(p["epoch"], p["total"], p["retry"]) for p in tl] == [(1000, 1, 1)]


def test_device_bucket_stats_survive_invalid_and_huge_epochs():
    """_device_entry_stats 10초 버킷 — 손상 epoch에서 예외 없이 동작하고,
    span 상한 초과 시 버킷 통계를 생략한다(정직한 공백, PR #27 리뷰)."""
    from analyzer.web.structured import _device_entry_stats
    ok = [make_frame(number=1, epoch=1000.0), make_frame(number=2, epoch=1005.0)]
    bad = [make_frame(number=3, epoch=float("nan")), make_frame(number=4, epoch=None)]
    entry = _device_entry_stats(ok + bad, lambda f: True, "aa:bb", "STA")
    assert len(entry["per_bucket"]) == 1  # 1000~1009 버킷 1개, 손상 2건 제외
    assert entry["per_bucket"][0]["total"] == 2

    huge = [make_frame(number=1, epoch=0.0), make_frame(number=2, epoch=100_000_000.0)]
    entry2 = _device_entry_stats(huge, lambda f: True, "aa:bb", "STA")
    assert entry2["per_bucket"] == []  # range 팽창 차단 — 버킷 생략
