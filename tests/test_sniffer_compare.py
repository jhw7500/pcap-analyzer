"""_structured_sniffer_compare — 스니퍼별 초당 시계열 + 커버리지 스키마 (스펙 §5)."""
from analyzer.core.merge import MergeResult, _MERGEABLE_DECODED_FIELDS
from analyzer.web.structured import _structured_sniffer_compare
from tests.conftest import make_frame


def _mr(per_source, stats=None):
    return MergeResult(
        frames=[], per_source=per_source, offsets={},
        stats=stats or {"window_ms": 50, "duplicates": 0, "kept": 0,
                        "coverage": {"both": 0, "only": {}}},
        warnings=[],
    )


def test_two_sources_series_and_coverage():
    w1 = [
        make_frame(number=1, epoch=1000.2, retry=False, rssi="-60"),
        make_frame(number=2, epoch=1000.7, retry=True, rssi="-40"),
        make_frame(number=3, epoch=1002.1, retry=False, rssi=""),
    ]
    w2 = [make_frame(number=1, epoch=1001.5, retry=False, rssi="-70,-72")]
    stats = {"window_ms": 50, "duplicates": 0, "kept": 4,
             "coverage": {"both": 1, "only": {"w1": 2, "w2": 1}}}
    sc = _structured_sniffer_compare(_mr({"w1": w1, "w2": w2}, stats))

    assert sc["tags"] == ["w1", "w2"]
    # w1: 1000초(2건, retry 1, 평균 (-60 + -40)/2 = -50.0) / 1001초(갭 → 0건)
    #     / 1002초(1건, rssi 없음 → None)
    assert sc["series"]["w1"] == [
        {"epoch": 1000, "frames": 2, "retry": 1, "rssi_avg": -50.0},
        {"epoch": 1001, "frames": 0, "retry": 0, "rssi_avg": None},
        {"epoch": 1002, "frames": 1, "retry": 0, "rssi_avg": None},
    ]
    # w2: rssi_first는 첫 안테나 값(-70)만 취한다
    assert sc["series"]["w2"] == [
        {"epoch": 1001, "frames": 1, "retry": 0, "rssi_avg": -70.0},
    ]
    assert sc["coverage"] == {"both": 1, "only": {"w1": 2, "w2": 1},
                              "groups_total": 4}


def test_single_source_returns_none():
    w1 = [make_frame(number=1, epoch=1000.0)]
    assert _structured_sniffer_compare(_mr({"w1": w1})) is None


def test_consumed_fields_are_not_borrowable():
    """per_source 소비 필드(epoch/retry/rssi)가 대표 필드 차용
    (_merge_decoded_fields) 대상에 편입되면 이 시계열은 소스별 순수 관측이
    아니게 된다 — 계약 위반을 여기서 즉시 잡는다 (MergeResult 주석의
    '차용 오염' 지뢰, PR #23 리뷰 4라운드 재리뷰)."""
    assert not {"epoch", "retry", "rssi"} & set(_MERGEABLE_DECODED_FIELDS)
