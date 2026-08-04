"""merge.estimate_offset — 비콘 TSF 교차 매칭 오프셋 추정."""
import pytest

from analyzer.core.merge import estimate_offset
from tests.conftest import make_frame

AP = "00:80:4c:e1:09:cb"


def _beacons(epoch0, tsf0, n, source):
    """102.4ms 간격 비콘 n개 — 실캡처(TEST1)와 동일한 TSF 보폭."""
    return [
        make_frame(number=i + 1, epoch=epoch0 + i * 0.1024, subtype="8",
                   ta=AP, bssid=AP, tsf=str(tsf0 + i * 102400), source=source)
        for i in range(n)
    ]


def test_tsf_offset_recovers_large_raw_offset():
    """실측 시나리오: DFK가 +183.51초 앞선 원시 시계 — TSF 매칭은 창 없이 복원한다."""
    ref = _beacons(1000.0, 9_893_376_059, 30, "w1")
    other = _beacons(1000.0 - 183.51, 9_893_376_059, 30, "w2")  # 같은 비콘, 시계만 뒤짐
    r = estimate_offset(ref, other)
    assert r.method == "tsf"
    assert r.pairs == 30
    assert r.offset_sec == pytest.approx(183.51, abs=0.001)
    assert r.spread_sec < 0.01


def test_tsf_offset_ignores_unmatched_bssid():
    ref = _beacons(1000.0, 100_000, 20, "w1")
    other = _beacons(998.0, 100_000, 20, "w2")
    noise = [make_frame(number=99, epoch=1500.0, subtype="8", ta="aa:aa:aa:aa:aa:01",
                        bssid="aa:aa:aa:aa:aa:01", tsf="100000", source="w2")]
    r = estimate_offset(ref, other + noise)
    assert r.pairs == 20 and r.offset_sec == pytest.approx(2.0, abs=0.001)


def test_insufficient_tsf_pairs_falls_back_to_seq_match():
    """TSF 쌍 < 10 → (ta, seq, subtype) 매칭 폴백 (±5초 창 — 사전 보정 전제)."""
    ref = [make_frame(number=i + 1, epoch=1000.0 + i, subtype="40", seq=str(100 + i),
                      source="w1") for i in range(20)]
    other = [make_frame(number=i + 1, epoch=999.7 + i, subtype="40", seq=str(100 + i),
                        source="w2") for i in range(20)]
    r = estimate_offset(ref, other)
    assert r.method == "seq-fallback"
    assert r.offset_sec == pytest.approx(0.3, abs=0.001)


def test_no_match_returns_zero_with_warning():
    ref = [make_frame(number=1, epoch=1000.0, subtype="40", seq="1", source="w1")]
    other = [make_frame(number=1, epoch=5000.0, subtype="40", seq="999", source="w2")]
    r = estimate_offset(ref, other)
    assert r.method == "none" and r.offset_sec == 0.0
    assert any("오프셋" in w for w in r.warnings)


def test_tsf_non_numeric_skipped():
    ref = _beacons(1000.0, 100_000, 12, "w1")
    broken = _beacons(1000.0, 100_000, 12, "w2")
    broken[0].tsf = "0x깨진값"
    r = estimate_offset(ref, broken)
    assert r.method == "tsf" and r.pairs == 11


def test_seq_fallback_nearest_match_not_first_come():
    """같은 (ta, seq, subtype)가 창 안에 두 번 등장(seq 랩 모사) — 최선착이 아니라
    최근접으로 매칭돼야 한다. 최선착이면 먼 쪽(첫 등장)에 걸려 +0.3s 실제 오프셋이
    음수 수 초 중앙값으로 붕괴한다(PR #23 리뷰 Finding C)."""
    ref, other = [], []
    for i in range(10):
        base = 1000.0 + i * 10
        ta, seq = f"ta{i}", str(100 + i)
        ref.append(make_frame(number=i * 2 + 1, epoch=base, subtype="40",
                              ta=ta, seq=seq, source="w1"))          # 먼 등장(랩 이전)
        ref.append(make_frame(number=i * 2 + 2, epoch=base + 3.0, subtype="40",
                              ta=ta, seq=seq, source="w1"))          # 가까운(진짜) 등장
        other.append(make_frame(number=i + 1, epoch=base + 2.7, subtype="40",
                                ta=ta, seq=seq, source="w2"))        # 진짜 오프셋 +0.3s
    r = estimate_offset(ref, other)
    assert r.method == "seq-fallback"
    assert r.pairs == 10
    assert r.offset_sec == pytest.approx(0.3, abs=0.001)


def test_seq_fallback_ref_occurrence_not_reused():
    """선택된 ref 발생(occurrence)은 소진돼야 한다 — 같은 ref epoch이 여러 other
    프레임에 재사용되면 표본이 중복 계상된다(PR #23 리뷰 Finding C)."""
    ref, other = [], []
    for i in range(9):
        base = 1000.0 + i * 10
        ta, seq = f"ta{i}", str(200 + i)
        ref.append(make_frame(number=i + 1, epoch=base, subtype="40",
                              ta=ta, seq=seq, source="w1"))
        other.append(make_frame(number=i + 1, epoch=base - 0.3, subtype="40",
                                ta=ta, seq=seq, source="w2"))

    # 단일 ref 발생에 두 개의 other 후보 — 가까운 쪽만 매칭되고 먼 쪽은 재사용
    # 없이 미매칭이어야 한다.
    dup_ta, dup_seq = "dup", "999"
    ref.append(make_frame(number=100, epoch=2000.0, subtype="40",
                          ta=dup_ta, seq=dup_seq, source="w1"))
    other.append(make_frame(number=100, epoch=1999.97, subtype="40",
                            ta=dup_ta, seq=dup_seq, source="w2"))  # diff 0.03(근접)
    other.append(make_frame(number=101, epoch=1999.70, subtype="40",
                            ta=dup_ta, seq=dup_seq, source="w2"))  # diff 0.30(먼 쪽)

    r = estimate_offset(ref, other)
    assert r.method == "seq-fallback"
    assert r.pairs == 10  # 9(기본) + 1(근접만) — 먼 쪽은 재사용 금지로 미매칭
