"""merge.estimate_offset — 비콘 TSF 교차 매칭 오프셋 추정."""
from collections import OrderedDict

import pytest

from analyzer.core.merge import estimate_offset, merge_captures, _tsf_table
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


def test_tsf_table_excludes_ambiguous_duplicate_key():
    """같은 캡처 안에서 (bssid, tsf)가 서로 다른 epoch로 두 번 등장하면 어느
    쪽이 진짜인지 알 수 없으므로 테이블에서 완전히 제외해야 한다 — 마지막
    값으로 덮어쓰면(수정 전) 잘못된 epoch가 매칭에 섞인다(PR #23 리뷰
    2라운드 Finding E-1)."""
    frames = [
        make_frame(number=1, epoch=1000.0, subtype="8", ta=AP, bssid=AP, tsf="999999"),
        make_frame(number=2, epoch=1050.0, subtype="8", ta=AP, bssid=AP, tsf="999999"),  # 같은 키, 다른 epoch(모호)
        make_frame(number=3, epoch=1001.0, subtype="8", ta=AP, bssid=AP, tsf="111111"),  # 정상 단독 키
    ]
    table = _tsf_table(frames)
    assert (AP, 999999) not in table
    assert table[(AP, 111111)] == 1001.0


def test_merge_captures_prefers_alignment_sources_for_offset():
    """alignment_sources가 주어지면 본 sources(content_*)에 비콘이 하나도
    없어도 그 정렬 증거로 TSF 오프셋을 추정해야 한다 — 내용 필터로 본
    프레임에서 비콘이 사라진 상황을 재현한다(PR #23 리뷰 2라운드 Finding A)."""
    align_w1 = _beacons(1000.0, 100_000, 12, "w1")
    align_w2 = _beacons(998.0, 100_000, 12, "w2")  # +2.0s

    content_w1 = [make_frame(number=1, epoch=1001.0, seq="200", subtype="40", source="w1")]
    content_w2 = [make_frame(number=1, epoch=999.005, seq="200", subtype="40", source="w2")]

    mr = merge_captures(
        OrderedDict([("w1", content_w1), ("w2", content_w2)]),
        alignment_sources=OrderedDict([("w1", align_w1), ("w2", align_w2)]),
    )
    assert mr.offsets["w2"].method == "tsf"
    assert mr.offsets["w2"].pairs == 12
    assert mr.offsets["w2"].offset_sec == pytest.approx(2.0, abs=0.001)
    # 본 sources(content_w2)에도 보정이 적용돼야 한다.
    assert content_w2[0].epoch == pytest.approx(1001.005, abs=0.001)


def test_merge_captures_reference_tag_dropped_from_sources_still_offsets_survivors():
    """reference_tag가 sources에 없어도(내용 필터로 0건 제외됨) alignment_sources에
    있으면, 생존한 소스 전부에 정렬 증거 기준 오프셋이 적용돼야 한다 —
    기준이 사라졌다고 보정까지 포기하면 미보정 시계가 그대로 남는다
    (PR #23 리뷰 3라운드 Finding A)."""
    align_w1 = _beacons(1000.0, 100_000, 12, "w1")
    align_w2 = _beacons(998.0, 100_000, 12, "w2")  # +2.0s

    content_w2 = [make_frame(number=1, epoch=999.0, seq="300", subtype="40", source="w2")]

    mr = merge_captures(
        OrderedDict([("w2", content_w2)]),  # w1 자체가 sources에 없음(0건 제외)
        alignment_sources=OrderedDict([("w1", align_w1), ("w2", align_w2)]),
        reference_tag="w1",
    )
    assert mr.offsets["w2"].method == "tsf"
    assert mr.offsets["w2"].pairs == 12
    assert content_w2[0].epoch == pytest.approx(1001.0, abs=0.001)
    assert mr.frames[0].epoch == pytest.approx(1001.0, abs=0.001)


def test_merge_captures_falls_back_to_main_frames_when_alignment_insufficient():
    """정렬 증거로도 TSF 매칭이 부족하면(극단적으로 비콘 자체가 적은 캡처)
    본 sources 프레임 기준으로 2차 시도(seq 폴백 포함)한다."""
    align_w1 = _beacons(1000.0, 100_000, 3, "w1")  # 10쌍 미만 — tsf 실패
    align_w2 = _beacons(998.0, 100_000, 3, "w2")

    content_w1 = [make_frame(number=i + 1, epoch=1000.0 + i, seq=str(100 + i),
                             subtype="40", source="w1") for i in range(10)]
    content_w2 = [make_frame(number=i + 1, epoch=999.7 + i, seq=str(100 + i),
                             subtype="40", source="w2") for i in range(10)]

    mr = merge_captures(
        OrderedDict([("w1", content_w1), ("w2", content_w2)]),
        alignment_sources=OrderedDict([("w1", align_w1), ("w2", align_w2)]),
    )
    assert mr.offsets["w2"].method == "seq-fallback"
    assert mr.offsets["w2"].offset_sec == pytest.approx(0.3, abs=0.001)
