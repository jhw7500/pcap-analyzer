"""merge.merge_captures — 캡처 간 dedup·재번호."""
from collections import OrderedDict

import pytest

from analyzer.core.merge import merge_captures
from tests.conftest import make_frame, AP1, STA1


def _src(tag, *frames):
    for f in frames:
        f.source = tag
    return list(frames)


def _pair(tag_frames):
    return OrderedDict(tag_frames)


def test_cross_source_duplicate_merged_once():
    """같은 (TA, seq, subtype, retry) 프레임이 두 캡처에 잡히면 1개로."""
    a = _src("w1",
             make_frame(number=1, epoch=1000.000, seq="100", subtype="40"),
             make_frame(number=2, epoch=1001.000, seq="101", subtype="40"))
    b = _src("w2",
             make_frame(number=1, epoch=1000.020, seq="100", subtype="40"),  # 중복(+20ms)
             make_frame(number=2, epoch=1002.000, seq="102", subtype="40"))  # w2 단독
    r = merge_captures(_pair([("w1", a), ("w2", b)]))
    assert len(r.frames) == 3
    assert r.stats["duplicates"] == 1
    assert r.stats["coverage"]["both"] == 1
    assert r.stats["coverage"]["only"] == {"w1": 1, "w2": 1}


def test_retry_bit_not_deduped():
    """재전송(retry=1)은 원본(retry=0)과 다른 프레임 — 병합 금지."""
    a = _src("w1", make_frame(number=1, epoch=1000.0, seq="100", retry=False))
    b = _src("w2", make_frame(number=1, epoch=1000.01, seq="100", retry=True))
    r = merge_captures(_pair([("w1", a), ("w2", b)]))
    assert len(r.frames) == 2 and r.stats["duplicates"] == 0


def test_outside_window_not_deduped():
    a = _src("w1", make_frame(number=1, epoch=1000.0, seq="100"))
    b = _src("w2", make_frame(number=1, epoch=1000.2, seq="100"))  # +200ms > 창
    r = merge_captures(_pair([("w1", a), ("w2", b)]))
    assert len(r.frames) == 2


def test_representative_prefers_decoded_copy():
    """실측 근거(DFK 암호화): 대표는 IP 필드가 채워진 쪽 — 먼저 잡힌 쪽이 아니라."""
    a = _src("w1", make_frame(number=1, epoch=1000.000, seq="100", ip_src=""))       # 암호화 사본(선행)
    b = _src("w2", make_frame(number=7, epoch=1000.030, seq="100", ip_src="10.0.0.1",
                              ip_dst="10.0.0.2", icmp_type="8"))                      # 복호화 사본
    r = merge_captures(_pair([("w1", a), ("w2", b)]))
    assert len(r.frames) == 1
    kept = r.frames[0]
    assert kept.ip_src == "10.0.0.1" and kept.source == "w2"


def test_representative_tie_earlier_epoch():
    a = _src("w1", make_frame(number=1, epoch=1000.000, seq="100", ip_src="10.0.0.1"))
    b = _src("w2", make_frame(number=1, epoch=1000.030, seq="100", ip_src="10.0.0.1"))
    r = merge_captures(_pair([("w1", a), ("w2", b)]))
    assert r.frames[0].source == "w1"


def test_offset_applied_before_dedup():
    """w2가 -2.0초 뒤진 시계여도 TSF 정렬 후 dedup이 잡는다."""
    beac_a = [make_frame(number=i + 10, epoch=1000.0 + i * 0.1024, subtype="8", ta=AP1,
                         bssid=AP1, tsf=str(500_000 + i * 102400)) for i in range(12)]
    beac_b = [make_frame(number=i + 10, epoch=998.0 + i * 0.1024, subtype="8", ta=AP1,
                         bssid=AP1, tsf=str(500_000 + i * 102400)) for i in range(12)]
    dat_a = make_frame(number=1, epoch=1001.000, seq="200", subtype="40")
    dat_b = make_frame(number=1, epoch=999.005, seq="200", subtype="40")  # 보정 후 +5ms
    a = _src("w1", *(beac_a + [dat_a]))
    b = _src("w2", *(beac_b + [dat_b]))
    r = merge_captures(_pair([("w1", a), ("w2", b)]))
    assert r.offsets["w2"].method == "tsf"
    assert r.offsets["w2"].offset_sec == pytest.approx(2.0, abs=0.001)
    # 비콘 12쌍 + 데이터 1쌍 전부 dedup → 13
    assert r.stats["duplicates"] == 13
    assert len(r.frames) == 13


def test_control_frame_approx_dedup():
    """seq 없는 제어 프레임(ACK 등)은 (subtype, ta/ra, 창) 근사 dedup."""
    a = _src("w1", make_frame(number=1, epoch=1000.000, seq="", subtype="29", ta="", ra=STA1))
    b = _src("w2", make_frame(number=1, epoch=1000.010, seq="", subtype="29", ta="", ra=STA1))
    r = merge_captures(_pair([("w1", a), ("w2", b)]))
    assert len(r.frames) == 1


def test_same_source_never_deduped():
    """같은 캡처(로테이션 연속 파일 포함) 안에서는 dedup하지 않는다."""
    a = _src("w1",
             make_frame(number=1, epoch=1000.000, seq="100"),
             make_frame(number=2, epoch=1000.010, seq="100"))  # 같은 소스 — 유지
    r = merge_captures(_pair([("w1", a)]))
    assert len(r.frames) == 2 and r.stats["duplicates"] == 0


def test_renumbered_sequential_and_sorted():
    a = _src("w1", make_frame(number=50, epoch=1002.0, seq="1"),
             make_frame(number=51, epoch=1000.0, seq="2"))
    b = _src("w2", make_frame(number=50, epoch=1001.0, seq="3"))
    r = merge_captures(_pair([("w1", a), ("w2", b)]))
    assert [f.number for f in r.frames] == [1, 2, 3]
    assert [f.epoch for f in r.frames] == sorted(f.epoch for f in r.frames)


def test_single_source_passthrough_numbers_untouched():
    """단일 소스는 재번호 없이 그대로 — 하위 호환."""
    a = _src("w1", make_frame(number=7, epoch=1000.0), make_frame(number=9, epoch=1001.0))
    r = merge_captures(_pair([("w1", a)]))
    assert [f.number for f in r.frames] == [7, 9]
    assert r.offsets == {} and r.stats["duplicates"] == 0


def test_control_frame_nearest_match_not_first_match():
    """근사 키(제어 프레임) dedup은 창 안 후보 중 '가장 가까운' 것과 매칭돼야 한다.

    A1(t=1000.000)·A2(t=1000.030)는 같은 근사 키(w1, 같은 소스라 서로 dedup 안 됨).
    B(t=1000.049)는 A2에 19ms 거리, A1에는 49ms 거리 — 둘 다 창(50ms) 안이지만
    A2가 더 가깝다. 삽입순(=A1 먼저) 스캔으로 첫 매치를 취하면 B가 더 먼 A1과
    잘못 병합된다 — '가장 가까운' 것을 선택해야 한다.
    """
    a1 = make_frame(number=1, epoch=1000.000, seq="", subtype="29", ta="", ra=STA1, ip_src="")
    a2 = make_frame(number=2, epoch=1000.030, seq="", subtype="29", ta="", ra=STA1, ip_src="")
    b1 = make_frame(number=1, epoch=1000.049, seq="", subtype="29", ta="", ra=STA1, ip_src="10.0.0.9")
    a = _src("w1", a1, a2)
    b = _src("w2", b1)
    r = merge_captures(_pair([("w1", a), ("w2", b)]))
    assert len(r.frames) == 2
    assert r.stats["duplicates"] == 1
    # B는 ip_src가 있어 병합되면 항상 대표가 된다 — 병합 안 된(단독) 쪽의 epoch로
    # 어느 A와 합쳐졌는지 판별: 올바른 최근접 매칭이면 A1(1000.000)이 단독으로 남는다.
    standalone = next(f for f in r.frames if f.ip_src == "")
    assert standalone.epoch == pytest.approx(1000.000)


def test_same_source_burst_bucket_bounded():
    """같은 소스·같은 근사 키가 창 안에서 밀집(서로 dedup 불가)해도 매칭 후보
    버킷은 MERGE_MAX_LIVE_GROUPS를 넘지 않는다 — 무한 누적에 의한 선형 스캔(O(n²))
    회귀 가드. 월클록 측정 대신 내부 버킷 길이를 구조적으로 검증한다.
    """
    from analyzer.core.merge import MERGE_MAX_LIVE_GROUPS, _MatchIndex, _dedup_key

    frames = [make_frame(number=i + 1, epoch=1000.0 + i * 1e-5, seq="", subtype="29",
                         ta="", ra=STA1) for i in range(500)]
    for f in frames:
        f.source = "w1"

    index = _MatchIndex()
    for f in frames:
        index.process(f)

    key = _dedup_key(frames[0])
    assert index.bucket_len(key) <= MERGE_MAX_LIVE_GROUPS
    assert len(index.all_groups) == 500  # 전부 같은 소스라 dedup 없이 새 group
