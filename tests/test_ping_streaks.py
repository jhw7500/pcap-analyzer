"""연속 Loss 구간(streak) 탐지 테스트 — 공유 알고리즘·장치별 집계·텍스트 리포트.

PR #18 리뷰(단위 테스트 저장소 부재) 반영: find_time_streaks / _ping_loss_streaks /
ping_loss.analyze의 장치별 구간을 make test에서 자동 회귀 검증한다.
"""
from analyzer.core.ping_matching import (
    LOSS_STREAK_GAP_SEC,
    LOSS_STREAK_MIN_LEN,
    find_time_streaks,
)
from analyzer.core.modules import ping_loss
from analyzer.web import structured as S
from tests.conftest import SAMPLE_ROLES, make_frame


class TestFindTimeStreaks:
    def test_empty(self):
        assert find_time_streaks([]) == []

    def test_single_below_min_len(self):
        assert find_time_streaks([1.0]) == []

    def test_two_within_gap(self):
        assert find_time_streaks([1.0, 2.0]) == [(0, 1)]

    def test_two_beyond_gap(self):
        assert find_time_streaks([1.0, 4.0]) == []

    def test_gap_boundary_inclusive(self):
        # 정확히 gap_sec(2.0) 간격은 연속으로 본다(> 비교라 경계 포함).
        assert find_time_streaks([1.0, 3.0]) == [(0, 1)]

    def test_gap_just_over_boundary(self):
        assert find_time_streaks([1.0, 3.01]) == []

    def test_run_gap_run(self):
        assert find_time_streaks([1, 2, 3, 10, 11]) == [(0, 2), (3, 4)]

    def test_trailing_single_dropped(self):
        assert find_time_streaks([1, 2, 10]) == [(0, 1)]

    def test_custom_min_len(self):
        assert find_time_streaks([1, 2], min_len=3) == []
        assert find_time_streaks([1, 2, 3], min_len=3) == [(0, 2)]

    def test_min_len_one_keeps_singletons(self):
        assert find_time_streaks([1.0, 5.0], min_len=1) == [(0, 0), (1, 1)]

    def test_custom_gap(self):
        assert find_time_streaks([1.0, 6.0], gap_sec=10.0) == [(0, 1)]

    def test_constants(self):
        assert LOSS_STREAK_GAP_SEC == 2.0
        assert LOSS_STREAK_MIN_LEN == 2


def _loss(epoch, src, dst, dev, seq, req_num, status="loss"):
    d = {
        "status": status, "epoch": epoch, "src": src, "dst": dst,
        "seq": str(seq), "req_num": req_num, "req_time": "",
    }
    if dev:
        d["src_mac"] = dev  # full_list의 src_mac은 장치명 문자열(예: "STA1(aa)")
    return d


class TestPingLossStreaks:
    def test_per_device_grouping(self):
        gw = "1.1.1.1"
        fl = [
            _loss(10.0, "1.1.1.10", gw, "STA1(aa)", 1, 101),
            _loss(11.0, "1.1.1.10", gw, "STA1(aa)", 2, 102),
            _loss(12.0, "1.1.1.10", gw, "STA1(aa)", 3, 103),
            _loss(20.0, "1.1.1.10", gw, "STA1(aa)", 9, 109),   # 단발 — 제외
            _loss(10.5, "1.1.1.20", gw, "STA2(bb)", 1, 201),
            _loss(11.5, "1.1.1.20", gw, "STA2(bb)", 2, None, status="loss_gap"),
            {"status": "matched", "epoch": 10.2, "src": "1.1.1.10",
             "dst": gw, "src_mac": "STA1(aa)", "rtt_ms": 1.0},        # matched — 무시
        ]
        res = S._ping_loss_streaks(fl)
        by = {(r["device"], r["count"]) for r in res}
        assert ("STA1(aa)", 3) in by
        assert ("STA2(bb)", 2) in by
        assert len(res) == 2
        # 정렬: start_epoch 오름차순
        assert [r["start_epoch"] for r in res] == sorted(r["start_epoch"] for r in res)

    def test_loss_gap_counted_but_no_ref(self):
        gw = "1.1.1.1"
        fl = [
            _loss(1.0, "1.1.1.20", gw, "STA2(bb)", 1, None, status="loss_gap"),
            _loss(1.5, "1.1.1.20", gw, "STA2(bb)", 2, None, status="loss_gap"),
        ]
        res = S._ping_loss_streaks(fl)
        assert len(res) == 1
        assert res[0]["count"] == 2           # 번호 없어도 건수엔 포함
        assert res[0]["frame_refs"] == []     # req_num 없어 근거 없음

    def test_frame_refs_capped_at_20(self):
        gw = "1.1.1.1"
        fl = [_loss(float(i), "1.1.1.10", gw, "STA1(aa)", i, 100 + i) for i in range(25)]
        res = S._ping_loss_streaks(fl)
        assert len(res) == 1
        assert res[0]["count"] == 25
        assert len(res[0]["frame_refs"]) == 20   # refs[:20] cap

    def test_empty(self):
        assert S._ping_loss_streaks([]) == []

    def test_sparse_no_streak(self):
        gw = "1.1.1.1"
        fl = [
            _loss(0.0, "1.1.1.10", gw, "STA1(aa)", 1, 1),
            _loss(100.0, "1.1.1.10", gw, "STA1(aa)", 2, 2),
        ]
        assert S._ping_loss_streaks(fl) == []


def _req(n, ep, seq, src, dst, ident):
    return make_frame(number=n, epoch=ep, icmp_type="8", icmp_seq=str(seq),
                      ip_src=src, ip_dst=dst, icmp_ident=ident, subtype="")


def _rep(n, ep, seq, src, dst, ident):
    return make_frame(number=n, epoch=ep, icmp_type="0", icmp_seq=str(seq),
                      ip_src=src, ip_dst=dst, icmp_ident=ident, subtype="")


class TestPingLossAnalyzeText:
    def test_device_streak_section_rendered(self):
        a, gw, b = "10.0.0.2", "10.0.0.1", "10.0.0.3"
        frames = []
        # 장치 A: req seq1..6 (0.5s 간격), reply seq1·6만 → seq2..5 = 4연속 손실
        for i, seq in enumerate([1, 2, 3, 4, 5, 6]):
            frames.append(_req(10 + i, 1000.0 + i * 0.5, seq, a, gw, "100"))
        frames += [_rep(100, 1000.05, 1, gw, a, "100"), _rep(106, 1002.55, 6, gw, a, "100")]
        # 장치 B: req seq1..3, reply seq1만 → seq2·3 = 2연속 손실
        for i, seq in enumerate([1, 2, 3]):
            frames.append(_req(20 + i, 1000.2 + i * 0.5, seq, b, gw, "200"))
        frames.append(_rep(200, 1000.25, 1, gw, b, "200"))

        # 역순 입력 — ping_loss.analyze의 방어적 정렬(losses.sort)이 동작해야 정확.
        sec = ping_loss.analyze(list(reversed(frames)), dict(SAMPLE_ROLES), index=None)
        txt = "\n".join(sec.lines)

        assert "연속 Loss 구간 (전역):" in txt
        assert "장치별 연속 Loss 구간:" in txt
        assert "10.0.0.2→10.0.0.1" in txt and "4건" in txt
        assert "10.0.0.3→10.0.0.1" in txt and "2건" in txt

    def test_no_loss_no_streak_section(self):
        # request↔reply 모두 매칭되면 loss 없음 → streak 섹션 없이 조기 종료.
        frames = [
            _req(1, 1000.0, 1, "10.0.0.2", "10.0.0.1", "100"),
            _rep(2, 1000.01, 1, "10.0.0.1", "10.0.0.2", "100"),
        ]
        sec = ping_loss.analyze(frames, dict(SAMPLE_ROLES), index=None)
        txt = "\n".join(sec.lines)
        assert "장치별 연속 Loss 구간:" not in txt
