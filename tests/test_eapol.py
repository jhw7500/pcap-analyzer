"""EAPOL 4-way 핸드셰이크 그룹핑 + 로밍 four_way_ms 매칭 테스트."""
from analyzer.core.modules.eapol import build_handshakes, match_four_way_ms
from analyzer.web.structured import _structured_per_second, _structured_roaming
from tests.conftest import AP1, STA1, STA2, SAMPLE_ROLES, make_frame


def _eapol(number, epoch, msgnr, sta=STA1, ap=AP1, retry=False):
    """msg 1/3 = AP→STA, msg 2/4 = STA→AP 방향으로 합성."""
    if msgnr in (1, 3):
        ta, ra = ap, sta
    else:
        ta, ra = sta, ap
    return make_frame(
        number=number, epoch=epoch, ta=ta, ra=ra, subtype="40",
        protocol="EAPOL", eapol_msgnr=str(msgnr), retry=retry,
    )


class TestBuildHandshakes:
    def test_complete_4way(self):
        frames = [
            _eapol(1, 1000.000, 1),
            _eapol(2, 1000.010, 2),
            _eapol(3, 1000.020, 3),
            _eapol(4, 1000.030, 4),
        ]
        hs = build_handshakes(frames, SAMPLE_ROLES)["handshakes"]
        assert len(hs) == 1
        h = hs[0]
        assert h["sta"] == STA1 and h["ap"] == AP1
        assert h["complete"] is True
        assert h["start_epoch"] == 1000.0
        assert h["end_epoch"] == 1000.03
        assert h["duration_ms"] == 30.0
        assert h["retry_total"] == 0
        assert set(h["messages"]) == {"1", "2", "3", "4"}

    def test_incomplete_flag(self):
        frames = [
            _eapol(1, 1000.000, 1),
            _eapol(2, 1000.010, 2),
        ]
        hs = build_handshakes(frames, SAMPLE_ROLES)["handshakes"]
        assert len(hs) == 1
        assert hs[0]["complete"] is False

    def test_retransmission_counts(self):
        frames = [
            _eapol(1, 1000.000, 1),
            _eapol(2, 1000.010, 1, retry=True),  # msg1 재전송 (retry bit)
            _eapol(3, 1000.020, 2),
            _eapol(4, 1000.030, 3),
            _eapol(5, 1000.040, 3),  # msg3 반복 (retry bit 없이)
            _eapol(6, 1000.050, 4),
        ]
        hs = build_handshakes(frames, SAMPLE_ROLES)["handshakes"]
        assert len(hs) == 1
        h = hs[0]
        assert h["messages"]["1"]["retries"] == 1
        assert h["messages"]["3"]["retries"] == 1
        assert h["messages"]["2"]["retries"] == 0
        assert h["retry_total"] == 2
        assert h["complete"] is True

    def test_two_handshakes_split_by_new_msg1(self):
        frames = [
            _eapol(1, 1000.000, 1),
            _eapol(2, 1000.010, 2),
            _eapol(3, 1000.020, 3),
            _eapol(4, 1000.030, 4),
            _eapol(5, 1002.000, 1),  # 두 번째 핸드셰이크 시작
            _eapol(6, 1002.010, 2),
        ]
        hs = build_handshakes(frames, SAMPLE_ROLES)["handshakes"]
        assert len(hs) == 2
        assert hs[0]["complete"] is True
        assert hs[1]["complete"] is False

    def test_gap_timeout_splits(self):
        frames = [
            _eapol(1, 1000.000, 1),
            _eapol(2, 1010.000, 2),  # 10초 간격 → 별개 핸드셰이크
        ]
        hs = build_handshakes(frames, SAMPLE_ROLES)["handshakes"]
        assert len(hs) == 2
        assert all(not h["complete"] for h in hs)

    def test_per_sta_grouping(self):
        frames = []
        n = 1
        for i, sta in enumerate((STA1, STA2)):
            base = 1000.0 + i * 0.001
            for m in (1, 2, 3, 4):
                frames.append(_eapol(n, base + m * 0.01, m, sta=sta))
                n += 1
        frames.sort(key=lambda f: f.epoch)
        hs = build_handshakes(frames, SAMPLE_ROLES)["handshakes"]
        assert len(hs) == 2
        assert {h["sta"] for h in hs} == {STA1, STA2}
        assert all(h["complete"] for h in hs)

    def test_non_eapol_ignored(self):
        frames = [make_frame(number=1, epoch=1000.0, ta=STA1, subtype="40")]
        assert build_handshakes(frames, SAMPLE_ROLES)["handshakes"] == []


class TestMatchFourWayMs:
    def _hs(self, start, dur_ms, sta=STA1, complete=True):
        return {
            "sta": sta, "start_epoch": start,
            "duration_ms": dur_ms, "complete": complete,
        }

    def test_match_first_after_assoc(self):
        hss = [self._hs(999.0, 10.0), self._hs(1000.1, 25.0), self._hs(1002.0, 30.0)]
        assert match_four_way_ms(1000.0, STA1, hss) == 25.0

    def test_no_match_returns_none(self):
        assert match_four_way_ms(1000.0, STA1, []) is None
        # 다른 STA / window 밖 / 미완료는 매칭 안 됨
        hss = [
            self._hs(1000.1, 25.0, sta=STA2),
            self._hs(1010.0, 30.0),
            self._hs(1000.2, 40.0, complete=False),
        ]
        assert match_four_way_ms(1000.0, STA1, hss) is None


class TestRoamingFourWayIntegration:
    def test_sequence_gets_four_way_ms(self):
        frames = [
            make_frame(number=1, epoch=1000.0, ta=STA1, ra=AP1, subtype="11"),  # Auth
            make_frame(number=2, epoch=1000.05, ta=STA1, ra=AP1, subtype="0"),  # AssocReq
            _eapol(3, 1000.100, 1),
            _eapol(4, 1000.110, 2),
            _eapol(5, 1000.120, 3),
            _eapol(6, 1000.130, 4),
        ]
        handshakes = build_handshakes(frames, SAMPLE_ROLES)["handshakes"]
        seqs = _structured_roaming(frames, SAMPLE_ROLES, handshakes=handshakes)["sequences"]
        assert len(seqs) == 1
        assert seqs[0]["four_way_ms"] == 30.0

    def test_sequence_without_handshake_null(self):
        frames = [
            make_frame(number=1, epoch=1000.0, ta=STA1, ra=AP1, subtype="11"),
            make_frame(number=2, epoch=1000.05, ta=STA1, ra=AP1, subtype="0"),
        ]
        seqs = _structured_roaming(frames, SAMPLE_ROLES, handshakes=[])["sequences"]
        assert seqs[0]["four_way_ms"] is None


class TestPerSecondBytes:
    def test_bytes_and_data_bytes(self):
        frames = [
            make_frame(number=1, epoch=1000.1, subtype="40", length=1000),  # QoS Data
            make_frame(number=2, epoch=1000.5, subtype="8", length=300),    # Beacon
            make_frame(number=3, epoch=1001.2, subtype="32", length=500),   # Data
        ]
        tl = _structured_per_second(frames)["timeline"]
        assert tl[0]["epoch"] == 1000
        assert tl[0]["bytes"] == 1300
        assert tl[0]["data_bytes"] == 1000
        assert tl[1]["bytes"] == 500
        assert tl[1]["data_bytes"] == 500

    def test_gap_seconds_zero_filled(self):
        frames = [
            make_frame(number=1, epoch=1000.0, subtype="40", length=100),
            make_frame(number=2, epoch=1002.0, subtype="40", length=200),
        ]
        tl = _structured_per_second(frames)["timeline"]
        assert [e["bytes"] for e in tl] == [100, 0, 200]
        assert [e["data_bytes"] for e in tl] == [100, 0, 200]
