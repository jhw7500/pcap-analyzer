"""build_ping_matches 손실 분류 단위 테스트.

핵심 회귀 보호 (PR #10 ping loss 교정):
- fully_unobserved(request도 reply도 캡처되지 않은 seq 갭)는 캡처 누락과 무선 손실을
  구분할 수 없으므로 손실로 카운트하지 않는다 — 별도 카운트로만 보존.
- reply_missing(req는 보였는데 같은 seq의 reply가 캡처 어디에도 없음)은 확정 손실로 센다.
"""
from analyzer.core.ping_matching import build_ping_matches
from tests.conftest import make_frame

STA_IP = "10.0.0.1"
DST_IP = "10.0.0.2"
IDENT = "100"


def _req(seq, epoch, number):
    return make_frame(number=number, epoch=epoch, ip_src=STA_IP, ip_dst=DST_IP,
                      icmp_type="8", icmp_seq=str(seq), icmp_ident=IDENT)


def _reply(seq, epoch, number):
    return make_frame(number=number, epoch=epoch, ip_src=DST_IP, ip_dst=STA_IP,
                      icmp_type="0", icmp_seq=str(seq), icmp_ident=IDENT)


class TestFullyUnobservedExcluded:
    def test_seq_gap_both_missing_not_counted_as_loss(self):
        # req/reply seq 1,2,5 (양쪽 관측). seq 3,4는 양쪽 미관측 → fully_unobserved.
        frames = [
            _req(1, 1000.0, 1), _reply(1, 1000.5, 2),
            _req(2, 1001.0, 3), _reply(2, 1001.5, 4),
            _req(5, 1004.0, 5), _reply(5, 1004.5, 6),
        ]
        result = build_ping_matches(frames, {})
        stats = result["stats"]
        # seq 3,4는 손실에 포함되지 않는다.
        assert result["losses"] == []
        assert stats["loss_count"] == 0
        assert stats["loss_pct"] == 0
        # 별도 카운트로는 보존 (seq 3,4 = 2건), 검증된 사이클은 3건.
        assert stats["fully_unobserved"] == 2
        assert stats["verified_cycle"] == 3

    def test_no_loss_gap_entry_leaks_into_full_list(self):
        frames = [
            _req(1, 1000.0, 1), _reply(1, 1000.5, 2),
            _req(4, 1003.0, 3), _reply(4, 1003.5, 4),
        ]
        result = build_ping_matches(frames, {})
        # seq 2,3(양쪽 미관측)이 loss_gap entry로 full_list/losses에 새어들지 않는다.
        statuses = {e["status"] for e in result["full_list"]}
        assert "loss_gap" not in statuses
        assert result["losses"] == []


class TestReplyMissingStillLoss:
    def test_request_without_reply_is_confirmed_loss(self):
        # req seq 1,2,3 / reply seq 1,2 → seq 3은 reply_missing = 확정 손실.
        frames = [
            _req(1, 1000.0, 1), _reply(1, 1000.5, 2),
            _req(2, 1001.0, 3), _reply(2, 1001.5, 4),
            _req(3, 1002.0, 5),  # reply 없음
        ]
        result = build_ping_matches(frames, {})
        stats = result["stats"]
        assert stats["loss_count"] == 1
        assert stats["loss_pct"] > 0
        assert stats["reply_missing"] == 1
        loss_seqs = {e["seq"] for e in result["losses"]}
        assert "3" in loss_seqs
