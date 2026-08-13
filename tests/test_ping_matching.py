"""build_ping_matches 손실 분류 단위 테스트.

핵심 회귀 보호 (PR #10 ping loss 교정):
- fully_unobserved(request도 reply도 캡처되지 않은 seq 갭)는 캡처 누락과 무선 손실을
  구분할 수 없으므로 손실로 카운트하지 않는다 — 별도 카운트로만 보존.
- reply_missing(req는 보였는데 같은 seq의 reply가 캡처 어디에도 없음)은 확정 손실로 센다.
"""
from analyzer.core.ping_matching import build_ping_matches
from analyzer.core.ping_matching import ping_losses, ping_pairs
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


class TestReplyTimeoutClassification:
    def test_exact_boundary_is_on_time_and_after_boundary_is_late(self):
        frames = [
            _req(1, 1000.0, 1), _reply(1, 1001.0, 2),
            _req(2, 1002.0, 3), _reply(2, 1003.001, 4),
        ]
        result = build_ping_matches(frames, {}, reply_timeout_sec=1.0)

        assert [p["status"] for p in result["pairs"]] == ["matched", "late"]
        assert result["stats"]["on_time_count"] == 1
        assert result["stats"]["late_count"] == 1
        assert result["stats"]["timeout_count"] == 1
        assert result["stats"]["timeout_pct"] == 50.0
        assert result["stats"]["loss_count"] == 0

    def test_late_reply_remains_a_pair_not_a_loss(self):
        result = build_ping_matches(
            [_req(1, 1000.0, 1), _reply(1, 1002.0, 2)],
            {},
            reply_timeout_sec=1.0,
        )
        stripped = {k: v for k, v in result.items() if k not in ("pairs", "losses")}
        assert ping_pairs(stripped)[0]["status"] == "late"
        assert ping_losses(stripped) == []

    def test_invalid_timeout_is_rejected(self):
        import pytest

        for value in (0, -1, 31, float("nan"), float("inf")):
            with pytest.raises(ValueError, match="Ping timeout"):
                build_ping_matches([], {}, reply_timeout_sec=value)


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


class TestLossesFullListLockstep:
    def test_losses_are_full_list_loss_subsequence_same_objects(self):
        """losses == full_list의 loss 필터 부분수열 (동일 객체·동일 순서).

        프론트 클릭 내비(static/js/charts.js)가 losses[i] ↔ full_list 인덱스
        조인을 이 불변식(원자적 동시 append + 독립 안정 정렬)에 의존한다
        (PR #26). 개수는 같고 순서만 어긋나는 변경은 프론트 가드를 통과해
        조용한 오점프를 만들므로 여기서 순서·정체성까지 고정한다.
        """
        # 동률 epoch 손실 2건(seq 3, 4)을 포함해 안정 정렬 타이 케이스까지 커버.
        frames = [
            _req(1, 1000.0, 1), _reply(1, 1000.5, 2),
            _req(3, 1002.0, 5),                # 손실 ①
            _req(2, 1001.0, 3), _reply(2, 1001.5, 4),
            _req(4, 1002.0, 6),                # 손실 ② — ①과 동일 epoch (타이)
        ]
        result = build_ping_matches(frames, {})
        loss_sub = [e for e in result["full_list"]
                    if e["status"] in ("loss", "loss_gap")]
        assert len(result["losses"]) == 2
        assert len(loss_sub) == len(result["losses"])
        # 같은 순서의 같은 객체여야 한다 — 값 비교가 아니라 정체성 비교.
        assert all(a is b for a, b in zip(loss_sub, result["losses"]))


class TestPairsLossesDerivation:
    """pairs/losses는 결과 JSON에서 제거되고 full_list에서 파생된다.

    full_list와 같은 entry 객체를 담은 부분수열이라 JSON에서만 완전 중복이었다
    (2시간 캡처 실측: structured.ping 32.8MB의 절반). 파생 규칙이 원래
    부분수열과 정확히 같아야 프론트 클릭 내비(lossFlIdx ↔ losses 조인)가
    유지된다.
    """

    def _frames(self):
        # 매칭 2건 + 확정 손실 2건(동일 epoch 타이 포함)
        return [
            _req(1, 1000.0, 1), _reply(1, 1000.5, 2),
            _req(3, 1002.0, 5),                # 손실 ①
            _req(2, 1001.0, 3), _reply(2, 1001.5, 4),
            _req(4, 1002.0, 6),                # 손실 ② — ①과 동일 epoch
        ]

    def test_derivation_reproduces_original_subsequences(self):
        result = build_ping_matches(self._frames(), {})
        stripped = {k: v for k, v in result.items() if k not in ("pairs", "losses")}
        # 값·순서 모두 원본과 동일해야 한다 (동일 epoch 타이 포함).
        assert ping_pairs(stripped) == result["pairs"]
        assert ping_losses(stripped) == result["losses"]

    def test_structured_ping_omits_duplicate_keys(self):
        from analyzer.web.structured import _structured_ping

        ping = _structured_ping(self._frames(), {})
        assert "pairs" not in ping
        assert "losses" not in ping
        assert ping["full_list"]          # 원본은 남아 있다
        # 파생값이 stats와 정합해야 한다 (stats는 제거 전 pairs/losses로 계산됨).
        assert len(ping_losses(ping)) == ping["stats"]["loss_count"]

    def test_legacy_result_uses_stored_keys(self):
        # 구버전 result(두 키 보존)는 저장된 값을 그대로 쓴다 —
        # serialized-result-backward-compat.
        legacy = {"full_list": [{"status": "matched"}], "pairs": [{"stored": True}],
                  "losses": [{"stored": True}]}
        assert ping_pairs(legacy) == [{"stored": True}]
        assert ping_losses(legacy) == [{"stored": True}]

    def test_empty_and_malformed_entries(self):
        assert ping_pairs({}) == []
        assert ping_losses({}) == []
        # dict 아닌 항목(직렬화 잔재)이 섞여도 터지지 않는다.
        junk = {"full_list": [None, "x", {"status": "loss"}]}
        assert ping_losses(junk) == [{"status": "loss"}]

    def test_loss_gap_counts_as_loss(self):
        d = {"full_list": [{"status": "loss_gap"}, {"status": "matched"}]}
        assert ping_losses(d) == [{"status": "loss_gap"}]
        assert ping_pairs(d) == [{"status": "matched"}]


class TestStatusVocabularyIsShared:
    """`status` 어휘는 생성부와 파생부가 **같은 상수**를 써야 한다.

    pairs/losses는 결과 JSON에서 빠지고 full_list의 status로 파생되므로
    (`ping_pairs`/`ping_losses`), 생성부가 리터럴을 쓰면 한쪽만 바뀌었을 때
    **예외도 로그도 없이 빈 목록**이 된다 — ping 근거가 통째로 사라진다.
    """

    def test_producer_uses_the_shared_constants(self):
        import inspect

        from analyzer.core import ping_matching as pm

        src = inspect.getsource(pm.build_ping_matches)
        src += inspect.getsource(pm._entry_from_frame)
        for literal in (
            '"matched"', "'matched'", '"late"', "'late'", '"loss"', "'loss'"
        ):
            assert literal not in src, f"생성부에 리터럴 {literal}이 남아 있다"

    def test_renaming_the_constant_is_caught(self):
        """상수를 바꾸면 파생이 즉시 어긋나는지 — 계약이 살아 있는지 확인."""
        from unittest.mock import patch

        from analyzer.core import ping_matching as pm

        ping = {"full_list": [{"status": pm.MATCHED_STATUS}, {"status": pm.LOSS_STATUS}]}
        assert len(pm.ping_pairs(ping)) == 1
        with patch.object(pm, "MATCHED_STATUS", "renamed"):
            assert pm.ping_pairs(ping) == []
