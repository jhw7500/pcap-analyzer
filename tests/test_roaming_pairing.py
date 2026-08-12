"""로밍 Auth ↔ Assoc/Reassoc 짝짓기 규칙 (`pair_roaming_sequences`).

실측 회귀: 2시간 캡처(143만 프레임)에서 로밍 858건 중 17건이 16.6~32.7초 gap으로
보고됐다. 원인은 Auth 앵커를 **소비 후 지우지 않아** Auth가 캡처되지 않은 로밍의
Reassoc이 수십 초 전 낡은 Auth와 짝지어진 것. 17건 중 16건은 AP가 보낸 Auth
응답이 Reassoc 3.4~6.2ms 전에 실재해 실제 로밍은 정상 속도였다.
수정 후 최대 gap 32,724ms → 104ms, 1초 초과 17건 → 0건.

앵커를 못 찾은 로밍은 **시퀀스로 남기되 gap_ms=None(측정 불가)** 으로 두고,
`missing`에 어떤 프레임이 캡처에 없어서 못 쟀는지를 담는다 — 로밍은 실제로
일어났으므로 횟수에서 빠지면 안 되고, 그렇다고 gap을 지어내서도 안 된다.
"""
from tests.conftest import AP1, STA1, make_frame

from analyzer.core.modules.roaming import (
    ASSOC_ATTEMPT_MAX_SEC,
    GAP_BASIS_REQUEST,
    GAP_BASIS_RESPONSE,
    ROAM_PAIR_MAX_GAP_SEC,
    analyze,
    pair_roaming_sequences,
)

AP2 = "00:80:4c:e1:09:cc"
STA_MACS = {STA1}
ROLES = {
    STA1: {"role": "STA", "name": "STA1"},
    AP1: {"role": "AP", "name": "AP1"},
    AP2: {"role": "AP", "name": "AP2"},
}


def _auth_req(number, epoch, ap=AP1):
    """STA → AP Auth 요청 (로밍 시작점)."""
    return make_frame(number=number, epoch=epoch, subtype="11", ta=STA1, ra=ap)


def _auth_resp(number, epoch, ap=AP1):
    """AP → STA Auth 응답 (STA 요청을 놓쳤을 때의 폴백 앵커)."""
    return make_frame(number=number, epoch=epoch, subtype="11", ta=ap, ra=STA1)


def _reassoc(number, epoch, ap=AP1, retry=False):
    return make_frame(
        number=number, epoch=epoch, subtype="2", ta=STA1, ra=ap, retry=retry
    )


def _gaps_ms(pairs):
    """측정된 gap은 반올림한 ms, 측정 불가는 None."""
    return [None if p.gap_ms is None else round(p.gap_ms, 1) for p in pairs]


def _measured(pairs):
    return [p for p in pairs if p.gap_ms is not None]


class TestAnchorConsumption:
    def test_anchor_is_not_reused_by_a_later_assoc(self):
        """핵심 회귀 — 낡은 Auth가 한참 뒤 Reassoc에 재사용되면 안 된다."""
        frames = [
            _auth_req(1, 1000.000),
            _reassoc(2, 1000.006),       # 정상 로밍 (6ms)
            _reassoc(3, 1032.700),       # Auth 없음 → 32.7초로 잡히면 안 된다
        ]
        pairs = pair_roaming_sequences(frames, STA_MACS)
        # 시퀀스는 2건 모두 남되, 두 번째는 32.7초가 아니라 측정 불가여야 한다.
        assert _gaps_ms(pairs) == [6.0, None]
        assert all(p.gap_ms is None or p.gap_ms < 1000 for p in pairs)

    def test_two_full_roams_pair_independently(self):
        frames = [
            _auth_req(1, 1000.000), _reassoc(2, 1000.005),
            _auth_req(3, 1030.000), _reassoc(4, 1030.007),
        ]
        assert _gaps_ms(pair_roaming_sequences(frames, STA_MACS)) == [5.0, 7.0]

    def test_auth_for_other_ap_is_not_consumed(self):
        """STA가 같아도 대상 AP가 다르면 Auth gap을 지어내면 안 된다."""
        frames = [
            _auth_req(1, 1000.000, ap=AP1),
            _reassoc(2, 1000.005, ap=AP2),
        ]

        pairs = pair_roaming_sequences(frames, STA_MACS)

        assert _gaps_ms(pairs) == [None]
        assert pairs[0].auth is None


class TestAssociationAttemptDedup:
    """같은 로밍 안의 Reassoc 반복이 새 로밍·측정불가로 부풀지 않는다."""

    def test_retry_seen_before_original_is_one_roam(self):
        """다중 스니퍼 시각 보정으로 retry가 original보다 먼저 정렬될 수 있다."""
        frames = [
            _auth_req(1, 1000.000),
            _reassoc(2, 1000.005, retry=True),
            _reassoc(3, 1000.009, retry=False),
        ]
        pairs = pair_roaming_sequences(frames, STA_MACS)
        assert _gaps_ms(pairs) == [5.0]
        assert pairs[0].assoc.number == 2

    def test_new_sequence_reassoc_retry_without_retry_bit_is_one_roam(self):
        """TEST14: 154ms 뒤 새 seq/retry=False 재시도도 같은 association 시도다."""
        frames = [
            _auth_req(1, 1000.000),
            _reassoc(2, 1000.015),
            _reassoc(3, 1000.169),
        ]
        assert _gaps_ms(pair_roaming_sequences(frames, STA_MACS)) == [15.0]

    def test_new_auth_inside_window_starts_a_new_roam(self):
        frames = [
            _auth_req(1, 1000.000), _reassoc(2, 1000.005),
            _auth_req(3, 1000.300), _reassoc(4, 1000.306),
        ]
        assert _gaps_ms(pair_roaming_sequences(frames, STA_MACS)) == [5.0, 6.0]

    def test_different_target_without_auth_is_not_merged(self):
        frames = [
            _auth_req(1, 1000.000), _reassoc(2, 1000.005),
            _reassoc(3, 1000.200, ap=AP2),
        ]
        assert _gaps_ms(pair_roaming_sequences(frames, STA_MACS)) == [5.0, None]

    def test_same_target_after_window_is_kept_unmeasurable(self):
        frames = [
            _auth_req(1, 1000.000), _reassoc(2, 1000.005),
            _reassoc(3, 1000.005 + ASSOC_ATTEMPT_MAX_SEC + 0.001),
        ]
        assert _gaps_ms(pair_roaming_sequences(frames, STA_MACS)) == [5.0, None]

    def test_independent_verifier_uses_same_attempt_window(self):
        from scripts.roaming_independent_verify import DEFAULT_ASSOC_ATTEMPT_MS

        assert DEFAULT_ASSOC_ATTEMPT_MS == ASSOC_ATTEMPT_MAX_SEC * 1000


class TestApSideFallback:
    def test_ap_auth_response_anchors_when_request_missed(self):
        """모니터가 STA의 Auth 요청을 놓쳐도 AP 응답으로 실제 gap을 복원한다."""
        frames = [
            _auth_req(1, 1000.000), _reassoc(2, 1000.006),   # 앞선 정상 로밍
            _auth_resp(3, 1032.6958, ap=AP2),                # AP 응답만 캡처됨
            _reassoc(4, 1032.700, ap=AP2),
        ]
        pairs = pair_roaming_sequences(frames, STA_MACS)
        assert _gaps_ms(pairs) == [6.0, 4.2]
        # 요청이 없어 응답 기준으로 잰 것이므로 하한값임을 표시해야 한다.
        assert pairs[1].basis == GAP_BASIS_RESPONSE
        assert pairs[1].missing == [GAP_BASIS_REQUEST]
        assert "하한" in pairs[1].note or "이보다 큼" in pairs[1].note

    def test_sta_request_wins_within_same_exchange(self):
        """같은 Auth 교환이면 AP 응답이 STA 요청 앵커를 덮어쓰지 않는다.

        요청 시각이 로밍의 진짜 시작점이므로 gap은 요청 기준이어야 한다.
        """
        frames = [
            _auth_req(1, 1000.000),
            _auth_resp(2, 1000.001),     # 1ms 뒤 응답 — 같은 교환
            _reassoc(3, 1000.006),
        ]
        assert _gaps_ms(pair_roaming_sequences(frames, STA_MACS)) == [6.0]

    def test_stale_sta_request_replaced_by_fresh_ap_response(self):
        """낡은 STA 요청이 남아 있어도 새 교환의 AP 응답이 앵커가 된다."""
        frames = [
            _auth_req(1, 1000.000),      # 짝을 못 만난 채 남는 요청
            _auth_resp(2, 1005.000),     # 5초 뒤 = 다른 교환
            _reassoc(3, 1005.004),
        ]
        assert _gaps_ms(pair_roaming_sequences(frames, STA_MACS)) == [4.0]


class TestWindowBound:
    def test_anchor_older_than_limit_is_rejected(self):
        frames = [
            _auth_req(1, 1000.0),
            _reassoc(2, 1000.0 + ROAM_PAIR_MAX_GAP_SEC + 0.1),
        ]
        pairs = pair_roaming_sequences(frames, STA_MACS)
        assert _gaps_ms(pairs) == [None]
        assert pairs[0].missing == [GAP_BASIS_REQUEST, GAP_BASIS_RESPONSE]

    def test_anchor_within_limit_is_accepted(self):
        frames = [
            _auth_req(1, 1000.0),
            _reassoc(2, 1000.0 + ROAM_PAIR_MAX_GAP_SEC - 0.1),
        ]
        assert len(pair_roaming_sequences(frames, STA_MACS)) == 1

    def test_slow_but_real_roam_still_measured(self):
        """상한은 허위 짝짓기만 끊는다 — 느린 로밍 탐지는 살아 있어야 한다."""
        frames = [_auth_req(1, 1000.0), _reassoc(2, 1000.35)]
        assert _gaps_ms(pair_roaming_sequences(frames, STA_MACS)) == [350.0]


class TestUnmeasurableCases:
    def test_assoc_without_any_auth_is_kept_as_unmeasurable(self):
        """로밍은 일어났으므로 시퀀스는 남고, gap만 측정 불가여야 한다."""
        pairs = pair_roaming_sequences([_reassoc(1, 1000.0)], STA_MACS)
        assert len(pairs) == 1
        assert pairs[0].gap_ms is None
        assert pairs[0].basis is None
        assert pairs[0].missing == [GAP_BASIS_REQUEST, GAP_BASIS_RESPONSE]
        assert "캡처에 없어" in pairs[0].note

    def test_ap_transmitted_assoc_is_not_a_sequence(self):
        """Assoc은 STA 송신만 로밍 시퀀스로 본다."""
        frames = [
            _auth_req(1, 1000.0),
            make_frame(number=2, epoch=1000.005, subtype="2", ta=AP1, ra=STA1),
        ]
        assert pair_roaming_sequences(frames, STA_MACS) == []

    def test_auth_for_other_sta_does_not_anchor(self):
        other = "00:50:43:99:99:99"
        frames = [
            make_frame(number=1, epoch=1000.0, subtype="11", ta=other, ra=AP1),
            _reassoc(2, 1000.005),
        ]
        assert _gaps_ms(pair_roaming_sequences(frames, STA_MACS)) == [None]

    def test_empty_input(self):
        assert pair_roaming_sequences([], STA_MACS) == []


class TestTextModuleSharesRule:
    def test_analyze_reports_no_fabricated_gap(self):
        """텍스트 모듈도 같은 규칙을 써야 한다 — 예전엔 로직이 복제돼 있었다."""
        frames = [
            _auth_req(1, 1000.000), _reassoc(2, 1000.006),
            _reassoc(3, 1032.700),      # 앵커 없음 — 32.7초로 보고되면 안 된다
        ]
        section = analyze(frames, ROLES)
        body = "".join(section.lines)
        # 로밍 2건 모두 세되, 32.7초는 어디에도 나오면 안 된다.
        assert "시퀀스: 2건" in section.lines[0]
        assert "32724" not in body
        assert "측정불가" in body
        # 100ms 임계를 넘는 느린 로밍으로 오분류되지 않아야 한다.
        assert "느린로밍(전체 소요 >100ms) 0건" in section.summary
        assert "gap 측정불가 1건" in section.summary

    def test_analyze_matches_pairing_helper_count(self):
        frames = [
            _auth_req(1, 1000.000), _reassoc(2, 1000.006),
            _auth_resp(3, 1032.696, ap=AP2), _reassoc(4, 1032.700, ap=AP2),
        ]
        section = analyze(frames, ROLES)
        expected = len(pair_roaming_sequences(frames, STA_MACS))
        assert expected == 2
        assert f"시퀀스: {expected}건" in section.lines[0]


class TestStructuredSharesRule:
    """시각화(`_structured_roaming`)와 텍스트(`analyze`)가 같은 시퀀스를 봐야 한다.

    이 등가성이 이번 버그의 핵심이다 — 짝짓기 로직이 두 곳에 복제돼 있어서
    결함도 양쪽에 똑같이 있었고, 한쪽만 고치면 화면과 리포트가 어긋난다.
    """

    def _frames(self):
        return [
            _auth_req(1, 1000.000), _reassoc(2, 1000.006),
            _auth_resp(3, 1032.696, ap=AP2), _reassoc(4, 1032.700, ap=AP2),
            _reassoc(5, 1099.000, ap=AP2),   # 앵커 없음 — 양쪽 모두 제외해야 한다
        ]

    def test_structured_gaps_match_helper(self):
        from analyzer.web.structured import _structured_roaming

        frames = self._frames()
        out = _structured_roaming(frames, ROLES)
        seqs = out["sequences"]
        assert [s["gap_ms"] for s in seqs] == _gaps_ms(
            pair_roaming_sequences(frames, STA_MACS)
        ) == [6.0, 4.0, None]
        assert all(not s["is_slow"] for s in seqs)
        # 측정 불가 항목은 무엇이 없어서 못 쟀는지 표시해야 한다.
        assert seqs[2]["missing_labels"] == ["STA→AP Auth 요청", "AP→STA Auth 응답"]
        assert seqs[2]["gap_note"]
        assert seqs[2]["auth_fnum"] is None

    def test_structured_and_text_agree_on_count(self):
        from analyzer.web.structured import _structured_roaming

        frames = self._frames()
        n_struct = len(_structured_roaming(frames, ROLES)["sequences"])
        assert f"시퀀스: {n_struct}건" in analyze(frames, ROLES).lines[0]

    def test_structured_never_fabricates_multi_second_gap(self):
        from analyzer.web.structured import _structured_roaming

        frames = [
            _auth_req(1, 1000.000), _reassoc(2, 1000.006),
            _reassoc(3, 1032.700),
        ]
        seqs = _structured_roaming(frames, ROLES)["sequences"]
        assert [s["gap_ms"] for s in seqs] == [6.0, None]
        measured = [s["gap_ms"] for s in seqs if s["gap_ms"] is not None]
        assert max(measured, default=0) < 1000


class TestUnmeasurableConsumers:
    """gap_ms=None이 소비자를 깨뜨리지 않고 사유까지 전달되는지.

    이전에는 gap_ms가 **항상 숫자**라 소비자들이 그 전제로 쓰여 있었다.
    ai/prompts는 `-x.get("gap_ms", 0)`(정렬)과 `f"{gap:.1f}"`(포맷)에서 TypeError,
    charts.js는 `s.gap_ms.toFixed(1)`에서 표 전체가 렌더되지 않았다.
    """

    def _structured(self):
        from analyzer.web.structured import _structured_roaming

        frames = [
            _auth_req(1, 1000.000), _reassoc(2, 1000.006),
            _reassoc(3, 1099.000),                 # 측정 불가
            _auth_req(4, 1200.000), _reassoc(5, 1200.350),   # 느린 로밍 350ms
        ]
        return {"roaming": _structured_roaming(frames, ROLES)}

    def test_report_markdown_shows_reason_not_dash(self):
        from analyzer.web.report import _roaming_section

        lines = _roaming_section(self._structured())
        body = "\n".join(lines)
        assert "측정불가" in body
        # 무엇이 없어서 못 쟀는지가 표에 드러나야 한다.
        assert "Auth 요청" in body and "미포착" in body
        assert "350.0" in body          # 측정된 값은 그대로

    def test_ai_prompt_does_not_crash_and_excludes_from_stats(self):
        from ai.prompts import _build_roaming_section

        lines = _build_roaming_section(self._structured()["roaming"])
        body = "\n".join(lines)
        assert "gap 측정불가 1회" in body
        assert "측정불가" in body
        # 평균/최대는 측정된 값(6.0, 350.0)만으로 계산돼야 한다.
        assert "max=350.0" in body
        assert "min=6.0" in body

    def test_threshold_severity_separates_unknown(self):
        from analyzer.core.thresholds import roam_gap_severity

        assert roam_gap_severity(None) == "unknown"   # good으로 낙관하지 않는다
        assert roam_gap_severity(50) == "good"
        assert roam_gap_severity(350) == "danger"

    def test_text_summary_counts_unmeasured_separately(self):
        frames = [
            _auth_req(1, 1000.000), _reassoc(2, 1000.006),
            _reassoc(3, 1099.000),
        ]
        section = analyze(frames, ROLES)
        # 로밍 횟수에는 포함되고, 느린 로밍에는 포함되지 않는다.
        assert "시퀀스: 2건" in section.lines[0]
        assert "느린로밍(전체 소요 >100ms) 0건" in section.summary
        assert "gap 측정불가 1건" in section.summary

    def test_casefile_message_and_timestamp_are_sane(self):
        from analyzer.web.structured import _structured_roaming

        frames = [_reassoc(1, 1500.0)]   # 앵커 없음 = 측정 불가
        seqs = _structured_roaming(frames, ROLES)["sequences"]
        assert seqs[0]["auth_epoch"] is None
        # casefile은 auth_epoch이 없어도 assoc_epoch으로 시각을 특정한다.
        assert seqs[0]["assoc_epoch"] == 1500.0


class TestUnmeasurableIntegration:
    """gap 측정 불가 시퀀스가 **파이프라인 전 경로**를 통과하는지.

    회귀 근거: 단위 테스트는 전부 통과했는데 실제 분석이 500으로 죽었다.
    `delay_analysis._find_cause`가 `seq.get("auth_epoch", 0) - start_epoch`을
    수행했고, auth_epoch이 None이라 TypeError였다 — 키가 있고 값이 None이면
    `.get(k, 0)`은 0이 아니라 None을 준다. 소비자를 개별로 보는 것만으로는
    부족하고 실제 데이터 흐름을 통과시켜야 잡힌다.
    """

    def _roaming_with_unmeasurable(self):
        from analyzer.web.structured import _structured_roaming

        frames = [
            _auth_req(1, 1000.000), _reassoc(2, 1000.006),
            _reassoc(3, 1010.500),      # 앵커 없음 → auth_epoch=None
        ]
        return _structured_roaming(frames, ROLES)

    def test_analyze_delays_survives_null_auth_epoch(self):
        from analyzer.web.delay_analysis import analyze_delays

        roaming = self._roaming_with_unmeasurable()
        ping = {
            "full_list": [
                {"epoch": 1010.4, "status": "loss", "rtt_ms": None},
                {"epoch": 1010.6, "status": "loss", "rtt_ms": None},
            ]
        }
        out = analyze_delays(ping, roaming, {"timeline": []})
        assert out["delay_zones"], "지연 구간이 나와야 한다"
        # 측정 불가라도 Assoc 시각으로 로밍이 원인 후보에 남아야 한다.
        assert out["delay_zones"][0]["cause"] == "roaming"

    def test_full_pipeline_with_unmeasurable_roam(self):
        """run_analysis 전 구간 — 500을 냈던 그 경로."""
        from analyzer.core.indexer import FrameIndex
        from analyzer.web.delay_analysis import analyze_delays
        from analyzer.web.evidence import build_debug_block
        from analyzer.web.structured import (
            _structured_diagnosis,
            _structured_per_second,
            _structured_roaming,
        )

        frames = [
            _auth_req(1, 1000.000), _reassoc(2, 1000.006),
            _reassoc(3, 1010.500),                       # 측정 불가
            make_frame(number=4, epoch=1010.6, subtype="40", ta=STA1, ra=AP1),
        ]
        # 합성 프레임 4개로는 detect_roles가 STA를 식별하지 못하므로 명시 지정.
        roles = ROLES
        index = FrameIndex(frames, roles)
        structured = {
            "roaming": _structured_roaming(frames, roles),
            "per_second": _structured_per_second(frames),
            "ping": {"full_list": [], "stats": {}},
            "signal": {"stas": {}, "aps": {}},
            "overview": {"total_frames": len(frames), "retry_pct": 0, "devices": []},
            "device_stats": {},
            "signal_cliffs": {},
            "anomaly_frames": {},
        }
        structured["delay_zones"] = analyze_delays(
            structured["ping"], structured["roaming"], structured["per_second"]
        )
        structured["diagnosis"] = _structured_diagnosis(structured, frames, index)
        structured["debug"] = build_debug_block(structured, frames, index, roles)
        # 여기까지 예외 없이 오면 통과. 측정 불가 시퀀스도 살아 있어야 한다.
        seqs = structured["roaming"]["sequences"]
        assert len(seqs) == 2
        assert seqs[1]["gap_ms"] is None

    def test_report_and_casefile_render_with_unmeasurable(self):
        from analyzer.web.report import _roaming_section

        roaming = self._roaming_with_unmeasurable()
        lines = _roaming_section({"roaming": roaming})
        assert lines and "측정불가" in "\n".join(lines)


class TestHealthScoreDenominator:
    """측정 불가 시퀀스가 건강도 점수 분모를 오염시키지 않는지.

    이건 예외를 내지 않아 조용히 틀린다 — 측정 불가를 "느리지 않음"으로 세면
    느린 로밍 비율이 희석돼 **캡처가 나쁠수록 건강해 보이는** 역전이 생긴다.
    """

    def _diag(self, seqs):
        from analyzer.web.structured import _structured_diagnosis

        structured = {
            "overview": {"total_frames": 1000, "retry_pct": 0, "devices": []},
            "ping": {"full_list": [], "stats": {}},
            "roaming": {"sequences": seqs, "roaming_frame_count": len(seqs)},
            "signal": {"stas": {}, "aps": {}},
            "device_stats": {},
            "delay_zones": {"delay_zones": []},
            "anomaly_frames": {},
            "signal_cliffs": {},
        }
        return _structured_diagnosis(structured, [], None)

    def _seq(self, gap_ms, sta=STA1):
        return {
            "sta": sta, "sta_name": "STA1", "ap": AP1, "ap_name": "AP1",
            "gap_ms": gap_ms, "is_slow": gap_ms is not None and gap_ms > 100,
            "assoc_epoch": 1000.0, "auth_epoch": None if gap_ms is None else 999.9,
            "assoc_type": "ReassocReq",
        }

    def test_unmeasurable_not_counted_as_fast(self):
        """측정 4건 중 2건이 느림 → 50%여야 한다. 측정 불가 6건이 희석하면 안 된다."""
        seqs = [self._seq(5.0), self._seq(5.0), self._seq(350.0), self._seq(350.0)]
        seqs += [self._seq(None) for _ in range(6)]
        d = self._diag(seqs)
        # 느린 비율 50% → roam_score = 100 - 50*2 = 0
        assert d["component_scores"]["roaming"] == 0
        # 분모와 판정 불가 건수가 드러나야 한다.
        assert d["summary"]["roaming_total"] == 10
        assert d["summary"]["roaming_measurable"] == 4
        assert d["summary"]["roaming_unmeasured"] == 6

    def test_all_unmeasurable_is_unknown_not_perfect(self):
        """전량 측정 불가면 만점이 아니라 '측정 불가'(None)여야 한다."""
        d = self._diag([self._seq(None) for _ in range(5)])
        assert d["component_scores"]["roaming"] is None
        assert d["summary"]["roaming_measurable"] == 0
        assert d["summary"]["roaming_unmeasured"] == 5

    def test_no_roaming_still_scores_full(self):
        """로밍 자체가 없는 건 '문제 없음'이라 만점 유지(기존 동작)."""
        d = self._diag([])
        assert d["component_scores"]["roaming"] == 100

    def test_sta_score_excludes_unmeasurable_from_denominator(self):
        seqs = [self._seq(350.0), self._seq(5.0)] + [self._seq(None) for _ in range(8)]
        d = self._diag(seqs)
        sta = [x for x in d["sta_diags"] if x.get("name") == "STA1"]
        if sta:   # sta_diags는 device_stats 유무에 따라 비어 있을 수 있다
            # 측정 2건 중 1건 느림 = 50% → s_roam = 100 - 50*2 = 0
            assert sta[0]["scores"]["roaming"] in (0, None)


class TestTotalRoamMs:
    """로밍 **전체** 소요(Auth 요청 → 4-way 완료).

    `gap_ms`(Auth→Reassoc)는 전체의 일부일 뿐이다 — 실측 중앙값 기준 전체
    25.1ms 중 gap이 5.3ms이고 4-way가 19.5ms다. gap만 보면 로밍 비용이
    1/5로 과소평가돼 "장치 로그는 50ms인데 pcap은 10ms 언더"가 된다.
    """

    def _eapol(self, number, epoch, msgnr, to_sta):
        return make_frame(
            number=number, epoch=epoch, subtype="40", protocol="EAPOL",
            eapol_msgnr=str(msgnr),
            ta=(AP1 if to_sta else STA1), ra=(STA1 if to_sta else AP1),
        )

    def _frames(self):
        return [
            _auth_req(1, 1000.000),
            _reassoc(2, 1000.005),
            self._eapol(3, 1000.008, 1, True),
            self._eapol(4, 1000.010, 2, False),
            self._eapol(5, 1000.020, 3, True),
            self._eapol(6, 1000.025, 4, False),
        ]

    def _seq(self, frames):
        from analyzer.core.modules.eapol import build_handshakes
        from analyzer.web.structured import _structured_roaming

        hs = build_handshakes(frames, ROLES)["handshakes"]
        return _structured_roaming(frames, ROLES, handshakes=hs)["sequences"]

    def test_total_is_auth_to_four_way_end(self):
        s = self._seq(self._frames())[0]
        assert s["gap_ms"] == 5.0
        assert s["four_way_ms"] == 17.0
        # 단순 합(22.0)이 아니라 실제 종료 시각 기준 25.0이어야 한다 —
        # Reassoc 요청 ~ 4-way 시작 사이 대기(3ms)가 빠지면 안 된다.
        assert s["total_roam_ms"] == 25.0
        assert s["total_basis"] == "four_way"
        assert s["total_note"] == ""

    def test_total_exceeds_gap(self):
        """전체가 gap보다 작아질 수 없다 — 이 관계가 깨지면 계산이 틀린 것."""
        s = self._seq(self._frames())[0]
        assert s["total_roam_ms"] > s["gap_ms"]

    def test_no_four_way_leaves_total_unknown(self):
        """4-way를 못 찾으면 전체 소요를 지어내지 않는다(FT이거나 EAPOL 미포착)."""
        frames = [_auth_req(1, 1000.000), _reassoc(2, 1000.005)]
        s = self._seq(frames)[0]
        assert s["gap_ms"] == 5.0
        assert s["four_way_ms"] is None
        assert s["total_roam_ms"] is None
        assert s["total_basis"] is None
        assert "4-way" in s["total_note"]

    def test_unmeasurable_gap_also_has_no_total(self):
        """Auth 앵커가 없으면 시작 시각을 몰라 전체도 계산 불가."""
        frames = [
            _auth_req(1, 1000.000), _reassoc(2, 1000.005),
            _reassoc(3, 1050.000),          # 앵커 없음
        ]
        seqs = self._seq(frames)
        assert seqs[1]["gap_ms"] is None
        assert seqs[1]["total_roam_ms"] is None
        assert "Auth 프레임 미포착" in seqs[1]["total_note"]

    def test_report_shows_total_column(self):
        from analyzer.web.report import _roaming_section

        seqs = self._seq(self._frames())
        body = "\n".join(_roaming_section({"roaming": {"sequences": seqs}}))
        assert "전체(ms)" in body
        assert "25.0" in body
        assert "Auth 요청 → 4-way 완료" in body   # 열 의미 설명

    def test_ai_prompt_includes_total_and_warns(self):
        from ai.prompts import _build_roaming_section

        seqs = self._seq(self._frames())
        body = "\n".join(_build_roaming_section({"sequences": seqs}))
        assert "total_roam_ms" in body
        assert "로밍 실소요" in body
        # gap만 보고 판단하지 말라는 안내가 있어야 한다.
        assert "total_roam_ms로 할 것" in body


class TestSlowJudgedOnTotal:
    """느린 로밍 판정 기준을 gap → **전체 소요(total_roam_ms)** 로 옮긴 것.

    gap에만 임계를 걸면 전체 25.2ms 중 5.3ms 구간만 보게 돼, 4-way가 길어 실제로
    느린 로밍을 놓친다 — 실측에서 gap 6.3ms / 4-way 41.7ms / 전체 105.0ms인 건이
    "정상"으로 분류되고 있었다.

    total이 없어도(4-way 미포착) **total ≥ gap 이 항상 성립**하므로 gap이 이미
    임계를 넘으면 확정적으로 느리다 — 아는 정보를 버리지 않는다.
    """

    def _eapol(self, number, epoch, msgnr, to_sta):
        return make_frame(
            number=number, epoch=epoch, subtype="40", protocol="EAPOL",
            eapol_msgnr=str(msgnr),
            ta=(AP1 if to_sta else STA1), ra=(STA1 if to_sta else AP1),
        )

    def _seq(self, frames):
        from analyzer.core.modules.eapol import build_handshakes
        from analyzer.web.structured import _structured_roaming

        hs = build_handshakes(frames, ROLES)["handshakes"]
        return _structured_roaming(frames, ROLES, handshakes=hs)["sequences"]

    def _roam(self, base, gap_s, four_way_span_s, n0=1):
        """gap 후 4-way가 four_way_span_s 동안 진행되는 로밍 프레임 세트."""
        t_auth = base
        t_assoc = base + gap_s
        t1 = t_assoc + 0.001
        t4 = t1 + four_way_span_s
        return [
            _auth_req(n0, t_auth), _reassoc(n0 + 1, t_assoc),
            self._eapol(n0 + 2, t1, 1, True),
            self._eapol(n0 + 3, t1 + four_way_span_s * 0.3, 2, False),
            self._eapol(n0 + 4, t1 + four_way_span_s * 0.6, 3, True),
            self._eapol(n0 + 5, t4, 4, False),
        ]

    def test_fast_gap_but_slow_total_is_flagged(self):
        """실측에서 놓치던 패턴 — gap 6ms인데 4-way가 길어 전체 105ms."""
        s = self._seq(self._roam(1000.0, gap_s=0.006, four_way_span_s=0.098))[0]
        assert s["gap_ms"] < 100                 # gap만 보면 정상
        assert s["total_roam_ms"] > 100
        assert s["is_slow"] is True              # 전체 기준이라 잡힌다
        assert s["slow_basis"] == "total"

    def test_fast_total_not_flagged(self):
        s = self._seq(self._roam(1000.0, gap_s=0.005, four_way_span_s=0.018))[0]
        assert s["total_roam_ms"] < 100
        assert s["is_slow"] is False
        assert s["slow_basis"] == "total"

    def test_no_four_way_but_gap_over_threshold_is_confirmed_slow(self):
        """total ≥ gap 이므로 gap이 이미 임계를 넘으면 확정적으로 느리다."""
        frames = [_auth_req(1, 1000.0), _reassoc(2, 1000.15)]   # gap 150ms, 4-way 없음
        s = self._seq(frames)[0]
        assert s["total_roam_ms"] is None
        assert s["is_slow"] is True
        assert s["slow_basis"] == "gap_lower_bound"

    def test_no_four_way_and_fast_gap_is_undecided(self):
        """gap은 빠른데 4-way를 못 봤으면 전체가 느렸을 수도 있다 — 판정 불가."""
        frames = [_auth_req(1, 1000.0), _reassoc(2, 1000.005)]
        s = self._seq(frames)[0]
        assert s["total_roam_ms"] is None
        assert s["is_slow"] is False
        assert s["slow_basis"] is None      # '정상'이 아니라 '모름'

    def test_undecided_excluded_from_health_denominator(self):
        """판정 불가는 건강도 분모에서 빠져야 한다 — 정상으로 세면 점수가 부풀려진다."""
        from analyzer.web.structured import _structured_diagnosis

        seqs = [
            {"sta": STA1, "sta_name": "STA1", "ap": AP1, "ap_name": "AP1",
             "gap_ms": 5.0, "total_roam_ms": 150.0, "is_slow": True,
             "slow_basis": "total", "assoc_epoch": 1000.0, "auth_epoch": 999.9,
             "assoc_type": "ReassocReq"},
            {"sta": STA1, "sta_name": "STA1", "ap": AP1, "ap_name": "AP1",
             "gap_ms": 5.0, "total_roam_ms": 20.0, "is_slow": False,
             "slow_basis": "total", "assoc_epoch": 1001.0, "auth_epoch": 1000.9,
             "assoc_type": "ReassocReq"},
        ] + [
            {"sta": STA1, "sta_name": "STA1", "ap": AP1, "ap_name": "AP1",
             "gap_ms": 5.0, "total_roam_ms": None, "is_slow": False,
             "slow_basis": None, "assoc_epoch": 1002.0 + i, "auth_epoch": 1001.9 + i,
             "assoc_type": "ReassocReq"}
            for i in range(8)
        ]
        structured = {
            "overview": {"total_frames": 1000, "retry_pct": 0, "devices": []},
            "ping": {"full_list": [], "stats": {}},
            "roaming": {"sequences": seqs, "roaming_frame_count": len(seqs)},
            "signal": {"stas": {}, "aps": {}}, "device_stats": {},
            "delay_zones": {"delay_zones": []}, "anomaly_frames": {}, "signal_cliffs": {},
        }
        d = _structured_diagnosis(structured, [], None)
        # 판정 가능 2건 중 1건 느림 = 50% → roam_score = 100 - 50*2 = 0
        assert d["summary"]["roaming_measurable"] == 2
        assert d["summary"]["roaming_unmeasured"] == 8
        assert d["component_scores"]["roaming"] == 0

    def test_text_and_structured_agree_on_slow_count(self):
        """화면과 텍스트 리포트가 같은 느린 로밍 건수를 봐야 한다."""
        frames = (self._roam(1000.0, 0.006, 0.098, n0=1)
                  + self._roam(1100.0, 0.005, 0.018, n0=11))
        seqs = self._seq(frames)
        n_struct = sum(1 for s in seqs if s["is_slow"])
        section = analyze(frames, ROLES)
        assert n_struct == 1
        assert f"느린로밍(전체 소요 >100ms) {n_struct}건" in section.summary


class TestStaScoresWithUndecided:
    """STA별 점수도 판정 불가를 견뎌야 한다.

    회귀 근거: `s_roam=None`을 그대로 `round()`에 넘겨 `TypeError: type NoneType
    doesn't define __round__`로 **분석 전체가 죽었다**. 일반 테스트는 device_stats를
    비워둬 sta_diags 자체가 안 만들어져 놓쳤고, tshark 골든 테스트에서만 잡혔다 —
    sta_diags가 실제로 생성되는 입력으로 검증해야 한다.
    """

    def _diag(self, seqs):
        from analyzer.web.structured import _structured_diagnosis

        structured = {
            "overview": {"total_frames": 1000, "retry_pct": 1.0, "devices": []},
            "ping": {"full_list": [], "stats": {}},
            "roaming": {"sequences": seqs, "roaming_frame_count": len(seqs)},
            # sta_diags 루프는 signal.stas의 "mac"으로 로밍 시퀀스를 매칭한다.
            "signal": {"stas": {"STA1": {"mac": STA1, "rssi_avg": -55,
                                         "rssi_min": -70}}, "aps": {}},
            # sta_diags는 device_stats가 있어야 만들어진다 — 이게 있어야 회귀를 잡는다.
            "device_stats": {
                "STA1": {"mac": STA1, "role": "STA", "total_frames": 500,
                         "retry_pct": 1.0, "rssi_stats": {"avg": -55, "min": -70}},
            },
            "delay_zones": {"delay_zones": []},
            "anomaly_frames": {}, "signal_cliffs": {},
        }
        return _structured_diagnosis(structured, [], None)

    def _seq(self, total, basis, slow):
        return {
            "sta": STA1, "sta_name": "STA1", "ap": AP1, "ap_name": "AP1",
            "gap_ms": 5.0, "total_roam_ms": total, "is_slow": slow,
            "slow_basis": basis, "assoc_epoch": 1000.0, "auth_epoch": 999.995,
            "assoc_type": "ReassocReq",
        }

    def test_all_undecided_gives_none_score_not_crash(self):
        d = self._diag([self._seq(None, None, False) for _ in range(4)])
        sta = [x for x in d["sta_diags"] if x["name"] == "STA1"]
        assert sta, "sta_diags가 만들어져야 이 회귀를 잡는다"
        # 0(최악)도 100(만점)도 아닌 None이어야 한다.
        assert sta[0]["scores"]["roaming"] is None
        assert isinstance(sta[0]["score"], int)      # 종합 점수는 재정규화로 계산됨
        assert sta[0]["metrics"]["roaming_measurable"] == 0

    def test_mixed_uses_only_decided_in_denominator(self):
        seqs = [self._seq(150.0, "total", True), self._seq(20.0, "total", False)]
        seqs += [self._seq(None, None, False) for _ in range(6)]
        d = self._diag(seqs)
        sta = [x for x in d["sta_diags"] if x["name"] == "STA1"][0]
        assert sta["metrics"]["roaming_count"] == 8
        assert sta["metrics"]["roaming_measurable"] == 2
        assert sta["metrics"]["slow_roaming"] == 1
        # 판정 2건 중 1건 느림 = 50% → s_roam = 100 - 50*200/100 = 0
        assert sta["scores"]["roaming"] == 0

    def test_report_omits_unknown_roaming_score(self):
        from analyzer.web.report import _sta_diags_section

        d = self._diag([self._seq(None, None, False) for _ in range(3)])
        lines = _sta_diags_section(d, None)
        score_line = next(x for x in lines if "세부 점수" in x)
        # 로밍 점수는 빠지되 다른 축은 남아야 한다 (0으로 찍히면 안 된다).
        assert "Retry" in score_line and "RSSI" in score_line
        assert "로밍" not in score_line
        # 메트릭에는 판정 분모가 병기돼 "느린 로밍 0회"가 정상으로 오독되지 않아야 한다.
        metric_line = next(x for x in lines if "메트릭" in x)
        assert "판정 0/3회" in metric_line


class TestRetransmittedAssoc:
    """802.11 재전송 사본이 별개 로밍으로 세어지면 안 된다.

    앵커를 소비 즉시 폐기(규칙 3)하므로, 같은 교환의 Assoc/Reassoc이 재전송돼
    두 번 잡히면 두 번째는 앵커를 찾지 못해 **측정 불가 시퀀스가 하나 더** 생긴다.
    로밍 횟수와 측정 불가 건수가 함께 부풀려지고 STA 로그도 두 번 붙는다.
    다중 스니퍼 시각 보정 뒤 retry가 original보다 먼저 정렬될 수 있고, 같은
    association 시도의 새-seq 재요청은 retry=False일 수 있으므로 retry 비트에만
    의존하지 않는다. Auth 없이 같은 STA→AP·subtype이 짧은 창 안에 반복될 때 묶는다.
    """

    def _auth_then_assoc(self, *, retry_at=None, retry_flag=True, subtype="2"):
        frames = [
            make_frame(number=1, epoch=1000.0, subtype="11", ta=STA1, ra=AP2),
            make_frame(number=2, epoch=1000.005, subtype=subtype, ta=STA1, ra=AP2),
        ]
        if retry_at is not None:
            frames.append(make_frame(number=3, epoch=retry_at, subtype=subtype,
                                     ta=STA1, ra=AP2, retry=retry_flag))
        return frames

    def test_retry_copy_does_not_create_second_sequence(self):
        pairs = pair_roaming_sequences(
            self._auth_then_assoc(retry_at=1000.02), STA_MACS)
        assert len(pairs) == 1
        assert pairs[0].gap_ms is not None      # 측정 불가가 새로 생기지 않는다

    def test_retry_false_reassoc_inside_attempt_window_is_merged(self):
        """retry=False여도 새 Auth 없는 짧은 재요청은 같은 association 시도다."""
        pairs = pair_roaming_sequences(
            self._auth_then_assoc(retry_at=1000.02, retry_flag=False), STA_MACS)
        assert len(pairs) == 1

    def test_retry_outside_window_counts_separately(self):
        pairs = pair_roaming_sequences(
            self._auth_then_assoc(retry_at=1002.0), STA_MACS)
        assert len(pairs) == 2

    def test_first_copy_may_itself_be_a_retry(self):
        """원본을 놓치고 재전송만 잡혔으면 그게 그 로밍의 유일한 프레임이다."""
        frames = [
            make_frame(number=1, epoch=1000.0, subtype="11", ta=STA1, ra=AP2),
            make_frame(number=2, epoch=1000.005, subtype="2", ta=STA1, ra=AP2,
                       retry=True),
        ]
        pairs = pair_roaming_sequences(frames, STA_MACS)
        assert len(pairs) == 1 and pairs[0].gap_ms is not None

    def test_different_subtype_is_not_a_retry_copy(self):
        """AssocReq 뒤의 ReassocReq는 재전송이 아니라 다른 교환이다."""
        frames = [
            make_frame(number=1, epoch=1000.0, subtype="11", ta=STA1, ra=AP2),
            make_frame(number=2, epoch=1000.005, subtype="0", ta=STA1, ra=AP2),
            make_frame(number=3, epoch=1000.02, subtype="2", ta=STA1, ra=AP2,
                       retry=True),
        ]
        assert len(pair_roaming_sequences(frames, STA_MACS)) == 2


class TestClassifySlowSingleSource:
    """느린 로밍 판정 규칙은 한 곳에만 있어야 한다.

    이 PR이 고친 gap 허위 보고의 근원이 짝짓기 로직 복제였다 — 판정 규칙까지
    복제되면 텍스트 리포트와 화면이 서로 다른 건수를 말하게 된다.
    """

    def test_total_decides_when_known(self):
        from analyzer.core.modules.roaming import SLOW_THRESHOLD_MS, classify_slow

        assert classify_slow(SLOW_THRESHOLD_MS + 1, 1.0) == (True, "total")
        assert classify_slow(SLOW_THRESHOLD_MS - 1, 1.0) == (False, "total")

    def test_sta_total_takes_priority_at_150ms(self):
        """STA 로그가 붙으면 pcap 100ms가 아니라 체감 150ms로 판정한다."""
        from analyzer.core.modules.roaming import classify_slow

        # pcap만 보면 느리지만 STA 체감은 150ms 이하 — 정상.
        assert classify_slow(120.0, 5.0, 149.0) == (False, "sta_log_total")
        # pcap은 빨라도 STA 체감이 150ms 초과 — 느림.
        assert classify_slow(25.0, 5.0, 151.0) == (True, "sta_log_total")
        # 경계값 자체는 낮은 단계에 포함한다.
        assert classify_slow(120.0, 5.0, 150.0) == (False, "sta_log_total")

    def test_gap_over_threshold_is_confirmed_slow_without_total(self):
        """total ≥ gap 이므로 gap이 이미 임계를 넘으면 전체도 반드시 넘는다."""
        from analyzer.core.modules.roaming import SLOW_THRESHOLD_MS, classify_slow

        assert classify_slow(None, SLOW_THRESHOLD_MS + 1) == (True, "gap_lower_bound")

    def test_undecidable_is_not_normal(self):
        from analyzer.core.modules.roaming import SLOW_THRESHOLD_MS, classify_slow

        assert classify_slow(None, SLOW_THRESHOLD_MS - 1) == (False, None)
        assert classify_slow(None, None) == (False, None)

    def test_structured_and_text_use_the_same_helper(self):
        """화면(structured)과 텍스트(roaming.analyze)가 같은 판정을 낸다."""
        import inspect

        from analyzer.core.modules import roaming as roaming_mod
        from analyzer.web import structured as structured_mod

        assert "apply_slow_classification" in inspect.getsource(
            structured_mod._structured_roaming
        )
        assert "classify_slow" in inspect.getsource(roaming_mod.analyze)
        assert "classify_slow" in inspect.getsource(roaming_mod.SequenceInfo.is_slow.fget)
