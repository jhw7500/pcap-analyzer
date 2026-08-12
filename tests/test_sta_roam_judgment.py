"""STA 체감 로밍 판정 승격과 텍스트↔structured 파리티 회귀."""

import inspect

from ai.prompts import _build_roaming_section
from analyzer.core.modules import roaming as roaming_mod
from analyzer.core.modules.roaming import (
    STA_SLOW_POLICY,
    reclassify_roaming_sequences,
    section_from_structured,
)
from analyzer.web.report import _roaming_section


STA = "00:11:22:33:44:55"
AP = "aa:bb:cc:dd:ee:ff"
ROLES = {
    STA: {"role": "STA", "name": "STA1"},
    AP: {"role": "AP", "name": "AP1"},
}


def _seq(*, pcap=25.0, gap=5.0, sta_marker="missing", fnum=1):
    seq = {
        "sta": STA,
        "sta_name": "STA1",
        "ap": AP,
        "ap_name": "AP1",
        "auth_epoch": 1000.0 + fnum,
        "assoc_epoch": 1000.01 + fnum,
        "auth_fnum": fnum,
        "assoc_fnum": fnum + 1,
        "gap_ms": gap,
        "total_roam_ms": pcap,
        "assoc_type": "ReassocReq",
    }
    if sta_marker != "missing":
        seq["sta_log"] = {"total_ms": sta_marker, "source": "1호기"}
    return seq


def _roaming(seqs):
    return {"roaming_frame_count": len(seqs) * 2, "sequences": seqs}


class TestStaPreferredClassification:
    def test_attached_uses_150_and_unmatched_keeps_pcap_100(self):
        attached_fast = _seq(pcap=120.0, sta_marker=149.0, fnum=1)
        attached_slow = _seq(pcap=25.0, sta_marker=151.0, fnum=10)
        unmatched_slow = _seq(pcap=101.0, fnum=20)
        roaming = _roaming([attached_fast, attached_slow, unmatched_slow])

        reclassify_roaming_sequences(roaming)

        assert (attached_fast["is_slow"], attached_fast["slow_basis"]) == (
            False,
            "sta_log_total",
        )
        assert (attached_slow["is_slow"], attached_slow["slow_basis"]) == (
            True,
            "sta_log_total",
        )
        assert (unmatched_slow["is_slow"], unmatched_slow["slow_basis"]) == (
            True,
            "total",
        )
        assert roaming["slow_policy"] == STA_SLOW_POLICY
        assert roaming["slow_thresholds_ms"] == {
            "sta_log_total": 150,
            "pcap_total": 100,
        }

    def test_invalid_sta_value_falls_back_without_crashing(self):
        seqs = [
            _seq(pcap=101.0, sta_marker=None, fnum=1),
            _seq(pcap=101.0, sta_marker=True, fnum=10),
            _seq(pcap=101.0, sta_marker=float("nan"), fnum=20),
        ]
        roaming = _roaming(seqs)
        reclassify_roaming_sequences(roaming)
        assert all(
            (seq["is_slow"], seq["slow_basis"]) == (True, "total")
            for seq in seqs
        )

    def test_no_measurement_remains_undecidable(self):
        seq = _seq(pcap=None, gap=5.0, sta_marker=None)
        roaming = _roaming([seq])
        reclassify_roaming_sequences(roaming)
        assert (seq["is_slow"], seq["slow_basis"]) == (False, None)


class TestStructuredTextParity:
    def test_text_count_comes_from_reclassified_structured(self):
        seqs = [
            _seq(pcap=120.0, sta_marker=149.0, fnum=1),
            _seq(pcap=25.0, sta_marker=151.0, fnum=10),
            _seq(pcap=101.0, fnum=20),
        ]
        roaming = _roaming(seqs)
        reclassify_roaming_sequences(roaming)

        section = section_from_structured(roaming, ROLES)
        assert sum(bool(s["is_slow"]) for s in seqs) == 2
        assert "STA 체감 >150ms / 로그 미매칭 pcap 전체 >100ms" in section.summary
        assert section.summary.endswith("2건")
        body = "\n".join(section.lines)
        assert "STA 체감 151.0ms" in body
        assert "pcap 전체 101.0ms" in body

    def test_pipeline_replaces_fixed_signature_section_after_correlation(self):
        from analyzer import pipeline

        src = inspect.getsource(pipeline.run_analysis)
        reclass_pos = src.index("reclassify_roaming_sequences")
        text_pos = src.index("section_from_structured")
        assert reclass_pos < text_pos


class TestOldResultCompatibility:
    def test_policy_key_absence_keeps_old_prompt_wording(self):
        roaming = _roaming([dict(_seq(pcap=120.0, sta_marker=149.0), is_slow=True)])
        text = "\n".join(_build_roaming_section(roaming))
        assert "느린 로밍(전체 소요 >100ms) 1회" in text
        assert "판정은 여전히 total_roam_ms 기준" in text

    def test_policy_key_absence_keeps_old_report_footnote(self):
        roaming = _roaming([dict(_seq(pcap=120.0, sta_marker=149.0), is_slow=True)])
        text = "\n".join(_roaming_section({"roaming": roaming}))
        assert "느린 로밍 판정은 전체 기준" in text
        assert "느린 로밍 판정은 여전히 전체(ms) 기준" in text

    def test_new_result_explains_sta_precedence(self):
        roaming = _roaming([_seq(pcap=25.0, sta_marker=151.0)])
        reclassify_roaming_sequences(roaming)
        prompt = "\n".join(_build_roaming_section(roaming))
        report = "\n".join(_roaming_section({"roaming": roaming}))
        assert "STA 체감 >150ms" in prompt
        assert "미매칭 pcap 전체 >100ms" in prompt
        assert "STA 로그 매칭 시 체감 >150ms" in report


def test_classification_rule_is_not_duplicated_in_pipeline_or_station_match():
    """판정 비교식은 roaming.classify_slow 한 곳에만 둔다."""
    from analyzer import pipeline
    from analyzer.core import station_match

    for obj in (pipeline.run_analysis, station_match.attach_station_to_sequences):
        src = inspect.getsource(obj)
        assert "STA_ROAM_SLOW_MS" not in src
        assert "> 150" not in src

    assert "STA_ROAM_SLOW_MS" in inspect.getsource(roaming_mod.classify_slow)
