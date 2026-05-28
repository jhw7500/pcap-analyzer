"""분석 리포트 마크다운 직렬화 단위 테스트.

build_report_markdown은 외부 공유용 산출물의 안정성과 표준 GFM 사양 준수가
중요하므로 섹션별 누락·중복·오류 케이스를 명시적으로 핀.
"""
from analyzer.web.report import (
    build_report_markdown,
    SIGNAL_TYPE_LABEL,
    _format_epoch,
)


def _result(**kw):
    """기본 메타 + structured.diagnosis 구조를 갖춘 result fixture."""
    base = {
        "id": "test-id",
        "pcap_name": "mon1.pcap",
        "pcap_size": 1024,
        "analyzed_at": "2026-05-28 06:00:00",
        "tshark_version": "4.2.2",
        "structured": {
            "overview": {"total_frames": 1000, "duration_sec": 60},
            "diagnosis": {},
        },
    }
    if "structured" in kw:
        base["structured"].update(kw.pop("structured"))
    base.update(kw)
    return base


# ── 메타 섹션 ───────────────────────────────────────────────────────────────

def test_report_header_and_meta_present():
    md = build_report_markdown(_result())
    assert md.startswith("# WLAN Pcap 종합 분석 리포트")
    assert "mon1.pcap" in md
    assert "분석 시각 `2026-05-28 06:00:00`" in md
    assert "tshark `4.2.2`" in md
    assert "프레임 1,000건" in md
    assert "캡처 시간 60s" in md


def test_report_invalid_input_returns_message():
    out1 = build_report_markdown(None)  # type: ignore[arg-type]
    out2 = build_report_markdown("not-a-dict")  # type: ignore[arg-type]
    for out in (out1, out2):
        assert "분석 결과를 불러올 수 없습니다" in out


# ── 건강도 섹션 ────────────────────────────────────────────────────────────

def test_health_section_included_when_present():
    md = build_report_markdown(_result(structured={
        "diagnosis": {
            "health": {"score": 75, "grade": "주의"},
            "component_scores": {"retry": 60, "loss": 80, "roaming": 70},
        },
    }))
    assert "## 네트워크 건강도" in md
    assert "**75** (주의)" in md
    assert "retry=60" in md


def test_health_section_omitted_when_missing():
    md = build_report_markdown(_result())
    assert "## 네트워크 건강도" not in md


# ── 종합 결론(correlations) 섹션 ───────────────────────────────────────────

def test_correlations_section_with_signals_labels():
    """결합 신호 type이 한국어 라벨로 변환되어 표시된다."""
    md = build_report_markdown(_result(structured={
        "diagnosis": {
            "correlations": [{
                "title": "혼잡으로 인한 로밍 영향",
                "confidence": 0.87,
                "sta_name": "STA1", "sta_mac": "AA",
                "time_window": {"start_epoch": 1772000000, "end_epoch": 1772000060},
                "frame_refs": list(range(1, 250)),
                "signals": [{"type": "high_retry"}, {"type": "slow_roaming"}],
                "explanation": "Retry 27% · 슬로우 로밍 3회",
            }],
        },
    }))
    assert "## 종합 진단 (다중 신호 결합)" in md
    assert "### C1: 혼잡으로 인한 로밍 영향 (conf=0.87)" in md
    # signals 라벨 한국어 변환
    assert "retry 폭증" in md
    assert "슬로우 로밍" in md
    # 증거 프레임 수
    assert "249건" in md
    # explanation
    assert "Retry 27%" in md


def test_correlations_c_numbering_continuous_with_invalid_items():
    """non-dict 항목이 섞여도 C1, C2 연속 번호."""
    md = build_report_markdown(_result(structured={
        "diagnosis": {
            "correlations": [
                "stale-string",
                {"title": "First", "confidence": 0.8, "sta_name": "S",
                 "signals": [{"type": "high_retry"}], "frame_refs": [1],
                 "explanation": "x"},
                {"title": "Second", "confidence": 0.7, "sta_name": "S",
                 "signals": [{"type": "weak_rssi"}], "frame_refs": [2],
                 "explanation": "y"},
            ],
        },
    }))
    assert "C1: First" in md
    assert "C2: Second" in md
    assert "C3:" not in md
    assert "stale-string" not in md


def test_correlations_section_omitted_when_empty():
    md = build_report_markdown(_result(structured={
        "diagnosis": {"correlations": []},
    }))
    assert "## 종합 진단 (다중 신호 결합)" not in md


def test_correlations_handles_non_numeric_confidence():
    md = build_report_markdown(_result(structured={
        "diagnosis": {"correlations": [{
            "title": "X", "confidence": "bad",
            "signals": [{"type": "high_retry"}, {"type": "weak_rssi"}],
            "explanation": "x",
        }]},
    }))
    assert "conf=0.00" in md


# ── 단일 진단 결론 표 ──────────────────────────────────────────────────────

def test_issues_table_renders_severity_and_action():
    md = build_report_markdown(_result(structured={
        "diagnosis": {"issues": [
            {"severity": "high", "category": "Retry",
             "msg": "전체 retry 25%", "action": "채널 확인"},
            {"severity": "medium", "category": "Ping",
             "msg": "loss 7%", "action": "AP 위치"},
        ]},
    }))
    assert "## 단일 진단 결론" in md
    assert "| Severity | Category | 문제 | 조치 |" in md
    assert "| high | Retry | 전체 retry 25% | 채널 확인 |" in md
    assert "| medium | Ping | loss 7% | AP 위치 |" in md


def test_issues_table_escapes_pipe_in_msg():
    md = build_report_markdown(_result(structured={
        "diagnosis": {"issues": [
            {"severity": "high", "category": "X", "msg": "a|b|c", "action": "do"},
        ]},
    }))
    # 마크다운 표의 row를 깨뜨리지 않도록 | 가 escape됨
    assert "a\\|b\\|c" in md


# ── STA별 진단 ─────────────────────────────────────────────────────────────

def test_sta_diags_section_includes_metrics_and_issues():
    md = build_report_markdown(_result(structured={
        "diagnosis": {"sta_diags": [{
            "name": "STA1", "mac": "AA:BB", "score": 72,
            "metrics": {"retry_pct": 16.6, "rssi_avg": -62, "roaming_count": 18,
                        "slow_roaming": 3},
            "issues": [
                {"severity": "high", "msg": "Retry율 16.6%", "action": "TX power"},
            ],
        }]},
    }))
    assert "### STA1 `AA:BB`" in md
    assert "**72**/100" in md
    assert "Retry 16.6" in md
    assert "RSSI 평균(dBm) -62" in md
    assert "[high] Retry율 16.6%" in md
    assert "조치: TX power" in md


# ── AI 가설 섹션 ───────────────────────────────────────────────────────────

def test_ai_review_section_appended_when_present():
    md = build_report_markdown(_result(
        ai_review="### C1: ...\n- **가능한 가설**: ...",
    ))
    assert "## AI 가설" in md
    assert "**가능한 가설**" in md


def test_ai_review_section_omitted_when_empty_or_missing():
    md_missing = build_report_markdown(_result())
    md_empty = build_report_markdown(_result(ai_review=""))
    md_whitespace = build_report_markdown(_result(ai_review="   \n  "))
    for md in (md_missing, md_empty, md_whitespace):
        assert "## AI 가설" not in md


# ── 라벨 sync ──────────────────────────────────────────────────────────────

def test_signal_type_label_covers_all_known_types():
    """report.py의 라벨 맵은 causality.py SIG_* 상수와 sync 유지."""
    from analyzer.core.modules.causality import (
        SIG_WEAK_RSSI, SIG_HIGH_RETRY, SIG_SLOW_ROAMING, SIG_FREQUENT_ROAMING,
        SIG_HIGH_LOSS, SIG_DELAY_ZONE, SIG_ANOMALY,
    )
    for stype in (SIG_WEAK_RSSI, SIG_HIGH_RETRY, SIG_SLOW_ROAMING,
                  SIG_FREQUENT_ROAMING, SIG_HIGH_LOSS, SIG_DELAY_ZONE,
                  SIG_ANOMALY):
        assert stype in SIGNAL_TYPE_LABEL, (
            f"causality SIG_{stype.upper()}가 report.SIGNAL_TYPE_LABEL에 없음 — "
            "둘은 의도적으로 sync 유지"
        )


# ── 부록 ──────────────────────────────────────────────────────────────────

def test_report_ends_with_footer_note():
    md = build_report_markdown(_result())
    assert "pcap-analyzer가 생성" in md
    assert "pandoc" in md  # 변환 가이드 한 줄


# ── _format_epoch ───────────────────────────────────────────────────────────

def test_format_epoch_uses_utc_for_determinism():
    """UTC 고정 — 호스트 timezone에 영향받지 않아 같은 분석이 어디서나 같은 출력."""
    out = _format_epoch(1700000000)  # 2023-11-14 22:13:20 UTC
    assert "UTC" in out
    assert "2023-11-14 22:13:20" in out


def test_format_epoch_handles_overflow_without_crashing():
    """매우 큰 epoch이 OverflowError를 일으켜도 빈 문자열 fallback."""
    huge = 10**18  # year 31e10+ — OverflowError 영역
    assert _format_epoch(huge) == ""


def test_format_epoch_handles_invalid_input():
    for bad in (None, "not-a-number", [], {}):
        assert _format_epoch(bad) == ""


# ── isinstance 가드 (gemini medium) ────────────────────────────────────────

def test_correlations_handles_non_list_signals_field():
    """signals가 list 아닌 비정상 입력에서도 crash 없이 라인 생략."""
    md = build_report_markdown(_result(structured={
        "diagnosis": {"correlations": [{
            "title": "X", "confidence": 0.5, "sta_name": "S",
            "signals": "not-a-list",  # ← 잘못된 type
            "frame_refs": [1],
            "explanation": "y",
        }]},
    }))
    assert "X" in md
    assert "결합 신호:" not in md  # signals 라인 자체가 emit 안 됨


def test_correlations_handles_non_list_frame_refs():
    md = build_report_markdown(_result(structured={
        "diagnosis": {"correlations": [{
            "title": "X", "confidence": 0.5, "sta_name": "S",
            "signals": [{"type": "high_retry"}],
            "frame_refs": "not-a-list",
            "explanation": "y",
        }]},
    }))
    assert "X" in md
    assert "증거 프레임:" not in md


def test_health_section_handles_non_dict_input():
    """health/component_scores가 dict 아닌 비정상 입력에서도 crash 없이 누락."""
    md = build_report_markdown(_result(structured={
        "diagnosis": {
            "health": "not-a-dict",
            "component_scores": "not-a-dict",
        },
    }))
    # 둘 다 비dict라 섹션 자체가 누락
    assert "## 네트워크 건강도" not in md


def test_sta_diags_handles_non_dict_metrics_and_issues():
    md = build_report_markdown(_result(structured={
        "diagnosis": {"sta_diags": [{
            "name": "STA1", "mac": "AA", "score": 70,
            "metrics": "not-a-dict",
            "issues": "not-a-list",
        }]},
    }))
    assert "### STA1" in md
    assert "**70**/100" in md
    # metrics/issues는 비정상이라 해당 라인 자체가 emit 안 됨 — crash 없음이 핵심
    assert "메트릭:" not in md
    assert "결론:" not in md


# ── 표 셀 newline escape (gemini medium) ───────────────────────────────────

def test_issues_table_strips_newlines_in_cells():
    """표 셀 안 줄바꿈은 GFM 표 row를 두 row로 분할시키므로 공백으로 치환."""
    md = build_report_markdown(_result(structured={
        "diagnosis": {"issues": [{
            "severity": "high", "category": "X",
            "msg": "line1\nline2", "action": "do1\r\ndo2",
        }]},
    }))
    assert "line1\nline2" not in md
    assert "line1 line2" in md
    assert "do1\r" not in md and "do2" in md


def test_issues_table_sanitises_severity_and_category():
    """severity/category에 pipe/newline이 와도 표 layout 무결성 유지."""
    md = build_report_markdown(_result(structured={
        "diagnosis": {"issues": [{
            "severity": "hi|gh",
            "category": "Re\ntry",
            "msg": "ok", "action": "do",
        }]},
    }))
    assert "hi\\|gh" in md
    assert "Re try" in md
    assert "Re\ntry" not in md


def test_issues_action_falls_back_to_recommendation_field():
    """action 누락 시 recommendation 필드를 fallback으로 사용."""
    md = build_report_markdown(_result(structured={
        "diagnosis": {"issues": [{
            "severity": "high", "category": "X",
            "msg": "문제 메시지",
            "recommendation": "조치 권고만 있는 경우",
        }]},
    }))
    assert "조치 권고만 있는 경우" in md


# ── backtick injection 방어 (claude low) ──────────────────────────────────

def test_pcap_name_backtick_does_not_break_code_span():
    md = build_report_markdown(_result(pcap_name="bad`name.pcap"))
    assert "`badname.pcap`" in md
    assert "bad`name.pcap" not in md


def test_sta_mac_backtick_sanitised():
    md = build_report_markdown(_result(structured={
        "diagnosis": {"sta_diags": [{
            "name": "STA1", "mac": "AA:`evil:01", "score": 70,
        }]},
    }))
    assert "AA:`evil:01" not in md
    assert "AA:evil:01" in md
