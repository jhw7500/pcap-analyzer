"""causality 모듈 단위 테스트 — 시간 윈도우가 겹치는 single-signal issue를
종합 correlation으로 묶고 confidence를 산출하는 로직 검증.
"""
from analyzer.core.modules.causality import (
    SIG_WEAK_RSSI,
    SIG_HIGH_RETRY,
    SIG_SLOW_ROAMING,
    SIG_HIGH_LOSS,
    build_correlations,
    _overlap_ratio,
    _confidence,
    _cluster_signals,
)


def _make_issue(signal_type, start, end, refs, msg="msg", severity="medium"):
    return {
        "severity": severity,
        "msg": msg,
        "action": "...",
        "signal_type": signal_type,
        "time_window": {"start_epoch": start, "end_epoch": end},
        "frame_refs": list(refs),
    }


def _diag(stas):
    """stas = [(name, mac, [issue, ...]), ...]"""
    return {
        "sta_diags": [
            {"name": name, "mac": mac, "issues": issues}
            for name, mac, issues in stas
        ]
    }


# ── _overlap_ratio ────────────────────────────────────────────────────────

def test_overlap_full_inside_smaller():
    """작은 윈도우가 큰 윈도우 안에 완전 포함 → 1.0."""
    w1 = {"start_epoch": 100.0, "end_epoch": 110.0}   # 10s
    w2 = {"start_epoch": 90.0,  "end_epoch": 130.0}   # 40s
    assert _overlap_ratio(w1, w2) == 1.0


def test_overlap_partial():
    """절반 겹침 → 0.5."""
    w1 = {"start_epoch": 100.0, "end_epoch": 110.0}   # 10s
    w2 = {"start_epoch": 105.0, "end_epoch": 115.0}   # 10s, 5s 겹침
    assert _overlap_ratio(w1, w2) == 0.5


def test_overlap_disjoint():
    w1 = {"start_epoch": 100.0, "end_epoch": 110.0}
    w2 = {"start_epoch": 200.0, "end_epoch": 210.0}
    assert _overlap_ratio(w1, w2) == 0.0


def test_overlap_invalid_window_returns_zero():
    assert _overlap_ratio({}, {"start_epoch": 1, "end_epoch": 2}) == 0.0
    assert _overlap_ratio(None, None) == 0.0  # type: ignore[arg-type]


# ── _cluster_signals ──────────────────────────────────────────────────────

def test_cluster_groups_overlapping_signals_for_same_sta():
    sigs = [
        {"sta_mac": "AA", "signal_type": "weak_rssi",
         "time_window": {"start_epoch": 100, "end_epoch": 110}},
        {"sta_mac": "AA", "signal_type": "high_retry",
         "time_window": {"start_epoch": 102, "end_epoch": 108}},
    ]
    clusters = _cluster_signals(sigs)
    assert len(clusters) == 1
    assert len(clusters[0]) == 2


def test_cluster_separates_different_stas():
    sigs = [
        {"sta_mac": "AA", "signal_type": "weak_rssi",
         "time_window": {"start_epoch": 100, "end_epoch": 110}},
        {"sta_mac": "BB", "signal_type": "weak_rssi",
         "time_window": {"start_epoch": 100, "end_epoch": 110}},
    ]
    clusters = _cluster_signals(sigs)
    assert len(clusters) == 2


def test_cluster_separates_disjoint_windows():
    sigs = [
        {"sta_mac": "AA", "signal_type": "weak_rssi",
         "time_window": {"start_epoch": 100, "end_epoch": 110}},
        {"sta_mac": "AA", "signal_type": "high_retry",
         "time_window": {"start_epoch": 200, "end_epoch": 210}},
    ]
    clusters = _cluster_signals(sigs)
    assert len(clusters) == 2


# ── _confidence ───────────────────────────────────────────────────────────

def test_confidence_increases_with_distinct_signal_count():
    base_window = {"start_epoch": 100, "end_epoch": 110}
    c2 = _confidence([
        {"signal_type": SIG_WEAK_RSSI, "time_window": base_window},
        {"signal_type": SIG_HIGH_RETRY, "time_window": base_window},
    ])
    c3 = _confidence([
        {"signal_type": SIG_WEAK_RSSI, "time_window": base_window},
        {"signal_type": SIG_HIGH_RETRY, "time_window": base_window},
        {"signal_type": SIG_SLOW_ROAMING, "time_window": base_window},
    ])
    assert c2 < c3
    assert c2 <= 0.95
    assert c3 <= 0.95


def test_confidence_duplicate_types_do_not_inflate():
    """같은 타입 중복은 confidence를 키우지 않음."""
    base_window = {"start_epoch": 100, "end_epoch": 110}
    c_single_dup = _confidence([
        {"signal_type": SIG_WEAK_RSSI, "time_window": base_window},
        {"signal_type": SIG_WEAK_RSSI, "time_window": base_window},
    ])
    c_two_distinct = _confidence([
        {"signal_type": SIG_WEAK_RSSI, "time_window": base_window},
        {"signal_type": SIG_HIGH_RETRY, "time_window": base_window},
    ])
    assert c_single_dup < c_two_distinct


# ── build_correlations ────────────────────────────────────────────────────

def test_no_correlations_when_single_signal_only():
    diag = _diag([
        ("STA1", "AA:BB:CC:DD:EE:01",
         [_make_issue(SIG_WEAK_RSSI, 100, 110, [1, 2])]),
    ])
    assert build_correlations(diag) == []


def test_correlation_built_when_signals_overlap():
    diag = _diag([
        ("STA1", "AA:BB:CC:DD:EE:01", [
            _make_issue(SIG_WEAK_RSSI, 100, 110, [1, 2]),
            _make_issue(SIG_HIGH_RETRY, 102, 108, [3, 4]),
        ]),
    ])
    corrs = build_correlations(diag)
    assert len(corrs) == 1
    c = corrs[0]
    assert c["sta_mac"] == "AA:BB:CC:DD:EE:01"
    assert c["confidence"] >= 0.5
    assert set(c["frame_refs"]) == {1, 2, 3, 4}
    assert {s["type"] for s in c["signals"]} == {SIG_WEAK_RSSI, SIG_HIGH_RETRY}


def test_correlation_title_matches_known_combo():
    diag = _diag([
        ("STA1", "AA", [
            _make_issue(SIG_WEAK_RSSI, 100, 110, [1]),
            _make_issue(SIG_HIGH_RETRY, 102, 108, [2]),
            _make_issue(SIG_SLOW_ROAMING, 103, 109, [3]),
        ]),
    ])
    corrs = build_correlations(diag)
    assert len(corrs) == 1
    assert corrs[0]["title"] == "약전계로 인한 multi-symptom"


def test_correlation_title_generic_when_no_rule_matches():
    diag = _diag([
        ("STA1", "AA", [
            # 두 signal이 어떤 TITLE_RULES에도 매칭 안 되는 조합.
            _make_issue("anomaly", 100, 110, [1]),
            _make_issue(SIG_HIGH_LOSS, 102, 108, [2]),
        ]),
    ])
    corrs = build_correlations(diag)
    # HIGH_LOSS는 sta_diags에 들어가지 않는 네트워크 signal이지만 fixture상
    # 강제로 sta_diags 안에 넣으면 클러스터링 됨. 룰 미일치 → generic 제목.
    assert len(corrs) == 1
    assert corrs[0]["title"] == "다중 신호 동시 관찰"


def test_correlations_sorted_by_confidence_desc():
    """STA가 둘이고 한쪽은 2 signal, 다른쪽은 3 signal — 3 signal이 먼저."""
    diag = _diag([
        ("STA1", "AA", [
            _make_issue(SIG_WEAK_RSSI, 100, 110, [1]),
            _make_issue(SIG_HIGH_RETRY, 100, 110, [2]),
        ]),
        ("STA2", "BB", [
            _make_issue(SIG_WEAK_RSSI, 100, 110, [3]),
            _make_issue(SIG_HIGH_RETRY, 100, 110, [4]),
            _make_issue(SIG_SLOW_ROAMING, 100, 110, [5]),
        ]),
    ])
    corrs = build_correlations(diag)
    assert len(corrs) == 2
    assert corrs[0]["sta_mac"] == "BB"
    assert corrs[0]["confidence"] >= corrs[1]["confidence"]


def test_signals_carry_issue_refs():
    """correlation의 signals 항목은 원본 issue 위치를 가리켜야 한다."""
    diag = _diag([
        ("STA1", "AA", [
            _make_issue(SIG_WEAK_RSSI, 100, 110, [1]),
            _make_issue(SIG_HIGH_RETRY, 102, 108, [2]),
        ]),
    ])
    corrs = build_correlations(diag)
    refs_by_type = {s["type"]: s["issue_refs"] for s in corrs[0]["signals"]}
    # 원본 issue 위치(0번 STA, 인덱스 0/1)를 가리켜야 한다.
    assert refs_by_type[SIG_WEAK_RSSI] == [
        {"sta_diag_index": 0, "issue_index": 0}
    ]
    assert refs_by_type[SIG_HIGH_RETRY] == [
        {"sta_diag_index": 0, "issue_index": 1}
    ]


def test_correlation_time_window_is_union():
    diag = _diag([
        ("STA1", "AA", [
            _make_issue(SIG_WEAK_RSSI, 100, 110, [1]),
            _make_issue(SIG_HIGH_RETRY, 105, 120, [2]),
        ]),
    ])
    corrs = build_correlations(diag)
    tw = corrs[0]["time_window"]
    assert tw["start_epoch"] == 100
    assert tw["end_epoch"] == 120
