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
    _collect_signals,
    _attach_network_signals,
    _window_union,
    _explanation_for,
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
    assert corrs[0]["title"] == "약전계로 인한 multi-symptom (느린 로밍 동반)"


def test_correlation_title_distinguishes_slow_vs_frequent_roaming():
    """동일 multi-symptom 조합이라도 슬로우/잦은 로밍 변종은 제목에서 구분된다."""
    from analyzer.core.modules.causality import SIG_FREQUENT_ROAMING
    diag = _diag([
        ("STA1", "AA", [
            _make_issue(SIG_WEAK_RSSI, 100, 110, [1]),
            _make_issue(SIG_HIGH_RETRY, 102, 108, [2]),
            _make_issue(SIG_FREQUENT_ROAMING, 103, 109, [3]),
        ]),
    ])
    corrs = build_correlations(diag)
    assert len(corrs) == 1
    assert corrs[0]["title"] == "약전계로 인한 multi-symptom (잦은 로밍 동반)"


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
    # scope=sta 신호는 sta_diag_index + issue_index를 가리킨다.
    assert refs_by_type[SIG_WEAK_RSSI] == [
        {"scope": "sta", "sta_diag_index": 0, "issue_index": 0}
    ]
    assert refs_by_type[SIG_HIGH_RETRY] == [
        {"scope": "sta", "sta_diag_index": 0, "issue_index": 1}
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


# ── _overlap_ratio edge cases (review fixes) ──────────────────────────────

def test_overlap_invalid_window_end_before_start():
    """end < start인 잘못된 윈도우는 0.0 반환(방어)."""
    bad = {"start_epoch": 110.0, "end_epoch": 100.0}
    good = {"start_epoch": 100.0, "end_epoch": 110.0}
    assert _overlap_ratio(bad, good) == 0.0
    assert _overlap_ratio(good, bad) == 0.0


def test_overlap_point_inside_interval():
    """점 윈도우가 더 큰 윈도우 안에 있으면 1.0 — sparse evidence 매칭."""
    point = {"start_epoch": 105.0, "end_epoch": 105.0}
    interval = {"start_epoch": 100.0, "end_epoch": 110.0}
    assert _overlap_ratio(point, interval) == 1.0
    assert _overlap_ratio(interval, point) == 1.0


def test_overlap_point_outside_interval():
    point = {"start_epoch": 200.0, "end_epoch": 200.0}
    interval = {"start_epoch": 100.0, "end_epoch": 110.0}
    assert _overlap_ratio(point, interval) == 0.0


def test_overlap_two_same_point():
    p = {"start_epoch": 100.0, "end_epoch": 100.0}
    assert _overlap_ratio(p, p) == 1.0


# ── _window_union edge cases ──────────────────────────────────────────────

def test_window_union_empty_returns_none():
    assert _window_union([]) is None


def test_window_union_all_none_returns_none():
    assert _window_union([None, None]) is None  # type: ignore[list-item]


def test_window_union_mixed_includes_valid():
    out = _window_union([
        None,                                        # type: ignore[list-item]
        {"start_epoch": 100, "end_epoch": 110},
        {"start_epoch": 105, "end_epoch": 120},
    ])
    assert out == {"start_epoch": 100, "end_epoch": 120}


# ── _explanation_for ──────────────────────────────────────────────────────

def test_explanation_uses_msg_only_no_english_keys():
    """[high_retry] 같은 영어 키를 prepend하지 않고 msg만 연결."""
    out = _explanation_for([
        {"signal_type": SIG_WEAK_RSSI, "msg": "RSSI 평균 -70dBm"},
        {"signal_type": SIG_HIGH_RETRY, "msg": "Retry율 30%"},
    ])
    assert out == "RSSI 평균 -70dBm · Retry율 30%"
    assert "[" not in out and "weak_rssi" not in out


def test_explanation_filters_empty_msg():
    out = _explanation_for([
        {"signal_type": SIG_WEAK_RSSI, "msg": "RSSI 약함"},
        {"signal_type": SIG_HIGH_RETRY},  # msg 누락
    ])
    assert out == "RSSI 약함"


# ── _cluster_signals defensive ────────────────────────────────────────────

def test_cluster_handles_missing_sta_mac():
    """sta_mac 키가 누락된 signal도 KeyError 없이 처리."""
    sigs = [
        {"signal_type": SIG_WEAK_RSSI,  # sta_mac 누락
         "time_window": {"start_epoch": 100, "end_epoch": 110}},
        {"signal_type": SIG_HIGH_RETRY,  # sta_mac 누락
         "time_window": {"start_epoch": 100, "end_epoch": 110}},
    ]
    clusters = _cluster_signals(sigs)
    assert len(clusters) == 1


# ── build_correlations defensive ──────────────────────────────────────────

def test_build_correlations_none_input_returns_empty():
    assert build_correlations(None) == []  # type: ignore[arg-type]


def test_build_correlations_non_dict_input_returns_empty():
    assert build_correlations([]) == []  # type: ignore[arg-type]
    assert build_correlations("oops") == []  # type: ignore[arg-type]


# ── _collect_signals + _attach_network_signals (option A 확장) ────────────

def test_collect_signals_separates_sta_and_network():
    """sta_diags issue는 sta 신호로, all_issues 중 STA 카테고리 아닌 것은 network."""
    diag = {
        "sta_diags": [{
            "name": "STA1", "mac": "AA",
            "issues": [
                {"signal_type": SIG_WEAK_RSSI, "msg": "RSSI",
                 "time_window": {"start_epoch": 100, "end_epoch": 110},
                 "frame_refs": [1]},
            ],
        }],
        "issues": [
            # 네트워크 카테고리 — sta name과 다름
            {"category": "Ping", "signal_type": SIG_HIGH_LOSS, "msg": "Loss",
             "time_window": {"start_epoch": 100, "end_epoch": 110},
             "frame_refs": [9]},
            # sta_diags에서 승격된 항목 — 같은 sta name → 중복으로 제외돼야
            {"category": "STA1", "signal_type": SIG_WEAK_RSSI, "msg": "RSSI",
             "time_window": {"start_epoch": 100, "end_epoch": 110},
             "frame_refs": [1]},
        ],
    }
    sta_sigs, net_sigs = _collect_signals(diag)
    assert len(sta_sigs) == 1
    assert sta_sigs[0]["signal_type"] == SIG_WEAK_RSSI
    assert len(net_sigs) == 1
    assert net_sigs[0]["signal_type"] == SIG_HIGH_LOSS
    assert net_sigs[0]["issue_scope"] == "net"


def test_attach_network_signals_joins_overlapping_clusters():
    """network signal이 시간 겹치는 STA cluster에 cross-attach."""
    cluster = [
        {"sta_mac": "AA", "signal_type": SIG_WEAK_RSSI,
         "time_window": {"start_epoch": 100, "end_epoch": 110},
         "frame_refs": [1], "msg": "weak"},
        {"sta_mac": "AA", "signal_type": SIG_HIGH_RETRY,
         "time_window": {"start_epoch": 100, "end_epoch": 110},
         "frame_refs": [2], "msg": "retry"},
    ]
    clusters = [cluster]
    net_signals = [{
        "sta_mac": None, "signal_type": SIG_HIGH_LOSS,
        "time_window": {"start_epoch": 102, "end_epoch": 108},
        "frame_refs": [9], "msg": "loss", "issue_scope": "net",
    }]
    _attach_network_signals(clusters, net_signals)
    assert len(clusters[0]) == 3
    assert any(s["signal_type"] == SIG_HIGH_LOSS for s in clusters[0])


def test_build_correlations_uses_network_signals_to_complete_combo():
    """STA 단일 신호 + 시간 겹치는 network signal → 종합 결론으로 묶임.

    'high_retry + high_loss' 룰이 매칭되어 generic 제목 대신 명시 제목.
    """
    diag = {
        "sta_diags": [{
            "name": "STA1", "mac": "AA",
            "issues": [{
                "signal_type": SIG_HIGH_RETRY, "msg": "Retry율 30%",
                "time_window": {"start_epoch": 100, "end_epoch": 110},
                "frame_refs": [1], "severity": "high",
            }],
        }],
        "issues": [{
            "category": "Ping", "signal_type": SIG_HIGH_LOSS,
            "msg": "Ping Loss 10%",
            "time_window": {"start_epoch": 102, "end_epoch": 108},
            "frame_refs": [9], "severity": "high",
        }],
    }
    corrs = build_correlations(diag)
    assert len(corrs) == 1
    c = corrs[0]
    types = {s["type"] for s in c["signals"]}
    assert SIG_HIGH_RETRY in types and SIG_HIGH_LOSS in types
    assert c["title"] == "혼잡으로 인한 ping loss"
    # network signal의 issue_ref는 scope="net"
    net_refs = next(s["issue_refs"] for s in c["signals"] if s["type"] == SIG_HIGH_LOSS)
    assert net_refs == [{"scope": "net", "issue_index": 0}]


def test_build_correlations_no_correlation_without_sta_signal():
    """sta_diags signal이 0이면 network signal만 있어도 cluster 생성 X."""
    diag = {
        "sta_diags": [],
        "issues": [{
            "category": "Ping", "signal_type": SIG_HIGH_LOSS,
            "time_window": {"start_epoch": 100, "end_epoch": 110},
            "frame_refs": [9], "msg": "loss",
        }],
    }
    assert build_correlations(diag) == []


def test_build_correlations_isolated_from_unknown_input():
    """build_correlations는 예측 가능한 형태로만 동작 — sta_diags 없으면 빈."""
    assert build_correlations({"sta_diags": None, "issues": None}) == []  # type: ignore[dict-item]


def test_correlation_signals_have_no_weight_field():
    """weight = 1/N 균등은 정보량 0이라 필드 자체를 노출하지 않는다."""
    diag = _diag([
        ("STA1", "AA", [
            _make_issue(SIG_WEAK_RSSI, 100, 110, [1]),
            _make_issue(SIG_HIGH_RETRY, 102, 108, [2]),
        ]),
    ])
    corrs = build_correlations(diag)
    for sig in corrs[0]["signals"]:
        assert "weight" not in sig, (
            "weight 필드는 균등 분배라 의미 없어 제거 — consumer 잘못된 기대 방지"
        )


def test_attach_network_signals_uses_any_member_overlap_not_union():
    """cluster union이 아닌 any-member 정책 — cluster 가운데 빈 시간대의
    network 사건이 STA 신호와 시간 안 맞으면 attach 되면 안 된다."""
    cluster = [
        {"sta_mac": "AA", "signal_type": SIG_WEAK_RSSI,
         "time_window": {"start_epoch": 100, "end_epoch": 110},
         "frame_refs": [1], "msg": "weak"},
        {"sta_mac": "AA", "signal_type": SIG_HIGH_RETRY,
         "time_window": {"start_epoch": 200, "end_epoch": 210},
         "frame_refs": [2], "msg": "retry"},
    ]
    clusters = [cluster]
    # network 사건: t=150~160 — union(100~210) 안이지만 멤버 어느 쪽과도 겹침 0.
    net_signals = [{
        "sta_mac": None, "signal_type": SIG_HIGH_LOSS,
        "time_window": {"start_epoch": 150, "end_epoch": 160},
        "frame_refs": [9], "msg": "loss", "issue_scope": "net",
    }]
    _attach_network_signals(clusters, net_signals)
    types = {s["signal_type"] for s in clusters[0]}
    assert SIG_HIGH_LOSS not in types, (
        "union 정책이라면 잘못 attach되겠지만 any-member 정책에선 거부돼야 함"
    )


def test_attach_network_signals_any_member_overlap_with_one_member():
    """cluster 멤버 중 하나라도 시간 겹치면 attach (any-member 정책)."""
    cluster = [
        {"sta_mac": "AA", "signal_type": SIG_WEAK_RSSI,
         "time_window": {"start_epoch": 100, "end_epoch": 110},
         "frame_refs": [1], "msg": "weak"},
        {"sta_mac": "AA", "signal_type": SIG_HIGH_RETRY,
         "time_window": {"start_epoch": 200, "end_epoch": 210},
         "frame_refs": [2], "msg": "retry"},
    ]
    clusters = [cluster]
    # 멤버 B(200~210)와 정확히 겹침.
    net_signals = [{
        "sta_mac": None, "signal_type": SIG_HIGH_LOSS,
        "time_window": {"start_epoch": 205, "end_epoch": 208},
        "frame_refs": [9], "msg": "loss", "issue_scope": "net",
    }]
    _attach_network_signals(clusters, net_signals)
    types = {s["signal_type"] for s in clusters[0]}
    assert SIG_HIGH_LOSS in types
