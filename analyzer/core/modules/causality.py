"""다중 신호 인과추론 — 시간 윈도우가 겹치는 single-signal issue들을 묶어
종합 결론(correlation)을 만든다.

기존 진단 결과(issues, sta_diags)는 그대로 두고, 별도 correlations 리스트만
새로 산출한다(추가형 — backwards-compat 완벽). UI 측에서 종합 진단 섹션이
선택적으로 표시.

핵심 가정:
- 같은 STA의 여러 signal이 같은 시간 구간에 동시 관찰되면 인과 관계 가능성이
  높음 (예: 약신호 + retry 폭증 + 슬로우 로밍 = 약전계 가설).
- 시간만 우연히 겹친 가능성도 있어 confidence는 1.0이 되지 않으며 결합
  신호 수와 윈도우 겹침 비율로 산출한다.
"""
import logging
from typing import Any, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

# Signal type constants — issue 객체의 signal_type 필드와 일치.
# msg 문자열 파싱 대신 명시적 type 부여로 견고성 확보.
SIG_WEAK_RSSI = "weak_rssi"
SIG_HIGH_RETRY = "high_retry"
SIG_SLOW_ROAMING = "slow_roaming"
SIG_FREQUENT_ROAMING = "frequent_roaming"
SIG_HIGH_LOSS = "high_loss"
SIG_DELAY_ZONE = "delay_zone"
SIG_ANOMALY = "anomaly"
SIG_MCS_HOTSPOT = "mcs_hotspot"
SIG_SIGNAL_CLIFF = "signal_cliff"
SIG_LEGACY_HEAVY = "legacy_heavy"

# 같은 클러스터로 묶일 수 있는 윈도우 겹침 비율(작은 윈도우 기준).
DEFAULT_OVERLAP_RATIO = 0.5
# correlation 1건의 최소 결합 신호 수.
MIN_CLUSTER_SIZE = 2
# confidence 산출 파라미터.
CONF_BASE = 0.5
CONF_PER_SIGNAL = 0.15
CONF_OVERLAP_BONUS = 0.1
CONF_CAP = 0.95

# 신호 조합별 사람 친화 제목. frozenset 키로 결정적 매칭.
# multi-symptom 룰은 로밍 변종(느린/잦은)을 제목에서 차별화 — 두 룰이 같은
# 제목을 갖던 코드 중복을 제거하면서 사용자에게 로밍 유형 정보를 노출.
TITLE_RULES: List[Tuple[frozenset, str]] = [
    # signal_cliff / mcs_hotspot 결합 — 구체 조합을 generic 2-신호 룰보다 먼저
    # 매칭(.issubset). cliff는 ping loss/retry/로밍/약전계와의 동반을 차별화.
    (frozenset({SIG_SIGNAL_CLIFF, SIG_HIGH_LOSS}),
     "신호 급강하로 인한 ping loss"),
    (frozenset({SIG_SIGNAL_CLIFF, SIG_HIGH_RETRY}),
     "신호 급강하로 인한 retry 폭증"),
    (frozenset({SIG_SIGNAL_CLIFF, SIG_SLOW_ROAMING}),
     "신호 급강하로 인한 로밍 정체"),
    (frozenset({SIG_SIGNAL_CLIFF, SIG_WEAK_RSSI}),
     "신호 급강하 동반 약전계"),
    (frozenset({SIG_WEAK_RSSI, SIG_MCS_HOTSPOT}),
     "약전계로 인한 특정 MCS 재전송"),
    (frozenset({SIG_HIGH_RETRY, SIG_MCS_HOTSPOT}),
     "특정 MCS 집중 retry"),
    (frozenset({SIG_WEAK_RSSI, SIG_HIGH_RETRY, SIG_SLOW_ROAMING}),
     "약전계로 인한 multi-symptom (느린 로밍 동반)"),
    (frozenset({SIG_WEAK_RSSI, SIG_HIGH_RETRY, SIG_FREQUENT_ROAMING}),
     "약전계로 인한 multi-symptom (잦은 로밍 동반)"),
    (frozenset({SIG_WEAK_RSSI, SIG_HIGH_RETRY}),
     "약전계로 인한 retry 폭증"),
    (frozenset({SIG_WEAK_RSSI, SIG_SLOW_ROAMING}),
     "약전계로 인한 로밍 정체"),
    (frozenset({SIG_HIGH_RETRY, SIG_SLOW_ROAMING}),
     "혼잡으로 인한 로밍 영향"),
    (frozenset({SIG_HIGH_RETRY, SIG_HIGH_LOSS}),
     "혼잡으로 인한 ping loss"),
    (frozenset({SIG_WEAK_RSSI, SIG_HIGH_LOSS}),
     "약전계로 인한 ping loss"),
]


def _overlap_ratio(w1: Dict[str, float], w2: Dict[str, float]) -> float:
    """두 time_window의 겹침 비율(작은 윈도우 기준 [0,1]).

    윈도우는 {start_epoch, end_epoch} 구조. 한쪽이 None/비정상이면 0.

    Edge cases:
    - 잘못된 윈도우(end < start)는 0.0 반환(방어).
    - 점 윈도우(start==end)가 다른 윈도우 안에 있으면 1.0 반환 — 단일 evidence
      frame만 있는 issue가 더 큰 retry/RSSI 윈도우와 시간 동기 결합할 수 있도록.
      점이 다른 윈도우 밖이면 0.0.
    """
    if not w1 or not w2:
        return 0.0
    a0, a1 = w1.get("start_epoch"), w1.get("end_epoch")
    b0, b1 = w2.get("start_epoch"), w2.get("end_epoch")
    if not all(isinstance(v, (int, float)) for v in (a0, a1, b0, b1)):
        return 0.0
    if a1 < a0 or b1 < b0:
        return 0.0  # invalid window 방어
    lo = max(a0, b0)
    hi = min(a1, b1)
    inter = max(0.0, hi - lo)
    a_len = max(a1 - a0, 0.0)
    b_len = max(b1 - b0, 0.0)
    smallest = min(a_len, b_len)
    if smallest <= 0.0:
        # 한쪽 또는 양쪽이 점 윈도우. 점이 다른 윈도우 안에 들어있으면 1.0.
        # (양쪽 점이 같은 epoch이어도 같은 분기로 1.0)
        if a_len == 0 and b0 <= a0 <= b1:
            return 1.0
        if b_len == 0 and a0 <= b0 <= a1:
            return 1.0
        return 0.0
    return inter / smallest


def _window_union(windows: Sequence[Dict[str, float]]) -> Optional[Dict[str, float]]:
    """여러 윈도우의 union (min start, max end)."""
    starts = [w.get("start_epoch") for w in windows if w]
    ends = [w.get("end_epoch") for w in windows if w]
    starts = [v for v in starts if isinstance(v, (int, float))]
    ends = [v for v in ends if isinstance(v, (int, float))]
    if not starts or not ends:
        return None
    return {"start_epoch": min(starts), "end_epoch": max(ends)}


def _collect_signals(
    diagnosis: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """진단 결과에서 cluster 후보 signal들을 추출. (sta, network) 튜플 반환.

    - STA signals: sta_diags의 issues 중 signal_type+time_window 보유. 같은
      STA 기준 결합이 인과 신호로 가장 의미 있음.
    - Network signals: diagnosis["issues"](all_issues) 중 sta_diags 카테고리가
      아닌 순수 네트워크 항목(ping loss, 네트워크 retry, 지연 구간, 이상 등).
      sta_diags 승격 항목은 category가 STA name과 일치해 자연 분리된다.
      network signal은 STA 무관이라 cluster 후처리(cross-attach)에서 시간
      윈도우가 겹치는 STA cluster에 추가 신호로 합류시킨다.

    각 signal dict 구조:
        {
            "sta_mac": str | None,      # network signal은 None
            "sta_name": str | None,
            "sta_diag_index": int|None, # network는 None
            "issue_index": int,          # all_issues 또는 sta_diags[i].issues 위치
            "issue_scope": "sta"|"net", # 출처 — UI에서 issue 위치 디스앰비
            "signal_type": str,
            "time_window": dict,
            "frame_refs": list[int],
            "msg": str,
            "severity": str,
        }
    """
    sta_signals: List[Dict[str, Any]] = []
    sta_names: set = set()
    for si, sd in enumerate(diagnosis.get("sta_diags", []) or []):
        mac = sd.get("mac") or ""
        name = sd.get("name") or mac
        sta_names.add(name)
        for ii, issue in enumerate(sd.get("issues", []) or []):
            stype = issue.get("signal_type")
            tw = issue.get("time_window")
            refs = issue.get("frame_refs") or []
            if not stype or not tw:
                continue
            sta_signals.append({
                "sta_mac": mac,
                "sta_name": name,
                "sta_diag_index": si,
                "issue_index": ii,
                "issue_scope": "sta",
                "signal_type": stype,
                "time_window": tw,
                "frame_refs": list(refs),
                "msg": issue.get("msg", ""),
                "severity": issue.get("severity", "medium"),
            })

    net_signals: List[Dict[str, Any]] = []
    for ii, issue in enumerate(diagnosis.get("issues", []) or []):
        stype = issue.get("signal_type")
        tw = issue.get("time_window")
        refs = issue.get("frame_refs") or []
        cat = issue.get("category")
        # sta_diags에서 승격된 카테고리는 STA name과 동일 — 중복 제외.
        if not stype or not tw or cat in sta_names:
            continue
        net_signals.append({
            "sta_mac": None,
            "sta_name": None,
            "sta_diag_index": None,
            "issue_index": ii,
            "issue_scope": "net",
            "signal_type": stype,
            "time_window": tw,
            "frame_refs": list(refs),
            "msg": issue.get("msg", ""),
            "severity": issue.get("severity", "medium"),
        })
    return sta_signals, net_signals


def _cluster_signals(
    signals: Sequence[Dict[str, Any]],
    overlap_threshold: float = DEFAULT_OVERLAP_RATIO,
) -> List[List[Dict[str, Any]]]:
    """같은 STA 내에서 time_window가 충분히 겹치는 signal들을 묶는다.

    단순 그리디 클러스터링: 각 signal에 대해 이미 만들어진 cluster 중 모든
    멤버와 임계 이상 겹치는 첫 cluster에 합류, 없으면 새 cluster 생성.
    동일 signal_type이 중복 들어가는 것은 허용하되, 제목/explanation은
    distinct type 집합으로 결정한다(같은 타입 중복은 confidence에는 기여 X).
    """
    clusters: List[List[Dict[str, Any]]] = []
    # STA별로 분리해서 클러스터링. sta_mac 키 누락 방어를 위해 .get 사용.
    by_sta: Dict[str, List[Dict[str, Any]]] = {}
    for s in signals:
        by_sta.setdefault(s.get("sta_mac") or "", []).append(s)
    for mac, sigs in by_sta.items():
        local: List[List[Dict[str, Any]]] = []
        for s in sigs:
            joined = False
            for cl in local:
                if all(_overlap_ratio(s["time_window"], m["time_window"])
                       >= overlap_threshold for m in cl):
                    cl.append(s)
                    joined = True
                    break
            if not joined:
                local.append([s])
        clusters.extend(local)
    return clusters


def _attach_network_signals(
    clusters: Sequence[List[Dict[str, Any]]],
    net_signals: Sequence[Dict[str, Any]],
    overlap_threshold: float = DEFAULT_OVERLAP_RATIO,
) -> None:
    """network signal이 시간 윈도우 겹치는 STA cluster에 추가 신호로 합류.

    매칭 정책은 **any-member overlap** — cluster의 *어떤* 멤버 윈도우와도
    임계 이상 겹치면 합류. cluster의 union window(t=100~500)와 비교하면
    가운데 빈 시간대(t=300)의 network 사건이 STA 신호 없이도 잘못 attach되는
    문제가 생긴다. any-member 정책은 적어도 한 STA 신호와는 시간이 맞는
    network 사건만 합류시켜 인과 가설을 명확히 한다.

    in-place로 cluster 리스트를 변경. network signal은 STA 무관이라 같은
    네트워크 사건이 여러 STA cluster에 동시 합류할 수 있다(중복 OK —
    distinct signal_type 수가 confidence를 결정하므로 각 cluster 안에서
    1회 카운트).
    """
    for ns in net_signals:
        for cl in clusters:
            if any(_overlap_ratio(ns["time_window"], m["time_window"])
                   >= overlap_threshold for m in cl):
                cl.append(ns)
                logger.debug(
                    "net signal %s cross-attached to cluster sta=%s (cluster size: %d)",
                    ns.get("signal_type"), cl[0].get("sta_mac"), len(cl),
                )


def _title_for(types: frozenset) -> str:
    """결합 신호 타입 집합 → 사람 친화 제목. 룰 미일치 시 generic."""
    for rule_types, title in TITLE_RULES:
        if rule_types.issubset(types):
            return title
    return "다중 신호 동시 관찰"


def _explanation_for(cluster: Sequence[Dict[str, Any]]) -> str:
    """결합 신호들의 msg를 간단히 합쳐 사람 친화 설명을 만든다.

    UI의 결합 신호 칩이 이미 신호 종류를 한국어 라벨로 표시하므로 여기서는
    각 issue의 한국어 msg만 연결해 중복/언어 불일치를 피한다.
    """
    parts = [s.get("msg", "") for s in cluster if s.get("msg")]
    return " · ".join(parts)


def _confidence(cluster: Sequence[Dict[str, Any]]) -> float:
    """결합 신호 수 + 윈도우 겹침 평균으로 confidence 산출.

    distinct signal_type 수를 N으로 사용(같은 타입 중복은 인과 강도 증가에
    기여 X). 모든 pair 평균 overlap 비율을 보너스로 추가.
    """
    distinct = {s["signal_type"] for s in cluster}
    N = len(distinct)
    if N < 1:
        return 0.0
    # pair-wise 평균 overlap
    pairs = []
    arr = list(cluster)
    for i in range(len(arr)):
        for j in range(i + 1, len(arr)):
            pairs.append(_overlap_ratio(arr[i]["time_window"], arr[j]["time_window"]))
    avg_overlap = sum(pairs) / len(pairs) if pairs else 1.0
    raw = CONF_BASE + CONF_PER_SIGNAL * (N - 1) + CONF_OVERLAP_BONUS * avg_overlap
    return round(min(CONF_CAP, raw), 3)


def _correlation_from_cluster(cluster: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """cluster → correlation dict."""
    distinct_types = {s["signal_type"] for s in cluster}
    title = _title_for(frozenset(distinct_types))
    union_refs: List[int] = []
    seen: set = set()
    for s in cluster:
        for n in s.get("frame_refs") or []:
            if n not in seen:
                seen.add(n)
                union_refs.append(n)
    window = _window_union([s["time_window"] for s in cluster])
    # cluster의 sta 정보는 STA scope signal 중 첫 번째에서 가져온다. network only
    # cluster는 sta_diags 기반 클러스터링에서 발생하지 않으므로 항상 STA 정보 있음.
    sta_mac = next((s.get("sta_mac") for s in cluster if s.get("sta_mac")), None)
    sta_name = next((s.get("sta_name") for s in cluster if s.get("sta_name")), None)
    # signal_type별로 issue_refs 묶음. weight 필드는 추가하지 않는다 —
    # distinct type 수로 동등 분배(1/N)할 경우 정보량이 0이라 consumer가
    # 잘못 기대(상대적 중요도)를 가질 수 있다. 향후 strength·severity 기반
    # 가중치를 도입하게 되면 그때 의미 있는 값으로 노출.
    by_type: Dict[str, List[Dict[str, Any]]] = {}
    for s in cluster:
        by_type.setdefault(s["signal_type"], []).append(s)
    signals_out: List[Dict[str, Any]] = []
    for stype, members in by_type.items():
        refs_out = []
        for m in members:
            ref = {"scope": m.get("issue_scope", "sta"),
                   "issue_index": m.get("issue_index")}
            if m.get("issue_scope") == "sta":
                ref["sta_diag_index"] = m.get("sta_diag_index")
            refs_out.append(ref)
        signals_out.append({
            "type": stype,
            "issue_refs": refs_out,
        })
    return {
        "title": title,
        "sta_mac": sta_mac,
        "sta_name": sta_name,
        "confidence": _confidence(cluster),
        "time_window": window,
        "frame_refs": union_refs,
        "signals": signals_out,
        "explanation": _explanation_for(cluster),
    }


def build_correlations(diagnosis: Dict[str, Any]) -> List[Dict[str, Any]]:
    """진단 결과에서 시간 동기 결합 결론을 산출.

    STA 단위 signal로 그리디 클러스터링 후, 네트워크 레벨 signal(ping loss,
    네트워크 retry, 지연 구간, 이상 등)은 시간 윈도우가 겹치는 STA cluster에
    추가 신호로 cross-attach. cluster 안 distinct signal_type 수가
    MIN_CLUSTER_SIZE 이상일 때만 correlation을 만든다.

    Args:
        diagnosis: _structured_diagnosis 반환값. None/non-dict은 빈 리스트.

    Returns:
        correlation 객체 리스트(confidence 내림차순). 결합 후보 부족 시 [].
    """
    if not isinstance(diagnosis, dict):
        return []
    sta_signals, net_signals = _collect_signals(diagnosis)
    if not sta_signals:
        logger.debug("build_correlations: no STA signals → 빈 리스트")
        return []
    clusters = _cluster_signals(sta_signals)
    logger.debug(
        "build_correlations: collected sta=%d net=%d → %d clusters",
        len(sta_signals), len(net_signals), len(clusters),
    )
    _attach_network_signals(clusters, net_signals)
    correlations = [
        _correlation_from_cluster(cl)
        for cl in clusters
        if len({s["signal_type"] for s in cl}) >= MIN_CLUSTER_SIZE
    ]
    correlations.sort(key=lambda c: c["confidence"], reverse=True)
    for c in correlations:
        logger.debug(
            "correlation built: sta=%s confidence=%.2f signals=%s title=%r",
            c.get("sta_mac"), c.get("confidence"),
            [s["type"] for s in c["signals"]], c.get("title"),
        )
    return correlations
