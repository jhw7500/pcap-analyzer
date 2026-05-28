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
from typing import Any, Dict, List, Optional, Sequence, Tuple

# Signal type constants — issue 객체의 signal_type 필드와 일치.
# msg 문자열 파싱 대신 명시적 type 부여로 견고성 확보.
SIG_WEAK_RSSI = "weak_rssi"
SIG_HIGH_RETRY = "high_retry"
SIG_SLOW_ROAMING = "slow_roaming"
SIG_FREQUENT_ROAMING = "frequent_roaming"
SIG_HIGH_LOSS = "high_loss"
SIG_DELAY_ZONE = "delay_zone"
SIG_ANOMALY = "anomaly"

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
TITLE_RULES: List[Tuple[frozenset, str]] = [
    (frozenset({SIG_WEAK_RSSI, SIG_HIGH_RETRY, SIG_SLOW_ROAMING}),
     "약전계로 인한 multi-symptom"),
    (frozenset({SIG_WEAK_RSSI, SIG_HIGH_RETRY, SIG_FREQUENT_ROAMING}),
     "약전계로 인한 multi-symptom"),
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
    """
    if not w1 or not w2:
        return 0.0
    a0, a1 = w1.get("start_epoch"), w1.get("end_epoch")
    b0, b1 = w2.get("start_epoch"), w2.get("end_epoch")
    if not all(isinstance(v, (int, float)) for v in (a0, a1, b0, b1)):
        return 0.0
    lo = max(a0, b0)
    hi = min(a1, b1)
    inter = max(0.0, hi - lo)
    smallest = min(max(a1 - a0, 0.0), max(b1 - b0, 0.0))
    if smallest <= 0.0:
        # 점 윈도우(start==end). 같은 점이면 1.0, 아니면 0.
        return 1.0 if (a0 == b0 == b1 == a1) else 0.0
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


def _collect_signals(diagnosis: Dict[str, Any]) -> List[Dict[str, Any]]:
    """진단 결과에서 cluster 후보 signal들을 추출.

    sta_diags의 issues만 본다(같은 STA 기준 결합이 인과 신호로 가장 의미 있음).
    네트워크 레벨 all_issues는 sta_diags 항목과 중복 승격되어 있어 같이 보면
    이중 카운트가 된다.

    각 signal:
        {
            "sta_mac": str,
            "sta_name": str,
            "sta_diag_index": int,        # diagnosis["sta_diags"] 위치
            "issue_index": int,            # sta_diags[i].issues 위치
            "signal_type": str,
            "time_window": dict,
            "frame_refs": list[int],
            "msg": str,                    # 표시용
            "severity": str,
        }
    """
    out: List[Dict[str, Any]] = []
    for si, sd in enumerate(diagnosis.get("sta_diags", []) or []):
        mac = sd.get("mac") or ""
        name = sd.get("name") or mac
        for ii, issue in enumerate(sd.get("issues", []) or []):
            stype = issue.get("signal_type")
            tw = issue.get("time_window")
            refs = issue.get("frame_refs") or []
            if not stype or not tw:
                continue
            out.append({
                "sta_mac": mac,
                "sta_name": name,
                "sta_diag_index": si,
                "issue_index": ii,
                "signal_type": stype,
                "time_window": tw,
                "frame_refs": list(refs),
                "msg": issue.get("msg", ""),
                "severity": issue.get("severity", "medium"),
            })
    return out


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
    # STA별로 분리해서 클러스터링.
    by_sta: Dict[str, List[Dict[str, Any]]] = {}
    for s in signals:
        by_sta.setdefault(s["sta_mac"], []).append(s)
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


def _title_for(types: frozenset) -> str:
    """결합 신호 타입 집합 → 사람 친화 제목. 룰 미일치 시 generic."""
    for rule_types, title in TITLE_RULES:
        if rule_types.issubset(types):
            return title
    return "다중 신호 동시 관찰"


def _explanation_for(cluster: Sequence[Dict[str, Any]]) -> str:
    """결합 신호들의 msg를 간단히 합쳐 사람 친화 설명을 만든다."""
    parts = [f"[{s['signal_type']}] {s['msg']}" for s in cluster]
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
        for n in s["frame_refs"]:
            if n not in seen:
                seen.add(n)
                union_refs.append(n)
    window = _window_union([s["time_window"] for s in cluster])
    sta_mac = cluster[0]["sta_mac"]
    sta_name = cluster[0]["sta_name"]
    # weight: distinct 타입에 균등 분배. 클러스터 안 동일 타입 중복은 한
    # signal로 합쳐 issue_refs에 모두 노출.
    signals_out: List[Dict[str, Any]] = []
    n_distinct = max(1, len(distinct_types))
    weight = round(1.0 / n_distinct, 3)
    by_type: Dict[str, List[Dict[str, Any]]] = {}
    for s in cluster:
        by_type.setdefault(s["signal_type"], []).append(s)
    for stype, members in by_type.items():
        signals_out.append({
            "type": stype,
            "weight": weight,
            "issue_refs": [
                {"sta_diag_index": m["sta_diag_index"], "issue_index": m["issue_index"]}
                for m in members
            ],
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
    """진단 결과의 sta_diags issues에서 시간 동기 결합 결론을 산출.

    Args:
        diagnosis: _structured_diagnosis 반환값 (sta_diags 보유).

    Returns:
        correlation 객체 리스트. confidence 내림차순.
        결합 후보가 부족하면 빈 리스트.
    """
    signals = _collect_signals(diagnosis)
    if len(signals) < MIN_CLUSTER_SIZE:
        return []
    clusters = _cluster_signals(signals)
    correlations = [
        _correlation_from_cluster(cl)
        for cl in clusters
        if len({s["signal_type"] for s in cl}) >= MIN_CLUSTER_SIZE
    ]
    correlations.sort(key=lambda c: c["confidence"], reverse=True)
    return correlations
