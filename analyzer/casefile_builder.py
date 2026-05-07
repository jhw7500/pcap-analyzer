from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from .core.ping_matching import build_ping_stats

WINDOW_BEFORE_SEC = 10.0
WINDOW_AFTER_SEC = 10.0
MERGE_GAP_SEC = 3.0
MERGE_OVERLAP_THRESHOLD = 0.5


@dataclass
class IncidentWindow:
    start_ts: float
    end_ts: float
    trigger_frame: int | None
    trigger_reason: str
    trigger_ts: float


def _window_overlap_ratio(a: IncidentWindow, b: IncidentWindow) -> float:
    overlap_start = max(a.start_ts, b.start_ts)
    overlap_end = min(a.end_ts, b.end_ts)
    if overlap_end <= overlap_start:
        return 0.0
    overlap = overlap_end - overlap_start
    shortest = min(a.end_ts - a.start_ts, b.end_ts - b.start_ts)
    return overlap / shortest if shortest > 0 else 0.0


def _build_incident_windows(
    ping_full_list: List[Dict[str, Any]],
) -> List[IncidentWindow]:
    losses = [item for item in ping_full_list if item.get("status") == "loss"]
    incidents: List[IncidentWindow] = []

    for loss in losses:
        epoch = float(loss.get("epoch") or 0.0)
        candidate = IncidentWindow(
            start_ts=epoch - WINDOW_BEFORE_SEC,
            end_ts=epoch + WINDOW_AFTER_SEC,
            trigger_frame=loss.get("req_num"),
            trigger_reason="ping timeout candidate",
            trigger_ts=epoch,
        )
        if not incidents:
            incidents.append(candidate)
            continue

        current = incidents[-1]
        merge_due_to_gap = (candidate.trigger_ts - current.trigger_ts) <= MERGE_GAP_SEC
        merge_due_to_overlap = (
            _window_overlap_ratio(current, candidate) >= MERGE_OVERLAP_THRESHOLD
        )
        if merge_due_to_gap or merge_due_to_overlap:
            current.end_ts = max(current.end_ts, candidate.end_ts)
            continue
        incidents.append(candidate)

    return incidents


def _resolve_incident_id(analysis_id: str, incident: IncidentWindow) -> str:
    frame = incident.trigger_frame or 0
    return f"{analysis_id}:{frame}:{incident.trigger_ts:.3f}"


def _filter_ping_window(
    ping_full_list: List[Dict[str, Any]], start_ts: float, end_ts: float
) -> Dict[str, Any]:
    full_list = [
        item
        for item in ping_full_list
        if start_ts <= float(item.get("epoch") or 0.0) <= end_ts
    ]
    pairs = [item for item in full_list if item.get("status") == "matched"]
    losses = [item for item in full_list if item.get("status") == "loss"]
    return {
        "full_list": full_list,
        "pairs": pairs,
        "losses": losses,
        "stats": build_ping_stats(pairs, losses),
    }


def _window_retry_pct(
    structured: Dict[str, Any], start_ts: float, end_ts: float
) -> float:
    timeline = structured.get("per_second", {}).get("timeline", [])
    bucketed = [
        item
        for item in timeline
        if start_ts <= float(item.get("epoch") or 0.0) <= end_ts
    ]
    total = sum(int(item.get("total") or 0) for item in bucketed)
    retry = sum(int(item.get("retry") or 0) for item in bucketed)
    return round(retry * 100.0 / total, 1) if total else 0.0


def _window_roaming_events(
    structured: Dict[str, Any], start_ts: float, end_ts: float
) -> List[Dict[str, Any]]:
    sequences = structured.get("roaming", {}).get("sequences", [])
    return [
        item
        for item in sequences
        if start_ts <= float(item.get("auth_epoch") or 0.0) <= end_ts
        or start_ts <= float(item.get("assoc_epoch") or 0.0) <= end_ts
    ]


def build_casefile(result: Dict[str, Any], incident_id: str = "") -> Dict[str, Any]:
    structured = result.get("structured", {})
    ping = structured.get("ping", {})
    ping_full_list = ping.get("full_list", [])
    analysis_id = result.get("id", "")

    incidents = _build_incident_windows(ping_full_list)
    if not incidents:
        raise ValueError("no ping timeout incident available")

    if incident_id:
        selected = next(
            (
                incident
                for incident in incidents
                if _resolve_incident_id(analysis_id, incident) == incident_id
            ),
            None,
        )
        if selected is None:
            raise KeyError("incident not found")
    else:
        selected = incidents[0]

    resolved_incident_id = _resolve_incident_id(analysis_id, selected)
    ping_window = _filter_ping_window(
        ping_full_list, selected.start_ts, selected.end_ts
    )
    if not ping_window["full_list"]:
        raise ValueError("incident window produced no ping evidence")

    window_retry_pct = _window_retry_pct(structured, selected.start_ts, selected.end_ts)
    roaming_sequences = _window_roaming_events(
        structured, selected.start_ts, selected.end_ts
    )
    loss_pct = float(ping_window["stats"].get("loss_pct") or 0.0)

    observed = [
        {
            "layer": "observed",
            "message": f"incident window 내 ping evidence {len(ping_window['full_list'])}건",
            "source_type": "pcap_metric",
            "source_ref": "structured.ping.full_list",
            "timestamp": selected.trigger_ts,
            "confidence": "high",
            "explainability": "저장된 structured.ping에서 incident window로 슬라이싱",
        }
    ]
    if ping_window["losses"]:
        first_loss = ping_window["losses"][0]
        observed.append(
            {
                "layer": "observed",
                "message": f"reply 없는 request #{first_loss['req_num']} 관측",
                "source_type": "pcap_frame",
                "source_ref": f"frame:{first_loss['req_num']}",
                "timestamp": float(first_loss.get("epoch") or selected.trigger_ts),
                "confidence": "high",
                "explainability": "공용 ping matcher에서 status=loss로 분류",
            }
        )
    for seq in roaming_sequences[:3]:
        observed.append(
            {
                "layer": "observed",
                "message": f"로밍 시퀀스 {seq.get('assoc_type', 'assoc')} gap {seq.get('gap_ms', 0)}ms",
                "source_type": "pcap_metric",
                "source_ref": f"roaming:{seq.get('auth_fnum')}->{seq.get('assoc_fnum')}",
                "timestamp": float(seq.get("auth_epoch") or selected.trigger_ts),
                "confidence": "high",
                "explainability": "structured.roaming.sequences에서 incident window 기준 추출",
            }
        )

    derived = [
        {
            "layer": "derived",
            "message": f"window ping loss {loss_pct:.1f}%",
            "source_type": "pcap_metric",
            "source_ref": "structured.ping.stats.loss_pct",
            "timestamp": selected.end_ts,
            "confidence": "high",
            "explainability": "incident window 내 ping pair/loss exact 재계산",
        },
        {
            "layer": "derived",
            "message": f"window retry {window_retry_pct:.1f}%",
            "source_type": "pcap_metric",
            "source_ref": "structured.per_second.timeline",
            "timestamp": selected.end_ts,
            "confidence": "high",
            "explainability": "incident window와 겹치는 per-second timeline bucket 집계",
        },
    ]

    heuristic = []
    if loss_pct > 0 and window_retry_pct > 15:
        heuristic.append(
            {
                "layer": "heuristic",
                "message": f"Retry({window_retry_pct:.1f}%)와 ping loss 동시 관측",
                "source_type": "pcap_metric",
                "source_ref": "structured.per_second.timeline+structured.ping.stats.loss_pct",
                "timestamp": selected.end_ts,
                "confidence": "medium",
                "explainability": "ping loss와 retry 증가가 같은 incident window에서 동시 관측됨",
                "counter_evidence_refs": [],
            }
        )
    if ping_window["losses"] and roaming_sequences:
        heuristic.append(
            {
                "layer": "heuristic",
                "message": "로밍 인접 구간에서 ping timeout 발생 가능성",
                "source_type": "pcap_metric",
                "source_ref": "structured.roaming.sequences+structured.ping.losses",
                "timestamp": selected.trigger_ts,
                "confidence": "medium",
                "explainability": "loss trigger와 roaming sequence가 같은 incident window에 존재",
                "counter_evidence_refs": [],
            }
        )

    unknown = [
        {
            "layer": "unknown",
            "message": "driver/AP 로그 상관분석은 MVP 범위에서 제외",
            "source_type": "system",
            "source_ref": "mvp-scope",
            "timestamp": None,
            "confidence": "n/a",
            "explainability": "pcap-only 단계로 제한",
            "missing_reason": "correlation deferred",
        }
    ]

    next_checks = ["loss frame neighborhood 확인", "retry burst 구간 재검토"]
    if roaming_sequences:
        next_checks.insert(0, "로밍 시퀀스와 timeout 시점 비교")

    return {
        "schema_version": "1.0",
        "generator_version": "casefile-v1",
        "analysis_id": analysis_id,
        "incident_id": resolved_incident_id,
        "incident_window": {
            "start_ts": selected.start_ts,
            "end_ts": selected.end_ts,
            "trigger_frame": selected.trigger_frame,
            "trigger_reason": selected.trigger_reason,
        },
        "summary": {
            "title": f"Ping Timeout Casefile - {result.get('pcap_name', '?')}",
            "confidence": "medium" if heuristic else "high",
            "next_checks": next_checks,
        },
        "layers": {
            "observed": observed,
            "derived": derived,
            "heuristic": heuristic,
            "unknown": unknown,
        },
        "ping": ping_window,
    }
