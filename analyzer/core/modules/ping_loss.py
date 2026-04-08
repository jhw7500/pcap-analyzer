"""10. Ping Loss 구간 탐지 — 응답 없는 Request + 원인 역추적"""
from bisect import bisect_left, bisect_right
from typing import List, Dict
from ..models import Frame, AnalysisSection
from ..detector import mac_name


def _find_losses(frames: List[Frame]) -> List[Frame]:
    requests = {}
    matched_ids = set()
    all_requests = []

    for f in frames:
        if f.is_icmp_request and not f.retry:
            key = (f.ip_src, f.ip_dst, f.icmp_seq) if f.icmp_seq else (f.ip_src, f.ip_dst)
            requests[key] = f
            all_requests.append((key, f))
        elif f.is_icmp_reply:
            key = (f.ip_dst, f.ip_src, f.icmp_seq) if f.icmp_seq else (f.ip_dst, f.ip_src)
            if key in requests:
                matched_ids.add(id(requests[key]))
                del requests[key]

    return [req for _, req in all_requests if id(req) not in matched_ids]


def _diagnose_loss(loss_frame: Frame, roles: Dict, index=None,
                   frames=None, window: float = 1.0) -> Dict:
    t = loss_frame.epoch

    if index:
        before_f, after_f = index.frames_in_window(t, window, window)
        nearby = before_f + after_f
        roaming_nearby = index.nearest_roaming(t, max_gap=5.0)
    else:
        nearby = [f for f in frames if t - window <= f.epoch <= t + window]
        roaming_nearby = None
        for f in frames:
            if f.is_roaming_related and f.subtype in ("11", "0", "2"):
                gap = abs(f.epoch - t)
                if gap < 5:
                    if roaming_nearby is None or gap < abs(roaming_nearby.epoch - t):
                        roaming_nearby = f

    retry_count = sum(1 for f in nearby if f.retry)
    total = len(nearby)
    retry_pct = retry_count * 100.0 / total if total else 0

    rssis = [f.rssi_first for f in nearby if f.rssi_first is not None]
    rssi_avg = sum(rssis) / len(rssis) if rssis else None

    cause = "불명"
    if roaming_nearby and abs(roaming_nearby.epoch - t) < 2:
        cause = f"로밍 중 (#{roaming_nearby.number} {roaming_nearby.subtype_name})"
    elif retry_pct > 60:
        cause = f"Retry 폭증 ({retry_pct:.0f}%)"
    elif rssi_avg is not None and rssi_avg < -75:
        cause = f"RSSI 약화 ({rssi_avg:.0f}dBm)"
    elif retry_pct > 30:
        cause = f"Retry 증가 ({retry_pct:.0f}%)"

    return {
        "retry_pct": retry_pct,
        "rssi_avg": rssi_avg,
        "roaming_nearby": roaming_nearby,
        "cause": cause,
        "nearby_total": total,
    }


def analyze(frames: List[Frame], roles: Dict, index=None) -> AnalysisSection:
    lines = []

    losses = _find_losses(frames)
    if not losses:
        return AnalysisSection(
            title="10. Ping Loss 분석",
            lines=["응답 없는 ping 없음 — 모든 Request에 Reply 수신"],
            summary="ping loss 없음")

    lines.append(f"응답 없는 ICMP Request: {len(losses)}건")
    lines.append("")
    lines.append(f"{'#':>3} | {'Frame':>6} | {'Timestamp':>15} | {'Src→Dst':>30} | "
                 f"{'원인':>20} | {'Retry%':>7} | {'RSSI':>5}")
    lines.append("-" * 100)

    cause_counts = {}
    for i, req in enumerate(losses):
        diag = _diagnose_loss(req, roles, index=index, frames=frames)
        cause_key = diag["cause"].split("(")[0].strip()
        cause_counts[cause_key] = cause_counts.get(cause_key, 0) + 1

        rssi_str = f"{diag['rssi_avg']:.0f}" if diag["rssi_avg"] is not None else "-"
        lines.append(
            f"{i+1:>3} | #{req.number:>5} | {req.time_short:>15} | "
            f"{req.ip_src:>14}→{req.ip_dst:<14} | "
            f"{diag['cause']:>20} | {diag['retry_pct']:>5.0f}% | {rssi_str:>5}")

    # 연속 loss 구간
    lines.append("")
    lines.append("연속 Loss 구간:")
    if len(losses) >= 2:
        streaks = []
        streak_start = 0
        for j in range(1, len(losses)):
            if losses[j].epoch - losses[j-1].epoch > 2.0:
                if j - streak_start >= 2:
                    streaks.append((streak_start, j - 1))
                streak_start = j
        if len(losses) - streak_start >= 2:
            streaks.append((streak_start, len(losses) - 1))

        if streaks:
            for s, e in streaks:
                dur = losses[e].epoch - losses[s].epoch
                lines.append(
                    f"  {losses[s].time_short} ~ {losses[e].time_short} "
                    f"({e - s + 1}건, {dur:.1f}초) "
                    f"근거: #{losses[s].number}~#{losses[e].number}")
        else:
            lines.append("  연속 loss 구간 없음 (산발적 발생)")
    else:
        lines.append("  단발성 loss 1건")

    lines.append("")
    lines.append("원인별 분포:")
    for cause, cnt in sorted(cause_counts.items(), key=lambda x: -x[1]):
        lines.append(f"  {cause}: {cnt}건")

    summary = f"ping loss {len(losses)}건"
    return AnalysisSection(title="10. Ping Loss 분석", lines=lines, summary=summary)
