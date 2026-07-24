"""10. Ping Loss 구간 탐지 — 응답 없는 Request + 원인 역추적"""

from typing import Any, Dict, List
from ..models import Frame, AnalysisSection
from ..ping_matching import build_ping_matches, find_time_streaks
from ..thresholds import RETRY_DANGER_PCT, RSSI_DANGER_DBM


def _find_losses(frames: List[Frame], roles: Dict[str, Dict[str, Any]]) -> List[Frame]:
    ping = build_ping_matches(frames, roles)
    req_by_num = {f.number: f for f in frames}
    losses: List[Frame] = []
    for item in ping.get("losses", []):
        req_num = item.get("req_num")
        if req_num in req_by_num:
            losses.append(req_by_num[req_num])
    return losses


def _diagnose_loss(
    loss_frame: Frame,
    roles: Dict[str, Dict[str, Any]],
    index=None,
    frames=None,
    window: float = 1.0,
) -> Dict[str, Any]:
    t = loss_frame.epoch

    if index:
        before_f, after_f = index.frames_in_window(t, window, window)
        nearby = before_f + after_f
        roaming_nearby = index.nearest_roaming(t, max_gap=5.0)
    else:
        source_frames = frames or []
        nearby = [f for f in source_frames if t - window <= f.epoch <= t + window]
        roaming_nearby = None
        for f in source_frames:
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
    # 손실 시점 ±1s 국소 burst 판정 — 지속 retry율보다 높은 경계가 적절해
    # 위험 경계(RETRY_DANGER_PCT)의 4배/2배를 사용 (단일 소스와 동기).
    elif retry_pct > RETRY_DANGER_PCT * 4:
        cause = f"Retry 폭증 ({retry_pct:.0f}%)"
    elif rssi_avg is not None and rssi_avg < RSSI_DANGER_DBM:
        cause = f"RSSI 약화 ({rssi_avg:.0f}dBm)"
    elif retry_pct > RETRY_DANGER_PCT * 2:
        cause = f"Retry 증가 ({retry_pct:.0f}%)"

    return {
        "retry_pct": retry_pct,
        "rssi_avg": rssi_avg,
        "roaming_nearby": roaming_nearby,
        "cause": cause,
        "nearby_total": total,
    }


def analyze(
    frames: List[Frame], roles: Dict[str, Dict[str, Any]], index=None
) -> AnalysisSection:
    lines = []

    losses = _find_losses(frames, roles)
    if not losses:
        return AnalysisSection(
            title="10. Ping Loss 분석",
            lines=["응답 없는 ping 없음 — 모든 Request에 Reply 수신"],
            summary="ping loss 없음",
        )

    lines.append(f"응답 없는 ICMP Request: {len(losses)}건")
    lines.append("")
    lines.append(
        f"{'#':>3} | {'Frame':>6} | {'Timestamp':>15} | {'Src→Dst':>30} | "
        f"{'원인':>20} | {'Retry%':>7} | {'RSSI':>5}"
    )
    lines.append("-" * 100)

    cause_counts = {}
    for i, req in enumerate(losses):
        diag = _diagnose_loss(req, roles, index=index, frames=frames)
        cause_key = diag["cause"].split("(")[0].strip()
        cause_counts[cause_key] = cause_counts.get(cause_key, 0) + 1

        rssi_str = f"{diag['rssi_avg']:.0f}" if diag["rssi_avg"] is not None else "-"
        lines.append(
            f"{i + 1:>3} | #{req.number:>5} | {req.time_short:>15} | "
            f"{req.ip_src:>14}→{req.ip_dst:<14} | "
            f"{diag['cause']:>20} | {diag['retry_pct']:>5.0f}% | {rssi_str:>5}"
        )

    # 연속 loss 구간 (전역 — 시간 기준, 장치 혼합). losses는 epoch 오름차순.
    lines.append("")
    lines.append("연속 Loss 구간 (전역):")
    if len(losses) >= 2:
        streaks = find_time_streaks([f.epoch for f in losses])
        if streaks:
            for s, e in streaks:
                dur = losses[e].epoch - losses[s].epoch
                lines.append(
                    f"  {losses[s].time_short} ~ {losses[e].time_short} "
                    f"({e - s + 1}건, {dur:.1f}초) "
                    f"근거: #{losses[s].number}~#{losses[e].number}"
                )
        else:
            lines.append("  연속 loss 구간 없음 (산발적 발생)")
    else:
        lines.append("  단발성 loss 1건")

    # 장치별 연속 loss 구간 — 특정 장치(src→dst 흐름)가 연속 실패한 구간을 분리 표시.
    # 전역 구간은 서로 다른 장치의 loss가 시간상 가까우면 한 구간으로 섞이므로, 흐름별로
    # 따로 묶어 "어느 장치가 언제부터 연속 실패했는지"를 명확히 한다.
    lines.append("")
    lines.append("장치별 연속 Loss 구간:")
    by_flow: Dict[str, List[Frame]] = {}
    for f in losses:
        by_flow.setdefault(f"{f.ip_src}→{f.ip_dst}", []).append(f)
    dev_streak_found = False
    for flow in sorted(by_flow):
        fl = sorted(by_flow[flow], key=lambda x: x.epoch)
        for s, e in find_time_streaks([x.epoch for x in fl]):
            dev_streak_found = True
            dur = fl[e].epoch - fl[s].epoch
            lines.append(
                f"  {flow}: {fl[s].time_short} ~ {fl[e].time_short} "
                f"({e - s + 1}건, {dur:.1f}초) 근거: #{fl[s].number}~#{fl[e].number}"
            )
    if not dev_streak_found:
        lines.append("  장치별 연속 loss 구간 없음")

    lines.append("")
    lines.append("원인별 분포:")
    for cause, cnt in sorted(cause_counts.items(), key=lambda x: -x[1]):
        lines.append(f"  {cause}: {cnt}건")

    summary = f"ping loss {len(losses)}건"
    return AnalysisSection(title="10. Ping Loss 분석", lines=lines, summary=summary)
