"""5. ICMP Ping Request→Reply 매칭 + RTT 분석"""

from typing import Any, Dict, List
from ..models import Frame, AnalysisSection
from ..ping_matching import build_ping_matches


def analyze(
    frames: List[Frame], roles: Dict[str, Dict[str, Any]], index=None
) -> AnalysisSection:
    lines = []

    ping = build_ping_matches(frames, roles)
    pairs = ping.get("pairs", [])

    if not pairs:
        return AnalysisSection(
            title="5. Ping RTT 분석",
            lines=["ICMP ping 프레임 없음"],
            summary="ping 없음",
        )

    lines.append(
        f"{'#':>3} | {'Req→Reply':>14} | {'RTT(ms)':>8} | {'Src→Dst':>30} | {'R':>1} | {'Timestamp':>15}"
    )
    lines.append("-" * 85)

    for i, p in enumerate(pairs):
        r = "R" if p["has_retry"] else " "
        lines.append(
            f"{i + 1:>3} | #{p['req_num']:>5}→#{p['reply_num']:<5} | "
            f"{p['rtt_ms']:>7.2f} | {p['src']:>14}→{p['dst']:<14} | "
            f"{r} | {p['req_time']:>15}"
        )

    rtts = [p["rtt_ms"] for p in pairs]
    normal = [p["rtt_ms"] for p in pairs if not p["has_retry"]]
    retried = [p["rtt_ms"] for p in pairs if p["has_retry"]]

    lines.append("")
    lines.append(
        f"전체: min={min(rtts):.2f}ms, max={max(rtts):.2f}ms, avg={sum(rtts) / len(rtts):.2f}ms (n={len(rtts)})"
    )
    if normal:
        lines.append(
            f"정상(no retry): min={min(normal):.2f}ms, avg={sum(normal) / len(normal):.2f}ms (n={len(normal)})"
        )
    if retried:
        lines.append(
            f"Retry 포함: min={min(retried):.2f}ms, avg={sum(retried) / len(retried):.2f}ms (n={len(retried)})"
        )

    avg = sum(rtts) / len(rtts)
    outliers = [p for p in pairs if p["rtt_ms"] > avg * 10]
    if outliers:
        lines.append("")
        lines.append("이상치 (avg×10 초과):")
        for p in outliers:
            lines.append(
                f"  #{p['req_num']}→#{p['reply_num']}: "
                f"{p['rtt_ms']:.1f}ms → {p['dst_mac']} ({p['dst']})"
            )

    summary = f"ping {len(pairs)}쌍, avg {sum(rtts) / len(rtts):.1f}ms"
    return AnalysisSection(title="5. Ping RTT 분석", lines=lines, summary=summary)
