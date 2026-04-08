"""5. ICMP Ping Request→Reply 매칭 + RTT 분석"""
from typing import List, Dict
from ..models import Frame, AnalysisSection
from ..detector import mac_name


def analyze(frames: List[Frame], roles: Dict, index=None) -> AnalysisSection:
    lines = []

    requests = {}
    pairs = []

    for f in frames:
        if f.is_icmp_request and not f.retry:
            key = (f.ip_src, f.ip_dst, f.icmp_seq) if f.icmp_seq else (f.ip_src, f.ip_dst)
            requests[key] = f
        elif f.is_icmp_reply:
            key = (f.ip_dst, f.ip_src, f.icmp_seq) if f.icmp_seq else (f.ip_dst, f.ip_src)
            if key in requests:
                req = requests.pop(key)
                rtt = (f.epoch - req.epoch) * 1000
                pairs.append({
                    "req": req, "reply": f, "rtt_ms": rtt,
                    "has_retry": req.retry or f.retry,
                })

    if not pairs:
        return AnalysisSection(title="5. Ping RTT 분석", lines=["ICMP ping 프레임 없음"], summary="ping 없음")

    lines.append(f"{'#':>3} | {'Req→Reply':>14} | {'RTT(ms)':>8} | {'Src→Dst':>30} | {'R':>1} | {'Timestamp':>15}")
    lines.append("-" * 85)

    for i, p in enumerate(pairs):
        r = "R" if p["has_retry"] else " "
        lines.append(
            f"{i+1:>3} | #{p['req'].number:>5}→#{p['reply'].number:<5} | "
            f"{p['rtt_ms']:>7.2f} | {p['req'].ip_src:>14}→{p['req'].ip_dst:<14} | "
            f"{r} | {p['req'].time_short:>15}"
        )

    rtts = [p["rtt_ms"] for p in pairs]
    normal = [p["rtt_ms"] for p in pairs if not p["has_retry"]]
    retried = [p["rtt_ms"] for p in pairs if p["has_retry"]]

    lines.append("")
    lines.append(f"전체: min={min(rtts):.2f}ms, max={max(rtts):.2f}ms, avg={sum(rtts)/len(rtts):.2f}ms (n={len(rtts)})")
    if normal:
        lines.append(f"정상(no retry): min={min(normal):.2f}ms, avg={sum(normal)/len(normal):.2f}ms (n={len(normal)})")
    if retried:
        lines.append(f"Retry 포함: min={min(retried):.2f}ms, avg={sum(retried)/len(retried):.2f}ms (n={len(retried)})")

    avg = sum(rtts) / len(rtts)
    outliers = [p for p in pairs if p["rtt_ms"] > avg * 10]
    if outliers:
        lines.append("")
        lines.append("이상치 (avg×10 초과):")
        for p in outliers:
            sta = mac_name(p["req"].ra, roles)
            lines.append(
                f"  #{p['req'].number}→#{p['reply'].number}: "
                f"{p['rtt_ms']:.1f}ms → {sta} ({p['req'].ip_dst})"
            )

    summary = f"ping {len(pairs)}쌍, avg {sum(rtts)/len(rtts):.1f}ms"
    return AnalysisSection(title="5. Ping RTT 분석", lines=lines, summary=summary)
