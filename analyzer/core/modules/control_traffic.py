"""6. ARP / ICMP / TCP ACK 타임라인"""
from typing import List, Dict
from ..models import Frame, AnalysisSection
from ..detector import mac_name


def _detail(f: Frame) -> str:
    if f.is_arp:
        return f"ARP {'Req' if f.arp_opcode == '1' else 'Reply'}"
    if f.icmp_type == "8":
        return "ICMP Req"
    if f.icmp_type == "0":
        return "ICMP Reply"
    if f.icmp_type:
        return f"ICMP t={f.icmp_type}"
    if f.is_pure_tcp_ack:
        return f"TCP ACK({f.protocol[:3]})"
    return "TCP ACK"


def analyze(frames: List[Frame], roles: Dict, index=None) -> AnalysisSection:
    ctrl = [f for f in frames if f.is_control_traffic]
    lines = []
    if not ctrl:
        return AnalysisSection(title="6. 제어 트래픽 타임라인", lines=["제어 트래픽 없음"], summary="없음")

    lines.append(f"총 {len(ctrl)}건 (ARP/ICMP/TCP ACK)")
    lines.append("")
    lines.append(
        f"{'Frame':>6} | {'Timestamp':>15} | {'R':>1} | {'Proto':>5} | {'Detail':>12} | "
        f"{'SrcIP→DstIP':>30} | {'TA→RA':>25} | {'RSSI':>5} | {'MCS':>3}"
    )
    lines.append("-" * 120)

    for f in ctrl[:200]:
        r = "R" if f.retry else " "
        ip_flow = f"{f.ip_src}→{f.ip_dst}" if f.ip_src else ""
        ta = mac_name(f.ta, roles)
        ra = mac_name(f.ra, roles)
        rssi = str(f.rssi_first) if f.rssi_first is not None else ""
        mcs = str(f.mcs_int) if f.mcs_int is not None else ""
        lines.append(
            f"{f.number:>6} | {f.time_short:>15} | {r} | {f.protocol:>5} | "
            f"{_detail(f):>12} | {ip_flow:>30} | {ta:>11}→{ra:<11} | {rssi:>5} | {mcs:>3}"
        )

    if len(ctrl) > 200:
        lines.append(f"  ... 외 {len(ctrl) - 200}건 생략")

    summary = f"제어 트래픽 {len(ctrl)}건"
    return AnalysisSection(title="6. 제어 트래픽 타임라인", lines=lines, summary=summary)
