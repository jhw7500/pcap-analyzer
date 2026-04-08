"""7. STA별 RSSI/MCS 신호 품질 분석"""
from collections import Counter
from typing import List, Dict
from ..models import Frame, AnalysisSection


def analyze(frames: List[Frame], roles: Dict, index=None) -> AnalysisSection:
    lines = []

    sta_macs = [m for m, r in roles.items() if r["role"] == "STA"]
    if not sta_macs:
        return AnalysisSection(title="7. 신호 품질", lines=["STA 없음"], summary="STA 없음")

    for sta in sta_macs:
        name = roles[sta]["name"]

        # index 활용: 사전 인덱싱된 TA/RA별 프레임 사용
        if index:
            tx_frames = [f for f in index.by_ta.get(sta, []) if f.rssi_first is not None]
            rx_frames = [f for f in index.by_ra.get(sta, []) if f.rssi_first is not None]
        else:
            tx_frames = [f for f in frames if f.ta == sta and f.rssi_first is not None]
            rx_frames = [f for f in frames if f.ra == sta and f.rssi_first is not None]

        lines.append(f"--- {name} ({sta}) ---")
        if tx_frames:
            rssis = [f.rssi_first for f in tx_frames]
            lines.append(f"  TX(STA→AP): {len(tx_frames)}프레임, RSSI min={min(rssis)} max={max(rssis)} avg={sum(rssis)/len(rssis):.0f}")
            mcs_dist = Counter(f.mcs_int for f in tx_frames if f.mcs_int is not None)
            if mcs_dist:
                lines.append(f"  TX MCS: {dict(sorted(mcs_dist.items()))}")
            worst = min(tx_frames, key=lambda f: f.rssi_first)
            lines.append(f"  최저 RSSI: {worst.rssi_first}dBm (#{worst.number}, {worst.time_short})")
        else:
            lines.append("  TX 프레임 없음")

        if rx_frames:
            rssis = [f.rssi_first for f in rx_frames]
            lines.append(f"  RX(AP→STA): {len(rx_frames)}프레임, RSSI min={min(rssis)} max={max(rssis)} avg={sum(rssis)/len(rssis):.0f}")
            worst = min(rx_frames, key=lambda f: f.rssi_first)
            lines.append(f"  최저 RSSI: {worst.rssi_first}dBm (#{worst.number}, {worst.time_short})")
        lines.append("")

    summary = f"STA {len(sta_macs)}대 분석"
    return AnalysisSection(title="7. 신호 품질", lines=lines, summary=summary)
