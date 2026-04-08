"""12. AP 간 로밍 성능 비교 + 프레임 분포 분석"""
from collections import Counter
from typing import List, Dict
from ..models import Frame, AnalysisSection, SUBTYPE_NAMES
from ..detector import mac_name

BROADCAST = "ff:ff:ff:ff:ff:ff"


def analyze(frames: List[Frame], roles: Dict, index=None) -> AnalysisSection:
    lines = []
    ap_macs = [m for m, r in roles.items() if r["role"] == "AP"]

    if len(ap_macs) < 2:
        return AnalysisSection(
            title="12. AP 비교", lines=["AP 2대 미만 — 비교 불가"],
            summary="비교 불가")

    # --- 기존: TA/RA 기반 성능 비교 ---
    lines.append("[ 성능 비교 (TA/RA 기반) ]")
    lines.append("")

    ap_stats = {}
    for ap in ap_macs:
        name = mac_name(ap, roles)
        all_f = [f for f in frames if f.ta == ap or f.ra == ap]
        total = len(all_f)
        retries = sum(1 for f in all_f if f.retry)
        rssis = [f.rssi_first for f in all_f if f.rssi_first is not None]
        roaming_to = sum(1 for f in frames
                         if f.subtype in ("0", "2") and f.ra == ap)

        ap_stats[ap] = {
            "name": name,
            "total": total,
            "retry": retries,
            "retry_pct": retries * 100.0 / total if total else 0,
            "rssi_avg": sum(rssis) / len(rssis) if rssis else None,
            "rssi_min": min(rssis) if rssis else None,
            "roaming_to": roaming_to,
        }

    lines.append(f"{'AP':>15} | {'프레임':>7} | {'Retry%':>7} | {'RSSI avg':>9} | "
                 f"{'RSSI min':>9} | {'로밍 수신':>8}")
    lines.append("-" * 70)
    for ap in ap_macs:
        s = ap_stats[ap]
        rssi_avg = f"{s['rssi_avg']:.0f}" if s["rssi_avg"] else "-"
        rssi_min = f"{s['rssi_min']}" if s["rssi_min"] else "-"
        lines.append(
            f"{s['name']:>15} | {s['total']:>7} | {s['retry_pct']:>6.1f}% | "
            f"{rssi_avg:>9} | {rssi_min:>9} | {s['roaming_to']:>8}")

    lines.append("")
    best = min(ap_stats.values(), key=lambda s: s["retry_pct"])
    worst = max(ap_stats.values(), key=lambda s: s["retry_pct"])
    diff = worst["retry_pct"] - best["retry_pct"]
    if diff > 10:
        lines.append(f"!! {worst['name']}의 retry rate({worst['retry_pct']:.1f}%)가 "
                     f"{best['name']}({best['retry_pct']:.1f}%)보다 현저히 높음")
    else:
        lines.append(f"AP 간 retry rate 차이 미미 "
                     f"({best['retry_pct']:.1f}% ~ {worst['retry_pct']:.1f}%)")

    # --- 신규: BSSID 기반 프레임 분포 ---
    lines.append("")
    lines.append("")
    lines.append("[ 프레임 분포 (BSSID 기반) ]")
    lines.append("")

    # BSSID별 프레임 분류
    ap_frames = {ap: [] for ap in ap_macs}
    unclassified = 0
    for f in frames:
        if f.bssid in ap_frames:
            ap_frames[f.bssid].append(f)
        else:
            unclassified += 1

    bssid_totals = {ap: len(fl) for ap, fl in ap_frames.items()}
    grand_total = sum(bssid_totals.values())

    if grand_total == 0:
        lines.append("BSSID 기반 프레임 없음 (Control 전용 캡처?)")
        summary = f"AP {len(ap_macs)}대 비교"
        return AnalysisSection(title="12. AP 비교", lines=lines, summary=summary)

    # 전체 프레임 수
    lines.append(f"{'AP':>15} | {'프레임':>10} | {'비율':>7}")
    lines.append("-" * 38)
    for ap in ap_macs:
        name = mac_name(ap, roles)
        cnt = bssid_totals[ap]
        pct = cnt * 100.0 / grand_total if grand_total else 0
        lines.append(f"{name:>15} | {cnt:>10,} | {pct:>6.1f}%")
    lines.append(f"{'합계':>15} | {grand_total:>10,} |")
    if unclassified > 0:
        lines.append(f"{'(BSSID없음)':>15} | {unclassified:>10,} | (Control 등)")

    # 프레임 타입별 분해
    lines.append("")
    lines.append("프레임 타입별:")
    type_names_ordered = ["Management", "Control", "Data"]
    ap_type_counts = {}
    for ap in ap_macs:
        counts = Counter(f.frame_type for f in ap_frames[ap])
        ap_type_counts[ap] = counts

    header = f"{'타입':<12}"
    for ap in ap_macs:
        name = mac_name(ap, roles)
        header += f" | {name:>10} {'%':>6}"
    if ap_macs:
        header += f" | {mac_name(ap_macs[0], roles)[:3]}비율"
    lines.append(header)
    lines.append("-" * len(header))

    for ft in type_names_ordered:
        row = f"{ft:<12}"
        vals = []
        for ap in ap_macs:
            cnt = ap_type_counts[ap].get(ft, 0)
            pct = cnt * 100.0 / bssid_totals[ap] if bssid_totals[ap] else 0
            row += f" | {cnt:>10,} {pct:>5.1f}%"
            vals.append(cnt)
        if sum(vals) > 0:
            row += f" | {vals[0]*100.0/sum(vals):>6.1f}%"
        lines.append(row)

    # 서브타입별 상세
    lines.append("")
    lines.append("서브타입별 상세:")
    all_subtypes = set()
    for ap in ap_macs:
        all_subtypes.update(f.subtype for f in ap_frames[ap])

    subtype_data = []
    for st in all_subtypes:
        vals = []
        for ap in ap_macs:
            cnt = sum(1 for f in ap_frames[ap] if f.subtype == st)
            vals.append(cnt)
        total_st = sum(vals)
        if total_st < max(10, grand_total * 0.001):
            continue
        name = SUBTYPE_NAMES.get(st, f"sub{st}")
        subtype_data.append((name, st, vals, total_st))

    subtype_data.sort(key=lambda x: x[3], reverse=True)

    header = f"{'서브타입':<15}"
    for ap in ap_macs:
        name = mac_name(ap, roles)
        header += f" | {name:>10}"
    header += f" | {'차이':>10}"
    lines.append(header)
    lines.append("-" * len(header))

    for name, st, vals, total_st in subtype_data:
        row = f"{name:<15}"
        for v in vals:
            row += f" | {v:>10,}"
        diff_val = vals[0] - vals[1] if len(vals) == 2 else 0
        row += f" | {diff_val:>+10,}"
        lines.append(row)

    # 불균형 기여도 (AP가 2대일 때)
    if len(ap_macs) == 2:
        ap1, ap2 = ap_macs[0], ap_macs[1]
        total_diff = bssid_totals[ap1] - bssid_totals[ap2]
        if abs(total_diff) > grand_total * 0.05:
            lines.append("")
            lines.append(f"불균형 기여도 (차이 {total_diff:+,}):")
            contrib_data = []
            for name, st, vals, total_st in subtype_data:
                d = vals[0] - vals[1]
                if total_diff != 0:
                    contrib = d * 100.0 / total_diff
                else:
                    contrib = 0
                contrib_data.append((name, vals[0], vals[1], d, contrib))

            contrib_data.sort(key=lambda x: abs(x[3]), reverse=True)

            lines.append(f"{'서브타입':<15} | {'AP1':>10} | {'AP2':>10} | {'차이':>10} | {'기여도':>7}")
            lines.append("-" * 62)
            for name, a1, a2, d, contrib in contrib_data[:10]:
                if abs(d) < max(100, abs(total_diff) * 0.005):
                    continue
                lines.append(f"{name:<15} | {a1:>10,} | {a2:>10,} | {d:>+10,} | {contrib:>6.1f}%")
            lines.append("-" * 62)
            lines.append(f"{'합계':<15} | {bssid_totals[ap1]:>10,} | {bssid_totals[ap2]:>10,} "
                         f"| {total_diff:>+10,} | 100.0%")
        else:
            lines.append("")
            lines.append(f"AP 간 프레임 수 차이 미미 (차이 {total_diff:+,}, "
                         f"{abs(total_diff)*100.0/grand_total:.1f}%)")

    # Beacon RSSI 비교
    lines.append("")
    lines.append("Beacon RSSI 비교:")
    for ap in ap_macs:
        name = mac_name(ap, roles)
        beacon_rssis = [f.rssi_first for f in ap_frames[ap]
                        if f.subtype == "8" and f.rssi_first is not None]
        if beacon_rssis:
            avg = sum(beacon_rssis) / len(beacon_rssis)
            lines.append(f"  {name}: 평균 {avg:.1f} dBm (샘플 {len(beacon_rssis):,}건)")
        else:
            lines.append(f"  {name}: Beacon RSSI 없음")

    summary = (f"AP {len(ap_macs)}대, BSSID기준 "
               + "/".join(f"{bssid_totals[ap]:,}" for ap in ap_macs))
    return AnalysisSection(title="12. AP 비교", lines=lines, summary=summary)
