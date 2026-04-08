"""2. Retry MCS 분포 + Rate Fallback 패턴 분석"""
from collections import Counter
from typing import List, Dict
from ..models import Frame, AnalysisSection
from ..detector import mac_name


def analyze(frames: List[Frame], roles: Dict, index=None) -> AnalysisSection:
    lines = []

    mcs_total = Counter()
    mcs_retry = Counter()
    for f in frames:
        m = f.mcs_int
        if m is not None:
            mcs_total[m] += 1
            if f.retry:
                mcs_retry[m] += 1

    if not mcs_total:
        return AnalysisSection(title="2. Retry MCS 분포", lines=["MCS 정보 없음"], summary="MCS 없음")

    lines.append("MCS별 Retry Rate:")
    lines.append(f"{'MCS':>5} | {'Total':>6} | {'Retry':>6} | {'Rate':>6} | Bar")
    lines.append("-" * 55)
    for mcs in sorted(mcs_total.keys()):
        t = mcs_total[mcs]
        r = mcs_retry[mcs]
        rate = r * 100.0 / t if t > 0 else 0
        bar = "#" * int(rate / 2)
        lines.append(f"MCS{mcs:>2} | {t:>6} | {r:>6} | {rate:>5.1f}% | {bar}")

    total_all = sum(mcs_total.values())
    retry_all = sum(mcs_retry.values())
    lines.append("-" * 55)
    lines.append(f"{'합계':>5} | {total_all:>6} | {retry_all:>6} | {retry_all*100.0/total_all:>5.1f}% |")

    high_mcs = [14, 15]
    high_total = sum(mcs_total.get(m, 0) for m in high_mcs)
    high_retry = sum(mcs_retry.get(m, 0) for m in high_mcs)
    if retry_all > 0 and high_total > 0:
        lines.append("")
        pct = high_retry * 100.0 / retry_all
        lines.append(f"MCS14+15 Retry 비중: {high_retry}/{retry_all} = {pct:.1f}%")
        lines.append(f"→ 고MCS 편중: {'예' if pct > 60 else '아니오 (균등 분포)'}")

    # Rate Fallback 체인
    lines.append("")
    lines.append("Retry MCS 하강(Rate Fallback) 패턴:")

    chains = []
    current = []
    for f in frames:
        if f.mcs_int is None:
            if current:
                chains.append(current)
                current = []
            continue
        if f.retry:
            current.append(f)
        else:
            if current:
                chains.append(current)
                current = []
    if current:
        chains.append(current)

    fallbacks = []
    for chain in chains:
        if len(chain) >= 2:
            mcs_seq = [fr.mcs_int for fr in chain]
            if mcs_seq[0] > mcs_seq[-1]:
                fallbacks.append((chain, mcs_seq))

    if fallbacks:
        lines.append(f"{'#':>3} | {'Frames':>12} | {'MCS변화':>20} | {'Station':>15}")
        lines.append("-" * 60)
        for i, (chain, mcs_seq) in enumerate(fallbacks[:20]):
            sta = mac_name(chain[0].ta, roles)
            mcs_str = "→".join(str(m) for m in mcs_seq)
            lines.append(
                f"{i+1:>3} | {chain[0].number:>5}~{chain[-1].number:<5} | "
                f"MCS {mcs_seq[0]:>2}→{mcs_seq[-1]:<2} ({mcs_str}) | {sta}"
            )
        lines.append(f"\n총 MCS 하강 체인: {len(fallbacks)}건 / retry 체인 {len(chains)}건")
    else:
        lines.append("  Rate Fallback 없음")

    summary = f"retry rate {retry_all*100.0/total_all:.1f}%, fallback {len(fallbacks)}건"
    return AnalysisSection(title="2. Retry MCS 분포", lines=lines, summary=summary)
