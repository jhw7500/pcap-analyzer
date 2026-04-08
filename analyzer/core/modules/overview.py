"""1. 개요 분석 — 시간범위, 프레임수, 프로토콜/서브타입 분포"""
from collections import Counter
from typing import List, Dict
from ..models import Frame, AnalysisSection, SUBTYPE_NAMES


def analyze(frames: List[Frame], roles: Dict, index=None) -> AnalysisSection:
    lines = []
    n = len(frames)
    if n == 0:
        return AnalysisSection(title="1. 개요", lines=["프레임 없음"], summary="프레임 없음")

    t_start = frames[0].timestamp
    t_end = frames[-1].timestamp
    duration = frames[-1].epoch - frames[0].epoch

    lines.append(f"총 프레임 수: {n:,}")
    lines.append(f"시간 범위: {t_start}")
    lines.append(f"          ~ {t_end}")
    lines.append(f"캡처 시간: {duration:.1f}초")
    lines.append("")

    proto_counts = Counter(f.protocol for f in frames)
    lines.append("프로토콜 분포:")
    for proto, cnt in proto_counts.most_common(15):
        pct = cnt * 100.0 / n
        bar = "#" * int(pct / 2)
        lines.append(f"  {proto:>10}: {cnt:>6} ({pct:>5.1f}%) {bar}")

    lines.append("")
    lines.append("802.11 서브타입 분포:")
    subtype_counts = Counter(f.subtype for f in frames)
    for st, cnt in subtype_counts.most_common(15):
        name = SUBTYPE_NAMES.get(st, f"type={st}")
        pct = cnt * 100.0 / n
        lines.append(f"  {name:>12}({st:>2}): {cnt:>6} ({pct:>5.1f}%)")

    retry_count = sum(1 for f in frames if f.retry)
    lines.append("")
    lines.append(f"Retry 프레임: {retry_count:,} / {n:,} ({retry_count*100.0/n:.1f}%)")

    lines.append("")
    lines.append("감지된 디바이스:")
    for mac, info in sorted(roles.items(), key=lambda x: x[1]["name"]):
        lines.append(f"  {info['name']:>15}: {mac}  (프레임 {info['count']:,}개)")

    summary = f"{n:,}프레임, {duration:.0f}초, retry {retry_count*100.0/n:.1f}%"
    return AnalysisSection(title="1. 개요", lines=lines, summary=summary)
