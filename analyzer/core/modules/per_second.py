"""8. 분당 통계 (retry 수, 제어트래픽 수, 전체 프레임 수)"""
from collections import Counter
from typing import List, Dict
from ..models import Frame, AnalysisSection
import time as _time


def analyze(frames: List[Frame], roles: Dict, index=None) -> AnalysisSection:
    lines = []
    if not frames:
        return AnalysisSection(title="8. 분당 통계", lines=["프레임 없음"], summary="없음")

    min_total = Counter()
    min_retry = Counter()
    min_ctrl = Counter()
    min_ctrl_retry = Counter()

    for f in frames:
        minute = int(f.epoch) // 60
        min_total[minute] += 1
        if f.retry:
            min_retry[minute] += 1
        if f.is_control_traffic:
            min_ctrl[minute] += 1
            if f.retry:
                min_ctrl_retry[minute] += 1

    all_mins = sorted(min_total.keys())

    lines.append(f"{'Time':>12} | {'Total':>7} | {'Retry':>7} | {'R%':>5} | {'Ctrl':>5} | {'Ctrl(R)':>7} | Bar(Retry)")
    lines.append("-" * 75)

    for minute in all_mins:
        ts = _time.strftime("%H:%M", _time.localtime(minute * 60))
        t = min_total[minute]
        r = min_retry[minute]
        c = min_ctrl[minute]
        cr = min_ctrl_retry[minute]
        rpct = r * 100.0 / t if t > 0 else 0
        bar = "#" * min(int(r / 100), 40)
        lines.append(f"{ts:>12} | {t:>7,} | {r:>7,} | {rpct:>4.0f}% | {c:>5} | {cr:>7} | {bar}")

    hotspots = [(m, min_retry[m]) for m in all_mins if min_retry[m] > 1000]
    if hotspots:
        lines.append("")
        lines.append("Retry 핫스팟 (>1000/min):")
        for minute, cnt in hotspots:
            ts = _time.strftime("%H:%M", _time.localtime(minute * 60))
            rpct = cnt * 100.0 / min_total[minute]
            lines.append(f"  {ts}: {cnt:,} retries ({rpct:.0f}%)")

    summary = f"{len(all_mins)}분, 핫스팟 {len(hotspots) if hotspots else 0}건"
    return AnalysisSection(title="8. 분당 통계", lines=lines, summary=summary)
