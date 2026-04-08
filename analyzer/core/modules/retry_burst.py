"""3. Retry Burst 탐지 + 직후 제어트래픽 지연 분석"""
from typing import List, Dict
from ..models import Frame, AnalysisSection


def analyze(frames: List[Frame], roles: Dict, index=None) -> AnalysisSection:
    lines = []
    lines.append("연속 3+개 retry burst 후 첫 non-retry 제어 프레임까지 시간:")
    lines.append("")

    burst_events = []
    retry_count = 0
    burst_start_epoch = 0.0
    burst_end_epoch = 0.0
    burst_start_fnum = 0

    for i, f in enumerate(frames):
        if f.retry:
            if retry_count == 0:
                burst_start_epoch = f.epoch
                burst_start_fnum = f.number
            retry_count += 1
            burst_end_epoch = f.epoch
        else:
            if retry_count >= 3:
                for j in range(i, min(i + 50, len(frames))):
                    ff = frames[j]
                    if ff.retry:
                        continue
                    if ff.is_control_traffic:
                        delay_ms = (ff.epoch - burst_end_epoch) * 1000
                        detail = "ARP" if ff.is_arp else ("ICMP" if ff.icmp_type else "TCP ACK")
                        burst_events.append({
                            "burst_len": retry_count,
                            "dur_ms": (burst_end_epoch - burst_start_epoch) * 1000,
                            "delay_ms": delay_ms,
                            "ctrl_detail": detail,
                            "ctrl_fnum": ff.number,
                            "ctrl_retry": ff.retry,
                            "burst_start_fnum": burst_start_fnum,
                        })
                        break
            retry_count = 0

    if not burst_events:
        return AnalysisSection(title="3. Retry Burst 분석", lines=["Retry burst 없음"], summary="burst 없음")

    lines.append(f"{'#':>3} | {'Burst':>5} | {'Duration':>8} | {'Delay':>8} | {'Type':>8} | {'근거 Frame':>16}")
    lines.append("-" * 68)
    for i, ev in enumerate(burst_events[:30]):
        lines.append(
            f"{i+1:>3} | {ev['burst_len']:>5} | {ev['dur_ms']:>6.1f}ms | "
            f"{ev['delay_ms']:>6.2f}ms | {ev['ctrl_detail']:>8} | "
            f"#{ev['burst_start_fnum']}~#{ev['ctrl_fnum']}"
        )

    delays = [ev["delay_ms"] for ev in burst_events]
    lines.append(f"\n총 burst: {len(burst_events)}건")
    lines.append(f"제어트래픽 지연: min={min(delays):.2f}ms, max={max(delays):.2f}ms, avg={sum(delays)/len(delays):.2f}ms")
    ctrl_retry = sum(1 for ev in burst_events if ev["ctrl_retry"])
    lines.append(f"제어트래픽이 retry: {ctrl_retry}/{len(burst_events)} ({ctrl_retry*100.0/len(burst_events):.1f}%)")

    summary = f"burst {len(burst_events)}건, 지연 avg {sum(delays)/len(delays):.1f}ms"
    return AnalysisSection(title="3. Retry Burst 분석", lines=lines, summary=summary)
