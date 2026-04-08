"""4. 로밍 이벤트 탐지 (Auth → Assoc/Reassoc → EAPOL 4-Way)"""

from dataclasses import dataclass, field
import importlib
from typing import Any, Dict, List, TYPE_CHECKING

if TYPE_CHECKING:
    from ..models import AnalysisSection as AnalysisSectionType
    from ..models import Frame as FrameType
else:
    AnalysisSectionType = Any
    FrameType = Any

try:
    from ..detector import mac_name
    from ..models import AnalysisSection, Frame
except (ImportError, ValueError):
    mac_name = importlib.import_module("detector").mac_name
    model_module = importlib.import_module("models")
    AnalysisSection = model_module.AnalysisSection
    Frame = model_module.Frame

SLOW_THRESHOLD_MS = 100


@dataclass
class SequenceInfo:
    sta: str
    ap: str
    auth_fnum: int
    assoc_fnum: int
    auth_ts: str
    assoc_type: str
    gap_ms: float


@dataclass
class StaSummary:
    count: int = 0
    gaps: List[float] = field(default_factory=list)
    ap_targets: Dict[str, int] = field(default_factory=dict)
    slow: int = 0


def analyze(
    frames: List[FrameType], roles: Dict[str, Dict[str, Any]], index: Any = None
) -> AnalysisSectionType:
    del index

    lines: List[str] = []
    roaming_frames = [f for f in frames if f.is_roaming_related]
    if not roaming_frames:
        return AnalysisSection(
            title="4. 로밍 이벤트", lines=["로밍 관련 프레임 없음"], summary="로밍 없음"
        )

    sta_macs = {mac for mac, role in roles.items() if role.get("role") == "STA"}

    sequences: List[SequenceInfo] = []
    auth_events: Dict[str, FrameType] = {}
    for frame in roaming_frames:
        if frame.subtype == "11" and frame.ta in sta_macs:
            auth_events[frame.ta] = frame
        elif frame.subtype in ("0", "2") and frame.ta in sta_macs:
            auth_frame = auth_events.get(frame.ta)
            if auth_frame is None:
                continue
            sequences.append(
                SequenceInfo(
                    sta=frame.ta,
                    ap=frame.ra,
                    auth_fnum=auth_frame.number,
                    assoc_fnum=frame.number,
                    auth_ts=auth_frame.time_short,
                    assoc_type=frame.subtype_name,
                    gap_ms=(frame.epoch - auth_frame.epoch) * 1000,
                )
            )

    sta_summary: Dict[str, StaSummary] = {}
    for sequence in sequences:
        info = sta_summary.setdefault(sequence.sta, StaSummary())
        info.count += 1
        info.gaps.append(sequence.gap_ms)
        info.ap_targets[sequence.ap] = info.ap_targets.get(sequence.ap, 0) + 1
        if sequence.gap_ms > SLOW_THRESHOLD_MS:
            info.slow += 1

    lines.append(
        f"로밍 관련 프레임: {len(roaming_frames)}건, 시퀀스: {len(sequences)}건"
    )
    lines.append("")
    lines.append("STA별 로밍 요약:")
    lines.append(
        f"{'STA':>15} | {'횟수':>5} | {'Gap avg':>8} | {'Gap max':>8} | {'느린로밍':>6} | {'AP 방향':>20}"
    )
    lines.append("-" * 80)

    for sta in sorted(
        sta_summary.keys(), key=lambda key: sta_summary[key].count, reverse=True
    ):
        info = sta_summary[sta]
        avg_gap = sum(info.gaps) / len(info.gaps) if info.gaps else 0.0
        max_gap = max(info.gaps) if info.gaps else 0.0
        ap_str = ", ".join(
            f"{mac_name(ap, roles)}({count})"
            for ap, count in sorted(
                info.ap_targets.items(), key=lambda item: item[1], reverse=True
            )
        )
        slow_str = f"{info.slow}건" if info.slow > 0 else "-"
        lines.append(
            f"{mac_name(sta, roles):>15} | {info.count:>5} | {avg_gap:>6.1f}ms | {max_gap:>6.1f}ms | {slow_str:>6} | {ap_str}"
        )

    if sequences:
        lines.append("")
        lines.append("로밍 시퀀스 상세 (Auth → Assoc/Reassoc):")
        lines.append(
            f"{'#':>3} | {'STA':>15} | {'Auth':>10} | {'Assoc':>10} | {'Gap':>8} | {'AP':>15}"
        )
        lines.append("-" * 80)
        for idx, sequence in enumerate(sequences[:20], start=1):
            lines.append(
                f"{idx:>3} | {mac_name(sequence.sta, roles):>15} | Auth #{sequence.auth_fnum:<4} | "
                f"#{sequence.assoc_fnum:<8} | {sequence.gap_ms:>6.1f}ms | {mac_name(sequence.ap, roles):>15}"
            )

    slow_sequences = [
        sequence for sequence in sequences if sequence.gap_ms > SLOW_THRESHOLD_MS
    ]
    if slow_sequences:
        lines.append("")
        lines.append(f"느린 로밍 상세 (>{SLOW_THRESHOLD_MS}ms):")
        lines.append(
            f"{'#':>3} | {'STA':>15} | {'Time':>15} | {'Gap':>8} | {'AP':>15} | {'Type':>12}"
        )
        lines.append("-" * 80)
        for idx, sequence in enumerate(slow_sequences, start=1):
            lines.append(
                f"{idx:>3} | {mac_name(sequence.sta, roles):>15} | {sequence.auth_ts:>15} | "
                f"{sequence.gap_ms:>6.1f}ms | {mac_name(sequence.ap, roles):>15} | {sequence.assoc_type}"
            )

    summary = f"로밍 시퀀스 {len(sequences)}건, 느린로밍(>{SLOW_THRESHOLD_MS}ms) {len(slow_sequences)}건"
    return AnalysisSection(title="4. 로밍 이벤트", lines=lines, summary=summary)
