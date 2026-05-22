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

# 로밍 이벤트로 추출할 mgmt 서브타입 → 이벤트 종류(kind).
#   "11" Auth, "0" AssocReq, "2" ReassocReq — analyze()의 시퀀스 탐지 규칙과 동일.
# 디버그 타임라인의 roaming 마커는 이 규칙으로 탐지된 이벤트만 재사용한다(신규
# 탐지 없음). Auth/Reassoc/Assoc 각각을 공유 시간축 위 개별 마커로 투영한다.
ROAMING_EVENT_KINDS = {
    "11": "auth",
    "0": "assoc",
    "2": "reassoc",
}


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


def extract_roaming_events(
    frames: List[FrameType], roles: Dict[str, Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """STA가 송신한 Auth/Assoc/Reassoc 로밍 이벤트를 구조화해 추출한다.

    `analyze`의 시퀀스 탐지와 **동일한 규칙**(roaming-related 프레임, STA 송신,
    서브타입 11/0/2 = `ROAMING_EVENT_KINDS`)을 사용한다 — 신규 로밍 탐지를 만들지
    않고 roaming.py의 탐지 결과를 재사용하기 위한 단일 소스. 디버그 타임라인은
    이 이벤트들을 공유 시간축 위 개별 마커로 투영한다(`timeline_series`).

    Args:
        frames: 전체 프레임(캡처 시간순). roaming-related가 아니거나 STA 송신이
            아닌 프레임, Auth/Assoc/Reassoc 외 서브타입은 건너뛴다.
        roles: MAC → 역할 dict. role == "STA"인 MAC의 송신만 이벤트로 본다.

    Returns:
        캡처 순서를 보존한 이벤트 dict 리스트. 각 이벤트:
        {
            "kind": str,          # "auth" | "assoc" | "reassoc"
            "epoch": float,       # 이벤트 발생 시각(공유 시간축 정렬용)
            "frame_number": int,  # tshark frame.number (증거용 canonical frame id)
            "sta": str,           # 송신 STA MAC
            "ap": str,            # 대상 AP MAC (frame.ra)
            "subtype": str,       # 원본 mgmt 서브타입 코드
            "subtype_name": str,  # 사람이 읽는 서브타입 이름(Auth/ReassocReq 등)
            "time_short": str,    # HH:MM:SS.mmm 표기(마커 라벨/툴팁용)
        }
    """
    sta_macs = {mac for mac, role in roles.items() if role.get("role") == "STA"}

    events: List[Dict[str, Any]] = []
    for frame in frames:
        if not frame.is_roaming_related:
            continue
        if frame.ta not in sta_macs:
            continue
        kind = ROAMING_EVENT_KINDS.get(frame.subtype)
        if kind is None:
            continue
        events.append(
            {
                "kind": kind,
                "epoch": frame.epoch,
                "frame_number": frame.number,
                "sta": frame.ta,
                "ap": frame.ra,
                "subtype": frame.subtype,
                "subtype_name": frame.subtype_name,
                "time_short": frame.time_short,
            }
        )
    return events


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

    # 시퀀스 탐지는 roaming 이벤트 추출(단일 소스)을 재사용한다.
    sequences: List[SequenceInfo] = []
    auth_events: Dict[str, Dict[str, Any]] = {}
    for event in extract_roaming_events(roaming_frames, roles):
        if event["kind"] == "auth":
            auth_events[event["sta"]] = event
        else:  # assoc / reassoc
            auth_event = auth_events.get(event["sta"])
            if auth_event is None:
                continue
            sequences.append(
                SequenceInfo(
                    sta=event["sta"],
                    ap=event["ap"],
                    auth_fnum=auth_event["frame_number"],
                    assoc_fnum=event["frame_number"],
                    auth_ts=auth_event["time_short"],
                    assoc_type=event["subtype_name"],
                    gap_ms=(event["epoch"] - auth_event["epoch"]) * 1000,
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
