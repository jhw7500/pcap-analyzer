"""11. STA별 종합 진단 — 모든 분석 결과를 교차하여 현장 제안 생성"""

from dataclasses import dataclass, field
from typing import Any, Dict, List
from collections import Counter, defaultdict
from ..models import Frame, AnalysisSection
from ..detector import mac_name
from ..ping_matching import build_ping_matches

VALID_LEVELS = ("INFO", "WARNING")

# 근거 없이 결론을 미루는("punt") 표현들 — 한/영. 소문자 비교로 매칭한다.
PUNT_PHRASES = (
    # 한국어
    "추가 조사 필요",
    "추가 조사",
    "추가 확인 필요",
    "확인 필요",
    "조사 필요",
    "원인 불명",
    "원인 미상",
    # English
    "further investigation needed",
    "needs further investigation",
    "further investigation",
    "needs investigation",
    "investigate further",
    "to be determined",
    "unknown cause",
    "tbd",
    "todo",
)


@dataclass
class TimeWindow:
    """진단 결론이 가리키는 시간 구간 (epoch 초)."""

    start_epoch: float
    end_epoch: float

    def __post_init__(self) -> None:
        if self.start_epoch is None or self.end_epoch is None:
            raise ValueError(
                "TimeWindow는 start_epoch와 end_epoch가 모두 필요합니다"
            )
        if self.end_epoch < self.start_epoch:
            raise ValueError(
                "TimeWindow의 end_epoch는 start_epoch 이상이어야 합니다"
            )


@dataclass
class Conclusion:
    """근거(frame_refs)와 시간 구간(time_window)을 동반하는 진단 결론.

    frame_refs는 추출 시 부여된 안정적인 tshark frame.number 값들이며,
    근거 없는(빈 frame_refs) 결론 생성은 거부한다.
    """

    level: str
    message: str
    frame_refs: List[int] = field(default_factory=list)
    time_window: TimeWindow = None

    def __post_init__(self) -> None:
        if self.level not in VALID_LEVELS:
            raise ValueError(
                f"level은 {VALID_LEVELS} 중 하나여야 합니다: {self.level!r}"
            )
        if not self.frame_refs:
            raise ValueError(
                "Conclusion은 최소 1개의 frame_ref가 필요합니다 "
                "(근거 없는 결론 금지)"
            )
        if self.time_window is None:
            raise ValueError("Conclusion은 time_window가 필요합니다")


def _conclusion_message(item: Any) -> str:
    """결론 항목(객체/딕셔너리)에서 message 문자열을 안전하게 추출한다."""
    if isinstance(item, dict):
        return str(item.get("message") or "")
    return str(getattr(item, "message", "") or "")


def _conclusion_frame_refs(item: Any) -> List[int]:
    """결론 항목에서 frame_refs를 안전하게 추출한다 (없으면 빈 리스트)."""
    if isinstance(item, dict):
        return item.get("frame_refs") or []
    return getattr(item, "frame_refs", None) or []


def _iter_conclusions(diagnosis_output: Any) -> List[Any]:
    """다양한 형태의 진단 출력 구조에서 결론 항목들을 평탄화하여 반환한다.

    허용 형태:
      - 결론 항목들의 list/tuple
      - {"conclusions": [...]} 또는 {"findings": [...]} 딕셔너리
      - 단일 결론(객체 또는 message/frame_refs를 가진 딕셔너리)
    """
    if diagnosis_output is None:
        return []
    if isinstance(diagnosis_output, dict):
        for key in ("conclusions", "findings"):
            if key in diagnosis_output:
                return list(diagnosis_output[key] or [])
        if "message" in diagnosis_output or "frame_refs" in diagnosis_output:
            return [diagnosis_output]
        return []
    if isinstance(diagnosis_output, (list, tuple)):
        return list(diagnosis_output)
    return [diagnosis_output]


def contains_punt_language(message: str) -> bool:
    """message에 '추가 조사 필요' 류 punt(결론 미루기) 표현이 있으면 True."""
    text = (message or "").lower()
    return any(phrase.lower() in text for phrase in PUNT_PHRASES)


def find_ungrounded_conclusions(diagnosis_output: Any) -> List[Any]:
    """진단 출력 구조를 훑어 '근거 없는' 결론 항목들을 반환한다.

    근거 없음(ungrounded) 판정 기준:
      1) frame_refs가 비어있거나 누락됨 (zero frame references), 또는
      2) message가 punt(결론 미루기) 표현을 포함함

    모든 결론이 근거를 갖추면 빈 리스트를 반환한다. 입력 순서를 보존하며,
    Conclusion 객체와 직렬화된 딕셔너리 형태를 모두 처리한다.
    """
    ungrounded: List[Any] = []
    for item in _iter_conclusions(diagnosis_output):
        frame_refs = _conclusion_frame_refs(item)
        message = _conclusion_message(item)
        if not frame_refs or contains_punt_language(message):
            ungrounded.append(item)
    return ungrounded


def _bounded_refs(frame_subset: List[Frame], limit: int = 100) -> List[int]:
    """근거 frame.number 리스트를 반환하되, 대용량 캡처를 위해 상한을 둔다.

    상한을 넘으면 시간축 전반을 대표하도록 균등 샘플링하고, 첫/마지막 프레임을
    반드시 포함한다. 빈 입력이면 빈 리스트(=근거 없음)를 반환한다.
    """
    nums = [f.number for f in frame_subset]
    if len(nums) <= limit:
        return nums
    step = len(nums) / limit
    sampled = [nums[int(i * step)] for i in range(limit)]
    sampled[0] = nums[0]
    sampled[-1] = nums[-1]
    return sampled


def _window_for(frame_subset: List[Frame]) -> TimeWindow:
    """근거 프레임들의 epoch 범위를 TimeWindow로 만든다 (호출 측이 비어있지 않음을 보장)."""
    epochs = [f.epoch for f in frame_subset if f.epoch is not None]
    return TimeWindow(start_epoch=min(epochs), end_epoch=max(epochs))


def _sta_frames_for(sta: str, frames: List[Frame], index=None) -> List[Frame]:
    if index:
        return index.by_sta.get(sta, [])
    return [f for f in frames if f.ta == sta or f.ra == sta]


def _ping_outcome_sets(frames: List[Frame], roles: Dict[str, Dict[str, Any]]):
    """(matched_set, loss_set) — (src, dst, seq) 키 집합으로 ping 성공/손실 판정."""
    ping = build_ping_matches(frames, roles)
    matched_set = set()
    loss_set = set()
    for item in ping.get("pairs", []):
        matched_set.add((item.get("src"), item.get("dst"), item.get("seq")))
    for item in ping.get("losses", []):
        loss_set.add((item.get("src"), item.get("dst"), item.get("seq")))
    return matched_set, loss_set


def _diagnose_sta(sta_frames: List[Frame], sta: str, matched_set, loss_set):
    """단일 STA에 대한 (진단 결론들, 제안 결론들, 렌더링용 metrics)를 만든다.

    각 결론은 반드시 1개 이상의 frame_ref와 time_window를 동반한다(근거 강제).
    'further investigation needed' 류 punt 제안은 생성하지 않는다.
    """
    total = len(sta_frames)
    retry_frames = [f for f in sta_frames if f.retry]
    retry_pct = len(retry_frames) * 100.0 / total if total else 0

    rssi_frames = [f for f in sta_frames if f.rssi_first is not None]
    rssis = [f.rssi_first for f in rssi_frames]
    rssi_avg = sum(rssis) / len(rssis) if rssis else None
    rssi_min = min(rssis) if rssis else None

    roaming_frames = [f for f in sta_frames if f.is_roaming_related and f.ta == sta]
    auth_frames = [f for f in roaming_frames if f.subtype == "11"]
    auth_count = len(auth_frames)

    ping_matched_frames: List[Frame] = []
    ping_lost_frames: List[Frame] = []
    for f in sta_frames:
        if not f.is_icmp_request or f.retry:
            continue
        seq = f.icmp_seq if f.icmp_seq else str(f.number)
        key = (f.ip_src, f.ip_dst, seq)
        if key in matched_set:
            ping_matched_frames.append(f)
        elif key in loss_set:
            ping_lost_frames.append(f)
    ping_matched = len(ping_matched_frames)
    ping_lost = len(ping_lost_frames)
    ping_total = ping_matched + ping_lost

    # 분당 retry 버킷 (폭증 구간의 실제 프레임을 근거로 보존)
    min_retry: Counter = Counter()
    min_buckets: Dict[int, List[Frame]] = defaultdict(list)
    for f in retry_frames:
        b = int(f.epoch) // 60
        min_retry[b] += 1
        min_buckets[b].append(f)
    max_retry_min = max(min_retry.values()) if min_retry else 0

    diags: List[Conclusion] = []

    if ping_lost > 0 and ping_total > 0:
        loss_pct = ping_lost * 100.0 / ping_total
        diags.append(Conclusion(
            level="WARNING",
            message=f"Ping Loss {ping_lost}/{ping_total} ({loss_pct:.0f}%)",
            frame_refs=_bounded_refs(ping_lost_frames),
            time_window=_window_for(ping_lost_frames),
        ))

    if retry_pct > 40:
        diags.append(Conclusion(
            level="WARNING",
            message=f"높은 Retry Rate: {retry_pct:.1f}%",
            frame_refs=_bounded_refs(retry_frames),
            time_window=_window_for(retry_frames),
        ))
    elif retry_pct > 25:
        diags.append(Conclusion(
            level="INFO",
            message=f"Retry Rate: {retry_pct:.1f}%",
            frame_refs=_bounded_refs(retry_frames),
            time_window=_window_for(retry_frames),
        ))

    if rssi_min is not None and rssi_min < -75:
        weak_frames = [f for f in rssi_frames if f.rssi_first < -75]
        diags.append(Conclusion(
            level="WARNING",
            message=f"RSSI 최저값 {rssi_min}dBm — 신호 약화 구간",
            frame_refs=_bounded_refs(weak_frames),
            time_window=_window_for(weak_frames),
        ))

    if max_retry_min > 3000:
        peak_bucket = max(min_retry, key=min_retry.get)
        peak_frames = min_buckets[peak_bucket]
        diags.append(Conclusion(
            level="WARNING",
            message=f"Retry 폭증: 최대 {max_retry_min}/min",
            frame_refs=_bounded_refs(peak_frames),
            time_window=_window_for(peak_frames),
        ))

    if auth_count > 3:
        diags.append(Conclusion(
            level="INFO",
            message=f"잦은 로밍: {auth_count}회",
            frame_refs=_bounded_refs(auth_frames),
            time_window=_window_for(auth_frames),
        ))

    # 정상 — 경고/정보 결론이 하나도 없을 때도 STA 대표 프레임으로 근거를 부여
    if not diags:
        diags.append(Conclusion(
            level="INFO",
            message="정상",
            frame_refs=_bounded_refs(sta_frames),
            time_window=_window_for(sta_frames),
        ))

    # 현장 제안 — 모든 제안은 근거(frame_refs) 동반, punt 표현 금지
    suggestions: List[Conclusion] = []
    if ping_lost > 0 and retry_pct > 30:
        evid = ping_lost_frames + retry_frames
        suggestions.append(Conclusion(
            level="WARNING",
            message=(
                "Retry 폭증이 ping loss 원인. "
                "로밍 트리거 RSSI 임계값 상향 또는 TX power 조정 권장"
            ),
            frame_refs=_bounded_refs(evid),
            time_window=_window_for(evid),
        ))
    elif ping_lost > 0 and auth_count > 2:
        evid = ping_lost_frames + auth_frames
        suggestions.append(Conclusion(
            level="WARNING",
            message=(
                "잦은 로밍으로 인한 전환 지연. 로밍 히스테리시스 값 확대 권장"
            ),
            frame_refs=_bounded_refs(evid),
            time_window=_window_for(evid),
        ))
    elif ping_lost > 0:
        # (구) "ping loss 원인 추가 조사 필요" punt 제거 →
        # 손실 ICMP request 프레임 자체를 근거로 직접 점검을 권고한다.
        suggestions.append(Conclusion(
            level="WARNING",
            message=(
                f"Ping loss {ping_lost}건 — 손실 ICMP request 프레임 "
                f"직접 점검 권장 (retry/로밍 임계 미달)"
            ),
            frame_refs=_bounded_refs(ping_lost_frames),
            time_window=_window_for(ping_lost_frames),
        ))

    metrics = {
        "total": total,
        "retry_pct": retry_pct,
        "rssi_avg": rssi_avg,
        "auth_count": auth_count,
        "ping_matched": ping_matched,
        "ping_lost": ping_lost,
    }
    return diags, suggestions, metrics


def build_conclusions(
    frames: List[Frame], roles: Dict[str, Dict[str, Any]], index=None
) -> List[Conclusion]:
    """전체 종합 진단을 실행하여 근거 기반 결론(Conclusion) 리스트를 반환한다.

    모든 진단 코드 경로가 frame_refs(>=1)와 time_window를 동반하는 Conclusion을
    생성하므로, find_ungrounded_conclusions(build_conclusions(...))는 항상 빈
    리스트여야 한다(근거 없는 결론 0건).
    """
    sta_macs = [m for m, r in roles.items() if r["role"] == "STA"]
    if not sta_macs:
        return []

    matched_set, loss_set = _ping_outcome_sets(frames, roles)
    conclusions: List[Conclusion] = []
    for sta in sta_macs:
        sta_frames = _sta_frames_for(sta, frames, index)
        if not sta_frames:
            continue
        diags, suggestions, _ = _diagnose_sta(sta_frames, sta, matched_set, loss_set)
        conclusions.extend(diags)
        conclusions.extend(suggestions)
    return conclusions


def analyze(
    frames: List[Frame], roles: Dict[str, Dict[str, Any]], index=None
) -> AnalysisSection:
    lines = []
    sta_macs = [m for m, r in roles.items() if r["role"] == "STA"]

    if not sta_macs:
        return AnalysisSection(
            title="11. 종합 진단", lines=["STA 없음"], summary="진단 대상 없음"
        )

    matched_set, loss_set = _ping_outcome_sets(frames, roles)
    warnings = []

    for sta in sta_macs:
        name = mac_name(sta, roles)
        sta_frames = _sta_frames_for(sta, frames, index)
        if not sta_frames:
            continue

        diags, suggestions, m = _diagnose_sta(sta_frames, sta, matched_set, loss_set)

        # 출력 (근거 기반 결론으로부터 렌더링)
        lines.append(f"--- {name} ({sta}) ---")
        rssi_str = f", RSSI avg: {m['rssi_avg']:.0f}dBm" if m["rssi_avg"] else ""
        lines.append(f"  프레임: {m['total']:,}, Retry: {m['retry_pct']:.1f}%{rssi_str}")
        lines.append(
            f"  로밍: {m['auth_count']}회, "
            f"Ping: {m['ping_matched']}성공/{m['ping_lost']}손실"
        )

        for c in diags:
            marker = "!!" if c.level == "WARNING" else "i "
            lines.append(f"  [{c.level}] {marker} {c.message}")
            if c.level == "WARNING":
                warnings.append(f"{name}: {c.message}")

        for c in suggestions:
            lines.append(f"  -> 제안: {c.message}")
        lines.append("")

    lines.append("=" * 60)
    lines.append("진단 요약")
    lines.append("=" * 60)
    if warnings:
        for w in warnings:
            lines.append(f"  !! WARNING: {w}")
    else:
        lines.append("  OK: WARNING 없음")

    summary = f"WARNING {len(warnings)}건, STA {len(sta_macs)}대"
    return AnalysisSection(title="11. 종합 진단", lines=lines, summary=summary)
