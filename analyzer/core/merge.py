"""다중 무선 캡처의 시계 정렬과 중복 제거.

같은 채널을 두 위치에서 캡처하면 같은 802.11 프레임이 양쪽에 잡힌다. 비콘의
TSF(wlan.fixed.timestamp)는 AP가 프레임에 찍는 값이라 어느 캡처에서 봐도
동일하다 — (BSSID, TSF) 정확 일치 쌍의 epoch 차 중앙값이 곧 캡처 간 시계
오프셋이다. 실측(2026-07-21 TEST1, DFK↔cantops): 12,298쌍, 오프셋 +183.510s,
IQR 3.4ms — 사전 timesync 보정 없이도 무선 간 정렬이 가능함을 확인했다.

TSF 폴백((TA, seq, subtype) 매칭)은 ±5초 창을 쓰므로 사전 보정된 입력을
전제한다(스펙 §3). 그것도 실패하면 오프셋 0 + 경고.
"""
import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from .models import Frame

MERGE_MIN_TSF_PAIRS = 10
FALLBACK_MATCH_WINDOW_SEC = 5.0
MERGE_DEDUP_WINDOW_SEC = 0.05  # Task 3에서 사용


@dataclass
class OffsetResult:
    offset_sec: float
    method: str
    pairs: int
    spread_sec: float
    warnings: List[str] = field(default_factory=list)


def _tsf_table(frames: List[Frame]) -> Dict[Tuple[str, int], float]:
    out: Dict[Tuple[str, int], float] = {}
    for f in frames:
        if f.subtype != "8" or not f.bssid or not f.tsf:
            continue
        try:
            out[(f.bssid, int(f.tsf))] = f.epoch
        except ValueError:
            continue  # 비정상 TSF 값은 무시
    return out


def _median_iqr(diffs: List[float]) -> Tuple[float, float]:
    s = sorted(diffs)
    n = len(s)
    return statistics.median(s), (s[(3 * n) // 4] - s[n // 4] if n >= 4 else 0.0)


def estimate_offset(reference: List[Frame], other: List[Frame]) -> OffsetResult:
    """other의 epoch에 더하면 reference 타임라인이 되는 오프셋을 추정한다."""
    ref_t, oth_t = _tsf_table(reference), _tsf_table(other)
    common = set(ref_t) & set(oth_t)
    if len(common) >= MERGE_MIN_TSF_PAIRS:
        med, iqr = _median_iqr([ref_t[k] - oth_t[k] for k in common])
        return OffsetResult(med, "tsf", len(common), iqr)

    # 폴백: (TA, seq, subtype) 매칭 — 사전 보정 전제의 ±5초 창
    ref_keys: Dict[Tuple[str, str, str], List[float]] = {}
    for f in reference:
        if f.ta and f.seq:
            ref_keys.setdefault((f.ta, f.seq, f.subtype), []).append(f.epoch)
    diffs: List[float] = []
    for f in other:
        if not (f.ta and f.seq):
            continue
        for ref_epoch in ref_keys.get((f.ta, f.seq, f.subtype), []):
            d = ref_epoch - f.epoch
            if abs(d) <= FALLBACK_MATCH_WINDOW_SEC:
                diffs.append(d)
                break
    if len(diffs) >= MERGE_MIN_TSF_PAIRS:
        med, iqr = _median_iqr(diffs)
        return OffsetResult(med, "seq-fallback", len(diffs), iqr)

    return OffsetResult(
        0.0, "none", 0, 0.0,
        warnings=["캡처 간 오프셋을 추정하지 못해 0으로 가정 — 타임라인이 어긋날 수 있다 "
                  "(비콘 TSF 쌍 부족·공통 프레임 없음)"],
    )
