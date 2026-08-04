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
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

from .models import Frame

MERGE_MIN_TSF_PAIRS = 10
FALLBACK_MATCH_WINDOW_SEC = 5.0
MERGE_DEDUP_WINDOW_SEC = 0.05  # Task 3에서 사용
# 창 안 후보 초과 시 낡은 순으로 매칭 후보에서 제외 — 최근접 매칭 원칙과 정합(먼
# 후보일수록 옳은 짝일 확률 낮음), same-source 밀집 버스트의 무한 누적을 막는다.
MERGE_MAX_LIVE_GROUPS = 64


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


@dataclass
class MergeResult:
    frames: List[Frame]                 # 통합·정렬·재번호된 리스트 (기존 파이프라인 입력)
    per_source: Dict[str, List[Frame]]  # 소스별 원본(epoch 보정됨) — 3단계용
    offsets: Dict[str, OffsetResult]    # 소스 태그 → 추정 결과 (기준 w1 제외)
    stats: Dict[str, Any]
    warnings: List[str]


def _dedup_key(f: Frame) -> Tuple:
    """dedup 매칭 키. seq가 있으면 (TA, seq, subtype, retry) 정확 매칭.

    제어 프레임(ACK 등)은 seq가 없어 (subtype, TA 또는 RA, retry)로 근사한다 —
    같은 상대와 주고받는 동일 subtype 제어 프레임끼리는 구분하지 못하는 한계가
    있지만, 창(MERGE_DEDUP_WINDOW_SEC)이 좁아 실측 트래픽에서는 충분한 근사다.
    """
    if f.seq:
        return ("s", f.ta, f.seq, f.subtype, f.retry)
    return ("c", f.subtype, f.ta or f.ra, f.retry)


def _prefer_new_representative(rep: Frame, candidate: Frame) -> bool:
    """대표 교체 여부 판정: ip_src가 채워진 쪽 우선, 동률이면 이른 epoch 우선.

    실측 근거: DFK 캡처는 완전 암호화(ICMP 0건)라 "먼저 잡힌 쪽"을 그대로 대표로
    쓰면 ping 분석에 쓸 IP 필드가 소실된다 — 복호화된 사본이 있으면 그쪽을 대표로.
    """
    rep_has_ip, cand_has_ip = bool(rep.ip_src), bool(candidate.ip_src)
    if cand_has_ip != rep_has_ip:
        return cand_has_ip
    return candidate.epoch < rep.epoch


class _MatchIndex:
    """키별 슬라이딩 윈도우 dedup 매칭 인덱스.

    all_groups는 최종 출력용 전체 group(창 밖으로 밀려나도 유지 — 절대 삭제 안 함).
    _windows는 키별 "아직 매칭 후보인" group들의 슬라이딩 윈도우(deque)다. 프레임
    전체 순회가 epoch 오름차순이라는 전제 하에 앞쪽(오래된) group부터 버려도
    안전하다. 각 키의 후보 수는 MERGE_MAX_LIVE_GROUPS로 bound한다 — same-source
    밀집 버스트처럼 서로 매치 불가한 프레임이 쌓이면 무한정 늘어나 매 프레임 스캔이
    O(n)이 되는 걸 막는다.
    """

    def __init__(self) -> None:
        self.all_groups: List[Dict[str, Any]] = []
        self._windows: Dict[Tuple, "deque[Dict[str, Any]]"] = {}

    def bucket_len(self, key: Tuple) -> int:
        """키의 현재 매칭 후보 수 — 테스트에서 bound 불변식 검증용."""
        return len(self._windows.get(key, ()))

    def process(self, f: Frame) -> bool:
        """프레임을 기존 group에 병합하거나 새 group을 만든다. 중복이면 True."""
        key = _dedup_key(f)
        dq = self._windows.setdefault(key, deque())
        while dq and f.epoch - dq[0]["epoch"] > MERGE_DEDUP_WINDOW_SEC:
            dq.popleft()  # 창을 벗어난 group은 더 이상 매칭 후보가 아니다.

        candidates = [
            g for g in dq
            if f.source not in g["sources"] and abs(f.epoch - g["epoch"]) <= MERGE_DEDUP_WINDOW_SEC
        ]
        if candidates:
            # 창 안 후보 중 가장 가까운 것과 매칭 — 삽입순 첫 매치가 아니다.
            # 동률(diff 같음)이면 이른 epoch의 group을 우선.
            match = min(candidates, key=lambda g: (abs(f.epoch - g["epoch"]), g["epoch"]))
            match["sources"].add(f.source)
            if _prefer_new_representative(match["rep"], f):
                match["rep"] = f
                match["epoch"] = f.epoch  # group.epoch는 항상 대표의 epoch로 유지
            return True

        group = {"rep": f, "sources": {f.source}, "epoch": f.epoch}
        dq.append(group)
        self.all_groups.append(group)
        if len(dq) > MERGE_MAX_LIVE_GROUPS:
            dq.popleft()  # 매칭 후보에서만 제외 — all_groups에는 남아 결과 불변.
        return False


def merge_captures(sources: "OrderedDict[str, List[Frame]]") -> MergeResult:
    """다중 캡처를 시계 정렬 후 dedup·재번호해 단일 타임라인으로 병합한다.

    sources: 태그 → 프레임 리스트(OrderedDict). 첫 항목이 기준(w1) — 나머지는
    이 기준에 대해 estimate_offset으로 보정된다. 각 Frame.source는 이미 태깅됨.
    """
    tags = list(sources.keys())
    reference_tag = tags[0]
    reference = sources[reference_tag]

    offsets: Dict[str, OffsetResult] = {}
    warnings: List[str] = []
    for tag in tags[1:]:
        frames = sources[tag]
        result = estimate_offset(reference, frames)
        offsets[tag] = result
        # epoch만 보정해 통합 타임라인을 만든다 — timestamp 문자열은 원본 그대로 둔다.
        for f in frames:
            f.epoch += result.offset_sec
        warnings.extend(result.warnings)
        if result.method == "none":
            warnings.append(f"{tag}: 오프셋 추정 실패 — 원시 시계 그대로 병합됨")

    by_source_raw = {tag: len(sources[tag]) for tag in tags}

    if len(tags) == 1:
        # 단일 소스는 dedup·재번호 없이 그대로 반환 — 기존 파이프라인 하위 호환.
        frames = sorted(reference, key=lambda f: f.epoch)
        stats: Dict[str, Any] = {
            "window_ms": MERGE_DEDUP_WINDOW_SEC * 1000,
            "duplicates": 0,
            "kept": len(frames),
            "by_source_raw": by_source_raw,
            "coverage": {"both": 0, "only": {reference_tag: len(frames)}},
        }
        return MergeResult(
            frames=frames,
            per_source={reference_tag: reference},
            offsets={},
            stats=stats,
            warnings=warnings,
        )

    all_frames: List[Frame] = []
    for tag in tags:
        all_frames.extend(sources[tag])
    all_frames.sort(key=lambda f: (f.epoch, f.source, f.number))

    index = _MatchIndex()
    duplicates = sum(1 for f in all_frames if index.process(f))
    all_groups = index.all_groups

    merged = [g["rep"] for g in all_groups]
    merged.sort(key=lambda f: f.epoch)
    for i, f in enumerate(merged):
        f.number = i + 1

    both = sum(1 for g in all_groups if len(g["sources"]) >= 2)
    only: Dict[str, int] = {}
    for g in all_groups:
        if len(g["sources"]) == 1:
            (tag,) = g["sources"]
            only[tag] = only.get(tag, 0) + 1

    stats = {
        "window_ms": MERGE_DEDUP_WINDOW_SEC * 1000,
        "duplicates": duplicates,
        "kept": len(merged),
        "by_source_raw": by_source_raw,
        "coverage": {"both": both, "only": only},
    }

    return MergeResult(
        frames=merged,
        per_source={tag: sources[tag] for tag in tags},
        offsets=offsets,
        stats=stats,
        warnings=warnings,
    )
