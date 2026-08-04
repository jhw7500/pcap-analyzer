"""다중 무선 캡처의 시계 정렬과 중복 제거.

같은 채널을 두 위치에서 캡처하면 같은 802.11 프레임이 양쪽에 잡힌다. 비콘의
TSF(wlan.fixed.timestamp)는 AP가 프레임에 찍는 값이라 어느 캡처에서 봐도
동일하다 — (BSSID, TSF) 정확 일치 쌍의 epoch 차 중앙값이 곧 캡처 간 시계
오프셋이다. 실측(2026-07-21 TEST1, DFK↔cantops): 12,298쌍, 오프셋 +183.510s,
IQR 3.4ms — 사전 timesync 보정 없이도 무선 간 정렬이 가능함을 확인했다.

TSF 폴백((TA, seq, subtype) 매칭)은 ±5초 창을 쓰므로 사전 보정된 입력을
전제한다(스펙 §3). 그것도 실패하면 오프셋 0 + 경고.
"""
import datetime as dt
import statistics
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

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
    """(BSSID, TSF) → epoch 매핑.

    같은 캡처 안에서 같은 키가 서로 다른 epoch로 두 번 이상 등장하면 어느
    발생이 진짜 짝인지 알 수 없다 — 마지막 값으로 덮어쓰면(기존 동작) 잘못된
    epoch가 섞여 오프셋 중앙값을 오염시킬 수 있다. 재등장한 키는 테이블에서
    아예 제외해 모호한 매칭을 원천 차단한다(PR #23 리뷰 2라운드 Finding E-1).
    """
    out: Dict[Tuple[str, int], float] = {}
    dupes: set = set()
    for f in frames:
        if f.subtype != "8" or not f.bssid or not f.tsf:
            continue
        try:
            key = (f.bssid, int(f.tsf))
        except ValueError:
            continue  # 비정상 TSF 값은 무시
        if key in dupes:
            continue
        if key in out:
            del out[key]
            dupes.add(key)
            continue
        out[key] = f.epoch
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

    # 폴백: (TA, seq, subtype) 매칭 — 사전 보정 전제의 ±5초 창. seq는 랩어라운드
    # (12비트, 4096마다 재사용)되므로 같은 키가 창 안에 두 번 이상 등장할 수
    # 있다 — 창 안 첫 후보를 그대로 취하면(최선착) 더 먼 쪽에 잘못 걸려 실제
    # 오프셋이 몇 초 어긋난 값으로 붕괴할 수 있다. 키별로 (ref 발생, other
    # 프레임) 후보 쌍을 모아 |diff| 최근접 순으로 그리디 매칭하고, 매칭된 ref
    # 발생·other 프레임은 각각 한 번만 소비한다(1:1 — PR #23 리뷰 Finding C).
    ref_keys: Dict[Tuple[str, str, str], List[float]] = {}
    for f in reference:
        if f.ta and f.seq:
            ref_keys.setdefault((f.ta, f.seq, f.subtype), []).append(f.epoch)
    other_keys: Dict[Tuple[str, str, str], List[Frame]] = {}
    for f in other:
        if f.ta and f.seq:
            other_keys.setdefault((f.ta, f.seq, f.subtype), []).append(f)

    diffs: List[float] = []
    for key, other_frames in other_keys.items():
        ref_epochs = ref_keys.get(key)
        if not ref_epochs:
            continue
        candidates = []
        for ri, ref_epoch in enumerate(ref_epochs):
            for oi, of in enumerate(other_frames):
                d = ref_epoch - of.epoch
                if abs(d) <= FALLBACK_MATCH_WINDOW_SEC:
                    candidates.append((abs(d), ri, oi, d))
        candidates.sort(key=lambda c: c[0])
        used_ref: set = set()
        used_other: set = set()
        for _, ri, oi, d in candidates:
            if ri in used_ref or oi in used_other:
                continue
            used_ref.add(ri)
            used_other.add(oi)
            diffs.append(d)
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


def _decoded_score(f: Frame) -> int:
    """프레임이 복호화됐다는 지표를 **개수**로 센다 — 다운스트림 판정(is_icmp_*,
    is_arp, is_pure_tcp_ack 등)에 실제로 쓰이는 복호화 필드 전수: ip_src(IP
    페이로드) · arp_opcode(ARP) · icmp_type(ICMP) · eapol_msgnr(EAPOL 4-way) ·
    tcp_flags(TCP) · tcp_len(TCP 페이로드 길이 — is_pure_tcp_ack가
    `tcp_len=="0"`을 요구) 중 채워진 필드 수.

    bool로만 판정하면(1라운드 수정) 지표가 하나라도 있는 두 사본이 항상
    동률로 취급돼, 필드를 더 많이 보존한 완전한 사본(예: ip_src+icmp_type)이
    부분적으로만 복호화된 사본(예: ip_src만)에 "이른 epoch" 동률 규칙으로 질
    수 있다 — 더 많은 정보를 보존한 사본이 대표가 돼야 한다(PR #23 리뷰
    2라운드 Finding D). tcp_len 누락 시 ip_src+tcp_flags 동률에서 tcp_len까지
    가진 완전판이 지는 동일한 문제가 재현된다(PR #23 리뷰 3라운드 Finding B).
    tcp_len="0"도 `bool("0")`이 True이므로 정상적으로 "채워짐"으로 계산된다.
    """
    return sum(
        bool(x) for x in (
            f.ip_src, f.arp_opcode, f.icmp_type, f.eapol_msgnr, f.tcp_flags, f.tcp_len,
        )
    )


def _prefer_new_representative(rep: Frame, candidate: Frame) -> bool:
    """대표 교체 여부 판정: 복호화 지표(_decoded_score) 점수가 높은 쪽 우선,
    동률이면 이른 epoch 우선.

    실측 근거: DFK 캡처는 완전 암호화(ICMP 0건)라 "먼저 잡힌 쪽"을 그대로 대표로
    쓰면 ping 분석에 쓸 IP 필드가 소실된다 — 복호화된 사본이 있으면 그쪽을 대표로.
    """
    rep_score, cand_score = _decoded_score(rep), _decoded_score(candidate)
    if cand_score != rep_score:
        return cand_score > rep_score
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


def _format_corrected_timestamp(epoch: float) -> str:
    """보정된 epoch를 로컬 타임존 timestamp 문자열로 재생성.

    tshark 원본 timestamp 포맷(요일·타임존 약어 포함 등)과는 다르지만, 이
    문자열의 유일한 계약은 자기 일관성(캡처 내에서 시각 표기가 실제 epoch와
    맞아야 함)과 `Frame.time_short`가 파싱하는 규칙(공백으로 나눈 파트 중
    콜론 2개+점을 포함하는 것)과의 호환이다 — "%H:%M:%S.%f"는 정확히 15자라
    `time_short`의 `part[:15]` 슬라이스와도 일치한다(테스트로 고정).
    """
    return dt.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S.%f")


def merge_captures(
    sources: "OrderedDict[str, List[Frame]]",
    alignment_sources: Optional["OrderedDict[str, List[Frame]]"] = None,
    reference_tag: Optional[str] = None,
) -> MergeResult:
    """다중 캡처를 시계 정렬 후 dedup·재번호해 단일 타임라인으로 병합한다.

    sources: 태그 → 프레임 리스트(OrderedDict). 나머지 태그는 기준(reference_tag)에
    대해 estimate_offset으로 보정된다. 각 Frame.source는 이미 태깅됨.

    reference_tag: 정렬 기준 태그. 생략하면 sources의 첫 키(기존 동작 — 보통
    "w1"). **reference_tag가 sources에 없어도**(내용 필터로 그 소스가 0건이라
    호출부에서 제외한 경우) alignment_sources에 그 태그가 있으면, 그 비콘
    집합을 기준으로 sources에 남은 **모든** 소스의 오프셋을 추정·적용한다 —
    생존 소스가 1개뿐이어도 이 경로에서는 오프셋 보정이 수행된다(dedup은
    자명하게 0). 기준 소스가 통째로 사라졌다고 오프셋 보정까지 포기하면,
    호출부가 이미 연기해 둔 시간 창(사용자의 실제 벽시계 기준)이 미보정
    (원시 스큐가 남은) epoch에 그대로 적용돼 구간이 어긋나거나 결과가 통째로
    비어버릴 수 있다(PR #23 리뷰 3라운드 Finding A).

    alignment_sources: 주어지면(sources와 동일 태그 체계) 오프셋 추정을 이
    프레임 집합으로 **우선** 수행한다 — pipeline.py가 mac_filter/ip_filter
    없이 비콘만 뽑은 별도 추출 결과(정렬 증거 전용)를 넘긴다. 내용 필터가
    걸린 본 sources는 STA mac_filter(비콘엔 STA 주소 없음)·ip_filter(비콘엔
    IP 없음)로 비콘이 통째로 사라질 수 있어, 그 상태로 오프셋을 추정하면
    TSF 매칭이 실패하고 ±5초 폴백도 183초 스큐엔 무력하다(PR #23 리뷰
    2라운드 Finding A). 정렬 증거로도 tsf 매칭이 부족하면(극히 드묾 — 비콘
    자체가 원래 적은 캡처) 본 sources 프레임 기준으로 2차 시도한다(seq
    폴백 포함 — 정렬 증거는 비콘 전용이라 seq 매칭에 쓸 데이터가 없다).
    None이면(기본) 기존처럼 sources로 직접 추정한다.
    """
    tags = list(sources.keys())
    if reference_tag is None:
        reference_tag = tags[0]
    reference_in_sources = reference_tag in sources
    reference = sources.get(reference_tag, [])
    align_reference = alignment_sources.get(reference_tag) if alignment_sources else None

    # 기준 태그가 sources에 있으면 기존처럼 그 외 나머지만 보정한다. 없으면
    # (내용 필터로 기준 소스가 0건 제외된 경우) sources 쪽엔 비교할 "이미
    # 정확한" 소스가 없다는 뜻이므로, 생존한 소스 **전부**가 정렬 증거
    # (alignment_sources) 기준으로 보정 대상이다(Finding A).
    tags_needing_offset = (
        [t for t in tags if t != reference_tag] if reference_in_sources else list(tags)
    )

    offsets: Dict[str, OffsetResult] = {}
    warnings: List[str] = []
    for tag in tags_needing_offset:
        frames = sources[tag]
        align_frames = alignment_sources.get(tag) if alignment_sources else None
        if align_reference and align_frames:
            result = estimate_offset(align_reference, align_frames)
            if result.method != "tsf":
                # reference가 sources에 없으면(빈 리스트) 이 2차 시도는
                # estimate_offset이 자연히 "none"으로 떨어진다 — 별도 분기 불필요.
                result = estimate_offset(reference, frames)
        else:
            result = estimate_offset(reference, frames)
        offsets[tag] = result
        # epoch를 보정해 통합 타임라인을 만든다. 오프셋이 0이 아닌 소스는
        # timestamp 문자열도 보정 epoch로 재생성한다 — overview 시작/종료·
        # evidence 표가 timestamp 문자열을 그대로 쓰므로, epoch만 보정하고
        # timestamp를 원본(다른 시계 도메인)으로 남겨두면 두 시계가 섞여
        # 표시된다(PR #23 리뷰 2라운드 Finding B). 기준(offset 0) 소스는
        # 항상 원본 timestamp를 유지한다.
        if result.offset_sec:
            for f in frames:
                f.epoch += result.offset_sec
                f.timestamp = _format_corrected_timestamp(f.epoch)
        warnings.extend(result.warnings)
        if result.method == "none":
            warnings.append(f"{tag}: 오프셋 추정 실패 — 원시 시계 그대로 병합됨")

    by_source_raw = {tag: len(sources[tag]) for tag in tags}

    if len(tags) == 1:
        # 생존 소스가 1개뿐 — dedup 대상이 없으니 재번호 없이 그대로
        # 반환한다(기존 파이프라인 하위 호환). only_tag(=tags[0])는
        # reference_tag와 다를 수 있다 — reference_tag가 sources에 없는
        # 경우(위 Finding A 경로)엔 이 유일한 생존 소스도 tags_needing_offset에
        # 포함돼 이미 오프셋이 적용됐을 수 있다. offsets는 그 결과를 그대로
        # 반영한다(reference_tag가 곧 only_tag인 기본 케이스는 tags_needing_offset이
        # 비어 있어 기존처럼 offsets={}가 된다).
        only_tag = tags[0]
        frames = sorted(sources[only_tag], key=lambda f: f.epoch)
        stats: Dict[str, Any] = {
            "window_ms": MERGE_DEDUP_WINDOW_SEC * 1000,
            "duplicates": 0,
            "kept": len(frames),
            "by_source_raw": by_source_raw,
            "coverage": {"both": 0, "only": {only_tag: len(frames)}},
        }
        return MergeResult(
            frames=frames,
            per_source={only_tag: sources[only_tag]},
            offsets=offsets,
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
