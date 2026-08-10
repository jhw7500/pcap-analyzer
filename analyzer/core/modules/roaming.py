"""4. 로밍 이벤트 탐지 (Auth → Assoc/Reassoc → EAPOL 4-Way)"""

from dataclasses import dataclass, field
import importlib
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..models import AnalysisSection as AnalysisSectionType
    from ..models import Frame as FrameType
else:
    AnalysisSectionType = Any
    FrameType = Any

try:
    from ..detector import mac_name
    from ..models import AnalysisSection, Frame
    from ..thresholds import ROAM_GAP_DANGER_MS
except (ImportError, ValueError):
    mac_name = importlib.import_module("detector").mac_name
    model_module = importlib.import_module("models")
    AnalysisSection = model_module.AnalysisSection
    Frame = model_module.Frame
    ROAM_GAP_DANGER_MS = importlib.import_module("thresholds").ROAM_GAP_DANGER_MS

# 진단 임계값 단일 소스(analyzer/core/thresholds.py)의 위험 경계와 동기.
SLOW_THRESHOLD_MS = ROAM_GAP_DANGER_MS

# 로밍 이벤트로 추출할 mgmt 서브타입 → 이벤트 종류(kind).
#   "11" Auth, "0" AssocReq, "2" ReassocReq — analyze()의 시퀀스 탐지 규칙과 동일.
# 디버그 타임라인의 roaming 마커는 이 규칙으로 탐지된 이벤트만 재사용한다(신규
# 탐지 없음). Auth/Reassoc/Assoc 각각을 공유 시간축 위 개별 마커로 투영한다.
ROAMING_EVENT_KINDS = {
    "11": "auth",
    "0": "assoc",
    "2": "reassoc",
}


#: Auth 앵커와 Assoc/Reassoc을 같은 로밍으로 인정하는 최대 간격(초).
#: 정상 로밍은 실측 중앙값 5.4ms·98%가 200ms 이내라 10초는 매우 관대한 상한이며,
#: "앵커를 못 찾아 한참 전 Auth와 엮이는" 경로를 끊기 위한 안전장치다.
ROAM_PAIR_MAX_GAP_SEC = 10.0

#: 같은 Auth 교환(STA 요청 ↔ AP 응답)으로 볼 최대 간격(초). 실측 수 µs~ms.
_SAME_AUTH_EXCHANGE_SEC = 1.0


#: gap 시작점으로 쓴 프레임 종류.
GAP_BASIS_REQUEST = "auth_request"    # STA → AP Auth 요청 (정확한 로밍 시작점)
GAP_BASIS_RESPONSE = "auth_response"  # AP → STA Auth 응답 (요청 미포착 시 하한값)

#: `missing` 코드 → 사람이 읽는 설명. 화면·리포트가 같은 문구를 쓰도록 단일 소스.
MISSING_FRAME_LABELS = {
    GAP_BASIS_REQUEST: "STA→AP Auth 요청",
    GAP_BASIS_RESPONSE: "AP→STA Auth 응답",
}

#: gap을 측정할 수 없을 때 붙는 설명(측정 불가 사유).
GAP_NOTE_UNMEASURABLE = (
    "이 로밍의 Auth 프레임(STA→AP 요청·AP→STA 응답)이 모두 캡처에 없어 "
    "시작 시각을 알 수 없음 — 모니터가 다른 채널에 있었을 가능성"
)
#: AP 응답만 잡혀 하한값으로 측정된 경우의 설명.
GAP_NOTE_LOWER_BOUND = (
    "STA→AP Auth 요청이 캡처에 없어 AP 응답을 시작점으로 계산 — 실제 gap은 이보다 큼"
)


@dataclass
class RoamPairing:
    """Assoc/Reassoc 하나에 대한 짝짓기 결과.

    앵커를 못 찾아도 **시퀀스 자체는 남긴다** — 로밍이 일어난 건 사실이므로
    횟수에서 빠지면 안 되고, 대신 gap을 지어내지 않고 측정 불가로 표시한다.
    """
    assoc: FrameType
    auth: Optional[FrameType]     #: 앵커 프레임. None이면 측정 불가.
    basis: Optional[str]          #: GAP_BASIS_* — gap 시작점으로 쓴 프레임 종류.
    missing: List[str]            #: 캡처에 없는 프레임 종류(GAP_BASIS_* 코드).

    @property
    def gap_ms(self) -> Optional[float]:
        """Auth 앵커 → Assoc 간격(ms). 앵커가 없으면 None(측정 불가)."""
        if self.auth is None:
            return None
        return (self.assoc.epoch - self.auth.epoch) * 1000

    @property
    def note(self) -> str:
        """측정 불가 사유 또는 하한값 안내. 정확히 측정됐으면 빈 문자열."""
        if self.auth is None:
            return GAP_NOTE_UNMEASURABLE
        if self.basis == GAP_BASIS_RESPONSE:
            return GAP_NOTE_LOWER_BOUND
        return ""


def pair_roaming_sequences(
    roaming_frames: List[FrameType], sta_macs: Any
) -> List[RoamPairing]:
    """Auth를 뒤따르는 Assoc/Reassoc에 짝지어 `RoamPairing` 목록을 만든다.

    `roaming.analyze`(텍스트)와 `structured._structured_roaming`(시각화)이 같은
    규칙을 쓰도록 **짝짓기 규칙의 단일 소스**로 둔다 — 두 곳에 복제돼 있던 탓에
    아래 결함도 양쪽에 똑같이 있었다.

    ## 이전 구현의 결함
    앵커를 `auth_events[sta] = frame`으로만 갱신하고 **소비 후 지우지 않았다.**
    그래서 Auth가 캡처되지 않은 로밍의 Assoc/Reassoc이 **수십 초 전의 낡은
    Auth**와 짝지어져 존재하지 않는 지연으로 보고됐다(실측: 2시간 캡처에서 17건이
    16.6~32.7초로 잡혔고, 전부 `ROAM_GAP_DANGER_MS`(100ms)를 넘겨 느린 로밍으로
    오분류됐다).

    ## 왜 Auth를 놓치는가
    모니터는 한 채널만 듣는다. STA가 대상 AP의 채널에서 Auth를 보내면 그 요청
    프레임이 캡처에 없을 수 있다. 실측 17건 중 16건이 정확히 이 경우로,
    **AP가 STA에게 보낸 Auth 응답은 Reassoc 3.4~6.2ms 전에 그대로 남아 있었다** —
    즉 로밍 자체는 정상 속도였다.

    ## 규칙
    1. STA가 **송신한** Auth(요청)가 로밍 시작점이라 1순위 앵커다.
    2. STA를 **수신자로 하는** Auth(AP 응답)는 폴백 앵커다. 같은 교환의 요청이
       이미 앵커면 덮어쓰지 않는다(요청 시각이 더 정확한 시작점).
    3. 짝지은 앵커는 **즉시 폐기**한다 — 다음 Assoc이 재사용할 수 없다.
    4. 앵커가 `ROAM_PAIR_MAX_GAP_SEC`보다 오래됐으면 그 로밍의 앵커로 보지 않는다.

    앵커를 찾지 못해도 **시퀀스는 남긴다** — 로밍이 일어난 건 사실이라 횟수에서
    빠지면 안 된다. 대신 gap을 지어내지 않고 `gap_ms=None`(측정 불가)으로 두고
    `missing`에 **어떤 프레임이 캡처에 없어서 측정할 수 없는지**를 담는다
    (정직한 공백). 소비자는 `gap_ms is None`을 반드시 처리해야 한다.

    Args:
        roaming_frames: `is_roaming_related` 프레임을 **캡처 시간순**으로.
        sta_macs: STA로 판정된 MAC 집합.

    Returns:
        `RoamPairing` 리스트(assoc 시간순). 측정 불가 항목도 포함된다.
    """
    # sta MAC → (앵커 프레임, 앵커 종류)
    anchors: Dict[str, Any] = {}
    pairs: List[RoamPairing] = []
    for frame in roaming_frames:
        if frame.subtype == "11":
            if frame.ta in sta_macs:
                # 규칙 1 — STA의 요청이 로밍 시작점이라 항상 우선
                anchors[frame.ta] = (frame, GAP_BASIS_REQUEST)
            elif frame.ra in sta_macs:
                prev = anchors.get(frame.ra)
                # 규칙 2 — 같은 교환의 요청이 이미 앵커면 덮어쓰지 않는다
                if prev is None or frame.epoch - prev[0].epoch > _SAME_AUTH_EXCHANGE_SEC:
                    anchors[frame.ra] = (frame, GAP_BASIS_RESPONSE)
            continue
        if frame.subtype in ("0", "2") and frame.ta in sta_macs:
            anchor = anchors.pop(frame.ta, None)      # 규칙 3 — 소비 즉시 폐기
            if anchor is not None:
                anchor_frame, basis = anchor
                delta = frame.epoch - anchor_frame.epoch
                if delta < 0 or delta > ROAM_PAIR_MAX_GAP_SEC:
                    anchor = None                     # 규칙 4 — 이 로밍의 Auth가 아니다
            if anchor is None:
                # 앵커 없음 = 이 로밍의 Auth 교환이 통째로 미포착. 시퀀스는 남기고
                # gap만 측정 불가로 둔다(로밍 횟수에서 빠지면 안 되므로).
                pairs.append(
                    RoamPairing(
                        assoc=frame,
                        auth=None,
                        basis=None,
                        missing=[GAP_BASIS_REQUEST, GAP_BASIS_RESPONSE],
                    )
                )
                continue
            pairs.append(
                RoamPairing(
                    assoc=frame,
                    auth=anchor_frame,
                    basis=basis,
                    # 응답만 잡힌 경우 요청이 미포착 — gap은 하한값이다.
                    missing=[] if basis == GAP_BASIS_REQUEST else [GAP_BASIS_REQUEST],
                )
            )
    return pairs


def _fmt_gap(gap_ms: Optional[float]) -> str:
    """gap을 표시 문자열로. 측정 불가(None)면 숫자 대신 '측정불가'."""
    return "측정불가" if gap_ms is None else f"{gap_ms:.1f}ms"


@dataclass
class SequenceInfo:
    sta: str
    ap: str
    auth_fnum: Optional[int]      #: 앵커 프레임 번호. 측정 불가면 None.
    assoc_fnum: int
    auth_ts: str
    assoc_type: str
    gap_ms: Optional[float]       #: None = 측정 불가(앵커 미포착)
    missing: List[str] = field(default_factory=list)
    note: str = ""
    total_roam_ms: Optional[float] = None   #: Auth 요청 → 4-way 완료 (로밍 실소요)
    slow_basis: Optional[str] = None        #: "total" | "gap_lower_bound" | None(판정 불가)

    @property
    def is_slow(self) -> bool:
        """느린 로밍 여부. **판정 불가면 False** — slow_basis로 구분할 것."""
        return self.slow_basis is not None and (
            (self.total_roam_ms is not None and self.total_roam_ms > SLOW_THRESHOLD_MS)
            or (self.slow_basis == "gap_lower_bound")
        )


@dataclass
class StaSummary:
    count: int = 0
    gaps: List[float] = field(default_factory=list)   #: 측정된 gap만 담는다
    ap_targets: Dict[str, int] = field(default_factory=dict)
    slow: int = 0
    unmeasured: int = 0                               #: gap 측정 불가 건수


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

    # 짝짓기 규칙·느린 로밍 판정 모두 _structured_roaming과 **같아야 한다**
    # (예전엔 로직이 복제돼 있어 화면과 텍스트 리포트가 어긋날 수 있었다).
    # 판정 기준은 gap이 아니라 로밍 전체 소요(Auth 요청 → 4-way 완료)다.
    from .eapol import build_handshakes, match_four_way

    sta_macs = {mac for mac, role in roles.items() if role.get("role") == "STA"}
    handshakes = build_handshakes(frames, roles).get("handshakes", [])

    sequences: List[SequenceInfo] = []
    for pairing in pair_roaming_sequences(roaming_frames, sta_macs):
        assoc = pairing.assoc
        hs = match_four_way(assoc.epoch, assoc.ta, handshakes, ap=assoc.ra)
        hs_end = hs.get("end_epoch") if hs else None
        total = None
        if pairing.auth is not None and isinstance(hs_end, (int, float)):
            total = round((hs_end - pairing.auth.epoch) * 1000, 1)
        gap = pairing.gap_ms
        if total is not None:
            basis = "total"
        elif gap is not None and gap > SLOW_THRESHOLD_MS:
            basis = "gap_lower_bound"   # total ≥ gap 이므로 확정적으로 느림
        else:
            basis = None                # 판정 불가
        sequences.append(SequenceInfo(
            sta=assoc.ta,
            ap=assoc.ra,
            auth_fnum=pairing.auth.number if pairing.auth else None,
            assoc_fnum=assoc.number,
            # 앵커가 없으면 Assoc 시각을 표시 기준으로 쓴다(시각 자체는 항상 안다).
            auth_ts=(pairing.auth or assoc).time_short,
            assoc_type=assoc.subtype_name,
            gap_ms=gap,
            missing=list(pairing.missing),
            note=pairing.note,
            total_roam_ms=total,
            slow_basis=basis,
        ))

    sta_summary: Dict[str, StaSummary] = {}
    for sequence in sequences:
        info = sta_summary.setdefault(sequence.sta, StaSummary())
        info.count += 1
        if sequence.gap_ms is None:
            info.unmeasured += 1
        else:
            info.gaps.append(sequence.gap_ms)
        info.ap_targets[sequence.ap] = info.ap_targets.get(sequence.ap, 0) + 1
        if sequence.is_slow:
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
        # 측정된 gap이 하나도 없으면 평균/최대를 0으로 찍지 않고 측정 불가로 둔다.
        avg_str = f"{avg_gap:>6.1f}ms" if info.gaps else "  측정불가"
        max_str = f"{max_gap:>6.1f}ms" if info.gaps else "  측정불가"
        if info.unmeasured:
            ap_str = f"{ap_str} (gap 측정불가 {info.unmeasured}건)"
        lines.append(
            f"{mac_name(sta, roles):>15} | {info.count:>5} | {avg_str} | {max_str} | {slow_str:>6} | {ap_str}"
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
                f"{idx:>3} | {mac_name(sequence.sta, roles):>15} | "
                f"{('Auth #' + str(sequence.auth_fnum)) if sequence.auth_fnum else 'Auth 미포착':<14} | "
                f"#{sequence.assoc_fnum:<8} | {_fmt_gap(sequence.gap_ms):>8} | {mac_name(sequence.ap, roles):>15}"
            )

    slow_sequences = [sequence for sequence in sequences if sequence.is_slow]
    unmeasured = [s for s in sequences if s.gap_ms is None]
    if slow_sequences:
        lines.append("")
        lines.append(
            f"느린 로밍 상세 (전체 소요 >{SLOW_THRESHOLD_MS}ms — Auth 요청→4-way 완료 기준):"
        )
        lines.append(
            f"{'#':>3} | {'STA':>15} | {'Time':>15} | {'Gap':>8} | {'AP':>15} | {'Type':>12}"
        )
        lines.append("-" * 80)
        for idx, sequence in enumerate(slow_sequences, start=1):
            lines.append(
                f"{idx:>3} | {mac_name(sequence.sta, roles):>15} | {sequence.auth_ts:>15} | "
                f"{_fmt_gap(sequence.gap_ms):>8} | {mac_name(sequence.ap, roles):>15} | {sequence.assoc_type}"
            )

    summary = (
        f"로밍 시퀀스 {len(sequences)}건, "
        f"느린로밍(전체 소요 >{SLOW_THRESHOLD_MS}ms) {len(slow_sequences)}건"
    )
    if unmeasured:
        summary += f", gap 측정불가 {len(unmeasured)}건"
    undecided = [x for x in sequences if x.slow_basis is None]
    if undecided:
        summary += f", 느림 판정불가 {len(undecided)}건"

    return AnalysisSection(title="4. 로밍 이벤트", lines=lines, summary=summary)
