"""4. 로밍 이벤트 탐지 (Auth → Assoc/Reassoc → EAPOL 4-Way)"""

from dataclasses import dataclass, field
import importlib
import math
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from ..models import AnalysisSection as AnalysisSectionType
    from ..models import Frame as FrameType
else:
    AnalysisSectionType = Any
    FrameType = Any

try:
    from ..detector import mac_name
    from ..models import AnalysisSection, Frame
    from ..thresholds import ROAM_PCAP_TOTAL_SLOW_MS, STA_ROAM_SLOW_MS
except (ImportError, ValueError):
    mac_name = importlib.import_module("detector").mac_name
    model_module = importlib.import_module("models")
    AnalysisSection = model_module.AnalysisSection
    Frame = model_module.Frame
    threshold_module = importlib.import_module("thresholds")
    ROAM_PCAP_TOTAL_SLOW_MS = threshold_module.ROAM_PCAP_TOTAL_SLOW_MS
    STA_ROAM_SLOW_MS = threshold_module.STA_ROAM_SLOW_MS

# 구버전 외부 import 호환. 신규 코드는 측정 기준이 드러나는 두 상수를 직접 쓴다.
SLOW_THRESHOLD_MS = ROAM_PCAP_TOTAL_SLOW_MS

# structured 결과가 이 정책 키를 가질 때 STA 로그 체감값을 우선 판정한다.
# 키가 없는 저장 결과는 기존 pcap 판정·표시 경로를 그대로 탄다.
STA_SLOW_POLICY = "sta_log_total_preferred_v1"

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

#: 같은 Assoc/Reassoc 교환의 **재전송 사본**으로 볼 최대 간격(초).
#: 802.11 재전송은 ACK 타임아웃 단위(수 ms)라 1초면 충분히 관대하다. 이 창을
#: 넘어 다시 온 요청은 retry 비트가 있어도 별개 시도로 본다(합쳤다가 실제 재시도
#: 로밍을 놓치는 것보다, 나눠서 세는 쪽이 로밍 횟수 왜곡이 작다).
_ASSOC_RETRY_SEC = 1.0


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


def classify_slow(
    total_roam_ms: Optional[float],
    gap_ms: Optional[float],
    sta_total_ms: Optional[float] = None,
) -> Tuple[bool, Optional[str]]:
    """느린 로밍 판정 — `(is_slow, slow_basis)`. **판정 규칙의 단일 소스.**

    `roaming.analyze`(텍스트)와 `structured._structured_roaming`(화면)이 서로
    다른 느린 로밍 건수를 말하면 안 된다. 이 PR이 고친 gap 허위 보고의 근원이
    바로 짝짓기 로직 복제였으므로, 판정 규칙도 처음부터 한 곳에만 둔다.

    STA 로그가 매칭됐으면 **STA 체감 전체**(ROAM 명령 → CONNECTED)를 150ms와
    비교한다. TEST9 837건의 p50 96ms·p95 138ms에서 100ms를 적용하면 43%가
    느림으로 뒤집히므로, 승인된 운용 경계 150ms를 쓴다.

    STA 로그가 없으면 기존 pcap **로밍 전체 소요**(Auth 요청 → 4-way 완료)를
    100ms와 비교한다. 구버전·로그 미첨부 분석의 판정을 바꾸지 않는 폴백이다.
    gap(Auth→Reassoc)에만 임계를 걸면 전체 25.2ms 중 5.3ms 구간만 보게 돼,
    4-way가 길어 실제로 느린 로밍을 놓친다(실측: gap 6.3ms인데 4-way 41.7ms로
    전체 105ms인 건이 있다).

    pcap total이 없어도(4-way 미포착) **total ≥ gap이 항상 성립**하므로 gap이 이미
    pcap 임계를 넘으면 그 로밍은 확정적으로 느리다 — 아는 정보를 버리지 않는다.
    둘 다 아니면 판정 불가(`None`)이며, '정상'이 아니라 '모름'이므로 건강도
    분모에서 제외해야 한다.
    """
    def _measurement(value: Any) -> bool:
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
            and value >= 0
        )

    if _measurement(sta_total_ms):
        return sta_total_ms > STA_ROAM_SLOW_MS, "sta_log_total"
    if _measurement(total_roam_ms):
        return total_roam_ms > ROAM_PCAP_TOTAL_SLOW_MS, "total"
    if _measurement(gap_ms) and gap_ms > ROAM_PCAP_TOTAL_SLOW_MS:
        return True, "gap_lower_bound"
    return False, None


def classify_sequence_slow(seq: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """structured 로밍 시퀀스의 느림 판정. 필드 추출까지 포함한 단일 소스."""
    sta_log = seq.get("sta_log")
    sta_total = sta_log.get("total_ms") if isinstance(sta_log, dict) else None
    return classify_slow(seq.get("total_roam_ms"), seq.get("gap_ms"), sta_total)


def apply_slow_classification(seq: Dict[str, Any]) -> Dict[str, Any]:
    """시퀀스에 단일 소스 판정 결과를 기록하고 같은 객체를 반환한다."""
    seq["is_slow"], seq["slow_basis"] = classify_sequence_slow(seq)
    return seq


def reclassify_roaming_sequences(roaming: Dict[str, Any]) -> None:
    """STA 로그 부착 후 모든 시퀀스를 체감 우선 정책으로 다시 판정한다."""
    for seq in roaming.get("sequences") or []:
        if isinstance(seq, dict):
            apply_slow_classification(seq)
    roaming["slow_policy"] = STA_SLOW_POLICY
    roaming["slow_thresholds_ms"] = {
        "sta_log_total": STA_ROAM_SLOW_MS,
        "pcap_total": ROAM_PCAP_TOTAL_SLOW_MS,
    }


def roam_total_ms(
    auth_epoch: Optional[float], handshake: Optional[Dict[str, Any]]
) -> Tuple[Optional[float], str]:
    """로밍 전체 소요(Auth 요청 → 4-way 완료)와 계산 불가 사유. **단일 소스.**

    `gap + four_way`의 **단순 합이 아니다** — Reassoc 요청과 4-way 시작 사이의 대기
    (실측 ~2ms)가 빠지기 때문이다(gap 4.0 + 4way 11.6 = 15.6인데 실제 전체는 17.6).
    그래서 핸드셰이크의 **실제 종료 시각**에서 계산한다.

    `roaming.analyze`(텍스트)와 `structured._structured_roaming`(화면)이 이 값을 각자
    계산하고 있었다 — 같은 식이 두 곳에 있으면 한쪽만 고쳐져 두 화면이 다른 숫자를
    말하게 된다(`classify_slow`를 단일 소스로 만든 것과 같은 이유).

    Returns:
        `(total_ms, note)`. 계산 불가면 `(None, 사유)` — 값을 지어내지 않고 왜 없는지
        남긴다. 텍스트 모듈처럼 note가 필요 없으면 무시하면 된다.
    """
    hs_end = handshake.get("end_epoch") if handshake else None
    if auth_epoch is not None and isinstance(hs_end, (int, float)):
        return round((hs_end - auth_epoch) * 1000, 1), ""
    if auth_epoch is None:
        return None, "Auth 프레임 미포착 — 시작 시각을 몰라 전체 소요 계산 불가"
    return None, (
        "4-way 핸드셰이크가 캡처에 없어 완료 시점 불명 "
        "(802.11r FT로 생략됐거나 모니터가 EAPOL을 놓침)"
    )


def is_decided(seq: Dict[str, Any]) -> bool:
    """느린 로밍 **판정이 선** 시퀀스인가 — 건강도 분모의 기준. **단일 소스.**

    판정 가능의 기준은 gap 유무가 아니라 `slow_basis`다: total을 알거나, total은
    몰라도 gap이 이미 임계를 넘어 확정된 경우가 판정 가능이다. 판정 불가를 분모에
    넣으면 "느린 비율"이 희석돼 **캡처가 나쁠수록 건강해 보이는** 역전이 생긴다.

    구버전 result에는 `slow_basis` 키가 없으므로 gap 유무로 폴백한다. `bool`은
    `int`의 서브클래스라 `gap_ms=True`가 측정값으로 통과하는 것을 막는다.

    전체 건강도와 STA별 점수가 이 술어를 각자 인라인으로 갖고 있었다 — 한쪽만
    고치면 두 점수가 다른 모집단을 쓰게 된다.
    """
    if seq.get("slow_basis") is not None:
        return True
    gap = seq.get("gap_ms")
    return (
        "slow_basis" not in seq
        and isinstance(gap, (int, float))
        and not isinstance(gap, bool)
    )


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
    5. 같은 STA·같은 subtype의 **retry 프레임**이 `_ASSOC_RETRY_SEC` 안에 다시 오면
       재전송 사본으로 보고 건너뛴다 — 규칙 3 때문에 사본은 앵커를 못 찾아
       "측정 불가" 시퀀스를 하나 더 만들고, 로밍 횟수까지 함께 부풀린다.

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
    # sta MAC → (직전 Assoc/Reassoc 시각, subtype) — 재전송 사본 식별용
    last_assoc: Dict[str, Any] = {}
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
            # 규칙 5 — 재전송 사본은 새 로밍이 아니다.
            # 802.11 Assoc/Reassoc 요청이 재전송되면 같은 교환의 프레임이 두 번
            # 잡힌다. 그대로 두면 두 번째는 앵커를 이미 소비한 뒤라 "측정 불가"
            # 시퀀스가 하나 더 생겨 **로밍 횟수와 측정 불가 건수가 함께 부풀려진다**
            # (STA 로그도 같은 로밍에 두 번 붙는다). 재전송은 retry 비트로 정확히
            # 구분되므로 시간 휴리스틱만으로 합치지 않는다 — 같은 STA가 같은
            # subtype으로 창 안에 다시 보낸 **retry 프레임**만 건너뛴다.
            prev_assoc = last_assoc.get(frame.ta)
            if (
                getattr(frame, "retry", False)
                and prev_assoc is not None
                and prev_assoc[1] == frame.subtype
                and abs(frame.epoch - prev_assoc[0]) <= _ASSOC_RETRY_SEC
            ):
                continue
            last_assoc[frame.ta] = (frame.epoch, frame.subtype)
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
    sta_total_ms: Optional[float] = None    #: ROAM 명령 → CONNECTED (STA 체감 전체)
    slow_basis: Optional[str] = None        #: "sta_log_total" | "total" | "gap_lower_bound" | None

    @property
    def is_slow(self) -> bool:
        """느린 로밍 여부. **판정 불가면 False** — `is_undecided`로 구분할 것."""
        return classify_slow(self.total_roam_ms, self.gap_ms, self.sta_total_ms)[0]

    @property
    def is_undecided(self) -> bool:
        """느림/정상을 **판정할 수 없는** 로밍(전체 소요도 gap도 근거가 안 됨).

        `not seq.is_slow`를 "정상 로밍"으로 읽으면 판정 불가가 정상에 섞인다 —
        건강도 분모 오염과 같은 실수다. 정상만 세려면
        `not seq.is_slow and not seq.is_undecided`.
        """
        return classify_slow(
            self.total_roam_ms, self.gap_ms, self.sta_total_ms
        )[1] is None


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


def _render_sequences(
    sequences: List[SequenceInfo],
    roles: Dict[str, Dict[str, Any]],
    roaming_frame_count: int,
    *,
    sta_policy: bool = False,
) -> AnalysisSectionType:
    """이미 구조화·판정된 시퀀스를 텍스트 섹션으로 직렬화한다."""
    lines: List[str] = []
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
        f"로밍 관련 프레임: {roaming_frame_count}건, 시퀀스: {len(sequences)}건"
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
        avg_str = f"{avg_gap:>6.1f}ms" if info.gaps else "  측정불가"
        max_str = f"{max_gap:>6.1f}ms" if info.gaps else "  측정불가"
        if info.unmeasured:
            ap_str = f"{ap_str} (gap 측정불가 {info.unmeasured}건)"
        lines.append(
            f"{mac_name(sta, roles):>15} | {info.count:>5} | {avg_str} | "
            f"{max_str} | {slow_str:>6} | {ap_str}"
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
                f"#{sequence.assoc_fnum:<8} | {_fmt_gap(sequence.gap_ms):>8} | "
                f"{mac_name(sequence.ap, roles):>15}"
            )

    threshold_label = (
        f"STA 체감 >{STA_ROAM_SLOW_MS}ms / 로그 미매칭 pcap 전체 "
        f">{ROAM_PCAP_TOTAL_SLOW_MS}ms"
        if sta_policy
        else f"전체 소요 >{ROAM_PCAP_TOTAL_SLOW_MS}ms"
    )
    slow_sequences = [sequence for sequence in sequences if sequence.is_slow]
    unmeasured = [s for s in sequences if s.gap_ms is None]
    if slow_sequences:
        lines.append("")
        lines.append(f"느린 로밍 상세 ({threshold_label}):")
        header = (
            f"{'#':>3} | {'STA':>15} | {'Time':>15} | {'Gap':>8} | "
            f"{'AP':>15} | {'Type':>12}"
        )
        if sta_policy:
            header += " | 판정값"
        lines.append(header)
        lines.append("-" * 80)
        for idx, sequence in enumerate(slow_sequences, start=1):
            row = (
                f"{idx:>3} | {mac_name(sequence.sta, roles):>15} | "
                f"{sequence.auth_ts:>15} | {_fmt_gap(sequence.gap_ms):>8} | "
                f"{mac_name(sequence.ap, roles):>15} | {sequence.assoc_type}"
            )
            if sta_policy:
                if sequence.slow_basis == "sta_log_total":
                    judgment = f"STA 체감 {sequence.sta_total_ms:.1f}ms"
                elif sequence.total_roam_ms is not None:
                    judgment = f"pcap 전체 {sequence.total_roam_ms:.1f}ms"
                else:
                    judgment = f"pcap Gap 하한 {_fmt_gap(sequence.gap_ms)}"
                row += f" | {judgment}"
            lines.append(row)

    summary = (
        f"로밍 시퀀스 {len(sequences)}건, "
        f"느린로밍({threshold_label}) {len(slow_sequences)}건"
    )
    if unmeasured:
        summary += f", gap 측정불가 {len(unmeasured)}건"
    undecided = [x for x in sequences if x.is_undecided]
    if undecided:
        summary += f", 느림 판정불가 {len(undecided)}건"

    return AnalysisSection(title="4. 로밍 이벤트", lines=lines, summary=summary)


def section_from_structured(
    roaming: Dict[str, Any], roles: Dict[str, Dict[str, Any]]
) -> AnalysisSectionType:
    """structured.roaming을 텍스트 섹션의 유일한 입력으로 직렬화한다.

    pipeline은 STA 로그 부착·재판정이 끝난 뒤 이 함수를 호출한다. 따라서 고정
    ``analyze(frames, roles, index)`` 시그니처가 station_logs를 볼 수 없어 화면과
    텍스트가 갈리던 구조를 없앤다.
    """
    raw_sequences = roaming.get("sequences") or []
    if not raw_sequences and not roaming.get("roaming_frame_count"):
        return AnalysisSection(
            title="4. 로밍 이벤트", lines=["로밍 관련 프레임 없음"], summary="로밍 없음"
        )

    sequences: List[SequenceInfo] = []
    for seq in raw_sequences:
        if not isinstance(seq, dict):
            continue
        sta_log = seq.get("sta_log")
        sta_total = sta_log.get("total_ms") if isinstance(sta_log, dict) else None
        auth_epoch = seq.get("auth_epoch")
        assoc_epoch = seq.get("assoc_epoch")
        display_epoch = auth_epoch if isinstance(auth_epoch, (int, float)) else assoc_epoch
        auth_ts = seq.get("event_time") or (
            str(display_epoch) if display_epoch is not None else "?"
        )
        sequences.append(
            SequenceInfo(
                sta=seq.get("sta") or "",
                ap=seq.get("ap") or "",
                auth_fnum=seq.get("auth_fnum"),
                assoc_fnum=seq.get("assoc_fnum") or 0,
                auth_ts=auth_ts,
                assoc_type=seq.get("assoc_type") or "",
                gap_ms=seq.get("gap_ms"),
                missing=list(seq.get("missing") or []),
                note=seq.get("gap_note") or "",
                total_roam_ms=seq.get("total_roam_ms"),
                sta_total_ms=sta_total,
                slow_basis=seq.get("slow_basis"),
            )
        )
    return _render_sequences(
        sequences,
        roles,
        roaming.get("roaming_frame_count") or 0,
        sta_policy=roaming.get("slow_policy") == STA_SLOW_POLICY,
    )


def analyze(
    frames: List[FrameType], roles: Dict[str, Dict[str, Any]], index: Any = None
) -> AnalysisSectionType:
    del index

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
        # 전체 소요 계산은 roam_total_ms(단일 소스) — 화면(structured)과 같은 식을
        # 쓴다. 텍스트 섹션은 사유(note)를 싣지 않으므로 값만 받는다.
        total, _ = roam_total_ms(
            pairing.auth.epoch if pairing.auth is not None else None, hs
        )
        gap = pairing.gap_ms
        _, basis = classify_slow(total, gap)   # 판정 규칙 단일 소스
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

    return _render_sequences(sequences, roles, len(roaming_frames))
