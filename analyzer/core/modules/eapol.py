"""EAPOL 4-way 핸드셰이크 타이밍 분석.

STA별 EAPOL 메시지(msgnr 1~4)를 시간순으로 그룹핑해 각 핸드셰이크의
시작/끝 epoch, duration_ms, 메시지별 재전송 수, 미완료 여부를 구조화한다.
소비자: pipeline(structured.eapol), structured._structured_roaming(four_way_ms).
"""

import importlib
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..models import Frame as FrameType
else:
    FrameType = Any

try:
    from ..detector import mac_name
except (ImportError, ValueError):
    mac_name = importlib.import_module("detector").mac_name

# 같은 STA의 EAPOL 메시지 간격이 이 시간을 넘으면 별개 핸드셰이크로 분리.
# 4-way는 정상적으로 수십 ms 안에 끝나고, 재전송을 감안해도 초 단위를 넘지 않는다.
HANDSHAKE_GAP_SEC = 5.0


def _parse_msgnr(raw: str) -> Optional[int]:
    """tshark msgnr 문자열 → 1~4 정수. multi-value는 첫 값. 그 외 None."""
    if not raw:
        return None
    first = str(raw).split(",")[0].strip()
    try:
        n = int(first)
    except (ValueError, TypeError):
        return None
    return n if 1 <= n <= 4 else None


def _sta_ap_of(frame: FrameType, sta_macs: set) -> Optional[tuple]:
    """EAPOL 프레임의 (STA, AP) MAC 추출.

    msg 1/3은 AP→STA(ra=STA), msg 2/4는 STA→AP(ta=STA). roles 기반으로
    STA 쪽을 식별하고, 반대편을 AP로 본다. 어느 쪽도 STA가 아니면 None.
    """
    if frame.ta in sta_macs:
        return frame.ta, frame.ra
    if frame.ra in sta_macs:
        return frame.ra, frame.ta
    return None


def _finalize(hs: Dict[str, Any]) -> Dict[str, Any]:
    """진행 중 핸드셰이크 상태 → 직렬화용 dict."""
    msgs = hs["msgs"]  # {msgnr: {"count": n, "retry_frames": m}}
    messages = {}
    for nr in sorted(msgs):
        m = msgs[nr]
        # 재전송 = retry bit 프레임 수와 동일 msgnr 반복(count-1) 중 큰 값
        messages[str(nr)] = {
            "count": m["count"],
            "retries": max(m["count"] - 1, m["retry_frames"]),
        }
    complete = all(str(n) in messages for n in (1, 2, 3, 4))
    return {
        "sta": hs["sta"],
        "sta_name": hs["sta_name"],
        "ap": hs["ap"],
        "ap_name": hs["ap_name"],
        "start_epoch": hs["start_epoch"],
        "end_epoch": hs["end_epoch"],
        "duration_ms": round((hs["end_epoch"] - hs["start_epoch"]) * 1000, 1),
        "messages": messages,
        "retry_total": sum(m["retries"] for m in messages.values()),
        "complete": complete,
        "frame_refs": hs["frame_refs"],
    }


def build_handshakes(
    frames: List[FrameType], roles: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    """EAPOL 4-way 핸드셰이크 목록을 구조화해 반환. → structured.eapol

    그룹핑 규칙(STA 단위, 시간순):
    - msgnr 1 이 오고 현재 핸드셰이크가 이미 msg2 이상 진행됐으면 새 핸드셰이크
      (msg1만 반복되면 msg1 재전송으로 같은 핸드셰이크에 귀속)
    - 직전 메시지와 HANDSHAKE_GAP_SEC 초과 간격이면 새 핸드셰이크
    - AP가 바뀌면(로밍) 새 핸드셰이크
    """
    sta_macs = {mac for mac, info in roles.items() if info.get("role") == "STA"}

    active: Dict[str, Dict[str, Any]] = {}  # sta → 진행 중 핸드셰이크 상태
    handshakes: List[Dict[str, Any]] = []

    def _close(sta: str) -> None:
        hs = active.pop(sta, None)
        if hs is not None:
            handshakes.append(_finalize(hs))

    for f in frames:
        msgnr = _parse_msgnr(getattr(f, "eapol_msgnr", "") or "")
        if msgnr is None:
            continue
        pair = _sta_ap_of(f, sta_macs)
        if pair is None:
            continue
        sta, ap = pair

        hs = active.get(sta)
        max_msg = max(hs["msgs"]) if hs else 0
        if hs is not None and (
            f.epoch - hs["end_epoch"] > HANDSHAKE_GAP_SEC
            or ap != hs["ap"]
            or (msgnr == 1 and max_msg >= 2)
        ):
            _close(sta)
            hs = None

        if hs is None:
            hs = active[sta] = {
                "sta": sta,
                "sta_name": mac_name(sta, roles),
                "ap": ap,
                "ap_name": mac_name(ap, roles),
                "start_epoch": f.epoch,
                "end_epoch": f.epoch,
                "msgs": {},
                "frame_refs": [],
            }
        hs["end_epoch"] = f.epoch
        m = hs["msgs"].setdefault(msgnr, {"count": 0, "retry_frames": 0})
        m["count"] += 1
        if f.retry:
            m["retry_frames"] += 1
        hs["frame_refs"].append(f.number)

    for sta in list(active):
        _close(sta)

    handshakes.sort(key=lambda h: h["start_epoch"])
    return {"handshakes": handshakes}


def match_four_way(
    assoc_epoch: float,
    sta: str,
    handshakes: List[Dict[str, Any]],
    window_sec: float = HANDSHAKE_GAP_SEC,
    ap: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """assoc 직후 첫 완결 핸드셰이크 dict. 매칭 실패 시 None.

    핸드셰이크 msg1은 assoc과 거의 동시에 캡처될 수 있어 50ms 슬랙을 둔다.
    ap가 주어지면 해당 AP와의 핸드셰이크만 매칭 — 다중 AP 로밍 캡처에서
    이전 AP의 핸드셰이크가 새 AP 행에 오귀속되는 것을 방지.

    `match_four_way_ms`(소요 시간만)와 로밍 전체 소요(`total_roam_ms`, 핸드셰이크
    **종료 시각**이 필요) 양쪽이 같은 매칭 규칙을 쓰도록 이 함수를 단일 소스로 둔다.
    """
    best = None
    for h in handshakes:
        if h.get("sta") != sta or not h.get("complete"):
            continue
        if ap and h.get("ap") != ap:
            continue
        start = h.get("start_epoch")
        if not isinstance(start, (int, float)):
            continue
        if assoc_epoch - 0.05 <= start <= assoc_epoch + window_sec:
            if best is None or start < best.get("start_epoch", float("inf")):
                best = h
    return best


def match_four_way_completion(
    assoc_epoch: float,
    sta: str,
    handshakes: List[Dict[str, Any]],
    window_sec: float = HANDSHAKE_GAP_SEC,
    ap: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Assoc 직후 msg4가 관측된 첫 핸드셰이크를 반환한다.

    EAPOL 탭의 ``complete``는 1~4번을 모두 포착했는지 나타내므로 그대로 엄격하게
    유지한다. 반면 로밍 전체 소요의 끝점은 STA→AP msg4 자체가 완료 증거다. TEST5
    실측처럼 msg1·2·4는 있고 msg3만 놓친 경우에도 Auth→msg4 전체시간은 측정할 수
    있으므로, 로밍 소비자는 이 함수를 사용한다.
    """
    best = None
    for h in handshakes:
        if h.get("sta") != sta:
            continue
        if ap and h.get("ap") != ap:
            continue
        messages = h.get("messages")
        if not isinstance(messages, dict) or "4" not in messages:
            continue
        start = h.get("start_epoch")
        if not isinstance(start, (int, float)):
            continue
        if assoc_epoch - 0.05 <= start <= assoc_epoch + window_sec:
            if best is None or start < best.get("start_epoch", float("inf")):
                best = h
    return best


def match_four_way_ms(
    assoc_epoch: float,
    sta: str,
    handshakes: List[Dict[str, Any]],
    window_sec: float = HANDSHAKE_GAP_SEC,
    ap: Optional[str] = None,
) -> Optional[float]:
    """assoc 직후 첫 완결 핸드셰이크의 duration_ms. 매칭 실패 시 None."""
    best = match_four_way(assoc_epoch, sta, handshakes, window_sec, ap)
    return best.get("duration_ms") if best else None
