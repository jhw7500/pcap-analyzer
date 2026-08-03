"""유선(포트 미러) pcap에서 ping ground truth를 만든다.

검증된 exping의 ICMP 추출·매칭 규칙(응답 인정 상한 1초, 꼬리 무응답 제거)을
그대로 재사용한다 — 대시보드용으로 EXPING xlsx 재현 규칙(RTT 정수 보정,
전각 문자열)은 쓰지 않고 Exchange 수준에서 소비한다. docs/EXPING.md 참조.
"""
import datetime as dt
from typing import Any, Dict, List, Optional, Tuple

from . import exping
from .ping_matching import find_time_streaks

#: streaks 항목 수 상한 — 비정상 캡처(수천 구간)로 결과 JSON이 비대해지는 것 방지
MAX_STREAKS = 100
#: ng_epochs 상한 — 타임라인 마커용 샘플
MAX_NG_EPOCHS = 1000

#: 시간 필터 입력 형식 — 초 생략형도 허용
_TIME_FILTER_FORMATS: Tuple[str, ...] = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M")


def _parse_local_epoch(value: str) -> Optional[float]:
    """"YYYY-MM-DD HH:MM[:SS]" 문자열을 로컬 타임존 기준 epoch로 파싱.

    무선 쪽 extractor.build_tshark_cmd의 `frame.time >= "..."` 필터도 tshark가
    로컬 타임존으로 해석하므로, 이 함수도 로컬 타임존(datetime.timestamp())을
    써야 두 필터가 같은 구간을 가리킨다. 실패 시 None.
    """
    for fmt in _TIME_FILTER_FORMATS:
        try:
            return dt.datetime.strptime(value, fmt).timestamp()
        except ValueError:
            continue
    return None


def _filter_exchanges(
    exchanges: List["exping.Exchange"],
    sender: str,
    time_start: str,
    time_end: str,
    ip_filter: str,
) -> Tuple[Optional[List["exping.Exchange"]], str]:
    """시간/IP 필터를 적용한다. 파싱 실패 시 (None, 에러메시지)를 반환.

    mac_filter는 유선(비-802.11) exchange에 MAC 개념이 없어 적용하지 않는다
    (호출부인 pipeline.py 주석 참조).
    """
    out = exchanges
    if time_start:
        start_epoch = _parse_local_epoch(time_start)
        if start_epoch is None:
            return None, f"시간 필터를 해석할 수 없다: {time_start}"
        out = [x for x in out if x.time >= start_epoch]
    if time_end:
        end_epoch = _parse_local_epoch(time_end)
        if end_epoch is None:
            return None, f"시간 필터를 해석할 수 없다: {time_end}"
        out = [x for x in out if x.time < end_epoch]
    if ip_filter:
        ips = {ip.strip() for ip in ip_filter.split(",") if ip.strip()}
        # 무선 'ip.addr == X'는 src/dst 어느 쪽이든 매칭. sender는 이 캡처의
        # 모든 exchange에서 고정 src이므로, sender가 필터에 있으면 전부
        # 매칭되는 것과 같다(=필터링 없음). 아니면 target(=dst)으로 좁힌다.
        if ips and sender not in ips:
            out = [x for x in out if x.target in ips]
    return out, ""


def build_ground_truth(
    pcap_path: str,
    tshark_path: str = "tshark",
    reply_timeout: float = exping.DEFAULT_REPLY_TIMEOUT,
    time_start: str = "",
    time_end: str = "",
    ip_filter: str = "",
) -> Dict[str, Any]:
    """유선 pcap → ping ground truth dict. 실패 시 {"error": str, "warnings": [...]}.

    time_start/time_end/ip_filter는 무선 extract_frames()가 받는 동일 인자와
    같은 구간을 가리키도록 대칭으로 구현했다 — 서로 다른 구간을 비교하지 않기
    위함(무선 필터만 적용되고 유선은 전체 구간을 쓰면 손실률이 왜곡된다).
    적용 순서는 "꼬리 무응답 제거(전체 캡처 기준) → 시간/IP 필터"다. 반대로 하면
    필터가 창 끝을 자를 때 창 안 마지막 자리의 진짜 손실이 "물리적 꼬리"로
    오인되어 조용히 사라질 수 있다(trailing_dropped는 항상 물리적 꼬리 기준).

    취소 이벤트는 지원하지 않는다 — exping.extract_exchanges에 취소 훅이 없고
    child_timeout(기본 3600초) 상한만 있다. ICMP 디스플레이 필터라 대체로 빠르다.
    """
    warnings: List[str] = []
    try:
        exchanges, sender = exping.extract_exchanges(
            pcap_path, tshark=tshark_path, timeout=reply_timeout
        )
    except FileNotFoundError:
        return {"error": f"tshark 를 찾을 수 없다: {tshark_path}", "warnings": warnings}
    except (ValueError, TimeoutError) as exc:
        return {"error": str(exc), "warnings": warnings}

    # drop 이전 체크: ICMP 교환이 처음부터 없는 경우
    if not exchanges:
        return {"error": f"{sender} 가 보낸 echo request 가 없다", "warnings": warnings}

    # 꼬리 무응답 제거는 필터 적용 "전" 전체 캡처 기준으로 한다. pairing(위
    # extract_exchanges)이 전체 캡처 기준으로 이미 끝났으므로, 창 끝 근처 요청의
    # 응답이 창 밖(그러나 캡처 안)에 있어도 이미 매칭되어 있다 — 즉 시간 필터의
    # 끝은 "캡처가 응답보다 먼저 끊긴" 물리적 꼬리가 아니다. 필터를 먼저 적용해
    # 잘라낸 뒤 꼬리를 제거하면, 창 안 마지막 자리에 우연히 놓인 **진짜 손실**이
    # "꼬리라 판정 불가"로 오인되어 조용히 사라진다. 그래서 물리적 꼬리(전체
    # 캡처의 맨 끝)만 걸러내도록 필터보다 먼저 수행한다.
    exchanges, dropped = exping.drop_trailing_unanswered(exchanges)
    if dropped:
        warnings.append(
            f"꼬리 무응답 요청 {dropped}건 제외 — 캡처가 응답보다 먼저 끊긴 구간"
        )

    # drop 이후 체크: 요청은 있었지만 응답이 전부 없는 경우 (100% 손실)
    if not exchanges:
        return {
            "error": f"응답 있는 요청이 하나도 없다 — 요청 {dropped}건 전부 무응답 (100% 손실이거나 미러 구성이 응답 방향을 놓친 캡처)",
            "warnings": warnings
        }

    if time_start or time_end or ip_filter:
        filtered, err = _filter_exchanges(exchanges, sender, time_start, time_end, ip_filter)
        if filtered is None:
            return {"error": err, "warnings": warnings}
        exchanges = filtered
        if not exchanges:
            return {"error": "필터 구간에 echo request 가 없다", "warnings": warnings}

    ng = [x for x in exchanges if not x.answered]
    targets: Dict[str, Dict[str, int]] = {}
    for x in exchanges:
        t = targets.setdefault(x.target, {"total": 0, "ng": 0})
        t["total"] += 1
        t["ng"] += 0 if x.answered else 1

    streaks: List[Dict[str, Any]] = []
    for target in sorted(targets):
        epochs = sorted(x.time for x in ng if x.target == target)
        for si, ei in find_time_streaks(epochs):
            streaks.append({
                "target": target,
                "start_epoch": epochs[si],
                "end_epoch": epochs[ei],
                "count": ei - si + 1,
                "duration_sec": round(epochs[ei] - epochs[si], 3),
            })
    streaks.sort(key=lambda s: s["start_epoch"])
    if len(streaks) > MAX_STREAKS:
        warnings.append(f"연속 손실 구간 {len(streaks)}곳 중 {MAX_STREAKS}곳만 기록")
        streaks = streaks[:MAX_STREAKS]

    total = len(exchanges)
    return {
        "total": total,
        "ok": total - len(ng),
        "ng": len(ng),
        "loss_pct": round(len(ng) * 100 / total, 2) if total else 0.0,
        "sender": sender,
        "targets": targets,
        "streaks": streaks,
        "ng_epochs": [x.time for x in ng][:MAX_NG_EPOCHS],
        "trailing_dropped": dropped,
        "warnings": warnings,
    }
