"""유선(포트 미러) pcap에서 ping ground truth를 만든다.

검증된 exping의 ICMP 추출·매칭 규칙(응답 인정 상한 1초, 꼬리 무응답 제거)을
그대로 재사용한다 — 대시보드용으로 EXPING xlsx 재현 규칙(RTT 정수 보정,
전각 문자열)은 쓰지 않고 Exchange 수준에서 소비한다. docs/EXPING.md 참조.
"""
from typing import Any, Dict, List

from . import exping
from .ping_matching import find_time_streaks

#: streaks 항목 수 상한 — 비정상 캡처(수천 구간)로 결과 JSON이 비대해지는 것 방지
MAX_STREAKS = 100
#: ng_epochs 상한 — 타임라인 마커용 샘플
MAX_NG_EPOCHS = 1000


def build_ground_truth(
    pcap_path: str,
    tshark_path: str = "tshark",
    reply_timeout: float = exping.DEFAULT_REPLY_TIMEOUT,
) -> Dict[str, Any]:
    """유선 pcap → ping ground truth dict. 실패 시 {"error": str, "warnings": [...]}.

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
