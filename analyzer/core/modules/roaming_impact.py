"""9. 로밍 전후 영향 분석 — canonical 로밍의 retry/RSSI/ping 변화를 측정."""
from typing import List, Dict
from ..models import Frame, AnalysisSection
from ..detector import mac_name
from .roaming import pair_roaming_sequences

WINDOW_SEC = 3


def _find_roaming_events(frames: List[Frame], roles: Dict) -> List[Dict]:
    """4번 로밍 섹션과 같은 pairing으로 영향 분석 이벤트를 만든다.

    예전 구현은 마지막 Auth를 소비하지 않고 모든 Assoc/Reassoc과 조합해 retry·
    association 재시도를 별도 로밍으로 중복 계수했다(TEST14: canonical 884 대비
    914). 탐지 규칙을 다시 만들지 않고 canonical pairing을 그대로 직렬화한다.
    """
    sta_macs = {m for m, r in roles.items() if r.get("role") == "STA"}
    roaming_frames = [frame for frame in frames if frame.is_roaming_related]
    events = []
    for pairing in pair_roaming_sequences(roaming_frames, sta_macs):
        auth = pairing.auth
        assoc = pairing.assoc
        events.append({
            "sta": assoc.ta,
            "ap": assoc.ra,
            "auth_frame": auth,
            "assoc_frame": assoc,
            "epoch": (auth or assoc).epoch,
            "handshake_ms": pairing.gap_ms,
        })
    return events


def _calc_stats(flist):
    if not flist:
        return {"total": 0, "retry": 0, "retry_pct": 0.0, "rssi_avg": None}
    retries = sum(1 for f in flist if f.retry)
    rssis = [f.rssi_first for f in flist if f.rssi_first is not None]
    return {
        "total": len(flist),
        "retry": retries,
        "retry_pct": retries * 100.0 / len(flist),
        "rssi_avg": sum(rssis) / len(rssis) if rssis else None,
    }


def analyze(frames: List[Frame], roles: Dict, index=None) -> AnalysisSection:
    lines = []
    events = _find_roaming_events(frames, roles)

    if not events:
        return AnalysisSection(
            title="9. 로밍 영향 분석", lines=["로밍 이벤트 없음"], summary="로밍 없음")

    lines.append(f"총 {len(events)}건의 로밍 이벤트 (전후 {WINDOW_SEC}초 분석)")
    lines.append("")

    problem_count = 0
    for i, ev in enumerate(events):
        sta = mac_name(ev["sta"], roles)
        ap = mac_name(ev["ap"], roles)

        # index 활용: O(log N) 윈도우 조회
        if index:
            before_f, after_f = index.sta_frames_in_window(
                ev["sta"], ev["epoch"], WINDOW_SEC, WINDOW_SEC)
        else:
            before_f = [f for f in frames
                        if ev["epoch"] - WINDOW_SEC <= f.epoch < ev["epoch"]
                        and (f.ta == ev["sta"] or f.ra == ev["sta"])]
            after_f = [f for f in frames
                       if ev["epoch"] < f.epoch <= ev["epoch"] + WINDOW_SEC
                       and (f.ta == ev["sta"] or f.ra == ev["sta"])]

        b = _calc_stats(before_f)
        a = _calc_stats(after_f)

        # ping 체크 (전후 윈도우 내에서만)
        window_frames = before_f + after_f
        ping_req = {}
        ping_matched = 0
        for f in window_frames:
            if f.is_icmp_request and not f.retry:
                ping_req[(f.ip_src, f.ip_dst)] = f
            elif f.is_icmp_reply:
                key = (f.ip_dst, f.ip_src)
                if key in ping_req:
                    del ping_req[key]
                    ping_matched += 1
        ping_lost = len(ping_req)

        has_problem = (a["retry_pct"] > 50 or ping_lost > 0)
        if has_problem:
            problem_count += 1

        marker = "★" if has_problem else " "
        start_frame = ev["auth_frame"]
        start_time = (start_frame or ev["assoc_frame"]).time_short
        lines.append(f"[로밍 #{i+1}] {marker} {sta}: →{ap}  {start_time}")
        if start_frame is None:
            lines.append(
                f"  ├─ 핸드셰이크: 측정불가 "
                f"(Auth 미포착→#{ev['assoc_frame'].number})"
            )
        else:
            lines.append(
                f"  ├─ 핸드셰이크: {ev['handshake_ms']:.0f}ms "
                f"(#{start_frame.number}→#{ev['assoc_frame'].number})"
            )

        if b["total"] > 0:
            rssi_b = f", RSSI {b['rssi_avg']:.0f}dBm" if b["rssi_avg"] else ""
            lines.append(f"  ├─ 전 {WINDOW_SEC}초: retry {b['retry_pct']:.0f}% "
                         f"({b['retry']}/{b['total']}){rssi_b}")
        else:
            lines.append(f"  ├─ 전 {WINDOW_SEC}초: 프레임 없음")

        if a["total"] > 0:
            rssi_a = f", RSSI {a['rssi_avg']:.0f}dBm" if a["rssi_avg"] else ""
            lines.append(f"  ├─ 후 {WINDOW_SEC}초: retry {a['retry_pct']:.0f}% "
                         f"({a['retry']}/{a['total']}){rssi_a}")
        else:
            lines.append(f"  ├─ 후 {WINDOW_SEC}초: 프레임 없음")

        loss_str = f"LOSS {ping_lost}건 ★" if ping_lost else "손실 없음"
        lines.append(f"  └─ Ping: 성공 {ping_matched}, {loss_str}")
        lines.append("")

    summary = f"로밍 {len(events)}건, 문제 {problem_count}건"
    return AnalysisSection(title="9. 로밍 영향 분석", lines=lines, summary=summary)
