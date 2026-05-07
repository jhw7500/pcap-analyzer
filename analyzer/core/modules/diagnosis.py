"""11. STA별 종합 진단 — 모든 분석 결과를 교차하여 현장 제안 생성"""

from typing import Any, Dict, List
from collections import Counter
from ..models import Frame, AnalysisSection
from ..detector import mac_name
from ..ping_matching import build_ping_matches


def analyze(
    frames: List[Frame], roles: Dict[str, Dict[str, Any]], index=None
) -> AnalysisSection:
    lines = []
    sta_macs = [m for m, r in roles.items() if r["role"] == "STA"]

    if not sta_macs:
        return AnalysisSection(
            title="11. 종합 진단", lines=["STA 없음"], summary="진단 대상 없음"
        )

    ping = build_ping_matches(frames, roles)
    matched_set = set()
    loss_set = set()
    for item in ping.get("pairs", []):
        matched_set.add((item.get("src"), item.get("dst"), item.get("seq")))
    for item in ping.get("losses", []):
        loss_set.add((item.get("src"), item.get("dst"), item.get("seq")))

    warnings = []

    for sta in sta_macs:
        name = mac_name(sta, roles)

        # index 활용: 사전 인덱싱된 STA별 프레임
        if index:
            sta_frames = index.by_sta.get(sta, [])
        else:
            sta_frames = [f for f in frames if f.ta == sta or f.ra == sta]

        if not sta_frames:
            continue

        total = len(sta_frames)
        retries = sum(1 for f in sta_frames if f.retry)
        retry_pct = retries * 100.0 / total if total else 0

        rssis = [f.rssi_first for f in sta_frames if f.rssi_first is not None]
        rssi_avg = sum(rssis) / len(rssis) if rssis else None
        rssi_min = min(rssis) if rssis else None

        roaming_frames = [f for f in sta_frames if f.is_roaming_related and f.ta == sta]
        auth_count = sum(1 for f in roaming_frames if f.subtype == "11")

        ping_matched = 0
        ping_lost = 0
        for f in sta_frames:
            if not f.is_icmp_request or f.retry:
                continue
            seq = f.icmp_seq if f.icmp_seq else str(f.number)
            key = (f.ip_src, f.ip_dst, seq)
            if key in matched_set:
                ping_matched += 1
            elif key in loss_set:
                ping_lost += 1
        ping_total = ping_matched + ping_lost

        # 분당 최대 retry
        min_retry = Counter()
        for f in sta_frames:
            if f.retry:
                min_retry[int(f.epoch) // 60] += 1
        max_retry_min = max(min_retry.values()) if min_retry else 0

        # 진단
        diags = []
        if ping_lost > 0 and ping_total > 0:
            loss_pct = ping_lost * 100.0 / ping_total
            diags.append(
                ("WARNING", f"Ping Loss {ping_lost}/{ping_total} ({loss_pct:.0f}%)")
            )

        if retry_pct > 40:
            diags.append(("WARNING", f"높은 Retry Rate: {retry_pct:.1f}%"))
        elif retry_pct > 25:
            diags.append(("INFO", f"Retry Rate: {retry_pct:.1f}%"))

        if rssi_min is not None and rssi_min < -75:
            diags.append(("WARNING", f"RSSI 최저값 {rssi_min}dBm — 신호 약화 구간"))

        if max_retry_min > 3000:
            diags.append(("WARNING", f"Retry 폭증: 최대 {max_retry_min}/min"))

        if auth_count > 3:
            diags.append(("INFO", f"잦은 로밍: {auth_count}회"))

        if not diags:
            diags.append(("INFO", "정상"))

        # 출력
        lines.append(f"--- {name} ({sta}) ---")
        rssi_str = f", RSSI avg: {rssi_avg:.0f}dBm" if rssi_avg else ""
        lines.append(f"  프레임: {total:,}, Retry: {retry_pct:.1f}%{rssi_str}")
        lines.append(
            f"  로밍: {auth_count}회, Ping: {ping_matched}성공/{ping_lost}손실"
        )

        for level, msg in diags:
            marker = "!!" if level == "WARNING" else "i "
            lines.append(f"  [{level}] {marker} {msg}")
            if level == "WARNING":
                warnings.append(f"{name}: {msg}")

        # 현장 제안
        if ping_lost > 0 and retry_pct > 30:
            lines.append(
                f"  -> 제안: Retry 폭증이 ping loss 원인. "
                f"로밍 트리거 RSSI 임계값 상향 또는 TX power 조정 권장"
            )
        elif ping_lost > 0 and auth_count > 2:
            lines.append(
                f"  -> 제안: 잦은 로밍으로 인한 전환 지연. "
                f"로밍 히스테리시스 값 확대 권장"
            )
        elif ping_lost > 0:
            lines.append(
                f"  -> 제안: ping loss 원인 추가 조사 필요 (wpa.log, kernel log 확인)"
            )
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
