"""분석 결과를 AI 프롬프트로 변환.

자동차 WiFi(88Q9098) 진단에 필요한 모든 핵심 지표를 포함:
- 장치별 상세 (role, retry, PHY-MCS 분포, RSSI, 서브타입)
- 로밍 시퀀스 상세 + 영향 분석
- Ping 응답/loss 시계열
- 신호 절벽 / 이상 프레임 / 지연 구간
- 종합 진단 (사전 계산된 결과 활용)
"""
from typing import Any


def _fmt_int(v: Any, default: str = "-") -> str:
    try:
        return f"{int(v):,}"
    except (TypeError, ValueError):
        return default


def _build_device_section(device_stats: dict) -> list:
    """장치별 상세 통계 — 자동차 환경에서 가장 진단가치가 높은 섹션."""
    if not device_stats:
        return []
    lines = ["", "## 장치별 상세 통계"]
    for name, s in device_stats.items():
        role = s.get("role", "?")
        total = s.get("total_frames", 0)
        tx = s.get("tx_frames", 0)
        retry_pct = s.get("retry_pct", 0)
        retry_n = s.get("retry_count", 0)
        rssi = s.get("rssi_stats", {}) or {}
        phy = s.get("phy_summary", {}) or {}
        mbp = s.get("mcs_by_phy", {}) or {}

        lines.append(f"\n### {name} [{role}]")
        lines.append(
            f"- 프레임: 총 {_fmt_int(total)} / 송신 {_fmt_int(tx)} / "
            f"Retry {_fmt_int(retry_n)} ({retry_pct}%)"
        )
        if rssi:
            lines.append(
                f"- RSSI: min={rssi.get('min','-')} / avg={rssi.get('avg','-')} / "
                f"max={rssi.get('max','-')} dBm (n={_fmt_int(rssi.get('count', 0))})"
            )
        if phy:
            phy_str = " / ".join(
                f"{k}={_fmt_int(v)}"
                for k, v in sorted(phy.items(), key=lambda kv: -int(kv[1]))
            )
            lines.append(f"- 송신 PHY 모드 분포: {phy_str}")
        # PHY별 MCS / Legacy rate 분포 (top 5)
        for phy_name in ("HE", "EHT", "VHT", "HT", "Legacy"):
            dist = mbp.get(phy_name)
            if not dist:
                continue
            top = sorted(dist.items(), key=lambda kv: -kv[1])[:5]
            unit = "Mbps" if phy_name == "Legacy" else "MCS"
            top_str = ", ".join(f"{unit}{k}×{_fmt_int(v)}" for k, v in top)
            lines.append(f"  · {phy_name} top: {top_str}")
        # 상위 서브타입 top 5
        sub = s.get("subtype_dist", {}) or {}
        if sub:
            top_sub = sorted(sub.items(), key=lambda kv: -kv[1])[:5]
            sub_str = ", ".join(f"{k} {_fmt_int(v)}" for k, v in top_sub)
            lines.append(f"- 서브타입 top: {sub_str}")
        # bucket별 retry 피크 (top 3)
        buckets = s.get("per_bucket", []) or []
        if buckets:
            peaks = sorted(
                [b for b in buckets if b.get("total", 0) > 50],
                key=lambda b: -b.get("retry_pct", 0),
            )[:3]
            if peaks:
                pk_str = " / ".join(
                    f"{b.get('retry_pct',0)}% (frames {_fmt_int(b.get('total',0))}, "
                    f"MCS {b.get('top_mcs','-')})"
                    for b in peaks
                )
                lines.append(f"- Retry 피크 구간 top3: {pk_str}")
    return lines


def _build_roaming_section(roaming: dict) -> list:
    seqs = roaming.get("sequences", []) or []
    if not seqs:
        return []
    slow = [s for s in seqs if s.get("is_slow")]
    failed = [s for s in seqs if s.get("failed") or s.get("status") == "failed"]
    gaps = [s.get("gap_ms", 0) for s in seqs if s.get("gap_ms") is not None]
    lines = ["", "## 로밍 (BSS Transition)"]
    lines.append(
        f"- 총 {len(seqs)}회 / 느린 로밍(>100ms) {len(slow)}회 / 실패 {len(failed)}회"
    )
    if gaps:
        lines.append(
            f"- gap_ms: min={min(gaps):.1f} / avg={sum(gaps)/len(gaps):.1f} / "
            f"max={max(gaps):.1f}"
        )
    # 느린 로밍 top 5 상세 (gap 큰 순)
    for s in sorted(slow or seqs, key=lambda x: -x.get("gap_ms", 0))[:5]:
        ts = s.get("auth_epoch") or s.get("timestamp") or "?"
        sta = s.get("sta_name") or s.get("sta") or "?"
        ap = s.get("ap_name") or s.get("ap") or "?"
        atype = s.get("assoc_type", "?")
        gap = s.get("gap_ms", 0)
        lines.append(f"  · t={ts} {sta} → {ap} [{atype}], gap={gap:.1f}ms")
    # STA별 로밍 횟수
    sta_counts: dict = {}
    for s in seqs:
        n = s.get("sta_name") or "?"
        sta_counts[n] = sta_counts.get(n, 0) + 1
    if sta_counts:
        top_str = ", ".join(
            f"{n}×{c}회" for n, c in sorted(sta_counts.items(), key=lambda kv: -kv[1])[:5]
        )
        lines.append(f"- STA별 로밍 횟수: {top_str}")
    return lines


def _build_ping_section(ping: dict) -> list:
    pairs = ping.get("pairs", []) or []
    losses = ping.get("losses", []) or []
    total = len(pairs) + len(losses)
    if total == 0:
        return []
    loss_pct = len(losses) * 100 / total
    lines = ["", "## Ping (ICMP)"]
    lines.append(
        f"- 응답 {len(pairs)} / 미응답 {len(losses)} / loss {loss_pct:.1f}%"
    )
    if pairs:
        rtts = [p["rtt_ms"] for p in pairs if "rtt_ms" in p]
        if rtts:
            rs = sorted(rtts)
            p50 = rs[len(rs) // 2]
            p95 = rs[int(len(rs) * 0.95)] if len(rs) > 20 else rs[-1]
            lines.append(
                f"- RTT(ms): min={min(rs):.1f} / p50={p50:.1f} / "
                f"avg={sum(rs)/len(rs):.1f} / p95={p95:.1f} / max={max(rs):.1f}"
            )
    # loss 패턴: 시간대별로 묶기
    if losses:
        epochs = [loss.get("epoch") for loss in losses if loss.get("epoch")]
        if epochs:
            # burst 감지: 연속 1초 내
            epochs_sorted = sorted(epochs)
            bursts = 1
            for i in range(1, len(epochs_sorted)):
                if epochs_sorted[i] - epochs_sorted[i - 1] > 1.0:
                    bursts += 1
            lines.append(
                f"- loss burst 구간: 약 {bursts}개 (총 {len(losses)}건이 {bursts}개 구간으로 분포)"
            )
    return lines


def _build_signal_section(signal: dict, cliffs: Any) -> list:
    stas = signal.get("stas", {}) or {}
    if not stas and not cliffs:
        return []
    lines = ["", "## 신호 품질"]
    for name, sta in stas.items():
        avg = sta.get("rssi_avg")
        minv = sta.get("rssi_min")
        maxv = sta.get("rssi_max")
        fc = sta.get("frame_count")
        lines.append(
            f"- {name}: RSSI avg={avg} / min={minv} / max={maxv} dBm (n={_fmt_int(fc)})"
        )
    # signal_cliffs: dict 또는 list 가능
    cliff_list = cliffs.get("cliffs", []) if isinstance(cliffs, dict) else (cliffs or [])
    if cliff_list:
        lines.append(f"- 신호 절벽(RSSI 급강하) {len(cliff_list)}건")
        for c in cliff_list[:5]:
            sta = c.get("sta", "?")
            drop = c.get("drop_db") or c.get("drop", "?")
            ts = c.get("timestamp") or c.get("time", "?")
            lines.append(f"  · {ts} {sta}: {drop}dB drop")
    return lines


def _build_diagnosis_section(diagnosis: Any) -> list:
    if not diagnosis or not isinstance(diagnosis, dict):
        return []
    lines = ["", "## 사전 계산된 진단"]
    health = diagnosis.get("health") or {}
    summary = diagnosis.get("summary") or {}
    if isinstance(health, dict) and health:
        lines.append(
            f"- 전체 health: score={health.get('score','-')} "
            f"({health.get('grade','-')})"
        )
    elif health:
        lines.append(f"- 전체 health: {health}")
    scores = diagnosis.get("component_scores") or {}
    if scores:
        score_str = " / ".join(f"{k}={v}" for k, v in scores.items())
        lines.append(f"- 컴포넌트 점수: {score_str}")
    if isinstance(summary, dict) and summary:
        summary_parts = []
        for k in (
            "total_frames", "retry_pct", "loss_pct",
            "roaming_total", "roaming_slow", "delay_zones", "anomaly_count",
        ):
            if summary.get(k) is not None:
                summary_parts.append(f"{k}={summary[k]}")
        if summary_parts:
            lines.append(f"- 핵심 지표: {', '.join(summary_parts)}")
    elif summary:
        lines.append(f"- 요약: {summary}")
    issues = diagnosis.get("issues") or diagnosis.get("findings") or []
    if issues:
        lines.append("")
        lines.append(f"### 진단 이슈 ({len(issues)}건)")
        for it in issues[:10]:
            if isinstance(it, dict):
                sev = it.get("severity", "?")
                cat = it.get("category") or it.get("type", "?")
                msg = (
                    it.get("msg")
                    or it.get("message")
                    or it.get("description")
                    or it.get("summary", "")
                )
                action = it.get("action") or it.get("recommendation") or ""
                line = f"- [{sev}] {cat}: {msg}"
                if action:
                    line += f" → 권장: {action}"
                lines.append(line)
            else:
                lines.append(f"- {it}")
    sta_diags = diagnosis.get("sta_diags") or {}
    if sta_diags and isinstance(sta_diags, dict):
        lines.append("")
        lines.append("### STA별 사전 진단")
        for sta_name, sd in list(sta_diags.items())[:5]:
            if isinstance(sd, dict):
                parts = []
                for k in ("roaming_count", "retry_pct", "rssi_avg", "loss_pct", "verdict"):
                    if sd.get(k) is not None:
                        parts.append(f"{k}={sd[k]}")
                lines.append(f"- {sta_name}: {', '.join(parts)}")
    return lines


def _build_delay_anomaly_section(delays: Any, anomalies: Any) -> list:
    lines = []
    zones = delays.get("delay_zones", []) if isinstance(delays, dict) else []
    if zones:
        lines.append("")
        lines.append(f"## 지연 구간 ({len(zones)}건)")
        for z in zones[:6]:
            lines.append(
                f"- {z.get('duration_sec', 0):.1f}초, 원인: {z.get('cause', '불명')}, "
                f"영향 ping: {z.get('affected_pings', 0)}건"
            )
    events = anomalies.get("anomalies", []) if isinstance(anomalies, dict) else []
    if events:
        lines.append("")
        lines.append(f"## 이상 프레임 ({len(events)}건)")
        for e in events[:6]:
            lines.append(
                f"- [{e.get('severity', '?')}] {e.get('type', '?')}: "
                f"{e.get('description', '')}"
            )
    return lines


def build_review_prompt(structured: dict) -> str:
    """분석 결과 → 자동차 WiFi 진단용 상세 프롬프트.

    빠진 데이터 없이 핵심 지표를 전부 포함하되, AI가 활용하기 쉬운 구조로 정리.
    """
    ov = structured.get("overview", {}) or {}
    ping = structured.get("ping", {}) or {}
    roaming = structured.get("roaming", {}) or {}
    signal = structured.get("signal", {}) or {}
    device_stats = structured.get("device_stats", {}) or {}
    delays = structured.get("delay_zones", {})
    anomalies = structured.get("anomaly_frames", {})
    cliffs = structured.get("signal_cliffs", {})
    diagnosis = structured.get("diagnosis", {})

    out = []
    out.append("## 분석 개요")
    out.append(f"- 총 프레임: {_fmt_int(ov.get('total_frames', 0))}")
    out.append(f"- 캡처 시간: {ov.get('duration_sec', 0)}초")
    out.append(f"- 전체 Retry율: {ov.get('retry_pct', 0)}%")
    out.append(f"- 디바이스: {len(device_stats)}대")
    # 프레임 타입 분포
    type_dist = ov.get("type_dist") or {}
    if type_dist:
        out.append(
            "- 프레임 타입 분포: "
            + ", ".join(f"{k} {_fmt_int(v)}" for k, v in type_dist.items())
        )

    out.extend(_build_device_section(device_stats))
    out.extend(_build_roaming_section(roaming))
    out.extend(_build_ping_section(ping))
    out.extend(_build_signal_section(signal, cliffs))
    out.extend(_build_delay_anomaly_section(delays, anomalies))
    out.extend(_build_diagnosis_section(diagnosis))

    out.append("")
    out.append("## 진단 요청")
    out.append(
        "위 자동차 WiFi(88Q9098 칩셋) 캡처 분석 결과를 검토하고 다음을 제시하세요:"
    )
    out.append("")
    out.append("1. **가장 심각한 문제 3개** (우선순위 순) — 각각 근거 데이터를 인용")
    out.append("2. **원인 추정** — PHY/MAC/네트워크 어느 계층 문제인지, 측정치 기반으로")
    out.append(
        "3. **구체적 조치 방안** — AP 설정(채널/대역폭/Beacon/MinBasicRate 등), "
        "STA 드라이버 파라미터, 모니터링 추가 지점 등 실행 가능한 액션"
    )
    out.append(
        "4. **자동차 환경 특수성 고려** — 빠른 로밍, 다중 AP, RSSI 변동, "
        "레거시/HE 혼재 등을 진단에 반영"
    )
    out.append("5. **전체 평가** — 양호 / 주의 / 위험 + 한 줄 요약")
    return "\n".join(out)
