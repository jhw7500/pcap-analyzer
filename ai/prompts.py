"""분석 결과를 AI 프롬프트로 변환.

자동차 WiFi(88Q9098) 진단에 필요한 모든 핵심 지표를 포함:
- 장치별 상세 (role, retry, PHY-MCS 분포, RSSI, 서브타입)
- 로밍 시퀀스 상세 + 영향 분석
- Ping 응답/loss 시계열
- 신호 절벽 / 이상 프레임 / 지연 구간
- 종합 진단 (사전 계산된 결과 활용)
"""
from typing import Any

from analyzer.core.ping_matching import ping_losses, ping_pairs
from analyzer.core.thresholds import ROAM_GAP_DANGER_MS


def _fmt_int(v: Any, default: str = "-") -> str:
    try:
        return f"{int(v):,}"
    except (TypeError, ValueError):
        return default


def _build_device_section(device_stats: dict, header: str = "## 장치별 상세 통계") -> list:
    """장치별 상세 통계 — 자동차 환경에서 가장 진단가치가 높은 섹션.

    header=None이면 헤더 두 줄을 생략하고 본문만 반환한다(네트워크 전체 섹션이
    자체 헤더를 붙여 재사용 — 호출 측의 취약한 슬라이스 의존 제거).
    """
    if not device_stats:
        return []
    lines = ["", header] if header else []
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
        # PHY/MCS retry 핫스팟 — 표본>=30인 (phy, mcs) 중 retry_pct 상위 3.
        mrbp = s.get("mcs_retry_by_phy", {}) or {}
        hotspots = []
        for phy_name, mcs_map in mrbp.items():
            for mcs_key, r in (mcs_map or {}).items():
                if r.get("total", 0) >= 30:
                    hotspots.append((phy_name, mcs_key, r))
        hotspots.sort(key=lambda x: -x[2].get("retry_pct", 0))
        if hotspots:
            hs_str = ", ".join(
                f"{phy_name} "
                f"{('MCS' + mcs_key) if phy_name != 'Legacy' else (mcs_key + 'Mbps')} "
                f"{r.get('retry_pct', 0)}% ({r.get('retry', 0)}/{r.get('total', 0)})"
                for phy_name, mcs_key, r in hotspots[:3]
            )
            lines.append(f"- Retry 핫스팟(표본≥30): {hs_str}")
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
                    f"MCS {b.get('avg_mcs') or '-'} [{b.get('mcs_breakdown') or '-'}])"
                    for b in peaks
                )
                lines.append(f"- Retry 피크 구간 top3: {pk_str}")
        # 최악 retry 피크의 sub-second MCS 컨텍스트 (worst 1-2 sub-seconds).
        # dict 아닌 항목 방어(직렬화 잔재로 .get() AttributeError 방지).
        peaks_detail = [p for p in (s.get("retry_peaks") or []) if isinstance(p, dict)]
        if peaks_detail:
            worst_peak = max(peaks_detail, key=lambda p: p.get("retry_pct", 0))
            subs = sorted(
                (b for b in (worst_peak.get("sub_buckets") or []) if isinstance(b, dict)),
                key=lambda b: -b.get("retry_pct", 0),
            )[:2]
            for b in subs:
                lines.append(
                    f"  · t={b.get('epoch')} {b.get('retry_pct', 0)}% "
                    f"[{b.get('mcs_breakdown') or '-'}]"
                )
    return lines


def _build_roaming_section(roaming: dict) -> list:
    seqs = roaming.get("sequences", []) or []
    if not seqs:
        return []
    slow = [s for s in seqs if s.get("is_slow")]
    failed = [s for s in seqs if s.get("failed") or s.get("status") == "failed"]
    # gap_ms는 None(측정 불가)일 수 있다 — 통계에서 제외해야 평균이 왜곡되지 않는다.
    gaps = [s.get("gap_ms") for s in seqs if isinstance(s.get("gap_ms"), (int, float))]
    unmeasured = [s for s in seqs if s.get("gap_ms") is None]
    lines = ["", "## 로밍 (BSS Transition)"]
    unmeasured_str = f" / gap 측정불가 {len(unmeasured)}회" if unmeasured else ""
    lines.append(
        f"- 총 {len(seqs)}회 / 느린 로밍(전체 소요 >{ROAM_GAP_DANGER_MS}ms) {len(slow)}회 / "
        f"실패 {len(failed)}회{unmeasured_str}"
    )
    if unmeasured:
        lines.append(
            "  · 측정불가 = 그 로밍의 Auth 프레임이 캡처에 없어 시작 시각을 알 수 없음"
            " (지연이 없었다는 뜻이 아님 — 판단 근거로 쓰지 말 것)"
        )
    if gaps:
        lines.append(
            f"- gap_ms(Auth→Reassoc 구간만): min={min(gaps):.1f} / "
            f"avg={sum(gaps)/len(gaps):.1f} / max={max(gaps):.1f}"
        )
    # 로밍 실소요는 4-way까지 포함해야 한다 — gap_ms만 보면 크게 과소평가된다.
    totals = [
        s.get("total_roam_ms") for s in seqs
        if isinstance(s.get("total_roam_ms"), (int, float))
    ]
    if totals:
        lines.append(
            f"- total_roam_ms(Auth→4-way 완료 = 로밍 실소요, n={len(totals)}): "
            f"min={min(totals):.1f} / avg={sum(totals)/len(totals):.1f} / "
            f"max={max(totals):.1f}"
        )
        lines.append(
            "  · gap_ms는 전체의 일부 구간일 뿐이다 — 로밍 빠르기 판단은 "
            "total_roam_ms로 할 것"
        )
    # 느린 로밍 top 5 상세 (gap 큰 순). 4-way/밴드 전환은 신규 키 — 있을 때만 표기.
    def _gap_sort_key(x):
        g = x.get("gap_ms")
        # None(측정 불가)은 -None이 TypeError라 정렬에서 맨 뒤로 보낸다.
        return -g if isinstance(g, (int, float)) else float("inf")

    for s in sorted(slow or seqs, key=_gap_sort_key)[:5]:
        # auth_epoch은 측정 불가 시 None — Assoc 시각으로 폴백(항상 아는 값).
        ts = s.get("auth_epoch") or s.get("assoc_epoch") or s.get("timestamp") or "?"
        sta = s.get("sta_name") or s.get("sta") or "?"
        ap = s.get("ap_name") or s.get("ap") or "?"
        atype = s.get("assoc_type", "?")
        gap = s.get("gap_ms")
        extra = ""
        fw = s.get("four_way_ms")
        if isinstance(fw, (int, float)):
            extra += f", 4-way={fw:.1f}ms"
        if s.get("band_change") is True:
            extra += f", 밴드 전환 {s.get('prev_ap_band') or '?'}→{s.get('ap_band') or '?'}"
        gap_str = f"{gap:.1f}ms" if isinstance(gap, (int, float)) else "측정불가"
        tot = s.get("total_roam_ms")
        if isinstance(tot, (int, float)):
            extra += f", 전체={tot:.1f}ms"
        lines.append(f"  · t={ts} {sta} → {ap} [{atype}], gap={gap_str}{extra}")
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
    # 결과 JSON에는 pairs/losses가 없다(full_list 중복이라 제거) — 헬퍼가
    # full_list에서 파생하고, 구버전 result면 저장된 값을 그대로 쓴다.
    pairs = ping_pairs(ping) or []
    losses = ping_losses(ping) or []
    total = len(pairs) + len(losses)
    if total == 0:
        # ICMP 자체가 없는 캡처 — 섹션을 통째로 생략하면 LLM이 RTT/Loss를
        # 추측할 여지가 생기므로 '평가 대상 아님'을 명시한다.
        stats = ping.get("stats", {}) or {}
        has_icmp = bool(
            ping.get("observations")
            or stats.get("req_total_raw") or stats.get("reply_total_raw")
        )
        if not has_icmp:
            return [
                "",
                "## Ping (ICMP)",
                "- 이 캡처에는 ICMP 트래픽이 없어 RTT/Loss는 평가 대상이 아님 "
                "(측정 불가 — '문제 없음'으로 해석하지 말 것)",
            ]
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
    # signal_cliffs는 {STA명: {cliffs:[{epoch, rssi_before, rssi_after, drop_db,
    # duration_sec}]}} 구조(analyze_signal_cliffs)다. STA명을 외부 키로 붙여
    # 평탄화하고 drop이 큰 순으로 상위 5건을 노출한다. (구버전 결과에는
    # moving_avg 키가 함께 있지만 여기서도 어디서도 읽지 않는다 — 그래서 제거됐다.)
    cliff_items = []
    if isinstance(cliffs, dict):
        for sta_name, cd in cliffs.items():
            for c in (cd.get("cliffs", []) if isinstance(cd, dict) else []):
                if isinstance(c, dict):
                    cliff_items.append((sta_name, c))
    if cliff_items:
        cliff_items.sort(key=lambda x: -(x[1].get("drop_db") or 0))
        lines.append(f"- 신호 절벽(RSSI 급강하) {len(cliff_items)}건")
        for sta_name, c in cliff_items[:5]:
            drop = c.get("drop_db", "?")
            ts = c.get("epoch", "?")
            before, after = c.get("rssi_before"), c.get("rssi_after")
            ctx = (
                f" ({before}→{after}dBm)"
                if before is not None and after is not None
                else ""
            )
            lines.append(f"  · t={ts} {sta_name}: {drop}dB drop{ctx}")
    return lines


def _build_diagnosis_section(diagnosis: Any) -> list:
    if not diagnosis or not isinstance(diagnosis, dict):
        return []
    lines = ["", "## 사전 계산된 진단"]
    health = diagnosis.get("health") or {}
    summary = diagnosis.get("summary") or {}
    # health/summary는 _structured_diagnosis가 항상 dict로 만든다. 비-dict는
    # (report.py _health_section과 동일 정책으로) 그냥 누락 — stringify하지 않는다.
    if isinstance(health, dict) and health:
        lines.append(
            f"- 전체 health: score={health.get('score','-')} "
            f"({health.get('grade','-')})"
        )
    scores = diagnosis.get("component_scores") or {}
    if scores:
        # None = 측정 불가(예: ICMP 없는 캡처의 loss) — 숫자와 혼동 않게 표기.
        score_str = " / ".join(
            f"{k}={'측정불가' if v is None else v}" for k, v in scores.items()
        )
        lines.append(f"- 컴포넌트 점수: {score_str}")
    if isinstance(summary, dict) and summary:
        summary_parts = []
        for k in (
            # loss_pct_used/loss_basis를 함께 넘긴다 — 유선 GT가 있으면 판정은
            # 그 값으로 났으므로, AI가 무선 관측값만 보고 다른 결론을 내면 안 된다.
            "total_frames", "retry_pct", "loss_pct", "loss_pct_used", "loss_basis",
            "roaming_total", "roaming_slow", "delay_zones", "anomaly_count",
        ):
            if summary.get(k) is not None:
                summary_parts.append(f"{k}={summary[k]}")
        if summary_parts:
            lines.append(f"- 핵심 지표: {', '.join(summary_parts)}")
        # 두 손실률이 함께 실리면 AI가 어느 쪽을 근거로 삼아야 하는지 명시한다 —
        # 값이 20배까지 벌어질 수 있어(실측 유선 0.38% vs 무선 8.24%) 안내 없이는
        # 모순된 진단이 나온다.
        if summary.get("loss_basis") == "wired_gt":
            lines.append(
                "  · 손실 판정 근거는 loss_pct_used(유선 확정)다. loss_pct(무선 관측)와의"
                " 차이는 네트워크 문제가 아니라 **모니터가 못 본 프레임**의 양이다 —"
                " 무선 값으로 손실을 논하지 말 것."
            )
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
                # 대표 frame_refs 병기 — SYSTEM의 '수치 인용' 의무를 프레임
                # 번호 수준까지 가능하게 한다(Wireshark 필터 복붙 가능 형태).
                refs = it.get("frame_refs")
                if isinstance(refs, list) and refs:
                    head = ",".join(str(r) for r in refs[:5])
                    line += f" [근거 frame.number in {{{head}}}"
                    if len(refs) > 5:
                        line += f" 외 {len(refs) - 5}건"
                    line += "]"
                lines.append(line)
            else:
                lines.append(f"- {it}")
    # sta_diags는 list — 각 원소 {name, mac, score, scores{}, metrics{retry_pct,
    # rssi_avg, rssi_min, roaming_count, slow_roaming, ...}, issues[]}. 메트릭은
    # metrics 아래 nested다(report.py의 _sta_diags_section과 동일 계약).
    sta_diags = diagnosis.get("sta_diags") or []
    if isinstance(sta_diags, list) and sta_diags:
        lines.append("")
        lines.append("### STA별 사전 진단")
        for sd in sta_diags[:5]:
            if not isinstance(sd, dict):
                continue
            name = sd.get("name", "?")
            m = sd.get("metrics") or {}
            parts = []
            if sd.get("score") is not None:
                parts.append(f"score={sd['score']}")
            for k in ("retry_pct", "rssi_avg", "rssi_min", "roaming_count", "slow_roaming"):
                if m.get(k) is not None:
                    parts.append(f"{k}={m[k]}")
            lines.append(f"- {name}: {', '.join(parts)}")

    # 종합 결론(correlation) — LLM이 결합 컨텍스트를 보고 사용자 환경
    # (설정·튜닝·간섭) 가설을 자연어로 추정할 수 있도록 노출.
    correlations = diagnosis.get("correlations") or []
    if correlations and isinstance(correlations, list):
        lines.append("")
        lines.append(
            f"### 종합 결론(다중 신호 결합, {len(correlations)}건)"
        )
        lines.append(
            "위 단일 이슈들이 같은 STA·같은 시간 구간에 동시 관찰돼 결합된 결론. "
            "confidence는 distinct 신호 수와 윈도우 겹침으로 산출(룰 기반, "
            "사용자 환경 가정 없음)."
        )
        # cap은 filter 후에 적용 — non-dict 항목을 먼저 거른 뒤 상위 5건만 렌더.
        # raw [:5]를 먼저 자르면 [stale, stale, dict, dict, ...]에서 valid 항목이
        # 5개 미만으로 줄어드는 silent loss가 발생한다. C-numbering은 enumerate
        # start=1로 1, 2, 3, ... 연속 보장 (SYSTEM의 ### C{n} 답변 헤더와 짝).
        valid_corrs = [c for c in correlations if isinstance(c, dict)][:5]
        for rendered, c in enumerate(valid_corrs, start=1):
            try:
                conf = float(c.get("confidence", 0))
            except (TypeError, ValueError):
                conf = 0.0
            title = c.get("title", "?")
            sta = c.get("sta_name") or c.get("sta_mac") or "?"
            sigs = ", ".join(
                s.get("type", "?")
                for s in (c.get("signals") or [])
                if isinstance(s, dict)
            )
            tw = c.get("time_window")
            dur_str = ""
            if isinstance(tw, dict):
                try:
                    s_ep = float(tw.get("start_epoch"))
                    e_ep = float(tw.get("end_epoch"))
                    dur_str = f", duration={e_ep - s_ep:.1f}s"
                except (TypeError, ValueError):
                    pass
            n_evidence = len(c.get("frame_refs") or [])
            explanation = (c.get("explanation") or "").strip()
            lines.append("")
            lines.append(
                f"#### C{rendered}: {title} (conf={conf:.2f}, STA={sta}{dur_str})"
            )
            lines.append(f"- 결합 신호: {sigs}")
            lines.append(f"- 증거 프레임: {n_evidence}건")
            if explanation:
                lines.append(f"- 단일 결론 요약: {explanation}")
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
    # `or {}`는 키가 있고 value가 None인 케이스 방어 — dict.get(k, default)는 키
    # 존재 시 default를 무시하므로 {"diagnosis": None} 입력에서 None을 반환한다.
    diagnosis = structured.get("diagnosis", {}) or {}

    out = []
    out.append("## 분석 개요")
    out.append(f"- 총 프레임: {_fmt_int(ov.get('total_frames', 0))}")
    out.append(f"- 캡처 시간: {ov.get('duration_sec', 0)}초")
    out.append(f"- 전체 Retry율: {ov.get('retry_pct', 0)}%")
    out.append(f"- 디바이스: {len(device_stats)}대")
    # 채널/밴드 — overview.channels(신규 키). 구버전 result엔 없어 생략.
    channels = ov.get("channels") or {}
    by_channel = channels.get("by_channel") if isinstance(channels, dict) else None
    if isinstance(by_channel, list) and by_channel:
        ch_str = ", ".join(
            f"CH{c.get('channel', '?')}({c.get('band') or '-'}) {_fmt_int(c.get('frames'))}"
            for c in by_channel[:5] if isinstance(c, dict)
        )
        out.append(f"- 채널/밴드: {ch_str}")
    # 평균/피크 throughput — per_second.bytes(신규 필드) 기반. 없으면 생략.
    per_sec = structured.get("per_second") or {}
    timeline = per_sec.get("timeline") if isinstance(per_sec, dict) else None
    if isinstance(timeline, list):
        byte_vals = [
            e.get("bytes") for e in timeline
            if isinstance(e, dict) and isinstance(e.get("bytes"), (int, float))
        ]
        if byte_vals:
            avg_mbps = sum(byte_vals) * 8 / 1e6 / len(byte_vals)
            peak_mbps = max(byte_vals) * 8 / 1e6
            out.append(
                f"- 처리량: 평균 {avg_mbps:.2f} Mbps / 피크 {peak_mbps:.2f} Mbps"
            )
    # 프레임 타입 분포
    type_dist = ov.get("type_dist") or {}
    if type_dist:
        out.append(
            "- 프레임 타입 분포: "
            + ", ".join(f"{k} {_fmt_int(v)}" for k, v in type_dist.items())
        )

    out.extend(_build_device_section(device_stats))
    # 네트워크 전체(모든 송신) 통계 — 장치별과 동일 포맷으로 단일 가상 장치 렌더.
    # header=None으로 _build_device_section의 자체 헤더를 끄고 전용 헤더를 붙인다
    # (예전 sys_lines[2:] 슬라이스는 헤더 줄 수 가정에 취약했음 — 제거).
    system_stats = structured.get("system_stats") or {}
    if isinstance(system_stats, dict) and system_stats:
        out.append("")
        out.append("## 네트워크 전체(모든 송신)")
        out.extend(
            _build_device_section({"🌐 전체 시스템": system_stats}, header=None)
        )
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
    # 종합 결론(correlation)이 실제 있을 때만 항목 0을 emit — 없는 캡처에서는
    # 진단 요청에 죽은 지시문이 들어가 token만 소모하고 LLM이 헤더만 빈 채로
    # 출력하는 false-positive 위험도 있음. 진단 섹션의 gating과 동일하게 처리.
    # diagnosis는 line 282에서 structured.get("diagnosis", {})로 항상 dict 보장.
    diag_corrs = diagnosis.get("correlations")
    if diag_corrs and isinstance(diag_corrs, list):
        out.append(
            "0. **종합 결론(correlation)별 가설** — 위 종합 결론 섹션의 각 항목"
            "(`#### C{n}`)에 대해 SYSTEM 규칙의 `### C{n}: ...` 헤더 형식으로 "
            "(가능한 가설 / 대안 해석 / 추가 검증)을 작성하세요."
        )
    out.append(
        "1. **가장 심각한 문제 (최대 3개, 우선순위 순)** — 각각 근거 데이터를 인용. "
        "중대 문제가 없으면 \"중대 문제 없음\"이라고 명시"
    )
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
